/*
 * vxlan_ipc.c — Unix socket IPC for the VXLAN module.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>

#include "vxlan.h"
#include "vxlan_ipc.h"

static char *ok(void) { return strdup("{\"status\":\"ok\"}\n"); }
static char *err(const char *m)
{
    char b[512]; snprintf(b, sizeof(b),
        "{\"status\":\"error\",\"message\":\"%s\"}\n", m);
    return strdup(b);
}
static const char *jstr(const char *l, const char *k, char *o, size_t ol)
{
    char s[128]; snprintf(s, sizeof(s), "\"%s\":\"", k);
    const char *p = strstr(l, s); if (!p) return NULL;
    p += strlen(s); size_t i = 0;
    while (*p && *p != '"' && i + 1 < ol) o[i++] = *p++;
    o[i] = '\0'; return o;
}
static long long jll(const char *l, const char *k)
{
    char s[128]; snprintf(s, sizeof(s), "\"%s\":", k);
    const char *p = strstr(l, s); if (!p) return -1;
    p += strlen(s); if (*p == '"') p++;
    return strtoll(p, NULL, 10);
}
static bool parse_addr(const char *req, const char *key, vxlan_addr_t *out)
{
    char s[INET6_ADDRSTRLEN] = {0};
    if (!jstr(req, key, s, sizeof(s))) return false;
    return vxlan_addr_parse(s, out) == VXLAN_OK;
}
static bool parse_mac(const char *req, const char *key, vxlan_mac_t *out)
{
    char s[20] = {0};
    if (!jstr(req, key, s, sizeof(s))) return false;
    return vxlan_mac_parse(s, out) == VXLAN_OK;
}

/* VNI handlers */
static char *h_add_vni(vxlan_ctx_t *ctx, const char *req)
{
    long long vni = jll(req, "vni"); if (vni <= 0) return err("missing vni");
    long long bd  = jll(req, "bd_ifindex");
    long long flg = jll(req, "flags");
    long long mtu = jll(req, "mtu");
    int rc = vxlan_vni_add(ctx, (uint32_t)vni,
                           bd  > 0 ? (uint32_t)bd  : 0,
                           flg > 0 ? (uint32_t)flg : 0,
                           mtu > 0 ? (uint16_t)mtu : 0);
    if (rc == VXLAN_ERR_EXISTS) return err("VNI already exists");
    if (rc == VXLAN_ERR_FULL)   return err("VNI table full");
    if (rc == VXLAN_ERR_INVAL)  return err("invalid VNI");
    return rc == VXLAN_OK ? ok() : err("failed");
}

static char *h_del_vni(vxlan_ctx_t *ctx, const char *req)
{
    long long vni = jll(req, "vni"); if (vni <= 0) return err("missing vni");
    return vxlan_vni_del(ctx, (uint32_t)vni) == VXLAN_OK
           ? ok() : err("VNI not found");
}

static char *h_list_vnis(vxlan_ctx_t *ctx)
{
    char *buf = malloc(VXLAN_IPC_MAX_MSG); if (!buf) return err("oom");
    size_t pos = 0, left = VXLAN_IPC_MAX_MSG;
    pos += snprintf(buf+pos,left-pos,"{\"status\":\"ok\",\"vnis\":[");
    bool first = true;
    pthread_rwlock_rdlock(&ctx->vni_table.lock);
    for (uint32_t i = 0; i < ctx->vni_table.n_buckets; i++)
        for (vxlan_vni_t *v = ctx->vni_table.buckets[i]; v; v = v->next) {
            char mcast_s[INET6_ADDRSTRLEN] = "";
            if (v->flags & VXLAN_VNI_MCAST)
                vxlan_addr_to_str(&v->mcast_group, mcast_s, sizeof(mcast_s));
            pos += snprintf(buf+pos,left-pos,
                "%s{\"vni\":%u,\"bd_ifindex\":%u,\"flags\":%u,\"mtu\":%u,"
                "\"n_fdb\":%u,\"n_flood\":%u,\"mcast_group\":\"%s\","
                "\"rx_pkts\":%llu,\"tx_pkts\":%llu}",
                first?"":",", v->vni, v->bd_ifindex, v->flags, v->mtu,
                v->fdb.n_entries, v->n_flood, mcast_s,
                (unsigned long long)v->rx_pkts,
                (unsigned long long)v->tx_pkts);
            first = false;
        }
    pthread_rwlock_unlock(&ctx->vni_table.lock);
    snprintf(buf+pos,left-pos,"]}\n");
    return buf;
}

static char *h_get_vni(vxlan_ctx_t *ctx, const char *req)
{
    long long vni_l = jll(req, "vni"); if (vni_l <= 0) return err("missing vni");
    vxlan_vni_t *v = vxlan_vni_find(ctx, (uint32_t)vni_l);
    if (!v) return err("VNI not found");
    char mcast_s[INET6_ADDRSTRLEN] = "";
    if (v->flags & VXLAN_VNI_MCAST)
        vxlan_addr_to_str(&v->mcast_group, mcast_s, sizeof(mcast_s));
    char *buf = malloc(512);
    snprintf(buf, 512,
        "{\"status\":\"ok\",\"vni\":%u,\"bd_ifindex\":%u,"
        "\"flags\":%u,\"mtu\":%u,\"n_fdb\":%u,\"n_flood\":%u,"
        "\"mcast_group\":\"%s\","
        "\"rx_pkts\":%llu,\"tx_pkts\":%llu,"
        "\"rx_bytes\":%llu,\"tx_bytes\":%llu}\n",
        v->vni, v->bd_ifindex, v->flags, v->mtu,
        v->fdb.n_entries, v->n_flood, mcast_s,
        (unsigned long long)v->rx_pkts, (unsigned long long)v->tx_pkts,
        (unsigned long long)v->rx_bytes, (unsigned long long)v->tx_bytes);
    return buf;
}

/* Tunnel handlers */
static char *h_add_tunnel(vxlan_ctx_t *ctx, const char *req)
{
    vxlan_addr_t rip; if (!parse_addr(req,"remote_ip",&rip)) return err("missing remote_ip");
    long long vni = jll(req,"vni"); if (vni<=0) return err("missing vni");
    long long flg = jll(req,"flags"), dp = jll(req,"dst_port"), ttl = jll(req,"ttl");
    int rc = vxlan_tunnel_add(ctx,&rip,(uint32_t)vni,
                              flg>0?(uint32_t)flg:0,
                              dp>0?(uint16_t)dp:0,
                              ttl>0?(uint8_t)ttl:0);
    if (rc==VXLAN_ERR_EXISTS) return err("tunnel already exists");
    if (rc==VXLAN_ERR_FULL)   return err("tunnel table full");
    return rc==VXLAN_OK?ok():err("failed");
}

static char *h_del_tunnel(vxlan_ctx_t *ctx, const char *req)
{
    vxlan_addr_t rip; if (!parse_addr(req,"remote_ip",&rip)) return err("missing remote_ip");
    long long vni = jll(req,"vni"); if (vni<=0) return err("missing vni");
    return vxlan_tunnel_del(ctx,&rip,(uint32_t)vni)==VXLAN_OK?ok():err("not found");
}

static char *h_list_tunnels(vxlan_ctx_t *ctx)
{
    char *buf = malloc(VXLAN_IPC_MAX_MSG); if (!buf) return err("oom");
    size_t pos=0,left=VXLAN_IPC_MAX_MSG;
    pos+=snprintf(buf+pos,left-pos,"{\"status\":\"ok\",\"tunnels\":[");
    bool first=true;
    pthread_rwlock_rdlock(&ctx->tunnel_table.lock);
    for (uint32_t i=0;i<ctx->tunnel_table.n_buckets;i++)
        for (vxlan_tunnel_t *t=ctx->tunnel_table.buckets[i];t;t=t->next) {
            char rip_s[INET6_ADDRSTRLEN];
            vxlan_addr_to_str(&t->remote_ip,rip_s,sizeof(rip_s));
            pos+=snprintf(buf+pos,left-pos,
                "%s{\"remote_ip\":\"%s\",\"vni\":%u,\"flags\":%u,"
                "\"dst_port\":%u,\"ttl\":%u,"
                "\"tx_pkts\":%llu,\"rx_pkts\":%llu}",
                first?"":",",rip_s,t->vni,t->flags,t->dst_port,t->ttl,
                (unsigned long long)t->tx_pkts,
                (unsigned long long)t->rx_pkts);
            first=false;
        }
    pthread_rwlock_unlock(&ctx->tunnel_table.lock);
    snprintf(buf+pos,left-pos,"]}\n");
    return buf;
}

/* FDB handlers */
static char *h_add_fdb(vxlan_ctx_t *ctx, const char *req)
{
    long long vni=jll(req,"vni"); if (vni<=0) return err("missing vni");
    vxlan_mac_t mac; if (!parse_mac(req,"mac",&mac)) return err("missing mac");
    vxlan_addr_t rip={0}; parse_addr(req,"remote_ip",&rip);
    long long oif=jll(req,"ifindex"), flg=jll(req,"flags");
    int rc=vxlan_fdb_add(ctx,(uint32_t)vni,&mac,
                         rip.af?&rip:NULL,
                         oif>0?(uint32_t)oif:0,
                         flg>0?(uint32_t)flg:VXLAN_FDB_REMOTE);
    if (rc==VXLAN_ERR_NOTFOUND) return err("VNI not found");
    if (rc==VXLAN_ERR_FULL)     return err("FDB full");
    return rc==VXLAN_OK?ok():err("failed");
}

static char *h_del_fdb(vxlan_ctx_t *ctx, const char *req)
{
    long long vni=jll(req,"vni"); if (vni<=0) return err("missing vni");
    vxlan_mac_t mac; if (!parse_mac(req,"mac",&mac)) return err("missing mac");
    return vxlan_fdb_del(ctx,(uint32_t)vni,&mac)==VXLAN_OK?ok():err("not found");
}

static char *h_list_fdb(vxlan_ctx_t *ctx, const char *req)
{
    long long vni_l=jll(req,"vni"); if (vni_l<=0) return err("missing vni");
    vxlan_vni_t *v=vxlan_vni_find(ctx,(uint32_t)vni_l);
    if (!v) return err("VNI not found");
    char *buf=malloc(VXLAN_IPC_MAX_MSG); if (!buf) return err("oom");
    size_t pos=0,left=VXLAN_IPC_MAX_MSG;
    pos+=snprintf(buf+pos,left-pos,"{\"status\":\"ok\",\"fdb\":[");
    bool first=true;
    pthread_rwlock_rdlock(&v->fdb.lock);
    for (uint32_t i=0;i<v->fdb.n_buckets;i++)
        for (vxlan_fdb_entry_t *e=v->fdb.buckets[i];e;e=e->next) {
            char mac_s[20],rip_s[INET6_ADDRSTRLEN]="";
            vxlan_mac_to_str(&e->mac,mac_s,sizeof(mac_s));
            if (e->remote_ip.af) vxlan_addr_to_str(&e->remote_ip,rip_s,sizeof(rip_s));
            pos+=snprintf(buf+pos,left-pos,
                "%s{\"mac\":\"%s\",\"remote_ip\":\"%s\","
                "\"ifindex\":%u,\"flags\":%u,\"hits\":%llu}",
                first?"":",",mac_s,rip_s,e->out_ifindex,e->flags,
                (unsigned long long)e->hit_count);
            first=false;
            if (pos+256>=left) break;
        }
    pthread_rwlock_unlock(&v->fdb.lock);
    snprintf(buf+pos,left-pos,"]}\n");
    return buf;
}

static char *h_lookup_fdb(vxlan_ctx_t *ctx, const char *req)
{
    long long vni=jll(req,"vni"); if (vni<=0) return err("missing vni");
    vxlan_mac_t mac; if (!parse_mac(req,"mac",&mac)) return err("missing mac");
    vxlan_fdb_entry_t *e=vxlan_fdb_lookup(ctx,(uint32_t)vni,&mac);
    if (!e) return err("not found");
    char mac_s[20],rip_s[INET6_ADDRSTRLEN]="";
    vxlan_mac_to_str(&e->mac,mac_s,sizeof(mac_s));
    if (e->remote_ip.af) vxlan_addr_to_str(&e->remote_ip,rip_s,sizeof(rip_s));
    char *buf=malloc(256);
    snprintf(buf,256,"{\"status\":\"ok\",\"mac\":\"%s\","
        "\"remote_ip\":\"%s\",\"ifindex\":%u,\"flags\":%u}\n",
        mac_s,rip_s,e->out_ifindex,e->flags);
    return buf;
}

static char *h_flush_fdb(vxlan_ctx_t *ctx, const char *req)
{
    long long vni=jll(req,"vni"); if (vni<=0) return err("missing vni");
    vxlan_addr_t rip={0}; parse_addr(req,"remote_ip",&rip);
    return vxlan_fdb_flush(ctx,(uint32_t)vni,rip.af?&rip:NULL)==VXLAN_OK
           ?ok():err("VNI not found");
}

/* Flood list handlers */
static char *h_add_flood(vxlan_ctx_t *ctx, const char *req)
{
    long long vni=jll(req,"vni"); if (vni<=0) return err("missing vni");
    vxlan_addr_t rip; if (!parse_addr(req,"remote",&rip)) return err("missing remote");
    int rc=vxlan_flood_add(ctx,(uint32_t)vni,&rip);
    if (rc==VXLAN_ERR_NOTFOUND) return err("VNI not found");
    return rc==VXLAN_OK?ok():err("failed");
}

static char *h_del_flood(vxlan_ctx_t *ctx, const char *req)
{
    long long vni=jll(req,"vni"); if (vni<=0) return err("missing vni");
    vxlan_addr_t rip; if (!parse_addr(req,"remote",&rip)) return err("missing remote");
    return vxlan_flood_del(ctx,(uint32_t)vni,&rip)==VXLAN_OK?ok():err("not found");
}

static char *h_list_flood(vxlan_ctx_t *ctx, const char *req)
{
    long long vni_l=jll(req,"vni"); if (vni_l<=0) return err("missing vni");
    vxlan_vni_t *v=vxlan_vni_find(ctx,(uint32_t)vni_l);
    if (!v) return err("VNI not found");
    char *buf=malloc(65536); if (!buf) return err("oom");
    size_t pos=0,left=65536;
    pos+=snprintf(buf+pos,left-pos,"{\"status\":\"ok\",\"flood_list\":[");
    bool first=true;
    pthread_rwlock_rdlock(&v->lock);
    for (uint32_t i=0;i<v->n_flood;i++) {
        char ip_s[INET6_ADDRSTRLEN];
        vxlan_addr_to_str(&v->flood_list[i],ip_s,sizeof(ip_s));
        pos+=snprintf(buf+pos,left-pos,"%s\"%s\"",first?"":",",ip_s);
        first=false;
    }
    pthread_rwlock_unlock(&v->lock);
    snprintf(buf+pos,left-pos,"]}\n");
    return buf;
}

/* Stats */
static char *h_get_stats(vxlan_ctx_t *ctx)
{
    vxlan_stats_t s; vxlan_stats_get(ctx,&s);
    char *buf=malloc(512);
    snprintf(buf,512,
        "{\"status\":\"ok\","
        "\"rx_pkts\":%llu,\"rx_bytes\":%llu,"
        "\"rx_decap_ok\":%llu,\"rx_decap_err\":%llu,"
        "\"rx_drop_vni\":%llu,\"rx_drop_short\":%llu,"
        "\"tx_pkts\":%llu,\"tx_bytes\":%llu,"
        "\"tx_encap_ok\":%llu,\"tx_encap_err\":%llu,"
        "\"tx_drop_notunnel\":%llu}\n",
        (unsigned long long)s.rx_pkts,(unsigned long long)s.rx_bytes,
        (unsigned long long)s.rx_decap_ok,(unsigned long long)s.rx_decap_err,
        (unsigned long long)s.rx_drop_vni,(unsigned long long)s.rx_drop_short,
        (unsigned long long)s.tx_pkts,(unsigned long long)s.tx_bytes,
        (unsigned long long)s.tx_encap_ok,(unsigned long long)s.tx_encap_err,
        (unsigned long long)s.tx_drop_notunnel);
    return buf;
}

/* Dispatch */
char *vxlan_ipc_handle(vxlan_ctx_t *ctx, const char *req, size_t req_len)
{
    (void)req_len;
    char cmd[64]={0}; jstr(req,"cmd",cmd,sizeof(cmd));

    if (!strcmp(cmd,VXLAN_CMD_ADD_VNI))       return h_add_vni(ctx,req);
    if (!strcmp(cmd,VXLAN_CMD_DEL_VNI))       return h_del_vni(ctx,req);
    if (!strcmp(cmd,VXLAN_CMD_LIST_VNIS))     return h_list_vnis(ctx);
    if (!strcmp(cmd,VXLAN_CMD_GET_VNI))       return h_get_vni(ctx,req);
    if (!strcmp(cmd,VXLAN_CMD_ADD_TUNNEL))    return h_add_tunnel(ctx,req);
    if (!strcmp(cmd,VXLAN_CMD_DEL_TUNNEL))    return h_del_tunnel(ctx,req);
    if (!strcmp(cmd,VXLAN_CMD_LIST_TUNNELS))  return h_list_tunnels(ctx);
    if (!strcmp(cmd,VXLAN_CMD_ADD_FDB))       return h_add_fdb(ctx,req);
    if (!strcmp(cmd,VXLAN_CMD_DEL_FDB))       return h_del_fdb(ctx,req);
    if (!strcmp(cmd,VXLAN_CMD_LIST_FDB))      return h_list_fdb(ctx,req);
    if (!strcmp(cmd,VXLAN_CMD_LOOKUP_FDB))    return h_lookup_fdb(ctx,req);
    if (!strcmp(cmd,VXLAN_CMD_FLUSH_FDB))     return h_flush_fdb(ctx,req);
    if (!strcmp(cmd,VXLAN_CMD_ADD_FLOOD))     return h_add_flood(ctx,req);
    if (!strcmp(cmd,VXLAN_CMD_DEL_FLOOD))     return h_del_flood(ctx,req);
    if (!strcmp(cmd,VXLAN_CMD_LIST_FLOOD))    return h_list_flood(ctx,req);
    if (!strcmp(cmd,VXLAN_CMD_GET_STATS))     return h_get_stats(ctx);
    if (!strcmp(cmd,VXLAN_CMD_CLEAR_STATS))   { vxlan_stats_clear(ctx); return ok(); }
    if (!strcmp(cmd,VXLAN_CMD_DUMP_CONFIG)) {
        char path[256]="vxlan_runtime.json"; jstr(req,"path",path,sizeof(path));
        char *buf=malloc(512);
        snprintf(buf,512,"{\"status\":\"%s\",\"path\":\"%s\"}\n",
                 vxlan_save_config(ctx,path)==VXLAN_OK?"ok":"error",path);
        return buf;
    }
    if (!strcmp(cmd,VXLAN_CMD_LOAD_CONFIG)) {
        char path[256]="vxlan_runtime.json"; jstr(req,"path",path,sizeof(path));
        return vxlan_load_config(ctx,path)==VXLAN_OK?ok():err("load failed");
    }
    if (!strcmp(cmd,"get")) {
        char key[64]={0}; jstr(req,"key",key,sizeof(key));
        char *buf=malloc(128);
        if (!strcmp(key,"UDP_PORT")) {
            snprintf(buf,128,"{\"status\":\"ok\",\"value\":\"%u\"}\n",ctx->listen_port);
        } else if (!strcmp(key,"LOCAL_IP")) {
            char ip_s[INET6_ADDRSTRLEN]={0};
            vxlan_addr_to_str(&ctx->local_ip,ip_s,sizeof(ip_s));
            snprintf(buf,128,"{\"status\":\"ok\",\"value\":\"%s\"}\n",ip_s);
        } else { free(buf); return err("unknown key"); }
        return buf;
    }
    if (!strcmp(cmd,"set")) return err("read-only: use daemon flags to change UDP_PORT/LOCAL_IP");
    if (!strcmp(cmd,"ping")) return strdup("{\"status\":\"ok\",\"msg\":\"pong\",\"module\":\"vxlan\"}\n");
    return err("unknown command");
}

/* IPC server */
int vxlan_ipc_init(vxlan_ctx_t *ctx)
{
    struct sockaddr_un addr={0}; addr.sun_family=AF_UNIX;
    snprintf(addr.sun_path,sizeof(addr.sun_path),"%.*s",
             (int)(sizeof(addr.sun_path)-1),ctx->sock_path);
    unlink(ctx->sock_path);
    ctx->ipc_fd=socket(AF_UNIX,SOCK_STREAM,0); if (ctx->ipc_fd<0) return VXLAN_ERR_SOCKET;
    if (bind(ctx->ipc_fd,(struct sockaddr*)&addr,sizeof(addr))<0||
        listen(ctx->ipc_fd,16)<0) {
        close(ctx->ipc_fd);ctx->ipc_fd=-1;return VXLAN_ERR_SOCKET;}
    return VXLAN_OK;
}

void vxlan_ipc_stop(vxlan_ctx_t *ctx)
{
    if (ctx->ipc_fd>=0){close(ctx->ipc_fd);ctx->ipc_fd=-1;}
    unlink(ctx->sock_path);
}

void *vxlan_ipc_thread(void *arg)
{
    vxlan_ctx_t *ctx=arg; char buf[VXLAN_IPC_MAX_MSG];
    while (ctx->running) {
        int client=accept(ctx->ipc_fd,NULL,NULL);
        if (client<0){if (!ctx->running) break;continue;}
        ssize_t n=recv(client,buf,sizeof(buf)-1,0);
        if (n>0){buf[n]='\0';char *r=vxlan_ipc_handle(ctx,buf,(size_t)n);
                 if (r){send(client,r,strlen(r),0);free(r);}}
        close(client);
    }
    return NULL;
}
