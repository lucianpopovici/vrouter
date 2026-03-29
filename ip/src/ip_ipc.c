/*
 * ip_ipc.c — Unix domain socket IPC for the IP module.
 * Adds: add_nexthop, del_nexthop, set_ecmp_hash.
 * lookup now returns the full nexthop group + selected path.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "ip.h"
#include "ip_ipc.h"

/* -----------------------------------------------------------------------
 * JSON micro-helpers
 * --------------------------------------------------------------------- */
static char *ok_json(void) { return strdup("{\"status\":\"ok\"}\n"); }

static char *err_json(const char *msg)
{
    char buf[512];
    snprintf(buf, sizeof(buf), "{\"status\":\"error\",\"message\":\"%s\"}\n", msg);
    return strdup(buf);
}

static const char *jstr(const char *line, const char *key, char *out, size_t olen)
{
    char search[128];
    snprintf(search, sizeof(search), "\"%s\":\"", key);
    const char *p = strstr(line, search);
    if (!p) return NULL;
    p += strlen(search);
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < olen) out[i++] = *p++;
    out[i] = '\0';
    return out;
}

static long jint(const char *line, const char *key)
{
    char search[128];
    snprintf(search, sizeof(search), "\"%s\":", key);
    const char *p = strstr(line, search);
    if (!p) return -1;
    p += strlen(search);
    if (*p == '"') p++;
    return strtol(p, NULL, 10);
}

static bool jbool(const char *line, const char *key)
{
    char search[128];
    snprintf(search, sizeof(search), "\"%s\":true", key);
    return strstr(line, search) != NULL;
}

/* Serialise a single nexthop path to JSON fragment (no trailing comma) */
static int nh_to_json(const ip_nexthop_t *nh, char *buf, size_t len)
{
    char nhstr[INET6_ADDRSTRLEN] = "::";
    ip_addr_to_str(&nh->addr, nhstr, sizeof(nhstr));
    return snprintf(buf, len,
                    "{\"nexthop\":\"%s\",\"ifindex\":%u,"
                    "\"weight\":%u,\"active\":%s,\"hits\":%llu}",
                    nhstr, nh->ifindex, nh->weight,
                    nh->active ? "true" : "false",
                    (unsigned long long)nh->hit_count);
}

/* -----------------------------------------------------------------------
 * Handlers
 * --------------------------------------------------------------------- */
static char *handle_add_addr(ip_ctx_t *ctx, const char *req)
{
    char pfx_str[INET6_ADDRSTRLEN+4]={0};
    long ifindex = jint(req,"ifindex");
    if (ifindex<0 || !jstr(req,"prefix",pfx_str,sizeof(pfx_str)))
        return err_json("missing ifindex or prefix");
    ip_prefix_t pfx;
    if (ip_prefix_parse(pfx_str,&pfx)!=IP_OK) return err_json("invalid prefix");
    uint32_t vl=(uint32_t)jint(req,"valid_lft");
    uint32_t pl=(uint32_t)jint(req,"pref_lft");
    int rc = ip_addr_add(ctx,(uint32_t)ifindex,&pfx,vl,pl);
    if (rc==IP_ERR_EXISTS)   return err_json("address already exists");
    if (rc==IP_ERR_NOTFOUND) return err_json("interface not found");
    return rc==IP_OK ? ok_json() : err_json("failed");
}

static char *handle_del_addr(ip_ctx_t *ctx, const char *req)
{
    char pfx_str[INET6_ADDRSTRLEN+4]={0};
    long ifindex = jint(req,"ifindex");
    if (ifindex<0 || !jstr(req,"prefix",pfx_str,sizeof(pfx_str)))
        return err_json("missing ifindex or prefix");
    ip_prefix_t pfx;
    if (ip_prefix_parse(pfx_str,&pfx)!=IP_OK) return err_json("invalid prefix");
    return ip_addr_del(ctx,(uint32_t)ifindex,&pfx)==IP_OK
           ? ok_json() : err_json("not found");
}

static char *handle_list_addrs(ip_ctx_t *ctx, const char *req)
{
    long filter = jint(req,"ifindex");
    char *buf = malloc(IP_IPC_MAX_MSG);
    if (!buf) return err_json("oom");
    size_t pos=0, left=IP_IPC_MAX_MSG;
    pos += snprintf(buf+pos,left-pos,"{\"status\":\"ok\",\"addresses\":[");

    bool first=true;
    pthread_rwlock_rdlock(&ctx->if_table.lock);
    for (uint32_t i=0;i<ctx->if_table.n_buckets;i++) {
        for (ip_interface_t *ifc=ctx->if_table.buckets[i];ifc;ifc=ifc->next) {
            if (filter>=0 && (uint32_t)filter!=ifc->ifindex) continue;
            pthread_rwlock_rdlock(&ifc->lock);
            for (ip_if_addr_t *a=ifc->addrs;a;a=a->next) {
                char ps[INET6_ADDRSTRLEN+4];
                ip_prefix_to_str(&a->prefix,ps,sizeof(ps));
                pos += snprintf(buf+pos,left-pos,
                    "%s{\"ifindex\":%u,\"ifname\":\"%s\","
                    "\"prefix\":\"%s\",\"af\":%d,\"state\":%u}",
                    first?"":",",ifc->ifindex,ifc->name,ps,
                    a->prefix.addr.af,a->state);
                first=false;
            }
            pthread_rwlock_unlock(&ifc->lock);
        }
    }
    pthread_rwlock_unlock(&ctx->if_table.lock);
    snprintf(buf+pos,left-pos,"]}\n");
    return buf;
}

static char *handle_list_interfaces(ip_ctx_t *ctx)
{
    char *buf = malloc(IP_IPC_MAX_MSG);
    if (!buf) return err_json("oom");
    size_t pos=0,left=IP_IPC_MAX_MSG;
    pos += snprintf(buf+pos,left-pos,"{\"status\":\"ok\",\"interfaces\":[");

    bool first=true;
    pthread_rwlock_rdlock(&ctx->if_table.lock);
    for (uint32_t i=0;i<ctx->if_table.n_buckets;i++) {
        for (ip_interface_t *ifc=ctx->if_table.buckets[i];ifc;ifc=ifc->next) {
            pthread_rwlock_rdlock(&ifc->lock);
            pos += snprintf(buf+pos,left-pos,
                "%s{\"name\":\"%s\",\"ifindex\":%u,\"flags\":%u,"
                "\"mtu\":%u,\"ip4_fwd\":%s,\"ip6_fwd\":%s,\"n_addrs\":%u}",
                first?"":",",ifc->name,ifc->ifindex,ifc->flags,ifc->mtu,
                ifc->ip4_fwd?"true":"false",ifc->ip6_fwd?"true":"false",
                ifc->n_addrs);
            first=false;
            pthread_rwlock_unlock(&ifc->lock);
        }
    }
    pthread_rwlock_unlock(&ctx->if_table.lock);
    snprintf(buf+pos,left-pos,"]}\n");
    return buf;
}

/* Helper: parse nexthop + ifindex from request */
static bool parse_nh(const char *req, ip_addr_t *nh, uint32_t *oif)
{
    char nhstr[INET6_ADDRSTRLEN]={0};
    if (!jstr(req,"nexthop",nhstr,sizeof(nhstr))) return false;
    if (ip_addr_parse(nhstr,nh)!=IP_OK) return false;
    long idx = jint(req,"ifindex");
    if (idx<0) return false;
    *oif = (uint32_t)idx;
    return true;
}

static char *handle_add_route(ip_ctx_t *ctx, const char *req)
{
    char pfx_str[INET6_ADDRSTRLEN+4]={0};
    if (!jstr(req,"prefix",pfx_str,sizeof(pfx_str)))
        return err_json("missing prefix");
    ip_prefix_t pfx;
    if (ip_prefix_parse(pfx_str,&pfx)!=IP_OK) return err_json("invalid prefix");

    ip_addr_t nh={0}; uint32_t oif=0;
    if (!parse_nh(req,&nh,&oif)) {
        /* allow nexthop-less add (on-link) */
        nh.af = pfx.addr.af;
        long idx = jint(req,"ifindex");
        if (idx>=0) oif=(uint32_t)idx;
    }
    uint8_t  ad     = (uint8_t)(jint(req,"ad")>=0 ? jint(req,"ad") : IP_AD_STATIC);
    long     ml     = jint(req,"metric");
    uint32_t metric = ml>=0 ? (uint32_t)ml : 0;
    long     wl     = jint(req,"weight");
    uint32_t weight = wl>0  ? (uint32_t)wl : 1;

    int rc = ip_fwd_add(ctx,&pfx,&nh,oif,ad,metric,weight);
    if (rc==IP_ERR_NOTFOUND) return err_json("VRF/table not found");
    if (rc==IP_ERR_NOMEM)    return err_json("FIB full");
    return rc==IP_OK ? ok_json() : err_json("failed");
}

static char *handle_add_nexthop(ip_ctx_t *ctx, const char *req)
{
    char pfx_str[INET6_ADDRSTRLEN+4]={0};
    if (!jstr(req,"prefix",pfx_str,sizeof(pfx_str)))
        return err_json("missing prefix");
    ip_prefix_t pfx;
    if (ip_prefix_parse(pfx_str,&pfx)!=IP_OK) return err_json("invalid prefix");

    ip_addr_t nh={0}; uint32_t oif=0;
    if (!parse_nh(req,&nh,&oif)) return err_json("missing nexthop or ifindex");

    long wl = jint(req,"weight");
    uint32_t weight = wl>0 ? (uint32_t)wl : 1;
    int rc = ip_nexthop_add(ctx,&pfx,&nh,oif,weight);
    if (rc==IP_ERR_NOTFOUND) return err_json("prefix not found");
    if (rc==IP_ERR_FULL)     return err_json("nexthop group full");
    return rc==IP_OK ? ok_json() : err_json("failed");
}

static char *handle_del_nexthop(ip_ctx_t *ctx, const char *req)
{
    char pfx_str[INET6_ADDRSTRLEN+4]={0};
    if (!jstr(req,"prefix",pfx_str,sizeof(pfx_str)))
        return err_json("missing prefix");
    ip_prefix_t pfx;
    if (ip_prefix_parse(pfx_str,&pfx)!=IP_OK) return err_json("invalid prefix");

    ip_addr_t nh={0}; uint32_t oif=0;
    if (!parse_nh(req,&nh,&oif)) return err_json("missing nexthop or ifindex");

    int rc = ip_nexthop_del(ctx,&pfx,&nh,oif);
    return rc==IP_OK ? ok_json() : err_json("nexthop not found");
}

static char *handle_del_route(ip_ctx_t *ctx, const char *req)
{
    char pfx_str[INET6_ADDRSTRLEN+4]={0};
    if (!jstr(req,"prefix",pfx_str,sizeof(pfx_str)))
        return err_json("missing prefix");
    ip_prefix_t pfx;
    if (ip_prefix_parse(pfx_str,&pfx)!=IP_OK) return err_json("invalid prefix");
    return ip_fwd_del(ctx,&pfx)==IP_OK ? ok_json() : err_json("not found");
}

static char *handle_list_routes(ip_ctx_t *ctx, const char *req)
{
    char af_str[8]={0};
    jstr(req,"af",af_str,sizeof(af_str));
    sa_family_t af_filter = strcmp(af_str,"ipv4")==0 ? AF_INET :
                            strcmp(af_str,"ipv6")==0 ? AF_INET6 : 0;

    char *buf = malloc(IP_IPC_MAX_MSG);
    if (!buf) return err_json("oom");
    size_t pos=0,left=IP_IPC_MAX_MSG;
    pos += snprintf(buf+pos,left-pos,"{\"status\":\"ok\",\"routes\":[");
    bool first=true;

    for (int a=0;a<2;a++) {
        ip_fwd_table_t *t = a==0 ? &ctx->fwd4 : &ctx->fwd6;
        sa_family_t taf   = a==0 ? AF_INET : AF_INET6;
        if (af_filter && af_filter!=taf) continue;
        pthread_rwlock_rdlock(&t->lock);
        for (uint32_t i=0;i<t->n_buckets;i++) {
            for (ip_fwd_entry_t *e=t->buckets[i];e;e=e->next) {
                char ps[INET6_ADDRSTRLEN+4];
                ip_prefix_to_str(&e->prefix,ps,sizeof(ps));
                pos += snprintf(buf+pos,left-pos,
                    "%s{\"prefix\":\"%s\",\"ad\":%u,\"metric\":%u,"
                    "\"ecmp_hash_mode\":%u,\"n_paths\":%u,\"hits\":%llu,"
                    "\"paths\":[",
                    first?"":",", ps, e->ad, e->metric,
                    e->ecmp_hash_mode, e->n_paths,
                    (unsigned long long)e->hit_count);
                first=false;
                for (uint8_t p=0;p<e->n_paths;p++) {
                    char nhbuf[256];
                    nh_to_json(&e->paths[p],nhbuf,sizeof(nhbuf));
                    pos += snprintf(buf+pos,left-pos,"%s%s",
                                    p?",":"", nhbuf);
                }
                pos += snprintf(buf+pos,left-pos,"]}");
                if (pos+1024>=left) goto done;
            }
        }
        pthread_rwlock_unlock(&t->lock);
        continue;
done:
        pthread_rwlock_unlock(&t->lock);
        break;
    }
    snprintf(buf+pos,left-pos,"]}\n");
    return buf;
}

static char *handle_lookup(ip_ctx_t *ctx, const char *req)
{
    char dst_str[INET6_ADDRSTRLEN]={0};
    if (!jstr(req,"dst",dst_str,sizeof(dst_str)))
        return err_json("missing dst");
    ip_addr_t dst;
    if (ip_addr_parse(dst_str,&dst)!=IP_OK) return err_json("invalid dst");

    /* Optional flow fields */
    ip_flow_key_t flow={0};
    bool has_flow=false;
    char src_str[INET6_ADDRSTRLEN]={0};
    if (jstr(req,"src",src_str,sizeof(src_str)) &&
        ip_addr_parse(src_str,&flow.src)==IP_OK) {
        flow.dst = dst;
        long sp=jint(req,"src_port"); if (sp>=0) flow.src_port=(uint16_t)sp;
        long dp=jint(req,"dst_port"); if (dp>=0) flow.dst_port=(uint16_t)dp;
        long pr=jint(req,"proto");    if (pr>=0) flow.proto   =(uint8_t)pr;
        has_flow=true;
    }

    ip_fwd_entry_t entry; ip_nexthop_t path;
    int rc = ip_fwd_lookup(ctx,&dst, has_flow ? &flow : NULL, &entry, &path);
    if (rc!=IP_OK) return err_json("no route");

    char ps[INET6_ADDRSTRLEN+4], nhbuf[256];
    ip_prefix_to_str(&entry.prefix,ps,sizeof(ps));
    nh_to_json(&path,nhbuf,sizeof(nhbuf));

    char *buf=malloc(1024);
    if (!buf) return err_json("oom");
    snprintf(buf,1024,
             "{\"status\":\"ok\",\"prefix\":\"%s\","
             "\"ad\":%u,\"metric\":%u,\"n_paths\":%u,"
             "\"selected_path\":%s}\n",
             ps, entry.ad, entry.metric, entry.n_paths, nhbuf);
    return buf;
}

static char *handle_set_ecmp_hash(ip_ctx_t *ctx, const char *req)
{
    /* If prefix provided, set per-prefix mode; else set global default */
    char pfx_str[INET6_ADDRSTRLEN+4]={0};
    long mode_l = jint(req,"mode");
    if (mode_l<0) return err_json("missing mode");
    uint32_t mode=(uint32_t)mode_l;

    if (jstr(req,"prefix",pfx_str,sizeof(pfx_str))) {
        ip_prefix_t pfx;
        if (ip_prefix_parse(pfx_str,&pfx)!=IP_OK) return err_json("invalid prefix");
        int rc = ip_set_ecmp_hash(ctx,&pfx,mode);
        return rc==IP_OK ? ok_json() : err_json("prefix not found");
    }
    /* global default */
    pthread_rwlock_wrlock(&ctx->cfg.lock);
    ctx->cfg.ecmp_hash_mode=mode;
    pthread_rwlock_unlock(&ctx->cfg.lock);
    return ok_json();
}

static char *handle_set_forwarding(ip_ctx_t *ctx, const char *req)
{
    char af_str[8]={0};
    jstr(req,"af",af_str,sizeof(af_str));
    sa_family_t af = strcmp(af_str,"ipv6")==0 ? AF_INET6 : AF_INET;
    ip_set_forwarding(ctx,af,jbool(req,"enable"));
    return ok_json();
}

static char *handle_get_forwarding(ip_ctx_t *ctx)
{
    bool v4=ip_get_forwarding(ctx,AF_INET), v6=ip_get_forwarding(ctx,AF_INET6);
    pthread_rwlock_rdlock(&ctx->cfg.lock);
    uint32_t flags=ctx->cfg.flags, hmode=ctx->cfg.ecmp_hash_mode;
    uint8_t ttl=ctx->cfg.default_ttl, hl=ctx->cfg.default_hop_limit;
    pthread_rwlock_unlock(&ctx->cfg.lock);
    char *buf=malloc(512);
    snprintf(buf,512,
             "{\"status\":\"ok\",\"ipv4_forwarding\":%s,"
             "\"ipv6_forwarding\":%s,\"flags\":%u,"
             "\"default_ttl\":%u,\"default_hop_limit\":%u,"
             "\"ecmp_hash_mode\":%u}\n",
             v4?"true":"false",v6?"true":"false",
             flags,ttl,hl,hmode);
    return buf;
}

static char *handle_get_stats(ip_ctx_t *ctx, const char *req)
{
    char af_str[8]={0};
    jstr(req,"af",af_str,sizeof(af_str));
    sa_family_t af=strcmp(af_str,"ipv6")==0?AF_INET6:AF_INET;
    ip_stats_t s; ip_stats_get(ctx,af,&s);
    char *buf=malloc(1024);
    snprintf(buf,1024,
             "{\"status\":\"ok\",\"af\":\"%s\","
             "\"rx_pkts\":%llu,\"tx_pkts\":%llu,\"fwd_pkts\":%llu,"
             "\"rx_bytes\":%llu,\"tx_bytes\":%llu,"
             "\"rx_drop_ttl\":%llu,\"rx_drop_noroute\":%llu,"
             "\"rx_drop_martian\":%llu,\"rx_drop_rpf\":%llu,"
             "\"rx_errors\":%llu,\"tx_errors\":%llu}\n",
             af==AF_INET?"ipv4":"ipv6",
             (unsigned long long)s.rx_pkts,(unsigned long long)s.tx_pkts,
             (unsigned long long)s.fwd_pkts,
             (unsigned long long)s.rx_bytes,(unsigned long long)s.tx_bytes,
             (unsigned long long)s.rx_drop_ttl,
             (unsigned long long)s.rx_drop_noroute,
             (unsigned long long)s.rx_drop_martian,
             (unsigned long long)s.rx_drop_rpf,
             (unsigned long long)s.rx_errors,
             (unsigned long long)s.tx_errors);
    return buf;
}

/* -----------------------------------------------------------------------
 * Dispatch
 * --------------------------------------------------------------------- */
char *ip_ipc_handle(ip_ctx_t *ctx, const char *req, size_t req_len)
{
    (void)req_len;
    char cmd[64]={0};
    jstr(req,"cmd",cmd,sizeof(cmd));

    if (!strcmp(cmd,IP_CMD_ADD_ADDR))     return handle_add_addr(ctx,req);
    if (!strcmp(cmd,IP_CMD_DEL_ADDR))     return handle_del_addr(ctx,req);
    if (!strcmp(cmd,IP_CMD_LIST_ADDRS))   return handle_list_addrs(ctx,req);
    if (!strcmp(cmd,IP_CMD_LIST_IFS))     return handle_list_interfaces(ctx);
    if (!strcmp(cmd,IP_CMD_ADD_ROUTE))    return handle_add_route(ctx,req);
    if (!strcmp(cmd,IP_CMD_ADD_NEXTHOP))  return handle_add_nexthop(ctx,req);
    if (!strcmp(cmd,IP_CMD_DEL_NEXTHOP))  return handle_del_nexthop(ctx,req);
    if (!strcmp(cmd,IP_CMD_DEL_ROUTE))    return handle_del_route(ctx,req);
    if (!strcmp(cmd,IP_CMD_LIST_ROUTES))  return handle_list_routes(ctx,req);
    if (!strcmp(cmd,IP_CMD_LOOKUP))       return handle_lookup(ctx,req);
    if (!strcmp(cmd,IP_CMD_SET_ECMP_HASH))return handle_set_ecmp_hash(ctx,req);
    if (!strcmp(cmd,IP_CMD_SET_FWD))      return handle_set_forwarding(ctx,req);
    if (!strcmp(cmd,IP_CMD_GET_FWD))      return handle_get_forwarding(ctx);
    if (!strcmp(cmd,IP_CMD_GET_STATS))    return handle_get_stats(ctx,req);
    if (!strcmp(cmd,IP_CMD_CLEAR_STATS)) {
        char af_str[8]={0}; jstr(req,"af",af_str,sizeof(af_str));
        ip_stats_clear(ctx, strcmp(af_str,"ipv6")==0?AF_INET6:AF_INET);
        return ok_json();
    }
    if (!strcmp(cmd,IP_CMD_SET_IF_FWD)) {
        long idx=jint(req,"ifindex"); if (idx<0) return err_json("missing ifindex");
        char af_str[8]={0}; jstr(req,"af",af_str,sizeof(af_str));
        sa_family_t af=strcmp(af_str,"ipv6")==0?AF_INET6:AF_INET;
        int rc=ip_set_if_forwarding(ctx,(uint32_t)idx,af,jbool(req,"enable"));
        return rc==IP_OK ? ok_json() : err_json("interface not found");
    }
    if (!strcmp(cmd,IP_CMD_DUMP_CONFIG)) {
        char path[256]="ip_runtime_config.json";
        jstr(req,"path",path,sizeof(path));
        char *buf=malloc(512);
        snprintf(buf,512,"{\"status\":\"%s\",\"path\":\"%s\"}\n",
                 ip_save_config(ctx,path)==IP_OK?"ok":"error", path);
        return buf;
    }
    if (!strcmp(cmd,IP_CMD_LOAD_CONFIG)) {
        char path[256]="ip_runtime_config.json";
        jstr(req,"path",path,sizeof(path));
        return ip_load_config(ctx,path)==IP_OK ? ok_json() : err_json("load failed");
    }
    if (!strcmp(cmd,"get")) {
        char key[64]={0}; jstr(req,"key",key,sizeof(key));
        bool v4=ip_get_forwarding(ctx,AF_INET), v6=ip_get_forwarding(ctx,AF_INET6);
        pthread_rwlock_rdlock(&ctx->cfg.lock);
        uint32_t hmode=ctx->cfg.ecmp_hash_mode;
        uint8_t ttl=ctx->cfg.default_ttl;
        pthread_rwlock_unlock(&ctx->cfg.lock);
        char *buf=malloc(128);
        if (!strcmp(key,"IPV4_FWD"))
            snprintf(buf,128,"{\"status\":\"ok\",\"value\":\"%s\"}\n",v4?"true":"false");
        else if (!strcmp(key,"IPV6_FWD"))
            snprintf(buf,128,"{\"status\":\"ok\",\"value\":\"%s\"}\n",v6?"true":"false");
        else if (!strcmp(key,"ECMP_HASH_MODE"))
            snprintf(buf,128,"{\"status\":\"ok\",\"value\":\"%u\"}\n",hmode);
        else if (!strcmp(key,"DEFAULT_TTL"))
            snprintf(buf,128,"{\"status\":\"ok\",\"value\":\"%u\"}\n",ttl);
        else { free(buf); return err_json("unknown key"); }
        return buf;
    }
    if (!strcmp(cmd,"set")) {
        char key[64]={0}, val[64]={0};
        jstr(req,"key",key,sizeof(key)); jstr(req,"value",val,sizeof(val));
        if (!strcmp(key,"IPV4_FWD")) {
            ip_set_forwarding(ctx,AF_INET,strcmp(val,"false")!=0&&strcmp(val,"0")!=0);
            return ok_json();
        }
        if (!strcmp(key,"IPV6_FWD")) {
            ip_set_forwarding(ctx,AF_INET6,strcmp(val,"false")!=0&&strcmp(val,"0")!=0);
            return ok_json();
        }
        if (!strcmp(key,"ECMP_HASH_MODE")) {
            long v=atol(val); if (v<0) return err_json("invalid value");
            pthread_rwlock_wrlock(&ctx->cfg.lock);
            ctx->cfg.ecmp_hash_mode=(uint32_t)v;
            pthread_rwlock_unlock(&ctx->cfg.lock);
            return ok_json();
        }
        if (!strcmp(key,"DEFAULT_TTL")) {
            long v=atol(val); if (v<1||v>255) return err_json("value out of range");
            pthread_rwlock_wrlock(&ctx->cfg.lock);
            ctx->cfg.default_ttl=(uint8_t)v;
            pthread_rwlock_unlock(&ctx->cfg.lock);
            return ok_json();
        }
        return err_json("unknown key");
    }
    if (!strcmp(cmd,"ping")) return strdup("{\"status\":\"ok\",\"msg\":\"pong\",\"module\":\"ip\"}\n");
    return err_json("unknown command");
}

/* -----------------------------------------------------------------------
 * IPC server
 * --------------------------------------------------------------------- */
int ip_ipc_init(ip_ctx_t *ctx)
{
    struct sockaddr_un addr={0};
    addr.sun_family=AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%.*s",
             (int)(sizeof(addr.sun_path)-1), ctx->sock_path);
    unlink(ctx->sock_path);
    ctx->sock_fd=socket(AF_UNIX,SOCK_STREAM,0);
    if (ctx->sock_fd<0) return IP_ERR_INVAL;
    if (bind(ctx->sock_fd,(struct sockaddr*)&addr,sizeof(addr))<0 ||
        listen(ctx->sock_fd,16)<0) {
        close(ctx->sock_fd); ctx->sock_fd=-1; return IP_ERR_INVAL;
    }
    return IP_OK;
}

void ip_ipc_stop(ip_ctx_t *ctx)
{
    if (ctx->sock_fd>=0) { close(ctx->sock_fd); ctx->sock_fd=-1; }
    unlink(ctx->sock_path);
}

void *ip_ipc_thread(void *arg)
{
    ip_ctx_t *ctx=arg;
    char buf[IP_IPC_MAX_MSG];
    while (ctx->running) {
        int client=accept(ctx->sock_fd,NULL,NULL);
        if (client<0) { if (!ctx->running) break; continue; }
        ssize_t n=recv(client,buf,sizeof(buf)-1,0);
        if (n>0) {
            buf[n]='\0';
            char *resp=ip_ipc_handle(ctx,buf,(size_t)n);
            if (resp) { send(client,resp,strlen(resp),0); free(resp); }
        }
        close(client);
    }
    return NULL;
}
