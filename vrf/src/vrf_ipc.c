/*
 * vrf_ipc.c — VRF IPC server with ECMP commands.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <arpa/inet.h>

#include "vrf.h"
#include "vrf_ipc.h"

static char *ok_json(void){return strdup("{\"status\":\"ok\"}\n");}
static char *err_json(const char *m){
    char b[512]; snprintf(b,sizeof(b),"{\"status\":\"error\",\"message\":\"%s\"}\n",m);
    return strdup(b);}

static const char *jstr(const char *l,const char *k,char *o,size_t ol){
    char s[128]; snprintf(s,sizeof(s),"\"%s\":\"",k);
    const char *p=strstr(l,s); if(!p) return NULL; p+=strlen(s);
    size_t i=0; while(*p&&*p!='"'&&i+1<ol) o[i++]=*p++; o[i]='\0'; return o;}
static long long jll(const char *l,const char *k){
    char s[128]; snprintf(s,sizeof(s),"\"%s\":",k);
    const char *p=strstr(l,s); if(!p) return -1;
    p+=strlen(s); if(*p=='"') p++;
    return strtoll(p,NULL,10);}

static int nh_to_json_vrf(const vrf_nexthop_t *nh,char *buf,size_t len){
    char nhstr[INET6_ADDRSTRLEN]="::";
    vrf_addr_to_str(&nh->addr,nhstr,sizeof(nhstr));
    return snprintf(buf,len,"{\"nexthop\":\"%s\",\"ifindex\":%u,"
        "\"weight\":%u,\"active\":%s,\"hits\":%llu}",
        nhstr,nh->ifindex,nh->weight,nh->active?"true":"false",
        (unsigned long long)nh->hit_count);}

static bool parse_nh_vrf(const char *req,vrf_addr_t *nh,uint32_t *oif){
    char nhstr[INET6_ADDRSTRLEN]={0};
    if (!jstr(req,"nexthop",nhstr,sizeof(nhstr))) return false;
    if (vrf_addr_parse(nhstr,nh)!=VRF_OK) return false;
    long long idx=jll(req,"ifindex"); if (idx<0) return false;
    *oif=(uint32_t)idx; return true;}

/* handlers */
static char *h_create(vrf_ctx_t *ctx,const char *req){
    char name[VRF_NAME_MAX]={0};
    if (!jstr(req,"name",name,sizeof(name))) return err_json("missing name");
    long long id=jll(req,"id"); if (id<0) return err_json("missing id");
    uint32_t flags=(uint32_t)jll(req,"flags");
    uint32_t tid=(uint32_t)jll(req,"table_id");
    long long rdl=jll(req,"rd"); uint64_t rd=rdl>=0?(uint64_t)rdl:0;
    int rc=vrf_create(ctx,(uint32_t)id,name,flags,tid,rd);
    if (rc==VRF_ERR_EXISTS) return err_json("already exists");
    if (rc==VRF_ERR_FULL)   return err_json("table full");
    return rc==VRF_OK?ok_json():err_json("failed");}

static char *h_delete(vrf_ctx_t *ctx,const char *req){
    long long id=jll(req,"id"); if (id<0) return err_json("missing id");
    int rc=vrf_delete(ctx,(uint32_t)id);
    if (rc==VRF_ERR_NOTFOUND) return err_json("not found");
    if (rc==VRF_ERR_INVAL)    return err_json("cannot delete default");
    return rc==VRF_OK?ok_json():err_json("failed");}

static char *h_list(vrf_ctx_t *ctx){
    char *buf=malloc(VRF_IPC_MAX_MSG); if (!buf) return err_json("oom");
    size_t pos=0,left=VRF_IPC_MAX_MSG;
    pos+=snprintf(buf+pos,left-pos,"{\"status\":\"ok\",\"vrfs\":[");
    bool first=true;
    pthread_rwlock_rdlock(&ctx->vrf_table.lock);
    for (uint32_t i=0;i<ctx->vrf_table.n_buckets;i++)
        for (vrf_instance_t *v=ctx->vrf_table.buckets[i];v;v=v->next) {
            pthread_rwlock_rdlock(&v->lock);
            pos+=snprintf(buf+pos,left-pos,
                "%s{\"id\":%u,\"name\":\"%s\",\"flags\":%u,"
                "\"table_id\":%u,\"rd\":%llu,\"n_ifaces\":%u,"
                "\"routes_v4\":%u,\"routes_v6\":%u,"
                "\"ecmp_hash_mode\":%u,"
                "\"fwd_pkts\":%llu,\"drop_noroute\":%llu}",
                first?"":",",v->id,v->name,v->flags,v->table_id,
                (unsigned long long)v->rd,v->n_ifaces,
                v->fib4.n_routes,v->fib6.n_routes,v->ecmp_hash_mode,
                (unsigned long long)v->fwd_pkts,
                (unsigned long long)v->drop_noroute);
            first=false;
            pthread_rwlock_unlock(&v->lock);
        }
    pthread_rwlock_unlock(&ctx->vrf_table.lock);
    snprintf(buf+pos,left-pos,"]}\n"); return buf;}

static char *h_get(vrf_ctx_t *ctx,const char *req){
    char nb[VRF_NAME_MAX]={0}; vrf_instance_t *v=NULL;
    long long id=jll(req,"id");
    if (id>=0) v=vrf_find(ctx,(uint32_t)id);
    else if (jstr(req,"name",nb,sizeof(nb))) v=vrf_find_by_name(ctx,nb);
    if (!v) return err_json("not found");
    char *buf=malloc(1024); if (!buf) return err_json("oom");
    pthread_rwlock_rdlock(&v->lock);
    snprintf(buf,1024,"{\"status\":\"ok\",\"id\":%u,\"name\":\"%s\","
        "\"flags\":%u,\"table_id\":%u,\"rd\":%llu,"
        "\"n_ifaces\":%u,\"n_leaks_out\":%u,"
        "\"routes_v4\":%u,\"routes_v6\":%u,"
        "\"ecmp_hash_mode\":%u,"
        "\"fwd_pkts\":%llu,\"drop_noroute\":%llu}\n",
        v->id,v->name,v->flags,v->table_id,(unsigned long long)v->rd,
        v->n_ifaces,v->n_leaks_out,v->fib4.n_routes,v->fib6.n_routes,
        v->ecmp_hash_mode,
        (unsigned long long)v->fwd_pkts,(unsigned long long)v->drop_noroute);
    pthread_rwlock_unlock(&v->lock); return buf;}

static char *h_bind_if(vrf_ctx_t *ctx,const char *req){
    long long id=jll(req,"vrf_id"),ifidx=jll(req,"ifindex");
    if (id<0||ifidx<0) return err_json("missing vrf_id or ifindex");
    char ifname[IFNAMSIZ]={0}; jstr(req,"ifname",ifname,sizeof(ifname));
    if (!ifname[0]) snprintf(ifname,sizeof(ifname),"if%u",(uint32_t)ifidx);
    int rc=vrf_bind_if(ctx,(uint32_t)id,(uint32_t)ifidx,ifname);
    if (rc==VRF_ERR_NOTFOUND) return err_json("VRF not found");
    if (rc==VRF_ERR_BOUND)    return err_json("already bound");
    return rc==VRF_OK?ok_json():err_json("failed");}

static char *h_unbind_if(vrf_ctx_t *ctx,const char *req){
    long long ifidx=jll(req,"ifindex"); if (ifidx<0) return err_json("missing ifindex");
    return vrf_unbind_if(ctx,(uint32_t)ifidx)==VRF_OK?ok_json():err_json("not bound");}

static char *h_list_ifs(vrf_ctx_t *ctx,const char *req){
    long long idf=jll(req,"vrf_id");
    char *buf=malloc(VRF_IPC_MAX_MSG); if (!buf) return err_json("oom");
    size_t pos=0,left=VRF_IPC_MAX_MSG;
    pos+=snprintf(buf+pos,left-pos,"{\"status\":\"ok\",\"interfaces\":[");
    bool first=true;
    pthread_rwlock_rdlock(&ctx->vrf_table.lock);
    for (uint32_t i=0;i<ctx->vrf_table.n_buckets;i++)
        for (vrf_instance_t *v=ctx->vrf_table.buckets[i];v;v=v->next) {
            if (idf>=0&&v->id!=(uint32_t)idf) continue;
            pthread_rwlock_rdlock(&v->lock);
            for (vrf_if_binding_t *b=v->ifaces;b;b=b->next) {
                pos+=snprintf(buf+pos,left-pos,
                    "%s{\"vrf_id\":%u,\"ifindex\":%u,\"ifname\":\"%s\"}",
                    first?"":",",v->id,b->ifindex,b->ifname);
                first=false;
            }
            pthread_rwlock_unlock(&v->lock);
        }
    pthread_rwlock_unlock(&ctx->vrf_table.lock);
    snprintf(buf+pos,left-pos,"]}\n"); return buf;}

static char *h_get_if_vrf(vrf_ctx_t *ctx,const char *req){
    long long ifidx=jll(req,"ifindex"); if (ifidx<0) return err_json("missing ifindex");
    uint32_t vid=vrf_if_lookup(ctx,(uint32_t)ifidx);
    if (vid==VRF_ID_INVALID) return err_json("not bound");
    char *buf=malloc(128); snprintf(buf,128,"{\"status\":\"ok\",\"vrf_id\":%u}\n",vid);
    return buf;}

static char *h_add_route(vrf_ctx_t *ctx,const char *req){
    char ps[INET6_ADDRSTRLEN+4]={0};
    long long vid=jll(req,"vrf_id");
    if (vid<0||!jstr(req,"prefix",ps,sizeof(ps))) return err_json("missing vrf_id or prefix");
    vrf_prefix_t pfx; if (vrf_prefix_parse(ps,&pfx)!=VRF_OK) return err_json("invalid prefix");
    vrf_addr_t nh={0}; uint32_t oif=0;
    if (!parse_nh_vrf(req,&nh,&oif)){nh.af=pfx.addr.af;long long ii=jll(req,"ifindex");if(ii>=0)oif=(uint32_t)ii;}
    uint8_t  ad=(uint8_t)(jll(req,"ad")>=0?jll(req,"ad"):VRF_AD_STATIC);
    long long ml=jll(req,"metric"); uint32_t metric=ml>=0?(uint32_t)ml:0;
    long long wl=jll(req,"weight"); uint32_t weight=wl>0?(uint32_t)wl:1;
    int rc=vrf_route_add(ctx,(uint32_t)vid,&pfx,&nh,oif,ad,metric,weight);
    if (rc==VRF_ERR_NOTFOUND) return err_json("VRF not found");
    if (rc==VRF_ERR_FULL)     return err_json("FIB full");
    return rc==VRF_OK?ok_json():err_json("failed");}

static char *h_add_nexthop(vrf_ctx_t *ctx,const char *req){
    char ps[INET6_ADDRSTRLEN+4]={0};
    long long vid=jll(req,"vrf_id");
    if (vid<0||!jstr(req,"prefix",ps,sizeof(ps))) return err_json("missing vrf_id or prefix");
    vrf_prefix_t pfx; if (vrf_prefix_parse(ps,&pfx)!=VRF_OK) return err_json("invalid prefix");
    vrf_addr_t nh={0}; uint32_t oif=0;
    if (!parse_nh_vrf(req,&nh,&oif)) return err_json("missing nexthop or ifindex");
    long long wl=jll(req,"weight"); uint32_t weight=wl>0?(uint32_t)wl:1;
    int rc=vrf_nexthop_add(ctx,(uint32_t)vid,&pfx,&nh,oif,weight);
    if (rc==VRF_ERR_NOTFOUND) return err_json("prefix not found");
    if (rc==VRF_ERR_FULL)     return err_json("group full");
    return rc==VRF_OK?ok_json():err_json("failed");}

static char *h_del_nexthop(vrf_ctx_t *ctx,const char *req){
    char ps[INET6_ADDRSTRLEN+4]={0};
    long long vid=jll(req,"vrf_id");
    if (vid<0||!jstr(req,"prefix",ps,sizeof(ps))) return err_json("missing vrf_id or prefix");
    vrf_prefix_t pfx; if (vrf_prefix_parse(ps,&pfx)!=VRF_OK) return err_json("invalid prefix");
    vrf_addr_t nh={0}; uint32_t oif=0;
    if (!parse_nh_vrf(req,&nh,&oif)) return err_json("missing nexthop or ifindex");
    return vrf_nexthop_del(ctx,(uint32_t)vid,&pfx,&nh,oif)==VRF_OK
           ?ok_json():err_json("not found");}

static char *h_del_route(vrf_ctx_t *ctx,const char *req){
    char ps[INET6_ADDRSTRLEN+4]={0};
    long long vid=jll(req,"vrf_id");
    if (vid<0||!jstr(req,"prefix",ps,sizeof(ps))) return err_json("missing vrf_id or prefix");
    vrf_prefix_t pfx; if (vrf_prefix_parse(ps,&pfx)!=VRF_OK) return err_json("invalid prefix");
    return vrf_route_del(ctx,(uint32_t)vid,&pfx)==VRF_OK?ok_json():err_json("not found");}

static char *h_list_routes(vrf_ctx_t *ctx,const char *req){
    long long vidf=jll(req,"vrf_id");
    char afs[8]={0}; jstr(req,"af",afs,sizeof(afs));
    int afi=strcmp(afs,"ipv4")==0?AF_INET:strcmp(afs,"ipv6")==0?AF_INET6:0;
    char *buf=malloc(VRF_IPC_MAX_MSG); if (!buf) return err_json("oom");
    size_t pos=0,left=VRF_IPC_MAX_MSG;
    pos+=snprintf(buf+pos,left-pos,"{\"status\":\"ok\",\"routes\":[");
    bool first=true;
    pthread_rwlock_rdlock(&ctx->vrf_table.lock);
    for (uint32_t i=0;i<ctx->vrf_table.n_buckets;i++)
        for (vrf_instance_t *v=ctx->vrf_table.buckets[i];v;v=v->next) {
            if (vidf>=0&&v->id!=(uint32_t)vidf) continue;
            for (int a=0;a<2;a++) {
                int caf=a==0?AF_INET:AF_INET6;
                if (afi&&afi!=caf) continue;
                vrf_fib_t *fib=a==0?&v->fib4:&v->fib6;
                pthread_rwlock_rdlock(&fib->lock);
                for (uint32_t bi=0;bi<fib->n_buckets;bi++)
                    for (vrf_route_t *r=fib->buckets[bi];r;r=r->next) {
                        char ps2[INET6_ADDRSTRLEN+4];
                        vrf_prefix_to_str(&r->prefix,ps2,sizeof(ps2));
                        pos+=snprintf(buf+pos,left-pos,
                            "%s{\"vrf_id\":%u,\"prefix\":\"%s\","
                            "\"ad\":%u,\"metric\":%u,\"src_vrf\":%u,"
                            "\"ecmp_hash_mode\":%u,\"n_paths\":%u,"
                            "\"hits\":%llu,\"paths\":[",
                            first?"":",",v->id,ps2,r->ad,r->metric,
                            r->src_vrf_id,r->ecmp_hash_mode,r->n_paths,
                            (unsigned long long)r->hit_count);
                        first=false;
                        for (uint8_t p=0;p<r->n_paths;p++) {
                            char nhb[256]; nh_to_json_vrf(&r->paths[p],nhb,sizeof(nhb));
                            pos+=snprintf(buf+pos,left-pos,"%s%s",p?",":"",nhb);
                        }
                        pos+=snprintf(buf+pos,left-pos,"]}");
                        if (pos+1024>=left) goto done;
                    }
                pthread_rwlock_unlock(&fib->lock); continue;
done:           pthread_rwlock_unlock(&fib->lock); goto outer_done;
            }
        }
outer_done:
    pthread_rwlock_unlock(&ctx->vrf_table.lock);
    snprintf(buf+pos,left-pos,"]}\n"); return buf;}

static char *h_lookup(vrf_ctx_t *ctx,const char *req){
    char ds[INET6_ADDRSTRLEN]={0};
    long long vid=jll(req,"vrf_id");
    if (vid<0||!jstr(req,"dst",ds,sizeof(ds))) return err_json("missing vrf_id or dst");
    vrf_addr_t dst; if (vrf_addr_parse(ds,&dst)!=VRF_OK) return err_json("invalid dst");
    vrf_flow_key_t flow={0}; bool has_flow=false;
    char ss[INET6_ADDRSTRLEN]={0};
    if (jstr(req,"src",ss,sizeof(ss))&&vrf_addr_parse(ss,&flow.src)==VRF_OK) {
        flow.dst=dst;
        long long sp=jll(req,"src_port");if(sp>=0)flow.src_port=(uint16_t)sp;
        long long dp=jll(req,"dst_port");if(dp>=0)flow.dst_port=(uint16_t)dp;
        long long pr=jll(req,"proto");  if(pr>=0)flow.proto=(uint8_t)pr;
        has_flow=true;
    }
    vrf_route_t entry; vrf_nexthop_t path;
    if (vrf_route_lookup(ctx,(uint32_t)vid,&dst,has_flow?&flow:NULL,&entry,&path)!=VRF_OK)
        return err_json("no route");
    char ps[INET6_ADDRSTRLEN+4],nhb[256];
    vrf_prefix_to_str(&entry.prefix,ps,sizeof(ps));
    nh_to_json_vrf(&path,nhb,sizeof(nhb));
    char *buf=malloc(1024);
    snprintf(buf,1024,"{\"status\":\"ok\",\"prefix\":\"%s\","
        "\"ad\":%u,\"metric\":%u,\"n_paths\":%u,"
        "\"selected_path\":%s}\n",
        ps,entry.ad,entry.metric,entry.n_paths,nhb);
    return buf;}

static char *h_set_ecmp_hash(vrf_ctx_t *ctx,const char *req){
    long long vid=jll(req,"vrf_id"),ml=jll(req,"mode");
    if (ml<0) return err_json("missing mode");
    uint32_t mode=(uint32_t)ml;
    char ps[INET6_ADDRSTRLEN+4]={0};
    if (vid>=0&&jstr(req,"prefix",ps,sizeof(ps))) {
        vrf_prefix_t pfx; if (vrf_prefix_parse(ps,&pfx)!=VRF_OK) return err_json("invalid prefix");
        int rc=vrf_set_ecmp_hash(ctx,(uint32_t)vid,&pfx,mode);
        return rc==VRF_OK?ok_json():err_json("prefix not found");
    }
    if (vid>=0) { /* set per-VRF default */
        vrf_instance_t *v=vrf_find(ctx,(uint32_t)vid);
        if (!v) return err_json("VRF not found");
        pthread_rwlock_wrlock(&v->lock); v->ecmp_hash_mode=mode;
        pthread_rwlock_unlock(&v->lock); return ok_json();
    }
    return err_json("missing vrf_id");}

static char *h_leak(vrf_ctx_t *ctx,const char *req){
    char ps[INET6_ADDRSTRLEN+4]={0};
    long long src=jll(req,"src_vrf_id"),dst=jll(req,"dst_vrf_id");
    if (src<0||dst<0||!jstr(req,"prefix",ps,sizeof(ps))) return err_json("missing fields");
    vrf_prefix_t pfx; if (vrf_prefix_parse(ps,&pfx)!=VRF_OK) return err_json("invalid prefix");
    vrf_addr_t nh={0}; uint32_t oif=0;
    if (!parse_nh_vrf(req,&nh,&oif)){nh.af=pfx.addr.af;long long ii=jll(req,"ifindex");if(ii>=0)oif=(uint32_t)ii;}
    long long ml=jll(req,"metric"); uint32_t metric=ml>=0?(uint32_t)ml:0;
    int rc=vrf_leak_route(ctx,(uint32_t)src,(uint32_t)dst,&pfx,&nh,oif,metric);
    if (rc==VRF_ERR_NOTFOUND) return err_json("src or dst VRF not found");
    if (rc==VRF_ERR_LOOP)     return err_json("same VRF");
    return rc==VRF_OK?ok_json():err_json("failed");}

static char *h_unleak(vrf_ctx_t *ctx,const char *req){
    char ps[INET6_ADDRSTRLEN+4]={0};
    long long src=jll(req,"src_vrf_id"),dst=jll(req,"dst_vrf_id");
    if (src<0||dst<0||!jstr(req,"prefix",ps,sizeof(ps))) return err_json("missing fields");
    vrf_prefix_t pfx; if (vrf_prefix_parse(ps,&pfx)!=VRF_OK) return err_json("invalid prefix");
    return vrf_unleak_route(ctx,(uint32_t)src,(uint32_t)dst,&pfx)==VRF_OK
           ?ok_json():err_json("failed");}

static char *h_list_leaks(vrf_ctx_t *ctx,const char *req){
    long long vidf=jll(req,"vrf_id");
    char *buf=malloc(VRF_IPC_MAX_MSG); if (!buf) return err_json("oom");
    size_t pos=0,left=VRF_IPC_MAX_MSG;
    pos+=snprintf(buf+pos,left-pos,"{\"status\":\"ok\",\"leaks\":[");
    bool first=true;
    pthread_rwlock_rdlock(&ctx->vrf_table.lock);
    for (uint32_t i=0;i<ctx->vrf_table.n_buckets;i++)
        for (vrf_instance_t *v=ctx->vrf_table.buckets[i];v;v=v->next) {
            if (vidf>=0&&v->id!=(uint32_t)vidf) continue;
            pthread_rwlock_rdlock(&v->lock);
            for (vrf_leak_t *lk=v->leaks_out;lk;lk=lk->next) {
                char ps[INET6_ADDRSTRLEN+4],nh[INET6_ADDRSTRLEN];
                vrf_prefix_to_str(&lk->prefix,ps,sizeof(ps));
                vrf_addr_to_str(&lk->nexthop,nh,sizeof(nh));
                pos+=snprintf(buf+pos,left-pos,
                    "%s{\"src_vrf\":%u,\"dst_vrf\":%u,"
                    "\"prefix\":\"%s\",\"nexthop\":\"%s\","
                    "\"ifindex\":%u,\"metric\":%u}",
                    first?"":",",lk->src_vrf_id,lk->dst_vrf_id,
                    ps,nh,lk->out_ifindex,lk->metric);
                first=false;
            }
            pthread_rwlock_unlock(&v->lock);
        }
    pthread_rwlock_unlock(&ctx->vrf_table.lock);
    snprintf(buf+pos,left-pos,"]}\n"); return buf;}

static char *h_get_stats(vrf_ctx_t *ctx,const char *req){
    long long id=jll(req,"vrf_id"); if (id<0) return err_json("missing vrf_id");
    vrf_instance_t *v=vrf_find(ctx,(uint32_t)id); if (!v) return err_json("not found");
    char *buf=malloc(512); if (!buf) return err_json("oom");
    pthread_rwlock_rdlock(&v->lock);
    snprintf(buf,512,"{\"status\":\"ok\",\"vrf_id\":%u,"
        "\"rx_pkts\":%llu,\"tx_pkts\":%llu,\"fwd_pkts\":%llu,"
        "\"drop_noroute\":%llu,\"drop_rpf\":%llu}\n",
        v->id,(unsigned long long)v->rx_pkts,(unsigned long long)v->tx_pkts,
        (unsigned long long)v->fwd_pkts,(unsigned long long)v->drop_noroute,
        (unsigned long long)v->drop_rpf);
    pthread_rwlock_unlock(&v->lock); return buf;}

static char *h_clear_stats(vrf_ctx_t *ctx,const char *req){
    long long id=jll(req,"vrf_id"); if (id<0) return err_json("missing vrf_id");
    vrf_instance_t *v=vrf_find(ctx,(uint32_t)id); if (!v) return err_json("not found");
    pthread_rwlock_wrlock(&v->lock);
    v->rx_pkts=v->tx_pkts=v->fwd_pkts=v->drop_noroute=v->drop_rpf=0;
    pthread_rwlock_unlock(&v->lock); return ok_json();}

char *vrf_ipc_handle(vrf_ctx_t *ctx,const char *req,size_t req_len){
    (void)req_len; char cmd[64]={0}; jstr(req,"cmd",cmd,sizeof(cmd));
    if (!strcmp(cmd,VRF_CMD_CREATE))       return h_create(ctx,req);
    if (!strcmp(cmd,VRF_CMD_DELETE))       return h_delete(ctx,req);
    if (!strcmp(cmd,VRF_CMD_LIST))         return h_list(ctx);
    if (!strcmp(cmd,VRF_CMD_GET))          return h_get(ctx,req);
    if (!strcmp(cmd,VRF_CMD_BIND_IF))      return h_bind_if(ctx,req);
    if (!strcmp(cmd,VRF_CMD_UNBIND_IF))    return h_unbind_if(ctx,req);
    if (!strcmp(cmd,VRF_CMD_LIST_IFS))     return h_list_ifs(ctx,req);
    if (!strcmp(cmd,VRF_CMD_GET_IF_VRF))   return h_get_if_vrf(ctx,req);
    if (!strcmp(cmd,VRF_CMD_ADD_ROUTE))    return h_add_route(ctx,req);
    if (!strcmp(cmd,VRF_CMD_ADD_NEXTHOP))  return h_add_nexthop(ctx,req);
    if (!strcmp(cmd,VRF_CMD_DEL_NEXTHOP))  return h_del_nexthop(ctx,req);
    if (!strcmp(cmd,VRF_CMD_DEL_ROUTE))    return h_del_route(ctx,req);
    if (!strcmp(cmd,VRF_CMD_LIST_ROUTES))  return h_list_routes(ctx,req);
    if (!strcmp(cmd,VRF_CMD_LOOKUP))       return h_lookup(ctx,req);
    if (!strcmp(cmd,VRF_CMD_SET_ECMP_HASH))return h_set_ecmp_hash(ctx,req);
    if (!strcmp(cmd,VRF_CMD_LEAK_ROUTE))   return h_leak(ctx,req);
    if (!strcmp(cmd,VRF_CMD_UNLEAK_ROUTE)) return h_unleak(ctx,req);
    if (!strcmp(cmd,VRF_CMD_LIST_LEAKS))   return h_list_leaks(ctx,req);
    if (!strcmp(cmd,VRF_CMD_GET_STATS))    return h_get_stats(ctx,req);
    if (!strcmp(cmd,VRF_CMD_CLEAR_STATS))  return h_clear_stats(ctx,req);
    if (!strcmp(cmd,VRF_CMD_DUMP_CONFIG)){
        char path[256]="vrf_runtime_config.json"; jstr(req,"path",path,sizeof(path));
        char *buf=malloc(512);
        snprintf(buf,512,"{\"status\":\"%s\",\"path\":\"%s\"}\n",
                 vrf_save_config(ctx,path)==VRF_OK?"ok":"error",path);
        return buf;}
    if (!strcmp(cmd,VRF_CMD_LOAD_CONFIG)){
        char path[256]="vrf_runtime_config.json"; jstr(req,"path",path,sizeof(path));
        return vrf_load_config(ctx,path)==VRF_OK?ok_json():err_json("load failed");}
    if (!strcmp(cmd,"get")){
        char key[64]=""; jstr(req,"key",key,sizeof(key));
        if (!strcmp(key,"ECMP_HASH_MODE")){
            char *buf=malloc(64);
            snprintf(buf,64,"{\"status\":\"ok\",\"value\":%u}\n",ctx->ecmp_hash_mode);
            return buf;}
        return err_json("unknown key");}
    if (!strcmp(cmd,"set")){
        char key[64]=""; jstr(req,"key",key,sizeof(key));
        if (!strcmp(key,"ECMP_HASH_MODE")){
            long long v=jll(req,"value");
            if (v<0||v>31) return err_json("value out of range (0-31)");
            ctx->ecmp_hash_mode=(uint32_t)v;
            return ok_json();}
        return err_json("unknown key");}
    if (!strcmp(cmd,"ping")) return strdup("{\"status\":\"ok\",\"msg\":\"pong\",\"module\":\"vrf\"}\n");
    return err_json("unknown command");}

int vrf_ipc_init(vrf_ctx_t *ctx){
    struct sockaddr_un addr={0}; addr.sun_family=AF_UNIX;
    snprintf(addr.sun_path,sizeof(addr.sun_path),"%.*s",
             (int)(sizeof(addr.sun_path)-1),ctx->sock_path);
    unlink(ctx->sock_path);
    ctx->sock_fd=socket(AF_UNIX,SOCK_STREAM,0); if (ctx->sock_fd<0) return VRF_ERR_INVAL;
    if (bind(ctx->sock_fd,(struct sockaddr*)&addr,sizeof(addr))<0||listen(ctx->sock_fd,16)<0){
        close(ctx->sock_fd);ctx->sock_fd=-1;return VRF_ERR_INVAL;}
    return VRF_OK;}

void vrf_ipc_stop(vrf_ctx_t *ctx){
    if (ctx->sock_fd>=0){close(ctx->sock_fd);ctx->sock_fd=-1;}
    unlink(ctx->sock_path);}

void *vrf_ipc_thread(void *arg){
    vrf_ctx_t *ctx=arg; char buf[VRF_IPC_MAX_MSG];
    while (ctx->running){
        int client=accept(ctx->sock_fd,NULL,NULL);
        if (client<0){if (!ctx->running) break;continue;}
        ssize_t n=recv(client,buf,sizeof(buf)-1,0);
        if (n>0){buf[n]='\0';char *r=vrf_ipc_handle(ctx,buf,(size_t)n);
                 if (r){send(client,r,strlen(r),0);free(r);}}
        close(client);}
    return NULL;}
