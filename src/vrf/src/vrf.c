/*
 * vrf.c — VRF module with ECMP nexthop groups.
 * Each vrf_route_t now holds paths[VRF_ECMP_MAX_PATHS] instead of a
 * single nexthop. Weighted flow-hash selection mirrors the IP module.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>

#include "vrf.h"
#include "vrf_ipc.h"
#include <vrouter/json.h>

/* -----------------------------------------------------------------------
 * FNV-1a (using shared vr_fnv1a from <vrouter/hash.h>)
 * --------------------------------------------------------------------- */
#include <vrouter/hash.h>

uint32_t vrf_fnv1a(uint32_t val, uint32_t n)
{ return vr_fnv1a_mod((const uint8_t*)&val, sizeof(val), n); }

uint32_t vrf_fnv1a_prefix(const vrf_prefix_t *pfx, uint32_t n)
{
    uint8_t buf[17];
    size_t al = pfx->addr.af==AF_INET ? 4 : 16;
    if (pfx->addr.af==AF_INET) memcpy(buf,&pfx->addr.u.v4,4);
    else                       memcpy(buf,&pfx->addr.u.v6,16);
    buf[al]=pfx->plen;
    return vr_fnv1a_mod(buf,al+1,n);
}

/* -----------------------------------------------------------------------
 * ECMP path selection (weighted flow hash)
 * --------------------------------------------------------------------- */
static uint32_t flow_hash_vrf(const vrf_route_t *route,
                              const vrf_flow_key_t *flow)
{
    uint32_t mode = route->ecmp_hash_mode ? route->ecmp_hash_mode
                                          : VRF_ECMP_HASH_DEFAULT;
    uint32_t h = VR_FNV_OFFSET;
#define MIX(data,len) do { \
    for (size_t _i=0;_i<(len);_i++) { h^=((const uint8_t*)(data))[_i]; h*=VR_FNV_PRIME; } \
} while(0)

    if (!flow) { MIX(&route->prefix.addr.u, route->prefix.addr.af==AF_INET?4:16); return h; }
    if ((mode&VRF_ECMP_HASH_SRC_IP) && flow->src.af==AF_INET)  MIX(&flow->src.u.v4,4);
    else if ((mode&VRF_ECMP_HASH_SRC_IP))                       MIX(&flow->src.u.v6,16);
    if ((mode&VRF_ECMP_HASH_DST_IP) && flow->dst.af==AF_INET)  MIX(&flow->dst.u.v4,4);
    else if ((mode&VRF_ECMP_HASH_DST_IP))                       MIX(&flow->dst.u.v6,16);
    if (mode&VRF_ECMP_HASH_SRC_PORT) MIX(&flow->src_port,2);
    if (mode&VRF_ECMP_HASH_DST_PORT) MIX(&flow->dst_port,2);
    if (mode&VRF_ECMP_HASH_PROTO)    MIX(&flow->proto,1);
#undef MIX
    return h;
}

uint8_t vrf_ecmp_select(const vrf_route_t *route, const vrf_flow_key_t *flow)
{
    uint32_t total=0;
    for (uint8_t i=0;i<route->n_paths;i++)
        if (route->paths[i].active)
            total += route->paths[i].weight ? route->paths[i].weight : 1;
    if (!total) return 0;
    uint32_t h=flow_hash_vrf(route,flow)%total, acc=0;
    for (uint8_t i=0;i<route->n_paths;i++) {
        if (!route->paths[i].active) continue;
        acc += route->paths[i].weight ? route->paths[i].weight : 1;
        if (h<acc) return i;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * Address helpers
 * --------------------------------------------------------------------- */
int vrf_addr_parse(const char *str, vrf_addr_t *out)
{
    if (!str||!out) return VRF_ERR_INVAL;
    if (inet_pton(AF_INET, str,&out->u.v4)==1){out->af=AF_INET; return VRF_OK;}
    if (inet_pton(AF_INET6,str,&out->u.v6)==1){out->af=AF_INET6;return VRF_OK;}
    return VRF_ERR_INVAL;
}

int vrf_prefix_parse(const char *str, vrf_prefix_t *out)
{
    if (!str||!out) return VRF_ERR_INVAL;
    char buf[INET6_ADDRSTRLEN+4];
    strncpy(buf,str,sizeof(buf)-1); buf[sizeof(buf)-1]='\0';
    char *sl=strchr(buf,'/'); int plen=-1;
    if (sl){*sl='\0'; plen=atoi(sl+1);}
    if (vrf_addr_parse(buf,&out->addr)!=VRF_OK) return VRF_ERR_INVAL;
    uint8_t maxp=out->addr.af==AF_INET?32:128;
    if (plen<0||plen>maxp) plen=maxp;
    out->plen=(uint8_t)plen; return VRF_OK;
}

void vrf_addr_to_str(const vrf_addr_t *a, char *buf, size_t len)
{ if (a->af==AF_INET) inet_ntop(AF_INET,&a->u.v4,buf,len);
  else                inet_ntop(AF_INET6,&a->u.v6,buf,len); }

void vrf_prefix_to_str(const vrf_prefix_t *p, char *buf, size_t len)
{ char ab[INET6_ADDRSTRLEN]; vrf_addr_to_str(&p->addr,ab,sizeof(ab));
  snprintf(buf,len,"%s/%u",ab,p->plen); }

bool vrf_prefix_contains(const vrf_prefix_t *pfx, const vrf_addr_t *addr)
{
    if (pfx->addr.af!=addr->af) return false;
    uint8_t pl=pfx->plen;
    if (addr->af==AF_INET) {
        uint32_t mask=pl?htonl(~0u<<(32-pl)):0;
        return (addr->u.v4.s_addr&mask)==(pfx->addr.u.v4.s_addr&mask);
    }
    uint8_t full=pl/8,rem=pl%8;
    const uint8_t *a=addr->u.v6.s6_addr,*p=pfx->addr.u.v6.s6_addr;
    if (memcmp(a,p,full)!=0) return false;
    if (!rem) return true;
    uint8_t mask=(uint8_t)(0xffu<<(8-rem));
    return (a[full]&mask)==(p[full]&mask);
}

/* -----------------------------------------------------------------------
 * FIB internals
 * --------------------------------------------------------------------- */
static int fib_init(vrf_fib_t *fib)
{
    fib->n_buckets=VRF_FWD_BUCKETS;
    fib->buckets=calloc(fib->n_buckets,sizeof(*fib->buckets));
    if (!fib->buckets) return VRF_ERR_NOMEM;
    fib->n_routes=0;
    return pthread_rwlock_init(&fib->lock,NULL)?VRF_ERR_NOMEM:VRF_OK;
}

static void fib_destroy(vrf_fib_t *fib)
{
    for (uint32_t i=0;i<fib->n_buckets;i++) {
        vrf_route_t *c=fib->buckets[i];
        while(c){vrf_route_t *n=c->next;free(c);c=n;}
    }
    free(fib->buckets); pthread_rwlock_destroy(&fib->lock);
}

static vrf_route_t *fib_find_locked(vrf_fib_t *fib, const vrf_prefix_t *pfx)
{
    uint32_t b=vrf_fnv1a_prefix(pfx,fib->n_buckets);
    for (vrf_route_t *e=fib->buckets[b];e;e=e->next) {
        if (e->prefix.plen==pfx->plen && e->prefix.addr.af==pfx->addr.af &&
            memcmp(&e->prefix.addr.u,&pfx->addr.u,
                   pfx->addr.af==AF_INET?4:16)==0) return e;
    }
    return NULL;
}

static bool vnh_eq(const vrf_nexthop_t *nh,
                   const vrf_addr_t *addr, uint32_t ifindex)
{
    if (nh->ifindex!=ifindex||nh->addr.af!=addr->af) return false;
    return memcmp(&nh->addr.u,&addr->u,addr->af==AF_INET?4:16)==0;
}

static int fib_add(vrf_fib_t *fib, const vrf_prefix_t *pfx,
                   const vrf_addr_t *nexthop, uint32_t out_ifindex,
                   uint32_t src_vrf_id, uint8_t ad, uint32_t metric,
                   uint32_t weight, uint32_t default_hash_mode)
{
    uint32_t b=vrf_fnv1a_prefix(pfx,fib->n_buckets);
    if (!weight) weight=1;
    int rc=VRF_OK;
    pthread_rwlock_wrlock(&fib->lock);

    vrf_route_t *e=fib_find_locked(fib,pfx);
    if (e) {
        if (ad<e->ad) {
            e->ad=ad; e->metric=metric; e->src_vrf_id=src_vrf_id;
            memset(e->paths,0,sizeof(e->paths)); e->n_paths=1;
            if (nexthop) e->paths[0].addr=*nexthop;
            e->paths[0].ifindex=out_ifindex; e->paths[0].weight=weight;
            e->paths[0].active=true;
        } else if (ad==e->ad) {
            for (uint8_t i=0;i<e->n_paths;i++)
                if (vnh_eq(&e->paths[i],nexthop,out_ifindex)) goto out;
            if (e->n_paths>=VRF_ECMP_MAX_PATHS){rc=VRF_ERR_FULL;goto out;}
            uint8_t idx=e->n_paths++;
            if (nexthop) e->paths[idx].addr=*nexthop;
            e->paths[idx].ifindex=out_ifindex;
            e->paths[idx].weight=weight; e->paths[idx].active=true;
        }
        goto out;
    }

    if (fib->n_routes>=VRF_MAX_ROUTES){rc=VRF_ERR_FULL;goto out;}
    e=calloc(1,sizeof(*e));
    if (!e){rc=VRF_ERR_NOMEM;goto out;}
    e->prefix=*pfx; e->ad=ad; e->metric=metric; e->src_vrf_id=src_vrf_id;
    e->n_paths=1;
    if (nexthop) e->paths[0].addr=*nexthop;
    e->paths[0].ifindex=out_ifindex; e->paths[0].weight=weight;
    e->paths[0].active=true;
    e->ecmp_hash_mode=default_hash_mode;
    e->installed_at=time(NULL);
    e->next=fib->buckets[b]; fib->buckets[b]=e; fib->n_routes++;

out:
    pthread_rwlock_unlock(&fib->lock);
    return rc;
}

static int fib_nexthop_add(vrf_fib_t *fib, const vrf_prefix_t *pfx,
                           const vrf_addr_t *nexthop, uint32_t ifindex,
                           uint32_t weight)
{
    if (!weight) weight=1;
    int rc=VRF_ERR_NOTFOUND;
    pthread_rwlock_wrlock(&fib->lock);
    vrf_route_t *e=fib_find_locked(fib,pfx);
    if (!e) goto out;
    for (uint8_t i=0;i<e->n_paths;i++)
        if (vnh_eq(&e->paths[i],nexthop,ifindex)) {
            e->paths[i].weight=weight; e->paths[i].active=true;
            rc=VRF_OK; goto out;
        }
    if (e->n_paths>=VRF_ECMP_MAX_PATHS){rc=VRF_ERR_FULL;goto out;}
    uint8_t idx=e->n_paths++;
    if (nexthop) e->paths[idx].addr=*nexthop;
    e->paths[idx].ifindex=ifindex; e->paths[idx].weight=weight;
    e->paths[idx].active=true; rc=VRF_OK;
out:
    pthread_rwlock_unlock(&fib->lock);
    return rc;
}

static int fib_nexthop_del(vrf_fib_t *fib, const vrf_prefix_t *pfx,
                           const vrf_addr_t *nexthop, uint32_t ifindex)
{
    int rc=VRF_ERR_NOTFOUND;
    pthread_rwlock_wrlock(&fib->lock);
    vrf_route_t *e=fib_find_locked(fib,pfx);
    if (!e) goto out;
    for (uint8_t i=0;i<e->n_paths;i++) {
        if (!vnh_eq(&e->paths[i],nexthop,ifindex)) continue;
        memmove(&e->paths[i],&e->paths[i+1],
                (e->n_paths-i-1)*sizeof(vrf_nexthop_t));
        memset(&e->paths[e->n_paths-1],0,sizeof(vrf_nexthop_t));
        e->n_paths--; rc=VRF_OK;
        if (e->n_paths==0) {
            uint32_t b=vrf_fnv1a_prefix(pfx,fib->n_buckets);
            vrf_route_t **pp=&fib->buckets[b];
            while (*pp&&*pp!=e) pp=&(*pp)->next;
            if (*pp){*pp=e->next;free(e);fib->n_routes--;}
        }
        goto out;
    }
out:
    pthread_rwlock_unlock(&fib->lock);
    return rc;
}

static int fib_del(vrf_fib_t *fib, const vrf_prefix_t *pfx)
{
    uint32_t b=vrf_fnv1a_prefix(pfx,fib->n_buckets);
    int rc=VRF_ERR_NOTFOUND;
    pthread_rwlock_wrlock(&fib->lock);
    vrf_route_t **pp=&fib->buckets[b];
    while (*pp) {
        vrf_route_t *e=*pp;
        if (e->prefix.plen==pfx->plen&&e->prefix.addr.af==pfx->addr.af&&
            memcmp(&e->prefix.addr.u,&pfx->addr.u,
                   pfx->addr.af==AF_INET?4:16)==0) {
            *pp=e->next;free(e);fib->n_routes--;rc=VRF_OK;break;
        }
        pp=&(*pp)->next;
    }
    pthread_rwlock_unlock(&fib->lock);
    return rc;
}

static int fib_lookup(vrf_fib_t *fib, const vrf_addr_t *dst,
                      const vrf_flow_key_t *flow,
                      vrf_route_t *entry_out, vrf_nexthop_t *path_out)
{
    vrf_route_t *best=NULL;
    pthread_rwlock_rdlock(&fib->lock);
    for (uint32_t i=0;i<fib->n_buckets;i++)
        for (vrf_route_t *e=fib->buckets[i];e;e=e->next) {
            if (!vrf_prefix_contains(&e->prefix,dst)) continue;
            if (!best||e->prefix.plen>best->prefix.plen||
                (e->prefix.plen==best->prefix.plen&&e->ad<best->ad))
                best=e;
        }
    int rc=VRF_ERR_NOTFOUND;
    if (best) {
        uint8_t idx=vrf_ecmp_select(best,flow);
        best->hit_count++; best->paths[idx].hit_count++;
        if (entry_out) *entry_out=*best;
        if (path_out)  *path_out =best->paths[idx];
        rc=VRF_OK;
    }
    pthread_rwlock_unlock(&fib->lock);
    return rc;
}

static void fib_del_leaked(vrf_fib_t *fib, uint32_t src_vrf_id)
{
    pthread_rwlock_wrlock(&fib->lock);
    for (uint32_t i=0;i<fib->n_buckets;i++) {
        vrf_route_t **pp=&fib->buckets[i];
        while (*pp) {
            if ((*pp)->src_vrf_id==src_vrf_id) {
                vrf_route_t *d=*pp;*pp=d->next;free(d);fib->n_routes--;
            } else pp=&(*pp)->next;
        }
    }
    pthread_rwlock_unlock(&fib->lock);
}

/* -----------------------------------------------------------------------
 * VRF table
 * --------------------------------------------------------------------- */
static int vrf_table_init(vrf_table_t *t)
{
    t->n_buckets=VRF_TABLE_BUCKETS;
    t->buckets=calloc(t->n_buckets,sizeof(*t->buckets));
    if (!t->buckets) return VRF_ERR_NOMEM;
    t->n_vrfs=0;
    return pthread_rwlock_init(&t->lock,NULL)?VRF_ERR_NOMEM:VRF_OK;
}

static void vrf_table_destroy(vrf_table_t *t)
{
    for (uint32_t i=0;i<t->n_buckets;i++) {
        vrf_instance_t *c=t->buckets[i];
        while (c) {
            vrf_instance_t *n=c->next;
            fib_destroy(&c->fib4); fib_destroy(&c->fib6);
            vrf_if_binding_t *b=c->ifaces;
            while(b){vrf_if_binding_t *bn=b->next;free(b);b=bn;}
            vrf_leak_t *l=c->leaks_out;
            while(l){vrf_leak_t *ln=l->next;free(l);l=ln;}
            pthread_rwlock_destroy(&c->lock); free(c); c=n;
        }
    }
    free(t->buckets); pthread_rwlock_destroy(&t->lock);
}

static uint32_t vrf_bucket(const vrf_table_t *t, uint32_t id)
{ return vrf_fnv1a(id,t->n_buckets); }

/* -----------------------------------------------------------------------
 * If-map
 * --------------------------------------------------------------------- */
static int if_map_init(vrf_if_map_t *m)
{
    m->n_buckets=VRF_IF_BUCKETS;
    m->buckets=calloc(m->n_buckets,sizeof(*m->buckets));
    if (!m->buckets) return VRF_ERR_NOMEM;
    return pthread_rwlock_init(&m->lock,NULL)?VRF_ERR_NOMEM:VRF_OK;
}

static void if_map_destroy(vrf_if_map_t *m)
{
    for (uint32_t i=0;i<m->n_buckets;i++) {
        vrf_if_binding_t *c=m->buckets[i];
        while(c){vrf_if_binding_t *n=c->next;free(c);c=n;}
    }
    free(m->buckets); pthread_rwlock_destroy(&m->lock);
}

static uint32_t if_bucket(const vrf_if_map_t *m, uint32_t ifindex)
{ return vrf_fnv1a(ifindex,m->n_buckets); }

/* -----------------------------------------------------------------------
 * Public VRF CRUD
 * --------------------------------------------------------------------- */
int vrf_create(vrf_ctx_t *ctx, uint32_t id, const char *name,
               uint32_t flags, uint32_t table_id, uint64_t rd)
{
    if (!ctx||!name||id==VRF_ID_INVALID) return VRF_ERR_INVAL;
    vrf_table_t *t=&ctx->vrf_table;
    uint32_t b=vrf_bucket(t,id);
    int rc=VRF_OK;
    pthread_rwlock_wrlock(&t->lock);
    for (vrf_instance_t *c=t->buckets[b];c;c=c->next)
        if (c->id==id){rc=VRF_ERR_EXISTS;goto out;}
    if (t->n_vrfs>=VRF_MAX_INSTANCES){rc=VRF_ERR_FULL;goto out;}
    vrf_instance_t *v=calloc(1,sizeof(*v));
    if (!v){rc=VRF_ERR_NOMEM;goto out;}
    v->id=id; v->flags=flags|VRF_FLAG_ACTIVE;
    v->table_id=table_id; v->rd=rd; v->created_at=time(NULL);
    v->ecmp_hash_mode=VRF_ECMP_HASH_DEFAULT;
    strncpy(v->name,name,VRF_NAME_MAX-1);
    if (fib_init(&v->fib4)!=VRF_OK||fib_init(&v->fib6)!=VRF_OK||
        pthread_rwlock_init(&v->lock,NULL)) {
        fib_destroy(&v->fib4);fib_destroy(&v->fib6);free(v);
        rc=VRF_ERR_NOMEM;goto out;
    }
    if (id==VRF_ID_DEFAULT) v->flags|=VRF_FLAG_DEFAULT;
    v->next=t->buckets[b]; t->buckets[b]=v; t->n_vrfs++;
out:
    pthread_rwlock_unlock(&t->lock);
    return rc;
}

int vrf_delete(vrf_ctx_t *ctx, uint32_t id)
{
    if (!ctx||id==VRF_ID_INVALID||id==VRF_ID_DEFAULT) return VRF_ERR_INVAL;
    vrf_table_t *t=&ctx->vrf_table;
    uint32_t b=vrf_bucket(t,id);
    int rc=VRF_ERR_NOTFOUND;
    pthread_rwlock_wrlock(&t->lock);
    vrf_instance_t **pp=&t->buckets[b];
    while (*pp) {
        if ((*pp)->id==id) {
            vrf_instance_t *del=*pp; *pp=del->next;
            /* unbind all interfaces */
            pthread_rwlock_wrlock(&ctx->if_map.lock);
            for (vrf_if_binding_t *b2=del->ifaces;b2;b2=b2->next) {
                uint32_t ib=if_bucket(&ctx->if_map,b2->ifindex);
                vrf_if_binding_t **pp2=&ctx->if_map.buckets[ib];
                while (*pp2) {
                    if ((*pp2)->ifindex==b2->ifindex) {
                        vrf_if_binding_t *d=*pp2;*pp2=d->next;free(d);break;
                    }
                    pp2=&(*pp2)->next;
                }
            }
            pthread_rwlock_unlock(&ctx->if_map.lock);
            /* clean up leaked routes exported to other VRFs */
            pthread_rwlock_rdlock(&ctx->vrf_table.lock);
            for (vrf_leak_t *lk=del->leaks_out;lk;lk=lk->next) {
                uint32_t db=vrf_bucket(&ctx->vrf_table,lk->dst_vrf_id);
                for (vrf_instance_t *c=ctx->vrf_table.buckets[db];c;c=c->next) {
                    if (c->id==lk->dst_vrf_id) {
                        fib_del_leaked(&c->fib4,del->id);
                        fib_del_leaked(&c->fib6,del->id);
                        break;
                    }
                }
            }
            pthread_rwlock_unlock(&ctx->vrf_table.lock);
            fib_destroy(&del->fib4); fib_destroy(&del->fib6);
            vrf_if_binding_t *bf=del->ifaces;
            while(bf){vrf_if_binding_t *bn=bf->next;free(bf);bf=bn;}
            vrf_leak_t *lf=del->leaks_out;
            while(lf){vrf_leak_t *ln=lf->next;free(lf);lf=ln;}
            pthread_rwlock_destroy(&del->lock); free(del);
            t->n_vrfs--; rc=VRF_OK; break;
        }
        pp=&(*pp)->next;
    }
    pthread_rwlock_unlock(&t->lock);
    return rc;
}

vrf_instance_t *vrf_find(vrf_ctx_t *ctx, uint32_t id)
{
    if (!ctx) return NULL;
    vrf_table_t *t=&ctx->vrf_table;
    uint32_t b=vrf_bucket(t,id);
    vrf_instance_t *found=NULL;
    pthread_rwlock_rdlock(&t->lock);
    for (vrf_instance_t *c=t->buckets[b];c;c=c->next)
        if (c->id==id){found=c;break;}
    pthread_rwlock_unlock(&t->lock);
    return found;
}

vrf_instance_t *vrf_find_by_name(vrf_ctx_t *ctx, const char *name)
{
    if (!ctx||!name) return NULL;
    vrf_instance_t *found=NULL;
    pthread_rwlock_rdlock(&ctx->vrf_table.lock);
    for (uint32_t i=0;i<ctx->vrf_table.n_buckets&&!found;i++)
        for (vrf_instance_t *c=ctx->vrf_table.buckets[i];c;c=c->next)
            if (strcmp(c->name,name)==0){found=c;break;}
    pthread_rwlock_unlock(&ctx->vrf_table.lock);
    return found;
}

/* -----------------------------------------------------------------------
 * Interface binding
 * --------------------------------------------------------------------- */
int vrf_bind_if(vrf_ctx_t *ctx, uint32_t vrf_id,
                uint32_t ifindex, const char *ifname)
{
    if (!ctx||!ifname) return VRF_ERR_INVAL;
    vrf_instance_t *v=vrf_find(ctx,vrf_id);
    if (!v) return VRF_ERR_NOTFOUND;
    if (vrf_if_lookup(ctx,ifindex)!=VRF_ID_INVALID) return VRF_ERR_BOUND;

    vrf_if_binding_t *b=calloc(1,sizeof(*b));
    if (!b) return VRF_ERR_NOMEM;
    b->ifindex=ifindex; b->vrf_id=vrf_id; b->bound_at=time(NULL);
    strncpy(b->ifname,ifname,IFNAMSIZ-1);

    uint32_t ib=if_bucket(&ctx->if_map,ifindex);
    pthread_rwlock_wrlock(&ctx->if_map.lock);
    b->next=ctx->if_map.buckets[ib]; ctx->if_map.buckets[ib]=b;
    pthread_rwlock_unlock(&ctx->if_map.lock);

    vrf_if_binding_t *local=calloc(1,sizeof(*local));
    if (local) {
        *local=*b; local->next=NULL;
        pthread_rwlock_wrlock(&v->lock);
        local->next=v->ifaces; v->ifaces=local; v->n_ifaces++;
        pthread_rwlock_unlock(&v->lock);
    }
    return VRF_OK;
}

int vrf_unbind_if(vrf_ctx_t *ctx, uint32_t ifindex)
{
    if (!ctx) return VRF_ERR_INVAL;
    uint32_t ib=if_bucket(&ctx->if_map,ifindex);
    uint32_t vrf_id=VRF_ID_INVALID;
    int rc=VRF_ERR_NOTFOUND;
    pthread_rwlock_wrlock(&ctx->if_map.lock);
    vrf_if_binding_t **pp=&ctx->if_map.buckets[ib];
    while (*pp) {
        if ((*pp)->ifindex==ifindex) {
            vrf_if_binding_t *d=*pp; vrf_id=d->vrf_id;
            *pp=d->next; free(d); rc=VRF_OK; break;
        }
        pp=&(*pp)->next;
    }
    pthread_rwlock_unlock(&ctx->if_map.lock);
    if (rc!=VRF_OK||vrf_id==VRF_ID_INVALID) return rc;
    vrf_instance_t *v=vrf_find(ctx,vrf_id);
    if (v) {
        pthread_rwlock_wrlock(&v->lock);
        vrf_if_binding_t **pp2=&v->ifaces;
        while (*pp2) {
            if ((*pp2)->ifindex==ifindex) {
                vrf_if_binding_t *d=*pp2;*pp2=d->next;free(d);v->n_ifaces--;break;
            }
            pp2=&(*pp2)->next;
        }
        pthread_rwlock_unlock(&v->lock);
    }
    return VRF_OK;
}

uint32_t vrf_if_lookup(vrf_ctx_t *ctx, uint32_t ifindex)
{
    if (!ctx) return VRF_ID_INVALID;
    uint32_t ib=if_bucket(&ctx->if_map,ifindex);
    uint32_t result=VRF_ID_INVALID;
    pthread_rwlock_rdlock(&ctx->if_map.lock);
    for (vrf_if_binding_t *c=ctx->if_map.buckets[ib];c;c=c->next)
        if (c->ifindex==ifindex){result=c->vrf_id;break;}
    pthread_rwlock_unlock(&ctx->if_map.lock);
    return result;
}

/* -----------------------------------------------------------------------
 * Per-VRF routing
 * --------------------------------------------------------------------- */
int vrf_route_add(vrf_ctx_t *ctx, uint32_t vrf_id,
                  const vrf_prefix_t *pfx, const vrf_addr_t *nexthop,
                  uint32_t out_ifindex, uint8_t ad, uint32_t metric,
                  uint32_t weight)
{
    if (!ctx||!pfx) return VRF_ERR_INVAL;
    vrf_instance_t *v=vrf_find(ctx,vrf_id);
    if (!v) return VRF_ERR_NOTFOUND;
    vrf_fib_t *fib=pfx->addr.af==AF_INET?&v->fib4:&v->fib6;
    return fib_add(fib,pfx,nexthop,out_ifindex,VRF_ID_INVALID,
                   ad,metric,weight,v->ecmp_hash_mode);
}

int vrf_route_del(vrf_ctx_t *ctx, uint32_t vrf_id, const vrf_prefix_t *pfx)
{
    if (!ctx||!pfx) return VRF_ERR_INVAL;
    vrf_instance_t *v=vrf_find(ctx,vrf_id);
    if (!v) return VRF_ERR_NOTFOUND;
    vrf_fib_t *fib=pfx->addr.af==AF_INET?&v->fib4:&v->fib6;
    return fib_del(fib,pfx);
}

int vrf_nexthop_add(vrf_ctx_t *ctx, uint32_t vrf_id,
                    const vrf_prefix_t *pfx, const vrf_addr_t *nexthop,
                    uint32_t out_ifindex, uint32_t weight)
{
    if (!ctx||!pfx||!nexthop) return VRF_ERR_INVAL;
    vrf_instance_t *v=vrf_find(ctx,vrf_id);
    if (!v) return VRF_ERR_NOTFOUND;
    vrf_fib_t *fib=pfx->addr.af==AF_INET?&v->fib4:&v->fib6;
    return fib_nexthop_add(fib,pfx,nexthop,out_ifindex,weight);
}

int vrf_nexthop_del(vrf_ctx_t *ctx, uint32_t vrf_id,
                    const vrf_prefix_t *pfx, const vrf_addr_t *nexthop,
                    uint32_t out_ifindex)
{
    if (!ctx||!pfx||!nexthop) return VRF_ERR_INVAL;
    vrf_instance_t *v=vrf_find(ctx,vrf_id);
    if (!v) return VRF_ERR_NOTFOUND;
    vrf_fib_t *fib=pfx->addr.af==AF_INET?&v->fib4:&v->fib6;
    return fib_nexthop_del(fib,pfx,nexthop,out_ifindex);
}

int vrf_route_lookup(vrf_ctx_t *ctx, uint32_t vrf_id,
                     const vrf_addr_t *dst, const vrf_flow_key_t *flow,
                     vrf_route_t *entry_out, vrf_nexthop_t *path_out)
{
    if (!ctx||!dst) return VRF_ERR_INVAL;
    vrf_instance_t *v=vrf_find(ctx,vrf_id);
    if (!v) return VRF_ERR_NOTFOUND;
    vrf_fib_t *fib=dst->af==AF_INET?&v->fib4:&v->fib6;
    int rc=fib_lookup(fib,dst,flow,entry_out,path_out);
    pthread_rwlock_wrlock(&v->lock);
    if (rc==VRF_OK) v->fwd_pkts++; else v->drop_noroute++;
    pthread_rwlock_unlock(&v->lock);
    return rc;
}

int vrf_set_ecmp_hash(vrf_ctx_t *ctx, uint32_t vrf_id,
                      const vrf_prefix_t *pfx, uint32_t mode)
{
    if (!ctx||!pfx) return VRF_ERR_INVAL;
    vrf_instance_t *v=vrf_find(ctx,vrf_id);
    if (!v) return VRF_ERR_NOTFOUND;
    vrf_fib_t *fib=pfx->addr.af==AF_INET?&v->fib4:&v->fib6;
    int rc=VRF_ERR_NOTFOUND;
    pthread_rwlock_wrlock(&fib->lock);
    vrf_route_t *e=fib_find_locked(fib,pfx);
    if (e){e->ecmp_hash_mode=mode;rc=VRF_OK;}
    pthread_rwlock_unlock(&fib->lock);
    return rc;
}

/* -----------------------------------------------------------------------
 * Route leaking
 * --------------------------------------------------------------------- */
int vrf_leak_route(vrf_ctx_t *ctx,
                   uint32_t src_vrf_id, uint32_t dst_vrf_id,
                   const vrf_prefix_t *pfx, const vrf_addr_t *nexthop,
                   uint32_t out_ifindex, uint32_t metric)
{
    if (!ctx||!pfx) return VRF_ERR_INVAL;
    if (src_vrf_id==dst_vrf_id) return VRF_ERR_LOOP;
    vrf_instance_t *src=vrf_find(ctx,src_vrf_id);
    vrf_instance_t *dst=vrf_find(ctx,dst_vrf_id);
    if (!src||!dst) return VRF_ERR_NOTFOUND;

    vrf_fib_t *fib=pfx->addr.af==AF_INET?&dst->fib4:&dst->fib6;
    int rc=fib_add(fib,pfx,nexthop,out_ifindex,src_vrf_id,
                   VRF_AD_LEAKED,metric,1,dst->ecmp_hash_mode);
    if (rc!=VRF_OK) return rc;

    vrf_leak_t *lk=calloc(1,sizeof(*lk));
    if (!lk) return VRF_ERR_NOMEM;
    lk->src_vrf_id=src_vrf_id; lk->dst_vrf_id=dst_vrf_id;
    lk->prefix=*pfx; if (nexthop) lk->nexthop=*nexthop;
    lk->out_ifindex=out_ifindex; lk->metric=metric; lk->leaked_at=time(NULL);
    pthread_rwlock_wrlock(&src->lock);
    lk->next=src->leaks_out; src->leaks_out=lk; src->n_leaks_out++;
    pthread_rwlock_unlock(&src->lock);
    return VRF_OK;
}

int vrf_unleak_route(vrf_ctx_t *ctx,
                     uint32_t src_vrf_id, uint32_t dst_vrf_id,
                     const vrf_prefix_t *pfx)
{
    if (!ctx||!pfx) return VRF_ERR_INVAL;
    vrf_instance_t *src=vrf_find(ctx,src_vrf_id);
    vrf_instance_t *dst=vrf_find(ctx,dst_vrf_id);
    if (!src||!dst) return VRF_ERR_NOTFOUND;
    vrf_fib_t *fib=pfx->addr.af==AF_INET?&dst->fib4:&dst->fib6;
    fib_del(fib,pfx);
    pthread_rwlock_wrlock(&src->lock);
    vrf_leak_t **pp=&src->leaks_out;
    while (*pp) {
        vrf_leak_t *lk=*pp;
        if (lk->dst_vrf_id==dst_vrf_id&&lk->prefix.plen==pfx->plen&&
            lk->prefix.addr.af==pfx->addr.af&&
            memcmp(&lk->prefix.addr.u,&pfx->addr.u,
                   pfx->addr.af==AF_INET?4:16)==0) {
            *pp=lk->next;free(lk);src->n_leaks_out--;break;
        }
        pp=&(*pp)->next;
    }
    pthread_rwlock_unlock(&src->lock);
    return VRF_OK;
}

/* -----------------------------------------------------------------------
 * Persistence
 * --------------------------------------------------------------------- */
int vrf_save_config(vrf_ctx_t *ctx, const char *path)
{
    if (!ctx||!path) return VRF_ERR_INVAL;
    char tmp[512]; snprintf(tmp,sizeof(tmp),"%s.tmp",path);
    FILE *f=fopen(tmp,"w"); if (!f) return VRF_ERR_INVAL;

    pthread_rwlock_rdlock(&ctx->vrf_table.lock);
    for (uint32_t i=0;i<ctx->vrf_table.n_buckets;i++) {
        for (vrf_instance_t *v=ctx->vrf_table.buckets[i];v;v=v->next) {
            pthread_rwlock_rdlock(&v->lock);
            fprintf(f,"{\"type\":\"vrf\",\"id\":%u,\"name\":\"%s\","
                      "\"flags\":%u,\"table_id\":%u,\"rd\":%llu,"
                      "\"ecmp_hash_mode\":%u}\n",
                    v->id,v->name,v->flags,v->table_id,
                    (unsigned long long)v->rd,v->ecmp_hash_mode);
            for (vrf_if_binding_t *b=v->ifaces;b;b=b->next)
                fprintf(f,"{\"type\":\"binding\",\"vrf_id\":%u,"
                          "\"ifindex\":%u,\"ifname\":\"%s\"}\n",
                        v->id,b->ifindex,b->ifname);
            for (int af=0;af<2;af++) {
                vrf_fib_t *fib=af==0?&v->fib4:&v->fib6;
                pthread_rwlock_rdlock(&fib->lock);
                for (uint32_t bi=0;bi<fib->n_buckets;bi++) {
                    for (vrf_route_t *r=fib->buckets[bi];r;r=r->next) {
                        char ps[INET6_ADDRSTRLEN+4];
                        vrf_prefix_to_str(&r->prefix,ps,sizeof(ps));
                        fprintf(f,"{\"type\":\"route\",\"vrf_id\":%u,"
                                  "\"prefix\":\"%s\",\"ad\":%u,"
                                  "\"metric\":%u,\"src_vrf\":%u,"
                                  "\"ecmp_hash_mode\":%u,\"n_paths\":%u",
                                v->id,ps,r->ad,r->metric,r->src_vrf_id,
                                r->ecmp_hash_mode,r->n_paths);
                        for (uint8_t p=0;p<r->n_paths;p++) {
                            char nh[INET6_ADDRSTRLEN]="::";
                            vrf_addr_to_str(&r->paths[p].addr,nh,sizeof(nh));
                            fprintf(f,",\"nh%u\":\"%s\",\"if%u\":%u,"
                                      "\"w%u\":%u,\"act%u\":%u",
                                    p,nh,p,r->paths[p].ifindex,
                                    p,r->paths[p].weight,
                                    p,(unsigned)r->paths[p].active);
                        }
                        fprintf(f,"}\n");
                    }
                }
                pthread_rwlock_unlock(&fib->lock);
            }
            pthread_rwlock_unlock(&v->lock);
        }
    }
    pthread_rwlock_unlock(&ctx->vrf_table.lock);
    fflush(f);fclose(f);rename(tmp,path);
    return VRF_OK;
}

static long long jll(const char *line,const char *key)
{
    char s[128]; snprintf(s,sizeof(s),"\"%s\":",key);
    const char *p=strstr(line,s); if (!p) return -1;
    p+=strlen(s); if (*p=='"') p++;
    return strtoll(p,NULL,10);
}

int vrf_load_config(vrf_ctx_t *ctx, const char *path)
{
    if (!ctx||!path) return VRF_ERR_INVAL;
    FILE *f=fopen(path,"r"); if (!f) return VRF_ERR_INVAL;
    char line[8192], type_buf[32];
    while (fgets(line,sizeof(line),f)) {
        if (vr_json_get_str(line,"type",type_buf,sizeof(type_buf))!=0) continue;
        if (strcmp(type_buf,"vrf")==0) {
            char name[VRF_NAME_MAX]={0};
            vr_json_get_str(line,"name",name,sizeof(name));
            uint32_t id=(uint32_t)jll(line,"id");
            uint32_t flags=(uint32_t)jll(line,"flags");
            uint32_t tid=(uint32_t)jll(line,"table_id");
            uint64_t rd=(uint64_t)jll(line,"rd");
            vrf_create(ctx,id,name,flags&~VRF_FLAG_ACTIVE,tid,rd);
            long long hm=jll(line,"ecmp_hash_mode");
            if (hm>0) {
                vrf_instance_t *v=vrf_find(ctx,id);
                if (v) v->ecmp_hash_mode=(uint32_t)hm;
            }
        } else if (strcmp(type_buf,"binding")==0) {
            char ifname[IFNAMSIZ]={0};
            vr_json_get_str(line,"ifname",ifname,sizeof(ifname));
            uint32_t vid=(uint32_t)jll(line,"vrf_id");
            uint32_t iidx=(uint32_t)jll(line,"ifindex");
            vrf_bind_if(ctx,vid,iidx,ifname);
        } else if (strcmp(type_buf,"route")==0) {
            char ps[INET6_ADDRSTRLEN+4]={0};
            vr_json_get_str(line,"prefix",ps,sizeof(ps));
            vrf_prefix_t pfx;
            if (vrf_prefix_parse(ps,&pfx)!=VRF_OK) continue;
            uint32_t vid=(uint32_t)jll(line,"vrf_id");
            uint32_t src_vrf=(uint32_t)jll(line,"src_vrf");
            uint8_t  ad=(uint8_t)jll(line,"ad");
            uint32_t metric=(uint32_t)jll(line,"metric");
            uint32_t hmode=(uint32_t)jll(line,"ecmp_hash_mode");
            long     np_l=jll(line,"n_paths");
            uint8_t  n_paths=np_l>0?(uint8_t)np_l:1;
            for (uint8_t p=0;p<n_paths;p++) {
                char nhk[16],ifk[16],wk[16];
                snprintf(nhk,sizeof(nhk),"nh%u",p);
                snprintf(ifk,sizeof(ifk),"if%u",p);
                snprintf(wk, sizeof(wk), "w%u", p);
                char nhstr[INET6_ADDRSTRLEN]={0};
                vr_json_get_str(line,nhk,nhstr,sizeof(nhstr));
                vrf_addr_t nh; memset(&nh,0,sizeof(nh));
                vrf_addr_parse(nhstr,&nh);
                uint32_t oif=(uint32_t)jll(line,ifk);
                long wl=jll(line,wk); uint32_t weight=wl>0?(uint32_t)wl:1;
                if (src_vrf==(uint32_t)-1||src_vrf==VRF_ID_INVALID) {
                    vrf_route_add(ctx,vid,&pfx,&nh,oif,ad,metric,weight);
                } else {
                    vrf_instance_t *dv=vrf_find(ctx,vid);
                    if (dv) {
                        vrf_fib_t *fib=pfx.addr.af==AF_INET?&dv->fib4:&dv->fib6;
                        fib_add(fib,&pfx,&nh,oif,src_vrf,ad,metric,weight,
                                dv->ecmp_hash_mode);
                    }
                }
            }
            if (hmode) vrf_set_ecmp_hash(ctx,vid,&pfx,hmode);
        }
    }
    fclose(f); return VRF_OK;
}

/* -----------------------------------------------------------------------
 * Lifecycle
 * --------------------------------------------------------------------- */
static vrf_ctx_t *g_ctx=NULL;
static void sig_handler(int sig) {
    if (!g_ctx) return;
    if (sig==SIGHUP) vrf_save_config(g_ctx,"vrf_runtime_config.json");
    else if (sig==SIGTERM||sig==SIGINT) g_ctx->running=false;
}

vrf_ctx_t *vrf_ctx_create(void) {
    vrf_ctx_t *ctx=calloc(1,sizeof(*ctx)); if (!ctx) return NULL;
    if (vrf_table_init(&ctx->vrf_table)!=VRF_OK||
        if_map_init(&ctx->if_map)!=VRF_OK) { vrf_ctx_destroy(ctx); return NULL; }
    ctx->sock_fd=-1; ctx->ecmp_hash_mode=VRF_ECMP_HASH_DEFAULT; return ctx;
}

void vrf_ctx_destroy(vrf_ctx_t *ctx) {
    if (!ctx) return;
    vrf_table_destroy(&ctx->vrf_table); if_map_destroy(&ctx->if_map); free(ctx);
}

int vrf_init(vrf_ctx_t *ctx, const char *sock_path) {
    if (!ctx||!sock_path) return VRF_ERR_INVAL;
    strncpy(ctx->sock_path,sock_path,sizeof(ctx->sock_path)-1);
    g_ctx=ctx;
    struct sigaction sa={.sa_handler=sig_handler};
    sigemptyset(&sa.sa_mask);
    sigaction(SIGHUP,&sa,NULL); sigaction(SIGTERM,&sa,NULL); sigaction(SIGINT,&sa,NULL);
    ctx->running=true;
    vrf_create(ctx,VRF_ID_DEFAULT,"default",VRF_FLAG_DEFAULT,254,0);
    if (vrf_ipc_init(ctx)!=VRF_OK) return VRF_ERR_INVAL;
    if (pthread_create(&ctx->ipc_thread,NULL,vrf_ipc_thread,ctx)) return VRF_ERR_NOMEM;
    return VRF_OK;
}

void vrf_shutdown(vrf_ctx_t *ctx) {
    if (!ctx) return;
    ctx->running=false;
    vrf_save_config(ctx,"vrf_runtime_config.json");
    vrf_ipc_stop(ctx); pthread_join(ctx->ipc_thread,NULL);
}
