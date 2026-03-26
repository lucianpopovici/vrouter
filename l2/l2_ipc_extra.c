/* ================================================================
 * l2_ipc_extra.c — IPC servers for VLAN, PortSec, Storm,
 *                  IGMP, ARPSnoop, LACP
 * Each server runs in its own thread, called from main_l2.c.
 * ================================================================ */
#include "vlan.h"
#include "portsec.h"
#include "storm.h"
#include "igmp.h"
#include "arpsnoop.h"
#include "l2_ipc_extra.h"
#include "lacp.h"
#include "fdb.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <time.h>


#define IBUF 4096
#define OBUF 32768

/* ── shared mini JSON helpers ───────────────────────────────── */
static int jget(const char *j, const char *k, char *b, size_t sz) {
    char nd[64]; snprintf(nd,sizeof(nd),"\"%s\"",k);
    const char *p=strstr(j,nd); if(!p) return -1;
    p+=strlen(nd);
    while(*p==' '||*p==':'||*p=='\t') p++;
    if(*p=='"'){p++;size_t i=0;while(*p&&*p!='"'&&i<sz-1)b[i++]=*p++;b[i]='\0';}
    else{size_t i=0;while(*p&&*p!=','&&*p!='\n'&&*p!='}'&&i<sz-1)b[i++]=*p++;
         b[i]='\0';while(i>0&&(b[i-1]==' '||b[i-1]=='\r'))b[--i]='\0';}
    return 0;
}
static int sock_serve(const char *path, void *ctx,
                       void (*handler)(void*,const char*,char*,size_t),
                       volatile int *running) {
    unlink(path);
    int srv=socket(AF_UNIX,SOCK_STREAM,0); if(srv<0)return -1;
    struct sockaddr_un a; memset(&a,0,sizeof(a));
    a.sun_family=AF_UNIX; strncpy(a.sun_path,path,sizeof(a.sun_path)-1);
    if(bind(srv,(struct sockaddr*)&a,sizeof(a))<0||listen(srv,8)<0){
        close(srv);return -1;}
    fprintf(stderr,"[l2] %-10s listening on %s\n",
            strrchr(path,'/')+1, path);
    char req[IBUF],resp[OBUF];
    while(*running){
        fd_set rfds; FD_ZERO(&rfds); FD_SET(srv,&rfds);
        struct timeval tv={1,0};
        if(select(srv+1,&rfds,NULL,NULL,&tv)<=0) continue;
        int cli=accept(srv,NULL,NULL); if(cli<0) continue;
        ssize_t n=recv(cli,req,sizeof(req)-1,0);
        if(n>0){req[n]='\0';handler(ctx,req,resp,sizeof(resp));
                send(cli,resp,strlen(resp),0);}
        close(cli);
    }
    close(srv); unlink(path); return 0;
}

/* ================================================================
 * VLAN IPC
 * ================================================================ */
static void vlan_handler(void *ctx, const char *req,
                          char *resp, size_t rsz) {
    vlan_db_t *db=(vlan_db_t*)ctx;
    char cmd[32]={0}; jget(req,"cmd",cmd,sizeof(cmd));

    if(strcmp(cmd,"add")==0){
        char vs[8]={0},name[VLAN_NAME_LEN]={0};
        jget(req,"vlan",vs,sizeof(vs)); jget(req,"name",name,sizeof(name));
        uint16_t vid=(uint16_t)atoi(vs);
        int rc=vlan_add(db,vid,name);
        snprintf(resp,rsz,"{\"status\":\"%s\",\"vlan\":%u}",rc==0?"ok":"error",vid);

    } else if(strcmp(cmd,"del")==0){
        char vs[8]={0}; jget(req,"vlan",vs,sizeof(vs));
        int rc=vlan_del(db,(uint16_t)atoi(vs));
        snprintf(resp,rsz,"{\"status\":\"%s\"}",rc==0?"ok":"error");

    } else if(strcmp(cmd,"port_set")==0){
        char port[16]={0},mode_s[12]={0},pvid_s[8]={0};
        jget(req,"port",port,sizeof(port));
        jget(req,"mode",mode_s,sizeof(mode_s));
        jget(req,"pvid",pvid_s,sizeof(pvid_s));
        vlan_port_mode_t mode=VLAN_PORT_ACCESS;
        if(strcmp(mode_s,"trunk")==0)  mode=VLAN_PORT_TRUNK;
        if(strcmp(mode_s,"hybrid")==0) mode=VLAN_PORT_HYBRID;
        uint16_t pvid=pvid_s[0]?(uint16_t)atoi(pvid_s):1;
        int rc=vlan_port_set_mode(db,port,mode,pvid);
        snprintf(resp,rsz,"{\"status\":\"%s\",\"port\":\"%s\",\"mode\":\"%s\",\"pvid\":%u}",
                 rc==0?"ok":"error",port,vlan_mode_str(mode),pvid);

    } else if(strcmp(cmd,"port_allow")==0||strcmp(cmd,"port_deny")==0){
        char port[16]={0},lo_s[8]={0},hi_s[8]={0};
        jget(req,"port",port,sizeof(port));
        jget(req,"vlan_lo",lo_s,sizeof(lo_s));
        jget(req,"vlan_hi",hi_s,sizeof(hi_s));
        uint16_t lo=(uint16_t)atoi(lo_s);
        uint16_t hi=hi_s[0]?(uint16_t)atoi(hi_s):lo;
        int rc= (cmd[5]=='a') ? vlan_port_allow(db,port,lo,hi)
                              : vlan_port_deny(db,port,lo,hi);
        snprintf(resp,rsz,"{\"status\":\"%s\",\"port\":\"%s\",\"vlans\":\"%u-%u\"}",
                 rc==0?"ok":"error",port,lo,hi);

    } else if(strcmp(cmd,"show")==0){
        size_t pos=0;
        pos+=(size_t)snprintf(resp+pos,rsz-pos,
            "{\"status\":\"ok\",\"vlan_count\":%d,\"vlans\":[",db->vlan_count);
        int first=1;
        for(int v=1;v<=VLAN_MAX&&pos<rsz-128;v++){
            if(!db->vlans[v].active) continue;
            if(!first&&pos<rsz-2) resp[pos++]=',';
            pos+=(size_t)snprintf(resp+pos,rsz-pos,
                "{\"vid\":%u,\"name\":\"%s\"}",v,db->vlans[v].name);
            first=0;
        }
        pos+=(size_t)snprintf(resp+pos,rsz-pos,"],\"ports\":[");
        first=1;
        for(int i=0;i<db->n_ports&&pos<rsz-128;i++){
            vlan_port_t *p=&db->ports[i];
            if(!first&&pos<rsz-2) resp[pos++]=',';
            pos+=(size_t)snprintf(resp+pos,rsz-pos,
                "{\"port\":\"%s\",\"mode\":\"%s\",\"pvid\":%u}",
                p->name,vlan_mode_str(p->mode),p->pvid);
            first=0;
        }
        if(pos<rsz-4){resp[pos++]=']';resp[pos++]='}';resp[pos]='\0';}

    } else if(strcmp(cmd,"ping")==0){
        snprintf(resp,rsz,"{\"status\":\"ok\",\"msg\":\"pong\",\"module\":\"vlan\"}");
    } else snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"unknown cmd: %s\"}",cmd);
}

/* ================================================================
 * Port Security IPC
 * ================================================================ */
static void portsec_handler(void *ctx, const char *req,
                              char *resp, size_t rsz) {
    portsec_table_t *ps=(portsec_table_t*)ctx;
    char cmd[32]={0}; jget(req,"cmd",cmd,sizeof(cmd));

    if(strcmp(cmd,"configure")==0){
        char port[16]={0},max_s[16]={0},viol_s[16]={0};
        jget(req,"port",port,sizeof(port));
        jget(req,"max_macs",max_s,sizeof(max_s));
        jget(req,"violation",viol_s,sizeof(viol_s));
        uint32_t max=(uint32_t)(max_s[0]?atoi(max_s):1);
        portsec_violation_t viol=PORTSEC_VIOL_DROP;
        if(strcmp(viol_s,"restrict")==0) viol=PORTSEC_VIOL_RESTRICT;
        if(strcmp(viol_s,"shutdown")==0) viol=PORTSEC_VIOL_SHUTDOWN;
        int rc=portsec_configure(ps,port,max,viol);
        snprintf(resp,rsz,"{\"status\":\"%s\",\"port\":\"%s\",\"max_macs\":%u,\"violation\":\"%s\"}",
                 rc==0?"ok":"error",port,max,portsec_viol_str(viol));

    } else if(strcmp(cmd,"check")==0){
        char port[16]={0},mac_s[24]={0},vlan_s[8]={0};
        jget(req,"port",port,sizeof(port));
        jget(req,"mac",mac_s,sizeof(mac_s));
        jget(req,"vlan",vlan_s,sizeof(vlan_s));
        uint8_t mac[6]; fdb_mac_parse(mac_s,mac);
        uint16_t vlan=vlan_s[0]?(uint16_t)atoi(vlan_s):1;
        int rc=portsec_check(ps,port,mac,vlan);
        snprintf(resp,rsz,"{\"status\":\"ok\",\"result\":\"%s\"}",rc==0?"permit":"deny");

    } else if(strcmp(cmd,"sticky")==0){
        char port[16]={0},mac_s[24]={0},vlan_s[8]={0};
        jget(req,"port",port,sizeof(port));
        jget(req,"mac",mac_s,sizeof(mac_s));
        jget(req,"vlan",vlan_s,sizeof(vlan_s));
        uint8_t mac[6]; fdb_mac_parse(mac_s,mac);
        uint16_t vlan=vlan_s[0]?(uint16_t)atoi(vlan_s):1;
        int rc=portsec_make_sticky(ps,port,mac,vlan);
        snprintf(resp,rsz,"{\"status\":\"%s\"}",rc==0?"ok":"not_found");

    } else if(strcmp(cmd,"recover")==0){
        char port[16]={0}; jget(req,"port",port,sizeof(port));
        portsec_errdisable_recover(ps,port);
        snprintf(resp,rsz,"{\"status\":\"ok\",\"port\":\"%s\"}",port);

    } else if(strcmp(cmd,"show")==0){
        size_t pos=0;
        pos+=(size_t)snprintf(resp+pos,rsz-pos,
            "{\"status\":\"ok\",\"total_violations\":%llu,\"ports\":[",
            (unsigned long long)ps->total_violations);
        for(int i=0;i<ps->n_ports&&pos<rsz-256;i++){
            portsec_port_t *p=&ps->ports[i];
            if(i>0&&pos<rsz-2) resp[pos++]=',';
            pos+=(size_t)snprintf(resp+pos,rsz-pos,
                "{\"port\":\"%s\",\"enabled\":%s,\"err_disabled\":%s,"
                "\"max_macs\":%u,\"learned\":%d,"
                "\"violation\":\"%s\",\"viol_count\":%llu}",
                p->name,p->enabled?"true":"false",
                p->err_disabled?"true":"false",
                p->max_macs,p->n_learned,
                portsec_viol_str(p->violation),
                (unsigned long long)p->viol_count);
        }
        if(pos<rsz-4){resp[pos++]=']';resp[pos++]='}';resp[pos]='\0';}

    } else if(strcmp(cmd,"ping")==0){
        snprintf(resp,rsz,"{\"status\":\"ok\",\"msg\":\"pong\",\"module\":\"portsec\"}");
    } else snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"unknown cmd: %s\"}",cmd);
}

/* ================================================================
 * Storm Control IPC
 * ================================================================ */
static void storm_handler(void *ctx, const char *req,
                           char *resp, size_t rsz) {
    storm_table_t *st=(storm_table_t*)ctx;
    char cmd[32]={0}; jget(req,"cmd",cmd,sizeof(cmd));

    if(strcmp(cmd,"set_rate")==0){
        char port[16]={0},type_s[24]={0},pps_s[20]={0},burst_s[20]={0};
        jget(req,"port",port,sizeof(port));
        jget(req,"type",type_s,sizeof(type_s));
        jget(req,"pps",pps_s,sizeof(pps_s));
        jget(req,"burst",burst_s,sizeof(burst_s));
        storm_type_t t=STORM_BROADCAST;
        if(strstr(type_s,"unicast")) t=STORM_UNKNOWN_UNICAST;
        if(strstr(type_s,"multicast")) t=STORM_MULTICAST;
        uint64_t pps=(uint64_t)atoll(pps_s);
        uint64_t burst=burst_s[0]?(uint64_t)atoll(burst_s):0;
        int rc=storm_set_rate(st,port,t,pps,burst);
        snprintf(resp,rsz,"{\"status\":\"%s\",\"port\":\"%s\",\"type\":\"%s\",\"pps\":%llu}",
                 rc==0?"ok":"error",port,storm_type_str(t),(unsigned long long)pps);

    } else if(strcmp(cmd,"check")==0){
        char port[16]={0},type_s[24]={0};
        jget(req,"port",port,sizeof(port));
        jget(req,"type",type_s,sizeof(type_s));
        storm_type_t t=STORM_BROADCAST;
        if(strstr(type_s,"unicast"))   t=STORM_UNKNOWN_UNICAST;
        if(strstr(type_s,"multicast")) t=STORM_MULTICAST;
        int rc=storm_check(st,port,t);
        snprintf(resp,rsz,"{\"status\":\"ok\",\"result\":\"%s\"}",
                 rc==0?"pass":"drop");

    } else if(strcmp(cmd,"clear")==0){
        char port[16]={0}; jget(req,"port",port,sizeof(port));
        storm_clear_counters(st,port);
        snprintf(resp,rsz,"{\"status\":\"ok\",\"port\":\"%s\"}",port);

    } else if(strcmp(cmd,"show")==0){
        size_t pos=0;
        pos+=(size_t)snprintf(resp+pos,rsz-pos,
            "{\"status\":\"ok\",\"ports\":[");
        for(int i=0;i<st->n_ports&&pos<rsz-512;i++){
            storm_port_t *p=&st->ports[i];
            if(i>0&&pos<rsz-2) resp[pos++]=',';
            pos+=(size_t)snprintf(resp+pos,rsz-pos,
                "{\"port\":\"%s\",\"err_disabled\":%s,"
                "\"total_dropped\":%llu,\"buckets\":[",
                p->name,p->err_disabled?"true":"false",
                (unsigned long long)p->total_dropped);
            for(int t=0;t<STORM_TYPE_COUNT&&pos<rsz-128;t++){
                storm_bucket_t *b=&p->buckets[t];
                if(t>0&&pos<rsz-2) resp[pos++]=',';
                pos+=(size_t)snprintf(resp+pos,rsz-pos,
                    "{\"type\":\"%s\",\"enabled\":%s,"
                    "\"rate_pps\":%llu,\"dropped\":%llu,\"passed\":%llu}",
                    storm_type_str((storm_type_t)t),
                    b->enabled?"true":"false",
                    (unsigned long long)b->rate_pps,
                    (unsigned long long)b->dropped,
                    (unsigned long long)b->passed);
            }
            if(pos<rsz-4){resp[pos++]=']';resp[pos++]='}';}
        }
        if(pos<rsz-4){resp[pos++]=']';resp[pos++]='}';resp[pos]='\0';}

    } else if(strcmp(cmd,"ping")==0){
        snprintf(resp,rsz,"{\"status\":\"ok\",\"msg\":\"pong\",\"module\":\"storm\"}");
    } else snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"unknown cmd: %s\"}",cmd);
}

/* ================================================================
 * IGMP Snooping IPC
 * ================================================================ */
static void igmp_handler(void *ctx, const char *req,
                          char *resp, size_t rsz) {
    igmp_table_t *tbl=(igmp_table_t*)ctx;
    char cmd[32]={0}; jget(req,"cmd",cmd,sizeof(cmd));

    if(strcmp(cmd,"report")==0||strcmp(cmd,"leave")==0){
        char port[16]={0},grp_s[20]={0},vlan_s[8]={0};
        jget(req,"port",port,sizeof(port));
        jget(req,"group",grp_s,sizeof(grp_s));
        jget(req,"vlan",vlan_s,sizeof(vlan_s));
        struct in_addr ga; inet_pton(AF_INET,grp_s,&ga);
        uint32_t grp=ntohl(ga.s_addr);
        uint16_t vlan=vlan_s[0]?(uint16_t)atoi(vlan_s):1;
        uint8_t type=(cmd[0]=='r')?IGMP_V2_MEMBERSHIP_RPT:IGMP_V2_LEAVE_GROUP;
        igmp_process(tbl,vlan,port,type,grp);
        snprintf(resp,rsz,"{\"status\":\"ok\",\"group\":\"%s\",\"vlan\":%u}",grp_s,vlan);

    } else if(strcmp(cmd,"query")==0){
        char port[16]={0},vlan_s[8]={0};
        jget(req,"port",port,sizeof(port));
        jget(req,"vlan",vlan_s,sizeof(vlan_s));
        uint16_t vlan=vlan_s[0]?(uint16_t)atoi(vlan_s):1;
        igmp_process(tbl,vlan,port,IGMP_MEMBERSHIP_QUERY,0);
        snprintf(resp,rsz,"{\"status\":\"ok\"}");

    } else if(strcmp(cmd,"age")==0){
        int r=igmp_age_sweep(tbl);
        snprintf(resp,rsz,"{\"status\":\"ok\",\"removed\":%d}",r);

    } else if(strcmp(cmd,"show")==0){
        size_t pos=0;
        pos+=(size_t)snprintf(resp+pos,rsz-pos,
            "{\"status\":\"ok\",\"groups\":[");
        int first=1;
        for(int i=0;i<tbl->n_groups&&pos<rsz-512;i++){
            igmp_group_t *g=&tbl->groups[i];
            if(!g->active) continue;
            char gs[20]; igmp_group_str(g->group,gs,sizeof(gs));
            if(!first&&pos<rsz-2) resp[pos++]=',';
            pos+=(size_t)snprintf(resp+pos,rsz-pos,
                "{\"group\":\"%s\",\"vlan\":%u,"
                "\"members\":%d,\"reports\":%llu,\"leaves\":%llu}",
                gs,g->vlan,g->n_members,
                (unsigned long long)g->report_count,
                (unsigned long long)g->leave_count);
            first=0;
        }
        if(pos<rsz-4){resp[pos++]=']';resp[pos++]='}';resp[pos]='\0';}

    } else if(strcmp(cmd,"stats")==0){
        snprintf(resp,rsz,
            "{\"status\":\"ok\","
            "\"groups\":%d,\"reports\":%llu,"
            "\"leaves\":%llu,\"queries\":%llu}",
            tbl->n_groups,
            (unsigned long long)tbl->total_reports,
            (unsigned long long)tbl->total_leaves,
            (unsigned long long)tbl->total_queries);
    } else if(strcmp(cmd,"ping")==0){
        snprintf(resp,rsz,"{\"status\":\"ok\",\"msg\":\"pong\",\"module\":\"igmp\"}");
    } else snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"unknown cmd: %s\"}",cmd);
}

/* ================================================================
 * ARP/ND Snooping IPC
 * ================================================================ */
static void arp_handler(void *ctx, const char *req,
                         char *resp, size_t rsz) {
    arpsnoop_table_t *tbl=(arpsnoop_table_t*)ctx;
    char cmd[32]={0}; jget(req,"cmd",cmd,sizeof(cmd));

    if(strcmp(cmd,"learn")==0){
        char mac_s[24]={0},ip_s[48]={0},port[16]={0};
        char vlan_s[8]={0},type_s[12]={0},v6_s[8]={0};
        jget(req,"mac",mac_s,sizeof(mac_s));
        jget(req,"ip",ip_s,sizeof(ip_s));
        jget(req,"port",port,sizeof(port));
        jget(req,"vlan",vlan_s,sizeof(vlan_s));
        jget(req,"type",type_s,sizeof(type_s));
        jget(req,"ipv6",v6_s,sizeof(v6_s));
        uint8_t mac[6]; fdb_mac_parse(mac_s,mac);
        uint8_t ip[16]={0};
        int is_v6=(v6_s[0]=='t'||v6_s[0]=='1');
        if(is_v6) inet_pton(AF_INET6,ip_s,ip);
        else { struct in_addr a; inet_pton(AF_INET,ip_s,&a); memcpy(ip,&a,4); }
        uint16_t vlan=vlan_s[0]?(uint16_t)atoi(vlan_s):1;
        arpsnoop_type_t t=ARPSNOOP_TYPE_ARP;
        if(strstr(type_s,"nd"))     t=ARPSNOOP_TYPE_ND;
        if(strstr(type_s,"dhcp"))   t=ARPSNOOP_TYPE_DHCP;
        if(strstr(type_s,"static")) t=ARPSNOOP_TYPE_STATIC;
        int rc=arpsnoop_learn(tbl,mac,ip,is_v6,vlan,port,t);
        snprintf(resp,rsz,"{\"status\":\"%s\",\"ip\":\"%s\",\"mac\":\"%s\"}",
                 rc==0?"ok":(rc==-1?"violation":"error"),ip_s,mac_s);

    } else if(strcmp(cmd,"lookup")==0){
        char ip_s[48]={0},vlan_s[8]={0},v6_s[8]={0};
        jget(req,"ip",ip_s,sizeof(ip_s));
        jget(req,"vlan",vlan_s,sizeof(vlan_s));
        jget(req,"ipv6",v6_s,sizeof(v6_s));
        uint8_t ip[16]={0};
        int is_v6=(v6_s[0]=='t'||v6_s[0]=='1');
        if(is_v6) inet_pton(AF_INET6,ip_s,ip);
        else { struct in_addr a; inet_pton(AF_INET,ip_s,&a); memcpy(ip,&a,4); }
        uint16_t vlan=vlan_s[0]?(uint16_t)atoi(vlan_s):1;
        const arpsnoop_entry_t *e=arpsnoop_lookup_ip(tbl,ip,is_v6,vlan);
        if(e){
            char ms[24]; fdb_mac_str(e->mac,ms,sizeof(ms));
            snprintf(resp,rsz,
                "{\"status\":\"ok\",\"ip\":\"%s\","
                "\"mac\":\"%s\",\"port\":\"%s\","
                "\"vlan\":%u,\"hits\":%llu}",
                ip_s,ms,e->port,e->vlan,
                (unsigned long long)e->hit_count);
        } else snprintf(resp,rsz,"{\"status\":\"miss\"}");

    } else if(strcmp(cmd,"age")==0){
        int r=arpsnoop_age_sweep(tbl);
        snprintf(resp,rsz,"{\"status\":\"ok\",\"aged_out\":%d}",r);

    } else if(strcmp(cmd,"show")==0){
        size_t pos=0;
        pos+=(size_t)snprintf(resp+pos,rsz-pos,
            "{\"status\":\"ok\",\"count\":%d,\"entries\":[",tbl->count);
        int first=1;
        for(int b=0;b<ARPSNOOP_BUCKETS&&pos<rsz-256;b++){
            arpsnoop_entry_t *e=tbl->buckets[b];
            while(e&&pos<rsz-256){
                char ms[24],is[48];
                fdb_mac_str(e->mac,ms,sizeof(ms));
                arpsnoop_ip_str(e->ip,e->is_ipv6,is,sizeof(is));
                if(!first&&pos<rsz-2) resp[pos++]=',';
                pos+=(size_t)snprintf(resp+pos,rsz-pos,
                    "{\"ip\":\"%s\",\"mac\":\"%s\","
                    "\"port\":\"%s\",\"vlan\":%u,"
                    "\"ipv6\":%s,\"hits\":%llu}",
                    is,ms,e->port,e->vlan,
                    e->is_ipv6?"true":"false",
                    (unsigned long long)e->hit_count);
                first=0; e=e->next;
            }
        }
        if(pos<rsz-4){resp[pos++]=']';resp[pos++]='}';resp[pos]='\0';}

    } else if(strcmp(cmd,"stats")==0){
        snprintf(resp,rsz,
            "{\"status\":\"ok\","
            "\"bindings\":%d,\"learned\":%llu,"
            "\"aged\":%llu,\"violations\":%llu}",
            tbl->count,
            (unsigned long long)tbl->total_learned,
            (unsigned long long)tbl->total_aged,
            (unsigned long long)tbl->total_violations);
    } else if(strcmp(cmd,"ping")==0){
        snprintf(resp,rsz,"{\"status\":\"ok\",\"msg\":\"pong\",\"module\":\"arpsnoop\"}");
    } else snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"unknown cmd: %s\"}",cmd);
}

/* ================================================================
 * LACP IPC
 * ================================================================ */
static void lacp_handler(void *ctx, const char *req,
                          char *resp, size_t rsz) {
    lacp_table_t *lt=(lacp_table_t*)ctx;
    char cmd[32]={0}; jget(req,"cmd",cmd,sizeof(cmd));

    if(strcmp(cmd,"lag_add")==0){
        char name[16]={0},key_s[8]={0};
        jget(req,"lag",name,sizeof(name));
        jget(req,"key",key_s,sizeof(key_s));
        uint16_t key=key_s[0]?(uint16_t)atoi(key_s):1;
        lacp_lag_t *l=lacp_lag_add(lt,name,key);
        snprintf(resp,rsz,"{\"status\":\"%s\",\"lag\":\"%s\",\"key\":%u}",
                 l?"ok":"error",name,key);

    } else if(strcmp(cmd,"lag_del")==0){
        char name[16]={0}; jget(req,"lag",name,sizeof(name));
        int rc=lacp_lag_del(lt,name);
        snprintf(resp,rsz,"{\"status\":\"%s\"}",rc==0?"ok":"not_found");

    } else if(strcmp(cmd,"member_add")==0){
        char lag_s[16]={0},port[16]={0},mode_s[12]={0};
        jget(req,"lag",lag_s,sizeof(lag_s));
        jget(req,"port",port,sizeof(port));
        jget(req,"mode",mode_s,sizeof(mode_s));
        lacp_lag_t *l=lacp_lag_find(lt,lag_s);
        if(!l){snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"lag not found\"}");return;}
        lacp_mode_t mode=LACP_MODE_ACTIVE;
        if(strcmp(mode_s,"passive")==0) mode=LACP_MODE_PASSIVE;
        if(strcmp(mode_s,"static")==0)  mode=LACP_MODE_STATIC;
        if(strcmp(mode_s,"off")==0)     mode=LACP_MODE_OFF;
        lacp_member_t *m=lacp_member_add(l,port,mode);
        snprintf(resp,rsz,"{\"status\":\"%s\",\"lag\":\"%s\",\"port\":\"%s\",\"mode\":\"%s\"}",
                 m?"ok":"error",lag_s,port,lacp_mode_str(mode));

    } else if(strcmp(cmd,"member_del")==0){
        char lag_s[16]={0},port[16]={0};
        jget(req,"lag",lag_s,sizeof(lag_s));
        jget(req,"port",port,sizeof(port));
        lacp_lag_t *l=lacp_lag_find(lt,lag_s);
        if(!l){snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"lag not found\"}");return;}
        int rc=lacp_member_del(l,port);
        snprintf(resp,rsz,"{\"status\":\"%s\"}",rc==0?"ok":"not_found");

    } else if(strcmp(cmd,"bpdu")==0){
        /* inject LACPDU: {"cmd":"bpdu","lag":"bond0","port":"eth0",
                          "actor_sys":"8000.aabbcc000099","actor_key":"1",
                          "actor_state":"61"} */
        char lag_s[16]={0},port[16]={0},sys_s[32]={0};
        char key_s[8]={0},state_s[8]={0};
        jget(req,"lag",lag_s,sizeof(lag_s));
        jget(req,"port",port,sizeof(port));
        jget(req,"actor_sys",sys_s,sizeof(sys_s));
        jget(req,"actor_key",key_s,sizeof(key_s));
        jget(req,"actor_state",state_s,sizeof(state_s));
        lacp_lag_t *l=lacp_lag_find(lt,lag_s);
        lacp_member_t *m=l?lacp_member_find(l,port):NULL;
        if(!m){snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"lag/port not found\"}");return;}
        lacp_pdu_t pdu; memset(&pdu,0,sizeof(pdu));
        pdu.actor_key=(uint16_t)(key_s[0]?atoi(key_s):1);
        pdu.actor_state=(uint8_t)(state_s[0]?(uint8_t)atoi(state_s):0x3D);
        if(sys_s[0]){
            unsigned int prio=0; unsigned int mm[6]={0};
            sscanf(sys_s,"%x.%02x%02x%02x%02x%02x%02x",
                   &prio,&mm[0],&mm[1],&mm[2],&mm[3],&mm[4],&mm[5]);
            pdu.actor_sys.priority=(uint16_t)prio;
            for(int i=0;i<6;i++) pdu.actor_sys.mac[i]=(uint8_t)mm[i];
        }
        lacp_receive(lt,l,m,&pdu);
        snprintf(resp,rsz,
            "{\"status\":\"ok\",\"port\":\"%s\","
            "\"mux_state\":\"%s\",\"selected\":%s}",
            port,lacp_mstate_str(m->mux_state),
            m->selected?"true":"false");

    } else if(strcmp(cmd,"tick")==0){
        lacp_tick(lt);
        snprintf(resp,rsz,"{\"status\":\"ok\"}");

    } else if(strcmp(cmd,"hash")==0){
        char lag_s[16]={0},src_s[24]={0},dst_s[24]={0};
        jget(req,"lag",lag_s,sizeof(lag_s));
        jget(req,"src",src_s,sizeof(src_s));
        jget(req,"dst",dst_s,sizeof(dst_s));
        lacp_lag_t *l=lacp_lag_find(lt,lag_s);
        if(!l){snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"lag not found\"}");return;}
        uint8_t src[6]={0},dst[6]={0};
        fdb_mac_parse(src_s,src); fdb_mac_parse(dst_s,dst);
        int idx=lacp_select_member(l,src,dst);
        if(idx<0) snprintf(resp,rsz,"{\"status\":\"ok\",\"member\":null}");
        else snprintf(resp,rsz,"{\"status\":\"ok\",\"member\":\"%s\",\"index\":%d}",
                     l->members[idx].port,idx);

    } else if(strcmp(cmd,"show")==0){
        size_t pos=0;
        pos+=(size_t)snprintf(resp+pos,rsz-pos,
            "{\"status\":\"ok\",\"lags\":[");
        int first=1;
        for(int i=0;i<lt->n_lags&&pos<rsz-512;i++){
            lacp_lag_t *l=&lt->lags[i];
            if(!l->active) continue;
            if(!first&&pos<rsz-2) resp[pos++]=',';
            pos+=(size_t)snprintf(resp+pos,rsz-pos,
                "{\"name\":\"%s\",\"key\":%u,"
                "\"n_members\":%d,\"n_active\":%d,\"members\":[",
                l->name,l->key,l->n_members,l->n_active);
            for(int j=0;j<l->n_members&&pos<rsz-128;j++){
                lacp_member_t *m=&l->members[j];
                if(j>0&&pos<rsz-2) resp[pos++]=',';
                pos+=(size_t)snprintf(resp+pos,rsz-pos,
                    "{\"port\":\"%s\",\"mode\":\"%s\","
                    "\"mux\":\"%s\",\"selected\":%s,"
                    "\"pdu_rx\":%llu,\"pdu_tx\":%llu}",
                    m->port,lacp_mode_str(m->mode),
                    lacp_mstate_str(m->mux_state),
                    m->selected?"true":"false",
                    (unsigned long long)m->pdu_rx,
                    (unsigned long long)m->pdu_tx);
            }
            if(pos<rsz-4){resp[pos++]=']';resp[pos++]='}';}
            first=0;
        }
        if(pos<rsz-4){resp[pos++]=']';resp[pos++]='}';resp[pos]='\0';}

    } else if(strcmp(cmd,"ping")==0){
        snprintf(resp,rsz,"{\"status\":\"ok\",\"msg\":\"pong\",\"module\":\"lacp\"}");
    } else snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"unknown cmd: %s\"}",cmd);
}

/* ================================================================
 * Public serve entry points
 * ================================================================ */
typedef struct { const char *path; void *ctx;
    void (*h)(void*,const char*,char*,size_t); volatile int *r; } _sa;

static void *_serve(void *a) {
    _sa *s=(_sa*)a; sock_serve(s->path,s->ctx,s->h,s->r); return NULL;
}

#include <pthread.h>

int l2_extra_serve(vlan_db_t *vlan, portsec_table_t *ps,
                    storm_table_t *storm, igmp_table_t *igmp,
                    arpsnoop_table_t *arp, lacp_table_t *lacp,
                    const l2_extra_paths_t *paths,
                    volatile int *running)
{
    static _sa args[5];
    static pthread_t tids[5];

    args[0]=(_sa){paths->portsec, ps,    portsec_handler, running};
    args[1]=(_sa){paths->storm,   storm, storm_handler,   running};
    args[2]=(_sa){paths->igmp,    igmp,  igmp_handler,    running};
    args[3]=(_sa){paths->arp,     arp,   arp_handler,     running};
    args[4]=(_sa){paths->lacp,    lacp,  lacp_handler,    running};

    for(int i=0;i<5;i++)
        pthread_create(&tids[i],NULL,_serve,&args[i]);

    /* VLAN on calling thread */
    sock_serve(paths->vlan, vlan, vlan_handler, running);

    for(int i=0;i<5;i++) pthread_join(tids[i],NULL);
    return 0;
}
