#include "l2rib_ipc.h"
#include "l2rib.h"
#include "fdb.h"
#include "l2_cli.h"
#include "../l3/json_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>

#define IPC_BUF  4096
#define IPC_RESP 32768


/* Push best candidate into FDB */
static void push_to_fdb(const l2rib_entry_t *entry,
                        const l2rib_candidate_t *best,
                        int install, void *ctx)
{
    fdb_table_t *fdb=(fdb_table_t*)ctx;
    uint32_t flags=FDB_FLAG_DYNAMIC;
    if(best->source==L2_SRC_STATIC) flags=FDB_FLAG_STATIC;
    if(best->source==L2_SRC_LOCAL)  flags=FDB_FLAG_LOCAL;
    if(best->source==L2_SRC_EVPN)   flags=FDB_FLAG_EVPN;
    char ms[24]; fdb_mac_str(entry->mac,ms,sizeof(ms));
    if(install){
        fdb_learn(fdb,entry->mac,entry->vlan,
                  best->port,flags,best->age_sec);
        fprintf(stderr,"[l2rib] → FDB learn %s vlan %u port %s (%s)\n",
                ms,entry->vlan,best->port,L2_SRC_NAME[best->source]);
    } else {
        fdb_delete(fdb,entry->mac,entry->vlan);
        fprintf(stderr,"[l2rib] → FDB withdraw %s vlan %u\n",
                ms,entry->vlan);
    }
}

static void handle(l2rib_table_t *rib, fdb_table_t *fdb,
                   l2_config_t *cfg,
                   const char *req, char *resp, size_t rsz)
{
    char cmd[32]={0}; jget(req,"cmd",cmd,sizeof(cmd));

    if(strcmp(cmd,"add")==0){
        char mac_s[24]={0},port[16]={0},vlan_s[8]={0},src_s[16]={0},age_s[16]={0};
        jget(req,"mac",mac_s,sizeof(mac_s));
        jget(req,"port",port,sizeof(port));
        jget(req,"vlan",vlan_s,sizeof(vlan_s));
        jget(req,"source",src_s,sizeof(src_s));
        jget(req,"age",age_s,sizeof(age_s));
        uint8_t mac[6]; fdb_mac_parse(mac_s,mac);
        uint16_t vlan=vlan_s[0]?(uint16_t)atoi(vlan_s):1;
        l2rib_source_t src=(l2rib_source_t)l2rib_source_from_str(src_s);
        uint32_t age=age_s[0]?(uint32_t)atoi(age_s):0;
        if(!port[0]) strncpy(port,"unknown",sizeof(port)-1);
        int rc=l2rib_add(rib,mac,vlan,port,src,0,age,push_to_fdb,fdb);
        snprintf(resp,rsz,"{\"status\":\"%s\",\"mac\":\"%s\",\"vlan\":%u,\"source\":\"%s\"}",
                 rc==0?"ok":"error",mac_s,vlan,L2_SRC_NAME[src]);

    } else if(strcmp(cmd,"del")==0){
        char mac_s[24]={0},vlan_s[8]={0},src_s[16]={0};
        jget(req,"mac",mac_s,sizeof(mac_s));
        jget(req,"vlan",vlan_s,sizeof(vlan_s));
        jget(req,"source",src_s,sizeof(src_s));
        uint8_t mac[6]; fdb_mac_parse(mac_s,mac);
        uint16_t vlan=vlan_s[0]?(uint16_t)atoi(vlan_s):1;
        l2rib_source_t src=(l2rib_source_t)l2rib_source_from_str(src_s);
        int rc=l2rib_del(rib,mac,vlan,src,push_to_fdb,fdb);
        snprintf(resp,rsz,"{\"status\":\"%s\"}",rc==0?"ok":"not_found");

    } else if(strcmp(cmd,"show")==0){
        size_t pos=0;
        pos+=(size_t)snprintf(resp+pos,rsz-pos,
            "{\"status\":\"ok\",\"count\":%d,\"entries\":[",rib->count);
        int first=1;
        for(int b=0;b<L2RIB_BUCKETS&&pos<rsz-512;b++){
            l2rib_entry_t *e=rib->buckets[b];
            while(e&&pos<rsz-512){
                char ms[24]; fdb_mac_str(e->mac,ms,sizeof(ms));
                if(!first&&pos<rsz-2) resp[pos++]=',';
                pos+=(size_t)snprintf(resp+pos,rsz-pos,
                    "{\"mac\":\"%s\",\"vlan\":%u,\"candidates\":[",
                    ms,e->vlan);
                for(int i=0;i<e->n_candidates&&pos<rsz-128;i++){
                    const l2rib_candidate_t *c=&e->candidates[i];
                    if(i>0&&pos<rsz-2) resp[pos++]=',';
                    pos+=(size_t)snprintf(resp+pos,rsz-pos,
                        "{\"port\":\"%s\",\"source\":\"%s\",\"best\":%s}",
                        c->port,L2_SRC_NAME[c->source],
                        c->active?"true":"false");
                }
                if(pos<rsz-4){resp[pos++]=']';resp[pos++]='}';}
                first=0;
                e=e->next;
            }
        }
        if(pos<rsz-4){resp[pos++]=']';resp[pos++]='}';resp[pos]='\0';}

    } else if(strcmp(cmd,"stats")==0){
        snprintf(resp,rsz,
            "{\"status\":\"ok\",\"entries\":%d,"
            "\"added\":%llu,\"deleted\":%llu,\"fdb_updates\":%llu}",
            rib->count,
            (unsigned long long)rib->n_added,
            (unsigned long long)rib->n_deleted,
            (unsigned long long)rib->n_fdb_updates);

    } else if(strcmp(cmd,"get")==0){
        char key[32]={0}; jget(req,"key",key,sizeof(key));
        char val[64]={0};
        if      (strcmp(key,"FDB_AGE_SEC"    )==0) snprintf(val,sizeof(val),"%u",cfg->fdb_age_sec);
        else if (strcmp(key,"FDB_MAX_ENTRIES")==0) snprintf(val,sizeof(val),"%u",cfg->fdb_max_entries);
        else { snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"unknown key: %s\"}",key); return; }
        snprintf(resp,rsz,"{\"status\":\"ok\",\"key\":\"%s\",\"value\":\"%s\"}",key,val);

    } else if(strcmp(cmd,"set")==0){
        char key[32]={0},val[64]={0};
        jget(req,"key",key,sizeof(key));
        jget(req,"value",val,sizeof(val));
        if (strcmp(key,"FDB_AGE_SEC")==0) {
            int v=atoi(val);
            if(v<10||v>86400){snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"out of range\"}");return;}
            cfg->fdb_age_sec=(uint32_t)v; fdb->age_sec=(uint32_t)v;
            l2_cli_save_key(key,val);
        } else if (strcmp(key,"FDB_MAX_ENTRIES")==0) {
            int v=atoi(val);
            if(v<100||v>524288){snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"out of range\"}");return;}
            cfg->fdb_max_entries=(uint32_t)v;
            l2_cli_save_key(key,val);
        } else {
            snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"unknown key: %s\"}",key); return;
        }
        snprintf(resp,rsz,"{\"status\":\"ok\",\"key\":\"%s\",\"value\":\"%s\"}",key,val);

    } else if(strcmp(cmd,"ping")==0){
        snprintf(resp,rsz,
            "{\"status\":\"ok\",\"msg\":\"pong\",\"module\":\"l2rib\"}");
    } else {
        snprintf(resp,rsz,
            "{\"status\":\"error\",\"msg\":\"unknown cmd: %s\"}",cmd);
    }
}

int l2rib_ipc_serve(l2rib_table_t *rib, fdb_table_t *fdb,
                    struct l2_config *cfg, const char *sock_path, volatile int *running)
{
    unlink(sock_path);
    int srv=socket(AF_UNIX,SOCK_STREAM,0);
    if(srv<0){perror("l2rib socket");return -1;}
    struct sockaddr_un addr;
    memset(&addr,0,sizeof(addr));
    addr.sun_family=AF_UNIX;
    strncpy(addr.sun_path,sock_path,sizeof(addr.sun_path)-1);
    if(bind(srv,(struct sockaddr*)&addr,sizeof(addr))<0||listen(srv,8)<0){
        perror("l2rib bind/listen");close(srv);return -1;}
    fprintf(stderr,"[l2rib] listening on %s\n",sock_path);
    char req[IPC_BUF],resp[IPC_RESP];
    while(*running){
        fd_set rfds; FD_ZERO(&rfds); FD_SET(srv,&rfds);
        struct timeval tv={1,0};
        if(select(srv+1,&rfds,NULL,NULL,&tv)<=0) continue;
        int cli=accept(srv,NULL,NULL); if(cli<0) continue;
        ssize_t n=recv(cli,req,sizeof(req)-1,0);
        if(n>0){req[n]='\0';handle(rib,fdb,(l2_config_t*)cfg,req,resp,sizeof(resp));
                send(cli,resp,strlen(resp),0);}
        close(cli);
    }
    close(srv); unlink(sock_path); return 0;
}
