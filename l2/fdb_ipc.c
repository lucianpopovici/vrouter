#include "fdb_ipc.h"
#include "fdb.h"
#include "l2_cli.h"
#include "../l3/json_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>

#define IPC_BUF  4096
#define IPC_RESP 32768


static void handle(fdb_table_t *fdb, l2_config_t *cfg,
                   const char *req, char *resp, size_t rsz)
{
    char cmd[32]={0}; jget(req,"cmd",cmd,sizeof(cmd));

    if (strcmp(cmd,"learn")==0) {
        char mac_s[24]={0},port[16]={0},vlan_s[8]={0},flags_s[16]={0};
        jget(req,"mac",mac_s,sizeof(mac_s));
        jget(req,"port",port,sizeof(port));
        jget(req,"vlan",vlan_s,sizeof(vlan_s));
        jget(req,"flags",flags_s,sizeof(flags_s));
        uint8_t mac[6]; fdb_mac_parse(mac_s,mac);
        uint16_t vlan = vlan_s[0]?(uint16_t)atoi(vlan_s):1;
        uint32_t flags= FDB_FLAG_DYNAMIC;
        if (strstr(flags_s,"static"))  flags=FDB_FLAG_STATIC;
        if (strstr(flags_s,"local"))   flags=FDB_FLAG_LOCAL;
        if (strstr(flags_s,"evpn"))    flags=FDB_FLAG_EVPN;
        if (!port[0]) strncpy(port,"unknown",sizeof(port)-1);
        int rc=fdb_learn(fdb,mac,vlan,port,flags,0);
        snprintf(resp,rsz,"{\"status\":\"%s\",\"mac\":\"%s\",\"vlan\":%u}",
                 rc==0?"ok":"error",mac_s,vlan);

    } else if (strcmp(cmd,"lookup")==0) {
        char mac_s[24]={0},vlan_s[8]={0};
        jget(req,"mac",mac_s,sizeof(mac_s));
        jget(req,"vlan",vlan_s,sizeof(vlan_s));
        uint8_t mac[6]; fdb_mac_parse(mac_s,mac);
        uint16_t vlan=vlan_s[0]?(uint16_t)atoi(vlan_s):1;
        fdb_entry_t entry;
        if (fdb_lookup(fdb,mac,vlan,&entry)==0)
            snprintf(resp,rsz,
                "{\"status\":\"ok\",\"mac\":\"%s\",\"vlan\":%u,"
                "\"port\":\"%s\",\"hits\":%llu}",
                mac_s,vlan,entry.port,
                (unsigned long long)atomic_load_explicit(&entry.hit_count, memory_order_relaxed));
        else
            snprintf(resp,rsz,
                "{\"status\":\"miss\",\"mac\":\"%s\",\"vlan\":%u,"
                "\"action\":\"flood\"}",mac_s,vlan);

    } else if (strcmp(cmd,"delete")==0) {
        char mac_s[24]={0},vlan_s[8]={0};
        jget(req,"mac",mac_s,sizeof(mac_s));
        jget(req,"vlan",vlan_s,sizeof(vlan_s));
        uint8_t mac[6]; fdb_mac_parse(mac_s,mac);
        uint16_t vlan=vlan_s[0]?(uint16_t)atoi(vlan_s):1;
        int rc=fdb_delete(fdb,mac,vlan);
        snprintf(resp,rsz,"{\"status\":\"%s\"}",rc==0?"ok":"not_found");

    } else if (strcmp(cmd,"flush")==0) {
        char port[16]={0},vlan_s[8]={0};
        jget(req,"port",port,sizeof(port));
        jget(req,"vlan",vlan_s,sizeof(vlan_s));
        int removed=0;
        if (port[0])           removed=fdb_flush_port(fdb,port);
        else if (vlan_s[0])    removed=fdb_flush_vlan(fdb,(uint16_t)atoi(vlan_s));
        else { fdb_flush_all(fdb); removed=-1; }
        snprintf(resp,rsz,"{\"status\":\"ok\",\"removed\":%d}",removed);

    } else if (strcmp(cmd,"age")==0) {
        int removed=fdb_age_sweep(fdb);
        snprintf(resp,rsz,"{\"status\":\"ok\",\"aged_out\":%d}",removed);

    } else if (strcmp(cmd,"show")==0) {
        char port_f[16]={0},vlan_s[8]={0};
        jget(req,"port",port_f,sizeof(port_f));
        jget(req,"vlan",vlan_s,sizeof(vlan_s));
        uint16_t vlan_f=vlan_s[0]?(uint16_t)atoi(vlan_s):0;

        size_t pos=0;
        pos+=(size_t)snprintf(resp+pos,rsz-pos,
            "{\"status\":\"ok\",\"count\":%d,\"entries\":[",fdb->count);
        int first=1;
        for (int b=0;b<FDB_BUCKETS&&pos<rsz-256;b++) {
            fdb_entry_t *e=fdb->buckets[b];
            while(e&&pos<rsz-256){
                if((!port_f[0]||strncmp(e->port,port_f,16)==0)&&
                   (!vlan_f||e->vlan==vlan_f)){
                    char ms[24]; fdb_mac_str(e->mac,ms,sizeof(ms));
                    if(!first&&pos<rsz-2) resp[pos++]=',';
                    pos+=(size_t)snprintf(resp+pos,rsz-pos,
                        "{\"mac\":\"%s\",\"vlan\":%u,\"port\":\"%s\","
                        "\"flags\":%u,\"hits\":%llu}",
                        ms,e->vlan,e->port,e->flags,
                        (unsigned long long)atomic_load_explicit(&e->hit_count, memory_order_relaxed));
                    first=0;
                }
                e=e->next;
            }
        }
        if(pos<rsz-3){resp[pos++]=']';resp[pos++]='}';resp[pos]='\0';}

    } else if (strcmp(cmd,"stats")==0) {
        snprintf(resp,rsz,
            "{\"status\":\"ok\",\"entries\":%d,"
            "\"lookups\":%llu,\"hits\":%llu,\"misses\":%llu,"
            "\"aged\":%llu,\"age_sec\":%u}",
            fdb->count,
            (unsigned long long)atomic_load_explicit(&fdb->total_lookups, memory_order_relaxed),
            (unsigned long long)atomic_load_explicit(&fdb->total_hits,    memory_order_relaxed),
            (unsigned long long)atomic_load_explicit(&fdb->total_misses,  memory_order_relaxed),
            (unsigned long long)atomic_load_explicit(&fdb->entries_aged,  memory_order_relaxed),
            fdb->age_sec);

    } else if (strcmp(cmd,"set_age")==0) {
        char v[16]={0}; jget(req,"age",v,sizeof(v));
        if(v[0]){ fdb->age_sec=(uint32_t)atoi(v);
            snprintf(resp,rsz,"{\"status\":\"ok\",\"age_sec\":%u}",fdb->age_sec);}
        else snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"missing age\"}");

    } else if (strcmp(cmd,"get")==0) {
        char key[32]={0}; jget(req,"key",key,sizeof(key));
        char val[64]={0};
        if      (strcmp(key,"FDB_AGE_SEC"    )==0) snprintf(val,sizeof(val),"%u",cfg->fdb_age_sec);
        else if (strcmp(key,"FDB_MAX_ENTRIES")==0) snprintf(val,sizeof(val),"%u",cfg->fdb_max_entries);
        else { snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"unknown key: %s\"}",key); return; }
        snprintf(resp,rsz,"{\"status\":\"ok\",\"key\":\"%s\",\"value\":\"%s\"}",key,val);

    } else if (strcmp(cmd,"set")==0) {
        char key[32]={0},val[64]={0};
        jget(req,"key",key,sizeof(key));
        jget(req,"value",val,sizeof(val));
        if (strcmp(key,"FDB_AGE_SEC")==0) {
            int v=atoi(val);
            if(v<10||v>86400){snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"FDB_AGE_SEC out of range (10-86400)\"}");return;}
            cfg->fdb_age_sec=(uint32_t)v;
            fdb->age_sec=(uint32_t)v;
            l2_cli_save_key(key,val);
        } else if (strcmp(key,"FDB_MAX_ENTRIES")==0) {
            int v=atoi(val);
            if(v<100||v>524288){snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"FDB_MAX_ENTRIES out of range (100-524288)\"}");return;}
            cfg->fdb_max_entries=(uint32_t)v;
            l2_cli_save_key(key,val);
        } else {
            snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"unknown key: %s\"}",key); return;
        }
        snprintf(resp,rsz,"{\"status\":\"ok\",\"key\":\"%s\",\"value\":\"%s\"}",key,val);

    } else if (strcmp(cmd,"ping")==0) {
        snprintf(resp,rsz,
            "{\"status\":\"ok\",\"msg\":\"pong\",\"module\":\"fdb\"}");
    } else {
        snprintf(resp,rsz,
            "{\"status\":\"error\",\"msg\":\"unknown cmd: %s\"}",cmd);
    }
}

int fdb_ipc_serve(fdb_table_t *fdb, struct l2_config *cfg,
                  const char *sock_path, volatile int *running)
{
    unlink(sock_path);
    int srv=socket(AF_UNIX,SOCK_STREAM,0);
    if(srv<0){perror("fdb socket");return -1;}
    struct sockaddr_un addr;
    memset(&addr,0,sizeof(addr));
    addr.sun_family=AF_UNIX;
    strncpy(addr.sun_path,sock_path,sizeof(addr.sun_path)-1);
    if(bind(srv,(struct sockaddr*)&addr,sizeof(addr))<0||listen(srv,8)<0){
        perror("fdb bind/listen");close(srv);return -1;}
    fprintf(stderr,"[fdb]  listening on %s\n",sock_path);
    char req[IPC_BUF],resp[IPC_RESP];
    while(*running){
        fd_set rfds; FD_ZERO(&rfds); FD_SET(srv,&rfds);
        struct timeval tv={1,0};
        if(select(srv+1,&rfds,NULL,NULL,&tv)<=0) continue;
        int cli=accept(srv,NULL,NULL); if(cli<0) continue;
        ssize_t n=recv(cli,req,sizeof(req)-1,0);
        if(n>0){req[n]='\0';handle(fdb,(l2_config_t*)cfg,req,resp,sizeof(resp));
                send(cli,resp,strlen(resp),0);}
        close(cli);
    }
    close(srv); unlink(sock_path); return 0;
}
