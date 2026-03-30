#include "stp_ipc.h"
#include "stp.h"
#include "fdb.h"
#include "l2_cli.h"
#include <vrouter/json.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <arpa/inet.h>

#define IPC_BUF  4096
#define IPC_RESP 32768


/* ─── Flush FDB on topology change ──────────────────────────── */
static void tc_flush_fdb(fdb_table_t *fdb, const char *port)
{
    if (port && port[0]) fdb_flush_port(fdb, port);
    else                 fdb_flush_all(fdb);
}

/* ─── Encode port info as JSON object ────────────────────────── */
static size_t port_json(const stp_port_t *p, char *buf, size_t sz)
{
    char rid[32], did[32];
    stp_bridge_id_str(&p->designated_root,   rid, sizeof(rid));
    stp_bridge_id_str(&p->designated_bridge, did, sizeof(did));
    return (size_t)snprintf(buf, sz,
        "{\"name\":\"%s\",\"state\":\"%s\",\"role\":\"%s\","
        "\"cost\":%u,\"root_cost\":%u,\"edge\":%s,\"p2p\":%s,"
        "\"agreed\":%s,\"proposing\":%s,"
        "\"des_root\":\"%s\",\"des_bridge\":\"%s\","
        "\"bpdu_rx\":%llu,\"bpdu_tx\":%llu,\"tc_rx\":%llu}",
        p->name, stp_state_str(p->state), stp_role_str(p->role),
        p->path_cost, p->root_path_cost,
        p->edge?"true":"false", p->point_to_point?"true":"false",
        p->agreed?"true":"false", p->proposing?"true":"false",
        rid, did,
        (unsigned long long)p->bpdu_rx,
        (unsigned long long)p->bpdu_tx,
        (unsigned long long)p->tc_rx);
}

static void handle(stp_bridge_t *br, fdb_table_t *fdb,
                   l2_config_t *cfg,
                   const char *req, char *resp, size_t rsz)
{
    char cmd[32]={0}; vr_json_get_str(req,"cmd",cmd,sizeof(cmd));

    /* ── show bridge ────────────────────────────────────────── */
    if (strcmp(cmd,"show")==0) {
        char rid[32],bid[32];
        stp_bridge_id_str(&br->root_id,   rid,sizeof(rid));
        stp_bridge_id_str(&br->bridge_id, bid,sizeof(bid));
        size_t pos=0;
        pos+=(size_t)snprintf(resp+pos,rsz-pos,
            "{\"status\":\"ok\","
            "\"mode\":\"%s\","
            "\"bridge_id\":\"%s\","
            "\"root_id\":\"%s\","
            "\"root_port\":%u,"
            "\"root_path_cost\":%u,"
            "\"we_are_root\":%s,"
            "\"hello\":%u,\"max_age\":%u,\"fwd_delay\":%u,"
            "\"tc_count\":%llu,"
            "\"ports\":[",
            stp_mode_str(br->mode),bid,rid,
            br->root_port_id, br->root_path_cost,
            stp_is_root(br)?"true":"false",
            br->hello_time,br->max_age,br->fwd_delay,
            (unsigned long long)br->tc_count);
        for(int i=0;i<br->n_ports&&pos<rsz-512;i++){
            char pb[512]; port_json(&br->ports[i],pb,sizeof(pb));
            if(i>0&&pos<rsz-2) resp[pos++]=',';
            size_t pl=strlen(pb);
            if(pos+pl<rsz-4){memcpy(resp+pos,pb,pl);pos+=pl;}
        }
        if(pos<rsz-4){resp[pos++]=']';resp[pos++]='}';resp[pos]='\0';}

    /* ── port add ───────────────────────────────────────────── */
    } else if (strcmp(cmd,"port_add")==0) {
        char name[16]={0},cost_s[16]={0},num_s[8]={0};
        vr_json_get_str(req,"port",name,sizeof(name));
        vr_json_get_str(req,"cost",cost_s,sizeof(cost_s));
        vr_json_get_str(req,"num",num_s,sizeof(num_s));
        uint32_t cost=(uint32_t)(cost_s[0]?atoi(cost_s):0);
        uint16_t num=(uint16_t)(num_s[0]?atoi(num_s):br->n_ports+1);
        int rc=stp_port_add(br,name,num,cost);
        snprintf(resp,rsz,"{\"status\":\"%s\",\"port\":\"%s\"}",
                 rc==0?"ok":"error",name);

    /* ── port up / down ─────────────────────────────────────── */
    } else if (strcmp(cmd,"port_up")==0||strcmp(cmd,"port_down")==0) {
        char name[16]={0}; vr_json_get_str(req,"port",name,sizeof(name));
        stp_port_t *p=stp_port_find(br,name);
        if(!p){snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"port not found\"}");return;}
        int up=(cmd[5]=='u');
        if(up) stp_port_up(br,p);
        else { stp_port_down(br,p); tc_flush_fdb(fdb,name); }
        snprintf(resp,rsz,"{\"status\":\"ok\",\"port\":\"%s\",\"link\":\"%s\","
                 "\"state\":\"%s\",\"role\":\"%s\"}",
                 name,up?"up":"down",
                 stp_state_str(p->state),stp_role_str(p->role));

    /* ── port config (edge, p2p, cost) ──────────────────────── */
    } else if (strcmp(cmd,"port_set")==0) {
        char name[16]={0},edge_s[8]={0},p2p_s[8]={0},cost_s[16]={0};
        vr_json_get_str(req,"port",name,sizeof(name));
        vr_json_get_str(req,"edge",edge_s,sizeof(edge_s));
        vr_json_get_str(req,"p2p",p2p_s,sizeof(p2p_s));
        vr_json_get_str(req,"cost",cost_s,sizeof(cost_s));
        stp_port_t *p=stp_port_find(br,name);
        if(!p){snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"port not found\"}");return;}
        if(edge_s[0]) p->edge=(strncmp(edge_s,"true",4)==0||edge_s[0]=='1');
        if(p2p_s[0])  p->point_to_point=(strncmp(p2p_s,"true",4)==0||p2p_s[0]=='1');
        if(cost_s[0]) p->path_cost=(uint32_t)atoi(cost_s);
        snprintf(resp,rsz,"{\"status\":\"ok\",\"port\":\"%s\","
                 "\"edge\":%s,\"p2p\":%s,\"cost\":%u}",
                 name,p->edge?"true":"false",
                 p->point_to_point?"true":"false",p->path_cost);

    /* ── receive BPDU (inject from test/other daemon) ────────── */
    } else if (strcmp(cmd,"bpdu")==0) {
        char port_s[16]={0},root_s[32]={0},bridge_s[32]={0};
        char cost_s[16]={0},flags_s[8]={0};
        vr_json_get_str(req,"port",port_s,sizeof(port_s));
        vr_json_get_str(req,"root",root_s,sizeof(root_s));
        vr_json_get_str(req,"bridge",bridge_s,sizeof(bridge_s));
        vr_json_get_str(req,"cost",cost_s,sizeof(cost_s));
        vr_json_get_str(req,"flags",flags_s,sizeof(flags_s));
        stp_port_t *p=stp_port_find(br,port_s);
        if(!p){snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"port not found\"}");return;}

        stp_bpdu_t bpdu; memset(&bpdu,0,sizeof(bpdu));
        bpdu.version=(br->mode==STP_MODE_STP)?0:2;
        bpdu.flags=(uint8_t)(flags_s[0]?atoi(flags_s):0);
        bpdu.root_path_cost=(uint32_t)(cost_s[0]?atoi(cost_s):0);

        /* parse "prio.aabbccddeeff" bridge IDs */
        if(root_s[0]) {
            unsigned int prio=0;
            unsigned int m[6]={0};
            sscanf(root_s,"%x.%02x%02x%02x%02x%02x%02x",
                   &prio,&m[0],&m[1],&m[2],&m[3],&m[4],&m[5]);
            bpdu.root_id.priority=(uint16_t)prio;
            for(int i=0;i<6;i++) bpdu.root_id.mac[i]=(uint8_t)m[i];
        }
        if(bridge_s[0]) {
            unsigned int prio=0;
            unsigned int m[6]={0};
            sscanf(bridge_s,"%x.%02x%02x%02x%02x%02x%02x",
                   &prio,&m[0],&m[1],&m[2],&m[3],&m[4],&m[5]);
            bpdu.bridge_id.priority=(uint16_t)prio;
            for(int i=0;i<6;i++) bpdu.bridge_id.mac[i]=(uint8_t)m[i];
        }

        stp_receive_bpdu(br,p,&bpdu);
        if(bpdu.flags&BPDU_FL_TC) tc_flush_fdb(fdb,NULL);

        char rid[32]; stp_bridge_id_str(&br->root_id,rid,sizeof(rid));
        snprintf(resp,rsz,
            "{\"status\":\"ok\",\"port\":\"%s\","
            "\"state\":\"%s\",\"role\":\"%s\","
            "\"root_id\":\"%s\",\"root_path_cost\":%u}",
            port_s,stp_state_str(p->state),stp_role_str(p->role),
            rid,br->root_path_cost);

    /* ── tick (advance timers) ───────────────────────────────── */
    } else if (strcmp(cmd,"tick")==0) {
        char n_s[8]={0}; vr_json_get_str(req,"n",n_s,sizeof(n_s));
        int n=n_s[0]?atoi(n_s):1;
        for(int i=0;i<n;i++) stp_tick(br);
        snprintf(resp,rsz,
            "{\"status\":\"ok\",\"ticks\":%d,\"tc_active\":%s}",
            n,br->tc_active?"true":"false");

    /* ── set bridge priority ─────────────────────────────────── */
    } else if (strcmp(cmd,"set_priority")==0) {
        char v[16]={0}; vr_json_get_str(req,"priority",v,sizeof(v));
        int prio=v[0]?atoi(v):32768;
        if(prio%4096!=0){
            snprintf(resp,rsz,"{\"status\":\"error\","
                     "\"msg\":\"priority must be multiple of 4096\"}");
            return;
        }
        br->bridge_id.priority=(uint16_t)prio;
        recalculate_roles_pub(br);
        snprintf(resp,rsz,"{\"status\":\"ok\",\"priority\":%d}",prio);

    /* ── set mode (stp/rstp/mst) ─────────────────────────────── */
    } else if (strcmp(cmd,"set_mode")==0) {
        char v[8]={0}; vr_json_get_str(req,"mode",v,sizeof(v));
        if(strncmp(v,"stp",3)==0)       br->mode=STP_MODE_STP;
        else if(strncmp(v,"rstp",4)==0) br->mode=STP_MODE_RSTP;
        else if(strncmp(v,"mst",3)==0)  br->mode=STP_MODE_MST;
        else{snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"unknown mode\"}");return;}
        snprintf(resp,rsz,
            "{\"status\":\"ok\",\"mode\":\"%s\"}",stp_mode_str(br->mode));

    /* ── MST: map vlan → instance ────────────────────────────── */
    } else if (strcmp(cmd,"mst_map")==0) {
        char vlan_s[8]={0},inst_s[8]={0};
        vr_json_get_str(req,"vlan",vlan_s,sizeof(vlan_s));
        vr_json_get_str(req,"instance",inst_s,sizeof(inst_s));
        if(!vlan_s[0]||!inst_s[0]){
            snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"need vlan and instance\"}");
            return;
        }
        uint16_t vlan=(uint16_t)atoi(vlan_s);
        uint8_t  inst=(uint8_t)atoi(inst_s);
        int rc=mst_map_vlan(br,vlan,inst);
        snprintf(resp,rsz,"{\"status\":\"%s\","
                 "\"vlan\":%u,\"instance\":%u}",
                 rc==0?"ok":"error",vlan,inst);

    /* ── MST: show instances ─────────────────────────────────── */
    } else if (strcmp(cmd,"mst_show")==0) {
        size_t pos=0;
        pos+=(size_t)snprintf(resp+pos,rsz-pos,
            "{\"status\":\"ok\","
            "\"region\":\"%s\",\"revision\":%u,\"instances\":[",
            br->mst_region,br->mst_revision);
        int first=1;
        for(int i=0;i<MST_MAX_INSTANCES&&pos<rsz-256;i++){
            const stp_msti_t *m=&br->mstis[i];
            if(!m->active) continue;
            char rr[32]; stp_bridge_id_str(&m->regional_root,rr,sizeof(rr));
            /* count vlans in this instance */
            int vcount=0;
            for(int v=1;v<=MST_MAX_VLANS;v++)
                if(m->vlan_map[v]==i) vcount++;
            if(!first&&pos<rsz-2) resp[pos++]=',';
            pos+=(size_t)snprintf(resp+pos,rsz-pos,
                "{\"id\":%u,\"regional_root\":\"%s\","
                "\"priority\":%u,\"vlan_count\":%d,"
                "\"tc_count\":%llu}",
                m->id,rr,m->bridge_priority,vcount,
                (unsigned long long)m->tc_count);
            first=0;
        }
        /* show port states per active instance */
        pos+=(size_t)snprintf(resp+pos,rsz-pos,"],\"port_msti\":[");
        first=1;
        for(int i=0;i<br->n_ports&&pos<rsz-256;i++){
            const stp_port_t *p=&br->ports[i];
            for(int j=0;j<MST_MAX_INSTANCES&&pos<rsz-128;j++){
                if(!br->mstis[j].active) continue;
                if(!first&&pos<rsz-2) resp[pos++]=',';
                pos+=(size_t)snprintf(resp+pos,rsz-pos,
                    "{\"port\":\"%s\",\"msti\":%d,"
                    "\"state\":\"%s\",\"role\":\"%s\"}",
                    p->name,j,
                    stp_state_str(p->msti[j].state),
                    stp_role_str(p->msti[j].role));
                first=0;
            }
        }
        if(pos<rsz-4){resp[pos++]=']';resp[pos++]='}';resp[pos]='\0';}

    /* ── MST: set region ─────────────────────────────────────── */
    } else if (strcmp(cmd,"mst_region")==0) {
        char name[MST_REGION_NAME_LEN]={0},rev_s[8]={0};
        vr_json_get_str(req,"name",name,sizeof(name));
        vr_json_get_str(req,"revision",rev_s,sizeof(rev_s));
        if(name[0]) snprintf(br->mst_region, sizeof(br->mst_region), "%s", name);
        if(rev_s[0]) br->mst_revision=(uint32_t)atoi(rev_s);
        snprintf(resp,rsz,
            "{\"status\":\"ok\","
            "\"region\":\"%s\",\"revision\":%u}",
            br->mst_region,br->mst_revision);

    /* ── build and show outgoing BPDU ────────────────────────── */
    } else if (strcmp(cmd,"bpdu_build")==0) {
        char port_s[16]={0}; vr_json_get_str(req,"port",port_s,sizeof(port_s));
        stp_port_t *p=stp_port_find(br,port_s);
        if(!p){snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"port not found\"}");return;}
        stp_bpdu_t bpdu; stp_build_bpdu(br,p,&bpdu);
        char rid[32],bid[32];
        /* copy packed fields to aligned locals before taking address */
        stp_bridge_id_t tmp_rid, tmp_bid;
        memcpy(&tmp_rid, &bpdu.root_id,   sizeof(tmp_rid));
        memcpy(&tmp_bid, &bpdu.bridge_id, sizeof(tmp_bid));
        stp_bridge_id_str(&tmp_rid, rid, sizeof(rid));
        stp_bridge_id_str(&tmp_bid, bid, sizeof(bid));
        snprintf(resp,rsz,
            "{\"status\":\"ok\","
            "\"version\":%u,\"flags\":\"0x%02x\","
            "\"root_id\":\"%s\",\"root_path_cost\":%u,"
            "\"bridge_id\":\"%s\",\"port_id\":%u,"
            "\"max_age\":%u,\"hello_time\":%u,\"fwd_delay\":%u}",
            bpdu.version,bpdu.flags,
            rid,bpdu.root_path_cost,
            bid,bpdu.port_id,
            bpdu.max_age/256,bpdu.hello_time/256,bpdu.fwd_delay/256);

    /* ── get <key> ───────────────────────────────────────────── */
    } else if (strcmp(cmd,"get")==0) {
        char key[32]={0}; vr_json_get_str(req,"key",key,sizeof(key));
        char val[64]={0};
        if      (strcmp(key,"STP_MODE"    )==0) snprintf(val,sizeof(val),"%s",stp_mode_str(br->mode));
        else if (strcmp(key,"STP_PRIORITY")==0) snprintf(val,sizeof(val),"%u",br->bridge_id.priority);
        else if (strcmp(key,"STP_HELLO"   )==0) snprintf(val,sizeof(val),"%u",br->hello_time);
        else if (strcmp(key,"STP_MAX_AGE" )==0) snprintf(val,sizeof(val),"%u",br->max_age);
        else if (strcmp(key,"STP_FWD_DELAY")==0)snprintf(val,sizeof(val),"%u",br->fwd_delay);
        else if (strcmp(key,"MST_REGION"  )==0) snprintf(val,sizeof(val),"%s",br->mst_region);
        else if (strcmp(key,"MST_REVISION")==0) snprintf(val,sizeof(val),"%u",br->mst_revision);
        else { snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"unknown key: %s\"}",key); return; }
        snprintf(resp,rsz,"{\"status\":\"ok\",\"key\":\"%s\",\"value\":\"%s\"}",key,val);

    /* ── set <key> <value> ───────────────────────────────────── */
    } else if (strcmp(cmd,"set")==0) {
        char key[32]={0},val[64]={0};
        vr_json_get_str(req,"key",key,sizeof(key));
        vr_json_get_str(req,"value",val,sizeof(val));
        if (strcmp(key,"STP_MODE")==0) {
            if     (strcmp(val,"stp" )==0) br->mode=STP_MODE_STP;
            else if(strcmp(val,"rstp")==0) br->mode=STP_MODE_RSTP;
            else if(strcmp(val,"mst" )==0) br->mode=STP_MODE_MST;
            else { snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"invalid mode\"}"); return; }
            if (cfg) snprintf(cfg->stp_mode, sizeof(cfg->stp_mode), "%.*s", (int)(sizeof(cfg->stp_mode) - 1), val);
            l2_cli_save_key(key,val);
        } else if (strcmp(key,"STP_PRIORITY")==0) {
            int v=atoi(val);
            if(v<0||v>61440||v%4096!=0){snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"must be 0-61440, multiple of 4096\"}");return;}
            br->bridge_id.priority=(uint16_t)v;
            if (cfg) cfg->stp_priority=(uint16_t)v;
            recalculate_roles(br);
            l2_cli_save_key(key,val);
        } else if (strcmp(key,"STP_HELLO")==0) {
            int v=atoi(val);
            if(v<1||v>10){snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"range 1-10\"}");return;}
            br->hello_time=(uint16_t)v;
            if (cfg) cfg->stp_hello=(uint16_t)v;
            l2_cli_save_key(key,val);
        } else if (strcmp(key,"STP_MAX_AGE")==0) {
            int v=atoi(val);
            if(v<6||v>40){snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"range 6-40\"}");return;}
            br->max_age=(uint16_t)v;
            if (cfg) cfg->stp_max_age=(uint16_t)v;
            l2_cli_save_key(key,val);
        } else if (strcmp(key,"STP_FWD_DELAY")==0) {
            int v=atoi(val);
            if(v<4||v>30){snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"range 4-30\"}");return;}
            br->fwd_delay=(uint16_t)v;
            if (cfg) cfg->stp_fwd_delay=(uint16_t)v;
            l2_cli_save_key(key,val);
        } else if (strcmp(key,"MST_REGION")==0) {
            snprintf(br->mst_region, sizeof(br->mst_region), "%.*s", (int)(sizeof(br->mst_region) - 1), val);
            if (cfg) snprintf(cfg->mst_region, sizeof(cfg->mst_region), "%.*s", (int)(sizeof(cfg->mst_region) - 1), val);
            l2_cli_save_key(key,val);
        } else if (strcmp(key,"MST_REVISION")==0) {
            int v=atoi(val);
            if(v<0||v>65535){snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"range 0-65535\"}");return;}
            br->mst_revision=(uint32_t)v;
            if (cfg) cfg->mst_revision=(uint32_t)v;
            l2_cli_save_key(key,val);
        } else {
            snprintf(resp,rsz,"{\"status\":\"error\",\"msg\":\"unknown key: %s\"}",key); return;
        }
        snprintf(resp,rsz,"{\"status\":\"ok\",\"key\":\"%s\",\"value\":\"%s\"}",key,val);

    } else if (strcmp(cmd,"ping")==0) {
        snprintf(resp,rsz,
            "{\"status\":\"ok\",\"msg\":\"pong\",\"module\":\"stp\","
            "\"mode\":\"%s\"}",stp_mode_str(br->mode));
    } else {
        snprintf(resp,rsz,
            "{\"status\":\"error\",\"msg\":\"unknown cmd: %s\"}",cmd);
    }
}

/* expose recalculate for set_priority */
void recalculate_roles_pub(stp_bridge_t *br);

int stp_ipc_serve(stp_bridge_t *br, fdb_table_t *fdb,
                  struct l2_config *cfg, const char *sock_path, volatile int *running)
{
    unlink(sock_path);
    int srv=socket(AF_UNIX,SOCK_STREAM,0);
    if(srv<0){perror("stp socket");return -1;}
    struct sockaddr_un addr;
    memset(&addr,0,sizeof(addr));
    addr.sun_family=AF_UNIX;
    strncpy(addr.sun_path,sock_path,sizeof(addr.sun_path)-1);
    if(bind(srv,(struct sockaddr*)&addr,sizeof(addr))<0||listen(srv,8)<0){
        perror("stp bind/listen");close(srv);return -1;}
    fprintf(stderr,"[stp]  listening on %s\n",sock_path);
    char req[IPC_BUF],resp[IPC_RESP];
    while(*running){
        fd_set rfds; FD_ZERO(&rfds); FD_SET(srv,&rfds);
        struct timeval tv={1,0};
        if(select(srv+1,&rfds,NULL,NULL,&tv)<=0) continue;
        int cli=accept(srv,NULL,NULL); if(cli<0) continue;
        ssize_t n=recv(cli,req,sizeof(req)-1,0);
        if(n>0){req[n]='\0';handle(br,fdb,(l2_config_t*)cfg,req,resp,sizeof(resp));
                send(cli,resp,strlen(resp),0);}
        close(cli);
    }
    close(srv); unlink(sock_path); return 0;
}
