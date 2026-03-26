#include "fdb.h"
#include "fdb_ipc.h"
#include "l2rib.h"
#include "l2rib_ipc.h"
#include "stp.h"
#include "stp_ipc.h"
#include "l2_cli.h"
#include "vlan.h"
#include "portsec.h"
#include "storm.h"
#include "igmp.h"
#include "arpsnoop.h"
#include "lacp.h"
#include "l2_ipc_extra.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>

static volatile int g_running = 1;
static void sig_handler(int sig) { (void)sig; g_running = 0; }
void recalculate_roles_pub(stp_bridge_t *br) { stp_tick(br); }

/* ── Compute a socket path: dir + "/" + name ─────────────────── */
static void mkpath(char *out, size_t sz,
                   const char *dir, const char *name) {
    snprintf(out, sz, "%s/%s", dir, name);
}

/* ── Thread arg structs ──────────────────────────────────────── */
typedef struct { fdb_table_t   *fdb; l2_config_t *cfg;
                 char path[512];     volatile int *r; } fdb_arg_t;
typedef struct { l2rib_table_t *rib; fdb_table_t *fdb;
                 l2_config_t   *cfg; char path[512];
                 volatile int  *r; } l2rib_arg_t;
typedef struct { stp_bridge_t  *br;  fdb_table_t *fdb;
                 l2_config_t   *cfg; char path[512];
                 volatile int  *r; } stp_arg_t;
typedef struct {
    vlan_db_t *vlan; portsec_table_t *ps; storm_table_t *storm;
    igmp_table_t *igmp; arpsnoop_table_t *arp; lacp_table_t *lacp;
    l2_extra_paths_t paths;
    volatile int *r;
} extra_arg_t;

static void *t_fdb(void *a) {
    fdb_arg_t *x=a;
    fdb_ipc_serve(x->fdb,(struct l2_config*)x->cfg,x->path,x->r);
    return NULL;
}
static void *t_l2rib(void *a) {
    l2rib_arg_t *x=a;
    l2rib_ipc_serve(x->rib,x->fdb,(struct l2_config*)x->cfg,x->path,x->r);
    return NULL;
}
static void *t_stp(void *a) {
    stp_arg_t *x=a;
    stp_ipc_serve(x->br,x->fdb,(struct l2_config*)x->cfg,x->path,x->r);
    return NULL;
}
static void *t_extra(void *a) {
    extra_arg_t *x=a;
    l2_extra_serve(x->vlan,x->ps,x->storm,x->igmp,x->arp,x->lacp,
                   &x->paths,x->r);
    return NULL;
}

static void apply_config(const l2_config_t *cfg,
                          fdb_table_t *fdb, stp_bridge_t *br) {
    fdb->age_sec=cfg->fdb_age_sec;
    br->hello_time=cfg->stp_hello; br->max_age=cfg->stp_max_age;
    br->fwd_delay=cfg->stp_fwd_delay;
    br->bridge_id.priority=cfg->stp_priority;
    if (cfg->stp_mode[0]) {
        if      (strcmp(cfg->stp_mode,"stp" )==0) br->mode=STP_MODE_STP;
        else if (strcmp(cfg->stp_mode,"rstp")==0) br->mode=STP_MODE_RSTP;
        else if (strcmp(cfg->stp_mode,"mst" )==0) br->mode=STP_MODE_MST;
    }
    if (cfg->mst_region[0])
        snprintf(br->mst_region, sizeof(br->mst_region), "%s", cfg->mst_region);
    br->mst_revision=cfg->mst_revision;
}

int main(int argc, char **argv) {
    int daemonize=0;
    stp_mode_t mode=STP_MODE_RSTP;
    const char *sock_dir_arg = NULL;
    int opt;

    while ((opt=getopt(argc,argv,"m:S:dh"))!=-1) {
        switch(opt) {
        case 'm':
            if      (strcmp(optarg,"stp" )==0) mode=STP_MODE_STP;
            else if (strcmp(optarg,"rstp")==0) mode=STP_MODE_RSTP;
            else if (strcmp(optarg,"mst" )==0) mode=STP_MODE_MST;
            else { fprintf(stderr,"Unknown mode: %s\n",optarg); return 1; }
            break;
        case 'S': sock_dir_arg = optarg; break;
        case 'd': daemonize=1; break;
        case 'h':
            fprintf(stderr,
                "Usage: %s [-m stp|rstp|mst] [-S <sock_dir>] [-d]\n"
                "\n"
                "  -m <mode>      STP variant: stp | rstp | mst  (default: rstp)\n"
                "  -S <sock_dir>  Directory for Unix sockets      (default: /tmp)\n"
                "  -d             Daemonize\n"
                "\n"
                "Socket dir can also be set via:\n"
                "  env var   L2D_SOCK_DIR\n"
                "  config    SOCK_DIR key in %s\n"
                "\n"
                "Socket names (9 total):\n"
                "  %s  %s  %s\n"
                "  %s  %s  %s\n"
                "  %s  %s  %s\n",
                argv[0], L2_RUNTIME_FILE,
                FDB_SOCK_NAME, L2RIB_SOCK_NAME, STP_SOCK_NAME,
                VLAN_SOCK_NAME, PORTSEC_SOCK_NAME, STORM_SOCK_NAME,
                IGMP_SOCK_NAME, ARP_SOCK_NAME, LACP_SOCK_NAME);
            return 0;
        default: return 1;
        }
    }

    /* ── 1. project-cli schema ───────────────────────────────── */
    if (l2_cli_write_schema()==0)
        fprintf(stderr,"[l2d] wrote %s\n",L2_SCHEMA_FILE);

    /* ── 2. Config: defaults → env → runtime_config → -S flag ── */
    l2_config_t *cfg = calloc(1,sizeof(l2_config_t));
    if (!cfg) { perror("calloc cfg"); return 1; }
    l2_config_defaults(cfg);

    switch(mode) {
    case STP_MODE_STP:  strncpy(cfg->stp_mode,"stp", 7); break;
    case STP_MODE_RSTP: strncpy(cfg->stp_mode,"rstp",7); break;
    case STP_MODE_MST:  strncpy(cfg->stp_mode,"mst", 7); break;
    }

    /* environment variable overrides default */
    const char *env_dir = getenv("L2D_SOCK_DIR");
    if (env_dir && env_dir[0])
        strncpy(cfg->sock_dir, env_dir, sizeof(cfg->sock_dir)-1);

    /* runtime_config.json may override (includes SOCK_DIR) */
    if (l2_cli_load_config(cfg)==0)
        fprintf(stderr,"[l2d] loaded %s\n",L2_RUNTIME_FILE);

    /* -S flag overrides everything */
    if (sock_dir_arg)
        strncpy(cfg->sock_dir, sock_dir_arg, sizeof(cfg->sock_dir)-1);

    /* ensure directory exists */
    mkdir(cfg->sock_dir, 0755);
    fprintf(stderr,"[l2d] sock_dir=%s  mode=%s\n",
            cfg->sock_dir, cfg->stp_mode);

    /* ── 3. Compute all 9 socket paths ──────────────────────── */
    char fdb_path[256], rib_path[256], stp_path[256];
    l2_extra_paths_t ep;
    mkpath(fdb_path, sizeof(fdb_path), cfg->sock_dir, FDB_SOCK_NAME);
    mkpath(rib_path, sizeof(rib_path), cfg->sock_dir, L2RIB_SOCK_NAME);
    mkpath(stp_path, sizeof(stp_path), cfg->sock_dir, STP_SOCK_NAME);
    mkpath(ep.vlan,    sizeof(ep.vlan),    cfg->sock_dir, VLAN_SOCK_NAME);
    mkpath(ep.portsec, sizeof(ep.portsec), cfg->sock_dir, PORTSEC_SOCK_NAME);
    mkpath(ep.storm,   sizeof(ep.storm),   cfg->sock_dir, STORM_SOCK_NAME);
    mkpath(ep.igmp,    sizeof(ep.igmp),    cfg->sock_dir, IGMP_SOCK_NAME);
    mkpath(ep.arp,     sizeof(ep.arp),     cfg->sock_dir, ARP_SOCK_NAME);
    mkpath(ep.lacp,    sizeof(ep.lacp),    cfg->sock_dir, LACP_SOCK_NAME);

    /* ── 4. Init all tables ──────────────────────────────────── */
    fdb_table_t      *fdb   = calloc(1,sizeof(fdb_table_t));
    l2rib_table_t    *l2rib = calloc(1,sizeof(l2rib_table_t));
    stp_bridge_t     *br    = calloc(1,sizeof(stp_bridge_t));
    vlan_db_t        *vlan  = calloc(1,sizeof(vlan_db_t));
    portsec_table_t  *ps    = calloc(1,sizeof(portsec_table_t));
    storm_table_t    *storm = calloc(1,sizeof(storm_table_t));
    igmp_table_t     *igmp  = calloc(1,sizeof(igmp_table_t));
    arpsnoop_table_t *arp   = calloc(1,sizeof(arpsnoop_table_t));
    lacp_table_t     *lacp  = calloc(1,sizeof(lacp_table_t));
    if (!fdb||!l2rib||!br||!vlan||!ps||!storm||!igmp||!arp||!lacp)
        { perror("calloc tables"); return 1; }

    fdb_init(fdb);
    l2rib_init(l2rib);
    uint8_t bmac[6]={0xaa,0xbb,0xcc,0x00,0x00,0x01};
    stp_init(br,bmac,mode);
    stp_port_add(br,"eth0",1,0);
    stp_port_add(br,"eth1",2,0);
    stp_port_add(br,"eth2",3,0);
    vlan_db_init(vlan);
    portsec_init(ps);
    storm_init(storm);
    igmp_init(igmp);
    arpsnoop_init(arp);
    lacp_init(lacp,bmac);
    apply_config(cfg,fdb,br);

    /* ── 5. Daemonize ────────────────────────────────────────── */
    if (daemonize) {
        pid_t pid=fork();
        if (pid<0) { perror("fork"); return 1; }
        if (pid>0) { fprintf(stderr,"[l2d] pid=%d\n",(int)pid); return 0; }
        setsid();
        { int _fd;
          _fd = open("/dev/null",  O_RDONLY); if (_fd>=0){dup2(_fd,STDIN_FILENO); close(_fd);}
          _fd = open("/tmp/l2d.log",O_WRONLY|O_CREAT|O_APPEND,0644); if (_fd>=0){dup2(_fd,STDOUT_FILENO);dup2(_fd,STDERR_FILENO);close(_fd);}
        }
    }

    signal(SIGINT,sig_handler);
    signal(SIGTERM,sig_handler);
    signal(SIGPIPE,SIG_IGN);

    fprintf(stderr,"[l2d] 9 modules ready\n");

    /* ── 6. Launch all threads ───────────────────────────────── */
    pthread_t t1,t2,t3,t4;
    fdb_arg_t   fa; fa.fdb=fdb; fa.cfg=cfg; fa.r=&g_running;
    snprintf(fa.path, sizeof(fa.path), "%s", fdb_path);
    l2rib_arg_t ra; ra.rib=l2rib; ra.fdb=fdb; ra.cfg=cfg; ra.r=&g_running;
    snprintf(ra.path, sizeof(ra.path), "%s", rib_path);
    stp_arg_t   sa; sa.br=br; sa.fdb=fdb; sa.cfg=cfg; sa.r=&g_running;
    snprintf(sa.path, sizeof(sa.path), "%s", stp_path);
    extra_arg_t xa;
    xa.vlan=vlan; xa.ps=ps; xa.storm=storm;
    xa.igmp=igmp; xa.arp=arp; xa.lacp=lacp;
    xa.paths=ep; xa.r=&g_running;

    pthread_create(&t1,NULL,t_fdb,  &fa);
    pthread_create(&t2,NULL,t_l2rib,&ra);
    pthread_create(&t3,NULL,t_stp,  &sa);
    pthread_create(&t4,NULL,t_extra,&xa);

    pthread_join(t1,NULL); pthread_join(t2,NULL);
    pthread_join(t3,NULL); pthread_join(t4,NULL);

    free(fdb); free(l2rib); free(br);
    free(vlan); free(ps); free(storm); free(igmp); free(arp); free(lacp);
    free(cfg);
    fprintf(stderr,"[l2d] shutdown\n");
    return 0;
}
