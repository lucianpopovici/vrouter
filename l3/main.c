#include "fib.h"
#include "fib_cli.h"
#include "fib_ipc.h"
#include "rib.h"
#include "rib_ipc.h"
#include "persist.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <arpa/inet.h>

static volatile int g_running = 1;
static volatile int g_sighup  = 0;
static void sig_handler(int sig) { (void)sig; g_running = 0; }
static void hup_handler(int sig) { (void)sig; g_sighup  = 1; }


/* ── Startup FIB push callback ───────────────────────────────── *
 * Used by persist_restore() to populate the FIB immediately     *
 * at startup (before the IPC threads are running).              */
static fib_table_t *g_startup_fib = NULL;

static void startup_push_to_fib(const rib_entry_t *entry,
                                  const rib_candidate_t *best,
                                  int install, void *ctx)
{
    fib_table_t *fib = ctx ? (fib_table_t*)ctx : g_startup_fib;
    if (!fib) return;

    struct in_addr pfx_in = { htonl(entry->prefix) };
    struct in_addr nh_in  = { htonl(best->nexthop) };
    char pfx_s[INET_ADDRSTRLEN+4], nh_s[INET_ADDRSTRLEN];
    char addr_s[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &pfx_in, addr_s, sizeof(addr_s));
    snprintf(pfx_s, sizeof(pfx_s), "%s/%u", addr_s, entry->prefix_len);
    inet_ntop(AF_INET, &nh_in, nh_s, sizeof(nh_s));

    if (install) {
        uint32_t flags = FIB_FLAG_STATIC;
        if (best->source == RIB_SRC_CONNECTED) flags = FIB_FLAG_CONNECTED;
        fib_add(fib, pfx_s, nh_s, best->iface, best->metric, flags);
    } else {
        fib_del(fib, pfx_s);
    }
}

/* ── Compute a socket path: dir + "/" + name ─────────────────── */
static void mkpath(char *out, size_t sz,
                   const char *dir, const char *name) {
    /* dir(≤255) + "/" + name(≤20) needs at least 277 bytes */
    snprintf(out, sz, "%s/%s", dir, name);
}

#define DEFAULT_SOCK_DIR "/tmp"

typedef struct { rib_table_t *rib; fib_table_t *fib;
                 char path[512];   volatile int *r; } rib_arg_t;
typedef struct { fib_table_t *fib; char path[512];
                 volatile int *r; } fib_arg_t;

static void *rib_thread(void *arg) {
    rib_arg_t *a=arg;
    rib_ipc_serve(a->rib,a->fib,a->path,a->r);
    return NULL;
}
static void *fib_thread(void *arg) {
    fib_arg_t *a=arg;
    ipc_serve(a->fib,a->path,a->r);
    return NULL;
}

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [-S <sock_dir>] [-d] [-h]\n"
        "\n"
        "  -S <sock_dir>  Directory for Unix sockets  (default: /tmp)\n"
        "  -d             Daemonize\n"
        "\n"
        "Socket dir can also be set via:\n"
        "  env var        FIBD_SOCK_DIR\n"
        "  config key     (written to schema.json, no runtime override yet)\n"
        "\n"
        "Socket names:\n"
        "  RIB  %s   (route add/del, source selection)\n"
        "  FIB  %s   (LPM lookup)\n",
        prog, RIB_SOCK_NAME, FIB_SOCK_NAME);
}

int main(int argc, char **argv) {
    int daemonize=0;
    const char *sock_dir_arg=NULL;
    int opt;

    while ((opt=getopt(argc,argv,"S:dh"))!=-1) {
        switch(opt) {
        case 'S': sock_dir_arg=optarg; break;
        case 'd': daemonize=1; break;
        case 'h': print_usage(argv[0]); return 0;
        default:  print_usage(argv[0]); return 1;
        }
    }

    /* ── Resolve socket directory: default → env → -S ───────── */
    char sock_dir[256];
    strncpy(sock_dir, DEFAULT_SOCK_DIR, sizeof(sock_dir)-1);

    const char *env_dir = getenv("FIBD_SOCK_DIR");
    if (env_dir && env_dir[0])
        strncpy(sock_dir, env_dir, sizeof(sock_dir)-1);

    if (sock_dir_arg)
        strncpy(sock_dir, sock_dir_arg, sizeof(sock_dir)-1);

    /* ── Compute socket paths ────────────────────────────────── */
    char fib_path[512], rib_path[512];
    mkpath(fib_path, sizeof(fib_path), sock_dir, FIB_SOCK_NAME);
    mkpath(rib_path, sizeof(rib_path), sock_dir, RIB_SOCK_NAME);

    /* ensure directory exists */
    mkdir(sock_dir, 0755);
    fprintf(stderr,"[main] sock_dir=%s\n",sock_dir);
    fprintf(stderr,"[main] RIB=%s  FIB=%s\n",rib_path,fib_path);

    /* ── project-cli schema ──────────────────────────────────── */
    if (cli_write_schema()==0)
        fprintf(stderr,"[main] wrote schema.json\n");
    else
        perror("[main] cli_write_schema");

    /* ── Init tables ─────────────────────────────────────────── */
    fib_table_t fib; fib_init(&fib);
    rib_table_t rib; rib_init(&rib);

    /* restore state from previous run */
    /* push_to_fib is defined in rib_ipc.c — use fib_add directly */
    /* Restore RIB from previous run and immediately populate FIB */
    persist_restore(&rib, startup_push_to_fib, &fib, NULL);

    if (cli_load_runtime_config(&fib)==0)
        fprintf(stderr,"[main] loaded runtime_config.json"
                       " (MAX_ROUTES=%u)\n",fib.max_routes);

    /* ── Daemonize ───────────────────────────────────────────── */
    if (daemonize) {
        pid_t pid=fork();
        if (pid<0) { perror("fork"); return 1; }
        if (pid>0) { fprintf(stderr,"[main] pid=%d\n",(int)pid); return 0; }
        setsid();
        { int _fd;
          _fd = open("/dev/null",   O_RDONLY); if (_fd>=0){dup2(_fd,STDIN_FILENO); close(_fd);}
          _fd = open("/tmp/ribd.log",O_WRONLY|O_CREAT|O_APPEND,0644); if (_fd>=0){dup2(_fd,STDOUT_FILENO);dup2(_fd,STDERR_FILENO);close(_fd);}
        }
    }

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGHUP,  hup_handler);
    signal(SIGPIPE, SIG_IGN);

    fprintf(stderr,"[main] RIB+FIB daemon starting\n");

    /* ── Launch RIB thread, FIB on main ─────────────────────── */
    pthread_t rib_tid;
    rib_arg_t ra; ra.rib=&rib; ra.fib=&fib; ra.r=&g_running;
    snprintf(ra.path, sizeof(ra.path), "%s", rib_path);
    if (pthread_create(&rib_tid,NULL,rib_thread,&ra)!=0) {
        perror("pthread_create rib"); return 1;
    }

    /* Run FIB IPC in its own thread so main can handle signals */
    pthread_t fib_tid;
    fib_arg_t fa; fa.fib=&fib; fa.r=&g_running;
    snprintf(fa.path, sizeof(fa.path), "%s", fib_path);
    if (pthread_create(&fib_tid,NULL,fib_thread,&fa)!=0) {
        perror("pthread_create fib"); return 1;
    }

    /* ── Management loop: handle SIGHUP while daemons run ── */
    while (g_running) {
        if (g_sighup) {
            fprintf(stderr,"[main] SIGHUP: checkpointing routes...\n");
            persist_dump(&rib, NULL);
            g_sighup = 0;
            fprintf(stderr,"[main] checkpoint done\n");
        }
        struct timespec ts = {0, 100000000}; /* 100ms */
        nanosleep(&ts, NULL);
    }

    pthread_join(rib_tid,NULL);
    pthread_join(fib_tid,NULL);
    /* Dump on clean shutdown — must be before rib_destroy */
    persist_dump(&rib, NULL);
    rib_destroy(&rib);
    fprintf(stderr,"[main] shutdown (fib=%d)\n",
            fib_count(&fib));
    return 0;
}
