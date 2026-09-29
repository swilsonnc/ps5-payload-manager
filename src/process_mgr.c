#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/sysctl.h>
#include <stdint.h>
#include "process_mgr.h"
#include "json_helpers.h"
#include "pldmgr.h"

#define MiB(x) ((x) / (1024.0 * 1024))
#define TERM_GRACE_MS     3000  /* time to wait after SIGTERM before SIGKILL */
#define POLL_INTERVAL_MS  50

typedef struct app_info {
    uint32_t app_id;
    uint64_t unknown1;
    char     title_id[14];
    char     unknown2[0x3c];
} app_info_t;

extern int sceKernelGetAppInfo(pid_t pid, app_info_t *info);

static int is_user_daemon(const char *name, uint32_t app_id) {
    if (!name) return 0;

    /* Specifically exclude mini-syscore.elf */
    if (strcmp(name, "mini-syscore.elf") == 0) return 0;

    /* Must have app_id == 0000 */
    if (app_id != 0) return 0;

    const char *ext = strrchr(name, '.');
    if (ext && strcasecmp(ext, ".elf") == 0) return 1;

    return 0;
}

size_t process_list_json(char *buf, size_t max_size) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0};
    size_t buf_size = 0;
    void *sysctl_buf = NULL;

    JsonListBuilder jb = { buf, max_size, 0, 1 };
    buf[0] = '\0';

    json_append(&jb, "{\"processes\":[\n");

    if (sysctl(mib, 4, NULL, &buf_size, NULL, 0) == 0) {
        sysctl_buf = malloc(buf_size);
        if (sysctl_buf) {
            if (sysctl(mib, 4, sysctl_buf, &buf_size, NULL, 0) == 0) {
                int count = 0;
                for (void *ptr = sysctl_buf; ptr < (sysctl_buf + buf_size);) {
                    struct kinfo_proc *ki = (struct kinfo_proc*)ptr;
                    if (ki->ki_structsize == 0) break;
                    ptr += ki->ki_structsize;

                    app_info_t appinfo;
                    if(sceKernelGetAppInfo(ki->ki_pid, &appinfo)) {
                        memset(&appinfo, 0, sizeof(appinfo));
                    }

                    int is_daemon = is_user_daemon(ki->ki_comm, appinfo.app_id);

                    char name_e[512];
                    pldmgr_json_escape(ki->ki_comm, name_e, sizeof(name_e));

                    double mem_mib = MiB(ki->ki_rssize * PAGE_SIZE);

                    if (json_append(&jb, "%s  {\"pid\":%d,\"name\":\"%s\",\"memory\":%.1f,\"is_daemon\":%s}",
                        (count > 0) ? ",\n" : "",
                        (int)ki->ki_pid, name_e, mem_mib, is_daemon ? "true" : "false") != 0) {
                        break;
                    }
                    count++;
                }
            }
            free(sysctl_buf);
        }
    }

    json_append(&jb, "\n]}\n");
    return jb.pos;
}

static int process_exists(pid_t pid) {
    if (kill(pid, 0) == 0) return 1;
    return (errno == EPERM);    /* exists, but we can't signal it */
}

int process_kill(int pid) {
    if (pid <= 1) return -1;    /* Prevent killing kernel (0) or init (1), and invalid/negative pids */

    /* Prevent killing our own process */
    if (pid == getpid()) return -1;

    /* 1. Ask the process to exit cleanly */
    if (kill(pid, SIGTERM) != 0) {
        return (errno == ESRCH) ? 0 : -1;   /* already gone vs. real error */
    }

    /* 2. Give it time to shut down */
    struct timespec ts = { 0, POLL_INTERVAL_MS * 1000000L };
    for (int waited = 0; waited < TERM_GRACE_MS; waited += POLL_INTERVAL_MS) {
        if (!process_exists(pid)) return 0;
        nanosleep(&ts, NULL);
    }

    /* 3. Still running, force kill */
    if (kill(pid, SIGKILL) == 0 || errno == ESRCH) return 0;
    return -1;
}
