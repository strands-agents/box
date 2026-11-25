#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/capability.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static unsigned long long started;
static const char *incarnation;

static void quote(const char *text) {
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
        else if (*p < 32) printf("\\u%04x", *p);
        else putchar(*p);
    }
    putchar('"');
}

static void identity(void) {
    printf("\"pid\":%ld,\"started_monotonic_ns\":%llu,\"incarnation\":", (long)getpid(), started);
    quote(incarnation);
}

static unsigned long long capabilities(void) {
    FILE *status = fopen("/proc/self/status", "r");
    if (!status) { perror("read capabilities"); exit(2); }
    char line[256];
    unsigned long long combined = 0, value;
    int fields = 0;
    while (fgets(line, sizeof(line), status)) {
        if (!strncmp(line, "Cap", 3) && sscanf(line, "%*[^:]: %llx", &value) == 1) {
            combined |= value;
            ++fields;
        }
    }
    fclose(status);
    if (fields != 5) { fputs("expected five capability masks\n", stderr); exit(2); }
    return combined;
}

static void operation(const char *action, const char *request, const char *path, const char *data) {
    char content[4097] = {0};
    int rc = -1, error = 0;
    if (!strcmp(action, "READ")) {
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) error = errno;
        else {
            ssize_t count = read(fd, content, sizeof(content) - 1);
            if (count < 0) error = errno; else rc = 0;
            close(fd);
        }
    } else if (!strcmp(action, "CREATE")) {
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0) error = errno;
        else {
            size_t length = strlen(data);
            ssize_t count = write(fd, data, length);
            if (count < 0) error = errno;
            else if ((size_t)count != length) error = EIO;
            else rc = 0;
            if (close(fd) && rc == 0) { error = errno; rc = -1; }
        }
    } else if (!strcmp(action, "EXEC_MAP")) {
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) error = errno;
        else {
            void *mapping = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
            if (mapping == MAP_FAILED) error = errno;
            else { rc = 0; munmap(mapping, 4096); }
            close(fd);
        }
    } else error = EINVAL;
    printf("{\"kind\":\"operation\","); identity();
    fputs(",\"request_id\":", stdout); quote(request);
    printf(",\"rc\":%d,\"errno\":%d,\"content\":", rc, error);
    quote(content); puts("}"); fflush(stdout);
}

static int field(char *value, size_t capacity) {
    if (!fgets(value, (int)capacity, stdin)) return 0;
    size_t length = strlen(value);
    if (!length || value[length - 1] != '\n') return 0;
    value[length - 1] = 0;
    return 1;
}

int main(int argc, char **argv) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 2;
    started = (unsigned long long)now.tv_sec * 1000000000ULL + (unsigned long long)now.tv_nsec;
    incarnation = "runtime-control";
    if (argc == 6 && !strcmp(argv[1], "--once")) {
        // Compare filesystem operations without the Runtime wrapper's effective capabilities.
        struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
        struct __user_cap_data_struct data[2] = {{0}};
        if (syscall(SYS_capset, &header, data) || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return 2;
        operation(argv[2], argv[3], argv[4], argv[5]);
        return 0;
    }
    if (argc != 4 || strcmp(argv[1], "--loop")) return 2;
    incarnation = argv[3];
    struct statvfs fs;
    int stat_rc = statvfs(argv[2], &fs), stat_errno = stat_rc ? errno : 0;
    printf("{\"kind\":\"started\","); identity();
    printf(",\"uid\":%ld,\"gid\":%ld,\"capability_masks_or\":%llu,\"seccomp\":%d,"
           "\"no_new_privs\":%d,\"statvfs_rc\":%d,\"statvfs_errno\":%d,\"storage_readonly\":%s}\n",
           (long)getuid(), (long)getgid(), capabilities(), prctl(PR_GET_SECCOMP, 0, 0, 0, 0),
           prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0), stat_rc, stat_errno,
           !stat_rc && (fs.f_flag & ST_RDONLY) ? "true" : "false");
    fflush(stdout);
    for (;;) {
        char action[32], request[128], path[PATH_MAX], data[4096];
        if (!field(action, sizeof(action))) return 2;
        if (!strcmp(action, "STOP")) return 0;
        if (!field(request, sizeof(request)) || !field(path, sizeof(path)) || !field(data, sizeof(data))) return 2;
        operation(action, request, path, data);
    }
}
