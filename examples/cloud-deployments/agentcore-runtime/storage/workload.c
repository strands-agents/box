#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>

static unsigned long long started;
static const char *incarnation;

static void quote(FILE *out, const char *text) {
    fputc('"', out);
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p == '"' || *p == '\\') { fputc('\\', out); fputc(*p, out); }
        else if (*p < 32) fprintf(out, "\\u%04x", *p);
        else fputc(*p, out);
    }
    fputc('"', out);
}

static FILE *open_result(const char *directory, const char *name, char *temporary, char *target) {
    if (snprintf(target, PATH_MAX, "%s/%s.json", directory, name) >= PATH_MAX ||
        snprintf(temporary, PATH_MAX, "%s/%s.tmp", directory, name) >= PATH_MAX) exit(2);
    FILE *out = fopen(temporary, "w");
    if (!out) { perror("open result"); exit(2); }
    return out;
}

static void publish(FILE *out, const char *temporary, const char *target) {
    if (fclose(out) || rename(temporary, target)) { perror("publish result"); exit(2); }
}

static void identity(FILE *out) {
    fprintf(out, "\"pid\":%ld,\"started_monotonic_ns\":%llu,\"incarnation\":", (long)getpid(), started);
    quote(out, incarnation);
}

static void operation(FILE *out, const char *action, const char *request, const char *path, const char *data) {
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
    } else error = EINVAL;
    fputs("{", out); identity(out);
    fputs(",\"request_id\":", out); quote(out, request);
    fprintf(out, ",\"rc\":%d,\"errno\":%d,\"content\":", rc, error);
    quote(out, content); fputs("}\n", out);
}

static int field(FILE *input, char *value, size_t capacity) {
    if (!fgets(value, (int)capacity, input)) return 0;
    size_t length = strlen(value);
    if (!length || value[length - 1] != '\n') return 0;
    value[length - 1] = 0;
    return 1;
}

int main(int argc, char **argv) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    started = (unsigned long long)now.tv_sec * 1000000000ULL + (unsigned long long)now.tv_nsec;
    incarnation = "outside-control";
    if (argc == 6 && !strcmp(argv[1], "--once")) {
        operation(stdout, argv[2], argv[3], argv[4], argv[5]);
        return 0;
    }
    if (argc != 5 || strcmp(argv[1], "--loop")) return 2;
    const char *control = argv[2], *storage = argv[3];
    incarnation = argv[4];
    char temporary[PATH_MAX], target[PATH_MAX], command[PATH_MAX];
    if (snprintf(command, sizeof(command), "%s/command", control) >= (int)sizeof(command)) return 2;
    FILE *out = open_result(control, "ready", temporary, target);
    struct statvfs fs;
    int stat_rc = statvfs(storage, &fs), stat_errno = stat_rc ? errno : 0;
    int entries = 0, directory_errno = 0;
    DIR *directory = opendir(storage);
    if (!directory) directory_errno = errno;
    else {
        struct dirent *entry;
        while ((entry = readdir(directory)) && entries < 1000)
            if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) ++entries;
        closedir(directory);
    }
    fputs("{", out); identity(out);
    fprintf(out, ",\"seccomp\":%d,\"no_new_privs\":%d,\"statvfs_rc\":%d,\"statvfs_errno\":%d,"
                 "\"storage_readonly\":%s,\"storage_entries\":%d,\"directory_errno\":%d}\n",
            prctl(PR_GET_SECCOMP, 0, 0, 0, 0), prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0),
            stat_rc, stat_errno, !stat_rc && (fs.f_flag & ST_RDONLY) ? "true" : "false", entries, directory_errno);
    publish(out, temporary, target);
    char last[128] = {0};
    for (;;) {
        FILE *input = fopen(command, "r");
        if (input) {
            char action[32], request[128], path[PATH_MAX], data[4096];
            int valid = field(input, action, sizeof(action));
            if (valid && !strcmp(action, "STOP")) { fclose(input); break; }
            valid = valid && field(input, request, sizeof(request)) && field(input, path, sizeof(path)) && field(input, data, sizeof(data));
            fclose(input);
            if (valid && strcmp(last, request)) {
                snprintf(last, sizeof(last), "%s", request);
                out = open_result(control, "response", temporary, target);
                operation(out, action, request, path, data);
                publish(out, temporary, target);
            }
        }
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 20000000};
        nanosleep(&pause, NULL);
    }
    return 0;
}
