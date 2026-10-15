#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int operation(const char *name, const char *from, const char *to) {
    if (!strcmp(name, "mcp-client")) {
        int input[2], output[2];
        if (pipe(input) || pipe(output)) return -1;
        pid_t child = fork();
        if (child < 0) return -1;
        if (!child) {
            if (dup2(input[0], STDIN_FILENO) < 0 || dup2(output[1], STDOUT_FILENO) < 0) _exit(95);
            close(input[0]); close(input[1]); close(output[0]); close(output[1]);
            execlp(from, from, NULL);
            _exit(96);
        }
        close(input[0]); close(output[1]);
        FILE *writer = fdopen(input[1], "w"), *reader = fdopen(output[0], "r");
        if (!writer || !reader) return -1;
        fputs("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{},\"clientInfo\":{\"name\":\"native-test\",\"version\":\"1\"}}}\n", writer);
        fflush(writer);
        char reply[4096];
        int success = fgets(reply, sizeof(reply), reader) && strstr(reply, "\"result\"");
        fclose(writer); fclose(reader);
        int status;
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) success = 0;
        return success ? 0 : -1;
    }
    if (!strcmp(name, "mcp-server")) {
        int result = operation("write", from, "-");
        FILE *observed = fopen(to, "w");
        if (!observed) return -1;
        fprintf(observed, "%d", result);
        fclose(observed);
        char request[8192];
        while (fgets(request, sizeof(request), stdin)) {
            char *id = strstr(request, "\"id\"");
            if (!id || !(id = strchr(id, ':'))) continue;
            ++id;
            while (*id == ' ') ++id;
            char *end = id;
            if (*end == '"') { ++end; while (*end && *end != '"') ++end; if (*end) ++end; }
            else { while (*end && *end != ',' && *end != '}') ++end; }
            *end = 0;
            printf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"native-test\",\"version\":\"1\"}}}\n", id);
            fflush(stdout);
        }
        return 0;
    }
    if (!strcmp(name, "shell")) {
        execlp("sh", "sh", "-c", from, NULL);
        return -1;
    }
    if (!strcmp(name, "shells")) {
        pid_t children[2];
        const char *commands[] = {from, to};
        for (int i = 0; i < 2; ++i) {
            children[i] = fork();
            if (children[i] < 0) return -1;
            if (!children[i]) {
                execlp("sh", "sh", "-c", commands[i], NULL);
                _exit(96);
            }
        }
        int success = 1;
        for (int i = 0; i < 2; ++i) {
            int status;
            if (waitpid(children[i], &status, 0) != children[i] ||
                !WIFEXITED(status) || WEXITSTATUS(status) != 0) success = 0;
        }
        return success ? 0 : -1;
    }
    if (!strcmp(name, "reads")) {
        int count = atoi(to);
        if (count <= 0 || count > 10000) { errno = EINVAL; return -1; }
        for (int i = 0; i < count; ++i)
            if (operation("read", from, "-")) return -1;
        return 0;
    }
    if (!strcmp(name, "detached")) {
        int ready[2];
        if (pipe(ready)) return -1;
        pid_t child = fork();
        if (child < 0) return -1;
        if (!child) {
            alarm(15);
            close(ready[0]);
            if (setsid() < 0) _exit(95);
            int file = open(from, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (file < 0) _exit(96);
            char pid[32];
            int length = snprintf(pid, sizeof(pid), "%d", getpid());
            if (write(file, pid, (size_t)length) != length) _exit(97);
            close(file);
            close(STDOUT_FILENO);
            close(STDERR_FILENO);
            if (write(ready[1], "R", 1) != 1) _exit(98);
            close(ready[1]);
            for (;;) pause();
        }
        close(ready[1]);
        char marker;
        int result = read(ready[0], &marker, 1) == 1 ? 0 : -1;
        close(ready[0]);
        return result;
    }

    if (!strcmp(name, "write-twice")) {
        if (operation("write", from, to) != 0) return -1;
        errno = 0;
        int result = operation("write", from, to);
        int error = errno;
        printf("SECOND_WRITE_RESULT=%d ERRNO=%d\n", result, error);
        if (result < 0 && (error == EACCES || error == EPERM)) return 0;
        errno = EINVAL;
        return -1;
    }
    if (!strcmp(name, "create")) {
        int fd = open(from, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0) return -1;
        close(fd);
        return 0;
    }
    if (!strcmp(name, "write") || !strcmp(name, "append")) {
        int fd = open(from, O_WRONLY | (!strcmp(name, "append") ? O_APPEND : 0));
        if (fd < 0) return -1;
        int result = write(fd, "changed", 7) == 7 ? 0 : -1;
        int error = errno;
        close(fd);
        errno = error;
        return result;
    }
    if (!strcmp(name, "read")) {
        int fd = open(from, O_RDONLY);
        if (fd < 0) return -1;
        char byte;
        int result = read(fd, &byte, 1) >= 0 ? 0 : -1;
        int error = errno;
        close(fd);
        errno = error;
        return result;
    }
    if (!strcmp(name, "event-only")) {
        int fd = open(from, O_EVTONLY | O_CLOEXEC);
        if (fd < 0) return -1;
        char byte;
        int result = (int)read(fd, &byte, 1);
        int error = errno;
        errno = 0;
        int written = (int)write(fd, "x", 1);
        int write_error = errno;
        close(fd);
        printf("EVENT_ONLY_READ=%d ERRNO=%d\n", result, error);
        printf("EVENT_ONLY_WRITE=%d ERRNO=%d\n", written, write_error);
        if (result == 1 && written == -1 && write_error == EBADF) return 0;
        errno = EINVAL;
        return -1;
    }
    if (!strcmp(name, "exec-only")) {
        int fd = open(from, O_EXEC | O_CLOEXEC | O_NOCTTY | O_NONBLOCK);
        if (fd < 0) return -1;
        char byte;
        errno = 0;
        int result = (int)read(fd, &byte, 1);
        int error = errno;
        errno = 0;
        int written = (int)write(fd, "x", 1);
        int write_error = errno;
        close(fd);
        printf("EXEC_ONLY_READ=%d ERRNO=%d\n", result, error);
        printf("EXEC_ONLY_WRITE=%d ERRNO=%d\n", written, write_error);
        if (result == -1 && error == EBADF && written == -1 && write_error == EBADF) return 0;
        errno = EINVAL;
        return -1;
    }
    if (!strcmp(name, "truncate")) return truncate(from, 0);
    if (!strcmp(name, "unlink")) return unlink(from);
    if (!strcmp(name, "mkdir")) return mkdir(from, 0700);
    if (!strcmp(name, "rmdir")) return rmdir(from);
    if (!strcmp(name, "symlink")) return symlink(from, to);
    if (!strcmp(name, "rename")) return rename(from, to);
    errno = EINVAL;
    return -1;
}

int main(int argc, char **argv) {
    if (argc != 6) return 90;
    if (!strcmp(argv[5], "child") || !strcmp(argv[5], "child-exec")) {
        pid_t child = fork();
        if (child < 0) return 91;
        if (child > 0) {
            int status;
            if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) return 92;
            return WEXITSTATUS(status);
        }
        if (!strcmp(argv[5], "child-exec")) {
            execl(argv[0], argv[0], argv[1], argv[2], argv[3], argv[4], "self", NULL);
            return 96;
        }
    }
    errno = 0;
    int result = operation(argv[1], argv[2], argv[3]);
    int error = errno;
    printf("NATIVE_RESULT=%d ERRNO=%d\n", result, error);
    if (!strcmp(argv[4], "allow")) return result == 0 ? 0 : 93;
    return result < 0 && (error == EACCES || error == EPERM || error == EROFS) ? 0 : 94;
}
