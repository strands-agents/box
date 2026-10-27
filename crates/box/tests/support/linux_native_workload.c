/* A static ARM64 workload. Each operation calls Linux directly, without Shell. */
#include <asm/unistd.h>
#include <fcntl.h>

static long invoke(long n, long a, long b, long c, long d, long e) {
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    register long x8 __asm__("x8") = n;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8) : "memory");
    return x0;
}

static long temporary_workload(char **argv) {
    const char *path = argv[2];
    const char *destination = argv[3];
    static const char content[] = "private bytes\n";
    long fd = invoke(__NR_openat, AT_FDCWD, (long)path, O_RDONLY | O_CLOEXEC, 0, 0);
    if (fd != -2) return -100;
    fd = invoke(__NR_openat, AT_FDCWD, (long)path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600, 0);
    if (argv[1][3] == 'w') return fd < 0 ? -13 : -101;
    if (fd < 0) return -102;
    if (invoke(__NR_write, fd, (long)content, sizeof(content)-1, 0, 0) != sizeof(content)-1) return -103;
    invoke(__NR_close, fd, 0, 0, 0, 0);
    fd = invoke(__NR_openat, AT_FDCWD, (long)path, O_RDONLY | O_CLOEXEC, 0, 0);
    if (argv[1][3] == 'r') return fd < 0 ? -13 : -104;
    if (fd < 0) return -105;
    char bytes[sizeof(content)];
    long count = invoke(__NR_read, fd, (long)bytes, sizeof(bytes), 0, 0);
    invoke(__NR_close, fd, 0, 0, 0, 0);
    if (count != sizeof(content)-1) return -106;
    for (int i=0; i<count; i++) if (bytes[i] != content[i]) return -107;
    if (invoke(__NR_renameat, AT_FDCWD, (long)path, AT_FDCWD, (long)destination, 0) != 0) return -108;
    if (invoke(__NR_unlinkat, AT_FDCWD, (long)destination, 0, 0, 0) != 0) return -109;
    if (invoke(__NR_mkdirat, AT_FDCWD, (long)path, 0700, 0, 0) != 0) return -110;
    if (invoke(__NR_unlinkat, AT_FDCWD, (long)path, AT_REMOVEDIR, 0, 0) != 0) return -111;
    if (invoke(__NR_symlinkat, (long)"target", AT_FDCWD, (long)path, 0, 0) != 0) return -112;
    if (invoke(__NR_unlinkat, AT_FDCWD, (long)path, 0, 0, 0) != 0) return -113;
    return 0;
}

void native_main(long *stack) {
    char **argv = (char **)(stack + 1);
    if (*stack != 5) {
        invoke(__NR_exit, 90, 0, 0, 0, 0);
        __builtin_unreachable();
    }
    if ((argv[1][0] == 'v' || argv[1][0] == 'l') && argv[1][1] == 'c') {
        long child = invoke(__NR_clone, 17, 0, 0, 0, 0);
        if (child < 0) { invoke(__NR_exit, 95, 0, 0, 0, 0); __builtin_unreachable(); }
        if (child > 0) {
            int status = 0;
            if (invoke(__NR_wait4, child, (long)&status, 0, 0, 0) != child) status = 96 << 8;
            invoke(__NR_exit, status >> 8, 0, 0, 0, 0); __builtin_unreachable();
        }
    }
    long result;
    char op = argv[1][0];
    long directory = AT_FDCWD;
    char parent[4096];
    const char *path = argv[2];
    int last = -1;
    for (int i = 0; argv[2][i] && i < sizeof(parent)-1; i++) { parent[i] = argv[2][i]; if (parent[i] == '/') last = i; }
    if (last < 0) { invoke(__NR_exit, 97, 0, 0, 0, 0); __builtin_unreachable(); }
    parent[last] = 0;
    if (op == 'l' && argv[1][1] != 'a') {
        if (argv[1][1] == 'c' && invoke(__NR_chdir, (long)parent, 0, 0, 0, 0) < 0) {
            invoke(__NR_exit, 98, 0, 0, 0, 0); __builtin_unreachable();
        }
        path = argv[2] + last + 1;
    }
    if (op == 'f') {
        directory = invoke(__NR_openat, AT_FDCWD, (long)parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0, 0);
        if (directory < 0) { invoke(__NR_exit, 99, 0, 0, 0, 0); __builtin_unreachable(); }
        path = argv[2] + last + 1;
    }
    if ((op == 'c' || op == 'd' || op == 'm') && argv[1][1] == 'l') path = argv[2] + last + 1;
    if (op == 'i') directory = -999;
    if (op == 'z') path = "absent.txt";
    if (op == 'e' || op == 'h') path = parent;
    if (op == 'P') {
        int flags = O_RDONLY | O_CLOEXEC;
        if (argv[1][1] == 'c') flags = O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC;
        if (argv[1][1] == 'd') flags = O_WRONLY | O_CREAT | O_CLOEXEC;
        if (argv[1][1] == 'h' || argv[1][1] == 's') flags = O_PATH | O_CLOEXEC;
        if (argv[1][1] == 's' || argv[1][1] == 'n') flags |= O_NOFOLLOW;
        result = invoke(__NR_openat, AT_FDCWD, (long)path, flags, flags & O_CREAT ? 0600 : 0, 0);
        if (result >= 0) {
            char bytes[16];
            if (flags & O_CREAT) {
                static const char content[] = "created\n";
                if (invoke(__NR_write, result, (long)content, sizeof(content)-1, 0, 0) != sizeof(content)-1)
                    invoke(__NR_exit, 109, 0, 0, 0, 0);
            } else if (flags & O_PATH) {
                long actual = invoke(__NR_fcntl, result, F_GETFL, 0, 0, 0);
                if (actual < 0 || !(actual & O_PATH) || invoke(__NR_read, result, (long)bytes, 1, 0, 0) != -9)
                    invoke(__NR_exit, 104, 0, 0, 0, 0);
            } else {
                long count = invoke(__NR_read, result, (long)bytes, sizeof(bytes), 0, 0);
                static const char expected[] = "original\n";
                if (count != sizeof(expected)-1) invoke(__NR_exit, 105, 0, 0, 0, 0);
                for (int i=0; i<count; i++) if (bytes[i] != expected[i]) invoke(__NR_exit, 106, 0, 0, 0, 0);
            }
            if (!(invoke(__NR_fcntl, result, F_GETFD, 0, 0, 0) & FD_CLOEXEC)) invoke(__NR_exit, 107, 0, 0, 0, 0);
            invoke(__NR_close, result, 0, 0, 0, 0);
        }
        if (argv[4][0] == 'p') {
            if (result < 0 && result != -95) invoke(__NR_exit, 108, 0, 0, 0, 0);
            argv[4] = result >= 0 ? "allow" : "deny";
        }
    } else if (op == 't') {
        result = temporary_workload(argv);
        if (result < -99) {
            invoke(__NR_exit, -result, 0, 0, 0, 0);
            __builtin_unreachable();
        }
    } else if (op == 'x') {
        result = invoke(__NR_truncate, (long)path, 3, 0, 0, 0);
    } else if (op == 'j') {
        invoke(__NR_umask, 0027, 0, 0, 0, 0);
        result = invoke(__NR_mkdirat, AT_FDCWD, (long)path, 0777, 0, 0);
        if (argv[1][1] == 'e') {
            long expected = 0;
            for (int i = 0; argv[3][i]; i++) expected = expected * 10 + argv[3][i] - '0';
            invoke(__NR_exit, result == -expected ? 0 : 91, 0, 0, 0, 0);
            __builtin_unreachable();
        }
    } else if (op == 'k') {
        result = invoke(__NR_unlinkat, AT_FDCWD, (long)path, AT_REMOVEDIR, 0, 0);
    } else if (op == 's') {
        result = invoke(__NR_symlinkat, (long)argv[3], AT_FDCWD, (long)path, 0, 0);
    } else if (op == 'd') {
        result = invoke(__NR_unlinkat, AT_FDCWD, (long)path, 0, 0, 0);
    } else if (op == 'm') {
        const char *destination = argv[3];
        if (argv[1][1] == 'l') { for (int i = 0; argv[3][i]; i++) if (argv[3][i] == '/') destination = argv[3] + i + 1; }
        result = invoke(__NR_renameat, AT_FDCWD, (long)path, AT_FDCWD, (long)destination, 0);
    } else {
        long flags = O_WRONLY | O_CLOEXEC | (op == 'c' ? O_CREAT | O_EXCL : O_TRUNC);
        long mode = op == 'c' ? 0600 : 0;
        if (op == 'c' && argv[1][1] != 'r') {
            flags = O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC;
            mode = 0666;
            if (argv[1][1] == 'n') flags &= ~O_CLOEXEC;
            if (argv[1][1] == 'w') invoke(__NR_umask, 0027, 0, 0, 0, 0);
            if (argv[1][1] == 'l') invoke(__NR_umask, 0077, 0, 0, 0, 0);
        }
        if (op == 'a') flags = O_WRONLY | O_APPEND | O_CLOEXEC;
        if (op == 'r' || op == 'q' || op == 'u' || op == 'v') flags = O_RDONLY | O_CLOEXEC;
        if (op == 'q') flags |= O_NOCTTY | 0400000;
        if (op == 'p') flags &= ~O_CLOEXEC;
        if (op == 'n') flags |= O_NOFOLLOW;
        if (op == 'b') flags |= O_NONBLOCK;
        if (op == 'l' && argv[1][1] == 'a') flags |= 0400000;
        if (op == 'e') flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC;
        if (op == 'h') flags = O_PATH | O_DIRECTORY | O_CLOEXEC;
        result = invoke(__NR_openat, directory, (long)(op == 'u' ? "/dev/urandom" : op == 'v' ? "/proc/self/stat" : path), flags, mode, 0);
        if (op == 'z' && result != -2) { invoke(__NR_exit, 100, 0, 0, 0, 0); __builtin_unreachable(); }
        if (result >= 0) {
            long descriptor_flags = invoke(__NR_fcntl, result, F_GETFD, 0, 0, 0);
            int valid = descriptor_flags >= 0 && ((descriptor_flags & FD_CLOEXEC) != 0) == ((flags & O_CLOEXEC) != 0);
            if (op == 'h') {
                long actual = invoke(__NR_fcntl, result, F_GETFL, 0, 0, 0);
                valid = valid && actual >= 0 && (actual & O_PATH) != 0;
            } else if (op == 'e') {
                char entries[1024];
                valid = valid && invoke(__NR_getdents64, result, (long)entries, sizeof(entries), 0, 0) > 0;
            } else if (op == 'v') {
                char text[128];
                long count = invoke(__NR_read, result, (long)text, sizeof(text), 0, 0);
                long pid = 0; int i = 0;
                while (i < count && text[i] >= '0' && text[i] <= '9') { pid = pid * 10 + text[i] - '0'; i++; }
                valid = valid && count > 0 && pid == invoke(__NR_getpid, 0, 0, 0, 0, 0);
            } else if (op == 'u') {
                char byte;
                valid = valid && invoke(__NR_read, result, (long)&byte, 1, 0, 0) == 1;
            } else if (op == 'r' || op == 'q') {
                char bytes[16];
                long count = invoke(__NR_read, result, (long)bytes, sizeof(bytes), 0, 0);
                static const char expected[] = "original\n";
                valid = valid && count == sizeof(expected) - 1;
                for (int i = 0; i < sizeof(expected) - 1; i++) valid = valid && bytes[i] == expected[i];
            } else {
                static const char bytes[] = "native workload wrote\n";
                long written = invoke(__NR_write, result, (long)bytes, sizeof(bytes) - 1, 0, 0);
                valid = valid && written == sizeof(bytes) - 1;
            }
            invoke(__NR_close, result, 0, 0, 0, 0);
            if (!valid) result = -1;
        }
    }
    static const char allowed[] = "NATIVE_ALLOWED\n";
    static const char denied[] = "NATIVE_DENIED\n";
    const char *message = result >= 0 ? allowed : denied;
    invoke(__NR_write, 1, (long)message, result >= 0 ? sizeof(allowed) - 1 : sizeof(denied) - 1, 0, 0);
    if (argv[4][0] == 'p') {
        if (result < 0 && result != -95) { invoke(__NR_exit, 110, 0, 0, 0, 0); __builtin_unreachable(); }
        argv[4] = result >= 0 ? "allow" : "deny";
    }
    long expected = argv[4][0] == 'a';
    invoke(__NR_exit, (result >= 0) == expected ? 0 : 91, 0, 0, 0, 0);
    __builtin_unreachable();
}

__asm__(".global _start\n_start:\nmov x0, sp\nbl native_main\n");
