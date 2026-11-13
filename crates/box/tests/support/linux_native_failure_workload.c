/* A static ARM64 workload. Each operation calls Linux directly, without Shell. */
#include <asm/unistd.h>
#include <errno.h>
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

static void message(const char *text, long length) {
    invoke(__NR_write, 1, (long)text, length, 0, 0);
}
static void gate(void) {
    char byte;
    if (invoke(__NR_read, 0, (long)&byte, 1, 0, 0) != 1) {
        invoke(__NR_exit, 0, 0, 0, 0, 0);
        __builtin_unreachable();
    }
}
static void finish(long code) {
    invoke(__NR_exit, code, 0, 0, 0, 0);
    __builtin_unreachable();
}
static long transfer(int fd, char *bytes, long count, int writing) {
    long done = 0;
    while (done < count) {
        long result = invoke(writing ? __NR_write : __NR_read, fd,
                             (long)(bytes + done), count - done, 0, 0);
        if (result == -EINTR) continue;
        if (result <= 0) return result;
        done += result;
    }
    return done;
}
static void report(const char *label, long count) {
    char line[64], digits[24];
    int length = 0, used = 0;
    while (*label) line[length++] = *label++;
    do { digits[used++] = '0' + count % 10; count /= 10; } while (count);
    while (used) line[length++] = digits[--used];
    line[length++] = '\n';
    transfer(1, line, length, 1);
}
static void parallel_reads(const char *path, int denied) {
    enum { count = 384 };
    int ready[2], release[2];
    if (invoke(__NR_pipe2, (long)ready, O_CLOEXEC, 0, 0, 0) < 0 ||
        invoke(__NR_pipe2, (long)release, O_CLOEXEC, 0, 0, 0) < 0) finish(100);
    long children[count];
    int spawned = 0;
    for (; spawned < count; spawned++) {
        long child = invoke(__NR_clone, 17, 0, 0, 0, 0);
        if (child < 0) break;
        if (child == 0) {
            invoke(__NR_close, ready[0], 0, 0, 0, 0);
            invoke(__NR_close, release[1], 0, 0, 0, 0);
            char bytes[16];
            bytes[0] = 'R';
            if (transfer(ready[1], bytes, 1, 1) != 1) finish(101);
            invoke(__NR_close, ready[1], 0, 0, 0, 0);
            if (transfer(release[0], bytes, 1, 0) != 1) finish(101);
            invoke(__NR_close, release[0], 0, 0, 0, 0);
            long fd = invoke(__NR_openat, AT_FDCWD, (long)path, O_RDONLY | O_CLOEXEC, 0, 0);
            if (denied) {
                if (fd >= 0) invoke(__NR_close, fd, 0, 0, 0, 0);
                finish(fd == -EACCES ? 0 : 102);
            }
            if (fd < 0) finish(103);
            long size = invoke(__NR_read, fd, (long)bytes, sizeof(bytes), 0, 0);
            invoke(__NR_close, fd, 0, 0, 0, 0);
            const char expected[] = "original\n";
            if (size != (long)(sizeof(expected) - 1)) finish(104);
            for (unsigned n = 0; n < sizeof(expected) - 1; n++) {
                if (bytes[n] != expected[n]) finish(105);
            }
            finish(0);
        }
        children[spawned] = child;
    }
    invoke(__NR_close, ready[1], 0, 0, 0, 0);
    invoke(__NR_close, release[0], 0, 0, 0, 0);
    char bytes[count];
    int failed = transfer(ready[0], bytes, spawned, 0) != spawned;
    /* No child opens the file until all spawned children have reached this barrier. */
    report("READY ", spawned);
    if (!failed && transfer(release[1], bytes, spawned, 1) != spawned) failed++;
    invoke(__NR_close, ready[0], 0, 0, 0, 0);
    invoke(__NR_close, release[1], 0, 0, 0, 0);
    int reaped = 0;
    for (int n = 0; n < spawned; n++) {
        int status = 0;
        long result;
        do { result = invoke(__NR_wait4, children[n], (long)&status, 0, 0, 0); }
        while (result == -EINTR);
        if (result == children[n]) reaped++;
        if (result != children[n] || status != 0) failed++;
    }
    report("COMPLETED ", reaped);
    report("FAILED ", failed);
    finish(failed || spawned != count || reaped != count ? 106 : 0);
}
void native_main(long *stack) {
    char **argv = (char **)(stack + 1);
    if (*stack != 3) { invoke(__NR_exit, 90, 0, 0, 0, 0); __builtin_unreachable(); }
    message("READY\n", 6);
    gate();
    if (argv[1][0] == 'p') parallel_reads(argv[2], argv[1][9] == 'd');
    if (argv[1][0] == 'r' || argv[1][0] == 'l') {
        int directory = argv[1][0] == 'l';
        long fd = invoke(__NR_openat, AT_FDCWD, (long)argv[2],
                         O_RDONLY | O_CLOEXEC | (directory ? O_DIRECTORY : 0), 0, 0);
        if (fd < 0) {
            message("DENIED\n", 7);
            invoke(__NR_exit, 97, 0, 0, 0, 0);
            __builtin_unreachable();
        }
        message("OPENED\n", 7);
        gate();
        char buffer[4096];
        long count = invoke(directory ? __NR_getdents64 : __NR_read,
                            fd, (long)buffer, sizeof(buffer), 0, 0);
        int valid = 0;
        if (directory && count > 0) {
            for (long offset = 0; offset + 20 <= count;) {
                unsigned short size = *(unsigned short *)(buffer + offset + 16);
                if (size < 20 || offset + size > count) break;
                const char *name = buffer + offset + 19;
                const char expected[] = "protected.txt";
                if (size >= 19 + sizeof(expected)) {
                    int matches = 1;
                    for (unsigned n = 0; n < sizeof(expected); n++)
                        if (name[n] != expected[n]) matches = 0;
                    if (matches) valid = 1;
                }
                offset += size;
            }
        } else if (!directory && count == 9) {
            const char expected[] = "original\n";
            valid = 1;
            for (int n = 0; n < 9; n++)
                if (buffer[n] != expected[n]) valid = 0;
        }
        if (!valid) {
            message("FAILED\n", 7);
            invoke(__NR_exit, 98, 0, 0, 0, 0);
            __builtin_unreachable();
        }
        message(directory ? "LISTED\n" : "READ\n", directory ? 7 : 5);
        gate();
        invoke(__NR_exit, 0, 0, 0, 0, 0);
        __builtin_unreachable();
    }
    if (argv[1][0] == 'd') {
        long result = invoke(__NR_unlinkat, AT_FDCWD, (long)argv[2], 0, 0, 0);
        message(result < 0 ? "DENIED\n" : "ALLOWED\n", result < 0 ? 7 : 8);
        gate();
        invoke(__NR_exit, 0, 0, 0, 0, 0);
        __builtin_unreachable();
    }
    if (argv[1][0] == 'c') {
        long children[16];
        for (int n = 0; n < 16; n++) {
            children[n] = invoke(__NR_clone, 17, 0, 0, 0, 0);
            if (children[n] < 0) { message("FORK_FAILED\n",12); invoke(__NR_exit, 91, 0, 0, 0, 0); }
            if (children[n] == 0) {
                for (int i = 0; i < 8; i++) {
                    long file = invoke(__NR_openat, AT_FDCWD, (long)argv[2], O_WRONLY | O_TRUNC | O_CLOEXEC, 0, 0);
                    if (file < 0) { message("DENIED\n",7); invoke(__NR_exit, 92, 0, 0, 0, 0); }
                    if (invoke(__NR_write, file, (long)"changed\n", 8, 0, 0) != 8) invoke(__NR_exit, 93, 0, 0, 0, 0);
                    invoke(__NR_close, file, 0, 0, 0, 0);
                }
                invoke(__NR_exit, 0, 0, 0, 0, 0);
                __builtin_unreachable();
            }
        }
        for (int n = 0; n < 16; n++) {
            int status = 0;
            if (invoke(__NR_wait4, children[n], (long)&status, 0, 0, 0) != children[n] || status != 0) {
                message("CHILD_FAILED\n",13); invoke(__NR_exit, 94, 0, 0, 0, 0);
            }
        }
        message("COMPLETE\n",9);
        invoke(__NR_exit, 0, 0, 0, 0, 0);
        __builtin_unreachable();
    }
    if (argv[1][0] == 'x') {
        long child = invoke(__NR_clone, 17, 0, 0, 0, 0);
        if (child < 0) { message("FORK_FAILED\n",12); invoke(__NR_exit, 91, 0, 0, 0, 0); }
        if (child == 0) {
            invoke(__NR_openat, AT_FDCWD, (long)argv[2], O_WRONLY | O_TRUNC | O_CLOEXEC, 0, 0);
            invoke(__NR_exit, 0, 0, 0, 0, 0);
            __builtin_unreachable();
        }
        message("PENDING\n",8);
        gate();
        if (invoke(__NR_tgkill, child, child, 9, 0, 0) != 0) invoke(__NR_exit, 95, 0, 0, 0, 0);
        int status = 0;
        if (invoke(__NR_wait4, child, (long)&status, 0, 0, 0) != child || status != 9) invoke(__NR_exit, 96, 0, 0, 0, 0);
        message("CANCELLED\n",10);
        gate();
    }
    long fd = invoke(__NR_openat, AT_FDCWD, (long)argv[2], O_WRONLY | O_TRUNC | O_CLOEXEC, 0, 0);
    if (fd < 0) {
        message("DENIED\n", 7);
        gate();
        invoke(__NR_exit, 0, 0, 0, 0, 0);
        __builtin_unreachable();
    }
    invoke(__NR_write, fd, (long)"changed\n", 8, 0, 0);
    message("ALLOWED\n", 8);
    if (argv[1][0] == 't') {
        for (int n = 0; n < 3; n++) {
            long child = invoke(__NR_clone, 17, 0, 0, 0, 0);
            if (child < 0) { message("FORK_FAILED\n",12); break; }
            if (child == 0) {
                if (invoke(__NR_setsid, 0, 0, 0, 0, 0) < 0) message("SETSID_FAILED\n",14);
                break;
            }
        }
        message("TREE\n", 5);
        for (int turn = 0; turn < 500; turn++) {
            invoke(__NR_write, fd, (long)"tick\n", 5, 0, 0);
            long delay[2] = {0, 20000000};
            invoke(__NR_clock_nanosleep, 1, 0, (long)delay, 0, 0);
        }
        invoke(__NR_exit, 0, 0, 0, 0, 0);
        __builtin_unreachable();
    }
    if (argv[1][0] != 'e') gate();
    invoke(__NR_exit, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl native_main\n");
