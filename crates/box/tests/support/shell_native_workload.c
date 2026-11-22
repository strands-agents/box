/* Direct ARM64 calls for the Shell/native comparison suite. */
#include <asm/unistd.h>
#include <fcntl.h>

static long call(long n, long a, long b, long c, long d) {
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x8 __asm__("x8") = n;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x8) : "memory");
    return x0;
}

static void finish(long code) {
    call(__NR_exit, code, 0, 0, 0);
    __builtin_unreachable();
}

static int same(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

static long read_file(const char *path) {
    long fd = call(__NR_openat, AT_FDCWD, (long)path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return fd;
    char bytes[32];
    long count = call(__NR_read, fd, (long)bytes, sizeof(bytes), 0);
    call(__NR_close, fd, 0, 0, 0);
    const char expected[] = "original\n";
    if (count != sizeof(expected) - 1) finish(101);
    for (long i = 0; i < count; i++) if (bytes[i] != expected[i]) finish(102);
    if (call(__NR_write, 1, (long)bytes, count, 0) != count) finish(103);
    return 0;
}

static long list_directory(const char *path) {
    long fd = call(__NR_openat, AT_FDCWD, (long)path, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (fd < 0) return fd;
    char bytes[1024];
    int found = 0;
    long count;
    while ((count = call(__NR_getdents64, fd, (long)bytes, sizeof(bytes), 0)) > 0) {
        for (long pos = 0; pos < count;) {
            if (pos + 19 >= count) finish(104);
            unsigned short len = *(unsigned short *)(bytes + pos + 16);
            if (len < 20 || pos + len > count) finish(105);
            const char *name = bytes + pos + 19;
            int terminated = 0;
            for (long j = pos + 19; j < pos + len; j++) if (!bytes[j]) terminated = 1;
            if (!terminated) finish(106);
            if (same(name, "child")) found++;
            else if (!same(name, ".") && !same(name, "..")) finish(107);
            pos += len;
        }
    }
    call(__NR_close, fd, 0, 0, 0);
    if (count < 0 || found != 1) finish(108);
    call(__NR_write, 1, (long)"child\n", 6, 0);
    return 0;
}

void native_main(long *stack) {
    if (*stack != 6) finish(90);
    char **argv = (char **)(stack + 1);
    long result;
    if (same(argv[1], "rename") || same(argv[1], "temporal")) {
        result = call(__NR_renameat, AT_FDCWD, (long)argv[2], AT_FDCWD, (long)argv[3]);
        if (same(argv[1], "temporal")) {
            if (result != 0) finish(109);
            result = read_file(argv[4]);
        }
    } else if (same(argv[1], "list")) {
        result = list_directory(argv[2]);
    } else if (same(argv[1], "read")) {
        result = read_file(argv[2]);
    } else finish(91);
    if (same(argv[5], "allow")) {
        if (result < 0) finish(92);
        call(__NR_write, 1, (long)"NATIVE_ALLOWED\n", 15, 0);
    } else {
        if (result != -13 && result != -1) finish(93);
        call(__NR_write, 1, (long)"NATIVE_DENIED\n", 14, 0);
    }
    finish(0);
}

__asm__(".global _start\n_start:\nmov x0, sp\nbl native_main\n");
