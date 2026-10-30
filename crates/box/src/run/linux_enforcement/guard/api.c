#include <linux/bpf.h>
#include <linux/capability.h>
#include <sys/prctl.h>
#include <linux/btf.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int box_guard_map(void) {
    struct {
        struct btf_header header;
        struct btf_type key;
        uint32_t key_encoding;
        struct btf_type word;
        uint32_t word_encoding;
        struct btf_type value;
        struct btf_array array;
        char strings[9];
    } btf = {0};
    btf.header.magic = BTF_MAGIC;
    btf.header.version = BTF_VERSION;
    btf.header.hdr_len = sizeof(struct btf_header);
    btf.header.type_len = 56;
    btf.header.str_off = 56;
    btf.header.str_len = sizeof(btf.strings);
    btf.key.name_off = 1;
    btf.key.info = BTF_KIND_INT << 24;
    btf.key.size = 4;
    btf.key_encoding = (BTF_INT_SIGNED << 24) | 32;
    btf.word.name_off = 5;
    btf.word.info = BTF_KIND_INT << 24;
    btf.word.size = 8;
    btf.word_encoding = 64;
    btf.value.info = BTF_KIND_ARRAY << 24;
    btf.array.type = 2;
    btf.array.index_type = 1;
    btf.array.nelems = 10;
    memcpy(btf.strings, "\0int\0u64\0", 9);
    union bpf_attr attr = {0};
    attr.btf = (uintptr_t)&btf;
    attr.btf_size = sizeof(struct btf_header) + 56 + 9;
    int description = syscall(SYS_bpf, BPF_BTF_LOAD, &attr, sizeof(attr));
    if (description < 0) return -1;
    memset(&attr, 0, sizeof(attr));
    attr.map_type = BPF_MAP_TYPE_TASK_STORAGE;
    attr.key_size = sizeof(int);
    attr.value_size = 80;
    attr.map_flags = BPF_F_NO_PREALLOC;
    attr.btf_fd = description;
    attr.btf_key_type_id = 1;
    attr.btf_value_type_id = 3;
    int map = syscall(SYS_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
    int saved_errno = errno;
    close(description);
    errno = saved_errno;
    return map;
}
int box_guard_update(int map, int task, const void *value) {
    union bpf_attr attr = {0};
    attr.map_fd = map;
    attr.key = (uintptr_t)&task;
    attr.value = (uintptr_t)value;
    return syscall(SYS_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}
int box_guard_delete(int map, int task) {
    union bpf_attr attr = {0};
    attr.map_fd = map;
    attr.key = (uintptr_t)&task;
    return syscall(SYS_bpf, BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}
int box_guard_load(const void *code, unsigned count, unsigned hook, char *log, unsigned size) {
    union bpf_attr attr = {0};
    attr.prog_type = BPF_PROG_TYPE_LSM;
    attr.insns = (uintptr_t)code;
    attr.insn_cnt = count;
    attr.license = (uintptr_t)"GPL";
    attr.expected_attach_type = BPF_LSM_MAC;
    attr.attach_btf_id = hook;
    attr.log_level = 1;
    attr.log_buf = (uintptr_t)log;
    attr.log_size = size;
    return syscall(SYS_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
}
int box_guard_attach(int program) {
    union bpf_attr attr = {0};
    attr.raw_tracepoint.prog_fd = program;
    return syscall(SYS_bpf, BPF_RAW_TRACEPOINT_OPEN, &attr, sizeof(attr));
}

int box_guard_capabilities(uint64_t *effective) {
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct data[2] = {{0}};
    if (syscall(SYS_capget, &header, data) < 0) return -1;
    *effective = ((uint64_t)data[1].effective << 32) | data[0].effective;
    return 0;
}
int box_guard_drop_capabilities(void) {
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct data[2] = {{0}};
    if (syscall(SYS_capget, &header, data) < 0) return -1;
    const uint32_t loader = (1U << (CAP_BPF - 32)) | (1U << (CAP_PERFMON - 32));
    if (!((data[1].effective | data[1].permitted | data[1].inheritable) & loader)) return 0;
    data[1].effective &= ~loader;
    data[1].permitted &= ~loader;
    data[1].inheritable &= ~loader;
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, CAP_BPF, 0, 0) < 0) return -1;
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, CAP_PERFMON, 0, 0) < 0) return -1;
    if (syscall(SYS_capset, &header, data) < 0) return -1;
    return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
}
