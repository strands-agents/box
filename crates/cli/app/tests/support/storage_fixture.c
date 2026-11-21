/* Trusted test fixture for incoming mounts, using libfuse's high-level API.
 * Build with the libfuse 3 development headers and library.
 * This is not a hardened general-purpose filesystem. */
#define _GNU_SOURCE
#define FUSE_USE_VERSION 31
#include <fuse.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statvfs.h>
#include <unistd.h>
static int backing;
static const char *relative(const char *path) { return path[1] ? path + 1 : "."; }
static int result(int value) { return value < 0 ? -errno : value; }
static void observed(const char *op, const char *path) {
    struct fuse_context *context = fuse_get_context();
    fprintf(stderr, "%s request_pid=%d path=%s\n", op, context ? context->pid : -1, path ? path : "-");
    fflush(stderr);
}
static void *initialize(struct fuse_conn_info *connection, struct fuse_config *config) {
    (void)connection;
    config->entry_timeout = 0;
    config->attr_timeout = 0;
    config->negative_timeout = 0;
    config->kernel_cache = 0;
    observed("INIT", "/");
    return NULL;
}
static int attributes(const char *path, struct stat *statbuf, struct fuse_file_info *file) {
    observed("GETATTR", path);
    return result(file ? fstat((int)file->fh, statbuf) : fstatat(backing, relative(path), statbuf, AT_SYMLINK_NOFOLLOW));
}
static int read_link(const char *path, char *buffer, size_t size) {
    observed("READLINK", path);
    ssize_t length = readlinkat(backing, relative(path), buffer, size - 1);
    if (length < 0) return -errno;
    buffer[length] = 0;
    return 0;
}
static int list_directory(const char *path, void *buffer, fuse_fill_dir_t fill, off_t offset,
                          struct fuse_file_info *file, enum fuse_readdir_flags flags) {
    (void)file; (void)flags; observed("READDIR", path);
    int fd = openat(backing, relative(path), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return -errno;
    DIR *directory = fdopendir(fd);
    if (!directory) { int error = errno; close(fd); return -error; }
    if (offset) seekdir(directory, offset);
    errno = 0;
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        struct stat statbuf;
        if (fstatat(fd, entry->d_name, &statbuf, AT_SYMLINK_NOFOLLOW) < 0) { int error = errno; closedir(directory); return -error; }
        if (fill(buffer, entry->d_name, &statbuf, telldir(directory), 0)) break;
        errno = 0;
    }
    int error = errno;
    closedir(directory);
    return error ? -error : 0;
}
static int open_file(const char *path, struct fuse_file_info *file) {
    observed("OPEN", path);
    int fd = openat(backing, relative(path), file->flags | O_CLOEXEC);
    if (fd < 0) return -errno;
    file->fh = (unsigned int)fd; file->direct_io = 1;
    return 0;
}
static int create_file(const char *path, mode_t mode, struct fuse_file_info *file) {
    observed("CREATE", path);
    int fd = openat(backing, relative(path), file->flags | O_CREAT | O_CLOEXEC, mode);
    if (fd < 0) return -errno;
    file->fh = (unsigned int)fd; file->direct_io = 1;
    return 0;
}
static int read_file(const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *file) {
    observed("READ", path);
    return result((int)pread((int)file->fh, buffer, size, offset));
}
static int write_file(const char *path, const char *buffer, size_t size, off_t offset, struct fuse_file_info *file) {
    observed("WRITE", path);
    return result((int)pwrite((int)file->fh, buffer, size, offset));
}
static int release_file(const char *path, struct fuse_file_info *file) {
    observed("RELEASE", path); return result(close((int)file->fh));
}
static int flush_file(const char *path, struct fuse_file_info *file) {
    (void)path; (void)file; return 0;
}
static int sync_file(const char *path, int data_only, struct fuse_file_info *file) {
    (void)path; return result(data_only ? fdatasync((int)file->fh) : fsync((int)file->fh));
}
static int truncate_file(const char *path, off_t size, struct fuse_file_info *file) {
    observed("TRUNCATE", path);
    if (file) return result(ftruncate((int)file->fh, size));
    int fd = openat(backing, relative(path), O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -errno;
    int rc = result(ftruncate(fd, size)); close(fd); return rc;
}
static int make_directory(const char *path, mode_t mode) { observed("MKDIR", path); return result(mkdirat(backing, relative(path), mode)); }
static int remove_directory(const char *path) { observed("RMDIR", path); return result(unlinkat(backing, relative(path), AT_REMOVEDIR)); }
static int remove_file(const char *path) { observed("UNLINK", path); return result(unlinkat(backing, relative(path), 0)); }
static int make_symlink(const char *target, const char *path) { observed("SYMLINK", path); return result(symlinkat(target, backing, relative(path))); }
static int rename_file(const char *old_path, const char *new_path, unsigned int flags) {
    observed("RENAME", old_path); if (flags) return -EINVAL;
    return result(renameat(backing, relative(old_path), backing, relative(new_path)));
}
static int change_mode(const char *path, mode_t mode, struct fuse_file_info *file) {
    observed("CHMOD", path); return result(file ? fchmod((int)file->fh, mode) : fchmodat(backing, relative(path), mode, 0));
}
static int change_owner(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *file) {
    observed("CHOWN", path); return result(file ? fchown((int)file->fh, uid, gid) : fchownat(backing, relative(path), uid, gid, AT_SYMLINK_NOFOLLOW));
}
static int change_times(const char *path, const struct timespec times[2], struct fuse_file_info *file) {
    observed("UTIMENS", path); return result(file ? futimens((int)file->fh, times) : utimensat(backing, relative(path), times, AT_SYMLINK_NOFOLLOW));
}
static int filesystem_stat(const char *path, struct statvfs *statbuf) { (void)path; return result(fstatvfs(backing, statbuf)); }
static const struct fuse_operations operations = {
    .init=initialize, .getattr=attributes, .readlink=read_link, .readdir=list_directory,
    .open=open_file, .create=create_file, .read=read_file, .write=write_file,
    .release=release_file, .flush=flush_file, .fsync=sync_file, .truncate=truncate_file,
    .mkdir=make_directory, .rmdir=remove_directory, .unlink=remove_file, .symlink=make_symlink,
    .rename=rename_file, .chmod=change_mode, .chown=change_owner, .utimens=change_times, .statfs=filesystem_stat
};
int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: %s BACKING_DIR MOUNTPOINT\n", argv[0]); return 2; }
    backing = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (backing < 0) { perror("backing directory"); return 2; }
    umask(0);
    char *fuse_argv[] = {argv[0], argv[2], "-f", "-s", "-o", "default_permissions,subtype=boxfixture", NULL};
    int rc = fuse_main(6, fuse_argv, &operations, NULL);
    close(backing); return rc;
}
