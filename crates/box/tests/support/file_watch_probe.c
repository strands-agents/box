#include <CoreServices/CoreServices.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int finished;
static FILE *progress;

static void require(int condition, const char *operation) {
    if (!condition) {
        fprintf(stderr, "probe failed: %s (errno=%d)\n", operation, errno);
        exit(2);
    }
}

static int refused(void) {
    return errno == EPERM || errno == EACCES;
}

static void check_access(const char *root) {
    char path[4096];
    struct stat metadata;
    snprintf(path, sizeof(path), "%s/denied/seed", root);
    require(stat(path, &metadata) == -1 && refused(), "denied stat");
    require(open(path, O_RDONLY) == -1 && refused(), "denied read");
    require(open(path, O_WRONLY) == -1 && refused(), "denied write");
    require(unlink(path) == -1 && refused(), "denied unlink");
    snprintf(path, sizeof(path), "%s/denied", root);
    require(opendir(path) == NULL && refused(), "denied list");
    snprintf(path, sizeof(path), "%s/allowed", root);
    require(stat(path, &metadata) == 0, "allowed stat");
    int fd = open(path, O_RDONLY);
    require(fd >= 0, "allowed read");
    char byte;
    require(read(fd, &byte, 1) == 1, "allowed contents");
    close(fd);
    fd = open(path, O_WRONLY);
    require(fd >= 0, "allowed write");
    require(write(fd, "x", 1) == 1, "allowed contents write");
    close(fd);
    fprintf(progress, "ACCESS_OK\n");
}

static void events(ConstFSEventStreamRef stream, void *context, size_t count,
                   void *event_paths, const FSEventStreamEventFlags flags[],
                   const FSEventStreamEventId ids[]) {
    (void)stream;
    (void)context;
    (void)ids;
    char **paths = event_paths;
    for (size_t i = 0; i < count; i++) {
        const char *name = strrchr(paths[i], '/');
        name = name ? name + 1 : paths[i];
        if (strcmp(name, "created") && strcmp(name, "modified") &&
            strcmp(name, "renamed") && strcmp(name, "finish")) continue;
        fprintf(progress, "EVENT %s %u\n", name, flags[i]);
        if (!strcmp(name, "finish")) finished = 1;
    }
}

int main(int argc, char **argv) {
    require(argc == 2, "one watch root");
    char progress_path[4096];
    snprintf(progress_path, sizeof(progress_path), "%s/watch-progress", argv[1]);
    progress = fopen(progress_path, "w");
    require(progress != NULL, "progress file");
    setvbuf(progress, NULL, _IOLBF, 0);
    check_access(argv[1]);
    CFStringRef root = CFStringCreateWithCString(NULL, argv[1], kCFStringEncodingUTF8);
    require(root != NULL, "watch root");
    CFArrayRef roots = CFArrayCreate(NULL, (const void **)&root, 1, &kCFTypeArrayCallBacks);
    require(roots != NULL, "watch roots");
    FSEventStreamRef stream = FSEventStreamCreate(
        NULL, events, NULL, roots, kFSEventStreamEventIdSinceNow, 0.01,
        kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagNoDefer);
    require(stream != NULL, "create stream");
    FSEventStreamScheduleWithRunLoop(stream, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
    if (!FSEventStreamStart(stream)) {
        fprintf(progress, "WATCH_REFUSED\n");
    } else {
        fprintf(progress, "WATCH_READY\n");
        CFAbsoluteTime deadline = CFAbsoluteTimeGetCurrent() + 20;
        while (!finished && CFAbsoluteTimeGetCurrent() < deadline)
            CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.1, false);
        FSEventStreamStop(stream);
        require(finished, "watch completion before deadline");
        check_access(argv[1]);
    }
    FSEventStreamInvalidate(stream);
    FSEventStreamRelease(stream);
    CFRelease(roots);
    CFRelease(root);
    fclose(progress);
    return 0;
}
