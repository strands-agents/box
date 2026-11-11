/* Exercise the production bridge with controlled OS responses. */
#include <EndpointSecurity/EndpointSecurity.h>
#include <dispatch/dispatch.h>
#include <assert.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0

static _Atomic unsigned replies, flags_reply, retains, releases, faults;
static unsigned sync_calls, fail_sync_call;
static es_return_t unsubscribe_result, delete_result;

static es_respond_result_t probe_flags(es_client_t *c, const es_message_t *m,
                                      uint32_t flags, bool cache) {
    (void)c; (void)m; (void)cache;
    atomic_fetch_add(&replies, 1);
    atomic_store(&flags_reply, flags);
    return ES_RESPOND_RESULT_SUCCESS;
}
static es_respond_result_t probe_auth(es_client_t *c, const es_message_t *m,
                                     es_auth_result_t result, bool cache) {
    return probe_flags(c, m, result == ES_AUTH_RESULT_ALLOW, cache);
}
static void probe_retain(const es_message_t *m) {
    (void)m; atomic_fetch_add(&retains, 1);
}
static void probe_release(const es_message_t *m) {
    (void)m; atomic_fetch_add(&releases, 1);
}
static es_return_t probe_sync(es_client_t *c, void (^block)(void)) {
    (void)c;
    if (++sync_calls == fail_sync_call) return ES_RETURN_ERROR;
    block();
    return ES_RETURN_SUCCESS;
}
static es_return_t probe_unsubscribe(es_client_t *c) {
    (void)c; return unsubscribe_result;
}
static es_return_t probe_delete(es_client_t *c) {
    (void)c; return delete_result;
}

#define es_respond_flags_result probe_flags
#define es_respond_auth_result probe_auth
#define es_retain_message probe_retain
#define es_release_message probe_release
#define es_sync_client probe_sync
#define es_unsubscribe_all probe_unsubscribe
#define es_delete_client probe_delete
#ifndef BOX_BRIDGE_SOURCE
#define BOX_BRIDGE_SOURCE "../../crates/box/src/run/macos_enforcement/bridge.c"
#endif
#include BOX_BRIDGE_SOURCE

static bool permit(void *ctx, const box_event *event, int error) {
    (void)ctx; (void)event;
    if (error) atomic_fetch_add(&faults, 1);
    return true;
}
static box_client *make_owner(void) {
    atomic_store(&replies, 0);
    atomic_store(&flags_reply, 0);
    atomic_store(&retains, 0);
    atomic_store(&releases, 0);
    atomic_store(&faults, 0);
    sync_calls = fail_sync_call = 0;
    unsubscribe_result = delete_result = ES_RETURN_SUCCESS;
    box_client *owner = calloc(1, sizeof(*owner));
    assert(owner);
    owner->callback = permit;
    owner->work = dispatch_queue_create("box.review.faults", DISPATCH_QUEUE_SERIAL);
    owner->jobs = dispatch_group_create();
    assert(pthread_mutex_init(&owner->processes_lock, NULL) == 0);
    return owner;
}
static void dispose(box_client *owner) {
    while (owner->processes) {
        box_process *next = owner->processes->next;
        free(owner->processes);
        owner->processes = next;
    }
    dispatch_release(owner->work);
    dispatch_release(owner->jobs);
    pthread_mutex_destroy(&owner->processes_lock);
    free(owner);
}
static void request_case(const char *name, size_t queued, bool expired) {
    box_client *owner = make_owner();
    atomic_store(&owner->queued, queued);
    const char *path = "/private/tmp/box-fault-probe";
    es_file_t file = {0};
    file.path.data = path;
    file.path.length = strlen(path);
    file.stat.st_dev = 1;
    file.stat.st_ino = 2;
    es_process_t process = {0};
    process.audit_token.val[5] = 1000001;
    process.audit_token.val[7] = 1;
    es_message_t message = {0};
    message.version = 4;
    message.process = &process;
    message.action_type = ES_ACTION_TYPE_AUTH;
    message.event_type = ES_EVENT_TYPE_AUTH_OPEN;
    message.event.open.file = &file;
    message.event.open.fflag = 1;
    message.deadline = expired ? 0 : UINT64_MAX;
    receive(owner, NULL, &message);
    assert(dispatch_group_wait(owner->jobs,
        dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) == 0);
    bool overflow = queued >= 1024;
    assert(atomic_load(&replies) == 1);
    assert(atomic_load(&flags_reply) == ((!overflow && !expired) ? 1u : 0u));
    assert(atomic_load(&owner->queued) == queued);
    assert(atomic_load(&retains) == (overflow ? 0u : 1u));
    assert(atomic_load(&releases) == atomic_load(&retains));
    assert(atomic_load(&faults) == (overflow ? 1u : 0u));
    printf("PASS %s\n", name);
    dispose(owner);
}
static void shutdown_case(const char *name, unsigned sync_failure,
                          es_return_t unsubscribe, es_return_t deletion, int expected) {
    box_client *owner = make_owner();
    fail_sync_call = sync_failure;
    unsubscribe_result = unsubscribe;
    delete_result = deletion;
    assert(box_es_stop(owner) == expected);
    if (expected) dispose(owner);
    printf("PASS %s\n", name);
}
static void device_identity(void) {
    const int32_t devices[] = {0, 1, INT32_MAX, INT32_MIN, -1};
    for (size_t i = 0; i < sizeof(devices) / sizeof(devices[0]); i++) {
        es_file_t file = {0};
        file.path.data = "/file";
        file.path.length = 5;
        file.stat.st_dev = devices[i];
        file.stat.st_ino = 7;
        uint64_t expected = (uint64_t)(int64_t)devices[i];
        box_event event = {0};
        assert(source_file(&event, &file, BOX_FILE));
        assert(event.source_dev == expected);
        assert(executable_is(&file, expected, 7));
        assert(!executable_is(&file, expected, 8));
        es_message_t message = {0};
        message.event_type = ES_EVENT_TYPE_AUTH_RENAME;
        message.event.rename.source = &file;
        message.event.rename.destination_type = ES_DESTINATION_TYPE_EXISTING_FILE;
        message.event.rename.destination.existing_file = &file;
        assert(decode(&message, &event));
        assert(event.destination_dev == expected);
        message.event.rename.destination_type = ES_DESTINATION_TYPE_NEW_PATH;
        message.event.rename.destination.new_path.dir = &file;
        message.event.rename.destination.new_path.filename.data = "child";
        message.event.rename.destination.new_path.filename.length = 5;
        assert(decode(&message, &event));
        assert(event.destination_dev == expected);
    }
    puts("PASS signed device identities in source, destinations, and executable checks");
}

static void path_tokens(void) {
    char out[BOX_PATH_CAPACITY];
    es_file_t directory = {0};
    directory.path = (es_string_token_t){.data = "/dir", .length = 4};
    const es_string_token_t invalid[] = {
        {.data = NULL, .length = 1},
        {.data = "", .length = 0},
        {.data = ".", .length = 1},
        {.data = "..", .length = 2},
        {.data = "a/b", .length = 3},
        {.data = "a\0b", .length = 3},
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        assert(!new_path(out, &directory, invalid[i]));
    }
    es_string_token_t leaf = {.data = "file", .length = 4};
    assert(new_path(out, &directory, leaf));
    assert(strcmp(out, "/dir/file") == 0);
    directory.path_truncated = true;
    assert(!new_path(out, &directory, leaf));
    directory.path_truncated = false;
    directory.path = (es_string_token_t){.data = "/", .length = 1};
    assert(new_path(out, &directory, leaf));
    assert(strcmp(out, "/file") == 0);

    char name[BOX_PATH_CAPACITY];
    memset(name, 'x', sizeof(name));
    leaf = (es_string_token_t){.data = name, .length = BOX_PATH_CAPACITY - 2};
    assert(new_path(out, &directory, leaf));
    assert(strlen(out) == BOX_PATH_CAPACITY - 1);
    leaf.length++;
    assert(!new_path(out, &directory, leaf));

    size_t page_size = (size_t)getpagesize();
    void *unreadable = mmap(NULL, page_size, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    assert(unreadable != MAP_FAILED);
    leaf = (es_string_token_t){.data = unreadable, .length = BOX_PATH_CAPACITY};
    assert(!copy_token(out, leaf));
    assert(!new_path(out, &directory, leaf));
    leaf.length = SIZE_MAX;
    assert(!new_path(out, &directory, leaf));
    assert(munmap(unreadable, page_size) == 0);
    puts("PASS path token validation and bounds before reading filename bytes");
}

static void permission_event(void) {
    bool subscribed = false;
    for (size_t i = 0; i < sizeof(subscriptions) / sizeof(*subscriptions); ++i)
        subscribed |= subscriptions[i] == ES_EVENT_TYPE_AUTH_SETMODE;
    assert(subscribed);
    es_file_t file = {0};
    file.path.data = "/target";
    file.path.length = 7;
    file.stat.st_dev = 3;
    file.stat.st_ino = 7;
    file.stat.st_mode = S_IFREG | 0640;
    es_message_t message = {0};
    message.action_type = ES_ACTION_TYPE_AUTH;
    message.event_type = ES_EVENT_TYPE_AUTH_SETMODE;
    message.event.setmode.target = &file;
    message.event.setmode.mode = 0500;
    box_event event = {0};
    assert(decode(&message, &event));
    assert(event.kind == BOX_SETMODE);
    assert(event.mode == (S_IFREG | 0640));
    assert(event.source_identity == BOX_FILE);
    assert(event.source_dev == 3 && event.source_ino == 7);
    assert(strcmp(event.path, "/target") == 0);
    file.path_truncated = true;
    assert(!decode(&message, &event));
    message.event.setmode.target = NULL;
    assert(!decode(&message, &event));
    puts("PASS permission event preserves target type, path, and identity");
}

int main(void) {
    path_tokens();
    device_identity();
    permission_event();
    request_case("queue below limit allows", 1023, false);
    request_case("queue at limit denies and reports failure", 1024, false);
    request_case("expired deadline denies despite policy permit", 0, true);
    shutdown_case("shutdown first sync failure", 1, ES_RETURN_SUCCESS, ES_RETURN_SUCCESS, 1);
    shutdown_case("shutdown unsubscribe failure", 0, ES_RETURN_ERROR, ES_RETURN_SUCCESS, 4);
    shutdown_case("shutdown final sync failure", 2, ES_RETURN_SUCCESS, ES_RETURN_SUCCESS, 5);
    shutdown_case("shutdown delete failure", 0, ES_RETURN_SUCCESS, ES_RETURN_ERROR, 6);
    shutdown_case("shutdown success", 0, ES_RETURN_SUCCESS, ES_RETURN_SUCCESS, 0);
    return 0;
}

#else
int main(void) {
    puts("SKIP: bridge checks require the macOS 27 SDK");
    return 77;
}
#endif
