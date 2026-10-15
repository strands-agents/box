/* Apple owns every message. Rust borrows this fixed record during each call. */
#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <mach/mach_time.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <libproc.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>

enum { BOX_OPEN = 1, BOX_CREATE, BOX_UNLINK, BOX_RENAME, BOX_TRUNCATE };
enum { BOX_AUTH = 1, BOX_NOTIFY, BOX_REPLY };
enum { BOX_FILE = 1, BOX_PARENT = 2 };
enum { BOX_PATH_CAPACITY = 4096 };

typedef struct {
    uint32_t kind, phase, flags, mode;
    uint64_t sequence, deadline;
    int32_t pid;
    uint32_t valid;
    uint64_t source_dev, source_ino, destination_dev, destination_ino;
    uint32_t source_identity, destination_identity, destination_exists, destination_mode, result;
    char path[BOX_PATH_CAPACITY], destination[BOX_PATH_CAPACITY];
} box_event;

typedef bool (*box_callback)(void *, const box_event *, int);
typedef struct box_process {
    audit_token_t token;
    bool mediated, root, registered, bootstrap;
    struct box_process *next;
} box_process;

typedef struct {
    es_client_t *client;
    void *context;
    box_callback callback;
    dispatch_queue_t work;
    dispatch_group_t jobs;
    pthread_mutex_t processes_lock;
    box_process *processes;
    uint64_t parent_dev, parent_ino, helper_dev, helper_ino;
    uint64_t sequence, delivered;
    bool has_sequence;
    _Atomic bool stopping, failed;
    _Atomic size_t queued;
} box_client;

size_t box_es_event_size(void) { return sizeof(box_event); }
size_t box_es_event_offset(size_t field) {
    const size_t offsets[] = {offsetof(box_event, kind), offsetof(box_event, phase), offsetof(box_event, flags), offsetof(box_event, mode), offsetof(box_event, sequence), offsetof(box_event, deadline), offsetof(box_event, pid), offsetof(box_event, valid), offsetof(box_event, source_dev), offsetof(box_event, source_ino), offsetof(box_event, destination_dev), offsetof(box_event, destination_ino), offsetof(box_event, source_identity), offsetof(box_event, destination_identity), offsetof(box_event, destination_exists), offsetof(box_event, destination_mode), offsetof(box_event, result), offsetof(box_event, path), offsetof(box_event, destination)};
    return field < sizeof(offsets) / sizeof(*offsets) ? offsets[field] : SIZE_MAX;
}
int box_es_stop(void *raw);

bool box_es_has_children(pid_t process) {
    pid_t child;
    return proc_listchildpids(process, &child, sizeof(child)) != 0;
}

#if defined(__MAC_27_0) && __MAC_OS_X_VERSION_MAX_ALLOWED >= __MAC_27_0

/* libproc omits availability metadata for this newer entry point. */
extern int proc_signal_with_audittoken(audit_token_t *, int) __attribute__((weak_import));

static bool copy_token(char *out, es_string_token_t token) {
    if (!token.data || token.length == 0 || token.length >= BOX_PATH_CAPACITY ||
        memchr(token.data, 0, token.length)) return false;
    memcpy(out, token.data, token.length);
    out[token.length] = 0;
    return true;
}

static bool file_path(char *out, const es_file_t *file) {
    return file && !file->path_truncated && copy_token(out, file->path);
}

static bool new_path(char *out, const es_file_t *directory, es_string_token_t leaf) {
    if (!file_path(out, directory) || !leaf.data || !leaf.length ||
        memchr(leaf.data, '/', leaf.length) || memchr(leaf.data, 0, leaf.length) ||
        (leaf.length == 1 && leaf.data[0] == '.') ||
        (leaf.length == 2 && memcmp(leaf.data, "..", 2) == 0)) return false;
    size_t length = strlen(out);
    size_t separator = length && out[length - 1] != '/' ? 1 : 0;
    if (leaf.length >= BOX_PATH_CAPACITY - length - separator) return false;
    if (separator) out[length++] = '/';
    memcpy(out + length, leaf.data, leaf.length);
    out[length + leaf.length] = 0;
    return true;
}

static bool source_file(box_event *out, const es_file_t *file, uint32_t identity) {
    if (!file) return false;
    out->source_dev = (uint32_t)file->stat.st_dev;
    out->source_ino = file->stat.st_ino;
    out->source_identity = identity;
    return file_path(out->path, file);
}

static bool decode(const es_message_t *message, box_event *out) {
    switch (message->event_type) {
        case ES_EVENT_TYPE_AUTH_OPEN:
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            out->kind = BOX_OPEN;
            out->flags = message->event.open.fflag;
            return source_file(out, message->event.open.file, BOX_FILE);
        case ES_EVENT_TYPE_AUTH_TRUNCATE:
        case ES_EVENT_TYPE_NOTIFY_TRUNCATE:
            out->kind = BOX_TRUNCATE;
            return source_file(out, message->event.truncate.target, BOX_FILE);
        case ES_EVENT_TYPE_AUTH_UNLINK:
        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            out->kind = BOX_UNLINK;
            out->mode = message->event.unlink.target->stat.st_mode;
            return source_file(out, message->event.unlink.target, BOX_FILE);
        case ES_EVENT_TYPE_AUTH_CREATE:
        case ES_EVENT_TYPE_NOTIFY_CREATE: {
            out->kind = BOX_CREATE;
            const es_event_create_t *event = &message->event.create;
            if (event->destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
                out->destination_exists = 1;
                out->mode = event->destination.existing_file->stat.st_mode;
                return source_file(out, event->destination.existing_file, BOX_FILE);
            }
            if (event->destination_type != ES_DESTINATION_TYPE_NEW_PATH) return false;
            out->mode = event->destination.new_path.mode;
            const es_file_t *parent = event->destination.new_path.dir;
            return source_file(out, parent, BOX_PARENT) &&
                new_path(out->path, parent, event->destination.new_path.filename);
        }
        case ES_EVENT_TYPE_AUTH_RENAME:
        case ES_EVENT_TYPE_NOTIFY_RENAME: {
            out->kind = BOX_RENAME;
            const es_event_rename_t *event = &message->event.rename;
            if (!source_file(out, event->source, BOX_FILE)) return false;
            if (event->destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
                out->destination_exists = 1;
                out->destination_dev = (uint32_t)event->destination.existing_file->stat.st_dev;
                out->destination_ino = event->destination.existing_file->stat.st_ino;
                out->destination_mode = event->destination.existing_file->stat.st_mode;
                out->destination_identity = BOX_FILE;
                return file_path(out->destination, event->destination.existing_file);
            }
            if (event->destination_type != ES_DESTINATION_TYPE_NEW_PATH) return false;
            const es_file_t *parent = event->destination.new_path.dir;
            out->destination_dev = (uint32_t)parent->stat.st_dev;
            out->destination_ino = parent->stat.st_ino;
            out->destination_identity = BOX_PARENT;
            return new_path(out->destination, parent, event->destination.new_path.filename);
        }
        default:
            return message->action_type == ES_ACTION_TYPE_NOTIFY;
    }
}

static void fail(box_client *owner, const box_event *event) {
    if (!atomic_exchange(&owner->failed, true)) owner->callback(owner->context, event, 4);
}

static bool same_process(audit_token_t a, audit_token_t b) {
    return audit_token_to_pid(a) == audit_token_to_pid(b) &&
        audit_token_to_pidversion(a) == audit_token_to_pidversion(b);
}

static bool executable_is(const es_file_t *file, uint64_t device, uint64_t inode) {
    return file && inode && (uint32_t)file->stat.st_dev == device && file->stat.st_ino == inode;
}

static bool process_mode(box_client *owner, const es_process_t *process, bool *bootstrap) {
    bool mediated = true;
    *bootstrap = process->ppid == getpid() &&
        executable_is(process->executable, owner->parent_dev, owner->parent_ino);
    pthread_mutex_lock(&owner->processes_lock);
    for (box_process *entry = owner->processes; entry; entry = entry->next)
        if (same_process(entry->token, process->audit_token)) {
            mediated = entry->mediated;
            *bootstrap = entry->bootstrap;
            break;
        }
    pthread_mutex_unlock(&owner->processes_lock);
    return mediated;
}

static void observe_process(box_client *owner, audit_token_t token, bool exited,
                            bool mediated, bool root, bool bootstrap, bool replaces) {
    pid_t pid = audit_token_to_pid(token);
    if (pid == getpid() || pid <= 0) return;
    pthread_mutex_lock(&owner->processes_lock);
    box_process **entry = &owner->processes;
    while (*entry && audit_token_to_pid((*entry)->token) != pid) entry = &(*entry)->next;
    if (exited) {
        if (*entry && same_process((*entry)->token, token)) {
            box_process *old = *entry;
            *entry = old->next;
            free(old);
        }
    } else {
        // Late messages from the previous executable must not replace its successor.
        if (*entry && !replaces && !same_process((*entry)->token, token)) {
            pthread_mutex_unlock(&owner->processes_lock);
            return;
        }
        if (!*entry) *entry = calloc(1, sizeof(**entry));
        if (*entry) {
            (*entry)->token = token;
            (*entry)->mediated = mediated;
            (*entry)->root = root;
            (*entry)->bootstrap = bootstrap;
        }
        if (!*entry || atomic_load(&owner->stopping)) {
            (void)proc_signal_with_audittoken(&token, SIGKILL);
        }
        if (!*entry) {
            box_event event = {0};
            fail(owner, &event);
        }
    }
    pthread_mutex_unlock(&owner->processes_lock);
}

static es_respond_result_t respond(es_client_t *client, const es_message_t *message,
                                   uint32_t flags, bool allow) {
    if (message->event_type == ES_EVENT_TYPE_AUTH_OPEN)
        return es_respond_flags_result(client, message, allow ? flags : 0, false);
    return es_respond_auth_result(client, message,
        allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY, false);
}

static void receive(box_client *owner, es_client_t *client, const es_message_t *message) {
    bool bootstrap = false;
    bool mediated = process_mode(owner, message->process, &bootstrap);
    bool root = message->process->ppid == getpid();
    observe_process(owner, message->process->audit_token,
                    message->event_type == ES_EVENT_TYPE_NOTIFY_EXIT, mediated, root, bootstrap, false);
    if (message->event_type == ES_EVENT_TYPE_NOTIFY_FORK) {
        bool trusted_parent = audit_token_to_pid(message->process->audit_token) == getpid();
        observe_process(owner, message->event.fork.child->audit_token, false, mediated, trusted_parent, trusted_parent, true);
    }
    if (message->event_type == ES_EVENT_TYPE_NOTIFY_EXEC)
        observe_process(owner, message->event.exec.target->audit_token, false, mediated, root, bootstrap, true);
    box_event event = {0};
    event.phase = message->action_type == ES_ACTION_TYPE_AUTH ? BOX_AUTH : BOX_NOTIFY;
    event.pid = audit_token_to_pid(message->process->audit_token);
    event.deadline = message->deadline;
    // Check every kernel message, including those that bypass Dogwood.
    bool consecutive = message->version >= 4 && (!owner->has_sequence ||
        (owner->sequence != UINT64_MAX && message->global_seq_num == owner->sequence + 1));
    owner->has_sequence = true;
    owner->sequence = message->version >= 4 ? message->global_seq_num : 0;
    if (!consecutive) fail(owner, &event);
    event.valid = message->version >= 4 && decode(message, &event);
    if (bootstrap && message->event_type == ES_EVENT_TYPE_NOTIFY_FORK) fail(owner, &event);
    if (atomic_load(&owner->stopping) || atomic_load(&owner->failed)) {
        if (event.phase == BOX_AUTH) (void)respond(client, message, event.flags, false);
        return;
    }
    if (message->event_type == ES_EVENT_TYPE_AUTH_EXEC) {
        bool allowed = true;
        if (bootstrap) {
            pthread_mutex_lock(&owner->processes_lock);
            allowed = false;
            for (box_process *entry = owner->processes; entry; entry = entry->next) {
                if (!same_process(entry->token, message->process->audit_token)) continue;
                if (entry->registered) {
                    entry->bootstrap = false;
                    allowed = true;
                } else {
                    allowed = executable_is(message->event.exec.target->executable, owner->helper_dev, owner->helper_ino);
                }
                break;
            }
            pthread_mutex_unlock(&owner->processes_lock);
        }
        if (respond(client, message, 0, allowed) != ES_RESPOND_RESULT_SUCCESS || !allowed) fail(owner, &event);
        return;
    }
    if (!mediated || bootstrap) {
        if (event.phase == BOX_AUTH) {
            uint32_t flags = message->event_type == ES_EVENT_TYPE_AUTH_OPEN ? message->event.open.fflag : 0;
            if (respond(client, message, flags, true) != ES_RESPOND_RESULT_SUCCESS) fail(owner, &event);
        }
        return;
    }
    // Rust checks the contiguous sequence of dispatched messages, not bypassed messages.
    event.sequence = ++owner->delivered;
    if (atomic_fetch_add(&owner->queued, 1) >= 1024) {
        atomic_fetch_sub(&owner->queued, 1);
        if (event.phase == BOX_AUTH) (void)respond(client, message, event.flags, false);
        fail(owner, &event);
        return;
    }
    es_retain_message(message);
    dispatch_group_async(owner->jobs, owner->work, ^{
        box_event delivered = event;
        if (atomic_load(&owner->stopping) || atomic_load(&owner->failed)) {
            if (delivered.phase == BOX_AUTH) (void)respond(client, message, delivered.flags, false);
        } else if (delivered.phase == BOX_NOTIFY) {
            owner->callback(owner->context, &delivered, 0);
        } else {
            bool allow = owner->callback(owner->context, &delivered, 0);
            if (mach_absolute_time() >= delivered.deadline || atomic_load(&owner->stopping) ||
                atomic_load(&owner->failed)) allow = false;
            es_respond_result_t result = respond(client, message, delivered.flags, allow);
            delivered.phase = BOX_REPLY;
            delivered.result = allow;
            owner->callback(owner->context, &delivered,
                            result == ES_RESPOND_RESULT_SUCCESS ? 0 : 1);
        }
        es_release_message(message);
        atomic_fetch_sub(&owner->queued, 1);
    });
}

static const es_event_type_t subscriptions[] = {
    ES_EVENT_TYPE_AUTH_OPEN, ES_EVENT_TYPE_AUTH_CREATE,
    ES_EVENT_TYPE_AUTH_UNLINK, ES_EVENT_TYPE_AUTH_RENAME, ES_EVENT_TYPE_AUTH_TRUNCATE,
    ES_EVENT_TYPE_AUTH_EXEC,
    ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CREATE,
    ES_EVENT_TYPE_NOTIFY_UNLINK, ES_EVENT_TYPE_NOTIFY_RENAME, ES_EVENT_TYPE_NOTIFY_TRUNCATE,
    ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_EXIT,
    ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_WRITE
};

API_AVAILABLE(macos(27.0))
static bool configure_mutes(es_client_t *client) {
    es_muted_paths_t *paths = NULL;
    if (es_muted_paths_events(client, &paths) != ES_RETURN_SUCCESS) return false;
    bool valid = true;
    for (size_t i = 0; i < paths->count && valid; ++i) {
        const es_muted_path_t *path = &paths->paths[i];
        es_event_type_t selected[sizeof(subscriptions) / sizeof(*subscriptions)];
        size_t count = 0;
        for (size_t j = 0; j < path->event_count; ++j)
            for (size_t k = 0; k < sizeof(subscriptions) / sizeof(*subscriptions); ++k)
                if (path->events[j] == subscriptions[k]) selected[count++] = subscriptions[k];
        char name[BOX_PATH_CAPACITY];
        if (count) valid = copy_token(name, path->path) &&
            es_unmute_path_events(client, name, path->type, selected, (uint32_t)count) == ES_RETURN_SUCCESS;
    }
    es_release_muted_paths(paths);
    paths = NULL;
    if (!valid || es_muted_paths_events(client, &paths) != ES_RETURN_SUCCESS) return false;
    for (size_t i = 0; i < paths->count; ++i)
        for (size_t j = 0; j < paths->paths[i].event_count; ++j)
            for (size_t k = 0; k < sizeof(subscriptions) / sizeof(*subscriptions); ++k)
                if (paths->paths[i].events[j] == subscriptions[k]) valid = false;
    es_release_muted_paths(paths);
    es_muted_processes_t *processes = NULL;
    if (es_muted_processes_events(client, &processes) != ES_RETURN_SUCCESS) return false;
    valid &= processes->count == 0;
    es_release_muted_processes(processes);
    return valid;
}

API_AVAILABLE(macos(27.0))
static bool synchronized(box_client *owner, dispatch_time_t deadline) {
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    dispatch_retain(done);
    es_return_t result = es_sync_client(owner->client, ^{
        dispatch_semaphore_signal(done);
        dispatch_release(done);
    });
    bool success = result == ES_RETURN_SUCCESS;
    if (success) success = dispatch_semaphore_wait(done, deadline) == 0;
    else dispatch_release(done);
    dispatch_release(done);
    return success;
}

bool box_es_set_process_mode(void *raw, pid_t pid, bool mediated) {
    if (__builtin_available(macOS 27.0, *)) {
        box_client *owner = raw;
        if (atomic_load(&owner->stopping) || atomic_load(&owner->failed) ||
            !synchronized(owner, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) return false;
        bool found = false;
        pthread_mutex_lock(&owner->processes_lock);
        for (box_process *entry = owner->processes; entry; entry = entry->next) {
            if (audit_token_to_pid(entry->token) == pid && entry->root && entry->bootstrap && !entry->registered) {
                entry->mediated = mediated;
                entry->registered = true;
                found = true;
                break;
            }
        }
        pthread_mutex_unlock(&owner->processes_lock);
        return found;
    }
    return false;
}

bool box_es_prepare_bootstrap(void *raw, uint64_t device, uint64_t inode) {
    box_client *owner = raw;
    pthread_mutex_lock(&owner->processes_lock);
    bool valid = inode && !atomic_load(&owner->stopping) && !atomic_load(&owner->failed) &&
        (!owner->helper_ino || (owner->helper_dev == device && owner->helper_ino == inode));
    if (valid) { owner->helper_dev = device; owner->helper_ino = inode; }
    pthread_mutex_unlock(&owner->processes_lock);
    return valid;
}

/* Negative errors belong to this bridge. Positive errors are es_new_client_result_t. */
void *box_es_start(void *context, box_callback callback, int *error, uint64_t parent_dev, uint64_t parent_ino) {
    *error = -1;
    if (__builtin_available(macOS 27.0, *)) {
        if (!proc_signal_with_audittoken) return NULL;
        box_client *owner = calloc(1, sizeof(*owner));
        if (!owner) { *error = -2; return NULL; }
        owner->context = context;
        owner->callback = callback;
        owner->parent_dev = parent_dev;
        owner->parent_ino = parent_ino;
        owner->work = dispatch_queue_create("box.native-filesystem-policy", DISPATCH_QUEUE_SERIAL);
        owner->jobs = dispatch_group_create();
        if (pthread_mutex_init(&owner->processes_lock, NULL)) abort();
        *error = es_new_descendants_client(&owner->client,
            ^(es_client_t *client, const es_message_t *message) { receive(owner, client, message); });
        if (*error == ES_NEW_CLIENT_RESULT_SUCCESS) {
            es_deadline_miss_mode_t mode;
            if (box_es_has_children(getpid())) *error = -7;
            else if (!configure_mutes(owner->client)) *error = -6;
            else if (es_set_deadline_miss_mode(owner->client, ES_DEADLINE_MISS_MODE_FAIL_CLOSED) != ES_RETURN_SUCCESS ||
                es_get_deadline_miss_mode(owner->client, &mode) != ES_RETURN_SUCCESS ||
                mode != ES_DEADLINE_MISS_MODE_FAIL_CLOSED) *error = -3;
            else {
                size_t expected = sizeof(subscriptions) / sizeof(subscriptions[0]);
                es_event_type_t *actual = NULL;
                size_t count = 0;
                bool valid = es_subscribe(owner->client, subscriptions, (uint32_t)expected) == ES_RETURN_SUCCESS &&
                    es_subscriptions(owner->client, &count, &actual) == ES_RETURN_SUCCESS && count == expected;
                for (size_t i = 0; valid && i < expected; ++i) {
                    bool found = false;
                    for (size_t j = 0; j < count; ++j) found |= subscriptions[i] == actual[j];
                    valid &= found;
                }
                free(actual);
                if (valid) { *error = 0; return owner; }
                *error = -4;
            }
            if (box_es_stop(owner) != 0) abort();
        } else {
            dispatch_release(owner->work);
            dispatch_release(owner->jobs);
            pthread_mutex_destroy(&owner->processes_lock);
            free(owner);
        }
    }
    return NULL;
}

int box_es_stop(void *raw) {
    if (__builtin_available(macOS 27.0, *)) {
        box_client *owner = raw;
        atomic_store(&owner->stopping, true);
        dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC);
        for (;;) {
            if (!synchronized(owner, deadline)) return 1;
            pthread_mutex_lock(&owner->processes_lock);
            bool empty = owner->processes == NULL;
            bool signaled = true;
            for (box_process *entry = owner->processes; entry; entry = entry->next) {
                int result = proc_signal_with_audittoken(&entry->token, SIGKILL);
                if (result != 0 && errno != ESRCH) signaled = false;
            }
            pthread_mutex_unlock(&owner->processes_lock);
            if (empty) break;
            if (!signaled || dispatch_time(DISPATCH_TIME_NOW, 0) >= deadline) return 2;
            usleep(1000);
        }
        if (dispatch_group_wait(owner->jobs, deadline) != 0) return 3;
        if (es_unsubscribe_all(owner->client) != ES_RETURN_SUCCESS) return 4;
        if (!synchronized(owner, deadline)) return 5;
        if (es_delete_client(owner->client) != ES_RETURN_SUCCESS) return 6;
        dispatch_release(owner->work);
        dispatch_release(owner->jobs);
        pthread_mutex_destroy(&owner->processes_lock);
        free(owner);
        return 0;
    }
    return 7;
}

#else
bool box_es_prepare_bootstrap(void *raw, uint64_t device, uint64_t inode) { (void)raw; (void)device; (void)inode; return false; }
bool box_es_set_process_mode(void *raw, pid_t pid, bool mediated) { (void)raw; (void)pid; (void)mediated; return false; }

void *box_es_start(void *context, box_callback callback, int *error, uint64_t parent_dev, uint64_t parent_ino) {
    (void)context;
    (void)callback;
    (void)parent_dev;
    (void)parent_ino;
    *error = -5;
    return NULL;
}

int box_es_stop(void *raw) {
    (void)raw;
    return 7;
}

#endif
