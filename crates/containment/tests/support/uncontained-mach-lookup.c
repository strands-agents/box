/* The standalone control for the Mach-lookup measurement.
 *
 * A Mach lookup that a contained process refuses proves nothing on its own: an absent service and
 * a refused one both return a non-zero code. This program does the same lookup outside any box.
 * `no_mach_service_answers_inside_the_box` runs the same control through
 * `containment-test-probe --uncontained`, so this file is for a lookup by hand.
 *
 *   cc -o /tmp/mach-lookup uncontained-mach-lookup.c
 *   /tmp/mach-lookup com.apple.DiskArbitration.diskarbitrationd
 *
 * Code 0 with a non-zero port means the service answers this user. 1100 is BOOTSTRAP_NOT_PRIVILEGED
 * and 1102 is BOOTSTRAP_UNKNOWN_SERVICE.
 */
#include <servers/bootstrap.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <mach-service-name>...\n", argv[0]);
        return 2;
    }
    for (int i = 1; i < argc; i++) {
        mach_port_t port = 0;
        kern_return_t result = bootstrap_look_up(bootstrap_port, argv[i], &port);
        printf("%-45s rc=%d port=%u\n", argv[i], result, port);
    }
    return 0;
}
