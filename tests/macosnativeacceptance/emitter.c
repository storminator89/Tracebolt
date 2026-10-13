/* Source-only evidence emitter. Native compilation/execution needs exact approval.
 * No host values enter messages. The sole stdout byte acknowledges three calls,
 * not persistence. The parent owns, terminates and reaps this foreground child.
 */
#include <os/log.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    static const char prefix[] = "org.tracebolt.nativeacceptance.";
    char subsystem[sizeof(prefix) + 32];
    if (argc != 2 || strlen(argv[1]) != 32) return 2;
    for (size_t i = 0; i < 32; ++i) {
        char c = argv[1][i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 2;
    }
    memcpy(subsystem, prefix, sizeof(prefix) - 1);
    memcpy(subsystem + sizeof(prefix) - 1, argv[1], 33);
    /* Independent last resort; normal parent cleanup happens much sooner. */
    alarm(89);
    os_log_t log = os_log_create(subsystem, "schema");
    if (log == NULL) return 3;
    os_log_with_type(log, OS_LOG_TYPE_DEFAULT, "%{public}s",
                     "tracebolt-native-public");
    os_log_with_type(log, OS_LOG_TYPE_DEFAULT, "%{public}s",
                     "tracebolt-native-special line1\nline2 \"quoted\" caf\xc3\xa9");
    os_log_with_type(log, OS_LOG_TYPE_DEFAULT,
                     "tracebolt-native-private %{public}s %{private}s",
                     "PUBLIC_CANARY", "PRIVATE_CANARY");
    if (write(STDOUT_FILENO, "R", 1) != 1) return 4;
    for (;;) pause();
}
