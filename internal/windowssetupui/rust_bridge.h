#ifndef TRACEBOLT_SETUP_RUST_BRIDGE_H
#define TRACEBOLT_SETUP_RUST_BRIDGE_H
#include <stdint.h>
#include <stddef.h>
#define TRACEBOLT_SETUP_ABI 1
typedef struct {
    uint32_t code, value;
    int32_t width, height;
    uint32_t dpi;
    uintptr_t owner;
} TraceboltSetupEvent;
_Static_assert(sizeof(TraceboltSetupEvent) == 32, "64-bit Setup event ABI required");
_Static_assert(offsetof(TraceboltSetupEvent, owner) == 24, "Setup event layout mismatch");
typedef intptr_t (*TraceboltSetupCallback)(uintptr_t, TraceboltSetupEvent*, uint8_t*, size_t);
extern intptr_t traceboltSetupEvent(uintptr_t, TraceboltSetupEvent*, uint8_t*, size_t);
extern int32_t tracebolt_setup_run(uintptr_t, TraceboltSetupCallback);
extern uint32_t tracebolt_setup_abi(void);
static inline int32_t tracebolt_setup_go_run(uintptr_t handle) {
    return tracebolt_setup_run(handle, traceboltSetupEvent);
}
#endif
