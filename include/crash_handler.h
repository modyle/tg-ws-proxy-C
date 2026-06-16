#ifndef CRASH_HANDLER_H
#define CRASH_HANDLER_H

#include <stddef.h>
#include <stdint.h>

struct bridge_session;

void init_crash_handler(void);

void crash_tracker_note_session(
    const struct bridge_session *session,
    const char *stage,
    const char *reason,
    const uint8_t *data,
    size_t data_len);

void crash_tracker_note_exit_code(int code, const char *reason);
void crash_tracker_note_service_rc(int rc);
void crash_tracker_note_ctrl_c(int is_ctrl_c);
int crash_tracker_should_stop(void);
void crash_tracker_dump_now(const char *why);

#endif