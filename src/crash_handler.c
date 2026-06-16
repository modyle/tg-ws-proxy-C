#include "../include/crash_handler.h"
#include "../include/main.h"
#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdint.h>

#pragma comment(lib, "dbghelp.lib")

#define SNAPSHOT_PREVIEW 96

typedef struct crash_snapshot {
    char stage[128];
    char reason[512];
    char why[128];
    int exit_code;
    int last_service_rc;
    int ctrl_c_seen;
    int dumped;
    uintptr_t wsi_local_tcp;
    uintptr_t wsi_remote_ws;
    int connection_established;
    size_t tcp_to_ws_len;
    size_t ws_to_tcp_len;
    int rx_paused_tcp;
    int rx_paused_ws;
} crash_snapshot;

static crash_snapshot g_snapshot;
static CRITICAL_SECTION g_snapshot_lock;
static LONG g_lock_initialized = 0;

static void ensure_lock(void) {
    if (InterlockedCompareExchange(&g_lock_initialized, 1, 0) == 0) {
        InitializeCriticalSection(&g_snapshot_lock);
    }
}

static void snapshot_lock(void) {
    ensure_lock();
    EnterCriticalSection(&g_snapshot_lock);
}

static void snapshot_unlock(void) {
    LeaveCriticalSection(&g_snapshot_lock);
}

static void get_timestamp(char *buffer, size_t size) {
    time_t rawtime;
    struct tm *timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(buffer, size, "%Y-%m-%d_%H-%M-%S", timeinfo);
}

static void copy_text(char *dst, size_t dst_size, const char *src) {
    if (!dst || dst_size == 0) return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    strncpy(dst, src, dst_size - 1);
    dst[dst_size - 1] = '\0';
}

static void dump_current_state_to_file(FILE *crash_log, const char *title) {
    if (!crash_log) return;
    fprintf(crash_log, "==================================================\n");
    fprintf(crash_log, "!!! %s !!!\n", title ? title : "ABNORMAL TERMINATION");
    fprintf(crash_log, "==================================================\n");

    snapshot_lock();
    fprintf(crash_log, "Stage:           %s\n", g_snapshot.stage[0] ? g_snapshot.stage : "<unknown>");
    fprintf(crash_log, "Exit code:       %d\n", g_snapshot.exit_code);
    fprintf(crash_log, "Ctrl+C seen:     %d\n", g_snapshot.ctrl_c_seen);
    fprintf(crash_log, "WSS established: %d\n", g_snapshot.connection_established);
    fprintf(crash_log, "TCP to WS bytes: %zu\n", g_snapshot.tcp_to_ws_len);
    fprintf(crash_log, "WS to TCP bytes: %zu\n", g_snapshot.ws_to_tcp_len);
    snapshot_unlock();
}

static LONG WINAPI unhandled_exception_handler(EXCEPTION_POINTERS *ep) {
    char timestamp[32];
    char log_filename[256];
    FILE *crash_log = NULL;

    get_timestamp(timestamp, sizeof(timestamp));
    snprintf(log_filename, sizeof(log_filename), "crash-%s.log", timestamp);
    crash_log = fopen(log_filename, "w");
    if (!crash_log) {
        printf("FAILED TO CREATE CRASH LOG FILE.\n");
        return EXCEPTION_EXECUTE_HANDLER;
    }

    fprintf(crash_log, "==================================================\n");
    fprintf(crash_log, "!!! FATAL CRASH DETECTED !!!\n");
    fprintf(crash_log, "==================================================\n");
    fprintf(crash_log, "Timestamp:       %s\n", timestamp);
    fprintf(crash_log, "Exception Code:  0x%08X\n", ep->ExceptionRecord->ExceptionCode);
    fprintf(crash_log, "Fault Address:   %p\n", ep->ExceptionRecord->ExceptionAddress);

    dump_current_state_to_file(crash_log, "LAST KNOWN STATE");
    fclose(crash_log);

    printf("\n[CRASH] Обнаружена критическая ошибка! Подробный лог сохранен в %s\n", log_filename);
    return EXCEPTION_EXECUTE_HANDLER;
}

static BOOL WINAPI console_ctrl_handler(DWORD ctrl_type) {
    switch (ctrl_type) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
            crash_tracker_note_ctrl_c(1);
            crash_tracker_note_exit_code(0, "console ctrl-c");
            return TRUE;
        default:
            crash_tracker_note_ctrl_c(0);
            crash_tracker_note_exit_code((int)ctrl_type, "console control event");
            crash_tracker_dump_now("console control event");
            return FALSE;
    }
}

void init_crash_handler(void) {
    ensure_lock();
    SetUnhandledExceptionFilter(unhandled_exception_handler);
    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);
}

void crash_tracker_note_session(const struct bridge_session *session,
                                const char *stage,
                                const char *reason,
                                const uint8_t *data,
                                size_t data_len) {
    snapshot_lock();
    if (stage) copy_text(g_snapshot.stage, sizeof(g_snapshot.stage), stage);
    if (reason) copy_text(g_snapshot.reason, sizeof(g_snapshot.reason), reason);
    if (session) {
        g_snapshot.wsi_local_tcp = (uintptr_t)session->wsi_local_tcp;
        g_snapshot.wsi_remote_ws = (uintptr_t)session->wsi_remote_ws;
        g_snapshot.connection_established = session->connection_established;
        g_snapshot.tcp_to_ws_len = session->tcp_to_ws_len;
        g_snapshot.ws_to_tcp_len = session->ws_to_tcp_len;
        g_snapshot.rx_paused_tcp = session->rx_paused_tcp;
        g_snapshot.rx_paused_ws = session->rx_paused_ws;
    }
    snapshot_unlock();
}

void crash_tracker_note_exit_code(int code, const char *reason) {
    snapshot_lock();
    g_snapshot.exit_code = code;
    if (reason) copy_text(g_snapshot.why, sizeof(g_snapshot.why), reason);
    snapshot_unlock();
}

void crash_tracker_note_service_rc(int rc) {
    snapshot_lock();
    g_snapshot.last_service_rc = rc;
    snapshot_unlock();
}

void crash_tracker_note_ctrl_c(int is_ctrl_c) {
    snapshot_lock();
    g_snapshot.ctrl_c_seen = is_ctrl_c ? 1 : 0;
    snapshot_unlock();
}

int crash_tracker_should_stop(void) {
    int stop;
    snapshot_lock();
    stop = g_snapshot.ctrl_c_seen;
    snapshot_unlock();
    return stop;
}

void crash_tracker_dump_now(const char *why) {
    char timestamp[32];
    char log_filename[256];
    FILE *crash_log = NULL;

    snapshot_lock();
    if (g_snapshot.dumped) {
        snapshot_unlock();
        return;
    }
    g_snapshot.dumped = 1;
    if (why) copy_text(g_snapshot.why, sizeof(g_snapshot.why), why);
    snapshot_unlock();

    get_timestamp(timestamp, sizeof(timestamp));
    snprintf(log_filename, sizeof(log_filename), "crash-%s.log", timestamp);
    crash_log = fopen(log_filename, "w");
    if (!crash_log) return;

    dump_current_state_to_file(crash_log, "FATAL TERMINATION DETECTED");
    fclose(crash_log);
    printf("\n[CRASH] Подробный лог сохранен в %s\n", log_filename);
}