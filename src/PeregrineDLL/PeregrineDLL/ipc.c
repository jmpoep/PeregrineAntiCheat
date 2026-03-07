// Simple IPC helper for sending JSON events to the named pipe listener.
#include <stdio.h>
#include "ipc.h"
#include <string.h>
#include <stdarg.h>
#include <windows.h>

#define IPC_PIPE_NAMEA "\\\\.\\pipe\\peregrine_ipc"

static void DebugLog(const char* format, ...) {
    char buf[512];
    va_list args;
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    OutputDebugStringA(buf);
}

static ULONGLONG ptr_to_ull(const void* p) {
    return (ULONGLONG)(ULONG_PTR)p;
}

void ipc_write_json(const char* json) {
    if (!json) return;

    if (!WaitNamedPipeA(IPC_PIPE_NAMEA, 500)) {
        DebugLog("[IPC] Pipe not available (err=%lu)\n", GetLastError());
        return;
    }

    HANDLE h = CreateFileA(
        IPC_PIPE_NAMEA,
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (h == INVALID_HANDLE_VALUE) {
        DebugLog("[IPC] CreateFile failed: %lu\n", GetLastError());
        return;
    }

    DWORD len = (DWORD)strlen(json);
    DWORD written = 0;
    if (!WriteFile(h, json, len, &written, NULL)) {
        DebugLog("[IPC] WriteFile failed: %lu\n", GetLastError());
    }
    CloseHandle(h);
}

void ipc_log_event(const char* event, const char* fmt, ...) {
    char params[768];
    va_list args;
    va_start(args, fmt);
    vsnprintf(params, sizeof(params), fmt, args);
    va_end(args);

    char buf[1024];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "{\"event\":\"%s\",%s}", event, params);

    ipc_write_json(buf);
}
