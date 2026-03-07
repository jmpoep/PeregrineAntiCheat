#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// Writes a raw JSON string to the named pipe; best-effort and may silently fail.
void ipc_write_json(const char* json);

// Generic event logger: formats key-value pairs as JSON and sends via IPC.
// Usage: ipc_log_event("ReadProcessMemory", "callerPID=%lu targetPID=%lu address=0x%llX size=%llu", ...);
void ipc_log_event(const char* event, const char* fmt, ...);

#ifdef __cplusplus
}
#endif
