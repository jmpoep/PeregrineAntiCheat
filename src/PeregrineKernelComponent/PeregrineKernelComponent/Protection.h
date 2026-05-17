#pragma once
#include <fltKernel.h>

// Set a process to Protected Process Light (PPL) status
NTSTATUS ProtectionSetProcessPPL(_In_ HANDLE ProcessId);
