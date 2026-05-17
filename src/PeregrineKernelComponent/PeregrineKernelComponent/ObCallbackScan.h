#pragma once
#include <fltKernel.h>

// Enumerate all ObRegisterCallbacks entries on PsProcessType and PsThreadType.
// Reports each callback's altitude, pre/post function addresses, and owning driver to userland.
NTSTATUS ObCallbackScanEnumerate(void);

// Resolve a kernel address to the name of the driver that owns it.
// Returns FALSE if not found. NameBuf must be at least NameBufSize bytes.
BOOLEAN ObCallbackScanResolveDriver(PVOID Address, char* NameBuf, ULONG NameBufSize);
