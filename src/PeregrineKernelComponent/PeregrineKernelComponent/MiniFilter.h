#pragma once
#include <fltKernel.h>

NTSTATUS MfInit(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);
VOID     MfCleanup(VOID);

NTSTATUS MfInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);

NTSTATUS MfUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
