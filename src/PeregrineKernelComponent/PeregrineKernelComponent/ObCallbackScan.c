#include "ObCallbackScan.h"
#include "Coms.h"
#include <ntstrsafe.h>

// ZwQuerySystemInformation for module resolution
typedef struct _RTL_PROCESS_MODULE_INFORMATION_OB {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION_OB, *PRTL_PROCESS_MODULE_INFORMATION_OB;

typedef struct _RTL_PROCESS_MODULES_OB {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION_OB Modules[1];
} RTL_PROCESS_MODULES_OB, *PRTL_PROCESS_MODULES_OB;

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

#define SystemModuleInfo 11

// Undocumented OBJECT_TYPE internal structure for ObCallback enumeration.
//
// OBJECT_TYPE contains a CallbackList (LIST_ENTRY) at a specific offset.
// Each entry in the list is an OB_CALLBACK_ENTRY_INTERNAL.
//
// These offsets are for Windows 10 2004+ / Windows 11 x64.
// OBJECT_TYPE->CallbackList offset: 0xC8
//
// OB_CALLBACK_ENTRY layout (undocumented, reverse-engineered):
//   +0x00  LIST_ENTRY          CallbackList
//   +0x10  OB_OPERATION        Operations
//   +0x14  BOOLEAN             Enabled  (at +0x14, may vary)
//   +0x18  OB_CALLBACK_ENTRY*  Registration  (pointer back)
//   +0x20  POBJECT_TYPE        ObjectType
//   +0x28  POB_PRE_OPERATION_CALLBACK  PreOperation
//   +0x30  POB_POST_OPERATION_CALLBACK PostOperation
//   +0x38  LARGE_INTEGER       RundownProtect (or lock)
//   +0x40  ...

#define OBJECT_TYPE_CALLBACK_LIST_OFFSET  0xC8

typedef struct _OB_CALLBACK_ENTRY_INTERNAL {
    LIST_ENTRY  CallbackList;       // +0x00
    ULONG       Operations;         // +0x10
    ULONG       Enabled;            // +0x14
    PVOID       Registration;       // +0x18
    POBJECT_TYPE ObjectType;        // +0x20
    PVOID       PreOperation;       // +0x28
    PVOID       PostOperation;      // +0x30
} OB_CALLBACK_ENTRY_INTERNAL, *POB_CALLBACK_ENTRY_INTERNAL;

static PRTL_PROCESS_MODULES_OB g_ModuleCache = NULL;

static NTSTATUS LoadModuleCache(void) {
    if (g_ModuleCache) {
        ExFreePoolWithTag(g_ModuleCache, 'bOcS');
        g_ModuleCache = NULL;
    }

    ULONG needed = 0;
    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInfo, NULL, 0, &needed);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        return status;
    }

    needed += 4096;
    g_ModuleCache = (PRTL_PROCESS_MODULES_OB)ExAllocatePool2(POOL_FLAG_NON_PAGED, needed, 'bOcS');
    if (!g_ModuleCache) return STATUS_INSUFFICIENT_RESOURCES;

    status = ZwQuerySystemInformation(SystemModuleInfo, g_ModuleCache, needed, &needed);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(g_ModuleCache, 'bOcS');
        g_ModuleCache = NULL;
    }
    return status;
}

static void FreeModuleCache(void) {
    if (g_ModuleCache) {
        ExFreePoolWithTag(g_ModuleCache, 'bOcS');
        g_ModuleCache = NULL;
    }
}

BOOLEAN ObCallbackScanResolveDriver(PVOID Address, char* NameBuf, ULONG NameBufSize) {
    if (!g_ModuleCache || !Address || !NameBuf || NameBufSize == 0) return FALSE;

    ULONG_PTR addr = (ULONG_PTR)Address;

    for (ULONG i = 0; i < g_ModuleCache->NumberOfModules; i++) {
        PRTL_PROCESS_MODULE_INFORMATION_OB mod = &g_ModuleCache->Modules[i];
        ULONG_PTR base = (ULONG_PTR)mod->ImageBase;
        if (addr >= base && addr < base + mod->ImageSize) {
            const char* fileName = (const char*)mod->FullPathName + mod->OffsetToFileName;
            RtlStringCchCopyA(NameBuf, NameBufSize, fileName);
            return TRUE;
        }
    }

    RtlStringCchCopyA(NameBuf, NameBufSize, "unknown");
    return FALSE;
}

static NTSTATUS ScanObjectTypeCallbacks(POBJECT_TYPE ObjectType, const char* typeName) {
    if (!ObjectType) return STATUS_INVALID_PARAMETER;

    // Get the CallbackList from OBJECT_TYPE
    PLIST_ENTRY callbackList = (PLIST_ENTRY)((PUCHAR)ObjectType + OBJECT_TYPE_CALLBACK_LIST_OFFSET);

    ULONG count = 0;

    __try {
        PLIST_ENTRY entry = callbackList->Flink;

        while (entry != callbackList) {
            POB_CALLBACK_ENTRY_INTERNAL cb = CONTAINING_RECORD(entry, OB_CALLBACK_ENTRY_INTERNAL, CallbackList);

            char preDriver[64] = { 0 };
            char postDriver[64] = { 0 };

            if (cb->PreOperation) {
                ObCallbackScanResolveDriver(cb->PreOperation, preDriver, sizeof(preDriver));
            }
            if (cb->PostOperation) {
                ObCallbackScanResolveDriver(cb->PostOperation, postDriver, sizeof(postDriver));
            }

            CHAR json[COMS_MAX_MESSAGE_SIZE];
            RtlStringCchPrintfA(
                json,
                ARRAYSIZE(json),
                "{ \"event\": \"ob_callback_found\", \"type\": \"%s\", "
                "\"pre_op\": \"0x%p\", \"pre_driver\": \"%s\", "
                "\"post_op\": \"0x%p\", \"post_driver\": \"%s\", "
                "\"operations\": \"0x%08X\", \"enabled\": %s }",
                typeName,
                cb->PreOperation,
                cb->PreOperation ? preDriver : "none",
                cb->PostOperation,
                cb->PostOperation ? postDriver : "none",
                cb->Operations,
                cb->Enabled ? "true" : "false");

            ComsSendToUser(json, (ULONG)strlen(json));
            count++;

            entry = entry->Flink;

            // Safety: don't walk more than 256 entries
            if (count > 256) break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        KdPrint(("Peregrine: Exception while scanning %s callbacks\n", typeName));
        CHAR json[COMS_MAX_MESSAGE_SIZE];
        RtlStringCchPrintfA(
            json,
            ARRAYSIZE(json),
            "{ \"event\": \"ob_callback_error\", \"type\": \"%s\", \"error\": \"exception during scan\" }",
            typeName);
        ComsSendToUser(json, (ULONG)strlen(json));
    }

    return STATUS_SUCCESS;
}

NTSTATUS ObCallbackScanEnumerate(void) {
    NTSTATUS status;

    KdPrint(("Peregrine: ObCallbackScan starting\n"));

    // Load module list for address resolution
    status = LoadModuleCache();
    if (!NT_SUCCESS(status)) {
        KdPrint(("Peregrine: ObCallbackScan failed to load module cache 0x%X\n", status));
        // Continue anyway, just won't resolve driver names
    }

    // Scan PsProcessType callbacks
    ScanObjectTypeCallbacks(*PsProcessType, "process");

    // Scan PsThreadType callbacks
    ScanObjectTypeCallbacks(*PsThreadType, "thread");

    // Send completion
    CHAR json[COMS_MAX_MESSAGE_SIZE];
    RtlStringCchPrintfA(
        json,
        ARRAYSIZE(json),
        "{ \"event\": \"ob_callback_scan_complete\" }");
    ComsSendToUser(json, (ULONG)strlen(json));

    FreeModuleCache();
    KdPrint(("Peregrine: ObCallbackScan complete\n"));
    return STATUS_SUCCESS;
}
