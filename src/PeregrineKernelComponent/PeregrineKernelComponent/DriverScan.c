#include "DriverScan.h"
#include "Coms.h"
#include <ntstrsafe.h>

// ZwQuerySystemInformation definitions
typedef enum _SYSTEM_INFORMATION_CLASS_EX {
    SystemModuleInformationEx = 11
} SYSTEM_INFORMATION_CLASS_EX;

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
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
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

// Known cheat/exploit driver filenames (lowercase, filename only)
static const char* g_DriverBlacklist[] = {
    "dbk64.sys",        // Cheat Engine
    "dbk32.sys",        // Cheat Engine 32-bit
    "kdmapper.sys",     // manual mapper
    "capcom.sys",       // exploit driver
    "cpuz141.sys",      // CPU-Z exploit
    "iqvw64e.sys",      // Intel NAL exploit
    "gdrv.sys",         // Gigabyte exploit
    "winring0.sys",     // WinRing0 exploit
    "winring0x64.sys",  // WinRing0 x64
    "asrdrv106.sys",    // ASRock exploit
    "ene.sys",          // ENE exploit
    "bsmi.sys",         // Biostar exploit
    "msio64.sys",       // MSI exploit
    "phymemx64.sys",    // physical memory exploit
    "rtkio64.sys",      // Realtek exploit
    "rzpnk.sys",        // Razer exploit
    "elbycdio.sys",     // ElbyCDIO exploit
    "nvoclock.sys",     // NvOclock exploit
    "winio64.sys",      // WinIo exploit
    "zemana.sys",       // Zemana anti-malware (sometimes abused)
};

#define BLACKLIST_COUNT (sizeof(g_DriverBlacklist) / sizeof(g_DriverBlacklist[0]))

// Case-insensitive comparison of ANSI strings
static BOOLEAN StrEqualNoCase(const char* a, const char* b) {
    while (*a && *b) {
        char ca = *a >= 'A' && *a <= 'Z' ? *a + 32 : *a;
        char cb = *b >= 'A' && *b <= 'Z' ? *b + 32 : *b;
        if (ca != cb) return FALSE;
        a++;
        b++;
    }
    return *a == *b;
}

static BOOLEAN IsBlacklisted(const char* fileName) {
    for (ULONG i = 0; i < BLACKLIST_COUNT; i++) {
        if (StrEqualNoCase(fileName, g_DriverBlacklist[i])) {
            return TRUE;
        }
    }
    return FALSE;
}

NTSTATUS DriverScanEnumerate(void) {
    ULONG needed = 0;
    NTSTATUS status;

    // First call to get required size
    status = ZwQuerySystemInformation(SystemModuleInformationEx, NULL, 0, &needed);
    if (status != STATUS_INFO_LENGTH_MISMATCH && !NT_SUCCESS(status)) {
        KdPrint(("Peregrine: DriverScan ZwQuerySystemInformation size query failed 0x%X\n", status));
        return status;
    }

    // Allocate with some extra room
    needed += 4096;
    PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePool2(POOL_FLAG_NON_PAGED, needed, 'nScD');
    if (!modules) {
        KdPrint(("Peregrine: DriverScan allocation failed\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQuerySystemInformation(SystemModuleInformationEx, modules, needed, &needed);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Peregrine: DriverScan ZwQuerySystemInformation failed 0x%X\n", status));
        ExFreePoolWithTag(modules, 'nScD');
        return status;
    }

    ULONG blacklistedCount = 0;
    ULONG totalCount = modules->NumberOfModules;

    for (ULONG i = 0; i < totalCount; i++) {
        PRTL_PROCESS_MODULE_INFORMATION mod = &modules->Modules[i];

        // Get just the filename from the full path
        const char* fullPath = (const char*)mod->FullPathName;
        const char* fileName = fullPath + mod->OffsetToFileName;

        BOOLEAN blacklisted = IsBlacklisted(fileName);
        if (blacklisted) {
            blacklistedCount++;
        }

        // Only send individual entries for blacklisted drivers to avoid flooding
        if (blacklisted) {
            CHAR json[COMS_MAX_MESSAGE_SIZE];
            RtlStringCchPrintfA(
                json,
                ARRAYSIZE(json),
                "{ \"event\": \"driver_scan\", \"driver\": \"%s\", \"path\": \"%s\", \"base\": \"0x%p\", \"size\": %lu, \"blacklisted\": true }",
                fileName,
                fullPath,
                mod->ImageBase,
                mod->ImageSize);
            ComsSendToUser(json, (ULONG)strlen(json));
        }
    }

    // Send summary
    CHAR json[COMS_MAX_MESSAGE_SIZE];
    RtlStringCchPrintfA(
        json,
        ARRAYSIZE(json),
        "{ \"event\": \"driver_scan_complete\", \"total_drivers\": %lu, \"blacklisted_count\": %lu }",
        totalCount,
        blacklistedCount);
    ComsSendToUser(json, (ULONG)strlen(json));

    ExFreePoolWithTag(modules, 'nScD');
    KdPrint(("Peregrine: DriverScan complete - %lu drivers, %lu blacklisted\n", totalCount, blacklistedCount));
    return STATUS_SUCCESS;
}
