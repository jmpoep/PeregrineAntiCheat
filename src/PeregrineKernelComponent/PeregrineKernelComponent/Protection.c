#include "Protection.h"

// Declare PsLookupProcessByProcessId (documented kernel function)
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS *Process
);

// PS_PROTECTION structure (undocumented)
typedef struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type : 3;
            UCHAR Audit : 1;
            UCHAR Signer : 4;
        } Flags;
    } u;
} PS_PROTECTION, *PPS_PROTECTION;

// Protection levels
#define PsProtectedTypeProtectedLight   1
#define PsProtectedSignerAntimalware    6

// Offset to PS_PROTECTION in EPROCESS (varies by Windows version)
// For Windows 10/11 x64, typically around 0x87A
// This will need adjustment based on your Windows version
static ULONG g_ProtectionOffset = 0;

// Scan PsIsProtectedProcess for the EPROCESS displacement operand.
// The function reads EPROCESS.Protection with one of these instruction forms:
//   movzx eax, byte ptr [rcx+disp32]  ->  0F B6 81 xx xx xx xx
//   mov   al,  byte ptr [rcx+disp32]  ->  8A 81 xx xx xx xx
//   movzx eax, byte ptr [rcx+disp8]   ->  0F B6 41 xx
//   mov   al,  byte ptr [rcx+disp8]   ->  8A 41 xx
static NTSTATUS FindProtectionOffsetByScan(void) {
    UNICODE_STRING funcName;
    RtlInitUnicodeString(&funcName, L"PsIsProtectedProcess");
    PUCHAR func = (PUCHAR)MmGetSystemRoutineAddress(&funcName);
    if (!func) return STATUS_NOT_FOUND;

    for (ULONG i = 0; i < 32; i++) {
        // movzx eax, byte ptr [rcx+disp32]
        if (func[i] == 0x0F && func[i + 1] == 0xB6 && func[i + 2] == 0x81) {
            g_ProtectionOffset = *(PULONG)(func + i + 3);
            return STATUS_SUCCESS;
        }
        // mov al, byte ptr [rcx+disp32]
        if (func[i] == 0x8A && func[i + 1] == 0x81) {
            g_ProtectionOffset = *(PULONG)(func + i + 2);
            return STATUS_SUCCESS;
        }
        // movzx eax, byte ptr [rcx+disp8]
        if (func[i] == 0x0F && func[i + 1] == 0xB6 && func[i + 2] == 0x41) {
            g_ProtectionOffset = (ULONG)func[i + 3];
            return STATUS_SUCCESS;
        }
        // mov al, byte ptr [rcx+disp8]
        if (func[i] == 0x8A && func[i + 1] == 0x41) {
            g_ProtectionOffset = (ULONG)func[i + 2];
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}

// Fallback: map OS build number -> known offset
static NTSTATUS FindProtectionOffsetByVersion(void) {
    RTL_OSVERSIONINFOW ver = { .dwOSVersionInfoSize = sizeof(ver) };
    NTSTATUS status = RtlGetVersion(&ver);
    if (!NT_SUCCESS(status)) return status;

    ULONG build = ver.dwBuildNumber;

    if (build >= 26100)       g_ProtectionOffset = 0x5FA;  // Win11 24H2+
    else if (build >= 19041)  g_ProtectionOffset = 0x87A;  // Win10 2004 – Win11 23H2
    else if (build >= 14393)  g_ProtectionOffset = 0x6CA;  // Win10 1607 – 1909
    else if (build >= 10240)  g_ProtectionOffset = 0x6AA;  // Win10 1507
    else return STATUS_NOT_SUPPORTED;

    return STATUS_SUCCESS;
}

static NTSTATUS FindProtectionOffset(void) {
    NTSTATUS status = FindProtectionOffsetByScan();
    if (!NT_SUCCESS(status)) {
        KdPrint(("Peregrine: Byte scan failed, falling back to version table\n"));
        status = FindProtectionOffsetByVersion();
    }
    if (!NT_SUCCESS(status)) {
        KdPrint(("Peregrine: Could not resolve PS_PROTECTION offset\n"));
        return status;
    }
    KdPrint(("Peregrine: PS_PROTECTION offset = 0x%X\n", g_ProtectionOffset));
    return STATUS_SUCCESS;
}

NTSTATUS ProtectionSetProcessPPL(_In_ HANDLE ProcessId) {
    NTSTATUS status;
    PEPROCESS process = NULL;

    KdPrint(("Peregrine: ProtectionSetProcessPPL called for PID %lu\n", (ULONG)(ULONG_PTR)ProcessId));

    // Find offset if not initialized
    if (g_ProtectionOffset == 0) {
        status = FindProtectionOffset();
        if (!NT_SUCCESS(status)) {
            KdPrint(("Peregrine: Failed to find protection offset\n"));
            return status;
        }
    }

    // Get EPROCESS structure for the target process
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Peregrine: PsLookupProcessByProcessId failed for PID %lu: 0x%X\n",
                 (ULONG)(ULONG_PTR)ProcessId, status));
        return status;
    }

    // Calculate pointer to PS_PROTECTION field
    PPS_PROTECTION protection = (PPS_PROTECTION)((PUCHAR)process + g_ProtectionOffset);

    // Set protection level to PPL with Antimalware signer
    PS_PROTECTION newProtection = { 0 };
    newProtection.u.Flags.Type = PsProtectedTypeProtectedLight;
    newProtection.u.Flags.Signer = PsProtectedSignerAntimalware;
    newProtection.u.Flags.Audit = 0;

    // Apply protection
    __try {
        protection->u.Level = newProtection.u.Level;
        KdPrint(("Peregrine: Set PID %lu to PPL (Type=%d, Signer=%d)\n",
                 (ULONG)(ULONG_PTR)ProcessId,
                 (int)newProtection.u.Flags.Type,
                 (int)newProtection.u.Flags.Signer));
        status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        KdPrint(("Peregrine: Exception while setting PPL for PID %lu\n",
                 (ULONG)(ULONG_PTR)ProcessId));
        status = STATUS_ACCESS_VIOLATION;
    }

    // Dereference the process object
    ObDereferenceObject(process);

    return status;
}
