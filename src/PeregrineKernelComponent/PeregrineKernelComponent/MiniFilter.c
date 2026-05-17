#include "MiniFilter.h"
#include "Coms.h"
#include "AppState.h"
#include <ntstrsafe.h>

static PFLT_FILTER g_FilterHandle = NULL;

static LARGE_INTEGER g_LastBlockReport = { 0 };
static HANDLE        g_LastBlockPid = NULL;
#define BLOCK_REPORT_INTERVAL_MS 2000

static BOOLEAN ShouldReport(HANDLE Pid)
{
    LARGE_INTEGER now;
    KeQuerySystemTime(&now);
    LONGLONG diffMs = (now.QuadPart - g_LastBlockReport.QuadPart) / 10000;
    if (g_LastBlockPid == Pid && diffMs < BLOCK_REPORT_INTERVAL_MS)
        return FALSE;
    g_LastBlockReport = now;
    g_LastBlockPid = Pid;
    return TRUE;
}

static BOOLEAN EndsWithI(_In_ PCUNICODE_STRING Path, _In_ PCWSTR Suffix, _In_ USHORT SuffixLen)
{
    if (!Path || !Path->Buffer) return FALSE;
    USHORT pathChars = Path->Length / sizeof(WCHAR);
    if (pathChars < SuffixLen) return FALSE;
    for (USHORT i = 0; i < SuffixLen; i++) {
        WCHAR a = Path->Buffer[pathChars - SuffixLen + i];
        WCHAR b = Suffix[i];
        if (a >= L'A' && a <= L'Z') a += 32;
        if (b >= L'A' && b <= L'Z') b += 32;
        if (a != b) return FALSE;
    }
    return TRUE;
}

static BOOLEAN ContainsI(_In_ PCUNICODE_STRING Path, _In_ PCWSTR Sub, _In_ USHORT SubLen)
{
    if (!Path || !Path->Buffer) return FALSE;
    USHORT pathChars = Path->Length / sizeof(WCHAR);
    if (pathChars < SubLen) return FALSE;
    for (USHORT i = 0; i <= pathChars - SubLen; i++) {
        BOOLEAN ok = TRUE;
        for (USHORT j = 0; j < SubLen; j++) {
            WCHAR a = Path->Buffer[i + j];
            WCHAR b = Sub[j];
            if (a >= L'A' && a <= L'Z') a += 32;
            if (b >= L'A' && b <= L'Z') b += 32;
            if (a != b) { ok = FALSE; break; }
        }
        if (ok) return TRUE;
    }
    return FALSE;
}

static BOOLEAN IsProtectedFile(_In_ PCUNICODE_STRING Path)
{
    if (!ContainsI(Path, L"\\peregrine\\", 11)) return FALSE;

    if (EndsWithI(Path, L"peregrinekernelcomponent.sys", 27)) return TRUE;
    if (EndsWithI(Path, L"peregrinekernelcomponent.inf", 27)) return TRUE;
    if (EndsWithI(Path, L"peregrine64.dll", 15)) return TRUE;
    if (EndsWithI(Path, L"peregrine32.dll", 15)) return TRUE;
    if (EndsWithI(Path, L"peregrine-tauri.exe", 19)) return TRUE;

    return FALSE;
}

static BOOLEAN IsOurProcess(VOID)
{
    return StateIsPidProtected(PsGetCurrentProcessId());
}

/* ------------------------------------------------------------------ */
/*  Pre-Create: report write/delete access to protected AC files      */
/*  Only resolves filename if it's a write-like operation.            */
/* ------------------------------------------------------------------ */

#define WRITE_ACCESS_FLAGS (FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | \
    FILE_WRITE_EA | FILE_APPEND_DATA | DELETE | WRITE_DAC | WRITE_OWNER)

static FLT_PREOP_CALLBACK_STATUS FLTAPI
PreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(FltObjects);

    if (Data == NULL || Data->Iopb == NULL) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (IsOurProcess()) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    ACCESS_MASK desired = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    ULONG disposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;

    BOOLEAN isWrite = (desired & WRITE_ACCESS_FLAGS) != 0;
    BOOLEAN isCreateNew = (disposition == FILE_CREATE ||
                           disposition == FILE_OVERWRITE ||
                           disposition == FILE_OVERWRITE_IF ||
                           disposition == FILE_SUPERSEDE);

    if (!isWrite && !isCreateNew) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS st = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(st) || nameInfo == NULL) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    FltParseFileNameInformation(nameInfo);

    if (IsProtectedFile(&nameInfo->Name)) {
        HANDLE callerPid = PsGetCurrentProcessId();
        if (ShouldReport(callerPid)) {
            CHAR json[COMS_MAX_MESSAGE_SIZE];
            ANSI_STRING ansi = { 0 };
            if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansi, &nameInfo->Name, TRUE))) {
                RtlStringCchPrintfA(json, ARRAYSIZE(json),
                    "{ \"event\": \"file_access\", \"pid\": %lu, \"path\": \"%s\", \"op\": \"write\" }",
                    (ULONG)(ULONG_PTR)callerPid, ansi.Buffer);
                ComsSendToUser(json, (ULONG)strlen(json));
                RtlFreeAnsiString(&ansi);
            }
        }
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* ------------------------------------------------------------------ */
/*  Pre-SetInformation: report rename/delete of protected AC files    */
/* ------------------------------------------------------------------ */

static FLT_PREOP_CALLBACK_STATUS FLTAPI
PreSetInfo(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data == NULL || Data->Iopb == NULL || FltObjects == NULL)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (IsOurProcess()) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    ULONG infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    BOOLEAN isDel = (infoClass == FileDispositionInformation ||
                     infoClass == FileDispositionInformationEx ||
                     infoClass == FileRenameInformation ||
                     infoClass == FileRenameInformationEx);
    if (!isDel) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS st = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(st) || nameInfo == NULL) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    FltParseFileNameInformation(nameInfo);

    if (IsProtectedFile(&nameInfo->Name)) {
        HANDLE callerPid = PsGetCurrentProcessId();
        const CHAR* opName = (infoClass == FileRenameInformation ||
                              infoClass == FileRenameInformationEx) ? "rename" : "delete";

        if (ShouldReport(callerPid)) {
            CHAR json[COMS_MAX_MESSAGE_SIZE];
            ANSI_STRING ansi = { 0 };
            if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansi, &nameInfo->Name, TRUE))) {
                RtlStringCchPrintfA(json, ARRAYSIZE(json),
                    "{ \"event\": \"file_access\", \"pid\": %lu, \"path\": \"%s\", \"op\": \"%s\" }",
                    (ULONG)(ULONG_PTR)callerPid, ansi.Buffer, opName);
                ComsSendToUser(json, (ULONG)strlen(json));
                RtlFreeAnsiString(&ansi);
            }
        }
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* ------------------------------------------------------------------ */
/*  Registration — only PreCreate + PreSetInfo, no PreWrite           */
/* ------------------------------------------------------------------ */

static const FLT_OPERATION_REGISTRATION g_Callbacks[] = {
    { IRP_MJ_CREATE,          0, PreCreate,  NULL },
    { IRP_MJ_SET_INFORMATION, 0, PreSetInfo, NULL },
    { IRP_MJ_OPERATION_END }
};

NTSTATUS MfInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    return STATUS_SUCCESS;
}

NTSTATUS MfUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    MfCleanup();
    return STATUS_SUCCESS;
}

static const FLT_REGISTRATION g_FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    g_Callbacks,
    (PFLT_FILTER_UNLOAD_CALLBACK)MfUnload,
    MfInstanceSetup,
    NULL, NULL, NULL,
    NULL, NULL, NULL
};

NTSTATUS MfInit(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status = FltRegisterFilter(DriverObject, &g_FilterRegistration, &g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Peregrine: FltRegisterFilter failed 0x%X\n", status));
        return status;
    }

    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Peregrine: FltStartFiltering failed 0x%X\n", status));
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
        return status;
    }

    KdPrint(("Peregrine: Minifilter started\n"));
    return STATUS_SUCCESS;
}

VOID MfCleanup(VOID)
{
    if (g_FilterHandle != NULL) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
    }
}
