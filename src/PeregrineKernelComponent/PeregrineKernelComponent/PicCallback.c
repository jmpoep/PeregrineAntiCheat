#include "PicCallback.h"
#include "Coms.h"
#include <ntstrsafe.h>

/* Undocumented info class for NtSetInformationProcess */
#define ProcessInstrumentationCallback 40

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION {
    ULONG  Version;
    ULONG  Reserved;
    PVOID  Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

NTSYSAPI NTSTATUS NTAPI ZwSetInformationProcess(
    _In_ HANDLE ProcessHandle, _In_ ULONG ProcessInformationClass,
    _In_ PVOID ProcessInformation, _In_ ULONG ProcessInformationLength);

/*
 * Ring buffer layout (1 page = 4096 bytes):
 *   offset 0: WriteIndex (u32, atomically incremented)
 *   offset 4: Entries[1023] (u32 syscall numbers)
 *
 * x64 shellcode (45 bytes + 8 byte buffer pointer):
 *   - Fires on every syscall return (r10=retaddr, rax=ntstatus)
 *   - Extracts syscall number from the mov eax,imm32 before syscall
 *   - Writes to ring buffer
 *   - Jumps to r10 to continue
 */
static const UCHAR g_PicShellcode[] = {
    0x50,                               /* push rax                  */
    0x51,                               /* push rcx                  */
    0x52,                               /* push rdx                  */
    0x49, 0x8D, 0x42, 0xF9,            /* lea  rax, [r10-7]         */
    0x80, 0x38, 0xB8,                   /* cmp  byte [rax], 0xB8     */
    0x75, 0x1B,                         /* jne  .done (+27)          */
    0x8B, 0x48, 0x01,                   /* mov  ecx, [rax+1]  ;nr   */
    0x48, 0x8D, 0x15, 0x17,0,0,0,      /* lea  rdx, [rip+23] ;ptr  */
    0x48, 0x8B, 0x12,                   /* mov  rdx, [rdx]          */
    0x8B, 0x02,                         /* mov  eax, [rdx]    ;idx  */
    0x25, 0xFF, 0x03, 0x00, 0x00,       /* and  eax, 0x3FF          */
    0x89, 0x4C, 0x82, 0x04,            /* mov  [rdx+rax*4+4], ecx  */
    0xF0, 0xFF, 0x02,                   /* lock inc dword [rdx]     */
    0x5A,                               /* pop  rdx                  */
    0x59,                               /* pop  rcx                  */
    0x58,                               /* pop  rax                  */
    0x41, 0xFF, 0xE2,                   /* jmp  r10                  */
    /* buf_ptr (8 bytes, patched at runtime): */
    0,0,0,0,0,0,0,0
};
#define PIC_SC_SIZE     sizeof(g_PicShellcode)
#define PIC_BUFPTR_OFF  45
#define PIC_BUF_SIZE    4096
#define PIC_POOL_TAG    'ciPp'

NTSTATUS PicSet(_In_ HANDLE ProcessId)
{
    NTSTATUS status;
    PEPROCESS proc = NULL;
    KAPC_STATE apcSt;
    PVOID scAlloc = NULL, bufAlloc = NULL;
    SIZE_T scSize = 0, bufSize = 0;
    HANDLE hProc = NULL;

    status = PsLookupProcessByProcessId(ProcessId, &proc);
    if (!NT_SUCCESS(status)) return status;

    /* Get a kernel handle for ZwSetInformationProcess */
    status = ObOpenObjectByPointer(proc, OBJ_KERNEL_HANDLE, NULL,
        PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &hProc);
    if (!NT_SUCCESS(status)) { ObDereferenceObject(proc); return status; }

    /* Attach to target process to allocate memory */
    KeStackAttachProcess(proc, &apcSt);

    /* Allocate shellcode page */
    scSize = PIC_SC_SIZE;
    status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &scAlloc, 0,
        &scSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status)) goto detach;

    /* Allocate ring buffer page */
    bufSize = PIC_BUF_SIZE;
    status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &bufAlloc, 0,
        &bufSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) goto detach;

    /* Write shellcode + patch buffer pointer */
    RtlCopyMemory(scAlloc, g_PicShellcode, PIC_SC_SIZE);
    *(PVOID*)((PUCHAR)scAlloc + PIC_BUFPTR_OFF) = bufAlloc;

    /* Zero the buffer */
    RtlZeroMemory(bufAlloc, PIC_BUF_SIZE);

    KeUnstackDetachProcess(&apcSt);

    /* Set instrumentation callback */
    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION info;
    info.Version = 0;
    info.Reserved = 0;
    info.Callback = scAlloc;

    status = ZwSetInformationProcess(hProc, ProcessInstrumentationCallback,
        &info, sizeof(info));

    if (NT_SUCCESS(status)) {
        CHAR json[COMS_MAX_MESSAGE_SIZE];
        RtlStringCchPrintfA(json, ARRAYSIZE(json),
            "{ \"event\": \"pic_set\", \"pid\": %lu, \"buffer\": %llu }",
            (ULONG)(ULONG_PTR)ProcessId, (ULONG64)(ULONG_PTR)bufAlloc);
        ComsSendToUser(json, (ULONG)strlen(json));
    }

    ZwClose(hProc);
    ObDereferenceObject(proc);
    return status;

detach:
    KeUnstackDetachProcess(&apcSt);
    ZwClose(hProc);
    ObDereferenceObject(proc);
    return status;
}

NTSTATUS PicRemove(_In_ HANDLE ProcessId)
{
    NTSTATUS status;
    PEPROCESS proc = NULL;
    HANDLE hProc = NULL;

    status = PsLookupProcessByProcessId(ProcessId, &proc);
    if (!NT_SUCCESS(status)) return status;

    status = ObOpenObjectByPointer(proc, OBJ_KERNEL_HANDLE, NULL,
        PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &hProc);
    if (!NT_SUCCESS(status)) { ObDereferenceObject(proc); return status; }

    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION info = { 0 };
    info.Callback = NULL;
    status = ZwSetInformationProcess(hProc, ProcessInstrumentationCallback,
        &info, sizeof(info));

    ZwClose(hProc);
    ObDereferenceObject(proc);
    return status;
}
