#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

/*
 * Call-stack evasion test: executes OpenProcess from unbacked RWX memory.
 * The Peregrine DLL hook will see a return address in MEM_PRIVATE+EXECUTE
 * and fire a CallstackAnomaly event.
 *
 * Usage:
 *   1. Start game.exe, note its PID
 *   2. Start this exe: cheat_callstack.exe <game_PID>
 *   3. Inject Peregrine DLL into THIS process
 *   4. Press Enter to trigger calls from shellcode
 *   5. Watch for CallstackAnomaly events in the Peregrine GUI
 */

/* x64 shellcode: calls OpenProcess(PROCESS_VM_READ, FALSE, <pid>)
 *
 *   mov ecx, 0x0010           ; dwDesiredAccess = PROCESS_VM_READ
 *   xor edx, edx              ; bInheritHandle = FALSE
 *   mov r8d, <pid>            ; dwProcessId (patched at +9)
 *   mov rax, <addr>           ; OpenProcess pointer (patched at +15)
 *   sub rsp, 0x28             ; shadow space
 *   call rax
 *   add rsp, 0x28
 *   ret
 */
static unsigned char shellcode_template[] = {
    0xB9, 0x10, 0x00, 0x00, 0x00,
    0x31, 0xD2,
    0x41, 0xB8, 0x00, 0x00, 0x00, 0x00,
    0x48, 0xB8,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x83, 0xEC, 0x28,
    0xFF, 0xD0,
    0x48, 0x83, 0xC4, 0x28,
    0xC3
};

#define PID_OFFSET   9
#define ADDR_OFFSET 15

int main(int argc, char* argv[])
{
    if (argc < 2) {
        printf("Usage: cheat_callstack.exe <target_PID>\n");
        printf("\nThis process must have the Peregrine DLL injected into it.\n");
        return 1;
    }

    DWORD targetPid = (DWORD)atoi(argv[1]);
    printf("[CALLSTACK] This process PID = %lu\n", GetCurrentProcessId());
    printf("[CALLSTACK] Target PID = %lu\n", targetPid);
    printf("[CALLSTACK] Waiting for DLL injection... Press Enter when ready.\n");
    getchar();

    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    FARPROC pOpenProcess = GetProcAddress(hK32, "OpenProcess");
    printf("[CALLSTACK] OpenProcess @ 0x%llX\n",
        (unsigned long long)(ULONG_PTR)pOpenProcess);

    void* execMem = VirtualAlloc(NULL, 4096,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execMem) {
        printf("[CALLSTACK] VirtualAlloc failed: %lu\n", GetLastError());
        return 1;
    }
    printf("[CALLSTACK] Allocated RWX page at 0x%p\n", execMem);

    unsigned char sc[sizeof(shellcode_template)];
    memcpy(sc, shellcode_template, sizeof(sc));
    *(DWORD*)(sc + PID_OFFSET) = targetPid;
    *(ULONGLONG*)(sc + ADDR_OFFSET) = (ULONGLONG)(ULONG_PTR)pOpenProcess;
    memcpy(execMem, sc, sizeof(sc));

    printf("[CALLSTACK] Calling OpenProcess from unbacked memory...\n");

    typedef HANDLE (*ShellFunc)(void);
    ShellFunc fn = (ShellFunc)execMem;

    for (int i = 0; i < 5; i++) {
        HANDLE h = fn();
        printf("[CALLSTACK] Call %d: OpenProcess returned 0x%p\n", i + 1, h);
        if (h) CloseHandle(h);
        Sleep(2000);
    }

    printf("[CALLSTACK] Done. Check Peregrine for CallstackAnomaly events.\n");
    printf("[CALLSTACK] Press Enter to exit.\n");
    getchar();

    VirtualFree(execMem, 0, MEM_RELEASE);
    return 0;
}
