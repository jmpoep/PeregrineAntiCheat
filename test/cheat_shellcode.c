#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

/* Shellcode injection: alloc RWX, write shellcode, create remote thread.
   Triggers: VirtualAllocEx hook, VirtualProtectEx hook, WriteProcessMemory hook,
   CreateRemoteThread hook, Thread RIP scan (suspicious - outside modules),
   ETW-TI (ALLOCVM_REMOTE, PROTECTVM_REMOTE, WRITEVM_REMOTE)

   IMPORTANT: Do NOT call kernel32 APIs (e.g. Sleep) from private RWX memory.
   Processes built with CFG (/guard:cf, VS default) FastFail the whole process
   on an indirect call whose origin is not a valid image. That looks like
   "cheat_shellcode killed the game" without pressing Enter. */

/* x64: infinite loop, RIP always inside this private page.
   pause reduces CPU burn a bit; no external calls = CFG-safe. */
static const unsigned char shellcode[] = {
    0xF3, 0x90,                         /* pause              */
    0xEB, 0xFC,                         /* jmp $-2 (to pause) */
};

int main(int argc, char* argv[])
{
    if (argc < 2) {
        printf("Usage: cheat_shellcode.exe <PID>\n");
        return 1;
    }

    DWORD pid = (DWORD)atoi(argv[1]);
    printf("[SHELLCODE] Target PID = %lu\n", pid);

    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_READ | PROCESS_VM_WRITE | SYNCHRONIZE,
        FALSE, pid);

    if (!hProc) {
        printf("[SHELLCODE] OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }
    printf("[SHELLCODE] Handle acquired\n");

    LPVOID remoteMem = VirtualAllocEx(hProc, NULL, 4096,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteMem) {
        printf("[SHELLCODE] VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hProc);
        return 1;
    }
    printf("[SHELLCODE] Allocated RW page at 0x%p\n", remoteMem);

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, remoteMem, shellcode, sizeof(shellcode), &written)) {
        printf("[SHELLCODE] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }
    printf("[SHELLCODE] Wrote %zu bytes of shellcode (CFG-safe spin loop)\n", written);

    DWORD oldProtect = 0;
    if (!VirtualProtectEx(hProc, remoteMem, 4096, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[SHELLCODE] VirtualProtectEx failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }
    printf("[SHELLCODE] Changed protection to RWX\n");

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);

    if (!hThread) {
        printf("[SHELLCODE] CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }
    printf("[SHELLCODE] Remote thread created at 0x%p\n", remoteMem);

    /* Detect immediate death (CFG FastFail, bad shellcode, etc.) */
    DWORD wait = WaitForSingleObject(hProc, 500);
    if (wait == WAIT_OBJECT_0) {
        DWORD code = 0;
        GetExitCodeProcess(hProc, &code);
        printf("[SHELLCODE] ERROR: target process exited within 500ms (code=%lu).\n", code);
        printf("[SHELLCODE] Likely CFG/crash — game is gone.\n");
        CloseHandle(hThread);
        CloseHandle(hProc);
        return 1;
    }

    printf("[SHELLCODE] Remote thread running at 0x%p (spin loop, no API calls)\n", remoteMem);
    printf("[SHELLCODE] Target still alive after 500ms.\n");
    printf("[SHELLCODE] Run 'Threads' in Peregrine — expect suspicious start/RIP at 0x%p\n", remoteMem);
    printf("[SHELLCODE] Press Enter to cleanup and exit.\n");
    getchar();

    VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return 0;
}
