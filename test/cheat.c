#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

int main(int argc, char* argv[])
{
    if (argc < 3) {
        printf("Usage: cheat.exe <PID> <address_hex>\n");
        printf("Example: cheat.exe 1234 0x00000012345ABCD0\n");
        return 1;
    }

    DWORD pid = (DWORD)atoi(argv[1]);
    ULONGLONG addr = strtoull(argv[2], NULL, 16);

    printf("[CHEAT] Target PID = %lu\n", pid);
    printf("[CHEAT] Target address = 0x%llX\n", addr);

    HANDLE hProc = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
        FALSE, pid);

    if (!hProc) {
        printf("[CHEAT] OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }
    printf("[CHEAT] Handle acquired\n\n");

    int value = 0;
    SIZE_T bytes = 0;

    while (1) {
        /* Read current value */
        ReadProcessMemory(hProc, (LPCVOID)addr, &value, sizeof(value), &bytes);
        printf("[CHEAT] Read health = %d\n", value);

        /* Write new value (9999 = god mode) */
        int godmode = 9999;
        WriteProcessMemory(hProc, (LPVOID)addr, &godmode, sizeof(godmode), &bytes);
        printf("[CHEAT] Wrote health = %d\n\n", godmode);

        Sleep(5000);
    }

    CloseHandle(hProc);
    return 0;
}
