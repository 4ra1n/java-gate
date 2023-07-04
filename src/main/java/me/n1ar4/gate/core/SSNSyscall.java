package me.n1ar4.gate.core;

import me.n1ar4.gate.util.JNIUtil;

/**
 * SSN Syscall
 */
@SuppressWarnings("unused")
public class SSNSyscall extends JavaGate {
    public SSNSyscall(String shellCodeHex) {
        super(shellCodeHex);
        JNIUtil.extractDll(SSN_SYSCALL);
    }

    public SSNSyscall(byte[] shellCode) {
        super(shellCode);
        JNIUtil.extractDll(SSN_SYSCALL);
    }

    @Override
    public void execAndWait() throws RuntimeException {
        super.execAndWait();
        exec0(this.shellCode, this.shellCode.length, false);
        super.waitInMain();
    }

    @Override
    public void execNoWait() throws RuntimeException {
        super.execNoWait();
        new Thread(() -> exec0(shellCode, shellCode.length, false)).start();
    }

    @Override
    public void debugAndWait() throws RuntimeException {
        super.debugAndWait();
        exec0(this.shellCode, this.shellCode.length, true);
        super.waitInMain();
    }

    @Override
    public void exec() throws RuntimeException {
        this.execAndWait();
    }

    private native void exec0(byte[] shellcode, int size, boolean debug);
}
