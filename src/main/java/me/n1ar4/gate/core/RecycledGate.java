package me.n1ar4.gate.core;

import me.n1ar4.gate.util.JNIUtil;

/**
 * Recycled Gate
 */
@SuppressWarnings("unused")
public class RecycledGate extends JavaGate {
    public RecycledGate(String shellCodeHex) {
        super(shellCodeHex);
        JNIUtil.extractDll(RECYCLED_GATE);
    }

    public RecycledGate(byte[] shellCode) {
        super(shellCode);
        JNIUtil.extractDll(RECYCLED_GATE);
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
