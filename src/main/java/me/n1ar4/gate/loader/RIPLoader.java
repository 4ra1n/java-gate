package me.n1ar4.gate.loader;

import me.n1ar4.gate.core.JavaGate;
import me.n1ar4.gate.util.JNIUtil;

/**
 * Modify RIP Register of Thread Context
 */
@SuppressWarnings("unused")
public class RIPLoader extends JavaGate {
    public RIPLoader(String shellCodeHex) {
        super(shellCodeHex);
        JNIUtil.extractDll(JAVA_LOADER);
    }

    public RIPLoader(byte[] shellCode) {
        super(shellCode);
        JNIUtil.extractDll(JAVA_LOADER);
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
