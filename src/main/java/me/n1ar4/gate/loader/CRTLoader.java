package me.n1ar4.gate.loader;

import me.n1ar4.gate.core.JavaGate;
import me.n1ar4.gate.exp.NotSupportExp;
import me.n1ar4.gate.util.JNIUtil;

/**
 * Create Remote Thread
 */
@SuppressWarnings("unused")
public class CRTLoader extends JavaGate {
    public CRTLoader(String shellCodeHex) {
        super(shellCodeHex);
        JNIUtil.extractDll(JAVA_LOADER);
    }

    public CRTLoader(byte[] shellCode) {
        super(shellCode);
        JNIUtil.extractDll(JAVA_LOADER);
    }

    @Override
    public void execAndWait() throws RuntimeException {
        this.exec();
    }

    @Override
    public void execNoWait() throws RuntimeException {
        this.exec();
    }

    @Override
    public void exec() throws RuntimeException {
        System.err.println("must use method with String param (process name)");
        throw new NotSupportExp(NOT_SUPPORT);
    }

    @Override
    public void debugAndWait() throws RuntimeException {
        this.exec();
    }

    public void execAndWait(String process) throws RuntimeException {
        super.execAndWait();
        exec0(this.shellCode, this.shellCode.length, process, false);
        super.waitInMain();
    }

    public void execNoWait(String process) throws RuntimeException {
        super.execNoWait();
        new Thread(() -> exec0(shellCode, shellCode.length, process, false)).start();
    }

    public void debugAndWait(String process) throws RuntimeException {
        super.debugAndWait();
        exec0(this.shellCode, this.shellCode.length, process, true);
        super.waitInMain();
    }

    public void exec(String process) throws RuntimeException {
        this.execAndWait(process);
    }

    private native void exec0(byte[] shellcode, int size, String process, boolean debug);
}
