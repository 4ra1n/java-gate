package me.n1ar4.gate.core;

/**
 * Common interface of java-gate
 */
public interface Gate {
    String JVM_ARCH = "sun.arch.data.model";
    String OS_ARCH = "os.arch";
    String ARCH_64 = "64";
    String JAVA_LOADER = "java_loader.dll";
    String HELLS_GATE = "hells_gate_jni.dll";
    String HALOS_GATE = "halos_gate_jni.dll";
    String RECYCLED_GATE = "recycled_gate_jni.dll";
    String SSN_SYSCALL = "ssn_gate_jni.dll";
    String TARTARUS_GATE = "tartarus_gate_jni.dll";

    void exec() throws RuntimeException;

    void execAndWait() throws RuntimeException;

    void execNoWait() throws RuntimeException;

    void debugAndWait() throws RuntimeException;

    void runNewJVM(String module, boolean debug) throws RuntimeException;
}
