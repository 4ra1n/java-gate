package me.n1ar4.gate.core;

import me.n1ar4.gate.exp.ArchException;
import me.n1ar4.gate.exp.ExpConst;
import me.n1ar4.gate.exp.ShellCodeException;
import me.n1ar4.gate.util.ByteUtil;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

/**
 * Java Gate Base Class (Core Class)
 */
@SuppressWarnings("unused")
public class JavaGate implements Gate, ExpConst {
    /**
     * shellcode byte array
     */
    protected byte[] shellCode;
    /**
     * JAVA_HOME
     * Note: this is not JAVA_HOME, but JAVA_HOME/bin/java.exe
     */
    protected String javaHome;

    /**
     * Constructor using shellcode hex string
     *
     * @param shellCodeHex shellcode hex string
     */
    public JavaGate(String shellCodeHex) {
        this(ByteUtil.hexStringToByteArray(shellCodeHex));
    }

    /**
     * Exec shellcode base method
     * <p>
     * 1. check 64 bit JVM and 64 bit windows
     * <br>
     * 2. output message
     * <br>
     * Add custom code after invoking this method
     * </p>
     *
     * @throws RuntimeException runtime exception
     */
    private void execBase() throws RuntimeException {
        if (this.shellCode == null || this.shellCode.length == 0) {
            throw new ShellCodeException(SHELL_CODE_NULL);
        }
        System.out.println("#######################################################");
        System.out.println("#                 JAVA-GATE PROJECT                   #");
        System.out.println("#   DANGEROUS   : JVM MAY CRASH WHEN LOAD SHELLCODE!  #");
        System.out.println("#   SUPPORT OS  : ONLY WINDOWS X64                    #");
        System.out.println("#   SUPPORT JVM : ONLY 64 BIT                         #");
        System.out.println("#######################################################");
        if (!System.getProperty(JVM_ARCH).equals(ARCH_64)) {
            throw new ArchException(ONLY_SUPPORT_64);
        }
        String osArch = System.getProperty(OS_ARCH);
        if (!osArch.contains(ARCH_64)) {
            throw new ArchException(ONLY_SUPPORT_64);
        }
        // INVOKE THIS METHOD FIRST
    }


    /**
     * Constructor using shellcode byte array
     * <p>
     * This is a base constructor
     * </p>
     *
     * @param shellCode shellcode byte array
     */
    public JavaGate(byte[] shellCode) {
        this.shellCode = shellCode;
        String osName = System.getProperty("os.name").toLowerCase();
        String javaHome;
        if (osName.contains("win")) {
            javaHome = System.getenv("JAVA_HOME");
        } else {
            // ACTUALLY WE CAN IGNORE THIS
            javaHome = System.getProperty("java.home");
        }
        File javaBin = new File(javaHome, "bin");
        File javaExe = new File(javaBin, "java.exe");
        // OTHER METHOD WILL USE THIS VARIABLE
        this.javaHome = javaExe.getAbsolutePath();
    }

    /**
     * Exec shellcode and wait in main thread, but not implement here
     *
     * @throws RuntimeException runtime exception
     */
    @Override
    public void execAndWait() throws RuntimeException {
        this.execBase();
    }

    /**
     * Exec shellcode in new thread, but not implement here
     *
     * @throws RuntimeException runtime exception
     */
    @Override
    public void execNoWait() throws RuntimeException {
        this.execBase();
    }

    /**
     * Debug shellcode and wait in main thread, but not implement here
     *
     * @throws RuntimeException runtime exception
     */
    @Override
    public void debugAndWait() throws RuntimeException {
        this.execBase();
    }

    /**
     * Run this program in a new JVM, and implement here, only support cli application
     *
     * @param module use which module (such as hell's gate)
     * @param debug  use debug module or not
     * @throws RuntimeException runtime exception
     */
    @Override
    public void runNewJVM(String module, boolean debug) throws RuntimeException {
        try {
            // get jar file path
            String path = this.getClass().getProtectionDomain()
                    .getCodeSource().getLocation().toURI().getPath();
            if (path == null || !path.endsWith(".jar")) {
                System.err.println("not support this method");
                return;
            }
            // this path starts with /
            path = path.substring(1);
            String sch = ByteUtil.bytesToHex(this.shellCode);
            String javaBin = this.javaHome;
            String finalPath = path;
            new Thread(() -> {
                String[] cmdArray = new String[]{javaBin, "-jar", finalPath, module, sch};
                if (debug) {
                    System.out.println("####### CMD #######");
                    System.out.println(Arrays.toString(cmdArray));
                    System.out.println("###################");
                }
                try {
                    Process process = Runtime.getRuntime().exec(cmdArray);
                    InputStream is = process.getInputStream();
                    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                    int nRead;
                    byte[] data = new byte[1024];
                    while ((nRead = is.read(data, 0, data.length)) != -1) {
                        buffer.write(data, 0, nRead);
                    }
                    System.out.println(new String(data));
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }).start();
            // wait in current process
            waitInMain();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    /**
     * Exec
     *
     * @throws RuntimeException runtime exception
     */
    @Override
    public void exec() throws RuntimeException {
        this.execBase();
    }

    /**
     * Wait in main thread
     */
    @SuppressWarnings("all")
    protected void waitInMain() {
        while (true) {
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
