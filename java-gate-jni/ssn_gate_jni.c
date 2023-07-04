#include <stdio.h>
#include "commons.h"
#include "ssn_syscall_core.h"
#include "ssn_gate_jni.h"

JNIEXPORT void JNICALL Java_me_n1ar4_gate_core_SSNSyscall_exec0
        (JNIEnv *env, jclass obj, jbyteArray jShellcode, jint length, jboolean debug) {
    jbyte *arrayPtr = (*env)->GetByteArrayElements(env, jShellcode, NULL);
    boolean nativeDebug = (boolean) debug;
    unsigned char *shellcode = (unsigned char *) arrayPtr;
    if (nativeDebug) {
        printf("jni debug shellcode length: %ld\n", length);
        DEBUG_SHELLCODE(shellcode, length);
    }
    SSN_SYSCALL_MAIN(shellcode, length, nativeDebug);
}