#include <stdio.h>
#include "commons.h"
#include "halos_gate_core.h"
#include "halos_gate_jni.h"

JNIEXPORT void JNICALL Java_me_n1ar4_gate_core_HalosGate_exec0
        (JNIEnv *env, jclass obj, jbyteArray jShellcode, jint length, jboolean debug) {
    jbyte *arrayPtr = (*env)->GetByteArrayElements(env, jShellcode, NULL);
    boolean nativeDebug = (boolean) debug;
    unsigned char *shellcode = (unsigned char *) arrayPtr;
    if (nativeDebug) {
        printf("jni debug shellcode length: %ld\n", length);
        DEBUG_SHELLCODE(shellcode, length);
    }
    HALOS_GATE_MAIN(shellcode, length, nativeDebug);
}