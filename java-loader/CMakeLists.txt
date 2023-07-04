cmake_minimum_required(VERSION 3.25)
project(java_loader C)

find_package(JNI REQUIRED)

include_directories(${JNI_INCLUDE_DIRS})

add_library(
        java_loader SHARED
        commons.c commons.h
        apc1.h apc1-jni.h apc1-jni.c
        apc2.h apc2-jni.h apc2-jni.c
        crt.h crt-jni.h crt-jni.c
        divide.h divide-jni.h divide-jni.c
        early-bird.h early-bird-jni.h early-bird-jni.c
        rip.h rip-jni.h rip-jni.c
        etwp.h etwp-jni.h etwp-jni.c
)

set_property(TARGET java_loader PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

target_link_libraries(java_loader ${JNI_LIBRARIES})

add_executable(apc1-test apc1-main.c)

add_executable(apc2-test apc2-main.c)

add_executable(crt-test crt-main.c)

add_executable(divide-test divide-main.c)

add_executable(early-bird-test early-bird-main.c)

add_executable(rip-test rip-main.c)

add_executable(heap-test etwp-main.c)

add_executable(etwp-test etwp-main.c)