cmake_minimum_required(VERSION 3.25)

################ JNI CONFIG START ################

project(java_gate_jni C)

set(CMAKE_C_STANDARD 11)

# INCLUDE JNI
find_package(JNI REQUIRED)

include_directories(${JNI_INCLUDE_DIRS})

################ JNI CONFIG END ##################

enable_language(ASM_MASM)

# BUILD HELLS GATE ASM

add_custom_target(
        hells_gate_asm ALL
        COMMAND ml64 /c /Fo${CMAKE_CURRENT_BINARY_DIR}/hells_gate.obj
        ${CMAKE_CURRENT_SOURCE_DIR}/hells_gate.asm
        BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/hells_gate.obj
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# BUILD HELLS GATE DLL

add_library(
        hells_gate_jni SHARED
        hells_gate_jni.h
        hells_gate_jni.c
        commons.h
        commons.c
        hells_gate_struct.h
        hells_gate_core.h
)

set_property(TARGET hells_gate_jni PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# HELLS GATE DLL DEPEND HELLS GATE ASM

add_dependencies(hells_gate_jni hells_gate_asm)

target_sources(hells_gate_jni PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/hells_gate.obj)

# HELLS GATE DLL LINK JNI LIB

target_link_libraries(hells_gate_jni ${JNI_LIBRARIES})

# HELLS GATE TEST EXE

add_executable(hells_gate_test hells_gate_main.c)

add_dependencies(hells_gate_test hells_gate_asm)

target_sources(hells_gate_test PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/hells_gate.obj)

# BUILD HALOS GATE ASM

add_custom_target(
        halos_gate_asm ALL
        COMMAND ml64 /c /Fo${CMAKE_CURRENT_BINARY_DIR}/halos_gate.obj
        ${CMAKE_CURRENT_SOURCE_DIR}/halos_gate.asm
        BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/halos_gate.obj
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# BUILD HALOS GATE DLL

add_library(
        halos_gate_jni SHARED
        halos_gate_jni.h
        halos_gate_jni.c
        commons.h
        commons.c
        halos_gate_struct.h
        halos_gate_core.h
)

set_property(TARGET halos_gate_jni PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# HALOS GATE DLL DEPEND HALOS GATE ASM

add_dependencies(halos_gate_jni halos_gate_asm)

target_sources(halos_gate_jni PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/halos_gate.obj)

# HALOS GATE DLL LINK JNI LIB

target_link_libraries(halos_gate_jni ${JNI_LIBRARIES})

# BUILD HALOS GATE TEST EXE

add_executable(halos_gate_test halos_gate_main.c)

add_dependencies(halos_gate_test halos_gate_asm)

target_sources(halos_gate_test PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/halos_gate.obj)

# BUILD SSN ASM

add_custom_target(
        ssn_syscall_asm ALL
        COMMAND nasm -f win64 ${CMAKE_CURRENT_SOURCE_DIR}/ssn_syscall.asm
        -o ${CMAKE_CURRENT_BINARY_DIR}/ssn_syscall.obj
        BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/ssn_syscall.obj
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# BUILD SSN GATE DLL

add_library(
        ssn_gate_jni SHARED
        ssn_gate_jni.h
        ssn_gate_jni.c
        commons.h
        commons.c
        ssn_api_def.h
        ssn_syscall.h
        ssn_syscall_core.h
        ssn_syscall_fun.h
)

set_property(TARGET ssn_gate_jni PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# SSN GATE DLL DEPEND SSN GATE ASM

add_dependencies(ssn_gate_jni ssn_syscall_asm)

target_sources(ssn_gate_jni PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/ssn_syscall.obj)

# SSN GATE DLL LINK JNI LIB

target_link_libraries(ssn_gate_jni ${JNI_LIBRARIES})

# BUILD SSN TEST EXE

add_executable(ssn_syscall_test ssn_syscall_main.c)

add_dependencies(ssn_syscall_test ssn_syscall_asm)

target_sources(ssn_syscall_test PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/ssn_syscall.obj)

# BUILD TARTARUS GATE ASM

add_custom_target(
        tartarus_gate_asm ALL
        COMMAND ml64 /c /Fo${CMAKE_CURRENT_BINARY_DIR}/tartarus_gate.obj
        ${CMAKE_CURRENT_SOURCE_DIR}/tartarus_gate.asm
        BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/tartarus_gate.obj
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# BUILD TARTARUS GATE DLL

add_library(
        tartarus_gate_jni SHARED
        tartarus_gate_jni.h
        tartarus_gate_jni.c
        commons.h
        commons.c
        tartarus_gate_struct.h
        tartarus_gate_core.h
)

set_property(TARGET tartarus_gate_jni PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# TARTARUS GATE DLL DEPEND TARTARUS GATE ASM

add_dependencies(tartarus_gate_jni tartarus_gate_asm)

target_sources(tartarus_gate_jni PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/tartarus_gate.obj)

# TARTARUS GATE DLL LINK JNI LIB

target_link_libraries(tartarus_gate_jni ${JNI_LIBRARIES})

# BUILD TARTARUS GATE TEST EXE

add_executable(tartarus_gate_test tartarus_gate_main.c)

add_dependencies(tartarus_gate_test tartarus_gate_asm)

target_sources(tartarus_gate_test PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/tartarus_gate.obj)

# BUILD RECYCLED GATE ASM

add_custom_target(
        recycled_gate_asm ALL
        COMMAND ml64 /c /Fo${CMAKE_CURRENT_BINARY_DIR}/recycled_gate.obj
        ${CMAKE_CURRENT_SOURCE_DIR}/recycled_gate.asm
        BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/recycled_gate.obj
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# BUILD RECYCLED GATE DLL

add_library(
        recycled_gate_jni SHARED
        recycled_gate_jni.h
        recycled_gate_jni.c
        commons.h
        commons.c
        recycled_gate_core.h
        recycled_gate_start.h
        recycled_gate_struct.h
)

set_property(TARGET recycled_gate_jni PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# RECYCLED GATE DLL DEPEND RECYCLED GATE ASM

add_dependencies(recycled_gate_jni recycled_gate_asm)

target_sources(recycled_gate_jni PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/recycled_gate.obj)

# RECYCLED GATE DLL LINK JNI LIB

target_link_libraries(recycled_gate_jni ${JNI_LIBRARIES})

# BUILD RECYCLED GATE TEST EXE

add_executable(recycled_gate_test recycled_gate_main.c)

add_dependencies(recycled_gate_test recycled_gate_asm)

target_sources(recycled_gate_test PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/recycled_gate.obj)