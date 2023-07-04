import os
import shutil


def copy_dll_files(source_dir, target_dir):
    os.makedirs(target_dir, exist_ok=True)
    for root, dirs, files in os.walk(source_dir):
        for file in files:
            if file.endswith(".dll"):
                source_path = os.path.join(root, file)
                target_path = os.path.join(target_dir, file)
                shutil.copy(source_path, target_path)
                print(f"copy: {source_path} -> {target_path}")


# must use debug cake
# DO NOT USE RELEASE
source_directory = "cmake-build-debug"

target_directory = "target"

copy_dll_files(source_directory, target_directory)
