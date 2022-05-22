cmake_minimum_required(VERSION 3.22)
project(tk2k_lib)

set(CMAKE_CXX_STANDARD 20)
find_package(Threads)
add_executable(tk2k_lib
        main.cpp
        integrity_validation.cpp integrity_validation.h
        archive.h archive.cpp
        archive_structures.h archive_structures.cpp
        misc/project_exceptions.h misc/project_exceptions.cpp
        compression.h compression.cpp
        misc/bitbuffer.h misc/bitbuffer.cpp
        misc/multithreading.h misc/multithreading.cpp
        misc/model.h
        misc/dc3.h
        cryptography.h cryptography.cpp
        )

target_link_libraries(tk2k_lib PRIVATE Threads::Threads)