cmake_minimum_required(VERSION 4.0)
project(untitled1 C)

set(CMAKE_C_STANDARD 23)

add_executable(untitled1 main.c
        src/diagnostics.c
        src/actions.c
        src/security.c
        src/main.c
        include/diagnostics.h
        include/actions.h
        include/security.h
)
