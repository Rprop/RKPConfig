cmake_minimum_required(VERSION 3.31.6)
project(rkp)

add_compile_options(
        -fvisibility=hidden
        -fvisibility-inlines-hidden
        -g0
        -O3 -ffast-math
        -fomit-frame-pointer
        -ffunction-sections
        -fdata-sections
        -fno-stack-protector
        -DNDEBUG
)
add_link_options(
        -static
        -Wl,--strip-all
        -Wl,--gc-sections
)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/build/.cxx/${CMAKE_BUILD_TYPE}/${ANDROID_ABI})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/build/.cxx/${CMAKE_BUILD_TYPE}/${ANDROID_ABI})

# ----------------------------------------------------------------

add_executable(
        rkp
        src/main/cpp/rkp.cpp
)
