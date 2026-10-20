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
target_link_options(rkp PRIVATE -static)
add_custom_command(TARGET rkp POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_SOURCE_DIR}/src/main/jniLibs/${ANDROID_ABI}
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:rkp> ${CMAKE_SOURCE_DIR}/src/main/jniLibs/${ANDROID_ABI}/librkp.so
)

# ----------------------------------------------------------------

add_executable(
        kmcli
        src/main/cpp/kmcli.c
)
target_link_libraries(kmcli PRIVATE dl)
add_custom_command(TARGET kmcli POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_SOURCE_DIR}/src/main/jniLibs/${ANDROID_ABI}
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:kmcli> ${CMAKE_SOURCE_DIR}/src/main/jniLibs/${ANDROID_ABI}/libkmcli.so
)
