cmake_minimum_required(VERSION 3.10)

project(quickjs LANGUAGES C)

include(CheckCCompilerFlag)
include(GNUInstallDirs)

set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_C_STANDARD 11)

if(NOT CMAKE_BUILD_TYPE)
    message(STATUS "No build type selected, default to Release")
    set(CMAKE_BUILD_TYPE "Release")
endif()

message(STATUS "Building in ${CMAKE_BUILD_TYPE} mode")
message(STATUS "Building with ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION} on ${CMAKE_SYSTEM}")

macro(xcheck_add_c_compiler_flag FLAG)
    string(REPLACE "-" "" FLAG_NO_HYPHEN ${FLAG})
    check_c_compiler_flag(${FLAG} COMPILER_SUPPORTS_${FLAG_NO_HYPHEN})
    if(COMPILER_SUPPORTS_${FLAG_NO_HYPHEN})
        add_compile_options(${FLAG})
    endif()
endmacro()

xcheck_add_c_compiler_flag(-Wall)
if(NOT MSVC AND NOT IOS)
    xcheck_add_c_compiler_flag(-Werror)
    xcheck_add_c_compiler_flag(-Wextra)
endif()
xcheck_add_c_compiler_flag(-Wformat=2)
xcheck_add_c_compiler_flag(-Wno-implicit-fallthrough)
xcheck_add_c_compiler_flag(-Wno-sign-compare)
xcheck_add_c_compiler_flag(-Wno-missing-field-initializers)
xcheck_add_c_compiler_flag(-Wno-unused-parameter)
xcheck_add_c_compiler_flag(-Wno-unused-but-set-variable)
xcheck_add_c_compiler_flag(-Wno-unused-result)
xcheck_add_c_compiler_flag(-Wno-stringop-truncation)
xcheck_add_c_compiler_flag(-Wno-array-bounds)
xcheck_add_c_compiler_flag(-funsigned-char)

# ClangCL is command line compatible with MSVC, so 'MSVC' is set.
if(MSVC)
    xcheck_add_c_compiler_flag(-Wno-unsafe-buffer-usage)
    xcheck_add_c_compiler_flag(-Wno-sign-conversion)
    xcheck_add_c_compiler_flag(-Wno-nonportable-system-include-path)
    xcheck_add_c_compiler_flag(-Wno-implicit-int-conversion)
    xcheck_add_c_compiler_flag(-Wno-shorten-64-to-32)
    xcheck_add_c_compiler_flag(-Wno-reserved-macro-identifier)
    xcheck_add_c_compiler_flag(-Wno-reserved-identifier)
    xcheck_add_c_compiler_flag(-Wdeprecated-declarations)
    xcheck_add_c_compiler_flag(/experimental:c11atomics)
    xcheck_add_c_compiler_flag(/wd4018) # -Wno-sign-conversion
    xcheck_add_c_compiler_flag(/wd4061) # -Wno-implicit-fallthrough
    xcheck_add_c_compiler_flag(/wd4100) # -Wno-unused-parameter
    xcheck_add_c_compiler_flag(/wd4200) # -Wno-zero-length-array
    xcheck_add_c_compiler_flag(/wd4242) # -Wno-shorten-64-to-32
    xcheck_add_c_compiler_flag(/wd4244) # -Wno-shorten-64-to-32
    xcheck_add_c_compiler_flag(/wd4245) # -Wno-sign-compare
    xcheck_add_c_compiler_flag(/wd4267) # -Wno-shorten-64-to-32
    xcheck_add_c_compiler_flag(/wd4388) # -Wno-sign-compare
    xcheck_add_c_compiler_flag(/wd4389) # -Wno-sign-compare
    xcheck_add_c_compiler_flag(/wd4710) # Function not inlined
    xcheck_add_c_compiler_flag(/wd4711) # Function was inlined
    xcheck_add_c_compiler_flag(/wd4820) # Padding added after construct
    xcheck_add_c_compiler_flag(/wd4996) # -Wdeprecated-declarations
    xcheck_add_c_compiler_flag(/wd5045) # Compiler will insert Spectre mitigation for memory load if /Qspectre switch specified
endif()

# MacOS and GCC 11 or later need -Wno-maybe-uninitialized
# https://github.com/quickjs-ng/quickjs/issues/453
if(APPLE AND CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 11)
    xcheck_add_c_compiler_flag(-Wno-maybe-uninitialized)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "WASI")
    add_compile_definitions(
        _WASI_EMULATED_PROCESS_CLOCKS
        _WASI_EMULATED_SIGNAL
    )
    add_link_options(
        -lwasi-emulated-process-clocks
        -lwasi-emulated-signal
    )
endif()

if(CMAKE_BUILD_TYPE MATCHES "Debug")
    message(STATUS "Building in debug mode")
    add_compile_options(-O0)
    xcheck_add_c_compiler_flag(-ggdb3)
    xcheck_add_c_compiler_flag(-fno-omit-frame-pointer)
    add_compile_definitions(LJS_DEBUG)
else()
    add_compile_definitions(NDEBUG)
endif()

macro(xoption OPTION_NAME OPTION_TEXT OPTION_DEFAULT)
    option(${OPTION_NAME} ${OPTION_TEXT} ${OPTION_DEFAULT})
    if(DEFINED ENV{${OPTION_NAME}})
        # Allow setting the option through an environment variable.
        set(${OPTION_NAME} $ENV{${OPTION_NAME}})
    endif()
    if(${OPTION_NAME})
        add_definitions(-D${OPTION_NAME})
    endif()
    message(STATUS "  ${OPTION_NAME}: ${${OPTION_NAME}}")
endmacro()

xoption(BUILD_SHARED_LIBS "Build a shared library" OFF)
if(BUILD_SHARED_LIBS)
    message(STATUS "Building a shared library")
endif()

# note: QJS_ENABLE_TSAN is currently incompatible with the other sanitizers but we
# don't explicitly check for that because who knows what the future will bring?
# QJS_ENABLE_MSAN only works with clang at the time of writing; also not checked
# for the same reason
xoption(QJS_BUILD_EXAMPLES "Build examples" OFF)
xoption(QJS_BUILD_STATIC "Build a static ljs executable" OFF)
xoption(QJS_BUILD_WITH_MIMALLOC "Build the ljs executable with mimalloc" OFF)
xoption(QJS_BUILD_WITH_STATIC_MIMALLOC "Build the ljs executable with mimalloc (statically linked)" OFF)
xoption(QJS_ENABLE_ASAN "Enable AddressSanitizer (ASan)" OFF)
xoption(QJS_ENABLE_MSAN "Enable MemorySanitizer (MSan)" OFF)
xoption(QJS_ENABLE_TSAN "Enable ThreadSanitizer (TSan)" OFF)
xoption(QJS_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer (UBSan)" OFF)

if(QJS_ENABLE_ASAN)
message(STATUS "Building with ASan")
add_compile_options(
    -fsanitize=address
    -fno-sanitize-recover=all
    -fno-omit-frame-pointer
)
add_link_options(
    -fsanitize=address
    -fno-sanitize-recover=all
    -fno-omit-frame-pointer
)
endif()

if(QJS_ENABLE_MSAN)
message(STATUS "Building with MSan")
add_compile_options(
    -fsanitize=memory
    -fno-sanitize-recover=all
    -fno-omit-frame-pointer
)
add_link_options(
    -fsanitize=memory
    -fno-sanitize-recover=all
    -fno-omit-frame-pointer
)
endif()

if(QJS_ENABLE_TSAN)
message(STATUS "Building with TSan")
add_compile_options(
    -fsanitize=thread
    -fno-sanitize-recover=all
    -fno-omit-frame-pointer
)
add_link_options(
    -fsanitize=thread
    -fno-sanitize-recover=all
    -fno-omit-frame-pointer
)
endif()

if(QJS_ENABLE_UBSAN)
message(STATUS "Building with UBSan")
add_compile_options(
    -fsanitize=undefined
    -fno-sanitize-recover=all
    -fno-omit-frame-pointer
)
add_link_options(
    -fsanitize=undefined
    -fno-sanitize-recover=all
    -fno-omit-frame-pointer
)
endif()

# QuickJS library
#

macro(add_static_if_needed target)
    if(QJS_BUILD_STATIC OR MINGW)
        target_link_options(${target} PRIVATE -static)
        if(MINGW)
            target_link_options(${target} PRIVATE -static-libgcc)
        endif()
    endif()
endmacro()

file(GLOB ljs_core src/*.c)
set(ljs_sources
    engine/cutils.c
    engine/libbf.c
    engine/libregexp.c
    engine/libunicode.c
    engine/quickjs.c
    engine/xsum.c # add in QuickJS-NG v0.9.1
    ${ljs_core}
)

list(APPEND ljs_defines _GNU_SOURCE)
if(WIN32)
    # NB: Windows 7 is EOL and we are only supporting in so far as it doesn't interfere with progress.
    list(APPEND ljs_defines WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0601)
endif()
list(APPEND ljs_libs ${CMAKE_DL_LIBS})
find_package(Threads)
if(NOT CMAKE_SYSTEM_NAME STREQUAL "WASI")
    list(APPEND ljs_libs ${CMAKE_THREAD_LIBS_INIT})
endif()
# try to find libm
find_library(M_LIBRARIES m)
if(M_LIBRARIES OR CMAKE_C_COMPILER_ID STREQUAL "TinyCC")
    list(APPEND ljs_libs m)
endif()

# mbedtls
# find_library(MBEDTLS_LIBRARIES mbedtls)
# if(MBEDTLS_LIBRARIES)
#     # check
#     include(CheckSymbolExists)
#     check_symbol_exists(MBEDTLS_X509_CRT_PARSE_C "mbedtls/mbedtls_config.h" HAVE_MBEDTLS_X509)
#     if(NOT HAVE_MBEDTLS_X509)
#         message(FATAL_ERROR "The build of MbedTLS does not support X509 certificates.")
#     endif()

#     message(STATUS "Building with mbedtls support")
#     add_compile_definitions(LJS_MBEDTLS)
#     list(APPEND ljs_libs mbedtls)
# endif()

# libffi
find_library(LIBFFI_LIBRARIES ffi)
if(LIBFFI_LIBRARIES)
    message(STATUS "Building with libffi support")
    add_compile_definitions(LJS_LIBFFI)
    list(APPEND ljs_libs ffi)
    list(APPEND ljs_libs dl)
    add_compile_options(-Wl,--export-dynamic)
endif()

#zlib
find_library(ZLIB_LIBRARIES z)
if(ZLIB_LIBRARIES)
    message(STATUS "Building with zlib support")
    add_compile_definitions(LJS_ZLIB)
    list(APPEND ljs_libs z)
endif()

#libexecinfo
find_library(LIBEXECINFO_LIBRARIES execinfo)
if(LIBEXECINFO_LIBRARIES)
    message(STATUS "Building with libexecinfo support")
    add_compile_definitions(LJS_LIBEXECINFO)
    list(APPEND ljs_libs execinfo)
endif()

# libexpat
find_library(EXPAT_LIBRARIES expat)
if(EXPAT_LIBRARIES)
    message(STATUS "Building with expat support")
    add_compile_definitions(LJS_LIBEXPAT)
    list(APPEND ljs_libs expat)
endif()

add_library(ljs ${ljs_sources})
target_compile_definitions(ljs PRIVATE ${ljs_defines})
target_include_directories(ljs PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_link_libraries(ljs PUBLIC ${ljs_libs})

if(EMSCRIPTEN)
    add_executable(ljs_wasm ${ljs_sources})
    target_link_options(ljs_wasm PRIVATE
        # in emscripten 3.x, this will be set to 16k which is too small for quickjs. #write sth. to force github rebuild
        -sSTACK_SIZE=2097152 # let it be 2m = 2 * 1024 * 1024 = 2097152, otherwise, stack overflow may be occured at bootstrap
        -sNO_INVOKE_RUN
        -sNO_EXIT_RUNTIME
        -sMODULARIZE # do not mess the global
        -sEXPORT_ES6 # export js file to morden es module
        -sEXPORT_NAME=getQuickJs # give a name
        -sTEXTDECODER=1 # it will be 2 if we use -Oz, and that will cause js -> c string convertion fail
        -sNO_DEFAULT_TO_CXX # this project is pure c project, no need for c plus plus handle
        -sEXPORTED_RUNTIME_METHODS=ccall,cwrap
    )
    target_compile_definitions(ljs_wasm PRIVATE ${ljs_defines})
    target_link_libraries(ljs_wasm m)
endif()

# LightJS CLI
#

add_executable(ljs_exe
    # gen/repl.c
    # gen/standalone.c
    main.c
)
add_static_if_needed(ljs_exe)
set_target_properties(ljs_exe PROPERTIES
    OUTPUT_NAME "ljs"
)
target_compile_definitions(ljs_exe PRIVATE ${ljs_defines})
target_link_libraries(ljs_exe ljs)
if(NOT WIN32)
    set_target_properties(ljs_exe PROPERTIES ENABLE_EXPORTS TRUE)
endif()
if(QJS_BUILD_WITH_MIMALLOC OR QJS_BUILD_WITH_STATIC_MIMALLOC)
    find_package(mimalloc REQUIRED)
    # Upstream mimalloc doesn't provide a way to know if both libraries are supported.
    if(QJS_BUILD_WITH_STATIC_MIMALLOC)
        target_link_libraries(ljs_exe mimalloc-static)
    else()
        target_link_libraries(ljs_exe mimalloc)
    endif()
endif()

# Install target
#

# if(NOT IOS)
#     file(STRINGS quickjs.h quickjs_h REGEX QJS_VERSION)
#     string(REGEX MATCHALL "([0-9])" QJS_VERSION "${quickjs_h}")
#     list(GET QJS_VERSION 0 QJS_VERSION_MAJOR)
#     list(GET QJS_VERSION 1 QJS_VERSION_MINOR)
#     list(GET QJS_VERSION 2 QJS_VERSION_PATCH)
#     set_target_properties(ljs PROPERTIES
#         VERSION ${QJS_VERSION_MAJOR}.${QJS_VERSION_MINOR}.${QJS_VERSION_PATCH}
#         SOVERSION ${QJS_VERSION_MAJOR}
#     )
#     install(FILES quickjs.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
#     if(QJS_BUILD_LIBC)
#         install(FILES quickjs-libc.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
#     endif()
#     install(TARGETS ljs_exe RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
#     install(TARGETS ljsc RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
#     install(TARGETS ljs EXPORT ljsConfig
#             RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
#             LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
#             ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
#     install(EXPORT ljsConfig DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/quickjs)
#     install(FILES LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR})
#     install(DIRECTORY examples DESTINATION ${CMAKE_INSTALL_DOCDIR})
# endif()
