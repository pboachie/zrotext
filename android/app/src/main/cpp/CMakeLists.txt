# ZROtext AndroidKeyStore HPKE bridge native build.
#
# Android (AGP externalNativeBuild): builds the vendored pinned wolfSSL
# subset as a static library plus the JNI bridge shared library. The wolfSSL
# feature set comes from user_settings.h (-DWOLFSSL_USER_SETTINGS), which
# realizes the maintainer-selected cryptocb-only ECC configuration from the
# #1003 review; see that file for the flag-by-flag rationale.
#
# Host (CI, -DZT_HOST_KAT=ON): builds the same bridge core against the same
# wolfSSL subset with a software test key and runs the RFC 9180 known-answer
# and fail-closed tests. This is an additional test lane; it does not replace
# the AndroidKeyStore instrumentation tests on an API 31+ emulator.
cmake_minimum_required(VERSION 3.22)
project(zrotext_hpke_keystore C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_VISIBILITY_PRESET hidden)

set(ZT_WOLFSSL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/wolfssl")
set(ZT_WOLFSSL_SOURCES
    "${ZT_WOLFSSL_DIR}/wolfcrypt/src/asn.c"
    "${ZT_WOLFSSL_DIR}/wolfcrypt/src/aes.c"
    "${ZT_WOLFSSL_DIR}/wolfcrypt/src/coding.c"
    "${ZT_WOLFSSL_DIR}/wolfcrypt/src/cryptocb.c"
    "${ZT_WOLFSSL_DIR}/wolfcrypt/src/ecc.c"
    "${ZT_WOLFSSL_DIR}/wolfcrypt/src/error.c"
    "${ZT_WOLFSSL_DIR}/wolfcrypt/src/hash.c"
    "${ZT_WOLFSSL_DIR}/wolfcrypt/src/hmac.c"
    "${ZT_WOLFSSL_DIR}/wolfcrypt/src/hpke.c"
    "${ZT_WOLFSSL_DIR}/wolfcrypt/src/kdf.c"
    "${ZT_WOLFSSL_DIR}/wolfcrypt/src/logging.c"
    "${ZT_WOLFSSL_DIR}/wolfcrypt/src/memory.c"
    "${ZT_WOLFSSL_DIR}/wolfcrypt/src/misc.c"
    "${ZT_WOLFSSL_DIR}/wolfcrypt/src/random.c"
    "${ZT_WOLFSSL_DIR}/wolfcrypt/src/sha256.c"
    "${ZT_WOLFSSL_DIR}/wolfcrypt/src/sp_int.c"
    "${ZT_WOLFSSL_DIR}/wolfcrypt/src/wc_port.c"
    "${ZT_WOLFSSL_DIR}/wolfcrypt/src/wolfmath.c"
)

add_library(wolfssl_zt STATIC ${ZT_WOLFSSL_SOURCES})
target_include_directories(wolfssl_zt PUBLIC
    "${ZT_WOLFSSL_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}")
# Both the library and every consumer compile with the same user_settings.h
# (wolfSSL integration rule: feature-define mismatch corrupts at runtime).
target_compile_definitions(wolfssl_zt PUBLIC WOLFSSL_USER_SETTINGS)
target_compile_options(wolfssl_zt PRIVATE -O2)
# The vendored upstream sources are compiled unmodified; they are not held to
# the warning bar of first-party bridge code below.
target_compile_options(wolfssl_zt PRIVATE -Wno-unused-parameter)

set(ZT_BRIDGE_CORE "${CMAKE_CURRENT_SOURCE_DIR}/zrotext_hpke_core.c")

if(ANDROID)
    add_library(zrotext_hpke_keystore SHARED
        "${ZT_BRIDGE_CORE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/zrotext_hpke_jni.c")
    target_link_libraries(zrotext_hpke_keystore PRIVATE wolfssl_zt log)
endif()

# Known-answer test runner for the software-key bridge KAT suite. On a host
# toolchain (-DZT_HOST_KAT=ON, CI) it runs under ctest; the same binary can
# be built with an Android toolchain and run on an emulator for extra
# on-device confirmation of the non-Keystore paths.
option(ZT_HOST_KAT "Build the software-key known-answer test runner" OFF)
if(ZT_HOST_KAT)
    enable_testing()
    add_executable(zrotext-hpke-kat
        "${ZT_BRIDGE_CORE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/zrotext_hpke_kat.c")
    target_link_libraries(zrotext-hpke-kat PRIVATE wolfssl_zt)
    add_test(NAME zrotext_hpke_kat COMMAND zrotext-hpke-kat)
endif()
