cmake_minimum_required(VERSION 3.18.1)
project(mlkem768 C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Vendored PQClean ML-KEM-768 + FIPS 202 SHAKE.
# Each platform keeps its own copy under android/src/main/cpp/mlkem768
# (and ios/mlkem768) — duplicating ~50KB of FIPS-203-finalized C source
# is cheaper than fighting CocoaPods' sandbox path rules.
set(PQCLEAN_DIR ${CMAKE_SOURCE_DIR}/src/main/cpp/mlkem768)

include_directories(${PQCLEAN_DIR})

file(GLOB PQCLEAN_SOURCES
  ${PQCLEAN_DIR}/cbd.c
  ${PQCLEAN_DIR}/fips202.c
  ${PQCLEAN_DIR}/indcpa.c
  ${PQCLEAN_DIR}/kem.c
  ${PQCLEAN_DIR}/ntt.c
  ${PQCLEAN_DIR}/poly.c
  ${PQCLEAN_DIR}/polyvec.c
  ${PQCLEAN_DIR}/randombytes.c
  ${PQCLEAN_DIR}/reduce.c
  ${PQCLEAN_DIR}/symmetric-shake.c
  ${PQCLEAN_DIR}/verify.c
)

add_library(mlkem768 SHARED
  ${PQCLEAN_SOURCES}
  ${CMAKE_SOURCE_DIR}/src/main/cpp/mlkem_jni.c
)

# arc4random_buf is in libc on Android API 21+; no extra link needed.
target_link_libraries(mlkem768
  android
  log
)

target_compile_options(mlkem768 PRIVATE
  -Wall
  -Wno-unused-parameter
  -Wno-implicit-fallthrough
  -O2
)
