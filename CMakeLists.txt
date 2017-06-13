cmake_minimum_required(VERSION 2.6)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY bin)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules")
set(CMAKE_EXPORT_COMPILE_COMMANDS 1)

cmake_policy(SET CMP0015 NEW)

project(paillier)

find_package(GMP REQUIRED)
#include_directories(${GMP_INCLUDES} ../../libgfshare/include)
#link_directories(../../libgfshare/BUILD/.libs)

add_executable(keygen keygen.c paillier.c util.c)
add_executable(encrypt encrypt.c paillier.c util.c)
add_executable(combine combine.c paillier.c util.c)
add_executable(combine_and_decrypt combine_and_decrypt.c paillier.c util.c)
add_executable(runtests runtests.c util.c nnsplit.c paillier.c shamir.c)
add_executable(nncombine nncombine.c util.c nnsplit.c)
add_executable(nnsplit nnsplit_main.c util.c nnsplit.c)
add_executable(shsplit shsplit.c shamir.c)
add_executable(shcombine shcombine.c shamir.c)

target_link_libraries(keygen ${GMP_LIBRARIES})
target_link_libraries(encrypt ${GMP_LIBRARIES})
target_link_libraries(combine ${GMP_LIBRARIES})
target_link_libraries(combine_and_decrypt ${GMP_LIBRARIES})
target_link_libraries(runtests ${GMP_LIBRARIES})
target_link_libraries(nncombine ${GMP_LIBRARIES})
target_link_libraries(nnsplit ${GMP_LIBRARIES})
