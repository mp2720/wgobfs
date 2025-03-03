cmake_minimum_required(VERSION 3.10)
project(wgobfs)

set(CMAKE_C_STANDARD 99)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE INTERNAL "")

add_compile_options(-Wall -Wextra)

if(SANITIZE)
  if(CMAKE_C_COMPILER_ID STREQUAL "Clang" OR CMAKE_C_COMPILER_ID STREQUAL "GNU")
    message("sanitizers enabled")
    add_compile_options(-fsanitize=address,undefined,leak)
    add_link_options(-fsanitize=address,undefined,leak)
  else()
    message(WARNING "sanitizers are not enabled due to unsupported compiler")
  endif()
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBUV REQUIRED IMPORTED_TARGET libuv)

add_library(
  libwgobfs

  src/utils.h
  src/err.c
  src/packet.h
  src/packet.c
  src/wgobfs.h
)
target_include_directories(libwgobfs PRIVATE ${LIBUV_INCLUDE_DIRS})
target_link_libraries(libwgobfs PkgConfig::LIBUV)

# ==== Tests ====

include(CTest)

add_executable(test_packet src/packet_test.c)
target_link_libraries(test_packet libwgobfs)
add_test(NAME test_packet COMMAND test_packet)
