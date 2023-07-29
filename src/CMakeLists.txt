cmake_minimum_required(VERSION 3.20)
project(send-arp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_EXTENSIONS ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/bin/)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/bin/)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/bin/)

set(COMMON_FLAGS
    -Os -Wall -Wextra
    -ffunction-sections -fdata-sections
    -fno-asynchronous-unwind-tables -fno-unwind-tables
    -fno-plt -fno-ident
    -march=native
)

add_compile_options(
    ${COMMON_FLAGS}
    -fno-rtti -fno-stack-protector
)
add_compile_definitions(__TBB_DYNAMIC_LOAD_ENABLED=0)
add_link_options(
    ${COMMON_FLAGS}
    -Wl,--build-id=none -Wl,-z,norelro
)

file(GLOB_RECURSE SRC src/*.cc)

add_executable(send-arp ${SRC})
target_link_libraries(send-arp pcap tbb)

target_include_directories(send-arp PRIVATE inc)