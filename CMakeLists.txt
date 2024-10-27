cmake_minimum_required(VERSION 3.16)
project(converter)

set(CMAKE_CXX_STANDARD 17)
add_compile_options(-Wall -Wextra -Wunused -Werror)

find_library(CAP capstone REQUIRED)
message(STATUS "Found capstone library - ${CAP}")

find_library(KEY keystone REQUIRED)
message(STATUS "Found keystone library - ${KEY}")

set(SOURCES 
    src/elf_file.cpp 
    src/elf_section.cpp 
    src/elf_converter.cpp 
    src/x86_instruction.cpp
)

add_executable(converter main.cpp ${SOURCES})

target_include_directories(converter PUBLIC include)
target_link_libraries(converter PUBLIC ${CAP} ${KEY})
