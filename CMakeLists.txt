cmake_minimum_required(VERSION 3.20.0)
project(SM2)
set(CMAKE_C_STANDARD 11)

include_directories(${PROJECT_SOURCE_DIR}/include)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/build)
aux_source_directory(${PROJECT_SOURCE_DIR}/src SRCLIST)
add_executable(main ${SRCLIST})