cmake_minimum_required(VERSION 3.20)
project(kvparse LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(parser src/parser.cpp)
target_include_directories(parser PUBLIC include)

add_executable(kvparse src/main.cpp)
target_link_libraries(kvparse PRIVATE parser)
