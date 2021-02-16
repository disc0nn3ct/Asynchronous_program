cmake_minimum_required(VERSION 3.5 FATAL_ERROR)
project(server LANGUAGES CXX)

add_executable(${PROJECT_NAME} main.cpp gen.cpp gen.hpp)
target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_20)
set_target_properties(${PROJECT_NAME} PROPERTIES CXX_EXTENSIONS OFF)

find_package(Boost 1.5 REQUIRED COMPONENTS system thread)

target_link_libraries(${PROJECT_NAME} PRIVATE Boost::system Boost::thread)
