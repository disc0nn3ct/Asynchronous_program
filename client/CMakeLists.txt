cmake_minimum_required(VERSION 3.5 FATAL_ERROR)
project(socks5_client LANGUAGES CXX)

add_executable(${PROJECT_NAME} client.cpp gen.cpp gen.hpp)
target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_20)
set_target_properties(${PROJECT_NAME} PROPERTIES CXX_EXTENSIONS OFF)


