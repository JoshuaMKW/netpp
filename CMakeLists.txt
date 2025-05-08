cmake_minimum_required(VERSION 3.14)

# Root project name
project(netpp_project VERSION 1.0 LANGUAGES CXX)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add subdirectories for subprojects
add_subdirectory(netpp)
add_subdirectory(examples)
