cmake_minimum_required(VERSION 3.14)

# Project name and version
project(Appsync VERSION 1.0 LANGUAGES CXX)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Define the executable
add_executable(Appsync "client.cpp" "server.cpp")

# Include directories
target_include_directories(Appsync PRIVATE
    ${CMAKE_SOURCE_DIR}/netpp
    ${CMAKE_SOURCE_DIR}/vcpkg_installed/x64-windows/include
)

target_link_directories(Appsync PRIVATE ${CMAKE_BINARY_DIR}/Application)

# Link libraries
target_link_libraries(Appsync PRIVATE
    netpp
    Crypt32.lib
)

# Add preprocessor definitions
target_compile_definitions(Appsync PRIVATE
    $<$<CONFIG:Debug>:_DEBUG;_CONSOLE;>
    $<$<CONFIG:Release>:NDEBUG;_CONSOLE;>
)

# Set output directories
set_target_properties(Appsync PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/Application/Appsync
    RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/Application/Appsync
)
