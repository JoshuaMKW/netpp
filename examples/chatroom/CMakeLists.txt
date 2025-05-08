cmake_minimum_required(VERSION 3.14)

# Project name and version
project(Chatroom VERSION 1.0 LANGUAGES CXX)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# ----------------
# ChatServer
# ----------------

# Define the executable
add_executable(ChatServer
    "common.h"
    "server.cpp")

# Include directories
target_include_directories(ChatServer PRIVATE
    ${CMAKE_SOURCE_DIR}/netpp
    ${CMAKE_SOURCE_DIR}/vcpkg_installed/x64-windows/include
)

target_link_directories(ChatServer PRIVATE ${CMAKE_BINARY_DIR}/Application)

# Link libraries
target_link_libraries(ChatServer PRIVATE
    netpp
    Crypt32.lib
)

# Add preprocessor definitions
target_compile_definitions(ChatServer PRIVATE
    $<$<CONFIG:Debug>:_DEBUG;_CONSOLE;NETPP_STATIC>
    $<$<CONFIG:Release>:NDEBUG;_CONSOLE;NETPP_STATIC>
)

# Set output directories
set_target_properties(ChatServer PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/Application/Chatroom
    RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/Application/Chatroom
)

# ----------------


# ----------------
# ChatClient
# ----------------

# Define the executable
add_executable(ChatClient
    "common.h"
    "client.cpp"
    "inputhandler.h"
    "inputhandler.cpp")

# Include directories
target_include_directories(ChatClient PRIVATE
    ${CMAKE_SOURCE_DIR}/netpp
    ${CMAKE_SOURCE_DIR}/vcpkg_installed/x64-windows/include
)

target_link_directories(ChatClient PRIVATE ${CMAKE_BINARY_DIR}/Application)

# Link libraries
target_link_libraries(ChatClient PRIVATE
    netpp
    Crypt32.lib
)

# Add preprocessor definitions
target_compile_definitions(ChatClient PRIVATE
    $<$<CONFIG:Debug>:_DEBUG;_CONSOLE;NETPP_STATIC>
    $<$<CONFIG:Release>:NDEBUG;_CONSOLE;NETPP_STATIC>
)

# Set output directories
set_target_properties(ChatClient PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/Application/Chatroom
    RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/Application/Chatroom
)