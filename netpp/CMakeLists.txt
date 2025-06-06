cmake_minimum_required(VERSION 3.14)

# Project name and version
project(netpp VERSION 1.0 LANGUAGES CXX)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(OPENSSL_USE_STATIC_LIBS FALSE)
find_package(OpenSSL REQUIRED)

# Define the library
add_library(netpp STATIC
    allocator.cpp
    client.cpp
    network.cpp
    protocol.cpp
    security.h
    server.cpp
    socket.h
    socket.cpp

    http/request.cpp
    http/response.cpp

    tls/proxy.h
    tls/proxy.cpp
    tls/controller.h
    tls/controller.cpp

    tcp/socket_win32.cpp
    tcp/client_unix.cpp
    tcp/client_win32.cpp
    tcp/server_unix.cpp
    tcp/server_win32.cpp

    udp/client_unix.cpp
    udp/client_win32.cpp
    udp/server_unix.cpp
    udp/server_win32.cpp
    udp/socket_win32.cpp
)

# Include directories
target_include_directories(netpp PRIVATE
    ${CMAKE_SOURCE_DIR}/netpp
    ${CMAKE_SOURCE_DIR}/vcpkg_installed/x64-windows/include
)

# Link libraries
target_link_libraries(netpp PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Add preprocessor definitions
target_compile_definitions(netpp PRIVATE
    $<$<CONFIG:Debug>:_DEBUG;_CONSOLE;NETPP_EXPORTS;NETPP_STATIC;>
    $<$<CONFIG:Release>:NDEBUG;_CONSOLE;NETPP_STATIC>
)

if (NETPP_SKIP_TLS_CERT_VERIFY)
    message(STATUS "Skipping TLS certificate verification.")
    target_compile_definitions(netpp PRIVATE NETPP_SKIP_TLS_CERT_VERIFY)
endif()

# Set output directories
set_target_properties(netpp PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/Application
    RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/Application
)