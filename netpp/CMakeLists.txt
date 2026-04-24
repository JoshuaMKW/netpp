cmake_minimum_required(VERSION 3.14)

# Project name and version
project(netpp VERSION 1.0 LANGUAGES CXX)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Define the library
add_library(netpp STATIC
    allocator.cpp
    client.cpp
    network.cpp
    protocol.cpp
    security.h
    server.cpp
    socket.h
    sockenum.h

    platform/socket.h
    platform/socket.cpp

    tls/security.h
    tls/security.cpp
    
    dtls/security.cpp
    dtls/security.h
    dtls/dtls_bio.h
    dtls/dtls_bio.cpp
    dtls/cookie.h

    tcp/socket.cpp
    tcp/client.cpp
    tcp/server.cpp

    udp/socket.cpp
    udp/client.cpp
    udp/server.cpp

    http/router.h
    http/router.cpp
    http/response.h
    http/response.cpp
    http/request.h
    http/request.cpp
    
    dns/record.h
    dns/record.cpp
)

set(OPENSSL_USE_STATIC_LIBS FALSE)
find_package(OpenSSL REQUIRED)

# Link libraries
target_link_libraries(netpp PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Include directories
target_include_directories(netpp PUBLIC
    ${CMAKE_SOURCE_DIR}/netpp
    #${CMAKE_SOURCE_DIR}/vcpkg_installed/x64-windows/include
)

# Add preprocessor definitions
target_compile_definitions(netpp PUBLIC
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