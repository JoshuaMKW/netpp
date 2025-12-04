cmake_minimum_required(VERSION 3.14)

# Project name and version
project(netpp VERSION 1.0 LANGUAGES CXX)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# This puts DLLs/EXEs in /bin and Static Libs/Import Libs in /lib
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(OPENSSL_USE_STATIC_LIBS FALSE)
find_package(OpenSSL REQUIRED)

# Define the library
add_library(netpp STATIC
    allocator.cpp
    client.cpp
    network.cpp
    protocol.cpp
    security.h
    security.cpp
    server.cpp
    socket.h

    platform/socket.h
    platform/socket.cpp

    http/request.cpp
    http/response.cpp

    tls/security.h
    tls/security.cpp

    tcp/socket.cpp
    tcp/client.cpp
    tcp/server.cpp

    udp/socket.cpp
    udp/client.cpp
    udp/server.cpp
 
    http/router.h
    http/router.cpp
    
    sockenum.h

    dtls/security.cpp
    dtls/security.h
    dtls/dtls_bio.h
    dtls/dtls_bio.cpp
    dtls/cookie.h
)

# Include directories
target_include_directories(netpp PUBLIC 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include>
)
target_include_directories(netpp PRIVATE ${OPENSSL_INCLUDE_DIR})

# Link libraries
target_link_libraries(netpp PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
)

# If building Shared (DLL), we need exports. If Static, we need the static flag.
if(BUILD_SHARED_LIBS)
    target_compile_definitions(netpp PRIVATE NETPP_EXPORTS NETPP_SHARED)
else()
    target_compile_definitions(netpp PRIVATE NETPP_STATIC)
endif()

# Add preprocessor definitions
target_compile_definitions(netpp PRIVATE
    $<$<CONFIG:Debug>:_DEBUG;_CONSOLE;>
    $<$<CONFIG:Release>:NDEBUG;_CONSOLE;>
)

if (NETPP_SKIP_TLS_CERT_VERIFY)
    target_compile_definitions(netpp PRIVATE NETPP_SKIP_TLS_CERT_VERIFY)
endif()

# This allows you to run "cmake --install ." to export to a specific folder
install(TARGETS netpp
    RUNTIME DESTINATION bin    # DLLs go here
    LIBRARY DESTINATION lib    # Linux .so goes here
    ARCHIVE DESTINATION lib    # Windows .lib (static) goes here
)

# Install headers so other projects can use the library
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/ DESTINATION include/netpp
    FILES_MATCHING PATTERN "*.h"
)

# Set output directories
# set_target_properties(netpp PROPERTIES
#     RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/Application
#     RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/Application
# )

# Print cmake info
message(STATUS "\n")
if (NETPP_STATIC)
message(STATUS "-------- netpp (STATIC) ---------")
else()
message(STATUS "-------- netpp (SHARED) ---------")
endif()
message(STATUS "netpp Version: ${PROJECT_VERSION}")
message(STATUS "netpp Source Dir: ${CMAKE_CURRENT_SOURCE_DIR}")
message(STATUS "netpp Build Dir: ${CMAKE_CURRENT_BINARY_DIR}")
if (NETPP_SKIP_TLS_CERT_VERIFY)
    message(STATUS "NETPP_SKIP_TLS_CERT_VERIFY: TRUE")
else()
    message(STATUS "NETPP_SKIP_TLS_CERT_VERIFY: FALSE")
endif()
message(STATUS "-----------------------------------")
message(STATUS "OpenSSL Include Dir: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL Libraries:")
foreach(lib ${OPENSSL_LIBRARIES})
    message(STATUS "  - ${lib}")
endforeach()
message(STATUS "OpenSSL Version: ${OPENSSL_VERSION}")
message(STATUS "OpenSSL Static Libs: ${OPENSSL_USE_STATIC_LIBS}")
message(STATUS "-----------------------------------\n")