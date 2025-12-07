cmake_minimum_required(VERSION 3.14)

# Project name and version
project(Webfetch VERSION 1.0 LANGUAGES CXX)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(OpenSSL REQUIRED)

# Define the executable
add_executable(Webfetch "client.cpp")

# Include directories
target_include_directories(Webfetch PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}../../netpp
    ${CMAKE_CURRENT_SOURCE_DIR}../../vcpkg_installed/x64-windows/include
)

target_link_directories(Webfetch PRIVATE ${CMAKE_BINARY_DIR}/Application)

target_link_libraries(Webfetch PRIVATE OpenSSL::SSL)
target_link_libraries(Webfetch PRIVATE OpenSSL::Crypto)

# Link libraries
target_link_libraries(Webfetch PRIVATE
    netpp
    Crypt32.lib
)

# Add preprocessor definitions
target_compile_definitions(Webfetch PRIVATE
    $<$<CONFIG:Debug>:_DEBUG;_CONSOLE;>
    $<$<CONFIG:Release>:NDEBUG;_CONSOLE;>
)

# Set output directories
set_target_properties(Webfetch PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/Application/Webfetch
    RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/Application/Webfetch
)

# Copy the cert files to the output directory
file(GLOB CERT_FILES "${CMAKE_CURRENT_SOURCE_DIR}/cert/*")
foreach(CERT_FILE ${CERT_FILES})
    get_filename_component(CERT_FILE_NAME ${CERT_FILE} NAME)
    add_custom_command(TARGET ChatServer POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CERT_FILE}"
        "${CMAKE_BINARY_DIR}/Application/Webfetch/cert/${CERT_FILE_NAME}"
    )
endforeach()