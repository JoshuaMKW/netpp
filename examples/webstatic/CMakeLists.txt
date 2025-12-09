cmake_minimum_required(VERSION 3.14)

# Project name and version
project(Webstatic VERSION 1.0 LANGUAGES CXX)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(OpenSSL REQUIRED)

# Define the executable
add_executable(Webstatic "server.cpp")

# Include directories
target_include_directories(Webstatic PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}../../netpp
    ${CMAKE_CURRENT_SOURCE_DIR}../../vcpkg_installed/x64-windows/include
)

target_link_directories(Webstatic PRIVATE ${CMAKE_BINARY_DIR}/Application)

target_link_libraries(Webstatic PRIVATE OpenSSL::SSL)
target_link_libraries(Webstatic PRIVATE OpenSSL::Crypto)

# Link libraries
target_link_libraries(Webstatic PRIVATE
    netpp
    Crypt32.lib
)

# Add preprocessor definitions
target_compile_definitions(Webstatic PRIVATE
    $<$<CONFIG:Debug>:_DEBUG;_CONSOLE;>
    $<$<CONFIG:Release>:NDEBUG;_CONSOLE;>
)

# Set output directories
set_target_properties(Webstatic PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/Application/Webstatic
    RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/Application/Webstatic
)

# Copy the HTML files to the output directory
file(GLOB HTML_FILES "${CMAKE_CURRENT_SOURCE_DIR}/webdata/*")
foreach(HTML_FILE ${HTML_FILES})
    get_filename_component(HTML_FILE_NAME ${HTML_FILE} NAME)
    add_custom_command(TARGET Webstatic POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${HTML_FILE}"
        "${CMAKE_BINARY_DIR}/Application/Webstatic/webdata/${HTML_FILE_NAME}"
    )
endforeach()

# Copy the cert files to the output directory
file(GLOB CERT_FILES "${CMAKE_CURRENT_SOURCE_DIR}/cert/*")
foreach(CERT_FILE ${CERT_FILES})
    get_filename_component(CERT_FILE_NAME ${CERT_FILE} NAME)
    add_custom_command(TARGET Webstatic POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CERT_FILE}"
        "${CMAKE_BINARY_DIR}/Application/Webstatic/cert/${CERT_FILE_NAME}"
    )
endforeach()