cmake_minimum_required(VERSION 3.14)

# Root project name
project(netpp_project VERSION 1.0 LANGUAGES CXX)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(NETPP_SKIP_TLS_CERT_VERIFY False CACHE BOOL "Setting this to true makes it so the TLS layer skips certificate verification for the server and clients.")

# Add subdirectories for subprojects
add_subdirectory(netpp)
add_subdirectory(examples)
