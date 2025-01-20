cmake_minimum_required(VERSION 3.10)

# Set the project name
project(pdf-extract)

# Specify the C++ standard to use
set(CMAKE_CXX_STANDARD 17)

# Find OpenSSL package
find_package(OpenSSL REQUIRED)

# Add the executable
add_executable(pdf-extract main.cpp)

# Link OpenSSL libraries
target_link_libraries(pdf-extract OpenSSL::Crypto OpenSSL::SSL)

