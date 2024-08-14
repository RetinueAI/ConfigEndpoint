cmake_minimum_required(VERSION 3.10)

# Set the project name and version
project(ConfigEndpoint VERSION 1.0)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

#Find and include Boost
find_package(Boost REQUIRED COMPONENTS system thread)

# Find and include jsoncpp
find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONCPP jsoncpp)

# Find and include OpenSSL
find_package(OpenSSL REQUIRED)

# Add the executable
add_executable(ConfigEndpoint src/main.cpp)

# Include directories
target_include_directories(ConfigEndpoint PUBLIC 
    ${Boost_INCLUDE_DIRS} 
    ${JSONCPP_INCLUDE_DIRS} 
    ${OPENSSL_INCLUDE_DIRS}
    "${CMAKE_SOURCE_DIR}/third_party/jwt-cpp/include"
)

# Link libraries
target_link_libraries(ConfigEndpoint 
    ${Boost_LIBRARIES} 
    ${JSONCPP_LIBRARIES} 
    OpenSSL::SSL 
    OpenSSL::Crypto
)