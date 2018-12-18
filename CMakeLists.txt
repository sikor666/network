cmake_minimum_required(VERSION 3.8)

project(network)

# Setting the C++ standard directly
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Add include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/common)

# Create files lists
file(GLOB_RECURSE SRC_COMMON
    "${CMAKE_CURRENT_SOURCE_DIR}/src/common/*.*"
)

# Add the executable
add_executable(checkopts src/checkopts.cpp
                         src/winsock.cpp
                         src/wrapsock.cpp
                         src/error.cpp
                         ${SRC_COMMON})

# Add source groups in project
source_group("common" FILES ${SRC_COMMON})

# Add link libraries
if(CMAKE_SYSTEM_NAME MATCHES "Windows")
target_link_libraries(checkopts LINK_PRIVATE Ws2_32)
endif()
