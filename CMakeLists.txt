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

file(GLOB_RECURSE SRC_SYSTEM
    "${CMAKE_CURRENT_SOURCE_DIR}/src/system/*.*"
)

file(GLOB_RECURSE SRC_UDP
    "${CMAKE_CURRENT_SOURCE_DIR}/src/udp/*.*"
)

# Add the executable
add_executable(checkopts src/checkopts.cpp ${SRC_COMMON} ${SRC_SYSTEM})
add_executable(byteorder src/byteorder.cpp ${SRC_COMMON})
add_executable(stun src/stun.cpp ${SRC_UDP} ${SRC_COMMON} ${SRC_SYSTEM})

# Add source groups in project
source_group("common" FILES ${SRC_COMMON})
source_group("system" FILES ${SRC_SYSTEM})
source_group("udp"    FILES ${SRC_UDP})

# Add link libraries
if(CMAKE_SYSTEM_NAME MATCHES "Windows")
target_link_libraries(checkopts LINK_PRIVATE Ws2_32)
target_link_libraries(stun LINK_PRIVATE Ws2_32)
endif()
