cmake_minimum_required(VERSION 3.10)
project(FtpPacketInspector VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find Libpcap
find_library(PCAP_LIBRARY pcap)

if(NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libpcap not found! Please install it (sudo apt install libpcap-dev)")
endif()

# Add Executable
add_executable(ftp_inspector src/main.cpp)

# Link Libraries
target_link_libraries(ftp_inspector ${PCAP_LIBRARY})

message(STATUS "Build setup complete. Run 'make' to compile.")
