# FTP Packet Inspector & Extractor

A C++ utility that analyzes raw PCAP network traffic, reconstructs FTP file transfers, and extracts files based on TCP stream analysis.

## 🚀 Features

*   **FTP Analysis:** Uses `libpcap` to parse raw Ethernet, IP, and TCP headers.
*   **State Machine Architecture:** Separates the Control Plane (Port 21) from the Data Plane to handle multi-file streams.
*   **Magic Byte Detection:** Identifies binary file types (ELF, PDF, PNG, ZIP) even if the filename lacks an extension.
*   **Statistical Reporting:** Generates a post-analysis report of file types transmitted.

## 🛠️ Prerequisites

*   Linux Environment (Ubuntu/Debian or WSL2)
*   C++17 Compiler
*   libpcap-dev

```bash
sudo apt-get update
sudo apt-get install build-essential libpcap-dev cmake
```



## Steps to build and run the program

# using CMake
```
mkdir build && cd build
cmake ..
make
./ftp_inspector ../traffic.pcap
```

# Manual Compilation
```
g++ -o ftp_inspector src/main.cpp
./ftp_inspector traffic.pcap
```


## Screenshots

### Starting TCP Dump

<img width="1685" height="445" alt="Start TCP Dump" src="https://github.com/user-attachments/assets/1b9355be-3a48-4445-97c4-fe847d960412" />

### Files Shared over FTP

<img width="1882" height="930" alt="Files Shared over FTP" src="https://github.com/user-attachments/assets/11b5414e-70a0-41c5-a7a7-ddd974178c6c" />

### Final OutPut - Report

<img width="1581" height="757" alt="OutPut" src="https://github.com/user-attachments/assets/a1be8ec8-fdf3-4182-b6c7-c014189dd87c" />



