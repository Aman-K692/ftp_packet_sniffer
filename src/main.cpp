#include <iostream>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string>
#include <vector>
#include <fstream>
#include <cstring>
#include <map>

// Headers configuration
#define SIZE_ETHERNET 14
#define IP_HL(ip) (((ip)->ip_hl) & 0x0f)
#define TCP_OFF(th) (((th)->th_off) & 0x0f)

// --- GLOBAL STATE ---
std::ofstream current_output_file;
std::string current_filename;
std::string current_extension; // Track the current extension to allow correction
int total_files_count = 0;
std::map<std::string, int> file_type_stats; // Stores "txt" -> 2, "html" -> 1

// Helper to get extension
std::string get_extension(const std::string& filename) {
    size_t pos = filename.find_last_of(".");
    if (pos != std::string::npos && pos < filename.length() - 1) {
        return filename.substr(pos + 1);
    }
    return "unknown";
}

// Helper: Magic Byte Detection
std::string identify_magic_bytes(const u_char* payload, int len) {
    if (len < 4) return "unknown_binary";

    // ELF (Linux Binary) - 7F 45 4C 46
    if (payload[0] == 0x7F && payload[1] == 'E' && payload[2] == 'L' && payload[3] == 'F') 
        return "elf_executable";

    // PDF - 25 50 44 46
    if (payload[0] == 0x25 && payload[1] == 0x50 && payload[2] == 0x44 && payload[3] == 0x46) 
        return "pdf";

    // ZIP/JAR/APK - 50 4B 03 04
    if (payload[0] == 0x50 && payload[1] == 0x4B && payload[2] == 0x03 && payload[3] == 0x04) 
        return "zip";

    // PNG - 89 50 4E 47
    if (payload[0] == 0x89 && payload[1] == 0x50 && payload[2] == 0x4E && payload[3] == 0x47) 
        return "png";

    // JPEG - FF D8 FF
    if (payload[0] == 0xFF && payload[1] == 0xD8 && payload[2] == 0xFF) 
        return "jpg";

    return "unknown_binary";
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    
    // 1. Parsing Headers
    const struct ether_header *ethernet = (struct ether_header*)(packet);
    const struct ip *ip_header = (struct ip*)(packet + SIZE_ETHERNET);
    u_int size_ip = IP_HL(ip_header) * 4;

    if (size_ip < 20 || ip_header->ip_p != IPPROTO_TCP) return;

    const struct tcphdr *tcp_header = (struct tcphdr*)(packet + SIZE_ETHERNET + size_ip);
    u_int size_tcp = TCP_OFF(tcp_header) * 4;
    if (size_tcp < 20) return;

    const u_char *payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    int payload_length = header->len - (SIZE_ETHERNET + size_ip + size_tcp);

    if (payload_length <= 0) return;

    int src_port = ntohs(tcp_header->th_sport);
    int dst_port = ntohs(tcp_header->th_dport);

    // --- LOGIC: CONTROL CHANNEL (Port 21) ---
    // Detect "STOR" command -> New File Start
    if (dst_port == 21) {
        std::string data((char*)payload, payload_length);
        
        if (data.find("STOR ") == 0) {
            // Close previous file if open
            if (current_output_file.is_open()) {
                current_output_file.close();
                std::cout << " -> Finished extracting: " << current_filename << std::endl;
            }

            // Extract new filename
            std::string raw_name = data.substr(5);
            // Remove \r\n
            while (!raw_name.empty() && (raw_name.back() == '\n' || raw_name.back() == '\r')) {
                raw_name.pop_back();
            }
            
            current_filename = raw_name;
            total_files_count++;

            // Initial Stats Recording (Might be 'unknown' for now)
            current_extension = get_extension(current_filename);
            file_type_stats[current_extension]++;

            std::cout << "[*] New File Detected: " << current_filename << " (Initial Type: " << current_extension << ")" << std::endl;

            // Open new stream
            current_output_file.open("extracted_" + current_filename, std::ios::binary);
        }
    }

    // --- LOGIC: DATA CHANNEL ---
    else if (current_output_file.is_open() && src_port != 21 && dst_port != 21) {
        
        // --- MAGIC BYTE CORRECTION LOGIC ---
        // Check only on the very first packet of the file (size == 0)
        long current_pos = current_output_file.tellp();
        
        if (current_pos == 0) {
            std::string detected_type = identify_magic_bytes(payload, payload_length);

            // If we previously marked it as "unknown", but now we know what it is:
            if (current_extension == "unknown" && detected_type != "unknown_binary") {
                
                // 1. Decrement the 'unknown' count
                if (file_type_stats["unknown"] > 0) {
                    file_type_stats["unknown"]--;
                    // Optional: Clean up map if count hits 0
                    if (file_type_stats["unknown"] == 0) {
                        file_type_stats.erase("unknown");
                    }
                }

                // 2. Increment the real type count
                file_type_stats[detected_type]++;
                
                // 3. Update current state so we don't check again
                current_extension = detected_type;

                std::cout << " -> Magic Bytes Correction: Type updated from 'unknown' to '" << detected_type << "'" << std::endl;
            }
        }

        // Write payload to disk
        current_output_file.write((char*)payload, payload_length);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file>" << std::endl;
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(argv[1], errbuf);
    
    if (handle == nullptr) {
        std::cerr << "Error: " << errbuf << std::endl;
        return 1;
    }

    std::cout << "--- Starting Multi-File Analysis ---" << std::endl;

    pcap_loop(handle, 0, packet_handler, nullptr);

    if (current_output_file.is_open()) {
        current_output_file.close();
        std::cout << " -> Finished extracting: " << current_filename << std::endl;
    }

    pcap_close(handle);

    // --- FINAL REPORT ---
    std::cout << "\n================ REPORT ================" << std::endl;
    std::cout << "Total Files Extracted: " << total_files_count << std::endl;
    std::cout << "File Types Distribution:" << std::endl;
    for (auto const& [type, count] : file_type_stats) {
        std::cout << " - ." << type << " : " << count << " file(s)" << std::endl;
    }
    std::cout << "========================================" << std::endl;

    return 0;
}
