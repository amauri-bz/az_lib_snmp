#pragma once
#include <iostream>
#include <vector>
#include <arpa/inet.h>
#include <string>
#include <iomanip>

namespace SnmpServer {

using OID = std::vector<unsigned int>;

/**
 * @brief SNMP Request Context (Data exchanged between threads).
 * Uses unique_ptr for clear ownership transfer from Listener to Worker.
 */
struct SnmpPacketContext {
    std::vector<uint8_t> raw_data;
    sockaddr_in client_addr;
};

/**
 * @brief Prints the contents of any byte container (vector or array) in hexadecimal format.
 * @param buffer The byte container (vector or array).
 * @param separator The separator to be used between the bytes (e.g., " " or "").
 */
template <typename Container>
void print_hex_buffer(const Container& buffer, const std::string& message = " ", const std::string& separator = " ") {
    std::ios state(nullptr);
    state.copyfmt(std::cout);

    std::cout << message << "Buffer Hex [" << buffer.size() << " bytes]: ";

    std::cout << std::hex << std::uppercase << std::setfill('0');

    for (const auto& byte : buffer) {
        std::cout << std::setw(2) << static_cast<int>(byte) << separator;
    }

    std::cout << "\n";

    std::cout.copyfmt(state);
}

} //SnmpServer