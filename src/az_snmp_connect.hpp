#pragma once

#include <vector>
#include <memory>
#include <functional>
#include <cstring>
#include <unistd.h>

#include "../src/az_snmp_intfs.hpp"

namespace SnmpServer {

/**
 * @brief Concrete Network Manager for UDP.
 * Inherits from ConnectIntf.
 */
class ConnectMgr : public ConnectIntf {
private:
    const int MAX_UDP_SIZE = 1500;

public:
    inline int init_socket(int port) override {
        int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) throw std::runtime_error("Failed to create socket.");

        sockaddr_in servaddr;
        std::memset(&servaddr, 0, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(port);
        servaddr.sin_addr.s_addr = INADDR_ANY;

        if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
            close(sockfd);
            throw std::runtime_error("Failed to bind socket (Port " + std::to_string(port) + " may be in use).");
        }
        return sockfd;
    }

    inline void send(int sock_fd, const std::vector<uint8_t>& data, const sockaddr_in& addr) override {
        sendto(sock_fd, data.data(), data.size(), 0, (const struct sockaddr *)&addr, sizeof(addr));
    }

    inline std::unique_ptr<SnmpPacketContext> receive(int sock_fd) override {
        auto context = std::make_unique<SnmpPacketContext>();
        context->raw_data.resize(MAX_UDP_SIZE);
        socklen_t addr_len = sizeof(context->client_addr);

        // Blocking call to receive the packet
        ssize_t bytes_received = recvfrom(
            sock_fd, context->raw_data.data(), MAX_UDP_SIZE, 0,
            (struct sockaddr *)&context->client_addr, &addr_len
        );

        if (bytes_received > 0) {
            context->raw_data.resize(bytes_received);
            return context;
        }
        return nullptr;
    }
};

} //SnmpServer