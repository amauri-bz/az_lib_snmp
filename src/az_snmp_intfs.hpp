#pragma once

#include "../src/az_snmp_global.hpp"

namespace SnmpServer {

/**
 * @brief Interface for MIB (Management Information Base) access.
 * Allows swapping between in-memory, SQLite, or other storage.
 */
class MibIntf {
public:
    virtual ~MibIntf() = default;
    virtual void create(const OID& oid, const std::string& value) = 0;
    virtual std::string read(const OID& oid) = 0;
    virtual void update(const OID& oid, const std::string& value) = 0;
    virtual void delete_oid(const OID& oid) = 0;
};

/**
 * @brief Interface for Network Communication (Socket I/O).
 * Allows swapping between UDP, TCP, or mock connections.
 */
class ConnectIntf {
public:
    virtual ~ConnectIntf() = default;
    virtual int init_socket(int port) = 0;
    virtual void send(int sockfd, const std::vector<uint8_t>& data, const sockaddr_in& addr) = 0;
    virtual std::unique_ptr<SnmpPacketContext> receive(int sockfd) = 0;
};

/**
 * @brief Interface for the Thread Pool system.
 */
class ThreadPollIntf {
public:
    virtual ~ThreadPollIntf() = default;
    // Receives the task (lambda function) to be executed by a worker.
    virtual void enqueue(std::function<void()> task) = 0;
};

} //SnmpServer