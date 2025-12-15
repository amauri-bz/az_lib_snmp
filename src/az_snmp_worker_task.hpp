#pragma once

#include "az_snmp_global.hpp"
#include "az_snmp_prot_handler.hpp"

namespace SnmpServer {

/**
 * @brief The actual logic executed by the worker threads.
 * Receives all necessary dependencies (Context, Mib, Connect)
 */
inline void WorkerTask(
    std::shared_ptr<SnmpPacketContext> context,
    MibIntf* mib_service,
    ConnectIntf* connect_service,
    int listener_socket_fd
) {
    // Handler is instantiated inside the worker for complete thread-safety
    SnmpProtocolHandler handler;

    try {
        std::cout << "[Worker] Processing request from: "
                  << inet_ntoa(context->client_addr.sin_addr)
                  << " on thread " << std::this_thread::get_id() << std::endl;

        // Deserialize the request
        auto snmp_pdu = handler.process_request(context->raw_data);

        // Read value from the MIB (via injected interface)
        std::string mib_value = mib_service->read(snmp_pdu.vars.at(0).oid);

        // Serialize the Response PDU
        std::vector<uint8_t> response_data = handler.resp_get(context->raw_data, snmp_pdu.vars.at(0).oid, mib_value);

        // Send the response back (via injected interface and context address)
        connect_service->send(listener_socket_fd, response_data, context->client_addr);
        std::cout << "[Worker] Response sent successfully." << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "WORKER ERROR: " << e.what() << std::endl;
    }
}

} //SnmpServer