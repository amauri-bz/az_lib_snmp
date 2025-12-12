#pragma once

#include <iostream>

#include "az_snmp_global.hpp"

namespace SnmpServer {

/**
 * @brief Handles ASN.1/BER encoding/decoding and PDU parsing/construction.
 * Instantiated per-request by the WorkerTask for thread-safety.
 */
class SnmpProtocolHandler {
public:
    // Simulates protocol parsing (returns OID and request type)
    inline std::pair<OID, int> process_request(const std::vector<uint8_t>& raw_data) {
        std::cout << "    [Handler] Deserializing and processing PDU..." << std::endl;
        // Mocking a GET request for sysDescr.0
        return {{1,3,6,1,2,1,1,1,0}, 1}; // OID, Request Type (1=GET)
    }

    // Simulates building the RESPONSE PDU and BER serialization
    inline std::vector<uint8_t> resp_get(std::vector<uint8_t>& raw_data, const OID& oid, const std::string& value) {

        print_hex_buffer(raw_data, "resp_get1 >>> ");
        raw_data[13] = 0xa2; //set RESPONSE

        std::cout << "    [Handler] Building RESPONSE for OID " << oid[8] << " with value: " << value << std::endl;
        return raw_data;
    }

    ///TODO: - resp_get_next()
    ///TODO: - resp_get_bulk()
    ///TODO: - asn1_oid()
};

} //SnmpServer