#pragma once
#include <iostream>
#include <vector>
#include <arpa/inet.h>
#include <string>
#include <iomanip>
#include <variant>
#include <cstdint>
#include <optional>

namespace SnmpServer {

// Forward declaration
struct SnmpValue;

using OID = std::vector<uint32_t>;

/**
 * @brief SEQUENCE representation (list od values)
 */
using SnmpSequence = std::vector<SnmpValue>;

using ErrorCode = uint8_t;

/**
 * @brief Variant to cover the SNMP V1 basic types
 */
using SnmpVariant = std::variant<
    std::monostate,   // NULL
    int64_t,          // INTEGER
    std::string,      // OCTET STRING
    OID,              // OBJECT IDENTIFIER
    SnmpSequence,     // SEQUENCE
    ErrorCode         // ERROR TAG
>;

/**
 * @brief SNMP Request Context (Data exchanged between threads)
 */
struct SnmpPacketContext {
    std::vector<uint8_t> raw_data;
    sockaddr_in client_addr;
};

enum class DataType {
    INTEGER          = 0x02,
    OCTET_STRING     = 0x04,
    VAL_NULL         = 0x05,
    OBJECT_ID        = 0x06,
    SEQUENCE         = 0x30,
    NO_SUCH_NAME	 = 0x80,
    END_OF_MIB_VIEW	 = 0x82,
    NO_SUCH_OBJECT	 = 0x81,
    GET_REQUEST      = 0xA0,
    GET_NEXT_REQUEST = 0xA1,
    GET_RESPONSE     = 0xA2,
    SET_REQUEST      = 0xA3,
    TRAP             = 0xA4
};

std::string DataTypeToString(DataType dt) {
    switch (dt) {
        case DataType::INTEGER:          return "INTEGER";
        case DataType::OCTET_STRING:     return "OCTET_STRING";
        case DataType::VAL_NULL:         return "VAL_NULL";
        case DataType::OBJECT_ID:        return "OBJECT_ID";
        case DataType::SEQUENCE:         return "SEQUENCE";
        case DataType::NO_SUCH_NAME:     return "NO_SUCH_NAME";
        case DataType::END_OF_MIB_VIEW:  return "END_OF_MIB_VIEW";
        case DataType::NO_SUCH_OBJECT:   return "NO_SUCH_OBJECT";
        case DataType::GET_REQUEST:      return "GET_REQUEST";
        case DataType::GET_NEXT_REQUEST: return "GET_NEXT_REQUEST";
        case DataType::GET_RESPONSE:     return "GET_RESPONSE";
        case DataType::SET_REQUEST:      return "SET_REQUEST";
        case DataType::TRAP:             return "TRAP";
        default:                         return "UNKNOWN";
    }
}

/**
 * @brief SNMP message data encapsulation
 */
typedef struct SnmpValue {
    OID oid;
    uint8_t type;
    SnmpVariant value;
} SnmpValue;

typedef struct SnmpPdu {
    uint32_t version;
    std::string community;

    std::string command;
    uint32_t req_id;

    uint32_t err_status;
    uint32_t err_idx;

    std::vector<SnmpValue> vars;
} SnmpPdu;

/**
 * @brief Prints the contents of any byte container (vector or array) in hexadecimal format.
 * @param buffer The byte container (vector or array).
 * @param separator The separator to be used between the bytes (e.g., " " or "").
 */
template <typename Container>
inline void print_hex_buffer(const Container& buffer, const std::string& message = " ", const std::string& separator = " ") {
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

inline void printOid(const OID& oid, std::string msg = "", bool lineBreak = false) {
    std::cout << msg;
    std::cout << "{";
    for (size_t i = 0; i < oid.size(); ++i) {
        std::cout << oid[i];
        if (i + 1 < oid.size()) std::cout << ".";
    }
    std::cout << "}";

    if(lineBreak)
        std::cout << "\n";
}

inline void printVariant(const SnmpVariant& var, std::string msg = "", bool lineBreak = false) {

    std::cout << msg;

    std::visit([&](auto&& arg) {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, std::monostate>) {
            std::cout << "null(NULL)";
        } else if constexpr (std::is_same_v<T, int64_t>) {
            std::cout << arg << "(INTEGER)";
        } else if constexpr (std::is_same_v<T, std::string>) {
            std::cout << "\"" << arg << "\"" << "(OCTET STRING)";
        } else if constexpr (std::is_same_v<T, OID>) {
            printOid(arg);
            std::cout << "(OBJECT ID)";
        } else if constexpr (std::is_same_v<T, SnmpSequence>) {
            std::cout << "SEQUENCE [\n";
            for (const auto& v : arg) {
                printOid(v.oid);
                std::cout << "(OID)";
                std::cout << " type=0x" << std::hex << static_cast<int>(v.type) << std::dec << " value=";
                printVariant(v.value);
                std::cout << "\n";
            }
            std::cout << "]";
        }
    }, var);

    if(lineBreak)
        std::cout << "\n";
}

inline void printSnmpPdu(const SnmpPdu& pdu) {
    std::cout << "SNMP PDU:\n";
    std::cout << "  Version: " << pdu.version << "\n";
    std::cout << "  Community: " << pdu.community << "\n";
    std::cout << "  Command: " << pdu.command << "\n";
    std::cout << "  Request ID: " << pdu.req_id << "\n";
    std::cout << "  Error Status: " << pdu.err_status << "\n";
    std::cout << "  Error Index: " << pdu.err_idx << "\n";

    std::cout << "  Variables:\n";
    for (const auto& var : pdu.vars) {
        std::cout << "    OID=";
        printOid(var.oid);
        std::cout << " type=0x" << std::hex << static_cast<int>(var.type) << std::dec << " value=";
        printVariant(var.value);
        std::cout << "\n";
    }
}

inline void printTlv(const std::tuple<std::optional<DataType>, uint8_t, SnmpVariant>& tlv,
                std::string msg = "", bool lineBreak = false) {
    const auto& [typeOpt, len, value] = tlv;

    std::cout << msg;

    std::cout << "TLV:";

    // Tipo
    if (typeOpt) {
        std::cout << " Type: 0x" << std::hex << static_cast<int>(*typeOpt)
                << std::dec << "(" << DataTypeToString(*typeOpt) << ")";
    } else {
        std::cout << " Type: INVALID/NULL";
    }

    // Tamanho
    std::cout << " Length: " << static_cast<int>(len);

    // Valor
    std::cout << " Value: ";
    printVariant(value);

    if(lineBreak)
        std::cout << "\n";
}

} //SnmpServer