#pragma once

#include <iostream>
#include <optional>

#include "az_snmp_global.hpp"

namespace SnmpServer {

/**
 * @brief Handles ASN.1/BER encoding/decoding and PDU parsing/construction.
 */
class SnmpProtocolHandler {
public:

    /**
     * @brief String value parser
     */
    inline std::string parseOctetString(const std::vector<uint8_t>& raw_data, const uint8_t len,  size_t& index) {
        std::string result(reinterpret_cast<const char*>(&raw_data[index]), len);
        index += len;
        return result;
    }

    /**
     * @brief Integral value parser
     */
    inline int parseInt(const std::vector<uint8_t>& raw_data, const uint8_t len, size_t& index) {
        int value = 0;
        for (int i = 0; i < len; ++i) {
            value = (value << 8) | raw_data[index++];
        }
        return value;
    }

    /**
     * @brief Object Identifier parser
     */
    inline OID parseOid(const std::vector<uint8_t>& raw_data, const uint8_t len, size_t& index) {
        OID oid;
        uint8_t first = raw_data[index++];
        oid.push_back(first / 40);
        oid.push_back(first % 40);

        size_t end = index + (len - 1);
        while (index < end) {
            uint32_t subid = 0;
            while (true) {
                uint8_t byte = raw_data[index++];
                subid = (subid << 7) | (byte & 0x7F);
                if ((byte & 0x80) == 0) break;
            }
            oid.push_back(subid);
        }

        return oid;
    }

    /**
     * @brief TLV processor
     */
    inline std::tuple<std::optional<DataType>, uint8_t, SnmpVariant> readTlv(const std::vector<uint8_t>& raw_data, size_t& index) {

        std::optional<DataType> type {std::nullopt};
        uint8_t len{0u};
        SnmpVariant value{};

        if (raw_data.size() == 0 || index > raw_data.size()) {
            std::cerr << "Erro: buffer is empty or invalid index\n";
            return {type, len, value};
        }

        std::cerr << "[Handler] start readTlv index " << index << "\n";

        switch (raw_data[index++]) {
            case 0x02: type = DataType::INTEGER;          break;
            case 0x04: type = DataType::OCTET_STRING;     break;
            case 0x05: type = DataType::VAL_NULL;         break;
            case 0x06: type = DataType::OBJECT_ID;        break;
            case 0x30: type = DataType::SEQUENCE;         break;
            case 0xA0: type = DataType::GET_REQUEST;      break;
            case 0xA1: type = DataType::GET_NEXT_REQUEST; break;
            case 0xA2: type = DataType::GET_RESPONSE;     break;
            case 0xA3: type = DataType::SET_REQUEST;      break;
            case 0xA4: type = DataType::TRAP;             break;
            default:   type = std::nullopt;               break;
        }

        len = static_cast<uint8_t>(raw_data[index++]);

        std::string debugType{""};

        switch(*type) {
            case DataType::INTEGER:
                debugType = "DataType::INTEGER";
                value = parseInt(raw_data, len, index);
            break;
            case DataType::OCTET_STRING:
                debugType = "DataType::OCTET_STRING";
                value = parseOctetString(raw_data, len, index);
            break;
            case DataType::VAL_NULL:
                debugType = "DataType::VAL_NULL";
            break;
            case DataType::OBJECT_ID:
                debugType = "DataType::OBJECT_ID";
                value = parseOid(raw_data, len, index);
            break;
            case DataType::SEQUENCE:
                debugType = "DataType::SEQUENCE";
            break;
            case DataType::GET_REQUEST:
                debugType = "DataType::GET_REQUEST";
                value = "GET_REQUEST";
            break;
            case DataType::GET_NEXT_REQUEST:
                debugType = "DataType::GET_NEXT_REQUEST";
                value  = "GET_NEXT_REQUEST";
            break;
            case DataType::SET_REQUEST:
                debugType = "DataType::SET_REQUEST";
                value  = "SET_REQUEST";
            break;
        }

        printTlv({type, len, value});

        return {type, len, value};
    }

    /**
     * @brief Internal vars data parser
     */
    inline bool process_oid_sequence(const std::vector<uint8_t>& raw_data, SnmpPdu& data, size_t& index) {
        std::cout << "[Handler] start process_oid_sequence" << " index:" << index << "\n";

        if (raw_data.size() == 0) {
            std::cerr << "Erro: buffer is empty or invalid index\n";
            return false;
        }
        if (index > raw_data.size())
            return true;

        SnmpValue var{};
        std::optional<DataType> type{};
        uint8_t len{};
        SnmpVariant value{};

        std::tie(type, len, value) = readTlv(raw_data, index);
        if(type && *type!=DataType::SEQUENCE)
            return false;

        // OID
        std::tie(type, len, value) = readTlv(raw_data, index);
        if(type && *type == DataType::OBJECT_ID)
            var.oid = std::get<OID>(value);
        else
            return false;

        // value
        std::tie(type, len, value) = readTlv(raw_data, index);
        if(type && *type == DataType::VAL_NULL)
            var.value = std::monostate{};
        else if(type && *type == DataType::INTEGER)
            var.value  = std::get<int64_t>(value);
        else if(type && *type == DataType::OCTET_STRING)
            var.value = std::get<std::string>(value);
        else
            return false;

        data.vars.push_back(var);

         // Vars
        std::tie(type, len, value) = readTlv(raw_data, index);
        if(type && *type == DataType::SEQUENCE) {
            index -= 2;
            process_var_sequence(raw_data, data, index);
        }

        return true;
    }

    /**
     * @brief Internal vars data parser
     */
    inline bool process_var_sequence(const std::vector<uint8_t>& raw_data, SnmpPdu& data, size_t& index) {
        std::cout << "[Handler] start process_var_sequence" << " index:" << index << "\n";

        if (raw_data.size() == 0) {
            std::cerr << "Erro: buffer is empty or invalid index\n";
            return false;
        }
        if (index > raw_data.size())
            return true;

        SnmpValue var{};
        std::optional<DataType> type{};
        uint8_t len{};
        SnmpVariant value{};

         // Vars
        std::tie(type, len, value) = readTlv(raw_data, index);
        if(type && *type == DataType::SEQUENCE) {
             process_oid_sequence(raw_data, data, index);
        }

        return true;
    }

    /**
     * @brief Data frame parser
     */
    inline bool process_pdu_sequence(const std::vector<uint8_t>& raw_data, SnmpPdu& data, size_t& index) {
        std::cout << "[Handler] start process_pdu_sequence" << " index:" << index << "\n";

        if (raw_data.size() == 0) {
            std::cerr << "Erro: buffer is empty or invalid index\n";
            return false;
        }
        if (index > raw_data.size())
            return true;

        print_hex_buffer(raw_data, "process_pdu_sequence >> ");

        std::optional<DataType> type{};
        uint8_t len{};
        SnmpVariant value{};

        std::tie(type, len, value) = readTlv(raw_data, index);
        if(type && *type!=DataType::SEQUENCE)
            return false;

        // Version
        std::tie(type, len, value) = readTlv(raw_data, index);
        if(type && *type == DataType::INTEGER)
            data.version = std::get<int64_t>(value);
        else
            return false;

        // Community
        std::tie(type, len, value) = readTlv(raw_data, index);
        if(type && *type == DataType::OCTET_STRING)
            data.community = std::get<std::string>(value);
        else
            return false;

        // Command
        std::tie(type, len, value) = readTlv(raw_data, index);
        if(type && *type == DataType::GET_REQUEST || type == DataType::GET_NEXT_REQUEST || type == DataType::SET_REQUEST)
            data.command = std::get<std::string>(value);
        else
            return false;

        // Req_id
        std::tie(type, len, value) = readTlv(raw_data, index);
        if(type && *type == DataType::INTEGER)
            data.req_id  = std::get<int64_t>(value);
        else
            return false;

        // Err_status
        std::tie(type, len, value) = readTlv(raw_data, index);
        if(type && *type == DataType::INTEGER)
            data.err_status  = std::get<int64_t>(value);
        else
            return false;

        // Err_idx
        std::tie(type, len, value) = readTlv(raw_data, index);
        if(type && *type == DataType::INTEGER)
            data.err_idx = std::get<int64_t>(value);
        else
            return false;

        // Vars
        std::tie(type, len, value) = readTlv(raw_data, index);
        if(type && *type == DataType::SEQUENCE) {
            index -= 2;
            process_var_sequence(raw_data, data, index);
        }

        printSnmpPdu(data);

        return true;
    }

    /**
     * @brief protocol parsing
     */
    inline SnmpPdu process_request(const std::vector<uint8_t>& raw_data) {
        std::cout << "[Handler] start process_request\n";

        SnmpPdu data{};
        size_t index = {0};
        process_pdu_sequence(raw_data, data, index);

        return data;
    }

    /**
     * @brief Simulates building the RESPONSE PDU and BER serialization
     */
    inline std::vector<uint8_t> resp_get(std::vector<uint8_t>& raw_data, const OID& oid, const std::string& value) {

        print_hex_buffer(raw_data, "resp_get >>> ");
        raw_data[13] = 0xa2; //set RESPONSE

        std::cout << "[Handler] Building RESPONSE for OID " << oid[8] << " with value: " << value << std::endl;
        return raw_data;
    }

    ///TODO: - resp_get_next()
    ///TODO: - resp_get_bulk()
};

} //SnmpServer