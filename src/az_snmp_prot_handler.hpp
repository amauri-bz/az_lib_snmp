#pragma once

#include <iostream>
#include <optional>

#include "az_snmp_global.hpp"

namespace SnmpServer {

/**
 * @brief Handles ASN.1/BER encoding/decoding and PDU parsing/construction.
 */
class SnmpProtocolHandler {
private:
    MibIntf* mib_service;

public:

    SnmpProtocolHandler(MibIntf* mib_ptr) {
        mib_service = mib_ptr;
    }

    //==============================================
    // DECODING
    //==============================================

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

        std::cerr << "[Decode] start readTlv index " << index << "\n";

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

        printTlv({type, len, value}, "[Decode] ", true);

        return {type, len, value};
    }

    /**
     * @brief Internal vars data parser
     */
    inline bool process_oid_sequence(const std::vector<uint8_t>& raw_data, SnmpPdu& data, size_t& index) {
        std::cout << "[Decode] start process_oid_sequence" << " index:" << index << "\n";

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
        std::cout << "[Decode] start process_var_sequence" << " index:" << index << "\n";

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
        std::cout << "[Decode] start process_pdu_sequence" << " index:" << index << "\n";

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
        std::cout << "[Decode] start process_request\n";

        SnmpPdu data{};
        size_t index = {0};
        process_pdu_sequence(raw_data, data, index);

        return data;
    }


    //==============================================
    // ENCODING
    //==============================================
    /**
    * Encodes an INTEGER
    */
    inline std::vector<uint8_t> encodeInteger(int value) {
        std::vector<uint8_t> out;
        out.push_back(0x02); // INTEGER tag
        out.push_back(4);    // length (4 bytes)
        out.push_back((value >> 24) & 0xFF);
        out.push_back((value >> 16) & 0xFF);
        out.push_back((value >> 8) & 0xFF);
        out.push_back(value & 0xFF);
        return out;
    }

    /**
    * @brief Encodes an OCTET STRING
    */
    inline std::vector<uint8_t> encodeOctetString(const std::string& s) {
        std::vector<uint8_t> out;
        out.push_back(0x04); // OCTET STRING tag
        out.push_back(static_cast<uint8_t>(s.size()));
        out.insert(out.end(), s.begin(), s.end());
        return out;
    }

    /**
    * @brief @brief Encodes an NULL
    */
    inline std::vector<uint8_t> encodeNull() {
        return {0x05, 0x00};
    }

    /**
    * @brief @brief Encodes an NULL
    */
    inline std::vector<uint8_t> encodeError(ErrorCode errorId) {
        return {errorId, 0x00};
    }

    /**
    * @brief Encodes an OID
    */
    inline std::vector<uint8_t> encodeOid(const OID& oid) {
        std::vector<uint8_t> out;
        out.push_back(0x06); // OBJECT IDENTIFIER tag

        std::vector<uint8_t> body;
        if (oid.size() >= 2) {
            body.push_back(oid[0] * 40 + oid[1]); // ASN.1 role
            for (size_t i = 2; i < oid.size(); ++i) {
                body.push_back(static_cast<uint8_t>(oid[i]));
            }
        }
        out.push_back(static_cast<uint8_t>(body.size()));
        out.insert(out.end(), body.begin(), body.end());
        return out;
    }

    /**
    * @brief Function to encapsulate SEQUENCE
    */
    inline std::vector<uint8_t> encodeSequence(const std::vector<uint8_t>& content) {
        std::vector<uint8_t> out;
        out.push_back(0x30); // SEQUENCE tag
        out.push_back(static_cast<uint8_t>(content.size()));
        out.insert(out.end(), content.begin(), content.end());
        return out;
    }

    /**
     * @brief Build a SNMP buffer from a SnmpPdu
     */
    inline std::vector<uint8_t> buildSnmpPdu(const SnmpPdu& pdu) {

        DataType cmd_type{DataType::VAL_NULL};
        if(pdu.command == DataTypeToString(DataType::GET_REQUEST)) {
            cmd_type = DataType::GET_REQUEST;
        } else if(pdu.command == DataTypeToString(DataType::GET_NEXT_REQUEST)) {
            cmd_type = DataType::GET_NEXT_REQUEST;
        }

        std::vector<uint8_t> version = encodeInteger(pdu.version);
        std::vector<uint8_t> community = encodeOctetString(pdu.community);

        // Request ID, Error Status, Error Index
        std::vector<uint8_t> reqId = encodeInteger(pdu.req_id);
        std::vector<uint8_t> errStatus = encodeInteger(pdu.err_status);
        std::vector<uint8_t> errIdx = encodeInteger(pdu.err_idx);

        // VarBindList
        std::vector<uint8_t> varbindsContent;
        for (const auto& var : pdu.vars) {
            // Read value from the MIB (via injected interface)
            std::vector<uint8_t> oid{};
            SnmpVariant mib_value{};
            if(cmd_type == DataType::GET_REQUEST) {
                mib_value = mib_service->read(var.oid);
                oid = encodeOid(var.oid);

                printOid(var.oid, "[Encode] MIB READ_NEXT OID: ", true);
                printVariant(mib_value, "[Encode] MIB READ Value: ", true);

            } else if(cmd_type == DataType::GET_NEXT_REQUEST) {
                auto tmp_var = mib_service->read_next(var.oid);
                auto tmp_oid = std::get<0>(tmp_var);
                mib_value = std::get<1>(tmp_var);
                oid = encodeOid(tmp_oid);

                printOid(tmp_oid, "[Encode] MIB READ_NEXT OID: ", true);
                printVariant(mib_value, "[Encode] MIB READ_NEXT Value: ", true);
            }
            else {
                std::cout << "[Encode] Invalid command\n";
            }

            std::vector<uint8_t> val = encodeNull();

            if (std::holds_alternative<std::monostate>(mib_value)) {
                val = encodeNull();
            } else if (std::holds_alternative<int64_t>(mib_value)) {
                val = encodeInteger(std::get<int64_t>(mib_value));
            } else if (std::holds_alternative<std::string>(mib_value)) {
                val = encodeOctetString(std::get<std::string>(mib_value));
            } else if (std::holds_alternative<OID>(mib_value)) {
                val = encodeOid(std::get<OID>(mib_value));
            } else if (std::holds_alternative<ErrorCode>(mib_value)) {
                val = encodeError(std::get<ErrorCode>(mib_value));
            } else {
                std::cout << "[Encode] Invalid value\n";
            }

            std::vector<uint8_t> vbContent;
            vbContent.insert(vbContent.end(), oid.begin(), oid.end());
            vbContent.insert(vbContent.end(), val.begin(), val.end());
            std::vector<uint8_t> vb = encodeSequence(vbContent);
            varbindsContent.insert(varbindsContent.end(), vb.begin(), vb.end());
        }
        std::vector<uint8_t> varbindList = encodeSequence(varbindsContent);

        // Command PDU
        std::vector<uint8_t> cmdContent;
        cmdContent.insert(cmdContent.end(), reqId.begin(), reqId.end());
        cmdContent.insert(cmdContent.end(), errStatus.begin(), errStatus.end());
        cmdContent.insert(cmdContent.end(), errIdx.begin(), errIdx.end());
        cmdContent.insert(cmdContent.end(), varbindList.begin(), varbindList.end());

        std::vector<uint8_t> command;
        if(cmd_type == DataType::GET_REQUEST || cmd_type == DataType::GET_NEXT_REQUEST)
            command.push_back(static_cast<uint8_t>(DataType::GET_RESPONSE));
        command.push_back(static_cast<uint8_t>(cmdContent.size()));
        command.insert(command.end(), cmdContent.begin(), cmdContent.end());

        // SNMP Message (SEQUENCE)
        std::vector<uint8_t> messageContent;
        messageContent.insert(messageContent.end(), version.begin(), version.end());
        messageContent.insert(messageContent.end(), community.begin(), community.end());
        messageContent.insert(messageContent.end(), command.begin(), command.end());

        return encodeSequence(messageContent);
    }

    /**
     * @brief Simulates building the RESPONSE PDU and BER serialization
     */
    inline std::vector<uint8_t> resp_get(const SnmpPdu& pdu) {

        auto packet = buildSnmpPdu(pdu);

        print_hex_buffer(packet, "resp_get >>> ");

        return packet;
    }
};

} //SnmpServer