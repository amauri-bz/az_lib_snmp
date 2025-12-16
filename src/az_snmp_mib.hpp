#pragma once

#include <map>
#include <sstream>

#include "az_snmp_global.hpp"
#include "az_snmp_intfs.hpp"

namespace SnmpServer {

/**
 * @brief Concrete MIB Manager (In-Memory for simplicity).
 * Inherits from MibIntf.
 */
class MibMgr : public MibIntf {
private:
    std::map<std::string, SnmpVariant> data;

    std::string oid_to_str(const OID& oid) {
        std::stringstream ss;
        for (const auto& num : oid) ss << "." << num;
        return ss.str();
    }

    OID str_to_oid(const std::string& s) {
        OID oid;
        std::stringstream ss(s);
        std::string token;

        // Usar '.' como separador
        while (std::getline(ss, token, '.')) {
            if (!token.empty()) {
                oid.push_back(static_cast<uint32_t>(std::stoul(token)));
            }
        }
        return oid;
    }

public:
    MibMgr() = default;

    inline void dumpData() {
        std::cout << "Dump std::map<std::string, SnmpVariant>:\n";
        for (const auto& [key, value] : data) {
            std::cout << "  Key=\"" << key << "\" Value=";
            printVariant(value);
            std::cout << "\n";
        }
    }

    inline void create(const OID& oid, const SnmpVariant& value) override {
        data[oid_to_str(oid)] = value;
    }

    inline SnmpVariant read(const OID& oid) override {
        SnmpVariant ret{};
        auto it = data.find(oid_to_str(oid));
        if (it != data.end()) {
            return it->second;
        }
        return ret;
    }

    inline std::tuple<OID, SnmpVariant> read_next(const OID& oid) override {
         auto it = data.upper_bound(oid_to_str(oid));
        if (it != data.end()) {
            return {str_to_oid(it->first), it->second};
        }
        return {oid, static_cast<ErrorCode>(DataType::NO_SUCH_OBJECT)};
    }

    inline void update(const OID& oid, const SnmpVariant& value) override {
        data[oid_to_str(oid)] = value;
    }

    inline void delete_oid(const OID& oid) override {
        data.erase(oid_to_str(oid));
    }
};

} //SnmpServer