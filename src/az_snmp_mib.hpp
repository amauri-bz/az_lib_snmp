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
    std::map<std::string, std::string> data;

    std::string oid_to_str(const OID& oid) {
        std::stringstream ss;
        for (const auto& num : oid) ss << "." << num;
        return ss.str();
    }

public:
    MibMgr() {
        // Initializing MIB-II system group objects for testing
        create({1,3,6,1,2,1,1,1,0}, "SNMP Server C++ Header-Only Library"); // sysDescr
        create({1,3,6,1,2,1,1,5,0}, "HOSNMP_AGENT_ALPHA");                 // sysName
    }

    inline void create(const OID& oid, const std::string& value) override {
        data[oid_to_str(oid)] = value;
    }

    inline std::string read(const OID& oid) override {
        auto it = data.find(oid_to_str(oid));
        if (it != data.end()) {
            return it->second;
        }
        return "OID Not Found";
    }

    inline void update(const OID& oid, const std::string& value) override {
        data[oid_to_str(oid)] = value;
    }

    inline void delete_oid(const OID& oid) override {
        data.erase(oid_to_str(oid));
    }
};

} //SnmpServer