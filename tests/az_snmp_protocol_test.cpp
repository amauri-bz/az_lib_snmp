#include <vector>
#include <memory>
#include <functional>

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "../src/az_snmp_global.hpp"
#include "../src/az_snmp_mib.hpp"
#include "../src/az_snmp_prot_handler.hpp"

using namespace SnmpServer;

TEST_CASE("Process GET-REQUEST") {

    MibMgr mibMgr;
    mibMgr.create({1,3,6,1,2,1,1,1,0}, "SNMP Server C++ Header-Only Library"); // sysDescr
    auto handler = SnmpProtocolHandler(&mibMgr);

    std::vector<std::uint8_t> raw_data = {0x30,0x29,0x02,0x01,0x00,0x04,0x06,0x70,0x75,
                                          0x62,0x6C,0x69,0x63,0xA0,0x1C,0x02,0x04,0x20,
                                          0xA5,0xD3,0xE3,0x02,0x01,0x00,0x02,0x01,0x00,
                                          0x30,0x0E,0x30,0x0C,0x06,0x08,0x2B,0x06,0x01,
                                          0x02,0x01,0x01,0x01,0x00,0x05,0x00};

    SnmpPdu pdu = handler.process_request(raw_data);

    printSnmpPdu(pdu);

    REQUIRE(pdu.version == 0);
    REQUIRE(pdu.community == "public");
    REQUIRE(pdu.command == "GET_REQUEST");
    REQUIRE(pdu.req_id == 547738595);
    REQUIRE(pdu.err_status == 0);
    REQUIRE(pdu.err_idx == 0);

    OID test_oid = OID{1,3,6,1,2,1,1,1,0};
    REQUIRE((std::equal(pdu.vars.at(0).oid.begin(), pdu.vars.at(0).oid.end(), test_oid.begin())) == true);

    REQUIRE(pdu.vars.at(0).type == 0x0);

    bool test_val = (std::holds_alternative<std::monostate>(pdu.vars.at(0).value))?true:false;
    REQUIRE(test_val == true);
}


TEST_CASE("Build GET-RESPONSE") {

    MibMgr mibMgr;
    mibMgr.create({1,3,6,1,2,1,1,1,0}, "SNMP Server C++ Header-Only Library"); // sysDescr
    auto handler = SnmpProtocolHandler(&mibMgr);

    SnmpPdu pdu;
    pdu.version = 0;
    pdu.community = "public";
    pdu.command = "GET_REQUEST";
    pdu.req_id = 547738595;
    pdu.err_status = 0;
    pdu.err_idx = 0;

    SnmpValue vars;
    vars.oid = OID{1,3,6,1,2,1,1,1,0};
    vars.type = 0x0;
    pdu.vars.push_back(vars);

    std::vector<std::uint8_t> resp_msg = {0x30,0x55,0x02,0x04,0x00,0x00,0x00,0x00,0x04,
                                         0x06,0x70,0x75,0x62,0x6C,0x69,0x63,0xA2,0x45,
                                         0x02,0x04,0x20,0xA5,0xD3,0xE3,0x02,0x04,0x00,
                                         0x00,0x00,0x00,0x02,0x04,0x00,0x00,0x00,0x00,
                                         0x30,0x31,0x30,0x2F,0x06,0x08,0x2B,0x06,0x01,
                                         0x02,0x01,0x01,0x01,0x00,0x04,0x23,0x53,0x4E,
                                         0x4D,0x50,0x20,0x53,0x65,0x72,0x76,0x65,0x72,
                                         0x20,0x43,0x2B,0x2B,0x20,0x48,0x65,0x61,0x64,
                                         0x65,0x72,0x2D,0x4F,0x6E,0x6C,0x79,0x20,0x4C,
                                         0x69,0x62,0x72,0x61,0x72,0x79};

    std::vector<uint8_t> response = handler.resp_get(pdu);

    print_hex_buffer(response);

    REQUIRE((std::equal(response.begin(), response.end(), resp_msg.begin())) == true);

}