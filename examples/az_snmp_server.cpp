
#include "../src/az_snmp_connect.hpp"
#include "../src/az_snmp_mib.hpp"
#include "../src/az_snmp_thread_poll.hpp"
#include "../src/az_snmp_listener.hpp"

#include <iostream>

/**
 * @brief Main function demonstrating the setup and dependency injection.
 */
int main_snmp_server_example() {
    using namespace SnmpServer;
    const int TEST_PORT = 10161;

    std::cout << "--- Initializing Modular Header-Only SNMP Server ---" << std::endl;

    try {
        // Concrete Components Instantiation
        ConnectMgr connectMgmt;
        ThreadPoll threadPool(4);

        // Initializing MIB-II system group objects for testing
        MibMgr mibMgr;
        mibMgr.create({1,3,6,1,2,1,1,1,0}, "SNMP Server C++ Header-Only Library"); // sysDescr
        mibMgr.create({1,3,6,1,2,1,1,5,0}, "HOSNMP_AGENT_ALPHA");                 // sysName
        mibMgr.create({1,3,6,1,4,1,121,1,1}, int64_t{111}); // User custom
        mibMgr.create({1,3,6,1,4,1,121,1,2}, int64_t{222}); // User custom
        mibMgr.create({1,3,6,1,4,1,121,1,3}, int64_t{333}); // User custom
        mibMgr.create({1,3,6,1,4,1,121,1,4}, int64_t{444}); // User custom

        mibMgr.dumpData();

        // Dependency Injection: Injecting concrete objects via interface pointers
        SnmpListener snmpListener(&connectMgmt, &threadPool, &mibMgr);

        // Start the server
        snmpListener.start(TEST_PORT);
        std::cout << "SNMP Agent running on UDP port " << TEST_PORT << std::endl;
        std::cout << "Ready to receive requests...Test with:\n\
        snmpget -v 1 -c public localhost:10161 1.3.6.1.2.1.1.1.0\n\
        snmpwalk -v 1 -c public localhost:10161 1.3.6.1.4.1.121" << std::endl;

        // Keep the main thread running (blocking for a duration)
        std::this_thread::sleep_for(std::chrono::seconds(30));

        // 4. Clean Shutdown
        snmpListener.stop();

    } catch (const std::exception& e) {
        std::cerr << "FATAL Initialization Error: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "--- SNMP Server shut down gracefully. ---" << std::endl;
    return 0;
}

int main()
{
    return main_snmp_server_example();
}