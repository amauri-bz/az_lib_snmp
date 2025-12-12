
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
        // 1. Concrete Components Instantiation
        // These are the actual implementations being used
        ConnectMgr connectMgmt;
        MibMgr mibMgr;
        ThreadPoll threadPool(4);

        // 2. Dependency Injection: Injecting concrete objects via interface pointers
        SnmpListener snmpListener(&connectMgmt, &threadPool, &mibMgr);

        // 3. Start the server
        snmpListener.start(TEST_PORT);
        std::cout << "SNMP Agent running on UDP port " << TEST_PORT << std::endl;
        std::cout << "Ready to receive requests... (Test with snmpget -v 1 -c public localhost:10161 1.3.6.1.2.1.1.1.0)" << std::endl;

        // Keep the main thread running (blocking for a duration)
        std::this_thread::sleep_for(std::chrono::seconds(20));

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