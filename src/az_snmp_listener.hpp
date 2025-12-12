#pragma once

#include "az_snmp_global.hpp"
#include "az_snmp_worker_task.hpp"

namespace SnmpServer {

/**
 * @brief Thread dedicated to non-blocking I/O, receiving packets and dispatching tasks.
 */
class SnmpListener {
private:
    ConnectIntf* connectMgr;
    ThreadPollIntf* threadPoll;
    MibIntf* mibMgr;

    std::thread listener_thread;
    int listener_socket_fd = -1;
    bool running = true;

    inline void run_loop() {
        while (running) {
            // 1. Receive packet (blocking call)
            std::shared_ptr<SnmpPacketContext> context = connectMgr->receive(listener_socket_fd);

            if (!running) break;

            if (context) {
                // 2. Dispatch task to the thread pool (Producer-Consumer)
                // Dependencies are captured by value (pointers to interfaces) or by move (context)
                threadPoll->enqueue([
                    context,
                    mib_service = mibMgr,
                    connect_service = connectMgr,
                    socket_fd = listener_socket_fd
                ] {
                    // 3. Call the worker logic
                    WorkerTask(
                        context,
                        mib_service,
                        connect_service,
                        socket_fd
                    );
                });
            }
        }
    }

public:
    // Dependencies are injected via the constructor
    SnmpListener(ConnectIntf* conn, ThreadPollIntf* pool, MibIntf* mib)
        : connectMgr(conn), threadPoll(pool), mibMgr(mib) {}

    inline void start(int port) {
        listener_socket_fd = connectMgr->init_socket(port);
        listener_thread = std::thread(&SnmpListener::run_loop, this);
    }

    inline void stop() {
        if (running) {
            running = false;
            // Force recvfrom() to unblock and terminate the loop
            shutdown(listener_socket_fd, SHUT_RDWR);
            if (listener_thread.joinable()) {
                listener_thread.join();
            }
            close(listener_socket_fd);
        }
    }
};

} //SnmpServer