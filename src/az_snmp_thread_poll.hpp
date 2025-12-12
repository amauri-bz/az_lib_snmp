#pragma once

#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>

#include "az_snmp_global.hpp"

namespace SnmpServer {

/**
 * @brief Concrete implementation of the ThreadPollIntf.
 */
class ThreadPoll : public ThreadPollIntf {
private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex queue_mutex;
    std::condition_variable condition;
    bool stop = false;

    // The main loop executed by each worker thread
    inline void worker_loop() {
        while (true) {
            std::function<void()> task;
            {
                std::unique_lock<std::mutex> lock(queue_mutex);
                condition.wait(lock, [this]{ return stop || !tasks.empty(); });

                if (stop && tasks.empty()) return;

                task = std::move(tasks.front());
                tasks.pop();
            }
            // Execute the task (WorkerTask)
            task();
        }
    }

public:
    ThreadPoll(size_t threads) {
        for (size_t i = 0; i < threads; ++i) {
            workers.emplace_back([this]{ this->worker_loop(); });
        }
    }

    inline void enqueue(std::function<void()> task) override {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            if(stop) throw std::runtime_error("ThreadPool cannot enqueue: already stopped.");
            tasks.emplace(std::move(task));
        }
        condition.notify_one();
    }

    inline ~ThreadPoll() {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            stop = true;
        }
        condition.notify_all();
        for(std::thread &worker: workers)
            if(worker.joinable()) worker.join();
    }
};

} //SnmpServer