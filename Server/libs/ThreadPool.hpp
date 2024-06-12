#pragma once

#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>

class ThreadPool {
public:
    ThreadPool(size_t numThreads);
    ~ThreadPool();
    void enqueue(std::function<void(std::thread::id)> task);

private:
    std::vector<std::thread> workers;
    std::queue<std::function<void(std::thread::id)>> tasks;
    std::mutex queueMutex;
    std::condition_variable condition;
    bool stop;

    void worker();
};