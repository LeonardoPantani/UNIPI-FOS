#pragma once

#include <iostream>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>

class AsyncInput {
public:
    AsyncInput();
    ~AsyncInput();
    std::string getLine();

private:
    std::atomic<bool> continueGettingInput;
    std::atomic<bool> sendOverNextLine;
    std::mutex inputLock;
    std::string input;
};