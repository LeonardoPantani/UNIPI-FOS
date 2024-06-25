#include "AsyncInput.hpp"

AsyncInput::AsyncInput() : continueGettingInput(true), sendOverNextLine(true), input("") {
    std::thread([&]() {
        std::string synchronousInput;
        char nextCharacter;
        do {
            synchronousInput = "";
            while (continueGettingInput) {
                while (std::cin.peek() == EOF) {
                    std::this_thread::yield();
                }
                nextCharacter = std::cin.get();
                if (nextCharacter == '\n') break;
                synchronousInput += nextCharacter;
            }
            if (!continueGettingInput) break;
            while (continueGettingInput && !sendOverNextLine) {
                std::this_thread::yield();
            }
            if (!continueGettingInput) break;
            {
                std::lock_guard<std::mutex> lock(inputLock);
                input = synchronousInput;
            }
            sendOverNextLine = false;
        } while (continueGettingInput);
    }).detach();
}

AsyncInput::~AsyncInput() {
    continueGettingInput = false;
}

std::string AsyncInput::getLine() {
    if (sendOverNextLine) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        return "";
    } else {
        std::string returnInput;
        {
            std::lock_guard<std::mutex> lock(inputLock);
            returnInput = input;
        }
        sendOverNextLine = true;
        return returnInput;
    }
}