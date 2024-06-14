#include "AsyncInput.hpp"

using namespace std;

AsyncInput::AsyncInput() : continueGettingInput(true), sendOverNextLine(true), input("") {
    thread([&]() {
        string synchronousInput;
        char nextCharacter;
        do {
            synchronousInput = "";
            while (continueGettingInput) {
                while (cin.peek() == EOF) {
                    this_thread::yield();
                }
                nextCharacter = cin.get();
                if (nextCharacter == '\n') break;
                synchronousInput += nextCharacter;
            }
            if (!continueGettingInput) break;
            while (continueGettingInput && !sendOverNextLine) {
                this_thread::yield();
            }
            if (!continueGettingInput) break;
            {
                lock_guard<mutex> lock(inputLock);
                input = synchronousInput;
            }
            sendOverNextLine = false;
        } while (continueGettingInput && input != "exit");
    }).detach();
}

AsyncInput::~AsyncInput() {
    continueGettingInput = false;
}

std::string AsyncInput::getLine() {
    if (sendOverNextLine) {
        this_thread::sleep_for(chrono::milliseconds(1));
        return "";
    } else {
        string returnInput;
        {
            lock_guard<mutex> lock(inputLock);
            returnInput = input;
        }
        sendOverNextLine = true;
        return returnInput;
    }
}
