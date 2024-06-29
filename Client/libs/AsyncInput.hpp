#pragma once
#ifndef ASYNCINPUT_HPP
#define ASYNCINPUT_HPP

#include <iostream>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>

/// @brief Classe che permette espone il metodo getLine() asincrono che restituisce l'input dell'utente
class AsyncInput {
    public:
        AsyncInput();
        ~AsyncInput();
        /// @brief Restituisce la stringa contenente l'input dell'utente.
        /// @return l'input inserito, vuoto se l'utente non ha inserito ancora nulla
        std::string getLine();

    private:
        std::atomic<bool> continueGettingInput;
        std::atomic<bool> sendOverNextLine;
        std::mutex inputLock;
        std::string input;
};

#endif
