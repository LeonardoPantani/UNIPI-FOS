#include "../shared-libs/configmanager.hpp"
#include "../shared-libs/cryptomanager.hpp"

#include "libs/ThreadPool.hpp"
#include "libs/ClientManager.hpp"
#include "libs/PersistentMemory.hpp"

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <vector>
#include <mutex>

// file di config
const std::string configPath = "config.json";
const std::vector<std::string> configKeys = {"configVersion", "serverIP", "serverPort", "threadPoolSize"};

// memoria persistente
const std::string dataFilePath = "persistentMemory.json"; // file memoria persistente
const std::string keyFilePath = "persistentMemory.key"; // file contenente la chiave per decriptare e criptare

int main() {
    try {
        ConfigManager configManager(configPath, configKeys);
        std::string configVersion = configManager.getString("configVersion");
        std::string serverIP = configManager.getString("serverIP");
        int serverPort = configManager.getInt("serverPort");
        int threadPoolSize = configManager.getInt("threadPoolSize");

        std::cout << "FILE DI CONFIGURAZIONE SERVER (v." << configVersion <<") CARICATO: " << std::endl;
        std::cout << "> Indirizzo IP: " << serverIP << std::endl;
        std::cout << "> Porta: " << serverPort << std::endl;
        std::cout << "> Dimensione pool di thread: " << threadPoolSize << std::endl;
        std::cout << std::endl;

        int server_socket = socket(AF_INET, SOCK_STREAM, 0);
        int new_server_socket;
        int opt = 1;
        if (server_socket == -1) {
            throw std::runtime_error("Creazione socket fallita.");
        }

        if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
            throw std::runtime_error("Operazione setsockopt SO_REUSEADDR fallita.");
        }
        if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt))) {
            throw std::runtime_error("Operazione setsockopt SO_REUSEPORT fallita.");
        }

        sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(serverPort);
        server_addr.sin_addr.s_addr = inet_addr(serverIP.c_str());
        int addrLen = sizeof(server_addr);

        if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            throw std::runtime_error("Binding fallito.");
        }

        if (listen(server_socket, 100) < 0) {
            throw std::runtime_error("Listen fallito.");
        }

        ThreadPool pool(100);

        while (true) {
            if ((new_server_socket = accept(server_socket, (struct sockaddr *)&server_addr, (socklen_t *)&addrLen)) < 0) {
                throw std::runtime_error("Accept fallita.");
            }
            pool.enqueue([new_server_socket](std::thread::id id) { handle_client(new_server_socket, id); });
        }

        close(server_socket);
    } catch (const std::exception& e) {
        std::cerr << "[!] " << e.what() << std::endl;
        return 1;
    }

    return 0;
}




/* // test memoria persistente
        std::cout << "------------------------------------------------" << std::endl;
        PersistentMemory pm(dataFilePath, keyFilePath);

        std::vector<User> initialUsers = pm.getUsers();
        std::vector<Message> initialMessages = pm.getMessages();

        std::cout << "Utenti in memoria:" << std::endl;
        for (const auto& user : initialUsers) {
            std::cout << "email: " << user.getEmail() << " | nick: " << user.getNickname() << std::endl;
        }

        std::cout << "Messaggi in memoria:" << std::endl;
        for (const auto& message : initialMessages) {
            std::cout << "UUID: " << message.getUUID() << " | title: " << message.getTitle() << " | autore: " << message.getAuthor() << " | body: " << message.getBody() << std::endl;
        }

        User user1("leonardo@example.com", "leonardo", {1, 2, 3, 4, 5});
        User user2("riccardo@example.com", "riccardo", {1, 2, 3, 4, 5});
        User user3("christian@example.com", "christian", {1, 2, 3, 4, 5});
        pm.addUser(user1);
        pm.addUser(user2);
        pm.addUser(user3);

        Message message1("Boia", "leonardo", "Deh");
        Message message2("Zio", "riccardo", "Pera");
        Message message3("Chiara?", "christian", "Smash.");
        pm.addMessage(message1);
        pm.addMessage(message2);
        pm.addMessage(message3);

        std::vector<User> users = pm.getUsers();
        std::vector<Message> messages = pm.getMessages();

        std::cout << "getUsers:" << std::endl;
        for (const auto& user : users) {
            std::cout << "Email: " << user.getEmail() << ", Nickname: " << user.getNickname() << std::endl;
        }

        std::cout << "getMessages:" << std::endl;
        for (const auto& message : messages) {
            std::cout << "UUID: " << message.getUUID() << ", Titolo: " << message.getTitle() << ", Autore: " << message.getAuthor() << ", Corpo: " << message.getBody() << std::endl;
        }

        User retrievedUser = pm.getUser("leonardo");
        std::cout << "Recupero nickname 'leonardo' - Email: " << retrievedUser.getEmail() << ", Nickname: " << retrievedUser.getNickname() << std::endl;
        try { User retrievedUser2 = pm.getUser("marco"); } catch (const UserNotFoundException&) { std::cout<< "Utente non trovato (ok)" << std::endl; }

        Message retrievedMessage = pm.getMessage(message1.getUUID());
        std::cout << "Recupero message1 - UUID: " << retrievedMessage.getUUID() << ", Titolo: " << retrievedMessage.getTitle() << ", Autore: " << retrievedMessage.getAuthor() << ", Corpo: " << retrievedMessage.getBody() << std::endl;
        try { Message retrievedMessage = pm.getMessage("asd"); } catch (const MessageNotFoundException&) { std::cout<< "Messaggio non trovato (ok)" << std::endl; }

        pm.removeUser("leonardo");
        pm.removeMessage(message1.getUUID());

        std::cout << "nickname 'leonardo' e messaggio message1 rimossi." << std::endl;
        std::cout << "------------------------------------------------" << std::endl;
        // fine test memoria persistente */