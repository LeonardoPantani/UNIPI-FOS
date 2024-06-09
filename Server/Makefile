CXX = g++ -std=c++17 -Wall -O2 -g

all: main

main: main.o ../shared-libs/configmanager.o ../shared-libs/cryptomanager.o libs/ClientManager.o
	$(CXX) -o main main.o ../shared-libs/configmanager.o ../shared-libs/cryptomanager.o libs/ClientManager.o -lssl -lcrypto

main.o: main.cpp
	$(CXX) -c main.cpp -o main.o

../shared-libs/configmanager.o: ../shared-libs/configmanager.cpp
	$(CXX) -c ../shared-libs/configmanager.cpp -o ../shared-libs/configmanager.o

../shared-libs/cryptomanager.o: ../shared-libs/cryptomanager.cpp
	$(CXX) -c ../shared-libs/cryptomanager.cpp -o ../shared-libs/cryptomanager.o

libs/ClientManager.o: libs/ClientManager.cpp
	$(CXX) -c libs/ClientManager.cpp -o libs/ClientManager.o

clean:
	rm -f *.o ../shared-libs/*.o libs/*.o main

cleann:
	rm -f *.o ../shared-libs/*.o libs/*.o main *.pub *.priv
	rm -f config.conf
