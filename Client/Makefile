CXX = g++ -std=c++17 -Wall -O2 -g

all: main

main: main.o ../shared-libs/configmanager.o libs/ServerManager.o
	$(CXX) -o main main.o ../shared-libs/configmanager.o libs/ServerManager.o

main.o: main.cpp
	$(CXX) -c main.cpp -o main.o

../shared-libs/configmanager.o: ../shared-libs/configmanager.cpp
	$(CXX) -c ../shared-libs/configmanager.cpp -o ../shared-libs/configmanager.o

libs/ServerManager.o: libs/ServerManager.cpp
	$(CXX) -c libs/ServerManager.cpp -o libs/ServerManager.o

clean:
	rm -f *.o ../shared-libs/*.o libs/*.o main

cleann:
	rm -f *.o ../shared-libs/*.o libs/*.o main
	rm -f config.conf