CXX = g++ -std=c++11 -Wall -O2

all: main

main: main.o ../shared-libs/configmanager.o
	$(CXX) -o main main.o ../shared-libs/configmanager.o

main.o: main.cpp
	$(CXX) -c main.cpp -o main.o

../shared-libs/configmanager.o: ../shared-libs/configmanager.cpp
	$(CXX) -c ../shared-libs/configmanager.cpp -o ../shared-libs/configmanager.o

clean:
	rm -f *.o ../shared-libs/*.o main

cleann:
	rm -f *.o ../shared-libs/*.o main
	rm -f config.conf