CXX = g++
CXXFLAGS = -std=c++11 -Wall -O2

all: main

main: main.o managers/configmanager.o
	$(CXX) $(CXXFLAGS) -o main main.o managers/configmanager.o

main.o: main.cpp
	$(CXX) $(CXXFLAGS) -c main.cpp

managers/configmanager.o: managers/configmanager.cpp managers/configmanager.hpp
	$(CXX) $(CXXFLAGS) -c managers/configmanager.cpp -o managers/configmanager.o

clean:
	rm -f *.o managers/*.o main

cleann:
	rm -f *.o managers/*.o main
	rm -f config.conf