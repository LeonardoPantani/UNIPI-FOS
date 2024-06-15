CXXOLD = g++ -std=c++17 -Wall -O2 -g
CXX = g++ -std=c++17 -O2 -pedantic -Wall -Wextra -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wlogical-op -Wmissing-declarations -Wmissing-include-dirs -Wnoexcept -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-conversion -Wsign-promo -Wstrict-null-sentinel -Wstrict-overflow=5 -Wswitch-default -Wundef -Werror -Wno-unused -g

all: main

main: main.o ../shared-libs/configmanager.o ../shared-libs/Utils.o libs/ClientManager.o libs/PersistentMemory.o libs/UUID.o
	$(CXX) -o main main.o ../shared-libs/configmanager.o ../shared-libs/Utils.o libs/ClientManager.o libs/PersistentMemory.o libs/UUID.o -lssl -lcrypto

main.o: main.cpp
	$(CXX) -c main.cpp -o main.o

../shared-libs/configmanager.o: ../shared-libs/configmanager.cpp
	$(CXX) -c ../shared-libs/configmanager.cpp -o ../shared-libs/configmanager.o

../shared-libs/Utils.o: ../shared-libs/Utils.cpp
	$(CXX) -c ../shared-libs/Utils.cpp -o ../shared-libs/Utils.o

libs/ClientManager.o: libs/ClientManager.cpp
	$(CXX) -c libs/ClientManager.cpp -o libs/ClientManager.o

libs/PersistentMemory.o: libs/PersistentMemory.cpp
	$(CXX) -c libs/PersistentMemory.cpp -o libs/PersistentMemory.o

libs/UUID.o: libs/UUID.cpp
	$(CXX) -c libs/UUID.cpp -o libs/UUID.o

clean:
	rm -f *.o ../shared-libs/*.o libs/*.o main

cleann:
	rm -f *.o ../shared-libs/*.o libs/*.o main *.pub *.priv persistentMemory.json persistentMemory.key
	rm -f config.json
