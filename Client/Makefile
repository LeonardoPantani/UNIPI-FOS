CXXOLD = g++ -std=c++17 -Wall -O2 -g
CXX = g++ -std=c++17 -O2 -pedantic -Wall -Wextra -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wlogical-op -Wmissing-declarations -Wmissing-include-dirs -Wnoexcept -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-conversion -Wsign-promo -Wstrict-null-sentinel -Wstrict-overflow=5 -Wswitch-default -Wundef -Werror -Wno-unused -g

all: main

main: main.o ../shared-libs/configmanager.o ../shared-libs/cryptomanager.o libs/ServerManager.o libs/AsyncInput.o
	$(CXX) -o main main.o ../shared-libs/configmanager.o ../shared-libs/cryptomanager.o libs/ServerManager.o libs/AsyncInput.o -lssl -lcrypto

main.o: main.cpp
	$(CXX) -c main.cpp -o main.o

../shared-libs/configmanager.o: ../shared-libs/configmanager.cpp
	$(CXX) -c ../shared-libs/configmanager.cpp -o ../shared-libs/configmanager.o

../shared-libs/cryptomanager.o: ../shared-libs/cryptomanager.cpp
	$(CXX) -c ../shared-libs/cryptomanager.cpp -o ../shared-libs/cryptomanager.o

libs/ServerManager.o: libs/ServerManager.cpp
	$(CXX) -c libs/ServerManager.cpp -o libs/ServerManager.o

libs/AsyncInput.o: libs/AsyncInput.cpp
	$(CXX) -c libs/AsyncInput.cpp -o libs/AsyncInput.o

clean:
	rm -f *.o ../shared-libs/*.o libs/*.o main

cleann:
	rm -f *.o ../shared-libs/*.o libs/*.o main *.pub *.priv
	rm -f config.json