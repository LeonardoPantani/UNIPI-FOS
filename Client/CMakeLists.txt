cmake_minimum_required(VERSION 3.10)

project(Client)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -O2 -g -Wno-deprecated-declarations")
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -pedantic -Wall -Wextra -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wlogical-op -Wmissing-declarations -Wmissing-include-dirs -Wnoexcept -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-conversion -Wsign-promo -Wstrict-null-sentinel -Wstrict-overflow=5 -Wswitch-default -Wundef -Werror -Wno-unused -g")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/../)

include_directories(${CMAKE_SOURCE_DIR}/../shared-libs)
include_directories(${CMAKE_SOURCE_DIR}/libs)

add_executable(main
    main.cpp
    ../shared-libs/ConfigManager.cpp
    ../shared-libs/Utils.cpp
    libs/CryptoClient.cpp
    libs/ServerManager.cpp
    libs/AsyncInput.cpp
)

target_link_libraries(main ssl crypto)