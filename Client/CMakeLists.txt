cmake_minimum_required(VERSION 3.10)

project(Client)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -O2 -Wno-deprecated-declarations")

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