cmake_minimum_required(VERSION 3.5)
project(TinyVPN)

set(CMAKE_CXX_STANDARD 11)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

include_directories(include)
add_executable(TinyServer mainServer.cpp TunManager.h protocol.h)

add_executable(TinyClientBackend ClientBackend.cpp ClientBackend.h protocol.h mainClient.cpp)



target_link_libraries(TinyServer Threads::Threads)
target_link_libraries(TinyClientBackend Threads::Threads)

