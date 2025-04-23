cmake_minimum_required(VERSION 3.10)
project(CPP_FTP)

set(CMAKE_CXX_STANDARD 11)

add_executable(ftp_client Ftp-Client3.cpp)
add_executable(ftp_server FTP-Server1.cpp)
