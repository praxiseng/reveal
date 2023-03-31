cmake_minimum_required(VERSION 3.0.0)
project(reveal VERSION 0.1.0)

set (CMAKE_CXX_STANDARD 17)

add_executable (hasher hasher.cpp util.cpp md5.c)