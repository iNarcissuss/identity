cmake_minimum_required(VERSION 2.8.1)
project(Fortika)

###############################################################################
## file globbing ##############################################################
###############################################################################

# These instructions search the directory tree when cmake is
# invoked and put all files that match the pattern in the variable
# 'sources'.
#file(GLOB_RECURSE sources src/*.c include/*.h)
# You can use set(sources src/main.cpp) etc if you don't want to
# use globbing to find files automatically.

set(sources main.cpp ac/ac.c)

include(FindPCAP.cmake)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}")

###############################################################################
## target definitions #########################################################
###############################################################################

# The data is just added to the executable, because in some IDEs (QtCreator)
# files are invisible when they are not explicitly part of the project.
add_executable(smatcher ${sources} ${data})

# Just for example add some compiler flags.
#target_compile_options(dss PUBLIC -O3 -std=c++14 -Wall)
target_compile_options(smatcher PUBLIC -g -O0 -std=c++14 -Wall -pthread)

# This allows to include files relative to the root of the src directory with a <> pair
target_include_directories(smatcher PUBLIC include/ /usr/local/include/pcapplusplus/)

target_link_libraries(smatcher ${PCAP_LIBRARY} -lPcap++ -lPacket++ -lCommon++ -lpcap)
