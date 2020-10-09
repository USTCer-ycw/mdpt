
cmake_minimum_required(VERSION 2.6)

project(mdpt)

include_directories(${PROJECT_SOURCE_DIR})
link_directories(${PROJECT_SOURCE_DIR}/lib)
include_directories(${PROJECT_SOURCE_DIR}/include)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

add_compile_options(-std=c++11)
add_definitions(-DNOMINMAX)
add_definitions(-DUSE_DL_PREFIX)


if(UNIX)
	add_definitions(-D__LINUX__)
	set(Debug_Mode $ENV{Debug_Mode})
	if(Debug_Mode STREQUAL "ON")
		message("************* build debug version *********")
		set(CMAKE_BUILD_TYPE Debug CACHE STRING "set build type to debug")
		set(CMAKE_CXX_FLAGS "-g -pg -fpermissive -fPIC")
	else()
		message("************* build debug version *********")
		set(CMAKE_BUILD_TYPE "Release")
		set(CMAKE_CXX_FLAGS_RELEASE "-o2 -fpermissive -fPIC -finline-limit=1000 -DNDEBUG")
	endif()
endif(UNIX)


add_subdirectory(src/Util)
add_subdirectory(src/Mdpt)
#add_subdirectory(src/istype)
#add_subdirectory(src/ismdgw)
#add_subdirectory(src/ismfast)
#add_subdirectory(src/isconfig)
#add_subdirectory(src/istemplate)
