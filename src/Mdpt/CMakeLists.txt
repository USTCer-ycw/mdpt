

add_executable(mdpt Mdpt.cc)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

LINK_DIRECTORIES(${PROJECT_SOURCE_DIR})
LINK_DIRECTORIES(${PROJECT_SOURCE_DIR}/lib)

target_link_libraries(mdpt util)

if(UNIX)
	target_link_libraries(mdpt pcap)
	target_link_libraries(mdpt pthread rt)
	set_target_properties(mdpt PROPERTIES COMPILE_FLAGS "-std=c++11")
	add_definitions("-g")
endif(UNIX)
