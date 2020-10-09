#
#set(util_srcs
#	Util.h
#	Util.cc
#	Types.h
#)

aux_source_directory(. util_srcs)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/include)

LINK_DIRECTORIES(${PROJECT_SOURCE_DIR})
LINK_DIRECTORIES(${PROJECT_SOURCE_DIR}/lib)

add_library(util STATIC ${util_srcs})
