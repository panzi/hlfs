set(hlfs_SRCS main.cpp hlfs.cpp)
set(hlfs_HDRS hlfs.h fuse_args.h)

include(CheckCSourceCompiles)

check_c_source_compiles("#include <string.h>
int main() { char buf[64]; return (int) strlcpy(buf, \"test\", sizeof(buf)); }" HAVE_STRLCPY)

if(NOT HAVE_STRLCPY)
	set(hlfs_SRCS ${hlfs_SRCS} strlcpy.c)
	set(hlfs_HDRS ${hlfs_HDRS} strlcpy.h)
else()
	add_definitions(-DHAVE_STRLCPY)
endif()

add_executable(hlfs ${hlfs_SRCS} ${hlfs_HDRS})
target_link_libraries(hlfs
	${HLLIB_LIBRARIES}
	${FUSE_LIBRARIES}
	${Boost_SYSTEM_LIBRARY}
	${Boost_FILESYSTEM_LIBRARY})
