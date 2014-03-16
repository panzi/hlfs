set(hlfs_SRCS main.cpp hlfs.cpp)
set(hlfs_HDRS hlfs.h fuse_args.h)

add_executable(hlfs ${hlfs_SRCS} ${hlfs_HDRS})
target_link_libraries(hlfs ${HLLIB_LIBRARIES} ${FUSE_LIBRARY})

install(TARGETS hlfs RUNTIME DESTINATION bin)
