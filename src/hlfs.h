/**
 * hlfs - mount various valve archives (e.g. vpk)
 * Copyright (C) 2014  Mathias Panzenböck <grosser.meister.morti@gmx.net>
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef HLFS_HLFS_H
#define HLFS_HLFS_H

#include <stdio.h>
#include <sys/statvfs.h>

#include <fuse.h>

#include <HLLib.h>

#include "fuse_args.h"

namespace HLFS {
	extern const std::string VERSION;

	class HLFS {
	public:

		HLFS(int argc, char *argv[]);
		~HLFS();

		int run();

		void init();
		int getattr(const char *path, struct stat *stbuf);
		int opendir(const char *path, struct fuse_file_info *fi);
		int readdir(const char *path, void *buf, fuse_fill_dir_t filler,
					off_t offset, struct fuse_file_info *fi);
		int open(const char *path, struct fuse_file_info *fi);
		int read(const char *path, char *buf, size_t size, off_t offset,
				 struct fuse_file_info *fi);
#if FUSE_USE_VERSION >= 29
		int read_buf(const char *path, struct fuse_bufvec **bufp,
					 size_t size, off_t offset, struct fuse_file_info *fi);
#endif
//		int statfs(const char *path, struct statvfs *stbuf);
		int listxattr(const char *path, char *buf, size_t size);
		int getxattr(const char *path, const char *name, char *buf, size_t size);

		void clear();

	private:
		void setup();

		FuseArgs               m_args;
		int                    m_flags;
		std::string            m_archive;
		std::string            m_mountpoint;
		struct fuse_operations m_operations;
		HLLib::CPackage       *m_package;
	};
}

#endif
