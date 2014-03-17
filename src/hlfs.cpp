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

#include "hlfs.h"

#ifndef HAVE_STRLCPY
#	include "strlcpy.h"
#endif

#ifndef HAVE_STRLCAT
#	include "strlcat.h"
#endif

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <attr/xattr.h>

#include <boost/filesystem/operations.hpp>

namespace fs = boost::filesystem;

static void usage(const char *binary);

const std::string HLFS::VERSION = "1.0.0";

enum {
	HLFS_OPTS_OK      = 0,
	HLFS_OPTS_HELP    = 1,
	HLFS_OPTS_VERSION = 2,
	HLFS_OPTS_ERROR   = 4
};

struct hlfs_config {
	hlfs_config(
		std::string &archive,
		std::string &mountpoint,
		int &flags)
	: archive(archive),
	  mountpoint(mountpoint),
	  argind(0),
	  flags(flags) {}

	std::string &archive;
	std::string &mountpoint;
	int argind;
	int &flags;
};

enum {
	KEY_HELP,
	KEY_VERSION
};

static struct fuse_opt hlfs_opts[] = {
	FUSE_OPT_KEY("-v",        KEY_VERSION),
	FUSE_OPT_KEY("--version", KEY_VERSION),
	FUSE_OPT_KEY("-h",        KEY_HELP),
	FUSE_OPT_KEY("--help",    KEY_HELP),
	FUSE_OPT_END
};

static int hlfs_opt_proc(struct hlfs_config *conf, const char *arg, int key, struct fuse_args *outargs) {
	switch (key) {
	case FUSE_OPT_KEY_NONOPT:
		switch (conf->argind) {
		case 0:
			conf->archive = arg;
			++ conf->argind;
			return 0;

		case 1:
			conf->mountpoint = arg;
			++ conf->argind;
			break;

		default:
			std::cerr << "*** error: to many arguments\n";
			usage(outargs->argv[0]);
			conf->flags |= HLFS_OPTS_ERROR;
			++ conf->argind;
		}
		break;

	case KEY_HELP:
		usage(outargs->argv[0]);
		conf->flags |= HLFS_OPTS_HELP;
		break;

	case KEY_VERSION:
		std::cout << "hlfs version " << HLFS::VERSION << std::endl;
		conf->flags |= HLFS_OPTS_VERSION;
		break;
	}
	return 1;
}

static void usage(const char *binary) {
	std::cout << "Usage: " << binary << " [OPTIONS] ARCHIVE MOUNTPOINT\n"
		"Mount valve game archives.\n"
		"This filesystem is read-only, single-threaded and only supports blocking operations.\n"
		"\n"
		"Options:\n"
		"    -o opt,[opt...]        mount options (see: man fuse)\n"
		"    -h   --help            print help\n"
		"    -v   --version         print version\n"
		"    -d   -o debug          enable debug output (implies -f)\n"
		"    -f                     foreground operation\n"
		"\n"
		"(c) 2014 Mathias Panzenböck\n";
}


static int hlfs_getattr(const char *path, struct stat *stbuf) {
	return ((HLFS::HLFS*) fuse_get_context()->private_data)->getattr(
		path, stbuf);
}

static int hlfs_opendir(const char *path, struct fuse_file_info *fi) {
	return ((HLFS::HLFS*) fuse_get_context()->private_data)->opendir(
		path, fi);
}

static int hlfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
						off_t offset, struct fuse_file_info *fi) {
	return ((HLFS::HLFS*) fuse_get_context()->private_data)->readdir(
		path, buf, filler, offset, fi);
}

static int hlfs_open(const char *path, struct fuse_file_info *fi) {
	return ((HLFS::HLFS*) fuse_get_context()->private_data)->open(
		path, fi);
}

static int hlfs_read(const char *path, char *buf, size_t size, off_t offset,
					 struct fuse_file_info *fi) {
	return ((HLFS::HLFS*) fuse_get_context()->private_data)->read(
		path, buf, size, offset, fi);
}

static int hlfs_release(const char *path, struct fuse_file_info *fi) {
	return ((HLFS::HLFS*) fuse_get_context()->private_data)->release(
		path, fi);
}

/*
static int hlfs_statfs(const char *path, struct statvfs *stbuf) {
	return ((HLFS::HLFS*) fuse_get_context()->private_data)->statfs(
		path, stbuf);
}
*/

static int hlfs_listxattr(const char *path, char *buf, size_t size) {
	return ((HLFS::HLFS*) fuse_get_context()->private_data)->listxattr(
		path, buf, size);
}

static int hlfs_getxattr(const char *path, const char *name, char *buf, size_t size) {
	return ((HLFS::HLFS*) fuse_get_context()->private_data)->getxattr(
		path, name, buf, size);
}

HLFS::HLFS::HLFS(int argc, char *argv[]) : m_args(), m_flags(HLFS_OPTS_OK), m_package(0) {
	for (int i = 0; i < argc; ++ i) {
		m_args.add_arg(argv[i]);
	}
	// HLLib does not support multithreading
	m_args.add_arg("-s");

	struct hlfs_config conf(m_archive, m_mountpoint, m_flags);
	m_args.parse(&conf, hlfs_opts, hlfs_opt_proc);

	if (m_flags == HLFS_OPTS_OK) {
		if (conf.argind < 1) {
			std::cerr << "*** error: required argument ARCHIVE is missing.\n";
			usage(argv[0]);
			m_flags |= HLFS_OPTS_ERROR;
		}
		else if (conf.argind < 2) {
			std::cerr << "*** error: required argument MOUNTPOINT is missing.\n";
			usage(argv[0]);
			m_flags |= HLFS_OPTS_ERROR;
		}
	}

	m_archive = fs::absolute(m_archive).string();

	memset(&m_operations, 0, sizeof(m_operations));

	m_operations.getattr          = hlfs_getattr;
	m_operations.open             = hlfs_open;
	m_operations.read             = hlfs_read;
	m_operations.release          = hlfs_release;
//	m_operations.statfs           = hlfs_statfs;
	m_operations.getxattr         = hlfs_getxattr;
	m_operations.listxattr        = hlfs_listxattr;
	m_operations.opendir          = hlfs_opendir;
	m_operations.readdir          = hlfs_readdir;
	m_operations.flag_nullpath_ok = 1;

#if FUSE_USE_VERSION >= 29
	m_operations.flag_nopath      = 1;
#endif
}

HLFS::HLFS::~HLFS() {
	delete m_package;
}

int HLFS::HLFS::run() {
	if (m_flags & HLFS_OPTS_ERROR) return 1;
	if (m_flags & (HLFS_OPTS_HELP | HLFS_OPTS_VERSION)) return 0;


	int mode = HL_MODE_READ;

	if (sizeof(off_t) >= 8) {
		mode |= HL_MODE_QUICK_FILEMAPPING;
	}

	m_package = HLLib::CPackage::AutoOpen(m_archive.c_str(), mode);

	if (m_package == 0 || !m_package->GetOpened()) {
		throw std::runtime_error("could not open or determine file type of package");
	}

	return fuse_main(m_args.argc(), m_args.argv(), &m_operations, this);
}

static struct stat *hlfs_stat(const HLLib::CDirectoryItem *item, struct stat *stbuf) {
	stbuf->st_ino = (ino_t) item;
	if (item->GetType() == HL_ITEM_FOLDER) {
		stbuf->st_mode  = S_IFDIR | 0555;
		stbuf->st_nlink = ((const HLLib::CDirectoryFolder *) item)->GetCount() + 2;
	}
	else {
		stbuf->st_mode  = S_IFREG | 0444;
		stbuf->st_nlink = 1;
		stbuf->st_size  = ((const HLLib::CDirectoryFile *) item)->GetSize();
	}
	return stbuf;
}

int HLFS::HLFS::getattr(const char *path, struct stat *stbuf) {
	const HLLib::CDirectoryFolder *root = m_package->GetRoot();
	if (root == 0) return -ENOENT;

	const HLLib::CDirectoryItem *item = root->GetRelativeItem(path);

	memset(stbuf, 0, sizeof(struct stat));

	if (!item) {
		return -ENOENT;
	}

	hlfs_stat(item, stbuf);

	struct stat archst;
	if (stat(m_archive.c_str(), &archst) == 0) {
		stbuf->st_uid = archst.st_uid;
		stbuf->st_gid = archst.st_gid;
		stbuf->st_blksize = archst.st_blksize;
		stbuf->st_atime = archst.st_atime;
		stbuf->st_ctime = archst.st_ctime;
		stbuf->st_mtime = archst.st_mtime;
		return 0;
	}
	else {
		return -errno;
	}
}

int HLFS::HLFS::opendir(const char *path, struct fuse_file_info *fi) {
	const HLLib::CDirectoryFolder *root = m_package->GetRoot();
	if (root == 0) return -ENOENT;

	const HLLib::CDirectoryItem *item = root->GetRelativeItem(path);

	if (!item) {
		return -ENOENT;
	}

	if (item->GetType() != HL_ITEM_FOLDER) {
		return -ENOTDIR;
	}

	if((fi->flags & 3) != O_RDONLY) {
		return -EACCES;
	}

	fi->fh = (intptr_t) (const HLLib::CDirectoryFolder *) item;

	return 0;
}

int HLFS::HLFS::readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			off_t offset, struct fuse_file_info *fi) {
	(void)path;
	(void)offset;

	const HLLib::CDirectoryFolder *folder = (const HLLib::CDirectoryFolder*)fi->fh;

	struct stat stbuf;
	memset(&stbuf, 0, sizeof(struct stat));

	if (filler(buf, ".", hlfs_stat(folder, &stbuf), 0)) return 0;
	if (filler(buf, "..", NULL, 0)) return 0;

	for (hlUInt i = 0, n = folder->GetCount(); i < n; ++ i) {
		const HLLib::CDirectoryItem *item = folder->GetItem(i);
		if (filler(buf, item->GetName(), hlfs_stat(item, &stbuf), 0)) return 0;
	}

	return 0;
}

int HLFS::HLFS::open(const char *path, struct fuse_file_info *fi) {
	const HLLib::CDirectoryFolder *root = m_package->GetRoot();
	if (root == 0) return -ENOENT;

	const HLLib::CDirectoryItem *item = root->GetRelativeItem(path);

	if (!item) {
		return -ENOENT;
	}

	if (item->GetType() == HL_ITEM_FOLDER) {
		return -EISDIR;
	}

	if ((fi->flags & 3) != O_RDONLY) {
		return -EACCES;
	}

	fi->keep_cache = 1;

	HLLib::Streams::IStream *pInput = 0;

	if (!m_package->CreateStream((HLLib::CDirectoryFile *)item, pInput))
	{
		return -EINVAL;
	}

	if (!pInput->Open(HL_MODE_READ)) {
		m_package->ReleaseStream(pInput);
		return -EACCES;
	}

	fi->fh = (intptr_t) pInput;

	return 0;
}

int HLFS::HLFS::read(const char *path, char *buf, size_t size, off_t offset,
                     struct fuse_file_info *fi) {
	(void)path;

	if (offset < 0) return -EINVAL;

	HLLib::Streams::IStream *pInput = (HLLib::Streams::IStream *) fi->fh;
	pInput->Seek(offset, HL_SEEK_BEGINNING);

	return pInput->Read(buf, size);
}

int HLFS::HLFS::release(const char *path, struct fuse_file_info *fi) {
	(void)path;

	HLLib::Streams::IStream *pInput = (HLLib::Streams::IStream *) fi->fh;

	pInput->Close();
	m_package->ReleaseStream(pInput);

	return 0;
}

/*
int HLFS::HLFS::statfs(const char *path, struct statvfs *stbuf) {
	// TODO
	(void)path;
	(void)stbuf;
	return -EINVAL;
}
*/

static char hlfs_fix_xattr_char(char ch) {
	if (isalnum(ch)) {
		return tolower(ch);
	}
	// allow some special characters:
	else if (ch != '-' && ch != '_' && ch != ':' && ch != '+' && ch != '$' && ch != 0) {
		return '_';
	}
	else {
		return ch;
	}
}

static void hlfs_copy_xattr_name(const char *prefix, const char *name, char *buf, size_t size) {
	if (size > 0) {
		size_t off = strlcpy(buf, prefix, size);
		strlcat(buf, name, size);

		if (off < size) {
			for (char *ptr = buf + off; *ptr; ++ ptr) {
				*ptr = hlfs_fix_xattr_char(*ptr);
			}
		}
	}
}

#define PKG_ATTR_PREFIX "user.package."
#define PKG_ATTR_PREFIX_SIZE (sizeof(PKG_ATTR_PREFIX) - 1)
#define ITEM_ATTR_PREFIX "user."
#define ITEM_ATTR_PREFIX_SIZE (sizeof(ITEM_ATTR_PREFIX) - 1)

int HLFS::HLFS::listxattr(const char *path, char *buf, size_t size) {
	(void)path;

	size_t listSize = 0;

	for (hlUInt attr = 0, n = m_package->GetAttributeCount(); attr < n; ++ attr) {
		const hlChar *name = m_package->GetAttributeName((HLPackageAttribute)attr);
		size_t nameSize = strlen(PKG_ATTR_PREFIX) + strlen(name) + 1;
		if (listSize < size) {
			hlfs_copy_xattr_name(PKG_ATTR_PREFIX, name, buf + listSize, size - listSize);
		}
		listSize += nameSize;
	}

	for (hlUInt attr = 0, n = m_package->GetItemAttributeCount(); attr < n; ++ attr) {
		const hlChar *name = m_package->GetItemAttributeName((HLPackageAttribute)attr);
		size_t nameSize = strlen(ITEM_ATTR_PREFIX) + strlen(name) + 1;
		if (listSize < size) {
			hlfs_copy_xattr_name(ITEM_ATTR_PREFIX, name, buf + listSize, size - listSize);
		}
		listSize += nameSize;
	}

	if (size > 0 && listSize > size) {
		return -ERANGE;
	}

	return listSize;
}

static int hlfs_getxattr(const HLAttribute &attribute, char *buf, size_t size) {
	// temp with enough room to print the string including a termination NIL.
	// If size would be exactly big enough for the xattr value the snprintf/strlcpy
	// functions would cut of the last character because they want to write a NIL.
	char temp[64] = "";

	size_t count = 0;

	switch (attribute.eAttributeType) {
	case HL_ATTRIBUTE_BOOLEAN:
	{
		const char *val = attribute.Value.Boolean.bValue ? "true" : "false";
		count = strlen(val);
		memcpy(buf, val, size < count ? size : count);
		return count;
	}
	case HL_ATTRIBUTE_INTEGER:
	{
		int icount = snprintf(temp, sizeof(temp), "%d", attribute.Value.Integer.iValue);
		if (icount < 0) return -ENOTSUP;
		count = icount;
		break;
	}
	case HL_ATTRIBUTE_UNSIGNED_INTEGER:
	{
		int icount;
		if (attribute.Value.UnsignedInteger.bHexadecimal) {
			icount = snprintf(temp, sizeof(temp), "%x", attribute.Value.UnsignedInteger.uiValue);
		}
		else {
			icount = snprintf(temp, sizeof(temp), "%u", attribute.Value.UnsignedInteger.uiValue);
		}
		if (icount < 0) return -ENOTSUP;
		count = icount;
		break;
	}
	case HL_ATTRIBUTE_FLOAT:
	{
		int icount = snprintf(temp, sizeof(temp), "%a", (double)attribute.Value.Float.fValue);
		if (icount < 0) return -ENOTSUP;
		count = icount;
		break;
	}
	case HL_ATTRIBUTE_STRING:
		count = strlen(attribute.Value.String.lpValue);
		memcpy(buf, attribute.Value.String.lpValue, size < count ? size : count);
		return count;

	default:
		return -ENOTSUP;
	}

	// xattr value will not contain a termination NIL
	memcpy(buf, temp, size < count ? size : count);

	if (size > 0 && count > size) {
		return -ERANGE;
	}

	return count;
}

static bool hlfs_xattr_name_match(const char *prefix, const char *name, const char *xattr_name) {
	while (*prefix) {
		if (*prefix ++ != *xattr_name ++) {
			return false;
		}
	}

	while (*name) {
		if (hlfs_fix_xattr_char(*name ++) != *xattr_name ++) {
			return false;
		}
	}

	return true;
}

int HLFS::HLFS::getxattr(const char *path, const char *name, char *buf, size_t size) {
	if (strncmp(PKG_ATTR_PREFIX, name, PKG_ATTR_PREFIX_SIZE) == 0) {
		for (hlUInt attr = 0, n = m_package->GetAttributeCount(); attr < n; ++ attr) {
			const hlChar *attrName = m_package->GetAttributeName((HLPackageAttribute)attr);
			if (hlfs_xattr_name_match(PKG_ATTR_PREFIX, attrName, name)) {
				HLAttribute attribute;
				if (!m_package->GetAttribute((HLPackageAttribute)attr, attribute)) {
					return -ENOTSUP;
				}
				return hlfs_getxattr(attribute, buf, size);
			}
		}
	}

	if (strncmp(ITEM_ATTR_PREFIX, name, ITEM_ATTR_PREFIX_SIZE) == 0) {
		for (hlUInt attr = 0, n = m_package->GetItemAttributeCount(); attr < n; ++ attr) {
			const hlChar *attrName = m_package->GetItemAttributeName((HLPackageAttribute)attr);
			if (hlfs_xattr_name_match(ITEM_ATTR_PREFIX, attrName, name)) {
				const HLLib::CDirectoryFolder *root = m_package->GetRoot();
				if (root == 0) return -ENOENT;

				const HLLib::CDirectoryItem *item = root->GetRelativeItem(path);
				HLAttribute attribute;
				if (!m_package->GetItemAttribute(item, (HLPackageAttribute)attr, attribute)) {
					return -ENOTSUP;
				}
				return hlfs_getxattr(attribute, buf, size);
			}
		}
	}

	return -ENOATTR;
}
