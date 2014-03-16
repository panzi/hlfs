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

#include <string.h>

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

void usage(const char *binary) {
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


HLFS::HLFS::HLFS(int argc, char *argv[]) : m_args(argc, argv, false), m_flags(HLFS_OPTS_OK), m_package(0) {
    struct hlfs_config conf(m_archive, m_mountpoint, m_flags);
    m_args.add_arg("-s"); // HLLib does not support multithreading
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
    setup();
}

HLFS::HLFS::~HLFS() {
    clear();
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

#if FUSE_USE_VERSION >= 29
static int hlfs_read_buf(const char *path, struct fuse_bufvec **bufp,
                        size_t size, off_t offset, struct fuse_file_info *fi) {
    return ((HLFS::HLFS*) fuse_get_context()->private_data)->read_buf(
        path, bufp, size, offset, fi);
}
#endif

static int hlfs_statfs(const char *path, struct statvfs *stbuf) {
    return ((HLFS::HLFS*) fuse_get_context()->private_data)->statfs(
        path, stbuf);
}

static int hlfs_listxattr(const char *path, char *buf, size_t size) {
    return ((HLFS::HLFS*) fuse_get_context()->private_data)->listxattr(
        path, buf, size);
}

static int hlfs_getxattr(const char *path, const char *name, char *buf, size_t size) {
    return ((HLFS::HLFS*) fuse_get_context()->private_data)->getxattr(
        path, name, buf, size);
}

static void *hlfs_init(struct fuse_conn_info *) {
    HLFS::HLFS *hlfs = (HLFS::HLFS*) fuse_get_context()->private_data;
    try {
        hlfs->init();
    }
    catch (const std::exception &exc) {
        std::cerr << "*** error: " << exc.what() << std::endl;
        exit(1); // can't throw through C code
    }
    catch (...) {
        std::cerr << "*** unknown exception\n";
        exit(1); // can't throw through C code
    }

    return hlfs;
}

void HLFS::HLFS::setup() {
    memset(&m_operations, 0, sizeof(m_operations));

    m_operations.init             = hlfs_init;
    m_operations.getattr          = hlfs_getattr;
    m_operations.open             = hlfs_open;
    m_operations.read             = hlfs_read;
    m_operations.statfs           = hlfs_statfs;
    m_operations.getxattr         = hlfs_getxattr;
    m_operations.listxattr        = hlfs_listxattr;
    m_operations.opendir          = hlfs_opendir;
    m_operations.readdir          = hlfs_readdir;
    m_operations.flag_nullpath_ok = 1;

#if FUSE_USE_VERSION >= 29
    m_operations.flag_nopath      = 1;
    m_operations.read_buf         = hlfs_read_buf;
#endif
}

int HLFS::HLFS::run() {
    if (m_flags & HLFS_OPTS_ERROR) return 1;
    if (m_flags & (HLFS_OPTS_HELP | HLFS_OPTS_VERSION)) return 0;

    return fuse_main(m_args.argc(), m_args.argv(), &m_operations, this);
}

void HLFS::HLFS::init() {
    clear();

    int mode = HL_MODE_READ;

    if (sizeof(off_t) >= 8) {
        mode |= HL_MODE_QUICK_FILEMAPPING;
    }

    m_package = HLLib::CPackage::AutoOpen(m_archive.c_str(), mode);

    if (m_package == 0) {
        throw std::runtime_error("could not open or determine file type of package");
    }
}

int HLFS::HLFS::getattr(const char *path, struct stat *stbuf) {
    // TODO
    (void)path;
    (void)stbuf;
    return -EINVAL;
}

int HLFS::HLFS::opendir(const char *path, struct fuse_file_info *fi) {
    // TODO
    (void)path;
    (void)fi;
    return -EINVAL;
}

int HLFS::HLFS::readdir(const char *path, void *buf, fuse_fill_dir_t filler,
            off_t offset, struct fuse_file_info *fi) {
    // TODO
    (void)path;
    (void)buf;
    (void)filler;
    (void)offset;
    (void)fi;
    return -EINVAL;
}

int HLFS::HLFS::open(const char *path, struct fuse_file_info *fi) {
    // TODO
    (void)path;
    (void)fi;
    return -EINVAL;
}

int HLFS::HLFS::read(const char *path, char *buf, size_t size, off_t offset,
         struct fuse_file_info *fi) {
    // TODO
    (void)path;
    (void)buf;
    (void)size;
    (void)offset;
    (void)fi;
    return -EINVAL;
}

#if FUSE_USE_VERSION >= 29
int HLFS::HLFS::read_buf(const char *path, struct fuse_bufvec **bufp,
             size_t size, off_t offset, struct fuse_file_info *fi) {
    // TODO
    (void)path;
    (void)bufp;
    (void)size;
    (void)offset;
    (void)fi;
    return -EINVAL;
}
#endif

int HLFS::HLFS::statfs(const char *path, struct statvfs *stbuf) {
    // TODO
    (void)path;
    (void)stbuf;
    return -EINVAL;
}

int HLFS::HLFS::listxattr(const char *path, char *buf, size_t size) {
    // TODO
    (void)path;
    (void)buf;
    (void)size;
    return -EINVAL;
}

int HLFS::HLFS::getxattr(const char *path, const char *name, char *buf, size_t size) {
    // TODO
    (void)path;
    (void)name;
    (void)buf;
    (void)size;
    return -EINVAL;
}

void HLFS::HLFS::clear() {
    delete m_package;
}
