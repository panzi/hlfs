hlfs
====

With hlfs you can mount various package files that can be found in Valve
games as a read-only file system.

Supported package formats: bsp, gcf, pak, vbsp, wad, xzp, zip, ncf, vpk, sga.

### Setup

	git clone https://github.com/panzi/hlfs.git
	mkdir hlfs/build
	cd hlfs/build
	cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr
	make
	sudo make install

### Usage

	Usage: hlfs [OPTIONS] ARCHIVE MOUNTPOINT
	Mount valve game archives.
	This filesystem is read-only, single-threaded and only supports blocking operations.
	
	Options:
	    -o opt,[opt...]           mount options (see: man fuse)
	    -h      --help            print help
	    -v      --version         print version
	    -t TYPE --type=TYPE       archive has type TYPE (don't do auto detection)
	                              types: bsp, gcf, pak, vbsp, wad, xzp, zip, ncf,
	                                     vpk, sga, auto (do auto detection)
	    -d      -o debug          enable debug output (implies -f)
	    -f                        foreground operation

### Dependencies

 * [VTFLib](https://github.com/panzi/VTFLib)
 * [FUSE](http://fuse.sourceforge.net/)
 * [Boost](http://www.boost.org/)

### License

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
