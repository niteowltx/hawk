Watch a Linux system like a hawk

Useful to look for resource leaks over time without having to prepare
the system in any way.

Periodically scans /proc for process changes. Command line flags:

	-t	time items

	-m	memory items

	-p	process items

	-f	file items

	-k	kernel items

	-y	YAFFS filesystem items (implies -k)

	-d	disk I/O items

Default is -m -f.  Adding -v enables all items in each selected category.
The -k flag looks at -t, -m and -y flags to determine which kernel
activity to watch and is affected by the -v flag.

Output can be saved and then later run through hawk_graph to create
plots of system activity over time.
