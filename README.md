# REveal

REveal is framework to evaluate 1-to-N similarities in binaries using sector hashes.  The process of taking many 
binaries, storing their sector hashes in a database, and searching that database with sector hashes on a 
file-of-interest is called Match Set Analysis.

To see Match Set Analysis used with Data Flow Slices, see the related project 
[Flowslicer](github.com/praxiseng/flowslicer).

## Getting started

REveal uses Python 3.10 or newer, and uses the cbor2 library, which can be installed with this command:

```
python -m pip install cbor2
```

## Create a Database

Ingest a list of files into a database:

```
src/hasher.py --blocksize=128 linux_bin.db sample_binaries/linux_bin/* --zeroize
```

> Note: the code will not overwrite existing databases, and databases are folders.  To rebuild a database, you must
> first `rm -rf` the database file.

Sample output:
```
16.05 Ingest  162 of 900   360031/685379  hashes  0.76 Hash          312435  sample_binaries/linux_bin/emacs-gtk
16.73 Ingest  162 of 900   468569/685379  hashes  0.60 Write       0/312435  sample_binaries/linux_bin/emacs-gtk
44.75 Ingest  655 of 900  1347073/1642441 hashes  0.55 Zeroizing      319442 sample_binaries/linux_bin/snap
48.63 Ingest  655 of 900  1522465/1834437 hashes  0.59 Write       0/191996  sample_binaries/linux_bin/snap
58.86 Ingest  900 of 900  1831695/2165015 hashes
11.10 Merge 900 files, 1832595 hashes
Merged 1832595 hashes from 900 files, 900 new
```

This output shows any operations that took over 0.5 seconds to process.  The total run time is about 70 seconds total.

## Search a Database

```
src/hasher.py linux_bin.db --search sample_binaries/linux_bin/ls
```

This command will perform a rolling hash on the ls binary and query the database.  There are several pieces of output:

1. An entropy map.  Sections of low entropy are ignored.
2. Unprocessed match sets.  This can be very verbose, and often shows short ranges of bytes.
3. Fuzzy match groups.  This occurs after some processing to reduce the number of lines of output, and here is a sample:

```
  e1d0+e0    e1d0     .text+9430       100% 3 dir ls vdir   57% 1 tar
  e2b0+d0    e2b0     .text+9510       100% 3 dir ls vdir   85% 1 cp   62% 9 df install ln mkdir mkfifo mknod mv readlink realpath
  e380+1c0   e380     .text+95e0       100% 5 cp dir install ls vdir   86% 2 chmod emacs-gtk   82% 1 mv   57% 2 find stat
  e540+f0    e540     .text+97a0       100% 3 dir ls vdir   80% 1 install   60% 2 cp mv   53% 6 ln mktemp nohup rm stdbuf tac
  e630+40    e630     .text+9890       100% 4 dir emacs-gtk ls vdir
  e670+470   e670     .text+98d0       100% 4 dir emacs-gtk ls vdir   90% 1 sort
  eae0+70    eae0     .text+9d40       100% 5 dir ls mv pr vdir   71% 1 emacs-gtk   43% 1 cp
  eb50+10    eb50     .text+9db0       100% 7 cp dir ls mv pr shuf vdir
  eb60+40    eb60     .text+9dc0       100% 7 chgrp cp dir ls shuf sort vdir
```