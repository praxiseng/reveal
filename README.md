# REveal

REveal is Framework to reverse engineer binaries and evaluate similarities using sector hashes, function similarity
hashes, and data flow slice hashes on large collections of files.

## Getting started

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

This output shows some operations that took over 0.5 seconds to process.  The total run time is 58.86+11.10 seconds,
or about 70 seconds total.



```
src/hasher.py linux_bin.db --search sample_binaries/linux_bin/ls
```

This command will perform a rolling hash on the ls binary and query the database.  