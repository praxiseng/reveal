import copy
import hashlib
import cbor2
import os
import itertools
import heapq


MAX_LIST_SIZE = 100


def coroutine(func):
    def start(*args,**kwargs):
        cr = func(*args,**kwargs)
        next(cr)
        return cr
    return start

def get_full_path(path):
    full_path = path
    try:
        full_path = os.path.realpath(path)
    except OSError as e:
        print("Error on ingest")
        print(e)
    return full_path

@coroutine
def cbor_dump(file_path):
    with open(file_path, 'wb') as out_fd:
        while True:
            entry = (yield)
            cbor2.dump(entry, out_fd)

def md5(b):
    m = hashlib.md5()
    m.update(b)
    return m.digest()[:6]


def btoh(b):
    return ''.join(format(x, '02x') for x in b)


def pretty_fileset(fileset):
    hash = fileset[0]
    if len(fileset) == 2 and isinstance(fileset[1], list):
        foffs = [f'{file_id}:{offset:x}' for file_id, offset in fileset[1]]
        return f'File/offset {" ".join(foffs)}'

    if len(fileset) == 3:
        hash, nmatch, nfiles = fileset
        return f'{nmatch} matches on {nfiles} files'
    return f'??? {fileset}'


def _uniq(sorted_hashes):
    getHash = lambda entry: entry[0]

    for k, g in itertools.groupby(sorted_hashes, key=getHash):
        g = list(g)

        all_lists = True
        n_matches = 0
        n_files = 0
        file_set = set()
        for hashdes in g:
            if len(hashdes) == 2 and isinstance(hashdes[1], list):
                n_matches += len(hashdes[1])
                file_set |= set([file_id for file_id, off in hashdes[1]])
            else:
                all_lists = False
            if len(hashdes) == 3:
                n_matches += hashdes[1]
                n_files += hashdes[2]
        n_files += len(file_set)

        if not all_lists or n_matches > MAX_LIST_SIZE:
            entry = [k, n_matches, n_files]
        else:
            summaries = [e[1] for e in g]
            merged_file_lists = list(itertools.chain.from_iterable(summaries))
            entry = [k, merged_file_lists]
        yield entry


class SimpleSectorHashList:
    def __init__(self, path):
        self.path = path
        self.header = None
        self.max_file_id = 0

    def createFile(self, hashed_file, blocksize, blockAlgorithm):
        f = cbor_dump(self.path)
        self.max_file_id = hashed_file.id
        self.header = dict(files=[hashed_file.getData()], blocksize=blocksize, blockAlgorithm=blockAlgorithm)
        f.send(self.header)
        return f

    def createMerge(self, hash_list_files, uniq=True):
        headers = [f.readHeader() for f in hash_list_files]

        # TODO: check blocksize, algorithm for consistency
        bs = headers[0]['blocksize']
        ba = headers[0]['blockAlgorithm']
        flist = []
        self.max_file_id = 0

        entryIters = []

        '''
        The hardest part is adjusting file IDs each data stream, since each source file serializes
        file IDs separately.  Here we wrap a generator than maps them into the new file ID numbers
        to ensure the merged files are using unique IDs and that the record entries are adjusted as
        appropriate.
        '''
        def thunkIDs(thunk_table, input_gen):
            for entry in input_gen:
                if len(entry) == 2 and isinstance(entry[1], list):
                    entry[1] = [[thunk_table[fid], offset] for fid, offset in entry[1]]
                yield entry

        for i, f in enumerate(hash_list_files):
            hdr = copy.deepcopy(headers[i])
            current_thunk = {}
            hdr_files = hdr['files']
            for file in hdr_files:
                self.max_file_id += 1
                fid = self.max_file_id
                current_thunk[file['id']] = fid
                file['id'] = fid

            flist += hdr_files
            entryIters.append(thunkIDs(current_thunk, f.readEntries()))

        output = cbor_dump(self.path)
        self.header = dict(files = flist, blocksize=bs, blockAlgorithm=ba)
        output.send(self.header)
        getHash = lambda entry : entry[0]
        it = heapq.merge(*entryIters, key=getHash)
        if uniq:
            it = _uniq(it)
        for entry in it:
            output.send(entry)

    def readHeader(self):
        with open(self.path, 'rb') as fd:
            self.header = cbor2.load(fd)
            return self.header

    def readEntries(self):
        with open(self.path, 'rb') as fd:
            self.header = cbor2.load(fd)
            try:
                while True:
                    yield cbor2.load(fd)
            except cbor2.CBORDecodeEOF:
                pass

    def delete_file(self):
        if os.path.exists(self.path):
            os.remove(self.path)

    def dump(self):
        header = self.readHeader()
        print(f'Dumping {self.path}:')
        #print(f'  {header}')
        print(f'  Blocksize {header["blocksize"]}, blockAlgorithm {header["blockAlgorithm"]}')
        print('  Files')
        for file in header['files']:
            print(f'    {btoh(file["md5"])} {file["id"]:4} {file["path"]}')

        for entry in self.readEntries():
            hashcode = entry[0]
            print(f'  {btoh(hashcode)} {pretty_fileset(entry)}')

    def find_matches(self, other, key = lambda entry : entry[0]):
        '''
        Find the matching values between two lists A and B.  The elements of A and B should be tuples/lists whose first
        element is the hash, and the lists should be sorted by this hash.  If hashes are not pre-grouped (using uniq above),
        it will yield m*n pairs for m and n matching hashes in A and B.  This implementation does not load the lists
        into memory, and simply iterates
        '''

        '''
        Sometimes it's easier to not use uniq ahead of time, such as when we want to enumerate rolling file hashes
        and later re-sort by offset.  So we groupby here in case they are not unique. 
        '''
        A = itertools.groupby(self.readEntries(), key=key)
        B = itertools.groupby(other.readEntries(), key=key)

        try:
            key_a, alist = next(A)
            key_b, blist = next(B)

            while True:
                if key_a == key_b:
                    alist = list(alist)
                    blist = list(blist)
                    for a in alist:
                        for b in blist:
                            yield (a, b)

                    key_a, alist = next(A)
                    key_b, blist = next(B)
                elif key_a < key_b:
                    key_a, alist = next(A)
                else:
                    key_b, blist = next(B)
        except StopIteration:
            pass



class HashedFile:
    def __init__(self, path, id=None):
        global current_file_id
        if id == None:
            id = current_file_id
            current_file_id += 1

        full_path = path
        try:
            full_path = os.path.realpath(path)
        except OSError as e:
            print(f"Error getting real path for {path}")
            print(e)
        dirname, filename = os.path.split(full_path)

        self.path = full_path
        self.id = id
        self.whole_file_hash = None

    def openFile(self):
        return open(self.path, 'rb')


    def getWholeFileHash(self):
        if not self.whole_file_hash:
            with self.openFile() as fd:
                self.whole_file_hash = md5(fd.read())
        return self.whole_file_hash

    def getData(self):
        return dict(path=self.path, id=self.id, md5=self.getWholeFileHash())

    def genericSectorHash(self, sectors, output, uniq = True):
        # TODO: chunk large lists instead of iterating the whole thing
        #sorted_sectors = sorted(list(sectors), key=lambda s: (s.hash(), s.file.id, s.offset))
        sorted_sectors = sorted([sector.getHashTuple() for sector in sectors])
        if uniq:
            sorted_sectors = _uniq(sorted_sectors)
        for hash_tuple in sorted_sectors:
            output.send(hash_tuple)


    def genAlignedBlocks(self, bs=10, offset=0, short_blocks=True):
        with self.openFile() as fd:
            while True:
                data = fd.read(bs)
                if not data:
                    break
                if not short_blocks and len(data) < bs:
                    break
                yield Sector(self, data, offset)
                offset += bs

    def genRollingBlocks(self, bs=10, step=1, offset=0, short_blocks=False):
        with self.openFile() as in_fd:
            data = in_fd.read(bs)
            while True:
                if not data:
                    break
                if not short_blocks and len(data) < bs:
                    break
                yield Sector(self, data, offset)

                data = data[step:] + in_fd.read(step)
                offset += step

    def hashBlocksToFile(self, blockSize, outFilePath, short_blocks=False, uniq=True):
        hl = SimpleSectorHashList(outFilePath)
        out_file = hl.createFile(self, blockSize, dict(aligned=1, step=blockSize, shortBlocks=short_blocks))
        block_gen = self.genAlignedBlocks(blockSize, short_blocks=short_blocks)
        self.genericSectorHash(block_gen, out_file, uniq=uniq)
        return hl

    def rollingHashToFile(self, blockSize, outFilePath, short_blocks=False, uniq=True):
        hl = SimpleSectorHashList(outFilePath)
        output = hl.createFile(self, blockSize, dict(aligned=0, step=1, shortBlocks=short_blocks))
        block_gen = self.genRollingBlocks(blockSize, short_blocks=short_blocks)
        self.genericSectorHash(block_gen, output, uniq=uniq)
        return hl

    @staticmethod
    def fromData(self, fileData):
        return HashedFile(fileData['path'], fileData['id'])


class Sector:
    def __init__(self, file, data, offset):
        self.file = file
        self.data = data
        self.offset = offset
        self.end_offset = offset + len(data)
        self._hash = md5(self.data)
        # low-entropy testing hash (4 bits)
        #self._hash = bytes([md5(self.data)[0]//16])

    def hash(self):
        return self._hash

    def getHashTuple(self):
        return (self.hash(), [[self.file.id, self.offset]])



def grouper(iterable, n):
    it = iter(iterable)
    while True:
        chunk_it = itertools.islice(it, n)
        try:
            first_el = next(chunk_it)
        except StopIteration:
            return
        yield itertools.chain((first_el,), chunk_it)

def sector_hash(sectors, out_fd):
    # TODO: chunk massively large lists to sort smaller ones then do a file-based mergesort.
    sorted_sectors = sorted(list(sectors), key=lambda s: (s.hash(), s.file.id, s.offset))
    for sector in sorted_sectors:
        cbor2.dump(sector.getHashTuple(), out_fd)
        print(f'{sector.file.path:20} {btoh(sector.data):>20} {sector.offset:3x}-{sector.end_offset:3x} Hash is {btoh(sector.hash())}')




class FileDB:
    def __init__(self, db_name, blocksize, short_blocks=False):
        self.db_name = db_name
        self.next_file_id = 1

        os.makedirs(db_name, exist_ok=True)

        self.blocksize = blocksize
        self.short_blocks = short_blocks

        self.enum_file_list()


        #self.db_file = SimpleSectorHashList(self.get_hashes_path())

    def get_hashes_path(self):
        return os.path.join(self.db_name, 'hashes.cbor')

    def get_merge_path(self):
        return os.path.join(self.db_name, 'merge.cbor')

    def open_db(self):
        return SimpleSectorHashList(self.get_hashes_path())

    def enum_file_list(self):
        #self.all_files = []
        #self.files_by_path = {}
        #self.files_by_id = {}

        self.paths_in_use = set()
        self.fids_in_use = set()

        if not os.path.exists(self.get_hashes_path()):
            return

        header = self.open_db().readHeader()
        for file in header['files']:
            path = file['path']
            fid = file['id']

            if path in self.paths_in_use:
                print(f'Warning: duplication of path {path}')
            if fid in self.fids_in_use:
                print(f'Warning: duplication of file ID {fid}')
            self.paths_in_use.add(path)
            self.fids_in_use.add(fid)

    def _mk_hashed_file(self, path):
        hf = HashedFile(path, self.next_file_id)
        self.next_file_id += 1
        return hf

    def _tmpname(self, hashedFile):
        return os.path.join(self.db_name, f'{btoh(hashedFile.getWholeFileHash())}_{hashedFile.id}')

    def _hash_file(self, path):
        hf = self._mk_hashed_file(path)
        hashlist = hf.hashBlocksToFile(self.blocksize, self._tmpname(hf), self.short_blocks)
        return hashlist


    def ingest(self, paths, force_existing=False):
        if isinstance(paths, (str, bytes)):
            paths = [paths]

        if not force_existing:
            print(f'Paths in use: {self.paths_in_use}')
            paths = [get_full_path(path) for path in paths]
            paths = [path for path in paths if path not in self.paths_in_use]
            print(f'Paths: {paths}')


        hash_files = [self._hash_file(path) for path in paths]

        merge_path = self.get_merge_path()
        if os.path.exists(merge_path):
            os.remove(merge_path)

        merged = SimpleSectorHashList(merge_path)

        merge_files = hash_files[:]
        if os.path.exists(self.get_hashes_path()):
            merge_files.append(self.open_db())

        merged.createMerge(merge_files)

        if os.path.exists(merge_path):
            os.replace(merge_path, self.get_hashes_path())
            self.enum_file_list()
        else:
            print(f"Error - no merge created at {merge_path}")

        return hash_files


    def rollingSearch(self, file_to_hash):
        fid = 0 # We don't need a valid fid
        hf = HashedFile(file_to_hash, fid)


        rolling_path = os.path.join(self.db_name, f'{btoh(hf.getWholeFileHash())}_rolling.cbor')

        rolling_hashes = hf.rollingHashToFile(self.blocksize, rolling_path, uniq=False)
        for a, b in rolling_hashes.find_matches(self.open_db()):
            yield a, b


import argparse
def main():
    parser = argparse.ArgumentParser(description='Sector hashing tool')
    parser.add_argument('db', metavar='PATH', help='The database path')
    parser.add_argument('ingest', nargs='*', help='Files to ingest into the database')
    parser.add_argument('--search', nargs='?', help='File to perform a rolling search')
    parser.add_argument('--blocksize', nargs='?', type=int, default=512, help="Block size")

    args = parser.parse_args()
    db = FileDB(args.db, args.blocksize)

    if(args.ingest):
        db.ingest(args.ingest)

    if args.search:
        search_results = list(db.rollingSearch(args.search))
        search_results = sorted(search_results, key=lambda a: a[0][1])

        for a, b in search_results:
            print(f'  Match {btoh(a[0])} {pretty_fileset(a)}, {pretty_fileset(b)}')


if __name__ == "__main__":
    main()