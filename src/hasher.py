#!/usr/bin/env python3

import copy
import hashlib
import cbor2
import os
import sys
import itertools
import heapq
from math import log, log2
import array
from collections import defaultdict

MAX_LIST_SIZE = 100


class Bunch(dict):
    def __init__(self, **kw):
        dict.__init__(self, kw)
        self.__dict__ = self


color = Bunch(
    red='\033[38;5;9m',
    lightred='\033[38;5;124m',
    blue='\033[38;5;24m',
    lightblue='\033[38;5;51m',
    green='\033[38;5;112m',
    lightyellow='\033[38;5;186m',
    yellow='\033[38;5;226m',
    purple='\033[38;5;147m',
    orange='\033[38;5;208m',
    brown='\033[38;5;94m',
    white='\033[38;5;255m',
    pink='\033[38;5;212m',
    grey='\033[38;5;236m',
    emphasis='\033[01m',
    reset='\033[0m',
    underline='\033[04m',
    lineclear='\033[2K\r',
)


def coroutine(func):
    def start(*args, **kwargs):
        cr = func(*args, **kwargs)
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


@coroutine
def sorter(target, key=None):
    whole_list = []
    try:
        while True:
            item = (yield)
            whole_list.append(item)
    except GeneratorExit:
        for item in sorted(whole_list, key=key):
            target.send(item)


def md5(b):
    m = hashlib.md5()
    m.update(b)
    return m.digest()[:6]


def entropy(contents):
    counts = defaultdict(int)
    incr = 1 / len(contents)
    for c in contents:
        counts[c] += incr
    return -sum(x * log2(x) for x in counts.values()) / log2(min(256, len(contents)))


def word_entropy(block):
    contents = array.array('H', block)
    counts = defaultdict(int)
    incr = 1 / len(contents)
    for c in contents:
        counts[c] += incr
    return -sum(x * log2(x) for x in counts.values()) / log2(min(65536, len(contents)))


def dword_entropy(block):
    contents = array.array('L', block)
    counts = defaultdict(int)
    incr = 1 / len(contents)
    for c in contents:
        counts[c] += incr
    return -sum(x * log2(x) for x in counts.values()) / log2(len(contents))


def qword_entropy(block):
    contents = array.array('Q', block)
    counts = defaultdict(int)
    incr = 1 / len(contents)
    for c in contents:
        counts[c] += incr
    return -sum(x * log2(x) for x in counts.values()) / log2(len(contents))


def nib_entropy_hi(contents):
    counts = defaultdict(int)
    incr = 1 / len(contents)
    for c in contents:
        counts[c & 0xf0] += incr
    return -sum(x * log2(x) for x in counts.values()) / log2(min(16, len(contents)))


def nib_entropy_lo(contents):
    counts = defaultdict(int)
    incr = 1 / len(contents)
    for c in contents:
        counts[c & 0xf] += incr
    # print(dict(counts), contents, sum(counts.values()))
    return -sum(x * log2(x) for x in counts.values()) / log2(min(16, len(contents)))


def _entropy_color(e):
    highlight = ''
    if e > 0.90:
        highlight = color.red
    elif e > 0.7:
        highlight = color.yellow
    elif e > 0.4:
        highlight = color.green
    elif e > 0.2:
        highlight = color.blue
    return highlight


def entropy_color(block, specific_char=None):
    highlight = ''
    e = entropy(block)
    e_hi = nib_entropy_hi(block)
    e_lo = nib_entropy_lo(block)
    if e > 0.90 and e_hi > 0.67:
        highlight = color.red
    elif e > 0.7:
        highlight = color.yellow
    elif e > 0.4:
        highlight = color.green
    elif e > 0.2:
        highlight = color.blue

    if e <= 0.7 and specific_char == 0:
        highlight = color.grey
    return highlight


def format_entropy(e):
    highlight = _entropy_color(e)
    return f'{highlight}{e * 100:3.0f}{color.reset}'


def entropyFilterIter(min_entropy, blocks):
    for block in blocks:
        e = entropy(block)
        if e > min_entropy:
            yield block


def sectorEntropyFilter(min_entropy, sectors):
    for sector in sectors:
        e = sector.getEntropy()
        if e > min_entropy:
            yield sector


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


@coroutine
def _uniq2(target, keyfunc=lambda entry: entry[0]):
    """
    Similar to itertools.groupby, but done as a coroutine
    """

    curvals = []
    tgtkey = None
    try:
        curval = (yield)
        curvals = [curval]
        tgtkey = keyfunc(curval)
        while True:
            curval = (yield)
            curkey = keyfunc(curval)

            if curkey == tgtkey:
                curvals.append(curval)
            else:
                target.send((tgtkey, curvals))
                tgtkey = curkey
                curvals = [curval]
    except GeneratorExit:
        if curvals:
            target.send((curkey, curvals))
        pass


from enum import Enum


class HashDes(Enum):
    MATCH_LIST = 0
    SUMMARY = 1


def hdType(hashdes):
    if len(hashdes) == 2 and isinstance(hashdes[1], list):
        return HashDes.MATCH_LIST
    if len(hashdes) == 3:
        return HashDes.SUMMARY

    print(f"Unknown hashdes type: {hashdes}")


def countHashDes(hashdes):
    hdt = hdType(hashdes)
    if hdt == HashDes.MATCH_LIST:
        n_matches = len(hashdes[1])
        n_files = len(set([file_id for file_id, off in hashdes[1]]))
        return n_matches, n_files
    if hdt == HashDes.SUMMARY:
        n_matches, n_files = hashdes[1:]
        return n_matches, n_files


def countHashDesGroup(g):
    n_matches = 0
    n_files = 0
    file_set = set()
    for hashdes in g:
        hdt = hdType(hashdes)
        if hdt == HashDes.MATCH_LIST:
            n_matches += len(hashdes[1])
            file_set |= set([file_id for file_id, off in hashdes[1]])
        if hdt == HashDes.SUMMARY:
            n_matches += hashdes[1]
            n_files += hashdes[2]

    # With MATCH_LIST items, we deduplicate file counts from the same group using a set() on the group.
    n_files += len(file_set)

    return (n_matches, n_files)


@coroutine
def summarize_large_hash_lists(target, max_list_size=MAX_LIST_SIZE):
    """ Takes in (key, group) output from uniq2 """
    while True:
        k, g = (yield)
        g = list(g)

        all_lists = True

        all_lists = all(hdType(hd) == HashDes.MATCH_LIST for hd in g)

        n_matches, n_files = countHashDesGroup(g)

        if not all_lists or n_matches > max_list_size:
            entry = [k, n_matches, n_files]
        else:
            summaries = [e[1] for e in g]
            merged_file_lists = list(itertools.chain.from_iterable(summaries))
            entry = [k, merged_file_lists]
        target.send(entry)


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

        def thunk_ids(thunk_table, input_gen):
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
            entryIters.append(thunk_ids(current_thunk, f.readEntries()))

        output = cbor_dump(self.path)
        self.header = dict(files=flist, blocksize=bs, blockAlgorithm=ba)
        output.send(self.header)
        getHash = lambda e: e[0]
        it = heapq.merge(*entryIters, key=getHash)
        if uniq:
            output = _uniq2(summarize_large_hash_lists(output))
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
        # print(f'  {header}')
        print(f'  Blocksize {header["blocksize"]}, blockAlgorithm {header["blockAlgorithm"]}')
        print('  Files')
        for file in header['files']:
            print(f'    {btoh(file["md5"])} {file["id"]:4} {file["path"]}')

        for entry in self.readEntries():
            hashcode = entry[0]
            print(f'  {btoh(hashcode)} {pretty_fileset(entry)}')

    def find_matches(self, other, key=lambda entry: entry[0]):
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
    def __init__(self, path, id):
        full_path = path
        try:
            full_path = os.path.realpath(path)
        except OSError as e:
            print(f"Error getting real path for {path}")
            print(e)

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

    def entropyValues(self, bs):
        with self.openFile() as fd:
            offset = 0
            while True:
                buf = fd.read(bs)
                if not buf or len(buf) < bs:
                    break

                e = entropy(buf)
                yield (offset, e)

                offset += bs


    def displayEntropyMap(self, bs, COL=128):
        entropies = self.entropyValues(bs)

        for i, ent in enumerate(entropies):
            offset, e = ent
            if i % COL == 0:
                print(f"{offset:5x}: ", end='')

            print(f'{_entropy_color(e)}#{color.reset}', end='')
            if (i+1) % COL == 0:
                print()
        print()

    def fastEntropyRanges(self, bs, threshold):
        counts = [0] * 256
        nonzeros = 0
        offset = 0


        entropies = self.entropyValues(bs)
        last_hi = False
        last_change = 0
        for offset, e in entropies:
            hi = e>threshold
            if last_change == offset:
                last_hi = hi
                continue

            if hi != last_hi:
                if last_hi:
                    yield (last_change, offset)
                last_hi = hi
                last_change = offset
        if last_hi:
            yield (last_change, offset+bs)





    def coarsen_ranges(self, ranges, block_size):
        """ Smooth over entropy holes so we include the adjacent high-entropy blocks. """
        lo1, hi1 = 0, 0
        for lo2, hi2 in ranges:
            if lo2 - hi1 < block_size:
                hi1 = hi2
            elif hi1:
                yield (lo1, hi1)
                lo1, hi1 = lo2, hi2
        if hi1:
            yield (lo1, hi1)




    def genericSectorHash(self, sectors, output, uniq=True):
        # TODO: chunk large lists instead of iterating the whole thing
        sorted_sectors = sorted([sector.getHashTuple() for sector in sectors])
        if uniq:
            # sorted_sectors = _uniq(sorted_sectors)

            output = _uniq2(summarize_large_hash_lists(output))

        sectors_hashed = 0
        for hash_tuple in sorted_sectors:
            output.send(hash_tuple)
            sectors_hashed += 1
        print(f"Hashed {sectors_hashed} sectors")
        return sectors_hashed

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

    def genRollingBlocks(self, bs=10, step=1, offset=0, short_blocks=False, entropy_ranges=None):
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

    def hashBlocksToFile(self, block_size, out_file_path, short_blocks=False, uniq=True):
        hl = SimpleSectorHashList(out_file_path)
        out_file = hl.createFile(self, block_size, dict(aligned=1, step=block_size, shortBlocks=short_blocks))
        block_gen = self.genAlignedBlocks(block_size, short_blocks=short_blocks)
        sectors_hashed = self.genericSectorHash(block_gen, out_file, uniq=uniq)
        print(f'Hashed {sectors_hashed} sectors block size {block_size} in {out_file_path}')

        return hl

    def filter_sector_entropy(self, sectors, block_size, threshold=0.2, overlap = 32):
        ranges = self.fastEntropyRanges(64, 0.2)
        cranges = self.coarsen_ranges(ranges, block_size)

        range_iter = iter(cranges)


        lo, hi = 0, 0
        for sector in sectors:
            s_lo = sector.offset
            s_hi = s_lo + block_size
            if s_lo + overlap > hi:
                try:
                    lo, hi = next(range_iter)
                except StopIteration as e:
                    break

            if lo <= s_lo:
                yield sector


    def rollingHashToFile(self, block_size, out_file_path, short_blocks=False, uniq=True):
        hl = SimpleSectorHashList(out_file_path)
        block_gen = self.genRollingBlocks(block_size, short_blocks=short_blocks)
        output = hl.createFile(self, block_size, dict(aligned=0, step=1, shortBlocks=short_blocks))

        self.displayEntropyMap(64, 64)

        ranges = self.fastEntropyRanges(64, 0.2)
        cranges = self.coarsen_ranges(ranges, block_size)
        print("CRanges:")
        for lo, hi in cranges:
            print(f"Range {lo:5x}-{hi:5x}")
        # block_gen = sectorEntropyFilter(0.5, block_gen)

        #sys.exit()

        block_gen = self.filter_sector_entropy(block_gen, block_size)
        self.genericSectorHash(block_gen, output, uniq=uniq)
        return hl

    @staticmethod
    def fromData(self, file_data):
        return HashedFile(file_data['path'], file_data['id'])


class Sector:
    def __init__(self, file, data, offset):
        self.file = file
        self.data = data
        self.offset = offset
        self.end_offset = offset + len(data)
        self._hash = md5(self.data)
        # low-entropy testing hash (4 bits)
        # self._hash = bytes([md5(self.data)[0]//16])

    def hash(self):
        return self._hash

    def getHashTuple(self):
        return (self.hash(), [[self.file.id, self.offset]])

    def getEntropy(self):
        e = entropy(self.data)
        we = word_entropy(self.data)
        de = dword_entropy(self.data)
        print(f"{self.offset:x} Entropy {e:.2f} {we:.2f} {de:.2f}")
        return e


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
        print(
            f'{sector.file.path:20} {btoh(sector.data):>20} {sector.offset:3x}-{sector.end_offset:3x} Hash is {btoh(sector.hash())}')


class FileDB:
    def __init__(self, db_name, blocksize, short_blocks=False):
        self.db_name = db_name
        self.next_file_id = 1

        os.makedirs(db_name, exist_ok=True)

        self.blocksize = blocksize
        self.short_blocks = short_blocks

        self.enum_file_list()

        # self.db_file = SimpleSectorHashList(self.get_hashes_path())

    def get_hashes_path(self):
        return os.path.join(self.db_name, 'hashes.cbor')

    def get_merge_path(self):
        return os.path.join(self.db_name, 'merge.cbor')

    def open_db(self):
        return SimpleSectorHashList(self.get_hashes_path())

    def enum_file_list(self):
        # self.all_files = []
        # self.files_by_path = {}
        # self.files_by_id = {}

        self.paths_in_use = set()
        self.fids_in_use = set()

        if not os.path.exists(self.get_hashes_path()):
            return

        header = self.open_db().readHeader()
        bs = header['blocksize']
        if bs != self.blocksize:
            print(f'{color.red}WARNING: SELECTED BLOCK SIZE IS {self.blocksize}, BUT THE DATABASE SAYS IT IS {bs}.{color.reset}')
            print(f'{color.red}Changing block size to {bs}{color.reset}')
            self.blocksize = bs

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
        print(f'Ingesting {path}')
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
        fid = 0  # We don't need a valid fid
        hf = HashedFile(file_to_hash, fid)

        rolling_path = os.path.join(self.db_name, f'{btoh(hf.getWholeFileHash())}_rolling.cbor')

        rolling_hashes = hf.rollingHashToFile(self.blocksize, rolling_path, uniq=False)

        for a, b in rolling_hashes.find_matches(self.open_db()):
            yield a, b

    def countMatches(self, searchResults, countFiles=False):
        match_counts = defaultdict(int)
        for a, b in searchResults:
            a_start = a[1][0][1]
            a_end = a_start + self.blocksize

            n_matches, n_files = countHashDes(b)
            count = n_files if countFiles else n_matches

            print(f"counts from {a_start:x}-{a_end:x} {count}")
            match_counts[a_start] += count
            match_counts[a_end] -= count

        counts = []
        cumulative = 0
        for off, delta in sorted(match_counts.items()):
            if not delta:
                continue
            cumulative += delta
            counts.append((off, cumulative))
        return counts


import argparse


def main():
    parser = argparse.ArgumentParser(description='Sector hashing tool')
    parser.add_argument('db', metavar='PATH', help='The database path')
    parser.add_argument('ingest', nargs='*', help='Files to ingest into the database')
    parser.add_argument('--search', nargs='?', help='File to perform a rolling search')
    parser.add_argument('--blocksize', nargs='?', type=int, default=512, help="Block size")

    args = parser.parse_args()
    db = FileDB(args.db, args.blocksize)

    if (args.ingest):
        db.ingest(args.ingest)

    if args.search:
        search_results = list(db.rollingSearch(args.search))
        search_results = sorted(search_results, key=lambda a: a[0][1])

        for a, b in search_results:
            print(f'  Match {btoh(a[0])} {pretty_fileset(a)}, {pretty_fileset(b)}')

        counts = db.countMatches(search_results, True)
        print("Match Counts")
        for off, count in counts:
            print(f"  {off:5x} {count}")


def unique_bytes(contents, exclude=set()):
    uniq = set()
    for b in contents:
        uniq.add(b)
    return len(uniq - exclude)


def test_entropy():
    for block in [os.urandom(12) for i in range(10)] + [b' ' * 1512] + [
        b'the quick brown fox jumped over the lazy dog']:
        e = entropy(block)
        e_nib_hi = nib_entropy_hi(block)
        e_nib_lo = nib_entropy_lo(block)
        print(f"{e:5.2f} {e_nib_hi:5.2f} {e_nib_lo:5.2f}  {block[:35].hex()}")


if __name__ == "__main__":
    main()
    # test_entropy()
