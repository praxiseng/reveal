#!/usr/bin/env python3

import copy
import hashlib
import struct
import time

import cbor2
import os
import sys
import itertools
import heapq
from math import log, log2
import array
from collections import defaultdict

MAX_LIST_SIZE = 1000
ZEROIZE_X86_PC_REL = True

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

def bg_to_fg(ansi_color):
    return ansi_color.replace('\033[38;5', '\033[48;5')


class Status:
    def __init__(self, **vars):
        self.active_processes = []
        self.process_txts = {}
        self.start_times = {}

        self.vars = vars
        pass


    def start_process(self, process_name, txt_format, **vars):
        self.active_processes.append(process_name)
        self.process_txts[process_name] = txt_format
        self.start_times[process_name] = time.time()
        self.vars = {**self.vars, **vars}

    def get(self, key, default=None):
        return self.vars.get(key, default)

    def _fmt_process(self, process_name):
        txt = self.process_txts.get(process_name, '')
        return f'{self.getTimeDelta(process_name):5.2f} {txt.format(**self.vars)}'

    def getTimeDelta(self, process_name):
        return time.time() - self.start_times[process_name]


    def getOuterTimeDelta(self):
        return self.getTimeDelta(self.active_processes[0])

    def getInnerTimeDelta(self):
        return self.getTimeDelta(self.active_processes[-1])

    def _display(self):
        if not self.active_processes:
            #print(color.lineclear)
            return

        proc_txts = [f'{self._fmt_process(name)}' for name in self.active_processes]
        print(f'{color.lineclear}{" ".join(proc_txts)}', end='')

    def update(self, process_name, **vars):
        self.vars = {**self.vars, **vars}
        self._display()
        pass

    def finish_process(self, process_name, **result):
        self.vars = {**self.vars, **result}
        self._display()

        delta = self.getInnerTimeDelta()
        if(delta > 0.5):
            print()
        else:
            pass #print(color.lineclear, end='')

        self.active_processes.remove(process_name)


status = Status()


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



def similarity_color(sim):
    highlight = ''
    if sim > 0.90:
        highlight = color.red
    elif sim > 0.8:
        highlight = color.orange
    elif sim > 0.7:
        highlight = color.yellow
    elif sim > 0.4:
        highlight = color.green
    elif sim > 0.2:
        highlight = color.blue
    elif sim > 0.05:
        highlight = color.lightblue
    return bg_to_fg(highlight)

def sim_colorize(sim):
    c = similarity_color(sim)
    digit = ' '
    #digit = '0123456789#'[int(sim*10)]
    #if sim < 0.001:
    #    digit = ' '
    return f'{c}{digit}{color.reset}'



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


def match_list_hash(fids):
    return md5(str(sorted(set(fids))).encode('ascii'))

def fid_to_names(fids, db):
    return [db.getNameFromFID(fid, str(fid)) for fid in fids]

def pretty_fileset(fileset, db = None, overlapping = None):
    #hash = fileset[0]

    hdt = hdType(fileset)
    if hdt == HashDes.MATCH_LIST:
        fid_offsets = fileset[1]

        fids = [fid for fid, offset in fid_offsets]
        list_hash = match_list_hash(fids)

        ofids = fids[:]
        ohash = list_hash
        if overlapping:
            for ovr in overlapping:
                if hdType(ovr) == HashDes.MATCH_LIST:
                    ofids.extend([fid for fid, offset in ovr[1]])
            ohash = match_list_hash(ofids)
        ofids = sorted(set(ofids))

        if db:
            fid_offsets = [(db.getNameFromFID(fid, str(fid)), offset) for fid, offset in fid_offsets]
            ofids = fid_to_names(ofids, db)
        foffs = [f'{file_id}:{offset:x}' for file_id, offset in fid_offsets]

        # {" ".join(foffs):50}
        return f'{btoh(list_hash)} {btoh(ohash)} {len(ofids):4} {" ".join(foffs):50}'
        #{" ".join(ofids[:30])}  '

    if hdt == HashDes.SUMMARY:
        hashcode, nmatch, nfiles = fileset
        return f'{nmatch} matches on {nfiles} files'
    return f'??? {fileset}'


def bitmask_fids(fids):
    if not fids:
        return
    max_fid = max(fids)
    bitmask = bytearray(b'\x00' * ((max_fid // 8) + 2))
    for fid in fids:
        bitmask[fid // 8] |= 1 << (fid % 8)
    return btoh(bytes(bitmask)).replace('0', ' ')


def bitmask_fileset(fileset):

    hdt = hdType(fileset)
    if hdt == HashDes.MATCH_LIST:
        fid_offsets = fileset[1]
        fids = [fid for fid, offset in fid_offsets]
        return bitmask_fids(fids)

    if hdt == HashDes.SUMMARY:
        hash, nmatch, nfiles = fileset
        return f'{nmatch} matches on {nfiles} files'

    return f'??? {fileset}'

def hashdes_files(fileset, db):

    hdt = hdType(fileset)
    if hdt == HashDes.MATCH_LIST:
        fid_offsets = fileset[1]
        fids = [fid for fid, offset in fid_offsets]
        return ' '.join(sorted(fid_to_names(fids, db)))

    if hdt == HashDes.SUMMARY:
        hash, nmatch, nfiles = fileset
        return f'{nmatch} matches on {nfiles} files'

    return f'??? {fileset}'

def match_set_similarity(A, B):
    A = set(A)
    B = set(B)

    return len(A&B)/(len(A|B) or 1)


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

        if (not all_lists) or (n_matches > max_list_size):
            # Create summary entry
            entry = [k, n_matches, n_files]
        else:
            # Concatenate lists
            summaries = [e[1] for e in g]
            merged_file_lists = list(itertools.chain.from_iterable(summaries))
            entry = [k, merged_file_lists]
        target.send(entry)


class Uniq:
    def __init__(self):
        self.n_uniq_sectors = 0

    @coroutine
    def uniq(self, target, keyfunc=lambda entry: entry[0]):
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
                    self.n_uniq_sectors += 1
                    target.send((tgtkey, curvals))
                    tgtkey = curkey
                    curvals = [curval]
        except GeneratorExit:
            if curvals:
                self.n_uniq_sectors += 1
                target.send((curkey, curvals))


class SimpleSectorHashList:
    def __init__(self, path):
        self.path = path
        self.header = None
        self.max_file_id = 0

    def createFile(self, hashed_file, blocksize, blockAlgorithm):
        f = cbor_dump(self.path)
        self.max_file_id = hashed_file.id
        self.header = dict(files=[hashed_file.getData()],
                           blocksize=blocksize,
                           zeroize_x86_pc_rel=ZEROIZE_X86_PC_REL,
                           blockAlgorithm=blockAlgorithm)
        f.send(self.header)
        return f

    def createMerge(self, hash_list_files, uniq=True):
        headers = [f.readHeader() for f in hash_list_files]

        # TODO: check blocksize, algorithm for consistency
        bs = headers[0]['blocksize']
        ba = headers[0]['blockAlgorithm']
        zi = headers[0]['zeroize_x86_pc_rel']
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

        n_files = 0
        for i, f in enumerate(hash_list_files):
            hdr = copy.deepcopy(headers[i])
            current_thunk = {}
            hdr_files = hdr['files']
            n_files += len(hdr_files)
            for file in hdr_files:
                self.max_file_id += 1
                fid = self.max_file_id
                current_thunk[file['id']] = fid
                file['id'] = fid

            flist += hdr_files
            entryIters.append(thunk_ids(current_thunk, f.readEntries()))

        status.start_process('Merge',
                             'Merge {files_to_merge} files, {n_hashes} hashes',
                             files_to_merge = len(hash_list_files),
                             n_hashes = 0)

        output = cbor_dump(self.path)
        self.header = dict(files=flist, blocksize=bs, zeroize_x86_pc_rel=zi, blockAlgorithm=ba)
        output.send(self.header)
        getHash = lambda e: e[0]
        it = heapq.merge(*entryIters, key=getHash)
        u = Uniq()
        if uniq:
            output = u.uniq(summarize_large_hash_lists(output))

        sum_hashes = status.get('sum_hashes', 0)
        n_hashes = 0
        for entry in it:
            n_hashes += 1
            output.send(entry)
            if (n_hashes % 20000) == 0:
                status.update('Merge', n_hashes=n_hashes, sum_hashes=sum_hashes+n_hashes)

        status.finish_process('Merge', n_hashes = n_hashes, sum_hashes=sum_hashes+n_hashes)
        print(f'Merged {n_hashes} hashes from {n_files} files, {len(hash_list_files)} new')

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




class MemFile:
    def __init__(self, path):
        self.n_removed = 0

        with open(path, 'rb') as fd:
            self.data = fd.read()

        self.offset = 0

        if ZEROIZE_X86_PC_REL:
            self.zeroize_x86_pc_rel()

    def scan_byte(self, byte_val):
        offset = -1

        try:
            while True:
                offset = self.data.index(byte_val, offset+1)
                yield offset
        except ValueError:
            pass


    def zeroize(self, off, nbytes=4):
        self.n_removed += 1
        for i in range(off, off+nbytes):
            self.data[i] = 0

    def zeroize_if(self, off, min_val, max_val):
        val, = struct.unpack('<i', self.data[off:off+4])
        if min_val <= val < max_val:
            self.zeroize(off)

    def zeroize_x86_pc_rel(self):
        MAX_REL = 2<<20
        MIN_REL = -MAX_REL


        n_removed = 0

        self.data = bytearray(self.data)

        relcall = 0xe8
        reljmp = 0xe9
        offset = -1
        for opcode in [relcall, reljmp]:
            for offset in self.scan_byte(opcode):
                self.zeroize(offset+1)


        lea = 0x8d
        mov_load = 0x8b
        mov_store = 0x89
        cmp = 0x39
        movsxd = 0x63
        coprocessor = [0xdb, 0xdb]
        modrm_instructions =  [lea, mov_load, mov_store, cmp, movsxd] + coprocessor

        for opcode in modrm_instructions:
            for offset in self.scan_byte(opcode):
                modrm = self.data[offset+1]
                is_pc_rel = (modrm & 0xc7) == 0x05

                if not is_pc_rel:
                    continue

                self.zeroize(offset + 2)

        offset = -1

        for offset in self.scan_byte(0x0f):
            opcode_byte2 = self.data[offset+1]

            jmp_codes = list(range(0x80, 0x90))
            movdqa = 0x6f

            if opcode_byte2 not in jmp_codes + [movdqa]:
                continue

            self.zeroize(offset + 2)

        for offset in self.scan_byte(0xff):
            opcode_byte2 = self.data[offset+1]

            near_call = 0x15
            if opcode_byte2 not in [near_call]:
                continue

            self.zeroize(offset+2)

        #print(f'Removed {n_removed}')
        self.data = bytes(self.data)


    def read(self, nbytes=None):
        end = self.offset+nbytes if nbytes != None else None
        data = self.data[self.offset:end]
        self.offset += len(data)
        return data

    def __enter__(self):
        return self
    def __exit__(self ,type, value, traceback):
        return False

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

        self.sectors_entropy_hi = 0
        self.sectors_entropy_lo = 0

        self.n_uniq_sectors = 0

        self.filesize = os.path.getsize(path)


    def openFile(self):
        #return open(self.path, 'rb')
        return MemFile(self.path)

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
        first = True
        for lo2, hi2 in ranges:
            if first:
                first = False
                lo1, hi1 = lo2, hi2
                continue
            if lo2 - hi1 < block_size:
                hi1 = hi2
            elif hi1:
                yield (lo1, hi1)
                lo1, hi1 = lo2, hi2
        if hi1:
            yield (lo1, hi1)

    def genericSectorHash(self, sectors, output, uniq=True):
        # TODO: chunk large lists instead of iterating the whole thing

        status.start_process("Hashing",
                             'Hash  ' + (' '*8) + '{sectors_hashed:<7} {filepath}',
                             sectors_hashed = 0, filepath = self.path)

        sector_list = []
        sum_hashes = status.get('sum_hashes', 0)
        sectors_hashed = 0
        for sector in sectors:
            sector_list.append(sector.getHashTuple())
            if (sectors_hashed % 20000) == 0:
                status.update("Hashing", sectors_hashed=sectors_hashed, sum_hashes=sum_hashes+sectors_hashed)
            sectors_hashed += 1
        status.finish_process("Hashing", sectors_hashed=sectors_hashed, sum_hashes=sum_hashes+sectors_hashed)


        status.start_process("Sorting", 'Sort  ' + (' '*8) + '{sectors_hashed:<7} {filepath}')
        sorted_sectors = sorted(sector_list)
        status.finish_process("Sorting")

        u = Uniq()
        if uniq:
            output = u.uniq(summarize_large_hash_lists(output))
        else:
            u.n_uniq_sectors = len(sorted_sectors)

        status.start_process("Output", 'Write {n_uniq_sectors:7}/{sectors_written:<7} {filepath}',
                             sectors_written=0,
                             n_uniq_sectors=u.n_uniq_sectors)

        sectors_written = 0

        sum_uniq = status.get('sum_uniq_hashes', 0)
        for hash_tuple in sorted_sectors:
            sectors_written += 1
            output.send(hash_tuple)

            if sectors_written % 10000 == 0:
                status.update('Output',
                              sectors_written=sectors_written,
                              n_uniq_sectors=self.n_uniq_sectors,
                              sum_uniq_hashes=sum_uniq+u.n_uniq_sectors)

        status.finish_process('Output',
                              sectors_written=sectors_written,
                              n_uniq_sectors=self.n_uniq_sectors,
                              sum_uniq_hashes=sum_uniq+u.n_uniq_sectors)

        return (sectors_hashed, self.n_uniq_sectors)

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

        return hl

    def filter_sector_entropy(self, sectors, block_size, threshold=0.2, overlap = None):
        ranges = self.fastEntropyRanges(64, 0.2)
        cranges = self.coarsen_ranges(ranges, block_size)

        if overlap == None:
            overlap = block_size // 2

        cranges = list(cranges)

        range_iter = iter(cranges)


        lo, hi = 0, 0
        self.sectors_entropy_hi = 0
        self.sectors_entropy_lo = 0
        for sector in sectors:
            s_lo = sector.offset
            s_hi = s_lo + block_size
            if s_lo + overlap > hi:
                try:
                    lo, hi = next(range_iter)
                except StopIteration as e:
                    break

            if lo <= s_lo:
                self.sectors_entropy_hi += 1
                yield sector
            else:
                self.sectors_entropy_lo += 1
        #print(f'Entropy: {self.sectors_entropy_lo} low, {self.sectors_entropy_hi} high')



    def rollingHashToFile(self, block_size, out_file_path, step=1, short_blocks=False, uniq=True):
        hl = SimpleSectorHashList(out_file_path)

        block_gen = self.genRollingBlocks(block_size, step=step, short_blocks=short_blocks)
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

        self.file_offset_thunks = []

        # self.db_file = SimpleSectorHashList(self.get_hashes_path())

    def get_hashes_path(self):
        return os.path.join(self.db_name, 'hashes.cbor')

    def get_merge_path(self):
        return os.path.join(self.db_name, 'merge.cbor')

    def open_db(self):
        return SimpleSectorHashList(self.get_hashes_path())


    def add_file_offset_thunk(self, thunk):
        self.file_offset_thunks.append(thunk)

    def find_thunks(self, address, only_nearest=True):
        for thunk in self.file_offset_thunks:
            thunk_results = []
            for a, b, meta in thunk.all_in_range(address):
                trans = try_translate(address, a, b)
                thunk_off = address - a[0]

                thunk_results.append((meta['name'], trans, thunk_off, meta))

            if only_nearest:
                if not thunk_results:
                    continue
                thunk_results = sorted(thunk_results, key = lambda result : result[2])
                yield thunk_results[0]
            else:
                for result in thunk_results:
                    yield result

    def thunk_txt(self, address):
        txt = []
        for name, new_addr, thunk_off, meta in self.find_thunks(address):
            if name:
                txt.append(f'{name}+{thunk_off:x}')
            else:
                txt.append('??')
        return ' '.join(txt)

    def enum_file_list(self):
        # self.all_files = []
        # self.files_by_path = {}
        # self.files_by_id = {}

        self.paths_in_use = set()
        self.fids_in_use = set()

        self.fid_to_path = {}

        if not os.path.exists(self.get_hashes_path()):
            return

        header = self.open_db().readHeader()
        bs = header['blocksize']
        if bs != self.blocksize:
            print(f'{color.red}WARNING: SELECTED BLOCK SIZE IS {self.blocksize}, BUT THE DATABASE SAYS IT IS {bs}.{color.reset}')
            print(f'{color.red}Changing block size to {bs}{color.reset}')
            self.blocksize = bs
        global ZEROIZE_X86_PC_REL

        db_zeroize = header.get('zeroize_x86_pc_rel', False)
        if ZEROIZE_X86_PC_REL != db_zeroize:

            print(f'{color.red}WARNING: ZEROIZE_X86_PC_REL IS {ZEROIZE_X86_PC_REL}, BUT THE DATABASE SAYS IT IS {db_zeroize}.{color.reset}')
            print(f'{color.red}Changing ZEROIZE_X86_PC_REL to {db_zeroize}{color.reset}')
            ZEROIZE_X86_PC_REL = db_zeroize

        for file in header['files']:
            path = file['path']
            fid = file['id']


            if path in self.paths_in_use:
                print(f'Warning: duplication of path {path}')
            if fid in self.fids_in_use:
                print(f'Warning: duplication of file ID {fid}')
            self.paths_in_use.add(path)
            self.fids_in_use.add(fid)

            self.fid_to_path[fid] = path

    def getPathFromFID(self, fid, default=None):
        return self.fid_to_path.get(fid, default)

    def getNameFromFID(self, fid, default=None):
        path = self.getPathFromFID(fid, None)
        if path==None:
            return default
        return os.path.basename(path)


    def _mk_hashed_file(self, path):
        hf = HashedFile(path, self.next_file_id)
        self.next_file_id += 1
        return hf

    def _tmpname(self, hashedFile):
        return os.path.join(self.db_name, f'{btoh(hashedFile.getWholeFileHash())}_{hashedFile.id}')

    def _hash_file(self, path):
        #print(f'Ingesting {path}')
        hf = self._mk_hashed_file(path)
        hashlist = hf.hashBlocksToFile(self.blocksize, self._tmpname(hf), self.short_blocks)
        return hashlist

    def ingest(self, paths, force_existing=False):
        if isinstance(paths, (str, bytes)):
            paths = [paths]

        if not force_existing:
            paths = [get_full_path(path) for path in paths]
            paths = [path for path in paths if path not in self.paths_in_use]

        hash_files = []
        status.start_process('Ingest',
                             'Ingest {ingest_file_index:4} of {files_to_ingest:<4} {sum_uniq_hashes:7}/{sum_hashes:<7} hashes',
                             ingest_file_index=0,
                             files_to_ingest=len(paths),
                             filepath = '',
                             filename = '',
                             sum_hashes = 0,
                             sum_uniq_hashes = 0)

        for i, path in enumerate(paths):
            status.update('Ingest', ingest_file_index=i+1, filepath=path, filename=os.path.basename(path))
            hash_files.append(self._hash_file(path))
        status.finish_process('Ingest')

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

    def rollingSearch(self, file_to_hash, step=1):
        fid = 0  # We don't need a valid fid
        hf = HashedFile(file_to_hash, fid)

        rolling_path = os.path.join(self.db_name, f'{btoh(hf.getWholeFileHash())}_rolling.cbor')

        rolling_hashes = hf.rollingHashToFile(self.blocksize, rolling_path, step=step, uniq=False)

        for a, b in rolling_hashes.find_matches(self.open_db()):
            yield a, b, self.blocksize

    def countMatches(self, searchResults, countFiles=False):
        match_counts = defaultdict(int)
        for a, b, l in searchResults:
            a_start = a[1][0][1]
            a_end = a_start + l #self.blocksize

            n_matches, n_files = countHashDes(b)
            count = n_files if countFiles else n_matches

            #print(f"counts from {a_start:x}-{a_end:x} {count}")
            match_counts[a_start] += count
            match_counts[a_end] -= count

        counts = []
        cumulative = 0

        last_off_delta = (0, 0, 0)
        for off, delta in sorted(match_counts.items()):
            if not delta:
                continue
            cumulative += delta

            if last_off_delta:
                counts.append(last_off_delta)
            last_off_delta = (off, cumulative, off - last_off_delta[0])
        counts.append(last_off_delta or (0, 0, 0))
        return counts

    def countMatches2(self, searchResults, countFiles=False):
        ''' Like countMatches, but account for overlapping intervals by incrementing/decrementing steps.
        '''
        match_counts = defaultdict(lambda:defaultdict(int))
        for a, b, l in searchResults:
            a_start = a[1][0][1]
            a_end = a_start + l #self.blocksize

            n_matches, n_files = countHashDes(b)
            count = n_files if countFiles else n_matches

            #print(f"counts from {a_start:x}-{a_end:x} {count}")
            if hdType(b) == HashDes.MATCH_LIST:
                for b_fid, b_offset in b[1]:
                    match_counts[a_start][b_fid] += 1
                    match_counts[a_end][b_fid] -= 1
            else:
                match_counts[a_start][-1] += count
                match_counts[a_end][-1] -= count

        counts = []
        cumulative = defaultdict(int)

        last_off_delta = None
        for off, deltas in sorted(match_counts.items()):
            if not deltas:
                continue

            for fid, delta in deltas.items():
                cumulative[fid] += delta

            files_present = sorted(set(fid for fid, count in cumulative.items() if count > 0))

            total = sum(count for count in cumulative.values())

            if last_off_delta:
                o, t, r, p = last_off_delta
                #if o+r >= off:
                r = off - o
                counts.append((o, t, r, p))

            run_len = off - (last_off_delta or [0])[0]
            last_off_delta = (off, total, run_len, files_present)
        counts.append(last_off_delta or (0, 0, 0, []))
        return counts

import argparse

def match_end(a1, a2, l1):
    fid1, off1 = a1
    fid2, off2 = a2
    #print(f'match_end {a1}, {a2}, {l1}')
    return fid1==fid2 and off2 == off1+l1


class MatchRun:
    def __init__(self, a, b, l):
        self.a = a
        self.b = b
        self.l = l

        self.offset = a[1][0][1]
        self.end = self.offset + self.l

        self.merged = False

        self.fds = None
        if HashDes.MATCH_LIST == hdType(b):
            self.fds = set(fid for fid, offset in b[1])

        #print(f'mr {self.offset:x}-{self.end:x} {self.l:x}')

    def can_merge(self, other):
        if other.offset != self.end:
            return False
        if not all(HashDes.MATCH_LIST == hdType(x) for x in [self.b, other.b]):
            return False
        if self.fds != other.fds:
            return False
        return True

    def merge(self, other):
        self.end = other.end
        self.l += other.l
        other.merged = True

def merge_runs(search_results):
    active_runs = []

    result_offsets = {}

    match_runs = []
    for a, b, l in search_results:
        mr = MatchRun(a, b, l)
        match_runs.append(mr)

        result_offsets[mr.offset] = mr

    for mr in match_runs:
        if mr.merged:
            continue
        while True:
            other = result_offsets.get(mr.end, None)
            if not other:
                break
            if not mr.can_merge(other):
                break
            mr.merge(other)

    for mr in match_runs:
        if not mr.merged:
            yield (mr.a, mr.b, mr.l)



    '''
    for a, b, l in search_results:
        appended = False

        for current_run in active_runs:
            a0, b0, l0 = current_run


            if all(HashDes.MATCH_LIST == hdType(x) for x in [a0, a, b0, b]) and \
               all(len(x[1]) == 1 for x in [a0, a]):
                if match_end(a0[1][0], a[1][0], l0):
                    if all(match_end(b1, b2, l0) for b1, b2 in zip(b0[1], b[1])):
                        current_run[2] += l
                        appended = True
                        #current_run = [a0, b0, l0+l]
                        break


        if not appended:
            active_runs.append([a, b, l])

        for aged_index, current_run in enumerate(active_runs):

            a0, b0, l0 = current_run

            if any(HashDes.MATCH_LIST != hdType(x) for x in [a0, b0]):
                continue

            a_offset = a[1][0][1]
            a0_offset = a0[1][0][1]
            if a_offset > a0_offset+l0+1024:
                continue

            break

        # produce items in the same order we were given them
        inactive = active_runs[:aged_index]
        active_runs = active_runs[aged_index:]

        for run in inactive:
            yield run

    for current_run in active_runs:
        yield current_run
    '''


class Matchset:
    def __init__(self, off, runlen, present):
        self.off = off
        self.runlen = runlen
        self.present = present
        self.nearest = []

        self.label = None

        self.labels = []

    def similarity(self, other):
        return match_set_similarity(self.present, other.present)

    def rank_close(self, matchsets):
        if not self.nearest:
            self.nearest = sorted([(self.similarity(other), other) for other in matchsets], key=lambda x: -x[0])
        return self.nearest

    def neighbors(self, matchsets, min_sim):
        return {other.off : other for sim, other in self.rank_close(matchsets) if sim > min_sim}


def DBSCAN(DB, min_sim, minPts):
    C = 0
    for P in DB:
        P.label = None

    for P in DB:
        if P.label != None:
            continue
        N = P.neighbors(DB, min_sim)
        if len(N) < minPts:
            P.label = -1 # Noise
            continue
        C += 1

        S_set = set(N.keys())
        S = list(N.values())
        i = 0 # have to do it this way because we are changing the list size
        while i < len(S):
            Q = S[i]
            i += 1

            # Change noise to border point
            if Q.label == -1:
                Q.label = C

            if Q.label != None:
                continue

            Q.label = C


            N = Q.neighbors(DB, min_sim)
            if len(N) >= minPts: # Handle core point
                added_one = False
                for off, other in N.items():
                    if off in S_set:
                        continue
                    added_one = True
                    S_set.add(off)
                    S.append(other)


class FileByteMatch:
    def __init__(self, fid):
        self.fid = fid

        self.total_bytes_matched = 0
        self.offset_length = []


    def add_match(self, offset, length):
        self.total_bytes_matched += length
        self.offset_length.append((offset, length))

    def sort(self):
        self.offset_length = sorted(self.offset_length)

    def set_similarity(self, other):
        pass



def per_file_amount_matched(search_results, db):
    bytes_matched = defaultdict(int)
    fbms = {}
    for a, b, l in search_results:
        if hdType(b) != HashDes.MATCH_LIST:
            continue

        for fid, offset in b[1]:
            if fid not in fbms:
                fbms[fid] = FileByteMatch(fid)
            fbm = fbms[fid]
            fbm.add_match(offset, l)


    file_matches = sorted(fbms.values(), key = lambda fbm : -fbm.total_bytes_matched)

    for fbm in file_matches:
        name = db.getNameFromFID(fbm.fid, str(fbm.fid))

        offsets = sorted(fbm.offset_length)
        offset_txt = ' '.join(f'{off:x}' for off, len in offsets)
        print(f'{fbm.fid:4} {fbm.total_bytes_matched:8} {name:24} {offset_txt[:200]}')





def group_matchsets(matchsets, db):

    try_dbscan = False
    if try_dbscan:
        for threshold in [0.4, 0.45, 0.5, 0.55, 0.6, 0.7, 0.8, 0.9, 0.95, 0.97, 0.99, 0.995]:
            DBSCAN(matchsets, threshold, 2)
            for ms in matchsets:
                ms.labels.append(ms.label)

        matchsets = sorted(matchsets, key=lambda ms : ms.labels)


    for ms in matchsets:
        sims = [ms.similarity(other) for other in matchsets]
        # simtxt = [f'{sim*100:3.0f}' for sim in sims]
        simtxt = [sim_colorize(sim) for sim in sims]
        lbltxt = ','.join(str(lbl) for lbl in ms.labels if lbl!=-1)
        print(f'{ms.off:8x}+{ms.runlen:<5x} {lbltxt:24} {len(ms.present):5}  {"".join(simtxt)}')


    for ms in matchsets:
        ms.rank_close(matchsets)

        close = ms.nearest[:3]   #[other for sim, other in sims if sim > 0.9]

        close_txt = [f'{sim:.3f}:{other.off:x}+{other.runlen:x}' for sim, other in close]

        lbltxt = ','.join(str(lbl) for lbl in ms.labels if lbl!=-1)

        filetxt = ' '.join(sorted(fid_to_names(ms.present, db)))

        print(f'{ms.off:8x}+{ms.runlen:<5x}  {lbltxt:24} {len(ms.present):5}  {filetxt[:300]}')
        #{"    ".join(close_txt)}



def try_translate(address, a_range, b_range):
    a_lo, a_len = a_range
    if a_lo <= address < a_lo + a_len:
        b_lo, b_len = b_range
        a_off = address - a_lo

        if a_off < b_len:
            return b_lo + a_off

    return None




class Thunk:
    def __init__(self, a_name, b_name):
        self.a_name = a_name
        self.b_name = b_name

        self.map = []

    def add(self, a_range, b_range, meta):
        self.map.append((a_range, b_range, meta))


    def all_in_range(self, address):
        for a_range, b_range, meta in self.map:
            a_lo, a_len = a_range
            if a_lo <= address < a_lo + a_len:
                yield a_range, b_range, meta

    def all_in_range_reverse(self, address):
        for a_range, b_range, meta in self.map:
            b_lo, b_len = b_range
            if b_lo <= address < b_lo + b_len:
                yield a_range, b_range, meta

    def translate(self, address):
        for a_range, b_range, meta in self.all_in_range(address):
            new_off = try_translate(address, a_range, b_range)
            if new_off != None:
                return new_off, meta
        return None, None

    def inverse_translate(self, address):
        for a_range, b_range, meta in self.all_in_range_reverse(address):
            new_off = try_translate(address, b_range, a_range)
            if new_off != None:
                return new_off, meta
        return None, None


from elftools.elf.elffile import ELFFile
class ELFThunks:
    def __init__(self, path):
        with open(path, 'rb') as f:
            elffile = ELFFile(f)

            self.section_thunk = Thunk('File Offset', 'Virtual Address')
            self.segment_thunk = Thunk('File Offset', 'Virtual Address')

            for sect in elffile.iter_sections():
                flags = sect.header['sh_flags']
                flag_map = [(2, 'A'), (1, 'W'), (4, 'X')]
                flag_txt = ''.join(txt if (flags & mask) else ' ' for mask, txt in flag_map)

                sh_type = sect.header['sh_type']
                sh_addr = sect.header['sh_addr']  # first virtual address
                sh_offset = sect.header['sh_offset']  # file offset
                sh_size = sect.header['sh_size']

                allocated = (flags & 2) != 0
                has_file_bytes = 'SHT_NOBITS' != sh_type

                mem_size = sh_size if allocated else 0
                file_size = sh_size if has_file_bytes else 0

                meta = dict(name = sect.name or sh_type, struct = dict(sect.header))
                self.segment_thunk.add((sh_offset,file_size), (sh_addr,mem_size), meta)


                print(
                    f'Section {sect.name:20} {flag_txt} {sh_offset:6x}+{file_size:<6x}  {sh_addr:6x}+{mem_size:<6x} {sect.header}')

            for seg in elffile.iter_segments():
                p_type = seg.header['p_type']
                p_offset = seg.header['p_offset']
                p_vaddr = seg.header['p_vaddr']
                p_paddr = seg.header['p_paddr']
                p_filesz = seg.header['p_filesz']
                p_memsz = seg.header['p_memsz']

                flags = seg.header['p_flags']

                flagmap = [(4, 'R'), (2, 'W'), (1, 'X')]
                flagtxt = ''.join(txt if (flags & mask) else ' ' for mask, txt in flagmap)

                meta = dict(name = p_type, struct = dict(seg.header))
                self.section_thunk.add((p_offset, p_filesz), (p_vaddr, p_memsz), meta)


                print(f'Segment {p_type:20} {flagtxt} {p_offset:6x}+{p_filesz:<6x} {p_vaddr:6x}+{p_memsz:<6x} {dict(seg.header)}')


def main():
    parser = argparse.ArgumentParser(description='Sector hashing tool')
    parser.add_argument('db', metavar='PATH', help='The database path')
    parser.add_argument('ingest', nargs='*', help='Files to ingest into the database')
    parser.add_argument('--search', nargs='?', help='File to perform a rolling search')
    parser.add_argument('--step', metavar='N', type=int, default=1, help='Step size for rolling search.')
    parser.add_argument('--blocksize', nargs='?', type=int, default=512, help="Block size")
    parser.add_argument('--zeroize', action='store_true',
                        help='Zero out immediate operands that look like x86_64 PC relative addresses')

    args = parser.parse_args()

    global ZEROIZE_X86_PC_REL
    ZEROIZE_X86_PC_REL = args.zeroize

    db = FileDB(args.db, args.blocksize)

    if args.ingest:
        db.ingest(args.ingest)

    if args.search:
        et = ELFThunks(args.search)
        db.add_file_offset_thunk(et.section_thunk)
        db.add_file_offset_thunk(et.segment_thunk)


        search_results = list(db.rollingSearch(args.search, step=args.step))
        search_results = sorted(search_results, key=lambda a: a[0][1])
        search_results = list(merge_runs(search_results))

        recent_results = []
        print('MATCH LISTS')
        for a, b, l in search_results:
            offset = a[1][0][1]

            overlapping = [b0 for offset0, len0, b0 in recent_results if offset0 <= offset <= offset0+len0]

            n_matches, n_files = countHashDes(b)

            print(f'  Match {btoh(a[0])} {n_matches:3}/{n_files:<3} {offset:5x}+{l:<5x} {pretty_fileset(b, db, overlapping)}')

            recent_results.append((offset, l, b))
            if len(recent_results) > 512:
                recent_results = recent_results[-512:]


        print('MATCH BITMASK')
        for a, b, l in search_results:
            n_matches, n_files = countHashDes(b)
            present_txt = hashdes_files(b, db)
            #present_txt = bitmask_fileset(b)
            print(f'  Match {btoh(a[0])} {n_matches:3}/{n_files:<3} {a[1][0][1]:5x}+{l:<5x} {present_txt}')

        counts = db.countMatches2(search_results, True)

        #per_file_amount_matched(search_results, db)

        print("Match Counts")


        last_present = set()

        matchsets = []
        prior_sets = set()

        for off, count, runlen, present in counts:
            list_hash = match_list_hash(present)

            sim = match_set_similarity(present, last_present)
            last_present = set(present)

            s = frozenset(present)

            if present and s not in prior_sets:
                prior_sets.add(s)
                matchsets.append(Matchset(off, runlen, s))


            present_txt = ' '.join(sorted(fid_to_names(present, db)))

            tt = db.thunk_txt(off)
            #present_txt = bitmask_fids(present)
            print(f"  {off:5x}+{runlen:<5x} {tt:32} {sim:5.3f} {count:4} {len(present):4}   {present_txt[:300]}")
            #present_txt = ' '.join(sorted(fid_to_names(present, db)))
            #print(f"  {off:5x}+{runlen:<5x} {count:4} {' '.join(present_txt[:30])}"


        #group_matchsets(matchsets, db)





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

'''
from tkinter import *
from tkinter import ttk
root = Tk()
frm = ttk.Frame(root, padding=10)
frm.grid()
ttk.Label(frm, text="Hello World!").grid(column=0, row=0)
ttk.Button(frm, text="Quit", command=root.destroy).grid(column=1, row=0)
root.mainloop()
'''