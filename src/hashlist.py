
from util import *
import copy
import itertools
import cbor2
import heapq
import reveal_globals as rg

#MAX_LIST_SIZE = 1000
#ZEROIZE_X86_PC_REL = True
#CLUMP_SIZE=20


from enum import Enum

class HashDes(Enum):
    MATCH_LIST = 0
    SUMMARY = 1
    MAPPING = 2

class MapKey(Enum):
    # File hash and file counts are required with the Mapping type
    # FILE_COUNT = 0
    HASH_COUNT = 1
    FILE_LIST = 2
    FILE_OFFSET = 3

    # TODO: implement a way of hashing/summarizing file lists
    # Perhaps use a XOR of each file's hash?
    FILE_LIST_HASH = 4


def hdType(hashdes):
    if len(hashdes) == 2:
        if isinstance(hashdes[1], list):
            return HashDes.MATCH_LIST
        else:
            # Mapping elided - just a hash and file count to keep it simple
            return HashDes.MAPPING
    
    if len(hashdes) == 3 and isinstance(hashdes[2], dict):
        # Mapping requires a hash and file count, all other fields
        # are stored in the dictionary as optional
        return HashDes.MAPPING
    
    if len(hashdes) == 3:
        return HashDes.SUMMARY

    print(f"Unknown hashdes type: {hashdes}")

class HashData:
    def __init__(self, hashdes=None):
        self.hash = None
        self.file_count = 0
        self.hash_count = 0
        self.fids = set()
        self.file_offsets = []

        if hashdes:
            self._fromHashDes(hashdes)
           
    def _fromHashDes(self, hashdes):
        t = hdType(hashdes)
        if t == HashDes.MATCH_LIST:
            self.hash = hashdes[0]
            self.file_offsets = hashdes[1]
            self.fids = set(fid for fid, off in self.file_offsets)
            self.file_count = len(self.fids)
            self.hash_count = len(self.file_offsets)
        elif t == HashDes.SUMMARY:
            self.hash = hashdes[0]
            self.hash_count = hashdes[1]
            self.file_count = hashdes[2]
        elif t == HashDes.MAPPING:
            self.hash = hashdes[0]
            self.file_count = hashdes[1]
            if len(hashdes) > 2:
                for k, v in hashdes[2].items():
                    if k == MapKey.HASH_COUNT:
                        self.hash_count = v
                    if k == MapKey.FILE_LIST:
                        self.fids |= set(v)
                    if k == MapKey.FILE_OFFSET:
                        self.file_offsets = v
                        self.fids |= set(fid for fid, off in self.file_offsets)

    def getFirstOffset(self):
        if not self.file_offsets:
            return None
        fd, offset = self.file_offsets[0]
        return offset
                            
    def asList(self):
        return [self.hash, self.file_offsets]

    def asSummary(self):
        return [self.hash, self.hash_count, self.file_count]
    
    def asListOrSummary(self):
        if self.file_offsets:
            return self.asList()
        else:
            return self.asSummary()

    def asMapping(self):
        mapping = dict()
        mapping[MapKey.HASH_COUNT.value] = self.hash_count
        
        if self.file_offsets:
            mapping[MapKey.FILE_OFFSET.value] = list(sorted(self.file_offsets))
        elif self.fids:
            mapping[MapKey.FILE_LIST.value] = list(sorted(self.fids))
        
        result = [self.hash, self.file_count]
        if mapping:
            result.append(mapping)
        return result


def merge_hash_data(hash_datas, max_list_size):
    combined = HashData()
    combined.hash = hash_datas[0].hash
    for hd in hash_datas:
        combined.file_count += hd.file_count
        combined.hash_count += hd.hash_count
        
    if combined.hash_count < max_list_size:
        for hd in hash_datas:
            combined.file_offsets.extend(hd.file_offsets)
    if combined.file_count < max_list_size:
        for hd in hash_datas:
            combined.fids |= hd.fids
    return combined
            


def bitmask_fids(fids):
    if not fids:
        return
    max_fid = max(fids)
    bitmask = bytearray(b'\x00' * ((max_fid // 8) + 2))
    for fid in fids:
        bitmask[fid // 8] |= 1 << (fid % 8)
    return btoh(bytes(bitmask)).replace('0', ' ')


def countHashDes(hashdes):
    hd = HashData(hashdes)
    return hd.hash_count, hd.file_count
 

@coroutine
def summarize_large_hash_lists(target, max_list_size):
    """ Takes in (key, group) output from uniq2 """
    while True:
        k, g = (yield)
        g = list(g)

        hash_datas = [HashData(hd) for hd in g]
        combined = merge_hash_data(hash_datas, max_list_size)
        entry = combined.asListOrSummary()
        #entry = combined.asMapping()
        target.send(entry)


def match_list_hash(fids):
    return md5(str(sorted(set(fids))).encode('ascii'))

def fid_to_names(fids, db):
    return [db.getNameFromFID(fid, str(fid)) for fid in fids]

class HashListFile:
    def __init__(self, path):
        self.path = path
        self.header = None
        self.max_file_id = 0

    def createFile(self, hashed_file, blocksize, zeroize, blockAlgorithm, entropy_ranges):
        f = cbor_dump(self.path, rg.globs.CLUMP_SIZE)
        self.max_file_id = hashed_file.id
        self.header = dict(files=[hashed_file.getData()],
                           blocksize=blocksize,
                           zeroize_x86_pc_rel=zeroize,
                           blockAlgorithm=blockAlgorithm,
                           entropy_ranges=entropy_ranges)
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

        output = cbor_dump(self.path, rg.globs.CLUMP_SIZE)
        self.header = dict(files=flist, blocksize=bs, zeroize_x86_pc_rel=zi, blockAlgorithm=ba)
        output.send(self.header)
        getHash = lambda e: e[0]
        it = heapq.merge(*entryIters, key=getHash)
        u = Uniq()
        if uniq:
            output = u.uniq(summarize_large_hash_lists(output, rg.globs.MAX_LIST_SIZE))

        sum_hashes = status.get('sum_hashes', 0)
        n_hashes = 0
        for entry in it:
            n_hashes += 1
            output.send(entry)
            if (n_hashes % 20000) == 0:
                status.update('Merge', n_hashes=n_hashes, sum_hashes=sum_hashes+n_hashes)

        status.finish_process('Merge', n_hashes = n_hashes, sum_hashes=sum_hashes+n_hashes)
        print(f'{color.lineclear}Merged {n_hashes} hashes from {n_files} files, {len(hash_list_files)} new')


    def readHeader(self):
        with open(self.path, 'rb') as fd:
            self.header = cbor2.load(fd)
            return self.header

    def readEntries(self):
        with open(self.path, 'rb') as fd:
            self.header = cbor2.load(fd)
            try:
                if self.header.get('clumped', None):
                    while True:
                        clump = cbor2.load(fd)
                        for item in clump:
                            yield item
                else:
                    while True:
                        yield cbor2.load(fd)
            except cbor2.CBORDecodeEOF:
                pass


    def delete_file(self):
        if os.path.exists(self.path):
            os.remove(self.path)

    def getEntropyRanges(self):
        hdr = self.readHeader()
        if not hdr:
            return []
        return hdr.get('entropy_ranges', [])


    def find_matching_items(self, other, key=lambda entry: entry[0]):
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
        count_a = 0
        count_b = 0

        try:
            key_a, alist = next(A)
            key_b, blist = next(B)

            count_a += 1
            count_b += 1

            while True:
                if key_a == key_b:
                    alist = list(alist)
                    blist = list(blist)
                    for a in alist:
                        for b in blist:
                            yield (a, b)

                    key_a, alist = next(A)
                    key_b, blist = next(B)

                    count_a += 1
                    count_b += 1
                elif key_a < key_b:
                    key_a, alist = next(A)
                    count_a += 1
                else:
                    key_b, blist = next(B)
                    count_b += 1
        except StopIteration:
            pass

        #print(f'find_matching_items counts {count_a} {count_b}')
