
from util import *
import copy
import itertools
import cbor2
import heapq
import reveal_globals

#MAX_LIST_SIZE = 1000
#ZEROIZE_X86_PC_REL = True
#CLUMP_SIZE=20


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


@coroutine
def summarize_large_hash_lists(target, max_list_size):
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
        f = cbor_dump(self.path, reveal_globals.CLUMP_SIZE)
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

        output = cbor_dump(self.path, reveal_globals.CLUMP_SIZE)
        self.header = dict(files=flist, blocksize=bs, zeroize_x86_pc_rel=zi, blockAlgorithm=ba)
        output.send(self.header)
        getHash = lambda e: e[0]
        it = heapq.merge(*entryIters, key=getHash)
        u = Uniq()
        if uniq:
            output = u.uniq(summarize_large_hash_lists(output, reveal_globals.MAX_LIST_SIZE))

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
