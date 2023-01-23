
import globals
import os
from util import *
from hashlist import *
from entropy import *




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
        #print(f"{self.offset:x} Entropy {e:.2f} {we:.2f} {de:.2f}")
        return e


class MemFile:
    def __init__(self, path):
        self.n_removed = 0

        with open(path, 'rb') as fd:
            self.data = fd.read()

        self.offset = 0

        if globals.ZEROIZE_X86_PC_REL:
            status.start_process('Zeroize', 'Zeroizing    {n_zeroize:8} {filename}', n_zeroize=0, filename=path)
            self.zeroize_x86_pc_rel()
            status.finish_process('Zeroize', n_zeroize=self.n_removed)

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

        if self.n_removed % 100000 == 0:
            status.update('Zeroize', n_zeroize=self.n_removed)
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

    def __enter__(self):
        return FileCursor(self)

    def __exit__(self ,type, value, traceback):
        return False

class FileCursor:
    def __init__(self, memfile):
        self.offset = 0
        self.memfile = memfile

    def read(self, nbytes=None):
        end = self.offset+nbytes if nbytes != None else None
        data = self.memfile.data[self.offset:end]
        self.offset += len(data)
        return data


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

        self.entropy_block_size = -1
        self.entropy_ranges = []
        self.entropy_threshold = 0.2

        self.n_uniq_sectors = 0

        self.filesize = os.path.getsize(path)

        self.file_data = None


    def openFile(self):
        #return open(self.path, 'rb')
        if not self.file_data:
            self.file_data = MemFile(self.path)
        return self.file_data

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

            print(f'{entropy_color2(e)}#{color.reset}', end='')
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
            output = u.uniq(summarize_large_hash_lists(output, globals.MAX_LIST_SIZE))
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

    def genRollingBlocks(self, bs=10, step=1, offset=0, short_blocks=False, entropy_ranges=None, limit_range=None):
        with self.openFile() as in_fd:
            lo, hi = None, None
            if limit_range:
                lo, hi = limit_range
                offset+=lo
                in_fd.read(lo)
            data = in_fd.read(bs)
            while True:
                if not data:
                    break
                if not short_blocks and len(data) < bs:
                    break

                yield Sector(self, data, offset)

                data = data[step:] + in_fd.read(step)
                offset += step

                if hi and offset >= hi:
                    break


    def hashBlocksToFile(self, block_size, out_file_path, short_blocks=False, uniq=True, entropy_threshold=0.2):
        hl = HashListFile(out_file_path)
        out_file = hl.createFile(self,
                                 block_size,
                                 globals.ZEROIZE_X86_PC_REL,
                                 dict(aligned=1, step=block_size, shortBlocks=short_blocks),
                                 self.get_entropy_ranges(block_size, entropy_threshold=entropy_threshold))
        block_gen = self.genAlignedBlocks(block_size, short_blocks=short_blocks)
        sectors_hashed = self.genericSectorHash(block_gen, out_file, uniq=uniq)

        return hl

    def get_entropy_ranges(self, block_size, entropy_threshold):
        if self.entropy_block_size != block_size or self.entropy_threshold != entropy_threshold:

            self.entropy_block_size = block_size
            self.entropy_threshold = entropy_threshold

            ranges = self.fastEntropyRanges(64, entropy_threshold)
            coarse_ranges = self.coarsen_ranges(ranges, block_size)
            self.entropy_ranges = list(coarse_ranges)
        return self.entropy_ranges

    def filter_sector_entropy(self, sectors, block_size, threshold=0.2, overlap=None):
        if overlap == None:
            overlap = block_size//2

        range_iter = iter(self.get_entropy_ranges(block_size, threshold))

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

    def rollingHashToFile(self,
                          block_size,
                          out_file_path,
                          step=1,
                          short_blocks=False,
                          uniq=True,
                          entropy_threshold=0.2,
                          limit_range=None):
        hl = HashListFile(out_file_path)

        block_gen = self.genRollingBlocks(block_size, step=step, short_blocks=short_blocks, limit_range=limit_range)
        output = hl.createFile(self,
                               block_size,
                               globals.ZEROIZE_X86_PC_REL,
                               dict(aligned=0, step=1, shortBlocks=short_blocks),
                               self.get_entropy_ranges(block_size, entropy_threshold))

        self.displayEntropyMap(64, 64)

        ranges = self.get_entropy_ranges(block_size, entropy_threshold)
        print("CRanges:")
        for lo, hi in ranges:
            print(f"Range {lo:5x}-{hi:5x}")
        # block_gen = sectorEntropyFilter(0.5, block_gen)

        #sys.exit()

        block_gen = self.filter_sector_entropy(block_gen, block_size, threshold=entropy_threshold)
        self.genericSectorHash(block_gen, output, uniq=uniq)
        return hl

    @staticmethod
    def fromData(self, file_data):
        return HashedFile(file_data['path'], file_data['id'])
