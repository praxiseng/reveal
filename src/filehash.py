from typing import Generator

from src.util import *
from src.entropy import *
import struct


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
        # print(f"{self.offset:x} Entropy {e:.2f} {we:.2f} {de:.2f}")
        return e


class MemFile:
    def __init__(self, path, data, zeroize):
        self.n_removed = 0

        if data:
            self.data = data
        else:
            with open(path, 'rb') as fd:
                self.data = fd.read()

        self.offset = 0

        if zeroize:
            # status.start_process('Zeroize', 'Zeroizing    {n_zeroize:8} {filename}', n_zeroize=0, filename=path)
            self.zeroize_x86_pc_rel()
            # status.finish_process('Zeroize', n_zeroize=self.n_removed)

    def scan_byte(self, byte_val):
        offset = -1

        try:
            while True:
                offset = self.data.index(byte_val, offset + 1)
                yield offset
        except ValueError:
            pass

    def zeroize(self, off, nbytes=4):
        self.n_removed += 1

        # if self.n_removed % 100000 == 0:
        #     status.update('Zeroize', n_zeroize=self.n_removed)
        try:
            for i in range(off, off + nbytes):
                self.data[i] = 0
        except IndexError:
            # Tried to zeroize past end of file?
            pass

    def zeroize_if(self, off, min_val, max_val):
        val, = struct.unpack('<i', self.data[off:off + 4])
        if min_val <= val < max_val:
            self.zeroize(off)

    def zeroize_x86_pc_rel(self):
        MAX_REL = 2 << 20
        MIN_REL = -MAX_REL

        n_removed = 0

        # Convert to a bytearray so that it will be read/write
        self.data = bytearray(self.data)

        relcall = 0xe8
        reljmp = 0xe9
        offset = -1
        for opcode in [relcall, reljmp]:
            for offset in self.scan_byte(opcode):
                self.zeroize(offset + 1)

        lea = 0x8d
        mov_load = 0x8b
        mov_store = 0x89
        cmp = 0x39
        movsxd = 0x63
        coprocessor = [0xdb, 0xdb]
        modrm_instructions = [lea, mov_load, mov_store, cmp, movsxd] + coprocessor

        for opcode in modrm_instructions:
            for offset in self.scan_byte(opcode):
                if offset + 1 >= len(self.data):
                    continue

                modrm = self.data[offset + 1]
                is_pc_rel = (modrm & 0xc7) == 0x05

                if not is_pc_rel:
                    continue

                self.zeroize(offset + 2)

        offset = -1

        for offset in self.scan_byte(0x0f):
            if offset+1 >= len(self.data):
                continue

            opcode_byte2 = self.data[offset + 1]

            jmp_codes = list(range(0x80, 0x90))
            movdqa = 0x6f

            if opcode_byte2 not in jmp_codes + [movdqa]:
                continue

            self.zeroize(offset + 2)

        for offset in self.scan_byte(0xff):
            if offset+1 >= len(self.data):
                continue
            opcode_byte2 = self.data[offset + 1]

            near_call = 0x15
            if opcode_byte2 not in [near_call]:
                continue

            self.zeroize(offset + 2)

        # print(f'Removed {n_removed}')
        self.data = bytes(self.data)

    def __enter__(self):
        return FileCursor(self)

    def __exit__(self, type, value, traceback):
        return False


class FileCursor:
    def __init__(self, memfile):
        self.offset = 0
        self.memfile = memfile

    def read(self, nbytes=None):
        end = self.offset + nbytes if nbytes != None else None
        data = self.memfile.data[self.offset:end]
        self.offset += len(data)
        return data


class HashedFile:
    def __init__(self, path, zeroize=True):
        full_path = path
        try:
            full_path = os.path.realpath(path)
        except OSError as e:
            print(f"Error getting real path for {path}")
            print(e)

        self.zeroize = zeroize

        self.path = full_path
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
        # return open(self.path, 'rb')
        if not self.file_data:
            self.file_data = MemFile(self.path, None, self.zeroize)
        return self.file_data

    def getWholeFileHash(self):
        if not self.whole_file_hash:
            self.whole_file_hash = get_whole_file_hash(self.path)
        return self.whole_file_hash

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
            if (i + 1) % COL == 0:
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
            hi = e > threshold
            if last_change == offset:
                last_hi = hi
                continue

            if hi != last_hi:
                if last_hi:
                    yield (last_change, offset)
                last_hi = hi
                last_change = offset
        if last_hi:
            yield (last_change, offset + bs)

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

    def genRollingBlocks(self,
                         bs=10,
                         step=1,
                         offset=0,
                         short_blocks=False,
                         entropy_ranges=None,
                         limit_range=None) -> Generator[Sector, None, None]:
        with self.openFile() as in_fd:
            lo, hi = None, None
            if limit_range:
                lo, hi = limit_range
                offset += lo
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
            overlap = block_size // 2

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
        print(f'{color.lineclear}Entropy: {self.sectors_entropy_lo} blocks below threshold, '
              f'{self.sectors_entropy_hi} above')
