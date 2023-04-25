import string
import struct
import sys

from intervaltree import IntervalTree



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

        self.forward = IntervalTree()
        self.backward = IntervalTree()

        self.map = []

    def add(self, a_range, b_range, meta):
        a, a_len = a_range
        b, b_len = b_range

        if a_len:
            self.forward[a:a+a_len] = (b, b_len, meta)
        if b_len:
            self.backward[b:b+b_len] = (a, a_len, meta)

    def all_in_range(self, address):
        for interval in self.forward.at(address):
            a_range = (interval.begin, interval.length())
            b, b_len, meta = interval.data
            b_range = (b, b_len)
            yield a_range, b_range, meta

    def all_in_range_reverse(self, address):
        for interval in self.forward.at(address):
            b_range = (interval.begin, interval.length())
            a, a_len, meta = interval.data
            a_range = (a, a_len)
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

    def all(self):
        for interval in self.forward.all_intervals:
            a_range = (interval.begin, interval.length())
            b, b_len, meta = interval.data
            b_range = (b, b_len)
            yield a_range, b_range, meta


printable_bytes = [
    ord(i) for i in string.printable if i not in string.whitespace
]
def format_printable(name):
    result = "".join(
        [
            chr(i)
            if (i in printable_bytes)
            else f"\\x{i:02x}"
            for i in name.rstrip(b"\x00")
        ]
    )
    return result


class ELFThunks:
    def __init__(self, path):
        self.file_to_va_thunk = None
        self.thunks = []
        self.structs = []

        self.try_parse_elf(path)

        if not self.thunks:
            self.try_parse_pe(path)

    def try_parse_pe(self, path):
        import pefile
        pe = pefile.PE(path)

        # print(f"Parsing PE {pe}")



        section_thunk = Thunk('File Offset', 'RVA')
        struct_thunk = Thunk('File Offset', 'RVA')
        self.thunks = [section_thunk, struct_thunk]
        for section in pe.sections:

            section: pefile.SectionStructure
            #print(section)
            #print(f'Section {format_printable(section.Name)}  {section.get_file_offset():5x} {section.sizeof():x}')

            meta = dict(name = format_printable(section.Name),
                        struct=str(section))

            rva_lo = section.section_min_addr
            rva_hi = section.section_max_addr
            file_lo = section.get_offset_from_rva(rva_lo)
            file_hi = section.get_offset_from_rva(rva_hi)
            #print(f'{rva_lo:x}-{rva_hi:x} {file_lo:x}-{file_hi:x}')
            section_thunk.add((file_lo, file_hi - file_lo),
                              (rva_lo, rva_hi - rva_lo),
                              meta)

        for struct in pe.__structures__:
            struct: pefile.Structure
            if struct in pe.sections:
                continue

            lo = struct.get_file_offset()
            sz = struct.sizeof()

            rva, thunk_meta = section_thunk.translate(lo)

            meta = dict(name = struct.name,
                        struct=str(struct))

            if rva is None:
                rva_range = (0, 0)
            else:
                rva_range = (rva, sz)

            struct_thunk.add((lo, sz), rva_range, meta)

            #print(f'Struct {struct.name} {struct.get_file_offset():5x} {struct.sizeof():x}')

        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                for entry in rsrc.directory.entries:
                    entry: pefile.ResourceDirEntryData

                    offset = entry.directory.entries[0].data.struct.OffsetToData
                    size = entry.directory.entries[0].data.struct.Size

                    meta = dict(name=entry.name or f'RESOURCE {entry.id}',
                                struct=str(entry.struct))

                    struct_thunk.add((offset, size), (0,0), meta)

    def try_parse_elf(self, path):
        from elftools.elf.elffile import ELFFile
        from elftools.common.exceptions import ELFError
        with open(path, 'rb') as f:
            try:
                elffile = ELFFile(f)
            except ELFError:
                return

            section_thunk = Thunk('File Offset', 'Virtual Address')
            segment_thunk = Thunk('File Offset', 'Virtual Address')
            # self.file_to_va_thunk = self.section_thunk
            self.thunks = [section_thunk, segment_thunk]

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
                segment_thunk.add((sh_offset,file_size), (sh_addr,mem_size), meta)

                #print(f'Section {sect.name:20} {flag_txt} {sh_offset:6x}+{file_size:<6x}  {sh_addr:6x}+{mem_size:<6x} {sect.header}')

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
                section_thunk.add((p_offset, p_filesz), (p_vaddr, p_memsz), meta)


                #print(f'Segment {p_type:20} {flagtxt} {p_offset:6x}+{p_filesz:<6x} {p_vaddr:6x}+{p_memsz:<6x} {dict(seg.header)}')


    def find_thunks(self, address, only_nearest=True):
        for thunk in self.thunks:
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
                break
            else:
                txt.append('??')
        return ' '.join(txt)

    def get_va(self, file_offset):
        if not self.file_to_va_thunk:
            return

        for a, b, meta in self.file_to_va_thunk.all_in_range(file_offset):
            trans = try_translate(file_offset, a, b)
            return trans



if __name__ == "__main__":
    thunks = ELFThunks(sys.argv[1])