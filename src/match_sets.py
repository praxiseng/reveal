from collections import defaultdict


class MatchSet:
    def __init__(self, file_set, count_of_bytes = 0):
        self.file_set = frozenset(file_set)
        self.count_of_bytes = count_of_bytes
        self.match_ranges: list[tuple[int, int]] = []

        # For use with GUI processing
        self.color = None

        self.family = None

    def add_match_range(self, lo, hi):
        # WARNING: this is not designed to handle overlapping ranges
        self.match_ranges.append((lo, hi))
        self.count_of_bytes += hi - lo

    def similarity(self, other):
        a, b = self.file_set, other.file_set
        return 1 - (len(a - b) + len(b - a)) / (len(a) + len(b))
        #return len(a & b) / len(a | b)

class MatchSetFamily:
    def __init__(self, first: MatchSet):
        self.first = first
        self.members: list[MatchSet] = []
        self.add(first)

    def add(self, member: MatchSet):
        assert(not member.family)
        member.family = self
        self.members.append(member)

    def total_bytes(self):
        return sum(ms.count_of_bytes for ms in self.members)

    def first_file_set(self):
        return self.first.file_set

    def union_file_set(self):
        fs = set(self.first_file_set())
        for member in self.members:
            fs |= member.file_set
        return fs

    def intersection_file_set(self):
        fs = set(self.first_file_set())
        for member in self.members:
            fs &= member.file_set
        return fs

    def count_match_bytes(self, file_set):
        counts = defaultdict(int)
        for member in self.members:
            for fid in (member.file_set & file_set):
                counts[fid] += member.count_of_bytes
        return list(counts.items())

    def all_ranges(self):
        ranges = []
        for member in self.members:
            ranges += member.match_ranges
        ranges = sorted(ranges)

        compacted_ranges = []
        last_lo, last_hi = ranges[0]
        for lo, hi in ranges[1:]:
            if lo == last_hi:
                last_hi = hi
            else:
                compacted_ranges.append((last_lo, last_hi))
                last_lo = lo
                last_hi = hi

        compacted_ranges.append((last_lo, last_hi))
        return compacted_ranges

