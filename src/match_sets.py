from collections import defaultdict


class MatchSet:
    def __init__(self, file_set, count_of_bytes = 0):
        self.file_set = frozenset(file_set)
        self.count_of_bytes = count_of_bytes
        self.match_ranges: list[tuple[int, int]] = []

        self.slice_matches: list = []

        # For use with GUI processing
        self.color = None

        self.family = None

    def add_match_range(self, lo, hi):
        # WARNING: this is not designed to handle overlapping ranges
        self.match_ranges.append((lo, hi))
        self.count_of_bytes += hi - lo

    def add_slice_match(self, slice_match):
        self.slice_matches.append(slice_match)

    def get_slice_size(self):
        if not self.slice_matches:
            return 0
        return max(sm.get_set_size() for sm in self.slice_matches)

    def similarity(self, other):
        a, b = self.file_set, other.file_set
        return 1 - (len(a - b) + len(b - a)) / (len(a) + len(b))
        #return len(a & b) / len(a | b)

    def summarize_files(self, limit=20, sep=' ', fid_lookup=None):
        fid_lookup = fid_lookup or (lambda fid: str(fid))
        return sep.join(fid_lookup(fid) for fid in sorted(self.file_set)[:limit])


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


def cluster_match_sets(match_sets: list[MatchSet],
                       group_family_limit=100,
                       group_family_threshold=0.85) -> list[MatchSetFamily]:
    # Input requirement:
    # Match sets should be sorted descending according to the input type:
    #    Sector Hashes    - The number of bytes covered by the MatchSet
    #    Data flow slices - The number of slices that have the MatchSet
    #
    # TODO: consider an actual clustering algorithms.  Set comparisons have arbitrarily high dimensionality, so picking
    # a good algorithm may be tricky.
    #

    match_set_families: list[MatchSetFamily] = []
    for ms in match_sets:
        if match_set_families:
            family_scores = []
            for family in match_set_families:
                similarity = family.first.similarity(ms)
                family_scores.append((similarity, family))
            highest_score, highest_family = sorted(family_scores, key=lambda x: -x[0])[0]
            if highest_score > group_family_threshold:
                highest_family.add(ms)
                continue
        if len(match_set_families) < group_family_limit:
            match_set_families.append(MatchSetFamily(ms))

    return match_set_families