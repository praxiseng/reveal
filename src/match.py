from math import floor, log10
from hashlist import *
from collections import defaultdict
from enum import Enum

def match_set_similarity(A, B):
    A = set(A)
    B = set(B)
    return len(A&B)/(len(A|B) or 1)

def superset_similarity(A, B):
    # matches perfectly if A is a superset, gives close numbers if it is a close superset
    A = set(A)
    B = set(B)

    if not A or not B:
        return 0

    if len(B)*5 <= len(A) and ((len(A) - len(B)) > 2):
        return 0

    return 1 - (len(B-A)/(len(B) or 1))



def match_end(a1, a2, l1):
    fid1, off1 = a1
    fid2, off2 = a2
    #print(f'match_end {a1}, {a2}, {l1}')
    return fid1==fid2 and off2 == off1+l1

def round_sig(x, sig=2):
    return round(x, sig-int(floor(log10(abs(x))))-1)

class MatchRun:
    def __init__(self, a, b, l):
        self.a = a
        self.b = b
        self.l = l

        self.hd_a = HashData(a)
        self.hd_b = HashData(b)

        #self.offset = a[1][0][1]
        self.offset = self.hd_a.getFirstOffset()
        self.end = self.offset + self.l

        self.merged = False

        #self.fds = None
        #if HashDes.MATCH_LIST == hdType(b):
        #    self.fds = set(fid for fid, offset in b[1])


    def can_merge(self, other: 'MatchRun'):
        #if round_sig(self.hd_b.file_count, 1) != round_sig(other.hd_b.file_count, 1):
        #    return False
        if self.hd_b.file_count != other.hd_b.file_count:
            return False
        if self.hd_b.fids and self.hd_b.fids != other.hd_b.fids:
            return False


        '''
        if other.offset != self.end:
            return False
        if not all(HashDes.MATCH_LIST == hdType(x) for x in [self.b, other.b]):
            return False
        if self.fds != other.fds:
            return False
        '''
        return True

    def merge(self, other: 'MatchRun'):
        assert(other.end > self.end)
        assert(self.end >= other.offset)
        self.end = other.end
        #self.l += other.l
        self.l = self.end - self.offset
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
            mr: MatchRun
            other = result_offsets.get(mr.end, None)
            if not other:
                break
            if not mr.can_merge(other):
                break
            mr.merge(other)

    for mr in match_runs:
        if not mr.merged:
            yield (mr.a, mr.b, mr.l)


class FuzzyMatchSpike:
    def __init__(self, offset, length, ascent, plateau, descent):
        self.offset = offset
        self.length = length
        self.ascent = ascent
        self.plateau = plateau
        self.descent = descent

        self.all_fds = set()

        for mc in ascent + plateau + descent:
            self.all_fds |= set(mc.files_present)


    def per_file_weights(self):
        ''' For each matched file, count the number of bytes they occupy '''
        weights = defaultdict(int)
        for mc in self.ascent + self.plateau + self.descent:
            for fd in mc.files_present:
                weights[fd] += mc.runlen

        return weights


    def get_entropy_range(self, offset, entropy_ranges):
        last_range = [0,0]
        for range in entropy_ranges:
            lo, hi = range
            if lo > offset:
                last_lo, last_hi = last_range
                return [0, last_hi, lo]
                return None
            if lo <= offset < hi:
                return [1, lo, hi]
            last_range = range

    def print_summary(self, db, thunks, entropy_ranges = []):
        weights = self.per_file_weights()
        weights_sorted = sorted(weights.items(), key=lambda w:(-w[1], w[0]))

        weight_group = itertools.groupby(weights_sorted, key=lambda w:w[1])

        #weight_txt = ' '.join(f'{db.getNameFromFID(fd)} {w}' for fd, w in weights_sorted)

        weight_group_list = [(w, [fd for fd, w2 in g]) for w, g in weight_group]
        weight_txt = '  '.join(f'{w*100/self.length:3.0f}% {len(fds)} ' + ' '.join(db.getNameFromFID(fd) or f'?{fd}' for fd in fds) for w, fds in weight_group_list)
        list_counts = f' {len(self.ascent):3} {len(self.plateau):3} {len(self.descent):3}'


        if thunks:
            tt = thunks.thunk_txt(self.offset)
            va = thunks.get_va(self.offset)
            va_txt = f'{va:x}' if va != None else ''
            exe_txt = f'{va_txt:8} {tt:16} '
        else:
            exe_txt = ''

        entropy_txt = ''
        if entropy_ranges:
            range = self.get_entropy_range(self.offset, entropy_ranges)
            if range:
                is_hi_entropy, entropy_off, entropy_len = range
                if not is_hi_entropy and not weight_txt:
                    weight_txt = f'Low entropy {entropy_off:5x}-{entropy_len:<4x}'
                #entropy_txt = f'Entropy: {is_hi_entropy} {entropy_off:5x}-{entropy_len:<4x} '


        print(f'{self.offset:6x}+{self.length:<5x} {exe_txt}{entropy_txt}{weight_txt[:120]}')


class SpikeState(Enum):
    ASCENDING = 0
    PLATEAU = 1
    DESCENDING = 2

class SpikeGrouper:
    def __init__(self, blocksize):
        self.blocksize = blocksize

        self.state = SpikeState.PLATEAU
        self.last_state = self.state

        self.ascent_items = []
        self.descent_items = []
        self.plateau_items = []


        self.emit_queue = []

        self.offset_last_state_change = 0
        self.offset_last_flush = 0
        self.current_offset = 0

    def transition_state(self, new_state, flush=True, info=''):

        #print(f'{self.current_offset:5x} Transitioning from {str(self.state):24} to {str(new_state):24} flush={1 if flush else 0} {info}')
        if flush:
            if self.ascent_items or self.descent_items or self.plateau_items:
                len_in_state = self.current_offset - self.offset_last_flush
                fms = FuzzyMatchSpike(self.offset_last_flush, len_in_state, self.ascent_items, self.plateau_items, self.descent_items)
                self.emit_queue.append(fms)
            self.offset_last_flush = self.current_offset

            self.ascent_items = []
            self.descent_items = []
            self.plateau_items = []

        self.offset_last_state_change = self.current_offset
        self.last_state = self.state
        self.state = new_state


    def group_spikes(self, counts):

        # Thresholds for similarity, ascending, and descending
        T, TA, TD = 0.90, 0.98, 0.98

        last_present = set()
        for mc in counts:
            similarity = match_set_similarity(mc.files_present, last_present)
            ascending = superset_similarity(mc.files_present, last_present)
            descending = superset_similarity(last_present, mc.files_present)
            last_present = set(mc.files_present)


            self.current_offset = mc.off

            length_in_state = mc.off+mc.runlen - self.offset_last_state_change
            goes_past_block = length_in_state > self.blocksize

            info = f'{ascending:4.2f} {similarity:4.2f} {descending:4.2f}'
            info += f' {len(self.ascent_items):3} {len(self.plateau_items):3} {len(self.descent_items):3}'
            info += f'  in state {length_in_state:x} {goes_past_block}'

            if self.state == SpikeState.PLATEAU:
                if similarity > T:
                    self.plateau_items.append(mc)
                elif ascending > TA:
                    #print(f'Ascent? {len(self.ascent_items)} {len(self.descent_items)}')
                    if self.ascent_items or self.descent_items or goes_past_block:
                        self.transition_state(SpikeState.ASCENDING, True, info=info)
                    else:
                        self.ascent_items = self.plateau_items
                        self.plateau_items = []
                        self.transition_state(SpikeState.ASCENDING, False, info=info)

                    self.ascent_items.append(mc)
                elif descending > TD:
                    self.transition_state(SpikeState.DESCENDING, False, info=info)
                    self.descent_items.append(mc)
                else:
                    # self-transition and emit consecutive plateaus when items are dissimilar
                    self.transition_state(SpikeState.PLATEAU, info=info)
                    self.plateau_items.append(mc)
            elif self.state == SpikeState.ASCENDING:
                # TODO: also force transition if current length is greater than blocksize
                if ascending > TA and not goes_past_block:
                    self.ascent_items.append(mc)
                elif similarity > T:
                    self.transition_state(SpikeState.PLATEAU, False, info=info)
                    self.plateau_items.append(mc)
                elif descending > TD:
                    self.transition_state(SpikeState.DESCENDING, False, info=info)
                    self.descent_items.append(mc)
                else:
                    self.transition_state(SpikeState.PLATEAU, info=info)
                    self.plateau_items.append(mc)
            elif self.state == SpikeState.DESCENDING:
                if descending > TD and not goes_past_block:
                    self.descent_items.append(mc)
                elif similarity > T:
                    self.transition_state(SpikeState.PLATEAU, info=info)
                    self.plateau_items.append(mc)
                elif ascending > TA:
                    self.transition_state(SpikeState.ASCENDING, info=info)
                    self.ascent_items.append(mc)
                else:
                    self.transition_state(SpikeState.PLATEAU, info=info)
                    self.plateau_items.append(mc)

            for item in self.emit_queue:
                yield item
            self.emit_queue = []

        self.transition_state(SpikeState.PLATEAU)
        for item in self.emit_queue:
            yield item

class MatchCount:
    def __init__(self, off, count, runlen, files_present):
        self.off = off
        self.count = count
        self.runlen = runlen
        self.files_present = files_present


    def display_comparison(self, other, db, thunks):
        # off, count, runlen, files_present in counts:
        if other:
            sim = match_set_similarity(self.files_present, other.files_present)
            ascending = superset_similarity(self.files_present, other.files_present)
            descending = superset_similarity(other.files_present, self.files_present)
        else:
            sim = 0
            ascending = 0
            descending = 0

        # ascending = set(files_present) > last_present
        # descending = set(files_present) < last_present

        last_present = set(self.files_present)

        present_txt = ' '.join(sorted(fid_to_names(self.files_present, db)))

        if thunks:
            tt = thunks.thunk_txt(self.off)
            va = thunks.get_va(self.off)
            va_txt = f'{va:x}' if va != None else ''
            exe_txt = f'{va_txt:8} {tt:20} '
        else:
            exe_txt = ''
        n_duplicates = self.count - len(self.files_present)
        # asctxt = ('A' if ascending else ' ') + ('D' if descending else ' ')
        asctxt = f'{ascending*100:3.0f}% {sim*100:3.0f}% {descending*100:3.0f}%'

        #print(f"  {self.off:5x}+{self.runlen:<5x} {exe_txt}  {self.count:4} {n_duplicates:4}  {asctxt} {present_txt[:120]}")
        print(f"{self.off:5x}+{self.runlen:<5x} {self.count:3} {asctxt} {present_txt[:120]}")



def countMatches2(searchResults, countFiles=False):
    '''
        Collect the count of matches and set of files that match (if match lists are given) for every offset
        in searchResults.

        For example, countMatches2 would take the following overlapping match ranges:
        1 {Foo}       ####################
        1 {Bar}                 #####################

        and convert them into a form that lets us easily count the set of overlapping files:
        1 {Foo}       ##########
        2 {Foo, Bar}            ##########
        1 {Bar}                           ###########

    '''

    ''' match_counts maps offsets in the search file to a file-count dictionary.  The file-count dictionary
        maps file IDs to the count of matches in that file. Summarized matches without file lists accumulate
        counts using file ID -1.
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
            counts.append(MatchCount(o, t, r, p))

        run_len = off - (last_off_delta or [0])[0]
        last_off_delta = (off, total, run_len, files_present)
    counts.append(MatchCount(*(last_off_delta or (0, 0, 0, []))))
    return counts