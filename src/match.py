

from hashlist import *


def match_set_similarity(A, B):
    A = set(A)
    B = set(B)
    return len(A&B)/(len(A|B) or 1)



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





