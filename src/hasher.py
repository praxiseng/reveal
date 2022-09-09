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

from util import *
from entropy import *
from hashlist import *
from exefile import *
from filehash import *
from match import *
from database import *
import globals


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



import argparse



def main():
    globals.init_globals()

    parser = argparse.ArgumentParser(description='Sector hashing tool')
    parser.add_argument('db', metavar='PATH', help='The database path')
    parser.add_argument('ingest', nargs='*', help='Files to ingest into the database')
    parser.add_argument('--search', nargs='?', help='File to perform a rolling search')
    parser.add_argument('--step', metavar='N', type=int, default=1, help='Step size for rolling search.')
    parser.add_argument('--blocksize', nargs='?', type=int, default=512, help="Block size")
    parser.add_argument('--zeroize', action='store_true',
                        help='Zero out immediate operands that look like x86_64 PC relative addresses')

    args = parser.parse_args()

    globals.ZEROIZE_X86_PC_REL = args.zeroize

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


if __name__ == "__main__":
    main()
