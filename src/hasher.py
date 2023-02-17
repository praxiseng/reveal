from match import *
from database import *
import reveal_globals as rg


import argparse

def hex_int(x):
    return int(x, 16)

def main():
    parser = argparse.ArgumentParser(description='Sector hashing tool')
    parser.add_argument('db', metavar='PATH', help='The database path')
    parser.add_argument('ingest', nargs='*', help='Files to ingest into the database')
    parser.add_argument('--search', nargs='?', help='File to perform a rolling search')
    parser.add_argument('--parallelism', metavar="N", type=int, default=1, help='Number of parallel file hashing routines.')
    parser.add_argument('--step', metavar='N', type=int, default=1, help='Step size for rolling search.')
    parser.add_argument('--blocksize', nargs='?', type=int, default=512, help="Block size")
    parser.add_argument('--zeroize', action='store_true',
                        help='Zero out immediate operands that look like x86_64 PC relative addresses')

    parser.add_argument('--range', nargs=2, type=hex_int, default=None, help='Range for rolling search')

    args = parser.parse_args()

    rg.globs.ZEROIZE_X86_PC_REL = args.zeroize

    db = FileDB(args.db, args.blocksize)

    if args.ingest:
        db.ingest(args.ingest, parallelism=args.parallelism)

    if args.search:
        et = ELFThunks(args.search)

        hash_list_file = db.rollingSearch(args.search, step=args.step, entropy_threshold=-1, limit_range=args.range)
        search_results = list(db.gen_matches_from_hash_list(hash_list_file))
        search_results = sorted(search_results, key=lambda a: a[0][1])
        search_results = list(merge_runs(search_results))
        counts = countMatches2(search_results, True)

        #per_file_amount_matched(search_results, db)

        print("Match Counts")
        last_present = set()

        last_mc = None
        for mc in counts:
            mc.display_comparison(last_mc, db, et)
            last_mc = mc

        if True:
            sg = SpikeGrouper(args.blocksize)
            spikes = list(sg.group_spikes(counts))


            print('Summary of item groups')
            for s in spikes:
                s.print_summary(db, et, hash_list_file.getEntropyRanges())



if __name__ == "__main__":
    main()
