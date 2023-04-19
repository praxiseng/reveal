import itertools
import sqlite3
import os
import shutil
import sys
import time
from collections import defaultdict
from typing import Generator

from util import status

import docopt

import gui

from filehash import Sector, HashedFile
import cbor2

N_BYTES_IN_HASH = 6


def rowgen2(con, query):
    res = con.execute(query)

    while True:
        row = res.fetchone()
        if not row:
            break
        yield row


def create_tables(db_connection, tables):
    for table in tables:
        db_connection.execute(table)


def init_db(path, tables, delete_existing):
    if delete_existing and os.path.exists(path):
        os.remove(path)

    # Check if we are opening an existing DB or implicitly creating one on the call to sqlite3.connect()
    exists = os.path.exists(path)
    connection = sqlite3.connect(path)
    if not exists:
        create_tables(connection, tables)
    return connection


def get_hash_id(hash_bytes):
    return int.from_bytes(hash_bytes[:N_BYTES_IN_HASH], 'big')


class SQLHashDB:
    tables = [
        '''
        CREATE TABLE "HASHCOUNT" (
            hash_id integer PRIMARY KEY not null,
            file_count integer not null,
            hash_count integer not null
        ) WITHOUT ROWID
        ''',
        '''
        CREATE TABLE "HASHFILES" (
            hash_id integer not null,
            offset integer not null,
            file_id integer not null,
            PRIMARY KEY(hash_id, file_id, offset)
            FOREIGN KEY(file_id) REFERENCES FILES(file_id)
        ) WITHOUT ROWID
        ''',
        '''
        CREATE TABLE "HASHFILES_INGEST" (
            hash_id integer not null,
            offset integer not null,
            file_id integer not null
        )
        ''',
        '''
        CREATE TABLE "FILES" (
            file_id INTEGER PRIMARY KEY not null,
            name TEXT,
            path TEXT,
            file_hash TEXT,
            metadata_id INTEGER
        )
        ''',
        '''
        CREATE VIEW HASH_FILE_NAMES
        AS
        SELECT 
            HASHFILES.hash_ID, 
            count(*) as n_files, 
            group_concat(FILES.name, ',') as FILE_NAMES,
	        group_concat(FILES.file_id, ',') as FILE_IDS
        FROM 
            HASHFILES 
            INNER JOIN FILES ON HASHFILES.file_id == FILES.file_id
        GROUP BY hash_id
        '''
    ]

    def __init__(self, path, delete_existing=True):
        self.path = path
        self.db_connection = init_db(path, SQLHashDB.tables, delete_existing)

        self.total_hashes_added = 0
        self.last_file_hashes = 0

    def close(self):
        self.db_connection.close()
        self.db_connection = None

    def add_file(self, path, file_hash="") -> int:
        name = os.path.basename(path)
        cur = self.db_connection.cursor()
        cur.execute("INSERT INTO FILES (name, path, file_hash) VALUES (?, ?, ?)",
                    (name, path, file_hash))
        row_id = cur.lastrowid
        cur.close()
        return row_id

    def import_nsrl_file_list(self,
                              input_db: sqlite3.Connection):
        insert_query = """INSERT INTO FILES
            (name, file_hash, metadata_id)
            VALUES (?, ?, ?)
        """

        file_records = []

        query = "SELECT DISTINCT key_hash, metadata_id, file_name, extension FROM MD5B128"
        for row in rowgen2(input_db, query):
            key_hash, metadata_id, file_name, extension = row
            # print(f'Row {metadata_id:12} {file_name} {extension}')
            file_records.append((f'{file_name}.{extension}', key_hash, metadata_id))

        self.db_connection.executemany(insert_query, file_records)
        self.db_connection.commit()

    def add_hash_blocks(self,
                        fid: int,
                        sectors: Generator[Sector, None, None]):

        new_records = []
        n_records = 0

        insert_query = """INSERT INTO HASHFILES_INGEST
            (hash_id, file_id, offset)
            VALUES (?, ?, ?)"""

        for sector in sectors:
            hash_id = get_hash_id(sector.hash())
            new_records.append((hash_id, fid, sector.offset))
            if len(new_records) >= 1000000:
                self.db_connection.executemany(insert_query, sorted(new_records))
                self.db_connection.commit()
                n_records += len(new_records)
                print(f'Inserted {n_records} hash blocks')
                new_records = []
        if new_records:
            self.db_connection.executemany(insert_query, sorted(new_records))
            self.db_connection.commit()
            n_records += len(new_records)

        self.total_hashes_added += n_records
        self.last_file_hashes = n_records

    def finalize_ingest(self):
        self.db_connection.execute("""
            INSERT INTO HASHFILES (hash_id, offset, file_id)
            SELECT SRC.hash_id, SRC.offset, SRC.file_id
            FROM HASHFILES_INGEST AS SRC;
        """)
        self.db_connection.execute("DELETE FROM HASHFILES_INGEST")

    def convert_nsrl_hashfiles(self,
                               input_db: sqlite3.Connection):

        fid_lookup = {metadata_id: file_id
                      for file_id, metadata_id in
                      rowgen2(self.db_connection, "SELECT file_id, metadata_id FROM FILES")}

        insert_query = """INSERT INTO HASHFILES
            (hash_id, file_id, offset)
            VALUES (?, ?, ?)"""
        query = "SELECT * FROM MD5B128 ORDER BY HASH"

        new_records = []
        n_records = 0
        for row in rowgen2(input_db, query):
            metadata_id, key_hash, block, hash, file_name, extension = row

            # hash_id = int.from_bytes(bytes.fromhex(hash)[:N_BYTES_IN_HASH], 'big')
            hash_id = get_hash_id(bytes.fromhex(hash))
            file_id = fid_lookup[metadata_id]
            offset = block * 128
            # print(f'Hash ID {hash_id:10} {hash} {hash_id:{N_BYTES_IN_HASH}x}')
            new_records.append((hash_id, file_id, offset))

            if len(new_records) >= 1000000:
                # Pre-sorting a large number of records makes the insert much more efficient because it improves locality of access
                # on the database's B-Tree.
                self.db_connection.executemany(insert_query, sorted(new_records))
                self.db_connection.commit()
                n_records += len(new_records)
                print(f'Inserted {n_records} hash files')

                new_records = []

        if new_records:
            self.db_connection.executemany(insert_query, sorted(new_records))
            self.db_connection.commit()

    def populate_hashcount(self):
        self.db_connection.execute("DELETE FROM HASHCOUNT")
        self.db_connection.commit()
        self.db_connection.execute("""
            INSERT INTO HASHCOUNT (hash_id, file_count, hash_count)
            SELECT hash_id, count(DISTINCT file_id) as file_count, count(*) as hash_count FROM HASHFILES GROUP BY hash_id
        """)
        self.db_connection.commit()

    def convert_nsrl_to_sector_db(self, input_db_path):
        input_db = sqlite3.connect(input_db_path)

        print(f'Listing Files')
        self.import_nsrl_file_list(input_db)

        print(f'Populating HASHFILES')
        self.convert_nsrl_hashfiles(input_db)

        print(f'Inserting into HASHCOUNT')
        self.populate_hashcount()

        input_db.close()


class RollingSearchDB:
    """
    A RollingSearchDB is a temporary DB with all the rolling hashes from a file.
    """

    tables = ['''
        CREATE TABLE "ROLLING_HASH" (
            hash_id integer not null,
            offset integer not null,
            PRIMARY KEY (hash_id, offset)
        ) WITHOUT ROWID
    ''']

    def __init__(self, path, delete_existing=True):
        self.path = path
        self.db_connection = init_db(path, RollingSearchDB.tables, delete_existing)

    def close(self):
        self.db_connection.close()
        self.db_connection = None

    def rolling_hash(self,
                     file_path,
                     bs,
                     entropy_threshold=0.2):
        hf = HashedFile(file_path)
        sectors = hf.genRollingBlocks(bs, step=1, short_blocks=False, limit_range=None)

        # block_gen = self.filter_sector_entropy(block_gen, block_size, threshold=entropy_threshold)

        insert_query = """INSERT INTO ROLLING_HASH
            (hash_id, offset)
            VALUES (?, ?)"""

        n_records = 0
        new_records = []

        sectors = hf.filter_sector_entropy(sectors, bs, threshold=entropy_threshold)

        for sector in sectors:
            hash_id = get_hash_id(sector.hash())
            new_records.append((hash_id, sector.offset))

            if len(new_records) >= 1000000:
                self.db_connection.executemany(insert_query, sorted(new_records))
                self.db_connection.commit()
                n_records += len(new_records)
                print(f'Inserted {n_records} rolling hashes')
                new_records = []

        if new_records:
            self.db_connection.executemany(insert_query, sorted(new_records))
            self.db_connection.commit()


def import_nsrl_db(hash_db_path, nsrl_db_path, rebuild=False):
    if rebuild or not os.path.exists(hash_db_path):
        hash_db = SQLHashDB(hash_db_path, rebuild)
        hash_db.convert_nsrl_to_sector_db(nsrl_db_path)
        hash_db.close()



class OffsetCount:
    def __init__(self, offset):
        self.offset = offset
        self.length = 0

        # When representing raw/delta counts, values can be negative (i.e. stop matching some files)
        # When representing cumulative counts, should always be positive
        self.fileCount = 0
        self.hashCount = 0

        # Maintain a count per-file so we can add positive/negative values.
        # The accumulator may count a file multiple times if it has multiple overlapping matches.
        self.fid_set = defaultdict(int)

        self._frozen = None

    def get_frozen_set(self):
        if not self.has_file_list():
            return None

        if self._frozen == None:
            self._frozen = frozenset(fid for fid, count in self.fid_set.items() if count)
        return self._frozen

    def has_file_list(self):
        return self.fileCount and self.fid_set # and self.fileCount < len(self.fid_set) * 2

    def get_count(self):

        return self.fileCount

        # if self.has_file_list():
        #     return len(self.fid_set)
        # else:
        #     return self.fileCount


class MatchSet:
    def __init__(self, file_set, count_of_bytes = 0):
        self.file_set = frozenset(file_set)
        self.count_of_bytes = count_of_bytes
        self.match_ranges = []

        # For use with GUI processing
        self.color = None

    def add_match_range(self, lo, hi):
        # WARNING: this is not designed to handle overlapping ranges
        self.match_ranges.append((lo, hi))
        self.count_of_bytes += hi - lo

    def similarity(self, other):
        return len(self.file_set & other.file_set) / len(self.file_set | other.file_set)


def accumulate(count_deltas : dict[int, OffsetCount]) -> list[OffsetCount]:
    """
    When querying HASHCOUNT, we get match counts at different offsets that extend over the sector,
    and these sectors can overlap.  This function accumulates the overlapping counts from the
    run_search_query function to get the total count at each specific offset.
    """
    counts = []

    sum_file_count = 0
    sum_hash_count = 0
    sum_fid_counts = defaultdict(int)

    lastCounts = None

    for offset, deltaCount in sorted(count_deltas.items()):
        deltaCount : OffsetCount

        # Simple counts are the easiest - just add the delta value
        sum_file_count += deltaCount.fileCount
        sum_hash_count += deltaCount.hashCount

        for fd, fd_delta in deltaCount.fid_set.items():
            sum_fid_counts[fd] += fd_delta

        # Prune zero-count items so that we don't maintain a huge list for the rest of the file
        # Also ensures the copy in the accumulation only has positive-valued counts.  This also enables
        # using frozenset(sum_fid_counts.keys()) as a lookup key to find offsets with the same match set.
        sum_fid_counts = defaultdict(int, {off : count for off, count in sum_fid_counts.items() if count != 0})

        newCounts = (sum_file_count, sum_hash_count, dict(sum_fid_counts))
        if lastCounts == newCounts:
            continue
        lastCounts = newCounts

        accumulation = OffsetCount(offset)
        accumulation.fileCount = sum_file_count
        accumulation.hashCount = sum_hash_count
        accumulation.fid_set = dict(sum_fid_counts)

        counts.append(accumulation)

    for a, b in itertools.pairwise(counts):
        a.length = b.offset - a.offset

    return counts


def run_search_query(hash_db_path, search_db_path, search_file, rebuild_search_db, block_size):
    if rebuild_search_db or not os.path.exists(search_db_path):
        search_db = RollingSearchDB(search_db_path, rebuild_search_db)
        search_db.rolling_hash(search_file, block_size)
        search_db.close()

    sql_db = sqlite3.connect(hash_db_path)
    sql_db.execute(f'ATTACH DATABASE "{search_db_path}" AS SEARCH')

    count_hashes = rowgen2(sql_db, f'''
         SELECT HC.hash_id, HC.file_count, HC.hash_count, RH.offset, HFN.FILE_NAMES, HFN.FILE_IDS
         FROM HASHCOUNT AS HC 
         INNER JOIN SEARCH.ROLLING_HASH as RH ON HC.hash_id == RH.hash_id
         LEFT JOIN HASH_FILE_NAMES AS HFN on HFN.hash_id == HC.hash_id AND HC.file_count < 1000
         ORDER BY RH.offset''')

    offsetCounts = {}

    for hash_id, file_count, hash_count, offset, file_names, file_ids in count_hashes:
        offset2 = offset+block_size

        count1 = offsetCounts.setdefault(offset, OffsetCount(offset))
        count2 = offsetCounts.setdefault(offset2, OffsetCount(offset2))

        count1.fileCount += file_count
        count2.fileCount -= file_count
        count1.hashCount += hash_count
        count2.hashCount -= hash_count

        fids = set(int(fid) for fid in file_ids.split(',')) if file_ids else set()

        for fid in fids:
            count1.fid_set[fid] += 1
            count2.fid_set[fid] -= 1

    return offsetCounts


def match_set_analysis(cumulative_counts: list[OffsetCount]) -> list[MatchSet]:
    match_sets = {}

    for count in cumulative_counts:
        if not count.has_file_list():
            continue

        fs = count.get_frozen_set()

        # TODO: ensure the count actually contains the set and is not just a count-only value
        if fs in match_sets:
            ms = match_sets[fs]
        else:
            ms = MatchSet(fs)
            match_sets[fs] = ms

        ms.add_match_range(count.offset, count.offset+count.length)

    return sorted(match_sets.values(), key=lambda ms: -ms.count_of_bytes)


def search_file_in_hashdb(args):
    block_size = int(args['--blocksize'])

    rebuild = args['--rebuild']
    hash_db_path = args['HASH_DB']

    search_db_path = args['SEARCH_DB']
    search_file = args['SEARCH_FILE']

    print(f'Running search query')
    offset_counts = run_search_query(hash_db_path, search_db_path, search_file, rebuild, block_size)
    cumulativeCounts = accumulate(offset_counts)
    match_sets = match_set_analysis(cumulativeCounts)

    sql_db = sqlite3.connect(hash_db_path)
    fid_to_name = {file_id: name
                    for file_id, name in
                    rowgen2(sql_db, "SELECT file_id, name FROM FILES")}

    print(f'Lengths: {len(offset_counts)} {len(cumulativeCounts)} {len(match_sets)}')


    print(f'Initializing GUI')
    gui_view = gui.FileView(search_file)
    gui_view.set_counts(fid_to_name, cumulativeCounts, match_sets)

    print(f'Entering GUI event loop')
    gui_view.event_loop()


def expand_paths(paths):
    if isinstance(paths, (str, bytes)):
        paths = [paths]

    for path in paths:
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                for file in files:
                    yield os.path.join(root, file)
        else:
            yield path

def format_ingest(n_files, n_hashes, elapsed, path, **kwargs):
    return f'{n_files:5} files, {n_hashes:8} hashes, {n_hashes / (elapsed or 1):5.0f} hash/s'

def ingest_files(hash_db_path, files_to_ingest, bs):
    hash_db = SQLHashDB(hash_db_path, False)
    n_files = 0


    status.start_process('Ingesting', format_ingest,
                         n_files=0, n_hashes=0, path='')
    for path in expand_paths(files_to_ingest):
        n_files += 1
        status.update('Ingesting', n_files=n_files, n_hashes=hash_db.total_hashes_added)


        status.start_process('IngestFile', 'File: {n_file_hashes:7} hashes {path}', path=path, n_file_hashes=0)
        hf = HashedFile(path)
        fid = hash_db.add_file(path, hf.getWholeFileHash())
        sector_gen = hf.genAlignedBlocks(bs=bs)
        hash_db.add_hash_blocks(fid, sector_gen)
        status.finish_process('IngestFile', n_file_hashes=hash_db.last_file_hashes)

    status.finish_process('Ingesting', n_files=n_files, n_hashes=hash_db.total_hashes_added)



    status.start_process('FinalizingIngest', 'Finalizing ingest by sorting into final table')
    hash_db.finalize_ingest()
    status.finish_process('FinalizingIngest')



    hash_db.populate_hashcount()


usage = """
REveal SQL Database Tool

Usage:
    sql_db ingest HASH_DB FILES...
    sql_db import HASH_DB NSRL_DB [options]
    sql_db search HASH_DB SEARCH_DB SEARCH_FILE [options]

Options:
    --rebuild         When creating a database, delete that database and make a clean one.
                      This includes the HASH_DB when using "import" and the cached search
                      database when using "search"
    --blocksize BS    Sector block size [default: 128]
"""


def main():
    args = docopt.docopt(usage)

    rebuild = args['--rebuild']
    hash_db_path = args['HASH_DB']

    if args['ingest']:
        ingest_files(args['HASH_DB'], args['FILES'], int(args['--blocksize']))

    if args['import']:
        import_nsrl_db(args['HASH_DB'], args['NSRL_DB'], args['--rebuild'])

    if args['search']:
        search_file_in_hashdb(args)



if __name__ == "__main__":
    main()
