import glob
import itertools
import sqlite3
import os
import shutil
import sys
import time
import traceback
from collections import defaultdict
from typing import Generator

from util import status

from match_sets import MatchSet

import docopt

import util

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
            metadata_id INTEGER,
            json_data TEXT
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
                status.print(f'Inserted {n_records} hash blocks')
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
        self.db_connection.commit()

    def cleanup(self):
        self.db_connection.execute("DELETE FROM HASHFILES_INGEST")
        self.db_connection.commit()

    def vacuum(self):
        self.db_connection.execute("VACUUM")

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
                status.print(f'Inserted {n_records} hash files')

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

        status.start_process()
        status.print(f'Listing Files')
        self.import_nsrl_file_list(input_db)

        status.print(f'Populating HASHFILES')
        self.convert_nsrl_hashfiles(input_db)

        status.print(f'Inserting into HASHCOUNT')
        self.populate_hashcount()

        input_db.close()


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


def matches_to_offset_counts(matches, block_size) -> dict[int, OffsetCount]:
    offset_counts = {}

    for hash_id, file_count, hash_count, offset, file_names, file_ids in matches:
        offset2 = offset+block_size

        count1 = offset_counts.setdefault(offset, OffsetCount(offset))
        count2 = offset_counts.setdefault(offset2, OffsetCount(offset2))

        count1.fileCount += file_count
        count2.fileCount -= file_count
        count1.hashCount += hash_count
        count2.hashCount -= hash_count

        fids = set(int(fid) for fid in file_ids.split(',')) if file_ids else set()

        for fid in fids:
            count1.fid_set[fid] += 1
            count2.fid_set[fid] -= 1

    return offset_counts


class FileRecord:
    def __init__(self, fid, name, path):
        self.fid = fid
        self.name = name
        self.path = path


class SearchDB:
    """
    A SearchDB holds search results.  A search takes a file of interest, computes a rolling hash, and looks at the
    matches for those rolling hashes.
    """

    tables = ['''
        CREATE TABLE "ROLLING_HASH" (
            hash_id integer not null,
            offset integer not null,
            PRIMARY KEY (hash_id, offset)
        ) WITHOUT ROWID
    ''','''
        CREATE TABLE "MATCH_RESULTS" (
            hash_id integer not null,
            file_count integer not null,
            hash_count integer not null,
            offset integer not null,
            file_names VARCHAR,
            file_ids VARCHAR,
            PRIMARY KEY (offset, hash_id)
        ) WITHOUT ROWID
    ''','''
    CREATE TABLE "FILES" (
        file_id INTEGER PRIMARY KEY not null,
        name TEXT,
        path TEXT,
        file_hash TEXT,
        metadata_id INTEGER,
        json_data TEXT
    )
    ''','''
    CREATE TABLE "FILE_CONTENTS" (
        file_id INTEGER,
        name TEXT,
        path TEXT,
        json_data TEXT,
        contents BLOB
    )
    ''']

    def __init__(self, path, delete_existing=False):
        self.path = path
        self.db_connection = None
        if delete_existing:
            self.delete()

        self.is_new = not os.path.exists(path)
        self.open()

        self.fid_to_name = None

    def close(self):
        if self.db_connection:
            self.db_connection.close()
            self.db_connection = None

    def delete(self):
        self.close()
        if os.path.exists(self.path):
            os.remove(self.path)
            self.is_new = True

    def open(self):
        if not self.db_connection:
            self.db_connection = init_db(self.path, SearchDB.tables, False)
        return self.db_connection

    def rebuild(self):
        self.delete()
        self.open()

    def store_file_contents(self, file_path):
        insert_query = "INSERT INTO FILE_CONTENTS (name, path, contents) VALUES (?, ?, ?)"

        with open(file_path, 'rb') as fd:
            contents = fd.read()

        name = os.path.basename(file_path)
        query_data = [(name, file_path, contents)]
        self.db_connection.executemany(insert_query, query_data)
        self.db_connection.commit()

    def load_file_contents(self):
        file_query = '''SELECT name, path, contents FROM FILE_CONTENTS'''

        res = self.db_connection.execute(file_query)
        data = res.fetchone()
        if data is None:
            return None

        name, path, contents = data
        return path, contents


    def rolling_hash(self,
                     file_path,
                     bs,
                     entropy_threshold=0.2,
                     zeroize=True):

        self.store_file_contents(file_path)

        hf = HashedFile(file_path, zeroize=zeroize)


        sectors = hf.genRollingBlocks(bs, step=1, short_blocks=False, limit_range=None)

        # block_gen = self.filter_sector_entropy(block_gen, block_size, threshold=entropy_threshold)

        insert_query = "INSERT INTO ROLLING_HASH (hash_id, offset) VALUES (?, ?)"

        n_records = 0
        new_records = []

        sectors = hf.filter_sector_entropy(sectors, bs, threshold=entropy_threshold)

        status.start_process('RollingHash', '{n_hashes} Rolling Hashes', n_hashes=0)
        for sector in sectors:
            hash_id = get_hash_id(sector.hash())
            new_records.append((hash_id, sector.offset))

            if len(new_records) >= 1000000:
                self.db_connection.executemany(insert_query, sorted(new_records))
                self.db_connection.commit()
                n_records += len(new_records)
                status.update('RollingHash', n_hashes= n_records)
                new_records = []

        if new_records:
            self.db_connection.executemany(insert_query, sorted(new_records))
            self.db_connection.commit()
            n_records += len(new_records)
            status.update('RollingHash', n_hashes=n_records)

        status.finish_process('RollingHash')

    def query_search_results(self):
        match_query = '''
            SELECT hash_id, file_count, hash_count, offset, file_names, file_ids FROM MATCH_RESULTS
        '''
        status.start_process('QueryResults', 'Querying match results')
        matches = list(rowgen2(self.db_connection, match_query))
        status.finish_process('QueryResults')

        return matches

    def _run_search_query(self, hash_db_path):
        status.start_process('PopulateTable', 'Populating MATCH_RESULTS table')
        self.db_connection.execute(f'ATTACH DATABASE "{hash_db_path}" AS HASH_DB')
        self.db_connection.execute(f'''
             INSERT INTO MATCH_RESULTS (hash_id, file_count, hash_count, offset, file_names, file_ids)
             SELECT HC.hash_id, HC.file_count, HC.hash_count, RH.offset, HFN.FILE_NAMES, HFN.FILE_IDS
             FROM HASH_DB.HASHCOUNT AS HC 
             INNER JOIN ROLLING_HASH as RH ON HC.hash_id == RH.hash_id
             LEFT JOIN HASH_DB.HASH_FILE_NAMES AS HFN on HFN.hash_id == HC.hash_id AND HC.file_count < 1000
             ORDER BY RH.offset''')
        self.db_connection.commit()

        # Copy file list over to be self-contained
        self.db_connection.execute('INSERT INTO FILES SELECT * FROM HASH_DB.FILES')

        self.db_connection.commit()
        status.finish_process('PopulateTable')

    def run_search_query(self, hash_db_path):
        matches = self.query_search_results()

        if not matches:
            self._run_search_query(hash_db_path)
            matches = self.query_search_results()

        return matches

    def _get_fid_to_name(self):

        fid_to_name = {file_id: FileRecord(file_id, name, path)
                       for file_id, name, path in
                       rowgen2(self.db_connection, "SELECT file_id, name, path FROM FILES")}
        return fid_to_name

    def fid_lookup(self, fid: int) -> FileRecord:
        if self.fid_to_name is None:
            self.fid_to_name = self._get_fid_to_name()

        return self.fid_to_name[fid]

def import_nsrl_db(hash_db_path, nsrl_db_path, rebuild=False):
    if rebuild or not os.path.exists(hash_db_path):
        hash_db = SQLHashDB(hash_db_path, rebuild)
        hash_db.convert_nsrl_to_sector_db(nsrl_db_path)
        hash_db.close()

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


def search_file_in_hashdb(args, search_db):
    block_size = int(args['--blocksize'])

    rebuild = args['--rebuild']
    hash_db_path = args['HASH_DB']

    zeroize = not args['--no-zeroize']
    search_file = args['SEARCH_FILE']

    status.start_process('FindMatches', 'Finding Matches')

    if rebuild:
        search_db.rebuild()
    if search_db.is_new:
        search_db.rolling_hash(search_file, block_size, zeroize=zeroize)

    matches = search_db.run_search_query(hash_db_path)
    #search_db.close()

    status.finish_process('FindMatches')

    return matches

def show_gui(matches, block_size, search_file_path, search_file_bytes, fid_lookup):
    try:
        import gui
    except ImportError:
        print(f'ImportError while trying to import GUI')
        return

    with util.Profiler(15):
        offset_counts = matches_to_offset_counts(matches, block_size)

        cumulative_counts = accumulate(offset_counts)
        match_sets = match_set_analysis(cumulative_counts)

        status.print(f'Lengths: {len(offset_counts)} {len(cumulative_counts)} {len(match_sets)}')

        status.print(f'Initializing GUI')
        gui_view = gui.GUIView(search_file_path, search_file_bytes)
        gui_view.set_counts(fid_lookup, cumulative_counts, match_sets)

    status.print(f'Entering GUI event loop')
    gui_view.event_loop()


def expand_paths(paths, use_globs = False):
    if isinstance(paths, (str, bytes)):
        paths = [paths]

    if use_globs:
        for glob_expression in paths:
            for path in glob.glob(glob_expression, recursive=True):
                yield path
    else:
        for path in paths:
            if os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    for file in files:
                        yield os.path.join(root, file)
            else:
                yield path

labels_kmb = ('', 'K', 'M', 'B', 'T', 'Q')
def format_5digit(number, labels=labels_kmb):
    for i, label in enumerate(labels):
        magnitude = (1000**i)
        if i and number < 100*magnitude:
            return f'{number/magnitude:4.1f}{label}'
        if number < 10000*magnitude:
            return f'{int(number//magnitude)}{label}'
    return str(number)


def format_4digit(number, labels=labels_kmb):
    for i, label in enumerate(labels):
        magnitude = (1000**i)
        if i and number < 10*magnitude:
            print("A")
            return f'{number/magnitude:3.1f}{label}'
        if number < 1000*magnitude:
            return f'{int(number//magnitude)}{label}'
    print("C")
    return str(number)

def format_ingest(n_files, n_hashes, elapsed, path, **kwargs):

    n_hash_txt = format_5digit(n_hashes)
    hash_rate_txt = format_4digit(n_hashes // (elapsed or 1))

    return f'{n_files:5} files {n_hash_txt:>5} hash {hash_rate_txt:>4}/s'

def format_ingest_file(n_file_hashes, path, **kwargs):
    file_hash_txt = format_5digit(n_file_hashes)
    return f'{file_hash_txt:>5} {path}'

def is_exe_by_header(path):
    with open(path, 'rb') as fd:
        signature = fd.read(4)
        if signature == b'\x7fELF':
            return True
        if signature[:2] == b'MZ':
            return True
    return False

def ingest_files(hash_db_path, files_to_ingest, bs, only_exe, use_glob, zeroize):
    hash_db = SQLHashDB(hash_db_path, False)
    n_files = 0

    status.start_process('Ingesting', format_ingest, n_files=0, n_hashes=0, path='')

    for path in expand_paths(files_to_ingest, use_glob):
        status.update('Ingesting', n_files=n_files, n_hashes=hash_db.total_hashes_added)

        if only_exe:
            try:
                is_exe = is_exe_by_header(path)
            except FileNotFoundError:
                print(f'\nFile not found: {path}')
                continue
            except Exception as e:
                print(f'\nCould not open file: {path}\n{e}')
                continue
            if not is_exe:
                continue

        n_files += 1
        status.start_process('IngestFile', format_ingest_file, path=path, n_file_hashes=0)
        try:
            hf = HashedFile(path, zeroize=zeroize)
            fid = hash_db.add_file(path, hf.getWholeFileHash())
            sector_gen = hf.genAlignedBlocks(bs=bs)
            hash_db.add_hash_blocks(fid, sector_gen)
        except PermissionError as e:
            print(f'\nPermission error {e}')
        status.finish_process('IngestFile', n_file_hashes=hash_db.last_file_hashes)

    status.finish_process('Ingesting', n_files=n_files, n_hashes=hash_db.total_hashes_added)

    status.start_process('FinalizingIngest', 'Finalizing ingest by sorting into final table')
    hash_db.finalize_ingest()
    status.finish_process('FinalizingIngest')

    status.start_process('Cleanup', 'Cleaning up')
    hash_db.cleanup()
    status.finish_process('Cleanup')

    status.start_process('Vacuum', 'Vacuuming')
    hash_db.vacuum()
    status.finish_process('Vacuum')

    hash_db.populate_hashcount()


usage = """
REveal SQL Database Tool

Usage:
    sql_db ingest HASH_DB FILES... [options] [--exe] [--glob]
    sql_db import HASH_DB NSRL_DB [options]
    sql_db search HASH_DB SEARCH_DB SEARCH_FILE [options] [--show]
    sql_db show SEARCH_DB

Options:
    --rebuild         When creating a database, delete that database and make a clean one.
                      This includes the HASH_DB when using "import" and the cached search
                      database when using "search"
    --blocksize SIZE  Sector block size [default: 128]
    --zeroize         Use the 'zero-ize' option to remove x86_64 relative addresses [default: true]
    --no-zeroize      Do not apply 'zero-ize' 
    --exe             Only process executable files (PE or ELF) for ingest
    --glob            Use globbing on the list of files for ingest
"""


def main():
    args = docopt.docopt(usage)

    rebuild = args['--rebuild']
    hash_db_path = args['HASH_DB']

    bs = int(args['--blocksize'])
    zeroize = not args['--no-zeroize']

    if args['ingest']:
        ingest_files(hash_db_path, args['FILES'], bs, args['--exe'], args['--glob'], zeroize)

    if args['import']:
        import_nsrl_db(hash_db_path, args['NSRL_DB'], args['--rebuild'])

    search = args['search']
    show = args['show'] or args['--show']

    if search or show:
        search_db = SearchDB(args['SEARCH_DB'])

        matches = search and search_file_in_hashdb(args, search_db)

        if show:
            path, contents = search_db.load_file_contents()
            matches = matches or search_db.query_search_results()
            show_gui(matches, bs, path, contents, search_db.fid_lookup)


if __name__ == "__main__":
    main()
