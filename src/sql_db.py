import itertools
import sqlite3
import os
import shutil
import sys
import time
from collections import defaultdict
from typing import Generator

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

        insert_query = """INSERT INTO HASHFILES
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


def accumulate_deltas(count_deltas : dict[int, int]) -> list[tuple[int, int]]:
    """
    When querying HASHCOUNT, we get match counts at different offsets that extend over the sector,
    and these sectors can overlap.  This function accumulates the overlapping counts from the
    run_search_query function to get the total count at each specific offset.
    """
    counts = []
    accumulation = 0
    last_count = None
    for offset, delta in sorted(count_deltas.items()):
        last_count = (offset, accumulation, delta)
        if not delta:
            continue
        accumulation += delta
        counts.append((offset, accumulation))

    if not counts:
        return counts

    if last_count:
        offset, accumulation, delta = last_count
        if not delta:
            # Ensure we keep the very last offset so that we can track the very
            # last block change closest to the end of the file.
            counts.append((offset, accumulation))

    return counts


def accumulate_fid_sets(id_set: tuple[int, set[int]]) -> list[tuple[int, set[int]]]:
    """ The input id_set will have a list of files that matched beginning at the specified
        offsets.  However, previous matches may overlap the current interval.  This function
        accumulates the list of all files matching at each offset that has a set change.
    """
    file_set_at_offset = []

    running_fid_count = defaultdict(int)
    last_set = set()
    for offset, set_counts in sorted(id_set.items()):
        for fd, fd_delta in set_counts.items():
            running_fid_count[fd] += fd_delta
        new_set = set(fd for fd, count in running_fid_count.items() if count > 0)
        if last_set == new_set:
            continue
        last_set = new_set
        file_set_at_offset.append((offset, new_set))

    return file_set_at_offset


def run_search_query(hash_db_path, search_db_path, search_file, rebuild_search_db, block_size):
    if rebuild_search_db or not os.path.exists(search_db_path):
        search_db = RollingSearchDB(search_db_path, rebuild_search_db)
        search_db.rolling_hash(search_file, block_size)
        search_db.close()

    sql_db = sqlite3.connect(hash_db_path)
    sql_db.execute(f'ATTACH DATABASE "{search_db_path}" AS SEARCH')

    count_hashes = list(rowgen2(sql_db, f'''
         SELECT HC.hash_id, HC.file_count, HC.hash_count, RH.offset, FILE_NAMES, FILE_IDS
         FROM HASHCOUNT AS HC 
         INNER JOIN SEARCH.ROLLING_HASH as RH ON HC.hash_id == RH.hash_id
         LEFT JOIN HASH_FILE_NAMES on HASH_FILE_NAMES.hash_id == HC.hash_id
         ORDER BY RH.offset'''))

    file_count_deltas = defaultdict(int)
    hash_count_deltas = defaultdict(int)
    id_set = defaultdict(lambda: defaultdict(int))

    print(f'Ran count_hashes')
    for hash_id, file_count, hash_count, offset, file_names, file_ids in count_hashes:
        file_count_deltas[offset] += file_count
        file_count_deltas[offset + block_size] -= file_count

        hash_count_deltas[offset] += hash_count
        hash_count_deltas[offset + block_size] -= hash_count

        fids = set(int(fid) for fid in (file_ids).split(',')) if file_ids else set()

        for fid in fids:
            id_set[offset][fid] += 1
            id_set[offset + block_size][fid] -= 1

    file_counts = accumulate_deltas(file_count_deltas)
    hash_counts = accumulate_deltas(hash_count_deltas)
    fid_set = accumulate_fid_sets(id_set)

    return file_counts, hash_counts, fid_set


def display_fid_sets(fid_set, fid_to_name):
    displayed_fids = set()
    for offset, file_set in fid_set:
        fids_txt = ','.join([str(fid) for fid in sorted(file_set)])

        if len(file_set) <= 10:
            fid_names = ' '.join(fid_to_name[fid] for fid in sorted(file_set))
            print(f'Offset {offset:6x} {len(file_set):4} {fids_txt[:150]}  {fid_names}')
        else:
            new_fids = file_set - displayed_fids
            if len(file_set) < 50:
                new_fid_txt = ' '.join([f'{fid}:{fid_to_name[fid]}' for fid in sorted(new_fids)])
                displayed_fids |= new_fids
            else:
                new_fid_txt = ''

            print(f'Offset {offset:6x} {len(file_set):4} {fids_txt[:150]}  {new_fid_txt}')

def match_set_analysis(fid_set, fid_to_name):

    set_byte_count = defaultdict(int)

    for current, next_set in itertools.pairwise(fid_set):
        offset, file_set = current
        next_offset, next_set = next_set

        length = next_offset - offset
        set_byte_count[frozenset(file_set)] += length

    counts = sorted(set_byte_count.items(), key=lambda x: x[1])

    for file_set, length in counts:
        fid_names = ' '.join(fid_to_name[fid] for fid in sorted(file_set)[:20])
        print(f'{length:6x} bytes, {len(file_set):3} files {fid_names}')

    return counts


def search_file_in_hashdb(args):
    block_size = int(args['--blocksize'])

    rebuild = args['--rebuild']
    hash_db_path = args['HASH_DB']

    search_db_path = args['SEARCH_DB']
    search_file = args['SEARCH_FILE']

    print(f'Running search query')
    file_counts, hash_counts, fid_set = run_search_query(hash_db_path, search_db_path, search_file, rebuild, block_size)


    print(f'Listing files')
    sql_db = sqlite3.connect(hash_db_path)
    fid_to_name = {file_id: name
                    for file_id, name in
                    rowgen2(sql_db, "SELECT file_id, name FROM FILES")}

    display_fid_sets(fid_set, fid_to_name)

    match_set_counts = match_set_analysis(fid_set, fid_to_name)

    print(f'Initializing GUI')
    gui_view = gui.FileView(search_file)

    gui_view.set_counts(file_counts, hash_counts, fid_set, fid_to_name, match_set_counts)

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


def ingest_files(hash_db_path, files_to_ingest, bs):
    hash_db = SQLHashDB(hash_db_path, False)
    for path in expand_paths(files_to_ingest):
        print(f"Ingesting {path}")
        hf = HashedFile(path)
        fid = hash_db.add_file(path, hf.getWholeFileHash())

        sector_gen = hf.genAlignedBlocks(bs=bs)

        hash_db.add_hash_blocks(fid, sector_gen)
    hash_db.populate_hashcount()


usage = """
REVeal SQL Database Tool

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
