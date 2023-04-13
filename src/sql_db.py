import itertools
import sqlite3
import os
import shutil
import sys
import time
from collections import defaultdict

import docopt

from filehash import Sector, HashedFile
import cbor2


N_BYTES_IN_HASH=6

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
            FOREIGN KEY(file_id) REFERENCES FILES(id)
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

    def convert_nsrl_file_list(self, input_db):
        insert_query = """INSERT INTO FILES
            (name, file_hash, metadata_id)
            VALUES (?, ?, ?)
        """

        file_records = []

        query = "SELECT DISTINCT key_hash, metadata_id, file_name, extension FROM MD5B128"
        for row in rowgen2(input_db, query):
            key_hash, metadata_id, file_name, extension = row
            #print(f'Row {metadata_id:12} {file_name} {extension}')
            file_records.append((f'{file_name}.{extension}', key_hash, metadata_id))

        self.db_connection.executemany(insert_query, file_records)
        self.db_connection.commit()

    def convert_nsrl_hashfiles(self, input_db):
        fid_lookup = {metadata_id : file_id
                      for file_id, metadata_id in
                      rowgen2(self.db_connection, "SELECT file_id, metadata_id FROM FILES")}

        insert_query = """INSERT INTO HASHFILES
            (hash_id, offset, file_id)
            VALUES (?, ?, ?)"""
        query = "SELECT * FROM MD5B128 ORDER BY HASH"

        new_records = []
        n_records = 0
        for row in rowgen2(input_db, query):
            metadata_id, key_hash, block, hash, file_name, extension = row

            #hash_id = int.from_bytes(bytes.fromhex(hash)[:N_BYTES_IN_HASH], 'big')
            hash_id = get_hash_id(bytes.fromhex(hash))
            file_id = fid_lookup[metadata_id]
            offset = block*128
            #print(f'Hash ID {hash_id:10} {hash} {hash_id:{N_BYTES_IN_HASH}x}')
            new_records.append((hash_id, offset, file_id))

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
        self.db_connection.execute("""
            INSERT INTO HASHCOUNT
            SELECT hash_id, count(*) as hash_count, count(DISTINCT file_id) as file_count FROM HASHFILES GROUP BY hash_id
        """)
        self.db_connection.commit()

    def convert_nsrl_to_sector_db(self, input_db_path):
        input_db = sqlite3.connect(input_db_path)

        print(f'Listing Files')
        self.convert_nsrl_file_list(input_db)

        print(f'Populating HASHFILES')
        self.convert_nsrl_hashfiles(input_db)

        print(f'Inserting into HASHCOUNT')
        self.populate_hashcount()

        input_db.close()


class RollingSearchDB:
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
                     entropy_threshold = 0.2):
        hf = HashedFile(file_path)
        sectors = hf.genRollingBlocks(bs, step=1, short_blocks=False, limit_range=None)

        #block_gen = self.filter_sector_entropy(block_gen, block_size, threshold=entropy_threshold)

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


def search_db(args):
    block_size = int(args['--blocksize'])

    rebuild = args['--rebuild']
    hash_db_path = args['HASH_DB']

    search_db_path = args['SEARCH_DB']
    search_file = args['SEARCH_FILE']
    if rebuild or not os.path.exists(search_db_path):
        search_db = RollingSearchDB(search_db_path, rebuild)
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

    count_deltas = defaultdict(int)
    id_set_add = defaultdict(set)
    id_set_sub = defaultdict(set)

    for hash_id, file_count, hash_count, offset, file_names, file_ids in count_hashes:
        count_deltas[offset] += file_count
        count_deltas[offset + block_size] -= file_count

        fids = set(int(fid) for fid in file_ids.split(','))
        id_set_add[offset] |= fids
        id_set_sub[offset + block_size] |= fids

    cumulative_counts = {}
    cumulative_value = 0
    running_set = set()
    file_set_at_offset = []
    last_set = None
    for offset, delta in sorted(count_deltas.items()):
        cumulative_value += delta
        cumulative_counts[offset] = cumulative_value

        running_set -= id_set_sub[offset]
        running_set |= id_set_add[offset]

        if last_set == running_set:
            continue
        last_set = set(running_set)

        file_set_at_offset.append((offset, set(running_set)))

    fid_name = {file_id: name
                for file_id, name in
                rowgen2(sql_db, "SELECT file_id, name FROM FILES")}

    displayed_fids = set()
    for offset, file_set in file_set_at_offset:
        fids_txt = ','.join([str(fid) for fid in sorted(file_set)])
        new_fids = file_set - displayed_fids
        new_fid_txt = ' '.join([f'{fid}:{fid_name[fid]}' for fid in sorted(new_fids)])
        displayed_fids |= new_fids

        print(f'Offset {offset:6x} {fids_txt}  {new_fid_txt}')


def ingest_files(hash_db_path, files_to_ingest):
    pass


usage = """
REVeal SQL Database Tool

Usage:
    sql_db import HASH_DB NSRL_DB [options]
    sql_db search HASH_DB SEARCH_DB SEARCH_FILE [options]
    sql_db ingest HASH_DB FILES...

Options:
    --rebuild         When creating a database, delete that database and make a clean one.
                      This includes the HASH_DB when using "import" and the cached search
                      database when using "search"
    --blocksize BS    Sector block size [default: 128]
"""


def main():
    args = docopt.docopt(usage)

    block_size = 128

    rebuild = args['--rebuild']
    hash_db_path = args['HASH_DB']
    if args['import']:
        import_nsrl_db(args['HASH_DB'], args['NSRL_DB'], args['--rebuild'])

    if args['search']:
        search_db(args)

    if args['ingest']:
        ingest_files(args['HASH_DB'], args['FILES'])



if __name__ == "__main__":
    main()