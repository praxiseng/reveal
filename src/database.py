#from hashlist import *
import queue
from filehash import *
from exefile import *
from collections import defaultdict

import multiprocessing as mp

class FileDB:
    def __init__(self, db_name, blocksize, short_blocks=False):
        self.db_name = db_name
        self.next_file_id = 1

        os.makedirs(db_name, exist_ok=True)

        self.blocksize = blocksize
        self.short_blocks = short_blocks

        self.enum_file_list()

        self.file_offset_thunks = []

        # self.db_file = SimpleSectorHashList(self.get_hashes_path())

    def get_hashes_path(self):
        return os.path.join(self.db_name, 'hashes.cbor')

    def get_merge_path(self):
        return os.path.join(self.db_name, 'merge.cbor')

    def open_db(self):
        return HashListFile(self.get_hashes_path())

    '''

    '''

    def enum_file_list(self):
        # self.all_files = []
        # self.files_by_path = {}
        # self.files_by_id = {}

        self.paths_in_use = set()
        self.fids_in_use = set()

        self.fid_to_path = {}

        if not os.path.exists(self.get_hashes_path()):
            return

        header = self.open_db().readHeader()
        bs = header['blocksize']
        if bs != self.blocksize:
            print(f'{color.red}WARNING: SELECTED BLOCK SIZE IS {self.blocksize}, BUT THE DATABASE SAYS IT IS {bs}.{color.reset}')
            print(f'{color.red}Changing block size to {bs}{color.reset}')
            self.blocksize = bs

        db_zeroize = header.get('zeroize_x86_pc_rel', False)
        if reveal_globals.ZEROIZE_X86_PC_REL != db_zeroize:

            print(f'{color.red}WARNING: ZEROIZE_X86_PC_REL IS {reveal_globals.ZEROIZE_X86_PC_REL}, BUT THE DATABASE SAYS IT IS {db_zeroize}.{color.reset}')
            print(f'{color.red}Changing ZEROIZE_X86_PC_REL to {db_zeroize}{color.reset}')
            reveal_globals.ZEROIZE_X86_PC_REL = db_zeroize


        for file in header['files']:
            path = file['path']
            fid = file['id']

            if path in self.paths_in_use:
                print(f'Warning: duplication of path {path}')
            if fid in self.fids_in_use:
                print(f'Warning: duplication of file ID {fid}')
            self.paths_in_use.add(path)
            self.fids_in_use.add(fid)

            self.fid_to_path[fid] = path

    def getPathFromFID(self, fid, default=None):
        return self.fid_to_path.get(fid, default)

    def getNameFromFID(self, fid, default=None):
        path = self.getPathFromFID(fid, None)
        if path==None:
            return default
        return os.path.basename(path)


    def _mk_hashed_file(self, path):
        hf = HashedFile(path, self.next_file_id)
        self.next_file_id += 1
        return hf

    def _tmpname(self, hashedFile):
        return os.path.join(self.db_name, f'{btoh(hashedFile.getWholeFileHash())}_{hashedFile.id}')

    def _hash_file(self, path):
        #print(f'Ingesting {path}')
        hf = self._mk_hashed_file(path)
        hashlist = hf.hashBlocksToFile(self.blocksize, self._tmpname(hf), self.short_blocks)
        return hashlist


    def expand_paths(self, paths, force_existing=False):
        if isinstance(paths, (str, bytes)):
            paths = [paths]

        if not force_existing:
            paths = [get_full_path(path) for path in paths]
            paths = [path for path in paths if path not in self.paths_in_use]

        # Expand directories
        file_paths = []
        for path in paths:
            if os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        file_paths.append(file_path)
            else:
                file_paths.append(path)
        return file_paths


    def hash_file(self, args) -> HashListFile:
        index, path = args
        status.update('Ingest', ingest_file_index=index, filepath=path, filename=os.path.basename(path))
        hashlist = self._hash_file(path)
        return hashlist.path
    

    def hash_files_serial(self, paths):

        hash_files = []
        for i, path in enumerate(paths):
            hashlist_path = self.hash_file((i+1, path))
            hash_file = HashListFile(hashlist_path)
            hash_files.append(hash_file)
            #status.update('Ingest', ingest_file_index=i+1, filepath=path, filename=os.path.basename(path))
            #hash_files.append(self._hash_file(path))
        return hash_files


    def hash_files_parallel_callback(self, in_files, out_files, files_processed, global_state={}):

        for key, value in global_state.items():
            globals()[key] = value

        while True:
            path = in_files.get()

            if path is None:
                break
            files_processed.value += 1
            out_path = self.hash_file((files_processed.value, path))
            out_files.put(out_path)
        out_files.put(None)


    def hash_files_parallel(self, paths, parallelism = 10):
        # Make linux use spawn method to behave like Windows, so we are less likely to introduce platform-specific bugs.
        #mp.set_start_method('spawn')

        files_processed = mp.Value('i', 0)

        procs = []
        inQ = mp.Queue()
        outQ = mp.Queue()
        global_state = dict()

        for i in range(parallelism):
            p = mp.Process(target=self.hash_files_parallel_callback,
                        args=(inQ, outQ, files_processed, global_state))
            procs.append(p)
            p.start()

        for path in paths:
            inQ.put(path)

        for p in procs:
            inQ.put(None)

        out_files = []
        n_nulls = 0
        # Need to drain the queue before join because on Windows the subprocesses will hang if
        # they have items waiting on the queue.
        while n_nulls < len(procs):
            path = outQ.get()
            if path is None:
                n_nulls += 1
            else:
                out_files.append(path)

        for p in procs:
            p.join()

        hash_files = [HashListFile(path) for path in out_files]
        return hash_files


    def ingest(self, paths, force_existing=False, parallelism=1):
        paths = self.expand_paths(paths, force_existing)

        status.start_process('Ingest',
                             'Ingest {ingest_file_index:4} of {files_to_ingest:<4} {sum_uniq_hashes:7}/{sum_hashes:<7} hashes',
                             ingest_file_index=0,
                             files_to_ingest=len(paths),
                             filepath = '',
                             filename = '',
                             sum_hashes = 0,
                             sum_uniq_hashes = 0)

        if parallelism <= 1:
            hash_files = self.hash_files_serial(paths)
        else:
            hash_files = self.hash_files_parallel(paths, parallelism)

        status.finish_process('Ingest')

        merge_path = self.get_merge_path()
        if os.path.exists(merge_path):
            os.remove(merge_path)

        merged = HashListFile(merge_path)

        merge_files = hash_files[:]
        if os.path.exists(self.get_hashes_path()):
            merge_files.append(self.open_db())

        merged.createMerge(merge_files)

        if os.path.exists(merge_path):
            os.replace(merge_path, self.get_hashes_path())
            self.enum_file_list()
        else:
            print(f"Error - no merge created at {merge_path}")

        return hash_files

    def rollingSearch(self, file_to_hash, step=1, entropy_threshold=0.2, limit_range=None):
        fid = 0  # We don't need a valid fid
        hashed_file = HashedFile(file_to_hash, fid)

        rolling_path = os.path.join(self.db_name, f'{btoh(hashed_file.getWholeFileHash())}_rolling.cbor')

        hash_list_file = hashed_file.rollingHashToFile(self.blocksize,
                                                       rolling_path,
                                                       step=step,
                                                       uniq=False,
                                                       entropy_threshold=entropy_threshold,
                                                       limit_range=limit_range)
        return hash_list_file

    def gen_matches_from_hash_list(self, hash_list_file):
        for a, b in hash_list_file.find_matching_items(self.open_db()):
            yield a, b, self.blocksize

