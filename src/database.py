

#from hashlist import *
from filehash import *
from exefile import *
from collections import defaultdict


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
        if globals.ZEROIZE_X86_PC_REL != db_zeroize:

            print(f'{color.red}WARNING: ZEROIZE_X86_PC_REL IS {globals.ZEROIZE_X86_PC_REL}, BUT THE DATABASE SAYS IT IS {db_zeroize}.{color.reset}')
            print(f'{color.red}Changing ZEROIZE_X86_PC_REL to {db_zeroize}{color.reset}')
            globals.ZEROIZE_X86_PC_REL = db_zeroize

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

    def ingest(self, paths, force_existing=False):
        if isinstance(paths, (str, bytes)):
            paths = [paths]

        if not force_existing:
            paths = [get_full_path(path) for path in paths]
            paths = [path for path in paths if path not in self.paths_in_use]

        hash_files = []
        status.start_process('Ingest',
                             'Ingest {ingest_file_index:4} of {files_to_ingest:<4} {sum_uniq_hashes:7}/{sum_hashes:<7} hashes',
                             ingest_file_index=0,
                             files_to_ingest=len(paths),
                             filepath = '',
                             filename = '',
                             sum_hashes = 0,
                             sum_uniq_hashes = 0)

        for i, path in enumerate(paths):
            status.update('Ingest', ingest_file_index=i+1, filepath=path, filename=os.path.basename(path))
            hash_files.append(self._hash_file(path))
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

