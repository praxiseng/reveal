#from hashlist import *
import queue
import subprocess

from filehash import *
from exefile import *
from util import color
from collections import defaultdict
import reveal_globals as rg

import multiprocessing as mp

class FileDB:
    def __init__(self, db_name, blocksize, short_blocks=False, use_c_tool=False):
        self.db_name = db_name
        #self.next_file_id = 1

        os.makedirs(db_name, exist_ok=True)

        self.blocksize = blocksize
        self.short_blocks = short_blocks

        self.enum_file_list()

        self.file_offset_thunks = []

        self.use_c_tool = use_c_tool
        print(f"Use C tool? {use_c_tool}")

        # self.db_file = SimpleSectorHashList(self.get_hashes_path())

    def get_hashes_path(self):
        return os.path.join(self.db_name, 'hashes.cbor')

    def get_merge_path(self):
        return os.path.join(self.db_name, 'merge.cbor')

    def open_db(self):
        return HashListFile(self.get_hashes_path())

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
        if rg.globs.ZEROIZE_X86_PC_REL != db_zeroize:

            print(f'{color.red}WARNING: ZEROIZE_X86_PC_REL IS {rg.globs.ZEROIZE_X86_PC_REL}, BUT THE DATABASE SAYS IT IS {db_zeroize}.{color.reset}')
            print(f'{color.red}Changing ZEROIZE_X86_PC_REL to {db_zeroize}{color.reset}')
            rg.globs.ZEROIZE_X86_PC_REL = db_zeroize


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

    def file_hashes_name(self, hashedFile):
        #return os.path.join(self.db_name, f'{btoh(hashedFile.getWholeFileHash())}_{hashedFile.id}')
        return os.path.join(self.db_name, f'{btoh(hashedFile.getWholeFileHash())}.hashes')
    
    def get_hashes_file_out_path(self, input_path):
        file_hash = get_whole_file_hash(input_path)
        return os.path.join(self.db_name, f'{btoh(file_hash)}.hashes')


    def _hash_file(self, in_path, out_path) -> HashListFile:
        #print(f'Ingesting {path}')
        hf = HashedFile(in_path)
        if self.use_c_tool:
            subcommand = ['hasher', 'hash', in_path, out_path, '--bs', str(self.blocksize)]
            # print(f'Running command: {subcommand}')
            p = subprocess.Popen(subcommand)
            p.wait()
            hashlist = HashListFile(out_path)
        else:
            hashlist = hf.hashBlocksToFile(self.blocksize,
                                           out_path,  #self.file_hashes_name(hf),
                                           self.short_blocks)
        return hashlist


    def expand_paths(self, paths, force_existing=False):
        if isinstance(paths, (str, bytes)):
            paths = [paths]

        if not force_existing:
            paths = [get_full_path(path) for path in paths]
            paths = [path for path in paths if path not in self.paths_in_use]

        # Expand directories
        for path in paths:
            if os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    for file in files:
                        yield os.path.join(root, file)
            else:
                yield path


    def hash_file(self, index, in_path, out_path) -> HashListFile:
        status.update('Ingest', ingest_file_index=index, filepath=in_path, filename=os.path.basename(in_path))
        hashlist = self._hash_file(in_path, out_path)
        return hashlist.path
    

    def hash_files_serial(self, inout_paths):
        inout_paths_copy = []
        for i, inout_path in enumerate(inout_paths):
            in_path, out_path = inout_path
            hashlist_path = self.hash_file(i+1, in_path, out_path)
            assert(hashlist_path == out_path)
            inout_paths_copy.append(inout_path)
        return inout_paths_copy


    def hash_files_parallel_callback(self, in_files, out_files, files_processed):
        while True:
            inout_path = in_files.get()
            if inout_path is None:
                break

            in_path, out_path = inout_path

            files_processed.value += 1
            out_path = self.hash_file(files_processed.value, in_path, out_path)
            out_files.put(out_path)
        out_files.put(None)


    def hash_files_parallel(self, inout_paths, parallelism = 10):
        # Make linux use spawn method to behave like Windows, so we are less likely to introduce platform-specific bugs.
        #mp.set_start_method('spawn')

        files_processed = mp.Value('i', 0)

        procs = []
        inQ = mp.Queue()
        outQ = mp.Queue()

        for i in range(parallelism):
            p = mp.Process(target=self.hash_files_parallel_callback,
                           args=(inQ, outQ, files_processed))
            procs.append(p)
            p.start()

        files_to_ingest = 0
        inout_path_list = []
        for inout_path in inout_paths:
            files_to_ingest += 1
            inQ.put(inout_path)
            inout_path_list.append(inout_path)
        status.update('Ingest', files_to_ingest=files_to_ingest)

        for p in procs:
            inQ.put(None)

        n_nulls = 0
        # Need to drain the queue before join because on Windows the subprocesses will hang if
        # they have items waiting on the queue.
        while n_nulls < len(procs):
            if outQ.get() is None:
                n_nulls += 1

        for p in procs:
            p.join()

        return inout_path_list

    def _ingest_process(self, inout_paths, parallelism):
        status.start_process('Ingest',
            'Ingest {ingest_file_index:4} of {files_to_ingest:<4} {sum_uniq_hashes:7}/{sum_hashes:<7} hashes',
            ingest_file_index=0,
            files_to_ingest=0,
            filepath = '',
            filename = '',
            sum_hashes = 0,
            sum_uniq_hashes = 0)

        if parallelism <= 1:
            inout_paths = self.hash_files_serial(inout_paths)
        else:
            inout_paths = self.hash_files_parallel(inout_paths, parallelism)

        status.finish_process('Ingest')
        return inout_paths

    def _merge(self, inout_paths):
        # TODO: handle really large ingest lists by doing a hierarchical merge.
        merge_files = [HashListFile(outpath) for inpath, outpath in inout_paths]

        # TODO: don't ingest existing files by MD5 if they are already in the database
        hashes_path = self.get_hashes_path()
        if os.path.exists(hashes_path):
            merge_files.append(HashListFile(hashes_path))
    
        merge_path = self.get_merge_path()
        if os.path.exists(merge_path):
            os.remove(merge_path)
        merged = HashListFile(merge_path)
        merged.createMerge(merge_files)

        if not os.path.exists(merge_path):
            print(f"Error - no merge created at {merge_path}")
            return
        
        os.replace(merge_path, self.get_hashes_path())
        self.enum_file_list()

    def singleton_output(self, inout_paths):
        ''' Output files are named by hash of the input file contents.  Since multiple input files (at different paths)
            may have the same hash, parallel processing could concurrently write to the same output and produce a corrupt
             file.  This function deduplicates outputs, only taking the first file with that hash.
            
        '''
        by_hashes = defaultdict(list)
        for inpath, outpath in inout_paths:
            if outpath not in by_hashes:
                yield (inpath, outpath)
            by_hashes[outpath].append(inpath)

        for outpath, inpaths in by_hashes.items():
            if len(inpaths) > 1:
                print(f'{color.lineclear}Deduplicating output to {outpath}')
                for i, inpath in enumerate(inpaths):
                    print(f'    Input {i}: {inpath}')


    def ingest(self, paths, force_existing=False, parallelism=1):

        paths = self.expand_paths(paths, force_existing)

        # Keep inout_paths as a generator so we don't have to read and compute whole-file hashes (needed for output file name) before we
        # start seeing progress.  This means that each stage should re-emit the items in the list.  
        # In parallel mode, this means the main process can asynchrounusly compute the whole-file hash before pushing into the queue.
        inout_paths = ((inpath, self.get_hashes_file_out_path(inpath)) for inpath in paths)
        inout_paths = self.singleton_output(inout_paths)
        inout_paths = self._ingest_process(inout_paths, parallelism)
        self._merge(inout_paths)


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

