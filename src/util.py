import cProfile as profile
import pstats
import time
import sys
import hashlib
import cbor2
import os

import itertools

class Bunch(dict):
    def __init__(self, **kw):
        dict.__init__(self, kw)
        self.__dict__ = self


color = Bunch(
    red='\033[38;5;9m',
    lightred='\033[38;5;124m',
    blue='\033[38;5;24m',
    lightblue='\033[38;5;51m',
    green='\033[38;5;112m',
    lightyellow='\033[38;5;186m',
    yellow='\033[38;5;226m',
    purple='\033[38;5;147m',
    orange='\033[38;5;208m',
    brown='\033[38;5;94m',
    white='\033[38;5;255m',
    pink='\033[38;5;212m',
    grey='\033[38;5;236m',
    emphasis='\033[01m',
    reset='\033[0m',
    underline='\033[04m',
    lineclear='\033[2K\r',
)



def grouper(iterable, n):
    it = iter(iterable)
    while True:
        chunk_it = itertools.islice(it, n)
        try:
            first_el = next(chunk_it)
        except StopIteration:
            return
        yield itertools.chain((first_el,), chunk_it)


def bg_to_fg(ansi_color):
    return ansi_color.replace('\033[38;5', '\033[48;5')


class Status:
    def __init__(self, **vars):
        self.active_processes = []
        self.process_txts = {}
        self.start_times = {}

        self.vars = vars
        pass


    def start_process(self, process_name, txt_format, **vars):
        self.active_processes.append(process_name)
        self.process_txts[process_name] = txt_format
        self.start_times[process_name] = time.time()
        self.vars = {**self.vars, **vars}
        self._display()

    def print(self, txt, *args, **kwargs):
        print(f'{color.lineclear}{txt}', *args, **kwargs)

    def get(self, key, default=None):
        return self.vars.get(key, default)

    def _fmt_process(self, process_name):
        txt = self.process_txts.get(process_name, '')
        self.vars['elapsed'] = self.getTimeDelta(process_name)

        prefix = f'{self.getTimeDeltaTxt(process_name):5}  '

        # Either txt is a format string or a callback function
        fx = txt.format if isinstance(txt, str) else txt

        return f'{prefix}{fx(**self.vars)}'

    def getTimeDelta(self, process_name):
        return time.time() - self.start_times[process_name]

    def getTimeDeltaTxt(self, process_name):
        delta = self.getTimeDelta(process_name)
        if delta < 10:
            return f'{delta:4.2f}s'
        if delta < 60:
            return f'{delta:4.1f}s'

        seconds = int(delta)
        minutes = seconds // 60
        if seconds < 3600:
            return f'{minutes}:{seconds%60:02}'
        hours = minutes // 60
        return f'{hours}H{minutes%60}M'


    def getOuterTimeDelta(self):
        return self.getTimeDelta(self.active_processes[0])

    def getInnerTimeDelta(self):
        return self.getTimeDelta(self.active_processes[-1])

    def _display(self):
        if not self.active_processes:
            #print(color.lineclear)
            return

        proc_txts = [f'{self._fmt_process(name)}' for name in self.active_processes]
        print(f'{color.lineclear}{" ".join(proc_txts)}', end='')

    def update(self, process_name, **vars):
        self.vars = {**self.vars, **vars}
        self._display()
        pass

    def finish_process(self, process_name, **result):
        self.vars = {**self.vars, **result}
        self._display()

        delta = self.getInnerTimeDelta()
        if(delta > 0.5):
            print()
        else:
            pass #print(color.lineclear, end='')

        self.active_processes.remove(process_name)


status = Status()


def coroutine(func):
    def start(*args, **kwargs):
        cr = func(*args, **kwargs)
        next(cr)
        return cr

    return start


def get_full_path(path):
    full_path = path
    try:
        full_path = os.path.realpath(path)
    except OSError as e:
        print("Error on ingest")
        print(e)
    return full_path


def btoh(b):
    ''' Convert bytes to hex '''
    return ''.join(format(x, '02x') for x in b)


@coroutine
def cbor_dump(file_path, clump_size=0):
    with open(file_path, 'wb') as out_fd:

        if clump_size:
            # Don't clump the first row, which is usually the header
            header = (yield)
            header['clumped'] = 1
            cbor2.dump(header, out_fd)

            current_clump = []
            try:
                while True:
                    for i in range(clump_size):
                        entry = (yield)
                        current_clump.append(entry)
                    cbor2.dump(current_clump, out_fd)
                    current_clump = []

            except GeneratorExit:
                if current_clump:
                    cbor2.dump(current_clump, out_fd)
        else:
            while True:
                entry = (yield)
                cbor2.dump(entry, out_fd)


@coroutine
def sorter(target, key=None):
    whole_list = []
    try:
        while True:
            item = (yield)
            whole_list.append(item)
    except GeneratorExit:
        for item in sorted(whole_list, key=key):
            target.send(item)


def md5(b, n_bytes=6):
    m = hashlib.md5()
    m.update(b)
    return m.digest()[:n_bytes]

def file_hash(b):
    return md5(b, 16)

def get_whole_file_hash(path):
    with open(path, 'rb') as fd:
        return file_hash(fd.read())



class Uniq:
    def __init__(self):
        self.n_uniq_sectors = 0

    @coroutine
    def uniq(self, target, keyfunc=lambda entry: entry[0]):
        """
        Similar to itertools.groupby, but done as a coroutine
        """

        curvals = []
        tgtkey = None
        try:
            curval = (yield)
            curvals = [curval]
            tgtkey = keyfunc(curval)
            while True:
                curval = (yield)
                curkey = keyfunc(curval)

                if curkey == tgtkey:
                    curvals.append(curval)
                else:
                    self.n_uniq_sectors += 1
                    target.send((tgtkey, curvals))
                    tgtkey = curkey
                    curvals = [curval]
        except GeneratorExit:
            if curvals:
                self.n_uniq_sectors += 1
                target.send((curkey, curvals))


class Profiler:
    def __init__(self, n_stats=50, sort="cumtime", min_display_secs=0.5):
        self.prof = profile.Profile()
        self.n_stats = n_stats
        self.sort = sort
        self.min_display_secs = min_display_secs

    def __enter__(self):
        self.prof.enable()

    def __exit__(self, exc_type, exc_value, exc_tb):
        self.prof.disable()

        stats = pstats.Stats(self.prof).strip_dirs().sort_stats(self.sort)
        if stats.total_tt > self.min_display_secs:
            stats.print_stats(self.n_stats)