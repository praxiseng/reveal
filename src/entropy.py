from util import color
import array
from collections import defaultdict
from math import log2


def entropy(contents):
    counts = defaultdict(int)
    incr = 1 / len(contents)
    for c in contents:
        counts[c] += incr
    return -sum(x * log2(x) for x in counts.values()) / log2(min(256, len(contents)))


def word_entropy(block):
    contents = array.array('H', block)
    counts = defaultdict(int)
    incr = 1 / len(contents)
    for c in contents:
        counts[c] += incr
    return -sum(x * log2(x) for x in counts.values()) / log2(min(65536, len(contents)))


def dword_entropy(block):
    contents = array.array('L', block)
    counts = defaultdict(int)
    incr = 1 / len(contents)
    for c in contents:
        counts[c] += incr
    return -sum(x * log2(x) for x in counts.values()) / log2(len(contents))


def qword_entropy(block):
    contents = array.array('Q', block)
    counts = defaultdict(int)
    incr = 1 / len(contents)
    for c in contents:
        counts[c] += incr
    return -sum(x * log2(x) for x in counts.values()) / log2(len(contents))


def nib_entropy_hi(contents):
    counts = defaultdict(int)
    incr = 1 / len(contents)
    for c in contents:
        counts[c & 0xf0] += incr
    return -sum(x * log2(x) for x in counts.values()) / log2(min(16, len(contents)))


def nib_entropy_lo(contents):
    counts = defaultdict(int)
    incr = 1 / len(contents)
    for c in contents:
        counts[c & 0xf] += incr
    # print(dict(counts), contents, sum(counts.values()))
    return -sum(x * log2(x) for x in counts.values()) / log2(min(16, len(contents)))


def entropy_color2(e):
    highlight = ''
    if e > 0.95:
        highlight = color.red
    elif e > 0.85:
        highlight = color.orange
    elif e > 0.75:
        highlight = color.yellow
    elif e > 0.3:
        highlight = color.green
    elif e > 0.2:
        highlight = color.blue
    elif e > 0.05:
        highlight = color.lightblue
    else:
        highlight = color.grey
    return highlight


def entropy_color(block, specific_char=None):
    highlight = ''
    e = entropy(block)
    e_hi = nib_entropy_hi(block)
    e_lo = nib_entropy_lo(block)
    if e > 0.90 and e_hi > 0.67:
        highlight = color.red
    elif e > 0.7:
        highlight = color.yellow
    elif e > 0.4:
        highlight = color.green
    elif e > 0.2:
        highlight = color.blue

    if e <= 0.7 and specific_char == 0:
        highlight = color.grey
    return highlight



def format_entropy(e):
    highlight = _entropy_color(e)
    return f'{highlight}{e * 100:3.0f}{color.reset}'


def entropyFilterIter(min_entropy, blocks):
    for block in blocks:
        e = entropy(block)
        if e > min_entropy:
            yield block


def sectorEntropyFilter(min_entropy, sectors):
    for sector in sectors:
        e = sector.getEntropy()
        if e > min_entropy:
            yield sector



def test_entropy():
    for block in [os.urandom(12) for i in range(10)] + [b' ' * 1512] + [
        b'the quick brown fox jumped over the lazy dog']:
        e = entropy(block)
        e_nib_hi = nib_entropy_hi(block)
        e_nib_lo = nib_entropy_lo(block)
        print(f"{e:5.2f} {e_nib_hi:5.2f} {e_nib_lo:5.2f}  {block[:35].hex()}")
