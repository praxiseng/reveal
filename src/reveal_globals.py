
class Globs():
    def __init__(self):
        
        # The maximum list size in the database.  The list will switch to a summary count above this value.
        self.MAX_LIST_SIZE = 1000

        # Whether to zero out bytes that look like they are PC-relative operands before hashing.
        self.ZEROIZE_X86_PC_REL = False

        # Clumps group a bunch of CBOR items in a larger bundle to reduce the Python serialization overhead.
        # IDEA: some form of clumps could be integrated with indexing.  The clump header could have some local
        # stats information, and the high-level index could point to the clump header.
        self.CLUMP_SIZE=20

    def update(self, other):
        self.MAX_LIST_SIZE = other.MAX_LIST_SIZE
        self.ZEROIZE_X86_PC_REL = other.ZEROIZE_X86_PC_REL
        self.CLUMP_SIZE = other.CLUMP_SIZE

globs = Globs()