BINARIES=bins/linux_bin/
SEARCH_FILE=bins/linux_bin/ls

DB=databases/default_database.db

PYTHON=python3
ENTRY=$(PYTHON) src/main.py

#HASH_FLAGS=--zeroize --parallelism=10
HASH_FLAGS=--parallelism=16 --blocksize=512 --use-c-tool

SOURCES = $(wildcard $(SOURCEDIR)/*.py)

search: $(DB) $(SEARCH_FILE) $(SOURCES)
	$(ENTRY) $(DB) --search $(SEARCH_FILE) $(HASH_FLAGS)

$(DB): $(BINARIES) $(SOURCES)
	$(ENTRY) $(DB) $(BINARIES) $(HASH_FLAGS)


clean:
	rm -rf $(DB)