BINARIES=bins/linux_bin
SEARCH_FILE=bins/linux_bin/ls

DB=databases/default_database.db

PYTHON=python3
ENTRY=$(PYTHON) src/hasher.py

HASH_FLAGS=--parallelism=16

SOURCES = $(wildcard $(SOURCEDIR)/*.py)

search: $(DB) $(SEARCH_FILE) $(SOURCES)
	$(ENTRY) $(DB) --search $(SEARCH_FILE) $(HASH_FLAGS)

$(DB): $(BINARIES) $(SOURCES)
	$(ENTRY) $(DB) $(BINARIES) $(HASH_FLAGS)


clean:
	rm -rf $(DB)