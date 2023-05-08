


def convert_db(db_path):
    all_files = dict()
    max_id = 1
    i = 0
    hash_6byte = lambda row:row[3][:N_BYTES_IN_HASH*2]
    hashlist = []

    query = "SELECT * FROM MD5B128 ORDER BY HASH"
    for row in rowgen(db_path, query):
        metadata_id, key_hash, block, hash, file_name, extension = row
        name_path = f'{key_hash[:N_BYTES_IN_HASH]}_{file_name}.{extension}'

        if metadata_id not in all_files:
            all_files[metadata_id] = dict(
                path=name_path,
                id=max_id,
                md5="",
                key_hash=key_hash
            )
            max_id += 1

    header = dict(files=list(all_files.values()),
                  blocksize=128,
                  zeroize_x86_pc_rel=False,
                  blockAlgorithm=dict(
                      aligned=1,
                      step=128,
                      shortBlocks=False))

    out_fd = open('test.cbor', 'wb')
    out_fd.write(cbor2.dumps(header))

    for hash_key, group_iter in itertools.groupby(rowgen(db_path, query), key=hash_6byte):
        i += 1
        #if i > 1000:
        #    break

        group_rows = list(group_iter)

        fid_offsets = []
        name_paths = []

        metadata_ids = set()
        for row in group_rows:
            metadata_id, key_hash, block, hash, file_name, extension = row

            metadata_ids.add(metadata_id)

            name_path = f'{key_hash[:6]}_{file_name}.{extension}'
            name_paths.append(name_path)

            fid = all_files[metadata_id]['id']

            file_offset = block*128

            fid_offsets.append((fid, file_offset))

        n_files = len(metadata_ids)
        n_hashes = len(group_rows)

        file_list_record = [bytes.fromhex(hash_key), n_hashes, fid_offsets]

        out_fd.write(cbor2.dumps(file_list_record))

        if i%10000 == 0:
            print(f'{i:8} hashes')
        # print(f'{i:4} {fid:6} {file_offset:6x} {hash_key} {fid_offsets} {",".join(name_paths)}')

#convert_db(r"C:\users\scott\Downloads\nsrl_blockhash.db")