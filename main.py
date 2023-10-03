import glob
import hashlib
import os.path
import concurrent.futures
import click


def find_files(input_glob):
    paths = glob.glob(input_glob, recursive=True)
    # return only paths that are files
    return [p for p in paths if os.path.isfile(p)]


def hash_file(file_path, hash_algorithm="sha256"):
    """
        Compute the hash (default: SHA-256) of a file.

    Args:
        file_path (str): The path to the file to be hashed.
        hash_algorithm (str): The hash algorithm to use (e.g., "sha256", "md5").

    Returns:
        str: The computed hash value in hexadecimal format.
    """
    try:
        # Create a hash object based on the specified algorithm
        hasher = hashlib.new(hash_algorithm)

        # Read the file in binary mode and update the hash object
        with open(file_path, "rb") as file:
            while True:
                data = file.read(8192)  # Read the file in chunks
                if not data:
                    break
                hasher.update(data)

        # Return the hexadecimal representation of the hash
        digest = hasher.hexdigest()
        # print(f"Processing {file_path}: {digest}")
        return file_path, digest
    except Exception as e:
        print(f"Error hashing the file: {e}")
        return None


def get_hashes(files):
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(hash_file, files))
        return results


def get_file_info(glob):
    print("finding files...")
    files = find_files(glob)
    print("comparing files...")
    return get_hashes(files)


def find_dups(file_infos):
    # create a dict from hash to path
    retval = {}
    for path, hash in file_infos:
        if hash in retval:
            retval[hash].append(path)
        else:
            retval[hash] = [path]
    return {k: v for k, v in retval.items() if len(v) > 1}


def prune_dups(dups):
    # dups is a dict from hash to list of paths
    for _hash, files in dups.items():
        for f in files[1:]:
            print(f"removing duplicate file: {f}")
            os.remove(f)


@click.group()
def main():
    pass


@main.command()
@click.argument("glob")
def find(**kwargs):
    glob = kwargs["glob"]
    files = get_file_info(glob)
    dups = find_dups(files)
    if len(dups) == 0:
        print("No duplicate files found.")
    else:
        print(
            "Duplicate files (all of these are copies of other files not in this list and can be safely removed):"
        )
        for k, v in dups.values():
            print(v)


@main.command()
@click.argument("glob")
@click.argument("output")
def coalesce(**kwargs):
    glob = kwargs["glob"]
    output_path = kwargs["output"]
    files = find_files(glob)
    for f in files:
        basename = os.path.basename(f)
        target = os.path.join(output_path, basename)
        (root, ext) = os.path.splitext(target)
        fixed_target = target
        i = 0
        while os.path.exists(fixed_target):
            i = i + 1
            fixed_target = f"{root}-{str(i)}{ext}"
        print(f"Moving {f} to {fixed_target}")
        os.rename(f, fixed_target)


@main.command()
@click.argument("glob")
@click.option("--dry-run", is_flag=True)
def dedup(**kwargs):
    glob = kwargs["glob"]
    files = get_file_info(glob)
    dups = find_dups(files)
    if len(dups) == 0:
        print("No duplicate files found.")
    else:
        if kwargs["dry_run"]:
            print("Dry run, would have deleted:")
            for k, v in dups.values():
                print(v)
        else:
            prune_dups(dups)
            pass


if __name__ == "__main__":
    main()
    # TODO: use logging
    # TODO: add stats
    # TODO: add quarantine option
    # TODO: add report command
