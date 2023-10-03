import glob
import argparse
import hashlib
import os.path
import concurrent.futures


def find_files(input_glob):
    paths = glob.glob(input_glob, recursive=True)
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
        print(f"Processing {file_path}")
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
        print(f"Processing {file_path}: {digest}")
        return digest
    except Exception as e:
        print(f"Error hashing the file: {e}")
        return None


def get_hashes(files):
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        results = list(executor.map(hash_file, files))
        return results


if __name__ == "__main__":
    print("hello")
    parser = argparse.ArgumentParser()
    parser.add_argument("glob")
    args = parser.parse_args()
    print("getting files")
    files = find_files(args.glob)
    print("computing hashes")
    hashes = get_hashes(files)
