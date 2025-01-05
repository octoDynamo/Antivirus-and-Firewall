import hashlib

def calculate_hash(file_path):
    hasher = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

file_path = "./test_files/eicar_test.txt"  # Adjust the path if necessary
print("MD5 Hash:", calculate_hash(file_path))
