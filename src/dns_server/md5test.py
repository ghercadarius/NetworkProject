import hashlib


def md5_checksum(file_path):
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
    except FileNotFoundError:
        return None, f"not found: {file_path}"
    return hash_md5.hexdigest(), None


def compare_files(file1, file2):
    checksum1, error1 = md5_checksum(file1)
    checksum2, error2 = md5_checksum(file2)

    if error1:
        return error1
    if error2:
        return error2

    if checksum1 == checksum2:
        return f"'{file1}' and '{file2}' checksum match success"
    else:
        return f"'{file1}' and '{file2}' checksum match failed"


def main():
    file1 = input("Enter the path for the first file: ")
    file2 = input("Enter the path for the second file: ")

    result = compare_files(file1, file2)
    print(result)


if __name__ == "__main__":
    main()