
import hashlib


def calculate_sha256(file_obj, chunk_size=1024 * 1024):
    """
    Calculate SHA-256 without loading the entire file into memory.

    Reads the file in 1 MB chunks and restores its original position.
    """
    sha256 = hashlib.sha256()

    original_position = file_obj.tell()

    try:
        file_obj.seek(0)

        while True:
            chunk = file_obj.read(chunk_size)

            if not chunk:
                break

            sha256.update(chunk)

    finally:
        file_obj.seek(original_position)

    return sha256.hexdigest()


def verify_artifact_version(version):
    """
    Recalculate the hash of a stored artifact version
    and compare it with the originally recorded hash.
    """
    with version.file.open("rb") as stored_file:
        actual_hash = calculate_sha256(stored_file)

    expected_hash = version.sha256_hash

    return {
        "artifact_id": version.artifact_id,
        "version_number": version.version_number,
        "expected_hash": expected_hash,
        "actual_hash": actual_hash,
        "is_valid": actual_hash == expected_hash,
    }
