import concurrent.futures
import hashlib
import secrets

hash_functions = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}

HASH_TYPE = "sha256"


def hash_func(*args) -> bytes:
    """Concatenate all the arguments and hash the result.
       Note that the hash function used can be modified
       in the global parameter `HASH_TYPE`.

    Args:
        *args: Arguments to concatenate.

    Returns:
        bytes: The hashed string.
    """
    t = b""

    for arg in args:
        if type(arg) is int:
            t += arg.to_bytes(8, "little")
        elif type(arg) is str:
            t += arg.encode("utf-8")
        else:
            t += arg

    return hash_functions[HASH_TYPE](t).digest()


def expand(buf: list[bytes], cnt: int, space_cost: int) -> int:
    """First step of the algorithm. Fill up a buffer with
       pseudorandom bytes derived from the password and salt
       by computing repeatedly the hash function on a combination
       of the password and the previous hash.

    Args:
        buf (list[bytes]): A list of hashes as bytes.
        cnt (int): Used in a security proof (read the paper).
        space_cost (int): The size of the buffer.

    Returns:
        int: Counter used in a security proof (read the paper).
    """
    for s in range(1, space_cost):
        buf.append(hash_func(cnt, buf[s - 1]))
        cnt += 1
    return cnt


def mix(
    buf: list[bytes], cnt: int, delta: int, salt: bytes, space_cost: int, time_cost: int
) -> None:
    """Second step of the algorithm. Mix `time_cost` number
       of times the pseudorandom bytes in the buffer. At each
       step in the for loop, update the nth block to be
       the hash of the n-1th block, the nth block, and `delta`
       other blocks chosen at random from the buffer `buf`.

    Args:
        buf (list[bytes]): A list of hashes as bytes.
        cnt (int): Used in a security proof (read the paper).
        delta (int): Number of random blocks to mix with.
        salt (bytes): A user defined random value for security.
        space_cost (int): The size of the buffer.
        time_cost (int): Number of rounds to mix.

    Returns:
        void: Updates the buffer and counter, but does not
        return anything.
    """
    for t in range(time_cost):
        for s in range(space_cost):
            buf[s] = hash_func(cnt, buf[s - 1], buf[s])
            cnt += 1
            for i in range(delta):
                idx_block = hash_func(t, s, i)
                other = (
                    int.from_bytes(hash_func(cnt, salt, idx_block), "little")
                    % space_cost
                )
                cnt += 1
                buf[s] = hash_func(cnt, buf[s], buf[other])
                cnt += 1


def extract(buf: list[bytes]) -> bytes:
    """Final step. Return the last value in the buffer.

    Args:
        buf (list[bytes]): A list of hashes as bytes.

    Returns:
        bytes: Last value of the buffer as bytes.
    """
    return buf[-1]


def balloon(
    password: str, salt: str, space_cost: int, time_cost: int, delta: int = 3
) -> bytes:
    """Main function that collects all the substeps. As
       previously mentioned, first expand, then mix, and
       finally extract. Note the result is returned as bytes,
       for a more friendly function with default values
       that returns a hex string, see the function `balloon_hash`.

    Args:
        password (str): The main string to hash.
        salt (str): A user defined random value for security.
        space_cost (int): The size of the buffer.
        time_cost (int): Number of rounds to mix.
        delta (int, optional): Number of random blocks to mix with. Defaults to 3.

    Returns:
        bytes: A series of bytes, the hash.
    """
    # Encode salt as bytes to be passed to _balloon()
    return _balloon(password, salt.encode("utf-8"), space_cost, time_cost, delta)


def _balloon(
    password: str, salt: bytes, space_cost: int, time_cost: int, delta: int = 3
) -> bytes:
    """For internal use. Implements steps outlined in `balloon`.

    Args:
        password (str): The main string to hash.
        salt (bytes): A user defined random value for security.
        space_cost (int): The size of the buffer.
        time_cost (int): Number of rounds to mix.
        delta (int, optional): Number of random blocks to mix with. Defaults to 3.

    Returns:
        bytes: A series of bytes, the hash.
    """
    if not isinstance(space_cost, int) or space_cost < 1:
        raise ValueError("'space_cost' must be a positive integer.")
    if not isinstance(time_cost, int) or time_cost < 1:
        raise ValueError("'time_cost' must be a positive integer.")
    if not isinstance(delta, int) or delta < 1:
        raise ValueError("'delta' must be a positive integer.")
    buf = [hash_func(0, password, salt)]
    cnt = 1

    cnt = expand(buf, cnt, space_cost)
    mix(buf, cnt, delta, salt, space_cost, time_cost)
    return extract(buf)


def balloon_hash(password: str, salt: str) -> str:
    """A more friendly client function that just takes
       a password and a salt and outputs the hash as a hex string.

    Args:
        password (str): The main string to hash.
        salt (str): A user defined random value for security.

    Returns:
        str: The hash as hex.
    """
    delta = 4
    time_cost = 20
    space_cost = 16
    return balloon(password, salt, space_cost, time_cost, delta=delta).hex()


def balloon_m(
    password: str,
    salt: str,
    space_cost: int,
    time_cost: int,
    parallel_cost: int,
    delta: int = 3,
) -> bytes:
    """M-core variant of the Balloon hashing algorithm. Note the result
       is returned as bytes, for a more friendly function with default
       values that returns a hex string, see the function `balloon_m_hash`.

    Args:
        password (str): The main string to hash.
        salt (str): A user defined random value for security.
        space_cost (int): The size of the buffer.
        time_cost (int): Number of rounds to mix.
        parallel_cost (int): Number of concurrent instances.
        delta (int, optional): Number of random blocks to mix with. Defaults to 3.

    Returns:
        bytes: A series of bytes, the hash.
    """
    if not isinstance(parallel_cost, int) or parallel_cost < 1:
        raise ValueError("'parallel_cost' must be a positive integer.")
    output = b""

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []

        for p in range(parallel_cost):
            parallel_salt = b"" + salt.encode("utf-8") + (p + 1).to_bytes(8, "little")
            futures.append(
                executor.submit(
                    _balloon,
                    password,
                    parallel_salt,
                    space_cost,
                    time_cost,
                    delta=delta,
                )
            )
        completed_futures = concurrent.futures.as_completed(futures)
        output = next(completed_futures).result()
        for future in completed_futures:
            output = bytes([_a ^ _b for _a, _b in zip(output, future.result())])

    return hash_func(password, salt, output)


def balloon_m_hash(password: str, salt: str) -> str:
    """A more friendly client function that just takes
       a password and a salt and outputs the hash as a hex string.
       This uses the M-core variant of the Balloon hashing algorithm.

    Args:
        password (str): The main string to hash.
        salt (str): A user defined random value for security.

    Returns:
        str: The hash as hex.
    """
    delta = 4
    time_cost = 20
    space_cost = 16
    parallel_cost = 4
    return balloon_m(
        password, salt, space_cost, time_cost, parallel_cost, delta=delta
    ).hex()


def verify(
    hash: str, password: str, salt: str, space_cost: int, time_cost: int, delta: int = 3
) -> bool:
    """Verify that hash matches password when hashed with salt, space_cost,
       time_cost, and delta.

    Args:
        hash (str): The hash to check against.
        password (str): The password to verify.
        salt (str): A user defined random value for security.
        space_cost (int): The size of the buffer.
        time_cost (int): Number of rounds to mix.
        delta (int): Number of random blocks to mix with. Defaults to 3.

    Returns:
        bool: True if password matches hash, otherwise False.
    """
    return secrets.compare_digest(
        balloon(password, salt, space_cost, time_cost, delta).hex(), hash
    )


def verify_m(
    hash: str,
    password: str,
    salt: str,
    space_cost: int,
    time_cost: int,
    parallel_cost: int,
    delta: int = 3,
) -> bool:
    """Verify that hash matches password when hashed with salt, space_cost,
       time_cost, parallel_cost, and delta.
       This uses the M-core variant of the Balloon hashing algorithm.

    Args:
        hash (str): The hash to check against.
        password (str): The password to verify.
        salt (str): A user defined random value for security.
        space_cost (int): The size of the buffer.
        time_cost (int): Number of rounds to mix.
        parallel_cost (int): Number of concurrent instances.
        delta (int): Number of random blocks to mix with. Defaults to 3.

    Returns:
        bool: True if password matches hash, otherwise False.
    """
    return secrets.compare_digest(
        balloon_m(password, salt, space_cost, time_cost, parallel_cost, delta).hex(),
        hash,
    )
