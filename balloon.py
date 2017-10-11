import hashlib

hash_functions = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha224': hashlib.sha224,
    'sha256': hashlib.sha256,
    'sha384': hashlib.sha384,
    'sha512': hashlib.sha512
}

HASH_TYPE = 'sha256'

def hash_func(*args):
    """Concatenate all the arguments and hash the result.
       Note that the hash function used can be modified
       in the global parameter HASH_TYPE.

    Args:
        *args: Arguments to concatenate

    Returns:
        str: The hashed string

    """
    t = ''.join([str(arg) for arg in args])
    return hash_functions[HASH_TYPE](t).digest()

def expand(buf, cnt, space_cost):
    """First step of the algorithm. Fill up a buffer with
       pseudorandom bytes derived from the password and salt
       by computing repeatedly the hash function on a combination
       of the password and the previous hash.

    Args:
        buf (list str): A list of hashes as bytes.
        cnt (int): Used in a security proof (read the paper)
        space_cost (int): The size of the buffer

    Returns:
        void: Updates the buffer and counter, but does not
        return anything.

    """
    for s in range(1, space_cost):
        buf.append(hash_func(cnt, buf[s - 1]))
        cnt += 1

def mix(buf, cnt, delta, salt, space_cost, time_cost):
    """Second step of the algorithm. Mix time_cost number
       of times the pseudorandom bytes in the buffer. At each
       step in the for loop, update the nth block to be
       the hash of the n-1th block, the nth block, and delta
       other blocks chosen at random from the buffer.

    Args:
        buf (list str): A list of hashes as bytes.
        cnt (int): Used in a security proof (read the paper)
        delta (int): Number of random blocks to mix with.
        salt (str): A user defined random value for security
        space_cost (int): The size of the buffer
        time_cost (int): Number of rounds to mix

    Returns:
        void: Updates the buffer and counter, but does not
        return anything.

    """
    for t in range(time_cost):
        for s in range(space_cost):
            buf[s] = hash_func(cnt, buf[s - 1], buf[s])
            cnt += 1
            for i in range(delta):
                other  = int(hash_func(cnt, salt, t, s, i).encode('hex'), 16) % space_cost
                cnt   += 1
                buf[s] = hash_func(cnt, buf[s], buf[other])
                cnt   += 1

def extract(buf):
    """Final step. Return the last value in the buffer.

    Args:
        buf (list str): A list of hashes as bytes.

    Returns:
        str: Last value of the buffer as bytes

    """
    return buf[-1]

def balloon(password, salt, space_cost, time_cost, delta=3):
    """Main function that collects all the substeps. As
       previously mentioned, first expand, then mix, and 
       finally extract. Note the result is returned as bytes,
       for a more friendly function with default values
       and returning a hex string see the function balloon_hash

    Args:
        password (str): The main string to hash
        salt (str): A user defined random value for security
        space_cost (int): The size of the buffer
        time_cost (int): Number of rounds to mix
        delta (int): Number of random blocks to mix with.

    Returns:
        str: A series of bytes, the hash.

    """
    buf = [hash_func(0, password, salt)]
    cnt = 1

    expand(buf, cnt, space_cost)
    mix(buf, cnt, delta, salt, space_cost, time_cost)
    return extract(buf)

def balloon_hash(password, salt):
    """A more friendly client function that just takes
       a password and a salt and computes outputs the hash in hex.

    Args:
        password (str): The main string to hash
        salt (str): A user defined random value for security

    Returns:
        str: The hash as hex.

    """
    delta      = 4
    time_cost  = 20
    space_cost = 16
    return balloon(password, salt, space_cost, time_cost, delta=delta).encode('hex')








