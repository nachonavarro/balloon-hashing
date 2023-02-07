# Balloon Hashing

An implementation in Python of Balloon Hashing. All credit to Dan Boneh, Henry Corrigan-Gibbs, and Stuart Schechter. For more information see
the [research paper](https://eprint.iacr.org/2016/027.pdf) or their [website](https://crypto.stanford.edu/balloon/) for this project. All errors in the code are, of course, mine. Feel free to fix any mistakes.

## Developer

Works on Python 3.

Check test vectors with `python -m unittest`.

## Background

Balloon Hashing is a new hashing function that, according to the paper, is:

* **Built from Standard Primitives:** Builds on top of other common hashing functions.
* **Has Proven Memory-Hardness Properties:** See paper.
* **Resistant to Cache Attacks:** The idea is that an adversary who can observe the memory access patterns of the buffer in the algorithm (for example through cached side-channels) still can't figure out the password being cached.
* **Practical:** Is as good as the best hashing functions used in production today.

## Algorithm

The algorithm consists of three main parts, as explained in the paper. The first step is the expansion, in which the system fills
up a buffer with pseudorandom bytes derived from the password and salt by computing repeatedly the hash function on a combination
of the password and the previous hash. The second step is mixing, in which the system mixes time_cost number of times the pseudorandom
bytes in the buffer. At each step in the for loop, it updates the nth block to be the hash of the n-1th block, the nth block,
and delta other blocks chosen at random from the buffer. In the last step, the extraction, the system outputs as the hash the last
element in the buffer.

## Usage

An example will suffice to show how it works:

```python
>>> import balloon as b
>>> password = "buildmeupbuttercup"
>>> salt = 'JqMcHqUcjinFhQKJ'
>>> print(b.balloon_hash(password, salt))
2ec8d833db5f88e584ab793950ecfb21657a3816edea8d9e73ea23c13ba2b740

# A slightly more advanced usage
>>> delta = 5
>>> time_cost = 18
>>> space_cost = 24
>>> bs = b.balloon(password, salt, space_cost, time_cost, delta=delta)
>>> print(bs.hex())
69f86890cef40a7ec5f70daff1ce8e2cde233a15bffa785e7efdb5143af51bfb
```

## Formatting

```bash
pip install black
black .
```
