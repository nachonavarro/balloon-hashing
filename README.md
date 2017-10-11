# Balloon Hashing

An implementation in Python of Balloon Hashing. All credit to Dan Boneh, Henry Corrigan-Gibbs, and Stuart Schechter. For more information see
the [research paper](https://eprint.iacr.org/2016/027.pdf) or their [website](https://crypto.stanford.edu/balloon/) for this project. All errors in the code are, of course, mine. Feel free to fix any mistakes.

## Background

Balloon Hashing is a new hashing function that, according to the paper, is:
	* **Built from Standard Primitives:** Builds on top of other common hashing functions.
	* **Has Proven Memory-Hardness Properties:** See paper.
	* **Resistant to Cache Attacks:** The idea is that an adversary who can observe the memory access patterns of the buffer in the algorithm (for example through cached side-channels) still can't figure out the password being cached.
	* **Practical:** Is as good as the best hashing functions used in production today.

