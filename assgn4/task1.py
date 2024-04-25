import hashlib

def compute_sha256_hash(input_data, num_bits):
    # Create a new SHA256 hash object
    sha256_hash = hashlib.sha256()

    # Update the hash object with the input data
    sha256_hash.update(input_data.encode())

    # Get the hexadecimal digest of the hash
    digest = sha256_hash.hexdigest()

    # Convert the digest to an integer
    digest_int = int(digest, 16)

    # Truncate the digest to the specified number of bits
    truncated_digest = digest_int & ((1 << num_bits) - 1)

    return truncated_digest


def find_collision(m0):
    # Initialize m1 as an empty string
    m1 = ""

    # Start with an initial value for m1
    i = 0

    # Keep iterating until a collision is found
    while True:
        # Concatenate m0 and the current value of i to form m1
        m1 = m0 + str(i)

        # Compute the hash of m0 and m1
        hash_m0 = compute_sha256_hash(m0, num_bits2)
        hash_m1 = compute_sha256_hash(m1, num_bits2)

        # Check if the hashes are equal
        if hash_m0 == hash_m1:
            break

        # Increment i for the next iteration
        i += 1

    return m1


# Example usage
input_data1 = "string1"
input_data2 = "string2"

num_bits1 = 8
num_bits2 = 50

digest1 = compute_sha256_hash(input_data1, num_bits1)
digest2 = compute_sha256_hash(input_data2, num_bits2)

print("Truncated Digest 1 ({} bits):".format(num_bits1), digest1)
print("Truncated Digest 2 ({} bits):".format(num_bits2), digest2)

print(find_collision(input_data1))