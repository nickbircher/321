import sys
sys.path.insert(0, "..")
import pkcs7  

def submit():
    print("")


def verify():
    print("")


def calculate_bitmasks(original, target):
    bitmasks = []
    for i in range(len(original)):
        # Calculate the bitmask
        bitmask = ord(original[i]) ^ ord(target[i])
        bitmasks.append(bitmask)

    return bitmasks


def flip_bits(temp):
    print()


def main():
    print()

if __name__ == "__main__":
    main()