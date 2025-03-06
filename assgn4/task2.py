import bcrypt
import nltk
import time

# Load the nltk word corpus
nltk.download('words')
from nltk.corpus import words

# Filter the words to only include those between 6 and 10 letters long
word_list = [word for word in words.words() if 6 <= len(word) <= 10]

# Load the shadow file
with open('test.txt', 'r') as f:
    lines = f.readlines()

# For each user in the shadow file
for line in lines:
    user, rest = line.split(":")
    parts = rest.split("$")
    algorithm, workfactor = parts[1], parts[2]
    salt_hash = "$".join(parts[3:])    
    salt, hash_value = salt_hash[:22], salt_hash[22:]

    print(user, algorithm, workfactor, salt, hash_value)

    start_time = time.time()

    # For each word in the filtered nltk corpus
    for word in word_list:
        # Hash the word with the user's salt using bcrypt
        hashed_word = bcrypt.hashpw(word.encode(), ("$" + algorithm + "$" + workfactor + "$" + salt).encode())
        split_hash = hashed_word.decode().split("$")[-1]
        test_hash = split_hash[22:]
        # print(hashed_word)
        # print(split_hash, hash_value)

        # If the hashed word matches the user's hash, the word is the user's password
        if test_hash == hash_value:
            end_time = time.time()
            elapsed_time = end_time - start_time
            print(f"Cracked password for {user}: {word}")
            print(f"Time taken to crack password: {elapsed_time} seconds")
            break
