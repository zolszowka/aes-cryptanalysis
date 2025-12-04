"""
Encrypt plainexts from a CSV file using BabyAES and save the results to another CSV.
"""

import os
import csv
from baby_aes import encrypt_with_babyaes

INPUT_FILE = "input.csv"
OUTPUT_FILE = "output.csv"
ROUNDS = 3

data = []
with open(INPUT_FILE, newline="", encoding="utf-8") as file:
    reader = csv.DictReader(file)

    for row in reader:
        plaintext = row["plaintext"]
        key = row["key"]
        data.append((plaintext, key))

file_exists = os.path.isfile(OUTPUT_FILE)

with open(OUTPUT_FILE, "a", newline="", encoding="utf-8") as file:
    writer = csv.writer(file)

    if not file_exists:
        writer.writerow(["plaintext", "key", "rounds", "ciphertext"])

    for row in data:
        if len(row[0]) != 16 or len(row[1]) != 16:
            print(
                f"Skipping invalid row (plaintext and key must be 16-bit): {row}")
            continue

        plaintext_int = int(row[0], 2)
        key_int = int(row[1], 2)

        ciphertext = encrypt_with_babyaes(plaintext_int, key_int, ROUNDS)

        # Używamy row[0] i row[1], czyli bieżącego wiersza
        writer.writerow([row[0], row[1], ROUNDS, f"{ciphertext:016b}"])


print(f"Results saved in {OUTPUT_FILE}")
