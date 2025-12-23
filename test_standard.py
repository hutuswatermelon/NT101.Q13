from playfair import generate_matrix, playfair_encrypt, playfair_decrypt, preprocess_text

# Test với ví dụ đơn giản
key = "PLAYFAIR"
plaintext = "HELLO WORLD"

print("=" * 80)
print("TEST WITH STANDARD PLAYFAIR TOOL")
print("=" * 80)
print(f"Key: {key}")
print(f"Plaintext: {plaintext}")
print()

# Generate matrix
matrix, pos_map = generate_matrix(key, size=5)

print("Generated Matrix:")
for row in matrix:
    print(" ".join(row))
print()

# Preprocess để xem text được xử lý như thế nào
preprocessed = preprocess_text(plaintext, matrix_size=5, pad_double_letters=True, padding_char='X')
print(f"Preprocessed text: {preprocessed}")
print(f"Pairs: {[preprocessed[i:i+2] for i in range(0, len(preprocessed), 2)]}")
print()

# Encrypt
ciphertext, steps, _, ciphertext_with_invalid = playfair_encrypt(
    plaintext, matrix, pos_map, 
    pad_double_letters=True, 
    padding_char='X'
)

print(f"Ciphertext (no spaces): {ciphertext}")
print(f"Ciphertext (with spaces): {ciphertext_with_invalid}")
print()

print("Encryption steps:")
for step in steps:
    print(f"  {step['pair']} -> {step['result']} ({step['rule']})")
print()

# Decrypt
decrypted, _, decrypted_with_invalid = playfair_decrypt(
    ciphertext, matrix, pos_map, 
    padding_char='X'
)

print(f"Decrypted (no spaces): {decrypted}")
print(f"Decrypted (with spaces): {decrypted_with_invalid}")
print()

print("=" * 80)
print("TEST CASE 2: Text with double letters")
print("=" * 80)
plaintext2 = "BALLOON"
print(f"Plaintext: {plaintext2}")

preprocessed2 = preprocess_text(plaintext2, matrix_size=5, pad_double_letters=True, padding_char='X')
print(f"Preprocessed: {preprocessed2}")
print(f"Pairs: {[preprocessed2[i:i+2] for i in range(0, len(preprocessed2), 2)]}")

ciphertext2, steps2, _, _ = playfair_encrypt(
    plaintext2, matrix, pos_map, 
    pad_double_letters=True, 
    padding_char='X'
)

print(f"Ciphertext: {ciphertext2}")
print("Steps:")
for step in steps2:
    print(f"  {step['pair']} -> {step['result']} ({step['rule']})")
print()

print("=" * 80)
print("INSTRUCTIONS FOR MANUAL VERIFICATION:")
print("=" * 80)
print("1. Go to: https://www.dcode.fr/playfair-cipher")
print("   or: https://planetcalc.com/7950/")
print("2. Use key: PLAYFAIR")
print("3. Test 'HELLO WORLD' and compare with our result")
print("4. Expected preprocessing: HELLO WORLD -> HEL LO WORLD -> HELXLOWORLDX (if double-L gets X)")
print()
print("Standard Playfair rules:")
print("- J is merged with I")
print("- Double letters in same digram get X inserted between them")
print("- Odd length text gets X appended at end")
