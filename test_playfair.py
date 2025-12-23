from playfair import generate_matrix, playfair_encrypt, playfair_decrypt

# Test với plaintext dài
plaintext = """Like most classical ciphers, the Playfair cipher can be easily cracked if there is enough text. Obtaining the key is relatively straightforward if both plaintext and ciphertext are known. When only the ciphertext is known, brute force cryptanalysis of the cipher involves searching through the key space for matches between the frequency of occurrence of digrams (pairs of letters) and the known frequency of occurrence of digrams in the assumed language of the original message.[12]

Cryptanalysis of Playfair is similar to that of four-square and two-square ciphers, though the relative simplicity of the Playfair system makes identifying candidate plaintext strings easier. Most notably, a Playfair digraph and its reverse (e.g. AB and BA) will decrypt to the same letter pattern in the plaintext (e.g. RE and ER). In English, there are many words which contain these reversed digraphs such as REceivER and DEpartED. Identifying nearby reversed digraphs in the ciphertext and matching the pattern to a list of known plaintext words containing the pattern is an easy way to generate possible plaintext strings with which to begin constructing the key."""

key = "SECRET"

# Generate matrix
matrix, pos_map = generate_matrix(key, size=5)

print("=" * 80)
print("PLAYFAIR CIPHER TEST")
print("=" * 80)
print(f"\nKey: {key}")
print(f"\nOriginal plaintext length: {len(plaintext)}")
print(f"\nOriginal plaintext:\n{plaintext}\n")

# Encrypt
ciphertext, steps, preprocessed, ciphertext_with_invalid = playfair_encrypt(
    plaintext, matrix, pos_map, 
    pad_double_letters=True, 
    padding_char='X'
)

print("=" * 80)
print("ENCRYPTION")
print("=" * 80)
print(f"\nPreprocessed text:\n{preprocessed[:200]}...\n")
print(f"Ciphertext (no spaces):\n{ciphertext[:200]}...\n")
print(f"Ciphertext (with original spacing):\n{ciphertext_with_invalid[:200]}...\n")

# Decrypt
decrypted, decrypt_steps, decrypted_with_invalid = playfair_decrypt(
    ciphertext_with_invalid, matrix, pos_map, 
    padding_char='X'
)

print("=" * 80)
print("DECRYPTION")
print("=" * 80)
print(f"\nDecrypted text (no spaces):\n{decrypted[:200]}...\n")
print(f"Decrypted text (with original spacing):\n{decrypted_with_invalid[:200]}...\n")

# Tìm đoạn có vấn đề
target = "frequency of occurrence of digrams"
print("=" * 80)
print(f"CHECKING TARGET PHRASE: '{target}'")
print("=" * 80)

# Tìm vị trí trong text gốc
start_idx = plaintext.lower().find(target)
if start_idx != -1:
    end_idx = start_idx + len(target)
    print(f"\nOriginal text [{start_idx}:{end_idx}]:")
    print(f"'{plaintext[start_idx:end_idx]}'")
    
    # Kiểm tra trong ciphertext_with_invalid
    print(f"\nCiphertext at same position:")
    print(f"'{ciphertext_with_invalid[start_idx:end_idx]}'")
    
    # Kiểm tra trong decrypted
    print(f"\nDecrypted at same position:")
    print(f"'{decrypted_with_invalid[start_idx:end_idx]}'")
    
    # So sánh chi tiết
    print("\nCharacter-by-character comparison:")
    print(f"{'Pos':<5} {'Original':<10} {'Encrypted':<10} {'Decrypted':<10} {'Match?'}")
    print("-" * 55)
    for i in range(start_idx, min(end_idx, start_idx + 50)):
        orig = plaintext[i]
        enc = ciphertext_with_invalid[i] if i < len(ciphertext_with_invalid) else '?'
        dec = decrypted_with_invalid[i] if i < len(decrypted_with_invalid) else '?'
        match = '✓' if orig.lower() == dec.lower() else '✗'
        print(f"{i:<5} {repr(orig):<10} {repr(enc):<10} {repr(dec):<10} {match}")

print("\n" + "=" * 80)
print("COMPARISON SUMMARY")
print("=" * 80)
print(f"Original length:  {len(plaintext)}")
print(f"Encrypted length: {len(ciphertext_with_invalid)}")
print(f"Decrypted length: {len(decrypted_with_invalid)}")
print(f"\nFirst 100 chars match: {plaintext[:100].lower() == decrypted_with_invalid[:100].lower()}")
