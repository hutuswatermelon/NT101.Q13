from playfair import generate_matrix, playfair_encrypt, playfair_decrypt

# Test với text ban đầu
plaintext = """Like most classical ciphers, the Playfair cipher can be easily cracked if there is enough text. Obtaining the key is relatively straightforward if both plaintext and ciphertext are known. When only the ciphertext is known, brute force cryptanalysis of the cipher involves searching through the key space for matches between the frequency of occurrence of digrams (pairs of letters) and the known frequency of occurrence of digrams in the assumed language of the original message.[12]

Cryptanalysis of Playfair is similar to that of four-square and two-square ciphers, though the relative simplicity of the Playfair system makes identifying candidate plaintext strings easier. Most notably, a Playfair digraph and its reverse (e.g. AB and BA) will decrypt to the same letter pattern in the plaintext (e.g. RE and ER). In English, there are many words which contain these reversed digraphs such as REceivER and DEpartED. Identifying nearby reversed digraphs in the ciphertext and matching the pattern to a list of known plaintext words containing the pattern is an easy way to generate possible plaintext strings with which to begin constructing the key."""

key = "SECRET"

# Generate matrix
matrix, pos_map = generate_matrix(key, size=5)

# Encrypt
ciphertext, steps, preprocessed, ciphertext_with_invalid = playfair_encrypt(
    plaintext, matrix, pos_map, 
    pad_double_letters=True, 
    padding_char='X'
)

print("=" * 80)
print("CIPHERTEXT COMPARISON")
print("=" * 80)
print("\n1. Ciphertext WITH spaces (for display only):")
print("-" * 80)
print(ciphertext_with_invalid[:200])
print()

print("2. Ciphertext WITHOUT spaces (compatible with standard tools):")
print("-" * 80)
print(ciphertext[:200])
print()

print("=" * 80)
print("IMPORTANT: For standard Playfair tools compatibility")
print("=" * 80)
print("✓ Use ciphertext WITHOUT spaces")
print("✓ Standard tools remove all spaces/special chars before encryption")
print("✓ Our 'ciphertext' (no spaces) = Standard tool output")
print("✓ Our 'ciphertext_with_invalid' = Display-friendly version")
print()

# Test decrypt với ciphertext KHÔNG CÓ space
print("=" * 80)
print("DECRYPTION TEST")
print("=" * 80)
print("\nDecrypting ciphertext (no spaces)...")
decrypted, _, decrypted_with_invalid = playfair_decrypt(
    ciphertext, matrix, pos_map, 
    padding_char='X'
)

print(f"\nDecrypted: {decrypted[:200]}")
print(f"\nOriginal (processed): {plaintext[:200].upper().replace('J', 'I')}")
print()

# So sánh với text bạn cung cấp
print("=" * 80)
print("VERIFY YOUR ENCRYPTED TEXT")
print("=" * 80)
your_encrypted = "FLEY SKMZ LSCPQLRBS LHQGYCM, VFY NHCKHBHD RHQGYD RDP DW YDQLHO RDBREYB GM KGYDK LQ DUEZHI UKZU. WCVRGQGQF UGY EYW HM COGRVHXOGO PKFBHHIKMKCYBDA LG CWVF SHBHMUWUV RUG BLVPKDUKZU BDY ESEEQ. YIDU ESHO VFO DHQGYFKWUX FM OSEEQ, CDVUK GKCDO RDAVVRPDHOQLZ CM KGY BLVPKD GQZYHZON NOBDALGQF UFAEZHI VFK EYW MQBRK GKC PRZRGYQ CKUOYDU VFK GDKNXDUAO KL CLDZBTDKSD YK GRLHDBN (MVHFB ZC GFKUUKC) MDP RUG YEMKO MGDKNXDUA OK LCLDZBTDKS DY KGRLHDB NM GQV FYDQZNZ NKCGDPNE DH YKM KGYKCLHG QCHNKQZ.[12]"

# Remove spaces from your encrypted text
your_encrypted_no_spaces = your_encrypted.replace(' ', '')

print(f"\nYour encrypted (with spaces): {your_encrypted[:100]}")
print(f"\nYour encrypted (no spaces): {your_encrypted_no_spaces[:100]}")
print(f"\nOur encrypted (no spaces): {ciphertext[:100]}")
print(f"\nMatch? {your_encrypted_no_spaces[:100] == ciphertext[:100]}")
print()

if your_encrypted_no_spaces == ciphertext:
    print("✓ PERFECT MATCH! Our encryption matches yours exactly!")
else:
    print("✗ Different results. Checking differences...")
    print(f"\nYour length: {len(your_encrypted_no_spaces)}")
    print(f"Our length:  {len(ciphertext)}")
    
    # Find first difference
    for i, (y, o) in enumerate(zip(your_encrypted_no_spaces, ciphertext)):
        if y != o:
            print(f"\nFirst difference at position {i}:")
            print(f"  Your char: {y}")
            print(f"  Our char:  {o}")
            print(f"  Context yours: ...{your_encrypted_no_spaces[max(0,i-5):i+6]}...")
            print(f"  Context ours:  ...{ciphertext[max(0,i-5):i+6]}...")
            break
