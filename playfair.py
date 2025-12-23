from __future__ import annotations

from typing import Dict, List, Tuple, Optional


Matrix = List[List[str]]
PositionMap = Dict[str, Tuple[int, int]]


def build_char_mapping(original: str, processed: str, matrix_size: int = 5) -> Dict[int, int]:
    """
    Build mapping from original text positions to processed text positions.
    
    Args:
        original: Original text with all characters
        processed: Processed text (after preprocess_text)
        matrix_size: Size of matrix
    
    Returns:
        Dictionary mapping original_pos -> processed_pos for valid characters
    """
    mapping = {}
    processed_idx = 0
    
    for orig_idx, char in enumerate(original):
        # Check if character is valid
        is_valid = False
        if matrix_size == 5:
            is_valid = char.isalpha()
        elif matrix_size == 6:
            is_valid = char.isalnum()
        
        if is_valid:
            if processed_idx < len(processed):
                mapping[orig_idx] = processed_idx
                processed_idx += 1
    
    return mapping


def extract_invalid_chars(text: str, matrix_size: int = 5) -> Tuple[str, List[Tuple[int, str]]]:
    """
    Extract valid text and record invalid character positions.
    
    Args:
        text: Input text with mixed characters
        matrix_size: Size of matrix (5 or 6)
    
    Returns:
        Tuple of (valid_text, list_of_invalid_chars) where:
        - valid_text: text with only valid characters
        - list_of_invalid_chars: list of (position, character) tuples
    """
    invalid_chars = []
    valid_text = []
    
    for char in text:
        # Check if character is valid based on matrix size
        is_valid = False
        if matrix_size == 5:
            is_valid = char.isalpha()
        elif matrix_size == 6:
            is_valid = char.isalnum()
        
        if is_valid:
            valid_text.append(char)
        else:
            # Lưu vị trí chèn và ký tự
            invalid_chars.append((len(valid_text), char))
    
    return ''.join(valid_text), invalid_chars


def restore_invalid_chars(text: str, invalid_chars: List[Tuple[int, str]]) -> str:
    """
    Restore invalid characters to text at original positions.
    
    Args:
        text: Text with only valid characters
        invalid_chars: List of (position, character) tuples
    
    Returns:
        Text with invalid characters restored
    """
    if not invalid_chars:
        return text
    
    result = list(text)
    # Chèn từ cuối để không ảnh hưởng vị trí
    for pos, char in sorted(invalid_chars, reverse=True):
        if pos <= len(result):
            result.insert(pos, char)
    
    return ''.join(result)


def preprocess_text(text: str, matrix_size: int = 5, pad_double_letters: bool = True, padding_char: str = 'X') -> str:
    """
    Preprocess text for Playfair encryption.
    Filters valid characters, handles duplicates, and adds padding.
    
    Args:
        text: Input text to preprocess
        matrix_size: Size of matrix (5 or 6)
        pad_double_letters: If True, insert padding between duplicate letters
        padding_char: Character to use for padding (default 'X')
    """
    # Convert to uppercase and filter valid characters
    if matrix_size == 5:
        # Only letters, J -> I
        text = "".join(c for c in text.upper() if c.isalpha())
        text = text.replace("J", "I")
    else:
        # Letters and digits
        text = "".join(c for c in text.upper() if c.isalnum())
    
    if not text:
        return ""

    characters: List[str] = list(text)
    
    # Handle double letters if enabled
    if pad_double_letters:
        i = 0
        while i < len(characters) - 1:
            if characters[i] == characters[i + 1]:
                characters.insert(i + 1, padding_char)
            i += 2
    
    # Ensure even length
    if len(characters) % 2 != 0:
        characters.append(padding_char)

    return "".join(characters)


def preprocess_key(key: str, matrix_size: int = 5) -> str:
    """
    Preprocess encryption key.
    
    Args:
        key: Input key
        matrix_size: Size of matrix (5 or 6)
    """
    if matrix_size == 5:
        key = "".join(c for c in key.upper() if c.isalpha())
        return key.replace("J", "I")
    else:
        return "".join(c for c in key.upper() if c.isalnum())


def generate_matrix(key: str, size: int = 5) -> Tuple[Matrix, PositionMap]:
    """
    Generate Playfair matrix with variable size.
    
    Args:
        key: Encryption key
        size: Matrix size (5 for classic 5x5, 6 for extended 6x6)
    
    Returns:
        Tuple of (matrix, position_map)
    """
    key = preprocess_key(key, matrix_size=size)
    
    if size == 5:
        matrix_source = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    elif size == 6:
        matrix_source = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    else:
        raise ValueError("Only size 5 or 6 is supported")

    used_chars: List[str] = []
    for c in key:
        if c in matrix_source and c not in used_chars:
            used_chars.append(c)

    for c in matrix_source:
        if c not in used_chars:
            used_chars.append(c)

    matrix: Matrix = [["" for _ in range(size)] for _ in range(size)]
    pos_map: PositionMap = {}

    idx = 0
    for row in range(size):
        for col in range(size):
            char = used_chars[idx]
            matrix[row][col] = char
            pos_map[char] = (row, col)
            idx += 1

    return matrix, pos_map


def find_position(char: str, pos_map: PositionMap) -> Tuple[int, int]:
    if char not in pos_map:
        raise ValueError(f"Character '{char}' not found in Playfair matrix.")
    return pos_map[char]


def playfair_encrypt(plaintext: str, matrix: Matrix, pos_map: PositionMap, pad_double_letters: bool = True, padding_char: str = 'X') -> Tuple[str, List[Dict], str, str]:
    """
    Encrypt plaintext using Playfair cipher with step tracking.
    Preserves all invalid characters (spaces, punctuation, etc.) in the original text.
    
    Args:
        plaintext: Text to encrypt
        matrix: Playfair matrix
        pos_map: Position map of characters in matrix
        pad_double_letters: If True, insert padding between duplicate letters
        padding_char: Character to use for padding
    
    Returns:
        Tuple of (ciphertext, steps, preprocessed_text, ciphertext_with_invalid) where:
        - ciphertext: encrypted text without invalid characters
        - steps: list of encryption details
        - preprocessed_text: text after preprocessing
        - ciphertext_with_invalid: encrypted text with original invalid characters
    """
    size = len(matrix)
    
    # Lưu lại các vị trí và ký tự không hợp lệ trong text gốc
    invalid_positions = []
    for i, char in enumerate(plaintext):
        is_valid = (size == 5 and char.isalpha()) or (size == 6 and char.isalnum())
        if not is_valid:
            invalid_positions.append((i, char))
    
    # Extract và preprocess text
    text_valid_only, _ = extract_invalid_chars(plaintext, matrix_size=size)
    preprocessed = preprocess_text(text_valid_only, matrix_size=size, pad_double_letters=pad_double_letters, padding_char=padding_char)
    
    if not preprocessed:
        return "", [], "", ""
    
    ciphertext_chars: List[str] = []
    steps: List[Dict] = []
    
    for i in range(0, len(preprocessed), 2):
        a = preprocessed[i]
        b = preprocessed[i + 1] if i + 1 < len(preprocessed) else "X"
        
        # Skip if character not in matrix
        try:
            row1, col1 = find_position(a, pos_map)
            row2, col2 = find_position(b, pos_map)
        except ValueError:
            continue
        
        step_info = {
            "pair": f"{a}{b}",
            "positions": f"({row1},{col1}) ({row2},{col2})",
            "rule": "",
            "result": ""
        }

        if col1 == col2:
            c1 = matrix[(row1 + 1) % size][col1]
            c2 = matrix[(row2 + 1) % size][col2]
            step_info["rule"] = "Cùng cột → đi xuống"
        elif row1 == row2:
            c1 = matrix[row1][(col1 + 1) % size]
            c2 = matrix[row2][(col2 + 1) % size]
            step_info["rule"] = "Cùng hàng → sang phải"
        else:
            c1 = matrix[row1][col2]
            c2 = matrix[row2][col1]
            step_info["rule"] = "Hình chữ nhật → góc đối"
        
        step_info["result"] = f"{c1}{c2}"
        steps.append(step_info)
        
        ciphertext_chars.append(c1)
        ciphertext_chars.append(c2)

    ciphertext = "".join(ciphertext_chars)
    
    # Restore invalid chars vào đúng vị trí gốc
    # Chỉ lấy số ký tự hợp lệ bằng với số ký tự hợp lệ trong plaintext
    result = []
    cipher_idx = 0
    valid_count_in_plaintext = sum(1 for c in plaintext if (size == 5 and c.isalpha()) or (size == 6 and c.isalnum()))
    
    for i, char in enumerate(plaintext):
        is_valid = (size == 5 and char.isalpha()) or (size == 6 and char.isalnum())
        if is_valid and cipher_idx < valid_count_in_plaintext:
            result.append(ciphertext[cipher_idx])
            cipher_idx += 1
        else:
            result.append(char)
    
    ciphertext_with_invalid = ''.join(result)
    
    return ciphertext, steps, preprocessed, ciphertext_with_invalid


def postprocess_decrypted(text: str, padding_char: str = 'X') -> str:
    """
    Remove padding characters from decrypted text.
    
    Args:
        text: Decrypted text
        padding_char: Padding character to remove
    
    Returns:
        Text with padding removed
    """
    result: List[str] = []
    for i, char in enumerate(text):
        # Xóa padding giữa các chữ giống nhau
        if i > 0 and i + 1 < len(text) and char == padding_char and text[i - 1] == text[i + 1]:
            continue
        result.append(char)

    # Xóa padding ở cuối nếu có
    if result and result[-1] == padding_char:
        result.pop()

    return "".join(result)


def playfair_decrypt(ciphertext: str, matrix: Matrix, pos_map: PositionMap, padding_char: str = 'X') -> Tuple[str, List[Dict], str]:
    """
    Decrypt ciphertext using Playfair cipher with step tracking.
    Only processes valid characters in the matrix.
    Preserves all invalid characters in the original ciphertext.
    
    Args:
        ciphertext: Text to decrypt
        matrix: Playfair matrix
        pos_map: Position map of characters in matrix
        padding_char: Padding character used in encryption
    
    Returns:
        Tuple of (plaintext, steps, plaintext_with_invalid) where:
        - plaintext: decrypted text without invalid characters
        - steps: list of decryption details
        - plaintext_with_invalid: decrypted text with original invalid characters
    """
    size = len(matrix)
    
    # Extract invalid characters
    text_valid_only, _ = extract_invalid_chars(ciphertext, matrix_size=size)
    
    # Clean ciphertext - only keep valid characters in matrix
    valid_chars = "".join(c for c in text_valid_only.upper() if c in pos_map)
    
    if not valid_chars:
        return "", [], ""
    
    plaintext_chars: List[str] = []
    steps: List[Dict] = []
    
    for i in range(0, len(valid_chars), 2):
        a = valid_chars[i]
        b = valid_chars[i + 1] if i + 1 < len(valid_chars) else "X"
        
        # Skip if character not in matrix
        try:
            row1, col1 = find_position(a, pos_map)
            row2, col2 = find_position(b, pos_map)
        except ValueError:
            continue
        
        step_info = {
            "pair": f"{a}{b}",
            "positions": f"({row1},{col1}) ({row2},{col2})",
            "rule": "",
            "result": ""
        }

        if col1 == col2:
            p1 = matrix[(row1 - 1) % size][col1]
            p2 = matrix[(row2 - 1) % size][col2]
            step_info["rule"] = "Cùng cột → đi lên"
        elif row1 == row2:
            p1 = matrix[row1][(col1 - 1) % size]
            p2 = matrix[row2][(col2 - 1) % size]
            step_info["rule"] = "Cùng hàng → sang trái"
        else:
            p1 = matrix[row1][col2]
            p2 = matrix[row2][col1]
            step_info["rule"] = "Hình chữ nhật → góc đối"
        
        step_info["result"] = f"{p1}{p2}"
        steps.append(step_info)
        
        plaintext_chars.append(p1)
        plaintext_chars.append(p2)

    plaintext = postprocess_decrypted("".join(plaintext_chars), padding_char=padding_char)
    
    # Restore invalid chars vào đúng vị trí gốc
    result = list(ciphertext)
    plain_idx = 0
    
    for i in range(len(result)):
        is_valid = (size == 5 and result[i].isalpha()) or (size == 6 and result[i].isalnum())
        if is_valid and plain_idx < len(plaintext):
            result[i] = plaintext[plain_idx]
            plain_idx += 1
    
    plaintext_with_invalid = ''.join(result)
    
    return plaintext, steps, plaintext_with_invalid


def format_output(text: str, format_type: str = 'none') -> str:
    """
    Format encrypted/decrypted output text.
    
    Args:
        text: Text to format
        format_type: 'none', 'groups_of_5', or 'groups_of_2'
    
    Returns:
        Formatted text
    """
    # Remove existing spaces for reformatting
    text_no_spaces = text.replace(' ', '')
    
    if format_type == 'groups_of_5':
        return ' '.join(text_no_spaces[i:i+5] for i in range(0, len(text_no_spaces), 5))
    elif format_type == 'groups_of_2':
        return ' '.join(text_no_spaces[i:i+2] for i in range(0, len(text_no_spaces), 2))
    else:
        return text