from __future__ import annotations

from typing import Dict, List, Tuple, Optional


Matrix = List[List[str]]
PositionMap = Dict[str, Tuple[int, int]]


def extract_spaces(text: str) -> Tuple[str, List[int]]:
    """
    Extract text without spaces and record space positions.
    
    Args:
        text: Input text with spaces
    
    Returns:
        Tuple of (text_without_spaces, list_of_space_positions)
    """
    space_positions = []
    text_without_spaces = []
    
    for i, char in enumerate(text):
        if char == ' ':
            space_positions.append(i)
        else:
            text_without_spaces.append(char)
    
    return ''.join(text_without_spaces), space_positions


def restore_spaces(text: str, space_positions: List[int]) -> str:
    """
    Restore spaces to text at original positions.
    
    Args:
        text: Text without spaces
        space_positions: List of original space positions
    
    Returns:
        Text with spaces restored
    """
    if not space_positions:
        return text
    
    result = list(text)
    for pos in sorted(space_positions, reverse=True):
        if pos <= len(result):
            result.insert(pos, ' ')
    
    return ''.join(result)


def preprocess_text(text: str, matrix_size: int = 5) -> str:
    """
    Preprocess text for Playfair encryption.
    Filters valid characters, handles duplicates, and adds padding.
    
    Args:
        text: Input text to preprocess
        matrix_size: Size of matrix (5 or 6)
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
    i = 0
    while i < len(characters) - 1:
        if characters[i] == characters[i + 1]:
            characters.insert(i + 1, "X")
        i += 2

    if len(characters) % 2 != 0:
        characters.append("X")

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


def playfair_encrypt(plaintext: str, matrix: Matrix, pos_map: PositionMap) -> Tuple[str, List[Dict], str, str]:
    """
    Encrypt plaintext using Playfair cipher with step tracking.
    Preserves spaces in the original text.
    
    Returns:
        Tuple of (ciphertext, steps, preprocessed_text, ciphertext_with_spaces) where:
        - ciphertext: encrypted text without spaces
        - steps: list of encryption details
        - preprocessed_text: text after preprocessing
        - ciphertext_with_spaces: encrypted text with original spaces
    """
    size = len(matrix)
    
    # Extract spaces before processing
    text_no_spaces, space_positions = extract_spaces(plaintext)
    preprocessed = preprocess_text(text_no_spaces, matrix_size=size)
    
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
    ciphertext_with_spaces = restore_spaces(ciphertext, space_positions)
    
    return ciphertext, steps, preprocessed, ciphertext_with_spaces


def postprocess_decrypted(text: str) -> str:
    result: List[str] = []
    for i, char in enumerate(text):
        if i > 0 and i + 1 < len(text) and char == "X" and text[i - 1] == text[i + 1]:
            continue
        result.append(char)

    if result and result[-1] == "X":
        result.pop()

    return "".join(result)


def playfair_decrypt(ciphertext: str, matrix: Matrix, pos_map: PositionMap) -> Tuple[str, List[Dict], str]:
    """
    Decrypt ciphertext using Playfair cipher with step tracking.
    Only processes valid characters in the matrix.
    Preserves spaces in the original ciphertext.
    
    Returns:
        Tuple of (plaintext, steps, plaintext_with_spaces) where:
        - plaintext: decrypted text without spaces
        - steps: list of decryption details
        - plaintext_with_spaces: decrypted text with original spaces
    """
    size = len(matrix)
    
    # Extract spaces before processing
    text_no_spaces, space_positions = extract_spaces(ciphertext)
    
    # Clean ciphertext - only keep valid characters
    valid_chars = "".join(c for c in text_no_spaces.upper() if c in pos_map)
    
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

    plaintext = postprocess_decrypted("".join(plaintext_chars))
    plaintext_with_spaces = restore_spaces(plaintext, space_positions)
    
    return plaintext, steps, plaintext_with_spaces