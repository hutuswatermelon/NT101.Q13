from __future__ import annotations

from typing import Tuple, List, Optional
import streamlit as st
from datetime import datetime
import math


def gcd(a: int, b: int) -> int:
    """
    Calculate Greatest Common Divisor using Euclidean algorithm.
    
    Args:
        a: First number
        b: Second number
    
    Returns:
        GCD of a and b
    """
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Extended Euclidean Algorithm.
    
    Args:
        a: First number
        b: Second number
    
    Returns:
        Tuple of (gcd, x, y) where ax + by = gcd
    """
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y


def mod_inverse(e: int, phi: int) -> int:
    """
    Calculate modular multiplicative inverse.
    
    Args:
        e: Number to find inverse of
        phi: Modulus
    
    Returns:
        Modular inverse of e mod phi
    """
    gcd_val, x, _ = extended_gcd(e, phi)
    if gcd_val != 1:
        raise ValueError("Modular inverse does not exist")
    return (x % phi + phi) % phi


def is_prime(n: int) -> bool:
    """
    Check if a number is prime.
    
    Args:
        n: Number to check
    
    Returns:
        True if n is prime, False otherwise
    """
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    
    for i in range(3, int(math.sqrt(n)) + 1, 2):
        if n % i == 0:
            return False
    return True


def generate_rsa_keys(p: int, q: int, e: Optional[int] = None) -> Tuple[Tuple[int, int], Tuple[int, int], dict]:
    """
    Generate RSA public and private keys.
    
    Args:
        p: First prime number
        q: Second prime number
        e: Public exponent (optional, will use 65537 if not provided)
    
    Returns:
        Tuple of (public_key, private_key, details) where:
        - public_key: (e, n)
        - private_key: (d, n)
        - details: dictionary with calculation steps
    """
    # Validate inputs
    if not is_prime(p):
        raise ValueError(f"{p} không phải số nguyên tố!")
    if not is_prime(q):
        raise ValueError(f"{q} không phải số nguyên tố!")
    if p == q:
        raise ValueError("p và q phải khác nhau!")
    
    # Calculate n
    n = p * q
    
    # Calculate phi(n)
    phi = (p - 1) * (q - 1)
    
    # Choose e if not provided
    if e is None:
        e = 65537  # Common choice for e
    
    # Validate e
    if e >= phi:
        e = 3  # Fallback to small e
    
    if gcd(e, phi) != 1:
        # Find a valid e
        for test_e in range(3, phi, 2):
            if gcd(test_e, phi) == 1:
                e = test_e
                break
    
    # Calculate d
    d = mod_inverse(e, phi)
    
    # Prepare details
    details = {
        "p": p,
        "q": q,
        "n": n,
        "phi": phi,
        "e": e,
        "d": d
    }
    
    return (e, n), (d, n), details


def rsa_encrypt(plaintext: str, public_key: Tuple[int, int]) -> Tuple[List[int], List[dict]]:
    """
    Encrypt plaintext using RSA public key.
    
    Args:
        plaintext: Message to encrypt
        public_key: (e, n) tuple
    
    Returns:
        Tuple of (ciphertext_list, steps) where:
        - ciphertext_list: List of encrypted integers
        - steps: List of encryption details for each character
    """
    e, n = public_key
    ciphertext = []
    steps = []
    
    for char in plaintext:
        # Convert character to ASCII
        m = ord(char)
        
        # Check if message is too large for key
        if m >= n:
            raise ValueError(f"Ký tự '{char}' (ASCII {m}) quá lớn cho khóa (n={n}). Cần số nguyên tố lớn hơn!")
        
        # Encrypt: c = m^e mod n
        c = pow(m, e, n)
        ciphertext.append(c)
        
        steps.append({
            "char": char,
            "ascii": m,
            "encrypted": c,
            "formula": f"{m}^{e} mod {n} = {c}"
        })
    
    return ciphertext, steps


def rsa_decrypt(ciphertext: List[int], private_key: Tuple[int, int]) -> Tuple[str, List[dict]]:
    """
    Decrypt ciphertext using RSA private key.
    
    Args:
        ciphertext: List of encrypted integers
        private_key: (d, n) tuple
    
    Returns:
        Tuple of (plaintext, steps) where:
        - plaintext: Decrypted message
        - steps: List of decryption details for each number
    """
    d, n = private_key
    plaintext_chars = []
    steps = []
    
    for c in ciphertext:
        # Decrypt: m = c^d mod n
        m = pow(c, d, n)
        
        # Convert ASCII back to character
        char = chr(m)
        plaintext_chars.append(char)
        
        steps.append({
            "encrypted": c,
            "ascii": m,
            "char": char,
            "formula": f"{c}^{d} mod {n} = {m}"
        })
    
    return "".join(plaintext_chars), steps


# ==================== STREAMLIT UI ====================
def display_rsa_keys(details: dict) -> None:
    """Display RSA key generation details."""
    st.subheader("Chi tiết tạo khóa RSA")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Các bước tính toán:**")
        st.write(f"1. p = {details['p']} (số nguyên tố)")
        st.write(f"2. q = {details['q']} (số nguyên tố)")
        st.write(f"3. n = p × q = {details['p']} × {details['q']} = **{details['n']}**")
        st.write(f"4. φ(n) = (p-1) × (q-1) = {details['p']-1} × {details['q']-1} = **{details['phi']}**")
    
    with col2:
        st.markdown("**Kết quả:**")
        st.success(f"**Khóa công khai:** (e={details['e']}, n={details['n']})")
        st.error(f"**Khóa riêng:** (d={details['d']}, n={details['n']})")
        st.info(f"Kiểm tra: (d × e) mod φ(n) = {(details['d'] * details['e']) % details['phi']}")


def display_steps(steps: List[dict], title: str) -> None:
    """Display encryption/decryption steps."""
    with st.expander(f"{title} ({len(steps)} bước)"):
        for idx, step in enumerate(steps, 1):
            if "char" in step:  # Encryption
                st.markdown(f"**Bước {idx}:** `'{step['char']}'` → ASCII {step['ascii']} → {step['encrypted']}")
                st.caption(step['formula'])
            else:  # Decryption
                st.markdown(f"**Bước {idx}:** {step['encrypted']} → ASCII {step['ascii']} → `'{step['char']}'`")
                st.caption(step['formula'])
            
            if idx < len(steps):
                st.divider()


def main() -> None:
    st.set_page_config(page_title="Mã hóa RSA", page_icon="🔐", layout="wide")
    
    st.title("Chương trình Mã hóa/Giải mã RSA")
    st.markdown("---")
    
    # Initialize session state
    if 'rsa_keys' not in st.session_state:
        st.session_state.rsa_keys = None
    if 'history' not in st.session_state:
        st.session_state.history = []
    
    # Sidebar configuration
    with st.sidebar:
        st.subheader("Cấu hình")
        show_steps = st.checkbox("Hiển thị từng bước", value=True)
        
        st.markdown("---")
        st.subheader("Thống kê")
        st.metric("Lịch sử", len(st.session_state.history))
        
        if st.button("Xóa lịch sử"):
            st.session_state.history = []
            st.success("Đã xóa!")
    
    # Main content with tabs
    tab1, tab2, tab3 = st.tabs(["Tạo khóa", "Mã hóa/Giải mã", "Lịch sử"])
    
    with tab1:
        st.header("Tạo khóa RSA")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            p = st.number_input("Số nguyên tố p:", min_value=2, value=61, step=1)
            if not is_prime(p):
                st.warning(f"⚠️ {p} không phải số nguyên tố!")
        
        with col2:
            q = st.number_input("Số nguyên tố q:", min_value=2, value=53, step=1)
            if not is_prime(q):
                st.warning(f"⚠️ {q} không phải số nguyên tố!")
        
        with col3:
            use_custom_e = st.checkbox("Tùy chỉnh e", value=False)
            if use_custom_e:
                e = st.number_input("Giá trị e:", min_value=3, value=17, step=2)
            else:
                e = None
        
        if st.button("Tạo khóa RSA", type="primary"):
            try:
                public_key, private_key, details = generate_rsa_keys(p, q, e)
                st.session_state.rsa_keys = {
                    'public': public_key,
                    'private': private_key,
                    'details': details
                }
                
                st.success("✅ Tạo khóa thành công!")
                display_rsa_keys(details)
                
            except ValueError as e:
                st.error(f"Lỗi: {e}")
        
        # Display current keys if they exist
        if st.session_state.rsa_keys:
            st.markdown("---")
            st.subheader("Khóa hiện tại")
            details = st.session_state.rsa_keys['details']
            
            col1, col2 = st.columns(2)
            with col1:
                st.info(f"**Khóa công khai:**\ne = {details['e']}\nn = {details['n']}")
            with col2:
                st.error(f"**Khóa riêng:**\nd = {details['d']}\nn = {details['n']}")
    
    with tab2:
        st.header("Mã hóa/Giải mã")
        
        if not st.session_state.rsa_keys:
            st.warning("⚠️ Vui lòng tạo khóa RSA trước ở tab 'Tạo khóa'!")
        else:
            operation = st.radio("Chọn thao tác:", ["Mã hóa", "Giải mã"])
            
            if operation == "Mã hóa":
                plaintext = st.text_area("Nhập văn bản cần mã hóa:", height=150,
                                        placeholder="Nhập văn bản của bạn...")
                
                if st.button("Mã hóa", type="primary"):
                    if not plaintext:
                        st.warning("Vui lòng nhập văn bản!")
                    else:
                        try:
                            public_key = st.session_state.rsa_keys['public']
                            ciphertext, steps = rsa_encrypt(plaintext, public_key)
                            
                            st.success("Mã hóa thành công!")
                            
                            st.subheader("Kết quả:")
                            ciphertext_str = " ".join(map(str, ciphertext))
                            
                            result_col1, result_col2 = st.columns([4, 1])
                            with result_col1:
                                st.code(ciphertext_str, language=None)
                            with result_col2:
                                st.download_button(
                                    "Lưu",
                                    ciphertext_str,
                                    file_name=f"rsa_encrypted_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                                    mime="text/plain"
                                )
                            
                            if show_steps:
                                display_steps(steps, "Chi tiết mã hóa")
                            
                            # Add to history
                            st.session_state.history.append({
                                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "type": "Mã hóa",
                                "input": plaintext[:50] + "..." if len(plaintext) > 50 else plaintext,
                                "output": ciphertext_str[:50] + "..." if len(ciphertext_str) > 50 else ciphertext_str
                            })
                            
                        except ValueError as e:
                            st.error(f"Lỗi: {e}")
            
            else:  # Giải mã
                ciphertext_input = st.text_area("Nhập văn bản cần giải mã (các số cách nhau bởi dấu cách):", 
                                               height=150,
                                               placeholder="Ví dụ: 123 456 789")
                
                if st.button("Giải mã", type="primary"):
                    if not ciphertext_input:
                        st.warning("Vui lòng nhập văn bản!")
                    else:
                        try:
                            # Parse ciphertext
                            ciphertext = [int(x) for x in ciphertext_input.split()]
                            
                            private_key = st.session_state.rsa_keys['private']
                            plaintext, steps = rsa_decrypt(ciphertext, private_key)
                            
                            st.success("Giải mã thành công!")
                            
                            st.subheader("Kết quả:")
                            result_col1, result_col2 = st.columns([4, 1])
                            with result_col1:
                                st.code(plaintext, language=None)
                            with result_col2:
                                st.download_button(
                                    "Lưu",
                                    plaintext,
                                    file_name=f"rsa_decrypted_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                                    mime="text/plain"
                                )
                            
                            if show_steps:
                                display_steps(steps, "Chi tiết giải mã")
                            
                            # Add to history
                            st.session_state.history.append({
                                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "type": "Giải mã",
                                "input": ciphertext_input[:50] + "..." if len(ciphertext_input) > 50 else ciphertext_input,
                                "output": plaintext[:50] + "..." if len(plaintext) > 50 else plaintext
                            })
                            
                        except ValueError as e:
                            st.error(f"Lỗi: {e}")
    
    with tab3:
        st.subheader("Lịch sử Mã hóa/Giải mã")
        
        if st.session_state.history:
            for idx, record in enumerate(reversed(st.session_state.history), 1):
                with st.container():
                    col1, col2, col3 = st.columns([1, 3, 1])
                    with col1:
                        st.markdown(f"**{record['type']}**")
                    with col2:
                        st.markdown(f"*{record['time']}*")
                    with col3:
                        st.caption(f"#{len(st.session_state.history) - idx + 1}")
                    
                    st.text(f"Input:  {record['input']}")
                    st.text(f"Output: {record['output']}")
                    st.divider()
        else:
            st.info("Chưa có lịch sử nào. Hãy thử mã hóa hoặc giải mã một văn bản!")
