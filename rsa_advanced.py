"""
Advanced RSA implementation using the professional rsa library.
Supports: Key generation, encryption/decryption, digital signatures, hybrid encryption.
"""

from __future__ import annotations
import sys
import os

# Add rsa folder to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'rsa'))

from typing import Tuple, Optional
import streamlit as st
from datetime import datetime

# Import from the professional rsa library
from rsa import (
    generate_keypair,
    text_to_bytes,
    bytes_to_text,
    encrypt_hybrid,
    decrypt_hybrid,
    sign_bytes,
    verify_bytes,
    b64e,
    b64d,
)
from rsa.models import KeyPair, PublicKey, PrivateKey


def display_keypair_info(keypair: KeyPair) -> None:
    """Display RSA keypair information."""
    st.subheader("Chi tiết khóa RSA")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Khóa công khai (Public Key):**")
        st.info(f"**e** (exponent): {keypair.public.e}")
        st.info(f"**n** (modulus): {keypair.public.n}")
        
        # Calculate bit length
        bit_length = keypair.public.n.bit_length()
        st.caption(f"🔒 Độ dài khóa: {bit_length} bits")
    
    with col2:
        st.markdown("**Khóa riêng (Private Key):**")
        st.error(f"**d** (private exponent): {keypair.private.d}")
        st.error(f"**n** (modulus): {keypair.private.n}")
        
        st.caption("⚠️ BẢO MẬT - Không chia sẻ khóa riêng!")


def display_encryption_steps(envelope: dict) -> None:
    """Display encryption envelope details."""
    with st.expander("Chi tiết mã hóa (Hybrid RSA-AES)"):
        st.markdown("### Quy trình mã hóa:")
        st.markdown("""
        1. **Tạo khóa AES ngẫu nhiên** - Khóa đối xứng 256-bit
        2. **Mã hóa dữ liệu với AES** - Nhanh và hiệu quả cho dữ liệu lớn
        3. **Mã hóa khóa AES với RSA** - Bảo vệ khóa AES bằng khóa công khai RSA
        4. **Gói envelope** - Kết hợp ciphertext + encrypted key
        """)
        
        st.markdown("### Thông tin envelope:")
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric("AES Ciphertext (bytes)", len(envelope.get('ciphertext', b'')))
            st.metric("Encrypted AES Key (bytes)", len(envelope.get('encrypted_key', b'')))
        
        with col2:
            st.metric("Algorithm", "RSA-AES Hybrid")
            st.metric("Security", "High (OAEP padding)")


def encrypt_text(plaintext: str, keypair: KeyPair) -> Tuple[str, dict]:
    """
    Encrypt text using hybrid RSA-AES encryption.
    
    Returns:
        Tuple of (base64_envelope, envelope_dict)
    """
    # Convert text to bytes
    data = text_to_bytes(plaintext)
    
    # Encrypt using hybrid mode (RSA + AES)
    envelope = encrypt_hybrid(data, keypair.public)
    
    # Convert envelope to base64 for display
    envelope_b64 = {
        'ciphertext': b64e(envelope['ciphertext']),
        'encrypted_key': b64e(envelope['encrypted_key'])
    }
    
    # Create compact display format
    import json
    envelope_str = json.dumps(envelope_b64, indent=2)
    
    return envelope_str, envelope


def decrypt_text(envelope_str: str, keypair: KeyPair) -> str:
    """
    Decrypt text using hybrid RSA-AES decryption.
    
    Args:
        envelope_str: JSON string containing base64-encoded envelope
        keypair: KeyPair with private key for decryption
    
    Returns:
        Decrypted plaintext
    """
    import json
    
    # Parse envelope
    envelope_b64 = json.loads(envelope_str)
    
    # Decode from base64
    envelope = {
        'ciphertext': b64d(envelope_b64['ciphertext']),
        'encrypted_key': b64d(envelope_b64['encrypted_key'])
    }
    
    # Decrypt using hybrid mode
    decrypted_data = decrypt_hybrid(envelope, keypair.private)
    
    # Convert bytes to text
    return bytes_to_text(decrypted_data)


def sign_text(message: str, keypair: KeyPair) -> str:
    """
    Create digital signature for message.
    
    Returns:
        Base64-encoded signature
    """
    data = text_to_bytes(message)
    signature = sign_bytes(data, keypair.private)
    return b64e(signature)


def verify_signature(message: str, signature_b64: str, public_key: PublicKey) -> bool:
    """
    Verify digital signature.
    
    Returns:
        True if signature is valid, False otherwise
    """
    data = text_to_bytes(message)
    signature = b64d(signature_b64)
    return verify_bytes(data, signature, public_key)


# ==================== STREAMLIT UI ====================
def main() -> None:
    st.set_page_config(page_title="RSA Advanced", page_icon="🔐", layout="wide")
    
    st.title("Mã hóa RSA Nâng cao")
    st.markdown("Implementation chuyên nghiệp với Hybrid Encryption (RSA + AES)")
    st.markdown("---")
    
    # Initialize session state
    if 'rsa_keypair' not in st.session_state:
        st.session_state.rsa_keypair = None
    if 'rsa_history' not in st.session_state:
        st.session_state.rsa_history = []
    
    # Sidebar configuration
    with st.sidebar:
        st.subheader("⚙️ Cấu hình")
        
        st.markdown("**Độ dài khóa:**")
        key_bits = st.selectbox(
            "Bits",
            [512, 1024, 2048, 4096],
            index=1,
            help="Độ dài khóa càng lớn càng an toàn nhưng chậm hơn"
        )
        
        st.markdown("---")
        st.markdown("**Tùy chọn hiển thị:**")
        show_details = st.checkbox("Hiển thị chi tiết kỹ thuật", value=True)
        
        st.markdown("---")
        st.subheader("📊 Thống kê")
        st.metric("Lịch sử", len(st.session_state.rsa_history))
        
        if st.button("🗑️ Xóa lịch sử"):
            st.session_state.rsa_history = []
            st.success("Đã xóa!")
    
    # Main content with tabs
    tab1, tab2, tab3, tab4 = st.tabs([
        "🔑 Tạo khóa", 
        "🔒 Mã hóa/Giải mã", 
        "✍️ Chữ ký số",
        "📜 Lịch sử"
    ])
    
    with tab1:
        st.header("Tạo cặp khóa RSA")
        
        st.info(f"💡 Khóa sẽ được tạo với độ dài **{key_bits} bits**")
        
        col1, col2, col3 = st.columns([2, 1, 1])
        
        with col1:
            if st.button("🎲 Tạo khóa RSA", type="primary", use_container_width=True):
                with st.spinner(f"Đang tạo khóa {key_bits} bits..."):
                    try:
                        # Generate keypair using professional library
                        keypair = generate_keypair(bits=key_bits)
                        st.session_state.rsa_keypair = keypair
                        
                        st.success(f"✅ Tạo khóa thành công! ({key_bits} bits)")
                        
                        if show_details:
                            display_keypair_info(keypair)
                        
                    except Exception as e:
                        st.error(f"❌ Lỗi: {e}")
        
        # Display current keypair if exists
        if st.session_state.rsa_keypair:
            st.markdown("---")
            st.subheader("Khóa hiện tại")
            
            keypair = st.session_state.rsa_keypair
            bit_length = keypair.public.n.bit_length()
            
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**🔓 Khóa công khai:**")
                with st.expander("Xem chi tiết"):
                    st.code(f"e = {keypair.public.e}\nn = {keypair.public.n}", language="python")
                st.caption(f"Độ dài: {bit_length} bits")
            
            with col2:
                st.markdown("**🔐 Khóa riêng:**")
                with st.expander("Xem chi tiết (BẢO MẬT)"):
                    st.code(f"d = {keypair.private.d}\nn = {keypair.private.n}", language="python")
                st.caption("⚠️ KHÔNG chia sẻ!")
    
    with tab2:
        st.header("Mã hóa & Giải mã")
        
        if not st.session_state.rsa_keypair:
            st.warning("⚠️ Vui lòng tạo khóa RSA trước ở tab 'Tạo khóa'!")
        else:
            operation = st.radio("Chọn thao tác:", ["🔒 Mã hóa", "🔓 Giải mã"], horizontal=True)
            
            if operation == "🔒 Mã hóa":
                st.markdown("### Mã hóa văn bản")
                plaintext = st.text_area(
                    "Nhập văn bản cần mã hóa:",
                    height=150,
                    placeholder="Nhập văn bản của bạn...\n\nHỗ trợ Unicode và văn bản dài."
                )
                
                if st.button("🔒 Mã hóa", type="primary"):
                    if not plaintext:
                        st.warning("⚠️ Vui lòng nhập văn bản!")
                    else:
                        try:
                            keypair = st.session_state.rsa_keypair
                            
                            with st.spinner("Đang mã hóa..."):
                                envelope_str, envelope = encrypt_text(plaintext, keypair)
                            
                            st.success("✅ Mã hóa thành công!")
                            
                            st.subheader("📦 Envelope (Dữ liệu mã hóa):")
                            
                            col1, col2 = st.columns([4, 1])
                            with col1:
                                st.code(envelope_str, language="json")
                            with col2:
                                st.download_button(
                                    "💾 Lưu",
                                    envelope_str,
                                    file_name=f"encrypted_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                                    mime="application/json"
                                )
                            
                            if show_details:
                                display_encryption_steps(envelope)
                            
                            # Add to history
                            st.session_state.rsa_history.append({
                                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "type": "Mã hóa",
                                "input": plaintext[:50] + "..." if len(plaintext) > 50 else plaintext,
                                "output": "Envelope (JSON)",
                                "details": f"Hybrid RSA-AES ({keypair.public.n.bit_length()} bits)"
                            })
                            
                        except Exception as e:
                            st.error(f"❌ Lỗi: {e}")
            
            else:  # Giải mã
                st.markdown("### Giải mã văn bản")
                envelope_input = st.text_area(
                    "Nhập envelope JSON cần giải mã:",
                    height=150,
                    placeholder='{\n  "ciphertext": "...",\n  "encrypted_key": "..."\n}'
                )
                
                if st.button("🔓 Giải mã", type="primary"):
                    if not envelope_input:
                        st.warning("⚠️ Vui lòng nhập envelope!")
                    else:
                        try:
                            keypair = st.session_state.rsa_keypair
                            
                            with st.spinner("Đang giải mã..."):
                                plaintext = decrypt_text(envelope_input, keypair)
                            
                            st.success("✅ Giải mã thành công!")
                            
                            st.subheader("📄 Văn bản gốc:")
                            
                            col1, col2 = st.columns([4, 1])
                            with col1:
                                st.code(plaintext, language=None)
                            with col2:
                                st.download_button(
                                    "💾 Lưu",
                                    plaintext,
                                    file_name=f"decrypted_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                                    mime="text/plain"
                                )
                            
                            # Add to history
                            st.session_state.rsa_history.append({
                                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "type": "Giải mã",
                                "input": "Envelope (JSON)",
                                "output": plaintext[:50] + "..." if len(plaintext) > 50 else plaintext,
                                "details": f"Hybrid RSA-AES ({keypair.public.n.bit_length()} bits)"
                            })
                            
                        except Exception as e:
                            st.error(f"❌ Lỗi giải mã: {e}")
    
    with tab3:
        st.header("Chữ ký số (Digital Signature)")
        
        if not st.session_state.rsa_keypair:
            st.warning("⚠️ Vui lòng tạo khóa RSA trước ở tab 'Tạo khóa'!")
        else:
            sign_mode = st.radio("Chọn chức năng:", ["✍️ Ký văn bản", "✅ Xác thực chữ ký"], horizontal=True)
            
            if sign_mode == "✍️ Ký văn bản":
                st.markdown("### Tạo chữ ký số")
                
                message = st.text_area(
                    "Nhập văn bản cần ký:",
                    height=150,
                    placeholder="Nhập văn bản cần xác thực..."
                )
                
                if st.button("✍️ Ký", type="primary"):
                    if not message:
                        st.warning("⚠️ Vui lòng nhập văn bản!")
                    else:
                        try:
                            keypair = st.session_state.rsa_keypair
                            
                            with st.spinner("Đang tạo chữ ký..."):
                                signature = sign_text(message, keypair)
                            
                            st.success("✅ Đã tạo chữ ký số!")
                            
                            st.subheader("🖊️ Chữ ký (Base64):")
                            
                            col1, col2 = st.columns([4, 1])
                            with col1:
                                st.code(signature, language=None)
                            with col2:
                                st.download_button(
                                    "💾 Lưu",
                                    signature,
                                    file_name=f"signature_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sig",
                                    mime="text/plain"
                                )
                            
                            if show_details:
                                with st.expander("Chi tiết chữ ký số"):
                                    st.markdown("""
                                    ### Quy trình tạo chữ ký:
                                    1. **Hash văn bản** - Tạo digest từ message
                                    2. **Mã hóa hash với khóa riêng** - Tạo chữ ký
                                    3. **Encode Base64** - Dễ chia sẻ và lưu trữ
                                    """)
                                    st.caption(f"Độ dài chữ ký: {len(signature)} ký tự (Base64)")
                            
                            # Add to history
                            st.session_state.rsa_history.append({
                                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "type": "Ký",
                                "input": message[:50] + "..." if len(message) > 50 else message,
                                "output": "Signature (Base64)",
                                "details": f"RSA Digital Signature ({keypair.public.n.bit_length()} bits)"
                            })
                            
                        except Exception as e:
                            st.error(f"❌ Lỗi: {e}")
            
            else:  # Xác thực
                st.markdown("### Xác thực chữ ký số")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    message = st.text_area(
                        "Văn bản gốc:",
                        height=150,
                        placeholder="Nhập văn bản gốc..."
                    )
                
                with col2:
                    signature = st.text_area(
                        "Chữ ký (Base64):",
                        height=150,
                        placeholder="Nhập chữ ký cần xác thực..."
                    )
                
                if st.button("✅ Xác thực", type="primary"):
                    if not message or not signature:
                        st.warning("⚠️ Vui lòng nhập cả văn bản và chữ ký!")
                    else:
                        try:
                            keypair = st.session_state.rsa_keypair
                            
                            with st.spinner("Đang xác thực..."):
                                is_valid = verify_signature(message, signature, keypair.public)
                            
                            if is_valid:
                                st.success("✅ CHỮ KÝ HỢP LỆ - Văn bản xác thực thành công!")
                                st.balloons()
                            else:
                                st.error("❌ CHỮ KÝ KHÔNG HỢP LỆ - Văn bản có thể đã bị thay đổi!")
                            
                            # Add to history
                            st.session_state.rsa_history.append({
                                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "type": "Xác thực",
                                "input": message[:50] + "..." if len(message) > 50 else message,
                                "output": "✅ Hợp lệ" if is_valid else "❌ Không hợp lệ",
                                "details": f"RSA Signature Verification ({keypair.public.n.bit_length()} bits)"
                            })
                            
                        except Exception as e:
                            st.error(f"❌ Lỗi xác thực: {e}")
    
    with tab4:
        st.subheader("📜 Lịch sử thao tác")
        
        if st.session_state.rsa_history:
            for idx, record in enumerate(reversed(st.session_state.rsa_history), 1):
                with st.container():
                    col1, col2, col3 = st.columns([1, 3, 1])
                    
                    with col1:
                        # Icon based on type
                        icon = {
                            "Mã hóa": "🔒",
                            "Giải mã": "🔓",
                            "Ký": "✍️",
                            "Xác thực": "✅"
                        }.get(record['type'], "📄")
                        st.markdown(f"**{icon} {record['type']}**")
                    
                    with col2:
                        st.markdown(f"*{record['time']}*")
                        st.caption(record['details'])
                    
                    with col3:
                        st.caption(f"#{len(st.session_state.rsa_history) - idx + 1}")
                    
                    st.text(f"Input:  {record['input']}")
                    st.text(f"Output: {record['output']}")
                    st.divider()
        else:
            st.info("📭 Chưa có lịch sử nào. Hãy thử các chức năng mã hóa, giải mã hoặc chữ ký số!")


if __name__ == "__main__":
    main()
