import streamlit as st
from datetime import datetime
from typing import List, Dict
import sys
import os

# Add rsa folder to path for advanced RSA
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'rsa'))

from playfair import generate_matrix, playfair_encrypt, playfair_decrypt, format_output

# Import advanced RSA library
try:
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
    USE_ADVANCED_RSA = True
except ImportError:
    # Fallback to simple RSA
    from rsa import (
        generate_rsa_keys, 
        rsa_encrypt, 
        rsa_decrypt, 
        is_prime,
        display_rsa_keys as show_rsa_keys
    )
    USE_ADVANCED_RSA = False


Matrix = List[List[str]]


# ==================== STREAMLIT UI ====================
def display_playfair_matrix(matrix: Matrix) -> None:
    """Display Playfair matrix in a nice format."""
    st.subheader("Ma trận Playfair")
    
    # Create styled table
    size = len(matrix)
    matrix_html = "<div style='display: flex; justify-content: center;'>"
    matrix_html += "<table style='border-collapse: collapse; box-shadow: 0 2px 8px rgba(0,0,0,0.1);'>"
    
    for row in matrix:
        matrix_html += "<tr>"
        for cell in row:
            matrix_html += f"<td style='border: 2px solid #4CAF50; padding: 15px; text-align: center; font-weight: bold; font-size: 18px; min-width: 40px; min-height: 40px; background: transparent; color: black;'>{cell}</td>"
        matrix_html += "</tr>"
    matrix_html += "</table></div>"
    
    st.markdown(matrix_html, unsafe_allow_html=True)
    st.caption(f"Ma trận {size}×{size} - Tổng {size*size} ký tự")


def display_steps(steps: List[Dict], title: str) -> None:
    """Display encryption/decryption steps."""
    with st.expander(f"{title} ({len(steps)} bước)"):
        for idx, step in enumerate(steps, 1):
            col1, col2, col3, col4 = st.columns([1, 2, 2, 1])
            with col1:
                st.markdown(f"**Bước {idx}:**")
            with col2:
                st.markdown(f"`{step['pair']}`")
            with col3:
                st.markdown(f"*{step['rule']}*")
            with col4:
                st.markdown(f"→ `{step['result']}`")
            
            if idx < len(steps):
                st.divider()


def main() -> None:
    st.set_page_config(page_title="Mã hóa Playfair & RSA", layout="wide")
    
    st.title("Chương trình Mã hóa/Giải mã")
    st.markdown("---")
    
    # Initialize session state for history
    if 'history' not in st.session_state:
        st.session_state.history = []
    if 'rsa_keys' not in st.session_state:
        st.session_state.rsa_keys = None
    
    # Sidebar for cipher selection
    rsa_options = ["Playfair Cipher"]
    
    if USE_ADVANCED_RSA:
        rsa_options.append("RSA Cipher (Advanced)")
    else:
        rsa_options.append("RSA Cipher (Basic)")
    
    cipher_type = st.sidebar.selectbox(
        "Chọn thuật toán",
        rsa_options
    )
    
    if cipher_type == "Playfair Cipher":
        st.header("Playfair Cipher")
        
        # Configuration section
        with st.sidebar:
            st.subheader("Cấu hình")
            matrix_size = st.radio("Kích thước ma trận:", [5, 6], 
                                   help="5×5: Chỉ chữ cái (A-Z, J→I)\n6×6: Chữ cái + số (A-Z, 0-9)")
            
            st.markdown("**Tùy chọn mã hóa:**")
            pad_double_letters = st.checkbox("Pad double-letters", value=True,
                                            help="Thêm ký tự padding giữa các chữ giống nhau")
            
            padding_char = st.selectbox("Ký tự padding:", ['X', 'Q', 'Z'],
                                       help="Ký tự dùng để padding và giữa các chữ giống nhau")
            
            output_format = st.selectbox("Định dạng kết quả:", 
                                        ['none', 'groups_of_5', 'groups_of_2'],
                                        format_func=lambda x: {
                                            'none': 'Không định dạng',
                                            'groups_of_5': 'Nhóm 5 ký tự',
                                            'groups_of_2': 'Nhóm 2 ký tự (digraphs)'
                                        }[x],
                                        help="Cách hiển thị kết quả mã hóa")
            
            preserve_format = st.checkbox("Giữ khoảng trắng/ký tự gốc", value=True,
                                         help="Bỏ chọn để xuất text thuần (tương thích công cụ chuẩn)")
            
            st.markdown("**Hiển thị:**")
            show_steps = st.checkbox("Hiển thị từng bước", value=True)
            
            st.markdown("---")
            st.subheader("Thống kê")
            st.metric("Lịch sử", len(st.session_state.history))
            
            if st.button("Xóa lịch sử"):
                st.session_state.history = []
                st.success("Đã xóa!")
        
        # Main content with tabs
        tab1, tab2, tab3 = st.tabs(["Mã hóa/Giải mã", "Lịch sử", "Hướng dẫn"])
        
        with tab1:
            col1, col2 = st.columns([1, 1])
            
            with col1:
                key = st.text_input("Nhập khóa (Key):", value="KEYWORD", 
                                   help="Khóa được sử dụng để tạo ma trận")
                
                if key:
                    try:
                        matrix, pos_map = generate_matrix(key, size=matrix_size)
                        display_playfair_matrix(matrix)
                    except Exception as e:
                        st.error(f"Lỗi khi tạo ma trận: {e}")
            
            with col2:
                operation = st.radio("Chọn thao tác:", ["Mã hóa", "Giải mã"])
                
                if operation == "Mã hóa":
                    plaintext = st.text_area("Nhập văn bản cần mã hóa:", height=150,
                                            placeholder="Nhập văn bản của bạn tại đây...")
                    
                    col_btn1, col_btn2 = st.columns([3, 1])
                    with col_btn1:
                        encrypt_btn = st.button("Mã hóa", type="primary", use_container_width=True)
                    with col_btn2:
                        if plaintext and st.button("Xóa", use_container_width=True):
                            st.rerun()
                    
                    if encrypt_btn:
                        if not key:
                            st.warning("Vui lòng nhập khóa!")
                        elif not plaintext:
                            st.warning("Vui lòng nhập văn bản!")
                        else:
                            try:
                                matrix, pos_map = generate_matrix(key, size=matrix_size)
                                ciphertext, steps, preprocessed, ciphertext_with_spaces = playfair_encrypt(
                                    plaintext, matrix, pos_map, 
                                    pad_double_letters=pad_double_letters,
                                    padding_char=padding_char
                                )
                                
                                if not ciphertext:
                                    st.warning("Không có ký tự hợp lệ để mã hóa!")
                                    return
                                
                                st.success("Mã hóa thành công!")
                                
                                if preprocessed != plaintext.upper().replace(" ", ""):
                                    st.info(f"**Văn bản sau xử lý:** {preprocessed}")
                                
                                st.subheader("Kết quả:")
                                result_col1, result_col2 = st.columns([4, 1])
                                with result_col1:
                                    # Chọn output dựa trên preserve_format
                                    output_text = ciphertext_with_spaces if preserve_format else ciphertext
                                    formatted_output = format_output(output_text, output_format)
                                    st.code(formatted_output, language=None)
                                    
                                    # Hiển thị thông tin về format
                                    if preserve_format:
                                        st.caption("Giữ nguyên khoảng trắng và ký tự đặc biệt từ văn bản gốc")
                                    else:
                                        st.caption("Chỉ ký tự mã hóa (tương thích với công cụ Playfair chuẩn)")
                                
                                with result_col2:
                                    output_text = ciphertext_with_spaces if preserve_format else ciphertext
                                    st.download_button(
                                        "Lưu",
                                        format_output(output_text, output_format),
                                        file_name=f"encrypted_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                                        mime="text/plain"
                                    )
                                
                                # Show steps
                                if show_steps:
                                    display_steps(steps, "Chi tiết mã hóa")
                                
                                # Add to history
                                st.session_state.history.append({
                                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                    "type": "Mã hóa",
                                    "key": key,
                                    "input": plaintext[:50] + "..." if len(plaintext) > 50 else plaintext,
                                    "output": ciphertext_with_spaces[:50] + "..." if len(ciphertext_with_spaces) > 50 else ciphertext_with_spaces
                                })
                                
                            except Exception as e:
                                st.error(f"Lỗi: {e}")
                
                else:  # Giải mã
                    ciphertext = st.text_area("Nhập văn bản cần giải mã:", height=150,
                                             placeholder="Nhập văn bản đã mã hóa...")
                    
                    col_btn1, col_btn2 = st.columns([3, 1])
                    with col_btn1:
                        decrypt_btn = st.button("Giải mã", type="primary", use_container_width=True)
                    with col_btn2:
                        if ciphertext and st.button("Xóa", use_container_width=True):
                            st.rerun()
                    
                    if decrypt_btn:
                        if not key:
                            st.warning("Vui lòng nhập khóa!")
                        elif not ciphertext:
                            st.warning("Vui lòng nhập văn bản!")
                        else:
                            try:
                                matrix, pos_map = generate_matrix(key, size=matrix_size)
                                plaintext, steps, plaintext_with_spaces = playfair_decrypt(
                                    ciphertext, matrix, pos_map,
                                    padding_char=padding_char
                                )
                                
                                if not plaintext:
                                    st.warning("Không có ký tự hợp lệ để giải mã!")
                                    return
                                
                                st.success("Giải mã thành công!")
                                
                                st.subheader("Kết quả:")
                                result_col1, result_col2 = st.columns([4, 1])
                                with result_col1:
                                    # Chọn output dựa trên preserve_format
                                    output_text = plaintext_with_spaces if preserve_format else plaintext
                                    formatted_output = format_output(output_text, output_format)
                                    st.code(formatted_output, language=None)
                                    
                                    # Hiển thị thông tin về format
                                    if preserve_format:
                                        st.caption("Giữ nguyên khoảng trắng và ký tự đặc biệt từ văn bản gốc")
                                    else:
                                        st.caption("Chỉ text giải mã (không có ký tự đặc biệt)")
                                
                                with result_col2:
                                    output_text = plaintext_with_spaces if preserve_format else plaintext
                                    st.download_button(
                                        "Lưu",
                                        format_output(output_text, output_format),
                                        file_name=f"decrypted_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                                        mime="text/plain"
                                    )
                                
                                # Show steps
                                if show_steps:
                                    display_steps(steps, "Chi tiết giải mã")
                                
                                # Add to history
                                st.session_state.history.append({
                                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                    "type": "Giải mã",
                                    "key": key,
                                    "input": ciphertext[:50] + "..." if len(ciphertext) > 50 else ciphertext,
                                    "output": plaintext_with_spaces[:50] + "..." if len(plaintext_with_spaces) > 50 else plaintext_with_spaces
                                })
                                
                            except Exception as e:
                                st.error(f"Lỗi: {e}")
        
        with tab2:
            st.subheader("Lịch sử Mã hóa/Giải mã")
            
            if st.session_state.history:
                for idx, record in enumerate(reversed(st.session_state.history), 1):
                    with st.container():
                        col1, col2, col3 = st.columns([1, 3, 1])
                        with col1:
                            if record["type"] == "Mã hóa":
                                st.markdown("**Mã hóa**")
                            else:
                                st.markdown("**Giải mã**")
                        with col2:
                            st.markdown(f"*{record['time']}* | Key: `{record['key']}`")
                        with col3:
                            st.caption(f"#{len(st.session_state.history) - idx + 1}")
                        
                        st.text(f"Input:  {record['input']}")
                        st.text(f"Output: {record['output']}")
                        st.divider()
            else:
                st.info("Chưa có lịch sử nào. Hãy thử mã hóa hoặc giải mã một văn bản!")
        
        with tab3:
            st.subheader("Hướng dẫn sử dụng Playfair Cipher")
            
            st.markdown("""
            ### Giới thiệu
            **Playfair Cipher** là một kỹ thuật mã hóa thay thế digraph (2 ký tự) được phát minh bởi Charles Wheatstone vào năm 1854 
            và được Lord Playfair quảng bá.
            
            ### Cách hoạt động
            
            #### 1. Tạo Ma trận
            - **Ma trận 5×5**: Sử dụng 25 chữ cái (A-Z), trong đó J được gộp với I
            - **Ma trận 6×6**: Sử dụng 36 ký tự (A-Z + 0-9), hỗ trợ cả số
            
            #### 2. Xử lý Văn bản
            - Loại bỏ ký tự không phải chữ cái
            - Chuyển thành chữ HOA
            - Thay J → I (trong ma trận 5×5)
            - Chia thành các cặp ký tự
            - Thêm 'X' giữa các ký tự giống nhau và ở cuối nếu lẻ
            
            #### 3. Quy tắc Mã hóa
            Với mỗi cặp ký tự (a, b):
            
            1. **Cùng hàng**: Lấy ký tự bên phải (vòng tròn)
               ```
               Ví dụ: AB → BC (trong cùng hàng)
               ```
            
            2. **Cùng cột**: Lấy ký tự bên dưới (vòng tròn)
               ```
               Ví dụ: AK → PU (trong cùng cột)
               ```
            
            3. **Khác hàng và cột**: Tạo hình chữ nhật, lấy góc đối diện
               ```
               Ví dụ: AB → BC
                      KE → LM
               ```
            
            #### 4. Quy tắc Giải mã
            Ngược lại với mã hóa:
            - Cùng hàng: Lấy ký tự bên trái
            - Cùng cột: Lấy ký tự bên trên
            - Khác hàng/cột: Vẫn lấy góc đối diện
            
            ### Ưu điểm
            - An toàn hơn các cipher thay thế đơn giản
            - Mã hóa theo cặp ký tự (digraph)
            - Khó bị phá bằng phân tích tần suất
            
            ### Hạn chế
            - Vẫn có thể bị phá bằng các kỹ thuật phân tích hiện đại
            - Yêu cầu khóa được giữ bí mật
            - Không phù hợp cho mã hóa dữ liệu quan trọng ngày nay
            
            ### Mẹo sử dụng
            - Chọn khóa dài và khó đoán
            - Sử dụng tính năng "Hiển thị từng bước" để học cách hoạt động
            - Lưu kết quả bằng nút Download
            - Xem lại các lần mã hóa trong tab Lịch sử
            """)
            
            st.markdown("---")
            st.info("**Lưu ý**: Playfair Cipher chỉ nên dùng cho mục đích học tập. Đối với dữ liệu quan trọng, hãy sử dụng các thuật toán hiện đại như AES, RSA.")
    
    
    elif "RSA Cipher" in cipher_type:
        if USE_ADVANCED_RSA:
            st.header("RSA Cipher (Advanced)")
            st.caption("Hybrid Encryption (RSA + AES) with Digital Signatures")
            
            # Import advanced RSA UI from rsa_advanced.py
            import rsa_advanced
            # Call its main function directly (without duplicate UI setup)
            
            # Configuration section
            with st.sidebar:
                st.subheader("Cấu hình")
                
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
                st.subheader("Thống kê")
                st.metric("Lịch sử", len(st.session_state.history))
                
                if st.button("Xóa lịch sử"):
                    st.session_state.history = []
                    st.success("Đã xóa!")
            
            # Initialize session state for advanced RSA
            if 'rsa_keypair' not in st.session_state:
                st.session_state.rsa_keypair = None
            
            # Main content with tabs
            tab1, tab2, tab3, tab4 = st.tabs([
                "Tạo khóa", 
                "Mã hóa/Giải mã", 
                "Chữ ký số",
                "Lịch sử"
            ])
            
            with tab1:
                st.subheader("Tạo cặp khóa RSA")
                
                st.info(f"Khóa sẽ được tạo với độ dài **{key_bits} bits**")
                
                col1, col2, col3 = st.columns([2, 1, 1])
                
                with col1:
                    if st.button("Tạo khóa RSA", type="primary", use_container_width=True):
                        with st.spinner(f"Đang tạo khóa {key_bits} bits..."):
                            try:
                                # Generate keypair using professional library
                                keypair = generate_keypair(bits=key_bits)
                                st.session_state.rsa_keypair = keypair
                                
                                st.success(f"Tạo khóa thành công! ({key_bits} bits)")
                                
                                if show_details:
                                    st.subheader("Chi tiết khóa RSA")
                                    
                                    col1, col2 = st.columns(2)
                                    
                                    with col1:
                                        st.markdown("**Khóa công khai (Public Key):**")
                                        st.info(f"**e** (exponent): {keypair.public.e}")
                                        st.info(f"**n** (modulus): {keypair.public.n}")
                                        
                                        # Calculate bit length
                                        bit_length = keypair.public.n.bit_length()
                                        st.caption(f"Độ dài khóa: {bit_length} bits")
                                    
                                    with col2:
                                        st.markdown("**Khóa riêng (Private Key):**")
                                        st.error(f"**d** (private exponent): {keypair.private.d}")
                                        st.error(f"**n** (modulus): {keypair.private.n}")
                                        
                                        st.caption("⚠️ BẢO MẬT - Không chia sẻ khóa riêng!")
                                
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
                        st.markdown("**Khóa công khai:**")
                        with st.expander("Xem chi tiết"):
                            st.code(f"e = {keypair.public.e}\nn = {keypair.public.n}", language="python")
                        st.caption(f"Độ dài: {bit_length} bits")
                    
                    with col2:
                        st.markdown("**Khóa riêng:**")
                        with st.expander("Xem chi tiết (BẢO MẬT)"):
                            st.code(f"d = {keypair.private.d}\nn = {keypair.private.n}", language="python")
                        st.caption("⚠️ KHÔNG chia sẻ!")
            
            with tab2:
                st.subheader("Mã hóa & Giải mã")
                
                if not st.session_state.rsa_keypair:
                    st.warning("⚠️ Vui lòng tạo khóa RSA trước ở tab 'Tạo khóa'!")
                else:
                    operation = st.radio("Chọn thao tác:", ["Mã hóa", "Giải mã"], horizontal=True)
                    
                    if operation == "Mã hóa":
                        st.markdown("### Mã hóa văn bản")
                        plaintext = st.text_area(
                            "Nhập văn bản cần mã hóa:",
                            height=150,
                            placeholder="Nhập văn bản của bạn...\n\nHỗ trợ Unicode và văn bản dài."
                        )
                        
                        if st.button("Mã hóa", type="primary"):
                            if not plaintext:
                                st.warning("⚠️ Vui lòng nhập văn bản!")
                            else:
                                try:
                                    keypair = st.session_state.rsa_keypair
                                    
                                    with st.spinner("Đang mã hóa..."):
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
                                    
                                    st.success("Mã hóa thành công!")
                                    
                                    st.subheader("Envelope (Dữ liệu mã hóa):")
                                    
                                    col1, col2 = st.columns([4, 1])
                                    with col1:
                                        st.code(envelope_str, language="json")
                                    with col2:
                                        st.download_button(
                                            "Lưu",
                                            envelope_str,
                                            file_name=f"encrypted_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                                            mime="application/json"
                                        )
                                    
                                    if show_details:
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
                                    
                                    # Add to history
                                    st.session_state.history.append({
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
                        
                        if st.button("Giải mã", type="primary"):
                            if not envelope_input:
                                st.warning("⚠️ Vui lòng nhập envelope!")
                            else:
                                try:
                                    keypair = st.session_state.rsa_keypair
                                    
                                    with st.spinner("Đang giải mã..."):
                                        import json
                                        
                                        # Parse envelope
                                        envelope_b64 = json.loads(envelope_input)
                                        
                                        # Decode from base64
                                        envelope = {
                                            'ciphertext': b64d(envelope_b64['ciphertext']),
                                            'encrypted_key': b64d(envelope_b64['encrypted_key'])
                                        }
                                        
                                        # Decrypt using hybrid mode
                                        decrypted_data = decrypt_hybrid(envelope, keypair.private)
                                        
                                        # Convert bytes to text
                                        plaintext = bytes_to_text(decrypted_data)
                                    
                                    st.success("✅ Giải mã thành công!")
                                    
                                    st.subheader("Văn bản gốc:")
                                    
                                    col1, col2 = st.columns([4, 1])
                                    with col1:
                                        st.code(plaintext, language=None)
                                    with col2:
                                        st.download_button(
                                            "Lưu",
                                            plaintext,
                                            file_name=f"decrypted_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                                            mime="text/plain"
                                        )
                                    
                                    # Add to history
                                    st.session_state.history.append({
                                        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                        "type": "Giải mã",
                                        "input": "Envelope (JSON)",
                                        "output": plaintext[:50] + "..." if len(plaintext) > 50 else plaintext,
                                        "details": f"Hybrid RSA-AES ({keypair.public.n.bit_length()} bits)"
                                    })
                                    
                                except Exception as e:
                                    st.error(f"❌ Lỗi giải mã: {e}")
            
            with tab3:
                st.subheader("Chữ ký số (Digital Signature)")
                
                if not st.session_state.rsa_keypair:
                    st.warning("⚠️ Vui lòng tạo khóa RSA trước ở tab 'Tạo khóa'!")
                else:
                    sign_mode = st.radio("Chọn chức năng:", ["Ký văn bản", "Xác thực chữ ký"], horizontal=True)
                    
                    if sign_mode == "Ký văn bản":
                        st.markdown("### Tạo chữ ký số")
                        
                        message = st.text_area(
                            "Nhập văn bản cần ký:",
                            height=150,
                            placeholder="Nhập văn bản cần xác thực..."
                        )
                        
                        if st.button("Ký", type="primary"):
                            if not message:
                                st.warning("⚠️ Vui lòng nhập văn bản!")
                            else:
                                try:
                                    keypair = st.session_state.rsa_keypair
                                    
                                    with st.spinner("Đang tạo chữ ký..."):
                                        data = text_to_bytes(message)
                                        signature = sign_bytes(data, keypair.private)
                                        signature_b64 = b64e(signature)
                                    
                                    st.success("✅ Đã tạo chữ ký số!")
                                    
                                    st.subheader("Chữ ký (Base64):")
                                    
                                    col1, col2 = st.columns([4, 1])
                                    with col1:
                                        st.code(signature_b64, language=None)
                                    with col2:
                                        st.download_button(
                                            "Lưu",
                                            signature_b64,
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
                                            st.caption(f"Độ dài chữ ký: {len(signature_b64)} ký tự (Base64)")
                                    
                                    # Add to history
                                    st.session_state.history.append({
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
                            signature_input = st.text_area(
                                "Chữ ký (Base64):",
                                height=150,
                                placeholder="Nhập chữ ký cần xác thực..."
                            )
                        
                        if st.button("✅ Xác thực", type="primary"):
                            if not message or not signature_input:
                                st.warning("⚠️ Vui lòng nhập cả văn bản và chữ ký!")
                            else:
                                try:
                                    keypair = st.session_state.rsa_keypair
                                    
                                    with st.spinner("Đang xác thực..."):
                                        data = text_to_bytes(message)
                                        signature = b64d(signature_input)
                                        is_valid = verify_bytes(data, signature, keypair.public)
                                    
                                    if is_valid:
                                        st.success("✅ CHỮ KÝ HỢP LỆ - Văn bản xác thực thành công!")
                                        st.balloons()
                                    else:
                                        st.error("❌ CHỮ KÝ KHÔNG HỢP LỆ - Văn bản có thể đã bị thay đổi!")
                                    
                                    # Add to history
                                    st.session_state.history.append({
                                        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                        "type": "Xác thực",
                                        "input": message[:50] + "..." if len(message) > 50 else message,
                                        "output": "Hợp lệ" if is_valid else "❌ Không hợp lệ",
                                        "details": f"RSA Signature Verification ({keypair.public.n.bit_length()} bits)"
                                    })
                                    
                                except Exception as e:
                                    st.error(f"Lỗi xác thực: {e}")
            
            with tab4:
                st.subheader("Lịch sử thao tác")
                
                if st.session_state.history:
                    for idx, record in enumerate(reversed(st.session_state.history), 1):
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
                                if 'details' in record:
                                    st.caption(record['details'])
                            
                            with col3:
                                st.caption(f"#{len(st.session_state.history) - idx + 1}")
                            
                            st.text(f"Input:  {record['input']}")
                            st.text(f"Output: {record['output']}")
                            st.divider()
                else:
                    st.info("Chưa có lịch sử nào. Hãy thử các chức năng mã hóa, giải mã hoặc chữ ký số!")
        
        else:
            # Use basic RSA (fallback)
            st.header("RSA Cipher (Basic)")
        
            # Configuration section
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
                st.subheader("Tạo khóa RSA")
                
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    p = st.number_input("Số nguyên tố p:", min_value=2, value=61, step=1)
                    if not is_prime(p):
                        st.warning(f"{p} không phải số nguyên tố!")
                
                with col2:
                    q = st.number_input("Số nguyên tố q:", min_value=2, value=53, step=1)
                    if not is_prime(q):
                        st.warning(f"{q} không phải số nguyên tố!")
                
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
                        
                        st.success("Tạo khóa thành công!")
                        show_rsa_keys(details)
                        
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
                st.subheader("Mã hóa/Giải mã")
                
                if not st.session_state.rsa_keys:
                    st.warning("Vui lòng tạo khóa RSA trước ở tab 'Tạo khóa'!")
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
                                        display_rsa_steps(steps, "Chi tiết mã hóa")
                                    
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
                                        display_rsa_steps(steps, "Chi tiết giải mã")
                                    
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
                st.subheader("Lịch sử Mã hóa/Giải mã RSA")
                
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


def display_rsa_steps(steps: List[Dict], title: str) -> None:
    """Display RSA encryption/decryption steps."""
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


if __name__ == "__main__":
    main()