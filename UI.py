import streamlit as st
from datetime import datetime
from typing import List, Dict
from playfair import generate_matrix, playfair_encrypt, playfair_decrypt
from rsa import (
    generate_rsa_keys, 
    rsa_encrypt, 
    rsa_decrypt, 
    is_prime,
    display_rsa_keys as show_rsa_keys
)


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
    st.set_page_config(page_title="Mã hóa Playfair & RSA", page_icon="🔐", layout="wide")
    
    st.title("Chương trình Mã hóa/Giải mã")
    st.markdown("---")
    
    # Initialize session state for history
    if 'history' not in st.session_state:
        st.session_state.history = []
    if 'rsa_keys' not in st.session_state:
        st.session_state.rsa_keys = None
    
    # Sidebar for cipher selection
    cipher_type = st.sidebar.selectbox(
        "Chọn thuật toán",
        ["Playfair Cipher", "RSA Cipher"]
    )
    
    if cipher_type == "Playfair Cipher":
        st.header("Playfair Cipher")
        
        # Configuration section
        with st.sidebar:
            st.subheader("Cấu hình")
            matrix_size = st.radio("Kích thước ma trận:", [5, 6], 
                                   help="5×5: Chỉ chữ cái (A-Z, J→I)\n6×6: Chữ cái + số (A-Z, 0-9)")
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
                                ciphertext, steps, preprocessed, ciphertext_with_spaces = playfair_encrypt(plaintext, matrix, pos_map)
                                
                                if not ciphertext:
                                    st.warning("Không có ký tự hợp lệ để mã hóa!")
                                    return
                                
                                st.success("Mã hóa thành công!")
                                
                                if preprocessed != plaintext.upper().replace(" ", ""):
                                    st.info(f"**Văn bản sau xử lý:** {preprocessed}")
                                
                                st.subheader("Kết quả:")
                                result_col1, result_col2 = st.columns([4, 1])
                                with result_col1:
                                    st.code(ciphertext_with_spaces, language=None)
                                with result_col2:
                                    st.download_button(
                                        "Lưu",
                                        ciphertext_with_spaces,
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
                                plaintext, steps, plaintext_with_spaces = playfair_decrypt(ciphertext, matrix, pos_map)
                                
                                if not plaintext:
                                    st.warning("Không có ký tự hợp lệ để giải mã!")
                                    return
                                
                                st.success("Giải mã thành công!")
                                
                                st.subheader("Kết quả:")
                                result_col1, result_col2 = st.columns([4, 1])
                                with result_col1:
                                    st.code(plaintext_with_spaces, language=None)
                                with result_col2:
                                    st.download_button(
                                        "Lưu",
                                        plaintext_with_spaces,
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
    
    elif cipher_type == "RSA Cipher":
        st.header("RSA Cipher")
        
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
