# Chương trình Mã hóa/Giải mã Playfair & RSA

Chương trình mã hóa và giải mã văn bản sử dụng thuật toán Playfair Cipher với giao diện Streamlit hiện đại.

## Tính năng

### Playfair Cipher
- ✅ Mã hóa/Giải mã văn bản
- ✅ Hỗ trợ ma trận 5×5 (chữ cái A-Z) và 6×6 (chữ cái + số 0-9)
- ✅ Hiển thị từng bước mã hóa/giải mã chi tiết
- ✅ Giữ nguyên khoảng trắng trong văn bản
- ✅ Lịch sử mã hóa/giải mã
- ✅ Xuất kết quả ra file
- ✅ Hướng dẫn sử dụng tích hợp

### RSA Cipher
- 🚧 Đang phát triển

## Yêu cầu hệ thống

- Python 3.8 trở lên
- pip (Python package manager)

## Cài đặt

### Bước 1: Clone hoặc tải dự án

```bash
# Clone repository (nếu có)
git clone <repository-url>
cd NT101.Q13

# Hoặc tải và giải nén file zip
```

### Bước 2: Tạo môi trường ảo (khuyến nghị)

**Windows:**
```bash
python -m venv .venv
.venv\Scripts\activate
```

**macOS/Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Bước 3: Cài đặt thư viện

```bash
pip install -r requirements.txt
```

Hoặc cài đặt trực tiếp:
```bash
pip install streamlit
```

## Chạy chương trình

### Khởi động ứng dụng Streamlit

```bash
streamlit run playfair.py
```

Chương trình sẽ tự động mở trình duyệt tại địa chỉ: `http://localhost:8501`

### Dừng chương trình

Nhấn `Ctrl + C` trong terminal để dừng server

## Hướng dẫn sử dụng

### Mã hóa văn bản

1. Chọn tab "Mã hóa/Giải mã"
2. Nhập khóa mã hóa (Key) vào ô bên trái
3. Chọn "Mã hóa" ở cột bên phải
4. Nhập văn bản cần mã hóa
5. Nhấn nút "Mã hóa"
6. Kết quả sẽ hiển thị bên dưới, có thể tải xuống

### Giải mã văn bản

1. Chọn tab "Mã hóa/Giải mã"
2. Nhập khóa mã hóa (Key) - phải giống với khóa đã dùng để mã hóa
3. Chọn "Giải mã" ở cột bên phải
4. Nhập văn bản đã mã hóa
5. Nhấn nút "Giải mã"
6. Kết quả sẽ hiển thị bên dưới

### Cấu hình

Trong sidebar, bạn có thể:
- Chọn kích thước ma trận (5×5 hoặc 6×6)
- Bật/tắt hiển thị từng bước
- Xem thống kê và xóa lịch sử

### Lịch sử

- Tab "Lịch sử" lưu tất cả các lần mã hóa/giải mã
- Hiển thị thời gian, loại thao tác, khóa và kết quả
- Có thể xóa lịch sử trong sidebar

## Cấu trúc thư mục

```
NT101.Q13/
├── playfair.py           # File chính chứa code
├── requirements.txt      # Danh sách thư viện cần thiết
├── README.md            # File hướng dẫn này
├── .gitignore           # Danh sách file/thư mục bỏ qua git
└── .venv/               # Môi trường ảo (không commit)
```

## Giải thích thuật toán Playfair

### Ma trận 5×5
- Sử dụng 25 chữ cái (A-Z)
- Chữ J được gộp với I
- Chỉ mã hóa chữ cái

### Ma trận 6×6
- Sử dụng 36 ký tự (A-Z và 0-9)
- Có thể mã hóa cả chữ và số

### Quy tắc mã hóa
1. **Cùng hàng**: Lấy ký tự bên phải (vòng tròn)
2. **Cùng cột**: Lấy ký tự bên dưới (vòng tròn)
3. **Khác hàng/cột**: Tạo hình chữ nhật, lấy góc đối diện

### Quy tắc giải mã
1. **Cùng hàng**: Lấy ký tự bên trái (vòng tròn)
2. **Cùng cột**: Lấy ký tự bên trên (vòng tròn)
3. **Khác hàng/cột**: Tạo hình chữ nhật, lấy góc đối diện

## Khắc phục sự cố

### Lỗi: Module 'streamlit' not found
```bash
pip install streamlit
```

### Lỗi: Port 8501 đã được sử dụng
```bash
streamlit run playfair.py --server.port 8502
```

### Giao diện không hiển thị
- Kiểm tra terminal có lỗi không
- Thử refresh trình duyệt (F5)
- Xóa cache: Streamlit menu > Clear cache

### Kết quả không đúng
- Kiểm tra khóa mã hóa có chính xác không
- Đảm bảo kích thước ma trận giống nhau khi mã hóa và giải mã

## Lưu ý bảo mật

- Playfair Cipher là thuật toán cổ điển, không an toàn cho dữ liệu thực tế
- Chỉ nên sử dụng cho mục đích học tập và giáo dục
- Đối với dữ liệu quan trọng, sử dụng các thuật toán hiện đại như AES, RSA

## Phát triển tiếp theo

- [ ] Hoàn thiện thuật toán RSA
- [ ] Thêm các cipher khác (Caesar, Vigenere, AES)
- [ ] Hỗ trợ upload/download file
- [ ] Phân tích tần suất ký tự
- [ ] So sánh các thuật toán

## Tác giả

Dự án môn Computer Network Security - NT101.Q13

## Giấy phép

Dự án học tập - Sử dụng tự do cho mục đích giáo dục
