## Giới thiệu chung
Trường Đại học Công nghệ Thông tin - Đại học Quốc Gia TP. Hồ Chí Minh
Đồ án môn học An toàn mạng máy tính - NT101.Q13
### Thành viên
- Cáp Hữu Tú - 23521696
- Huỳnh Ngọc Ngân Tuyền - 23521753
- Nguyễn Tài Quang - 23521587

---

# Chương trình Mã hóa/Giải mã Playfair & RSA

Chương trình mã hóa và giải mã văn bản sử dụng thuật toán Playfair Cipher với giao diện Streamlit.

## Tính năng

### Playfair Cipher
- Mã hóa/Giải mã văn bản
- Hỗ trợ ma trận 5×5 (chữ cái A-Z) và 6×6 (chữ cái + số 0-9)
- Hiển thị từng bước mã hóa/giải mã chi tiết
- Giữ nguyên khoảng trắng trong văn bản
- Lịch sử mã hóa/giải mã
- Xuất kết quả ra file
- Hướng dẫn sử dụng tích hợp

### RSA Cipher
- Tạo khóa RSA từ hai số nguyên tố p, q
- Mã hóa/Giải mã văn bản
- Hiển thị chi tiết các bước tính toán khóa
- Hiển thị từng bước mã hóa/giải mã
- Lịch sử mã hóa/giải mã
- Xuất kết quả ra file

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

### Bước 2: Tạo môi trường ảo

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
streamlit run UI.py
```

Chương trình sẽ tự động mở trình duyệt tại địa chỉ: `http://localhost:8501`

### Dừng chương trình

Nhấn `Ctrl + C` trong terminal để dừng server

## Hướng dẫn sử dụng

### Chọn thuật toán

Trong sidebar, chọn thuật toán mong muốn:
- **Playfair Cipher**: Mã hóa thay thế digraph cổ điển
- **RSA Cipher**: Mã hóa bất đối xứng hiện đại

### Playfair Cipher

#### Mã hóa văn bản
1. Chọn "Playfair Cipher" trong sidebar
2. Chọn tab "Mã hóa/Giải mã"
3. Nhập khóa mã hóa (Key) vào ô bên trái
4. Chọn "Mã hóa" ở cột bên phải
5. Nhập văn bản cần mã hóa
6. Nhấn nút "Mã hóa"
7. Kết quả sẽ hiển thị bên dưới, có thể tải xuống

#### Giải mã văn bản
1. Chọn tab "Mã hóa/Giải mã"
2. Nhập khóa mã hóa (Key) - phải giống với khóa đã dùng để mã hóa
3. Chọn "Giải mã" ở cột bên phải
4. Nhập văn bản đã mã hóa
5. Nhấn nút "Giải mã"
6. Kết quả sẽ hiển thị bên dưới

### RSA Cipher

#### Tạo khóa RSA
1. Chọn "RSA Cipher" trong sidebar
2. Chọn tab "Tạo khóa"
3. Nhập hai số nguyên tố p và q
4. (Tùy chọn) Tùy chỉnh giá trị e
5. Nhấn nút "Tạo khóa RSA"
6. Khóa công khai và khóa riêng sẽ được hiển thị

#### Mã hóa văn bản
1. Đảm bảo đã tạo khóa RSA
2. Chọn tab "Mã hóa/Giải mã"
3. Chọn "Mã hóa"
4. Nhập văn bản cần mã hóa
5. Nhấn nút "Mã hóa"
6. Kết quả sẽ hiển thị dưới dạng chuỗi số

#### Giải mã văn bản
1. Đảm bảo đã tạo khóa RSA
2. Chọn tab "Mã hóa/Giải mã"
3. Chọn "Giải mã"
4. Nhập chuỗi số đã mã hóa (cách nhau bởi dấu cách)
5. Nhấn nút "Giải mã"
6. Kết quả sẽ hiển thị văn bản gốc

### Cấu hình

Trong sidebar, có thể:
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
├── UI.py               # File chính chứa giao diện
├── playfair.py         # File chứa code playfair cipher
├── rsa.py              # File chứa code rsa cipher
├── requirements.txt    # Danh sách thư viện cần thiết
├── README.md           # File hướng dẫn này
├── .gitignore          # Danh sách file/thư mục bỏ qua git
└── .venv/              # Môi trường ảo (không commit)
```

## Giải thích thuật toán

### Playfair Cipher

#### Ma trận 5×5
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

### RSA Cipher

RSA là thuật toán mã hóa bất đối xứng sử dụng cặp khóa công khai và khóa riêng.

#### Tạo khóa
1. Chọn hai số nguyên tố khác nhau: **p** và **q**
2. Tính **n = p × q** (modulus)
3. Tính **φ(n) = (p-1) × (q-1)** (hàm Euler)
4. Chọn **e** sao cho 1 < e < φ(n) và gcd(e, φ(n)) = 1 (khóa công khai)
5. Tính **d** sao cho (d × e) mod φ(n) = 1 (khóa riêng)

#### Mã hóa
- Với mỗi ký tự, chuyển thành mã ASCII: **m**
- Tính: **c = m^e mod n**
- **c** là ký tự đã mã hóa

#### Giải mã
- Với mỗi số đã mã hóa: **c**
- Tính: **m = c^d mod n**
- Chuyển **m** về ký tự ASCII

#### Ưu điểm
- Bảo mật cao dựa trên độ khó của bài toán phân tích số nguyên lớn
- Không cần chia sẻ khóa bí mật
- Hỗ trợ chữ ký số

#### Lưu ý
- Cần chọn số nguyên tố đủ lớn để đảm bảo an toàn
- Khóa riêng (d) phải được bảo mật tuyệt đối
- Với n nhỏ, chỉ phù hợp mã hóa văn bản ngắn

## Khắc phục sự cố

### Lỗi: Module 'streamlit' not found
```bash
pip install streamlit
```

### Lỗi: Port 8501 đã được sử dụng
```bash
streamlit run UI.py --server.port 8502
```

### Giao diện không hiển thị
- Kiểm tra terminal có lỗi không
- Thử refresh trình duyệt (F5)
- Xóa cache: Streamlit menu > Clear cache

### Kết quả không đúng
- Kiểm tra khóa mã hóa có chính xác không
- Đảm bảo kích thước ma trận giống nhau khi mã hóa và giải mã

## Lưu ý bảo mật
- **Playfair Cipher**: Chỉ nên sử dụng cho mục đích học tập, không an toàn cho dữ liệu thực tế
- **RSA Cipher**: Implementation này dùng cho giáo dục với số nguyên tố nhỏ. Trong thực tế, cần sử dụng số nguyên tố rất lớn (2048-4096 bit) và thư viện mã hóa chuẩn


