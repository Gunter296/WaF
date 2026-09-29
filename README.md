# WaF local lab

Repo thử nghiệm Coraza + OWASP CRS và lab website tài chính giả lập. Cấu hình gốc hiện có được giữ làm tài liệu tham chiếu; lab mới nằm trong [lab/](lab/README.md).

## Bắt đầu

1. Cài Docker Desktop và bật Docker Compose.
2. Xem [hướng dẫn lab](lab/README.md), đặc biệt là giới hạn chỉ chạy trên máy cục bộ.
3. Khởi động stack: `docker compose -f lab/docker-compose.yml up --build -d`.
4. Mở website tại http://127.0.0.1:8080, portal tại http://127.0.0.1:8090 và Kibana tại http://127.0.0.1:5601.

## Tài liệu

- [Cách chạy và kiểm thử](lab/README.md)
- [Cấu trúc file, vai trò thư mục và luồng mã nguồn](docs/lab-structure.md)
- [Quản trị rule tuning, learning và automation](docs/learning-tuning.md)
- [Đề xuất cho cấu hình gốc (chỉ tài liệu)](docs/de-xuat-cau-hinh-goc.md)
- [CVE, ca lab và cách diễn giải](docs/scenarios.md)
- [Nguồn tham khảo chính thức](docs/references.md)

Chỉ dùng mục tiêu thuộc stack lab. Dữ liệu tài chính đều là dữ liệu giả.
