# Tài liệu WaF

Trang này là mục lục cho người mới. Các hướng dẫn thao tác chi tiết vẫn ở tài liệu chuyên biệt để tránh chép nội dung.

## Bắt đầu

1. Đọc [README dự án](../README.md) để biết phạm vi và các thành phần.
2. Dùng [hướng dẫn chạy lab](../lab/README.md) để kiểm tra yêu cầu, khởi động và dừng Compose.
3. Xem [kiến trúc và vận hành](waf-architecture.md) để hiểu bốn luồng Mermaid và cách điều tra request.

## Theo chủ đề

- [Ứng dụng tài chính giả lập](finance-application.md) — tài khoản demo, nghiệp vụ và dữ liệu giả.
- [Quản trị ca tuning tài chính](finance-tuning-admin.md) — tái hiện false positive nghiệp vụ và phạm vi tuning.
- [Learning, candidate và automation](learning-tuning.md) — điều kiện, review, ngưỡng và giới hạn.
- [Scenario và cách diễn giải](scenarios.md) — fixture, marker và tiêu chuẩn bằng chứng.
- [Bản đồ cấu trúc repo](lab-structure.md) — vai trò file và thư mục ở mức mã nguồn.
- [Xử lý sự cố khi chạy lab](ubuntu-deploy.md) — chuẩn bị môi trường Docker trên Ubuntu.
- [Đề xuất cấu hình gốc](de-xuat-cau-hinh-goc.md) — ghi chú tham khảo, không tự áp dụng.
- [Nguồn tham khảo](references.md) — tài liệu upstream và advisory.

## Trạng thái bằng chứng

Tài liệu mô tả cấu hình được kiểm tra trong repo, không khẳng định service đang chạy. Trong lần tổ chức tài liệu này, `docker compose ps` trả danh sách rỗng nên không xác nhận runtime. Giá trị trong `lab/runtime/policy/policy.json` là file trạng thái lưu trên host, không đủ để khẳng định policy hiệu lực trong một container đang chạy.
