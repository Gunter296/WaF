# Đề xuất cho cấu hình gốc (chỉ tham khảo)

Tài liệu này ghi lại những điểm nên xem xét khi nâng cấp cấu hình ban đầu. Không chỉnh sửa hay tự áp dụng thay đổi trong các file được nhắc đến. Lab mới chạy bằng cấu hình dưới `lab/`.

| File gốc | Quan sát | Đề xuất nếu sau này chủ động nâng cấp |
| --- | --- | --- |
| `docker-compose.yml` | WAF publish `8080:8080` trên mọi interface; các service `rule-manager`, `log-analyzer`, `admin-api`, `web-admin` chưa có source; healthcheck có typo `helathcheck`; khai báo port của portal không đúng dạng Compose; Juice Shop và volume dùng tag/latest hoặc external phụ thuộc máy. | Bind loopback cho lab; tách Compose lab; bỏ service placeholder khỏi cấu hình chạy mới; sửa healthcheck; ghim image/version; dùng network internal và volume riêng. |
| `coraza-caddy/Caddyfile` | Reverse proxy tới Juice Shop cố định; cấu hình hiện tại không phải route tới finance lab. | Giữ làm cấu hình cũ; cấu hình tài chính nằm trong `lab/waf/Caddyfile`. Nếu chuyển đổi sau này, thêm request ID tin cậy, host route và health endpoint. |
| `coraza-caddy/config/coraza.conf` | Body limit 13 MiB; debug log level cao; audit chỉ ghi giao dịch liên quan. | Đánh giá body limit/PII retention theo mục tiêu thực tế; giảm debug trong vận hành thường ngày; với lab dùng cấu hình riêng có giới hạn 10 MiB và log sự kiện riêng. |
| `coraza-caddy/Dockerfile` | CRS download/build đang comment; CRS version arg có comment. File này có một thay đổi chưa commit từ trước: `ARG CRS_VERSION` đã thành `#ARG CRS_VERSION`. | Không ghi đè thay đổi sẵn có. Trong một thay đổi khác, ghim Caddy/Coraza/CRS rõ ràng và xác minh tương thích. |
| `README.md` | Ban đầu chỉ có tiêu đề `WaF`. | README hiện liên kết vào lab; tài liệu vận hành chi tiết nằm ở `lab/README.md`. |

Với route backup HAProxy, cần coi failover tới origin là trạng thái giảm bảo vệ và cảnh báo rõ. Không dùng khả năng bypass này cho dịch vụ tài chính thật. Xem cấu hình lab và hướng dẫn chạy để biết hiện thực hóa được cô lập như thế nào.
