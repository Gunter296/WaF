# Northstar Portal UI

Giao diện NTVDT mới lấy cảm hứng từ các ảnh dashboard bảo mật: menu trái, bảng phân tích, biểu đồ, dark mode cyan `#00F5FF` và light mode hồng/đỏ. Cả hai theme dùng cỡ chữ nội dung 20px và tiêu đề chính 28px; nhãn phụ nhỏ hơn để giữ bố cục dễ quét. Light mode dùng chữ đỏ mận tương phản cao trên nền sáng phủ toàn viewport. Dark mode dùng cyan `#00F5FF` làm màu nhấn. Lựa chọn theme được lưu cục bộ trên trình duyệt. `lab/portal/` được giữ nguyên làm bản dự phòng. Compose gốc không bị chỉnh sửa.

## Xem thử không cần Docker

Chạy từ thư mục repo:

```powershell
node lab/portal-ui/preview.mjs
```

Mở <http://127.0.0.1:8091/?preview=1>. Banner vàng ghi rõ dữ liệu mẫu. Có thể thử điều hướng, tìm kiếm, lọc, phân trang, xuất JSON, thay đổi policy, thêm/sửa/thu hồi ngoại lệ và đánh nhãn learning. Các thay đổi chỉ lưu trong bộ nhớ trang; tải lại trang sẽ reset. Không gọi API WAF. Ctrl+C để dừng preview.

## Dùng với lab thực tế

```powershell
docker compose -f lab/docker-compose.yml -f lab/docker-compose.portal-ui.yml config
docker compose -f lab/docker-compose.yml -f lab/docker-compose.portal-ui.yml up -d --build portal
```

Mở <http://127.0.0.1:8090>. Service giữ tên `portal`, cổng, biến môi trường, volume và network cũ để worker vẫn hoạt động. Không chạy hai portal cùng ghi policy. Sau này dùng cùng hai `-f` khi thao tác stack mới.

Quay lại giao diện dự phòng (policy và dữ liệu PostgreSQL vẫn giữ):

```powershell
docker compose -f lab/docker-compose.yml up -d --build --force-recreate portal
```

## Màn hình và dữ liệu

| Menu | Chức năng |
| --- | --- |
| Tổng quan | Chế độ, PL, số ngoại lệ còn hiệu lực, biểu đồ và hàng đợi từ tối đa 200 ứng viên learning API trả về. Không dựng số request, quốc gia hay tuyến failover giả trong chế độ thật. |
| Hàng đợi phân tích | Tìm kiếm, lọc trạng thái, phân trang, xuất JSON đã lọc, xem request ID và gắn nhãn kèm bằng chứng. |
| WAF & CRS | Bật policy lab, DetectionOnly/On, Blocking/Detection PL, hai virtual patch, ngoại lệ SQLi fixture, xem JSON. |
| Bot & hành vi | Bot detection, token bucket, fanout, rate IP/CIDR, prefix IPv4/IPv6, đăng nhập thất bại, burst 404, truy cập chứng từ tuần tự. |
| IP & quốc gia | Allow/deny IP/CIDR, mã quốc gia và IP fixture dạng JSON. |
| Tuning rules | Tạo/sửa/thu hồi/bật/tắt ngoại lệ theo site, rule ID, method, route, target, thời hạn và lý do. Backend giữ validation và rollback reload cũ. |
| Learning & automation | Heartbeat worker, Manual/Automatic, PL mục tiêu, xác nhận flow test, cho phép ngoại lệ tự động và endpoint được phép. |

Policy được chỉnh thành bản nháp dùng chung giữa các màn hình. “Lưu và áp dụng” gửi `PUT /api/policy` kèm version. Khi lỗi, bản nháp được giữ; khi xung đột version, hủy bản nháp rồi làm mới. “Thu hồi” ngoại lệ chỉ vào bản nháp cho đến khi lưu. Nhãn learning lưu ngay sau khi xác nhận trong hộp thoại. Backend vẫn ghi audit, xuất policy JSON và reload tuning khi thay đổi. Không có thao tác tự hạ ngưỡng learning hoặc ép nâng PL.

Thống kê lưu lượng theo thời gian, địa lý thực và cảnh báo nằm trong Kibana. Portal hiện không có API cung cấp chúng, vì vậy giao diện không tạo bản đồ hoặc traffic chart bằng dữ liệu giả. `preview=1` luôn sử dụng dữ liệu mẫu và không ghi API, kể cả khi mở trên port 8090.

## File và luồng mã

- `public/index.html`: khung ứng dụng, sidebar, thanh lưu và hộp thoại.
- `public/styles.css`: theme tối, biểu đồ CSS, bảng, form và responsive.
- `public/app.js`: điều hướng bằng hash, bản nháp policy, gọi API, form tuning, bảng learning, biểu đồ tổng hợp và xử lý lỗi.
- `public/demo.js`: fixture chỉ dùng khi `preview=1`; không gửi vào backend.
- `server.mjs`: bản sao backend portal, thay phần phục vụ giao diện bằng static asset allowlist. API và các kiểm soát ghi policy được giữ.
- `tuning.mjs`, `automation.mjs`: bản sao logic hiện có để thư mục mới chạy độc lập. Cần đồng bộ chủ động nếu backend cũ được sửa trong tương lai.
- `package.json`: dependency PostgreSQL của backend.
- `Dockerfile`: đóng gói backend và tài nguyên giao diện.
- `preview.mjs`: static server loopback, không dependency, không kết nối cơ sở dữ liệu.
- `backup-checksums.json`: SHA-256 các file portal cũ tại thời điểm tạo giao diện mới.
- `../docker-compose.portal-ui.yml`: override tùy chọn để chuyển build portal sang thư mục này.

Luồng thật: browser → `app.js` → API của `server.mjs` → PostgreSQL + policy/tuning volume → WAF. Learning: Elasticsearch → worker hiện có → portal API → bảng ứng viên. Chế độ xem thử: browser → static server → `demo.js`, không có bước ghi WAF.

## Kiểm chứng triển khai

Đã kiểm tra cú pháp JavaScript, tính nguyên vẹn các file backup, tính đồng nhất logic backend và 5 test tuning/automation hiện có. Đã chạy preview trong trình duyệt và kiểm tra điều hướng, sửa/lưu/hủy policy, tạo ngoại lệ, tìm kiếm liên tục và gắn nhãn learning; không ghi nhận lỗi console. Chưa chạy tích hợp PostgreSQL/Caddy bằng Docker trên máy này do chưa có lệnh Docker. `preview.png` là ảnh dashboard với dữ liệu mẫu, không phải bằng chứng xử lý lưu lượng thực.
