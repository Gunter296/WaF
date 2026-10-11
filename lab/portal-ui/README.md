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
docker compose --env-file lab/.env -f lab/docker-compose.yml -f lab/docker-compose.portal-ui.yml config
docker compose --env-file lab/.env -f lab/docker-compose.yml -f lab/docker-compose.portal-ui.yml build --no-cache portal
docker compose --env-file lab/.env -f lab/docker-compose.yml -f lab/docker-compose.portal-ui.yml up -d --force-recreate portal
```

Mở <http://127.0.0.1:8090>. Trên VM đang đứng trong thư mục `lab`, dùng cùng hai file Compose và đổi đường dẫn env thành `.env`:

```bash
docker compose --env-file .env -f docker-compose.yml -f docker-compose.portal-ui.yml build --no-cache portal
docker compose --env-file .env -f docker-compose.yml -f docker-compose.portal-ui.yml up -d --force-recreate portal
```

`git pull` chỉ cập nhật source trên máy; lệnh build tạo lại image có HTML/CSS/JS mới, còn `--force-recreate` thay container đang chạy. Service giữ tên `portal`, cổng, biến môi trường, volume và network cũ để worker vẫn hoạt động. Không chạy hai portal cùng ghi policy. Sau này dùng cùng hai `-f` khi thao tác stack mới.

Quay lại giao diện dự phòng (policy và dữ liệu PostgreSQL vẫn giữ):

```powershell
docker compose -f lab/docker-compose.yml up -d --build --force-recreate portal
```

## Màn hình và dữ liệu

| Menu | Chức năng |
| --- | --- |
| Tổng quan | Chế độ, PL, số ngoại lệ, heatmap sự kiện WAF nghi ngờ theo giờ/ngày và mức độ, phân loại theo cùng bộ lọc của trang nhật ký và danh sách request đáng ngờ gần đây. Chọn ô heatmap hoặc loại sự kiện để mở nhật ký đã lọc; mở điều tra theo X-Request-ID hoặc lưu kết quả xử lý/đánh dấu nhầm. Ứng viên learning vẫn được quản lý riêng trong hàng đợi phân tích. |
| Hàng đợi phân tích | Tìm kiếm, lọc trạng thái, phân trang, xuất JSON đã lọc, xem request ID và gắn nhãn kèm bằng chứng. |
| WAF & CRS | Bật policy lab, DetectionOnly/On, Blocking/Detection PL, hai virtual patch, ngoại lệ SQLi fixture, xem JSON. |
| Bot & hành vi | Bot detection, token bucket, fanout, rate IP/CIDR, prefix IPv4/IPv6, đăng nhập thất bại, burst 404, truy cập chứng từ tuần tự. |
| IP & quốc gia | Allow/deny IP/CIDR sinh rule Coraza `@ipMatch`; mã quốc gia và IP fixture dạng JSON vẫn là mô phỏng. |
| Tuning rules | Tạo/sửa/thu hồi/bật/tắt ngoại lệ theo site, rule ID, method, route, target, thời hạn và lý do. Backend giữ validation và rollback reload cũ. |
| Learning & automation | Heartbeat worker, Manual/Automatic, PL mục tiêu, xác nhận flow test, cho phép ngoại lệ tự động và endpoint được phép. |
| Nhật ký | Tìm và lọc sự kiện trong Elasticsearch theo ngày, giờ, phút; thời điểm “Trước” là mốc kết thúc không bao gồm. Mỗi request có X-Request-ID hiển thị trạng thái xử lý từ audit và mở được phần điều tra: kết quả, request, quyết định, tuyến, bản ghi từng nguồn và cấu hình có bằng chứng tại thời điểm request. |

Policy được chỉnh thành bản nháp dùng chung giữa các màn hình. “Lưu và áp dụng” gửi `PUT /api/policy` kèm version. Khi lỗi, bản nháp được giữ; khi xung đột version, hủy bản nháp rồi làm mới. “Thu hồi” ngoại lệ chỉ vào bản nháp cho đến khi lưu. Nhãn learning lưu ngay sau khi xác nhận trong hộp thoại. Backend vẫn ghi audit, xuất policy JSON và reload tuning khi thay đổi. Không có thao tác tự hạ ngưỡng learning hoặc ép nâng PL.

Portal đọc nhật ký qua API `/api/logs` từ Elasticsearch. Heatmap tổng quan dùng aggregation phía Elasticsearch trên log WAF/Coraza có dấu hiệu đáng chú ý, lấy đủ tuần hiện tại kể cả khi tuần bắt đầu ở tháng trước, rồi cho xem trong ngày, tuần hoặc tháng theo múi giờ `Asia/Ho_Chi_Minh`. Log `/healthz` được loại như ở trang Nhật ký. Mỗi document được xếp vào đúng một mức nghiêm trọng theo mức cao nhất tìm thấy; tổng heatmap đếm bản ghi, không đếm request duy nhất. Phân loại SQLi, XSS, bot, scanner, behavior và các loại khác dùng bộ lọc phân loại của trang Nhật ký; số đếm phân loại là bản ghi WAF đáng chú ý trong tháng. Bộ lọc phân loại dùng điều kiện gốc cho từng nhóm để tránh truy vấn Elasticsearch lồng nhau quá lớn. Nếu phần thống kê hoặc danh sách request lỗi riêng, phần còn lại vẫn hiển thị. Chọn ô hoặc loại sự kiện mở trang Nhật ký với cùng bộ lọc dấu hiệu WAF, có nút bỏ bộ lọc này. Tổng quan làm mới khi quay lại trang hoặc sau 60 giây khi đang hiển thị. Danh sách xử lý tổng quan gom tối đa 50 request nghi ngờ gần nhất trong tháng theo X-Request-ID; con số chờ xử lý chỉ áp dụng cho mẫu này, không phải toàn bộ log. Thao tác xử lý ghi bản ghi `log_reviewed` vào `lab_audit` và log portal, chỉ lưu request ID, trạng thái, ghi chú và người duyệt cục bộ; không sao chép body hoặc payload. Trạng thái mới nhất hiển thị ở trang nhật ký và quyết định request còn mở hay đã đóng trên tổng quan. Ứng viên learning vẫn là luồng riêng và tiếp tục được xử lý trong hàng đợi phân tích. Thống kê lưu lượng tổng thể và địa lý vẫn nằm trong Kibana. `preview=1` chỉ dùng dữ liệu mẫu trong bộ nhớ trình duyệt; thao tác preview không ghi PostgreSQL.

Giao diện hiển thị policy trước khi thống kê Elasticsearch hoàn tất; thống kê tổng quan chỉ tải khi mở trang tổng quan. Truy vấn nhật ký không chuyển body request/response sang bảng danh sách; bản xem chi tiết tiếp tục giữ rule, header và metadata cần điều tra. Trang nhật ký cập nhật request mới mỗi 15 giây khi đang ở trang đầu và khoảng thời gian còn mở; khoảng lịch sử đã kết thúc không tự thăm dò.

Khi mở một request, portal gọi `/api/logs/trace?request_id=...` để tìm các bản ghi có ID khớp chính xác, tối đa 200 bản ghi. API áp dụng quy tắc che lên bản sao gửi cho trình duyệt; log lưu trong Elasticsearch không bị sửa. Trang nhật ký tìm mode trong log WAF cùng request ID, kể cả khi Coraza audit nằm ngoài trang đang xem; chỉ dùng `portal.audit policy_updated` trước thời điểm request nếu không có mode ở request. Những log có trước mốc policy đầu tiên và thiếu Coraza audit vẫn có thể hiện “Không xác định”. Nguồn không tìm thấy chỉ được ghi là thiếu bằng chứng, không suy ra WAF down. Audit policy hiện không ghi đầy đủ policy version và PL; các trường này chỉ hiện khi có trong log request.

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
