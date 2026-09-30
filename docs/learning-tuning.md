# Quản trị CRS tuning và learning trong lab

## Luồng cấu hình

1. Trong portal mặc định tại `http://127.0.0.1:8090/advanced`, admin nhập rule ID CRS, HTTP method, đường dẫn chính xác, target cụ thể (ví dụ `ARGS:q`), lý do và hạn dùng tối đa 30 ngày. Với giao diện `portal-ui` bật qua Compose override, dùng `http://127.0.0.1:8090/#tuning`; `/advanced` chỉ mở cùng giao diện chính. Chọn phạm vi `rule` chỉ khi ngoại lệ một tham số không đủ.
2. Portal kiểm tra dữ liệu, lưu bản chính và lịch sử thay đổi ở PostgreSQL, sinh `lab/runtime/tuning/tuning.conf`. File này chứa `SecRule` phase 1 trước CRS và dùng `ctl:ruleRemoveTargetById` hoặc `ctl:ruleRemoveById` cho đúng method/route.
3. Portal gọi Caddy `/load` qua địa chỉ admin `172.31.0.3:2019` trên mạng `management`. Caddy kiểm tra và áp dụng cấu hình atomically; khi lỗi portal phục hồi file tuning trước đó. Website và worker không nằm trên mạng có địa chỉ admin.
4. Thu hồi trên portal xóa ngoại lệ và reload. Mỗi rule có điều kiện `TIME_EPOCH` nên hết hạn ngay trong Coraza theo thời gian request; portal cũng xóa rule hết hạn và reload mỗi phút.

`policy.json` vẫn chứa mode, PL, rate, geo và hành vi để module Go đọc trên từng request. Nó cũng chứa danh sách ngoại lệ **có cấu trúc** và số phiên bản; portal từ chối lượt lưu dựa trên phiên bản cũ. Coraza chỉ thực thi sau khi portal sinh và reload `tuning.conf`. Sửa tay `policy.json` khi portal đang chạy sẽ bị ghi đè bởi PostgreSQL.

## Learning worker

`lab/learning-worker/worker.mjs` đọc audit Coraza trong Elasticsearch và nhóm theo biến thể finance, rule ID, PL, method, đường dẫn, tham số. Mỗi ứng viên có số request khớp, số ngày, vài request ID để tra Kibana và số request khớp PL cao hơn Blocking PL. Con số cuối là **ước lượng thô của rule match mới**, không phải số request chắc chắn sẽ bị chặn vì CRS cộng điểm bất thường. Nếu hơn 5.000 audit event hoặc 100 nhóm trong cửa sổ 4 ngày, worker vẫn đưa các mẫu nhìn thấy vào portal nhưng ngừng quyết định tự động ở lượt đó.

Admin xem request ID và log ứng dụng trước khi chọn `Xác nhận FP`, `Cần xem` hoặc `Bỏ qua`. Khi xác nhận FP, portal yêu cầu ghi bằng chứng kiểm thử và lưu cùng nhãn trong PostgreSQL. Worker không tự suy ra false positive từ HTTP 2xx.

## Mode automatic

Mặc định `manual`: worker chỉ thu thập và đề xuất. Worker tính điều kiện automation từ lưu lượng finance dễ tổn thương. Mode và PL của WAF hiện dùng chung cho hai biến thể finance; ngoại lệ CRS được gắn riêng với từng Host. Admin bật `automatic`, đặt PL mục tiêu, tăng Detection PL trước khi tăng Blocking PL, rồi xác nhận bài kiểm thử luồng hợp lệ.

Portal chỉ nâng một bước khi có ít nhất 10.000 request WAF trong 7 ngày, giai đoạn hiện tại đã tồn tại 7 ngày, có ít nhất 30 request trong 15 phút gần nhất, không có ứng viên mức cao đang chờ xem và Detection PL bao phủ PL mới. PL3/4 phải do admin đặt làm mục tiêu. Sau nâng, portal ghi mode/PL trước đó và so tỉ lệ 5xx, 403/429 trong 15 phút. Khi tỉ lệ tăng vượt ngưỡng tương đối hoặc tuyệt đối, thiếu lưu lượng đánh giá, hoặc worker ngừng gửi heartbeat quá 2 phút, portal rollback và ghi audit log.

Ngoại lệ tự động phải được admin xác nhận FP, nằm trên endpoint đã cho phép, xuất hiện ít nhất 30 lần trải qua ít nhất 3 ngày, không đi kèm rule nghiêm trọng khác. Chỉ ngoại lệ **một target** được tự áp dụng và hết hạn sau 24 giờ; toàn bộ rule cần admin thao tác thủ công. Đây là guardrail cho bài lab, không phải bằng chứng một request hợp lệ trong môi trường thật.

## Kiểm tra

```powershell
docker compose -f lab/docker-compose.yml logs -f learning-worker portal waf
node lab/portal/tuning.test.mjs
node lab/portal/automation.test.mjs
node lab/learning-worker/learning.test.mjs
```

Trong Kibana tìm `event.dataset : "portal.audit"`, `event.dataset : "waf.behavior"` và audit Coraza theo request ID. Thử ngoại lệ tham số bằng request khớp đúng method/route/target, rồi đổi một trong ba thành phần để xác nhận CRS vẫn hoạt động ngoài phạm vi. Thử một rule không hợp lệ để xác nhận portal trả lỗi và WAF giữ cấu hình trước.
