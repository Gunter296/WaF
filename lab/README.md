# Hướng dẫn lab WAF tài chính

## 1. Phạm vi và yêu cầu

Lab dành cho học tập trên máy cá nhân, chứa endpoint cố ý mô phỏng lỗi. Không dùng dữ liệu, mật khẩu, URL hoặc hệ thống của bên thứ ba. Các cổng được publish chỉ bind `127.0.0.1`; các network trong Compose đều đặt `internal: true`. Docker cần truy cập registry/npm/Go module trong bước pull/build lần đầu; các container lab không có đường ra Internet sau khi chạy.

Yêu cầu: Docker Desktop có Compose v2, ít nhất 6 GB RAM cấp cho Docker và khoảng 8 GB dung lượng trống. Elasticsearch có thể chậm khởi động trên máy yếu.

## 2. Khởi động và dừng

Tại thư mục repo:

```powershell
# Tùy chọn: sao chép lab/.env.example thành lab/.env; thêm --env-file lab/.env
# vào lệnh Compose nếu cần thay giá trị mặc định dùng riêng trong lab.
docker compose -f lab/docker-compose.yml config
docker compose -f lab/docker-compose.yml up --build -d
docker compose -f lab/docker-compose.yml ps
```

Mở website `http://127.0.0.1:8080`, portal `http://127.0.0.1:8090`, Kibana `http://127.0.0.1:5601`, Mailpit `http://127.0.0.1:8025`. Đăng nhập demo: `an.demo@northstar.test` / `demo1234`. `patched.localhost` và `direct.localhost` được chọn qua HTTP Host header; script Nuclei bên dưới thiết lập header này.

`lab/waf/Caddyfile` và `lab/waf/config/` được mount chỉ đọc vào WAF. Khi sửa rule hoặc directive trên host, áp dụng sau khi kiểm tra:

```powershell
docker compose -f lab/docker-compose.yml exec waf caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
docker compose -f lab/docker-compose.yml exec waf caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --address 172.31.0.3:2019
```

Các công tắc WAF ghi vào `policy.json` và được đọc ở từng request. Mở `http://127.0.0.1:8090/advanced` để tạo ngoại lệ CRS mới (rule ID, method, đường dẫn, tham số, hạn dùng), xem ứng viên learning và chọn `manual`/`automatic`. Portal sinh `lab/runtime/tuning/tuning.conf`, nạp lại Caddy qua admin API chỉ có trên mạng quản trị nội bộ; nếu nạp lỗi, cấu hình đang chạy được giữ lại. Xem [hướng dẫn learning và tuning](../docs/learning-tuning.md).

Worker đọc log Coraza/HAProxy từ Elasticsearch mỗi 60 giây. Chế độ mặc định là `manual`. Để thử `automatic`, quản trị viên cần đặt PL mục tiêu, xác nhận bài kiểm thử luồng hợp lệ và, nếu muốn tự áp dụng ngoại lệ tham số, bật lựa chọn đó kèm danh sách endpoint được phép. Dữ liệu Nuclei ít request sẽ không đạt điều kiện nâng PL 7 ngày/10.000 request; không hạ các ngưỡng này để lấy kết quả giả.

```powershell
docker compose -f lab/docker-compose.yml logs -f edge waf finance-vulnerable
docker compose -f lab/docker-compose.yml stop
docker compose -f lab/docker-compose.yml start
```

Reset dữ liệu app/policy/log mà vẫn giữ Elasticsearch: xóa volume PostgreSQL và xóa các file dưới `lab/runtime/logs` và `lab/runtime/results` sau khi stack đã dừng. Reset toàn bộ lab, bao gồm chỉ mục Kibana: `docker compose -f lab/docker-compose.yml down -v`. Lệnh `down -v` xóa volume của lab.

## 3. Các lượt kiểm thử Nuclei

Scanner chạy bên trong Docker trên network lab. Dùng `scripts/run-nuclei.ps1` để ghi JSONL, toàn bộ raw request/response, manifest phiên bản/chế độ/tuyến và log lượt quét. Script giới hạn target vào ba Host header trong lab, tắt OAST và tự cập nhật template (`-ni`, `-duc`), concurrency 1; rate tối đa 10 request/giây. Request ID nằm trong response raw và dùng để tra ngược Kibana. Các lượt baseline/WAF/vá chỉ chạy CVE/fixture đơn lẻ; template burst chạy riêng.

```powershell
# Baseline direct tới ứng dụng dễ tổn thương (origin)
.\lab\scripts\run-nuclei.ps1 -RunName baseline -HostName direct.localhost -WafMode 'N/A' `
  -Templates @('cve-2026-64642-middleware-bypass.yaml','cve-2026-64645-ssrf-canary.yaml', `
    'simulated-sqli.yaml','simulated-xss.yaml','simulated-idor.yaml','simulated-path.yaml', `
    'simulated-csrf.yaml','simulated-upload.yaml')

# Qua WAF đến bản Next.js dễ bị ảnh hưởng
.\lab\scripts\run-nuclei.ps1 -RunName waf-on -HostName localhost -WafMode On `
  -Templates @('cve-2026-64642-middleware-bypass.yaml','cve-2026-64645-ssrf-canary.yaml', `
    'simulated-sqli.yaml','simulated-xss.yaml','simulated-idor.yaml','simulated-path.yaml', `
    'simulated-csrf.yaml','simulated-upload.yaml')

# Qua WAF đến bản đã vá
.\lab\scripts\run-nuclei.ps1 -RunName patched -HostName patched.localhost -WafMode On `
  -Templates @('cve-2026-64642-middleware-bypass.yaml','cve-2026-64645-ssrf-canary.yaml')

# Chỉ một nhóm template cụ thể
.\lab\scripts\run-nuclei.ps1 -RunName ssrf-only -HostName localhost -WafMode On `
  -Templates @('cve-2026-64645-ssrf-canary.yaml') -RateLimit 1
```

Vào portal để chuyển `DetectionOnly` hoặc `On`, rồi lặp lại lượt qua WAF. Lượt kiểm tra quốc gia dùng scanner có IP fixture khác:

```powershell
.\lab\scripts\run-nuclei.ps1 -RunName geo-us -HostName localhost -WafMode On `
  -Client nuclei-us -Templates @('behavior-geo-policy.yaml') -RateLimit 1
```

Fixture mặc định ánh xạ `.10` thành `VN`, `.20` thành `US`. Trong portal bật country policy và thêm `US` vào danh sách deny để so sánh. HAProxy ghi log request ID và tuyến; WAF ghi Coraza audit cùng sự kiện behavior. HTTP 403/429 không tự chứng minh rằng một CVE đã được vá hay WAF bị vượt qua.

### Kiểm thử các policy hành vi

Bot detection dùng thư viện Go nguồn mở [mileusna/useragent](https://github.com/mileusna/useragent) phiên bản `v1.3.5` để phân loại User-Agent và bộ giới hạn token bucket nguồn mở [golang.org/x/time/rate](https://pkg.go.dev/golang.org/x/time/rate) `v0.16.0` để xử lý spam request ngay tại WAF. Trong portal `/advanced`, bật bot detection, đặt `unique_paths=8`, `window_seconds=30`, `spam_requests=10`, `spam_window_seconds=10`, `action=block`, giữ WAF `On`, rồi chạy từng template riêng ngay sau khi cửa sổ đếm cũ hết:

```powershell
.\lab\scripts\run-nuclei.ps1 -RunName bot-fanout -HostName localhost -WafMode On -Templates @('behavior-bot-declared-fanout.yaml') -RateLimit 2
.\lab\scripts\run-nuclei.ps1 -RunName bot-spam -HostName localhost -WafMode On -Templates @('behavior-bot-spam.yaml') -RateLimit 10
```

Template fanout cần đủ tám đường dẫn khác nhau trong 30 giây. Template spam lặp một đường dẫn; WAF trả 429 khi hết token trong bucket. Đối chiếu `rule.id=bot_declared_fanout` hoặc `bot_request_rate`, `http.request.id` và `lab.route=waf` trong Kibana. Khi đặt `action=observe` hoặc WAF `DetectionOnly`, request đi tiếp và template chặn sẽ không tạo finding; xem log `waf.behavior` để xác nhận ghi nhận. User-Agent là dữ liệu do client gửi, nên đây là phân loại tự khai báo, không xác thực danh tính Googlebot. Bot giấu User-Agent vẫn chịu giới hạn request chung của `rate_limit`.

Bật rate limit trong portal rồi chạy template giới hạn 35 request; chạy riêng sau khi cửa sổ đếm đã hết. Template đăng nhập gửi sáu lần đăng nhập giả và kiểm tra header rule. Để kiểm thử quốc gia, bật geo policy và deny `US`, sau đó dùng `nuclei-us` với template `behavior-geo-policy.yaml`. Ví dụ:

```powershell
.\lab\scripts\run-nuclei.ps1 -RunName rate -HostName localhost -WafMode On -Templates @('behavior-rate-limit.yaml') -RateLimit 2
.\lab\scripts\run-nuclei.ps1 -RunName login-burst -HostName localhost -WafMode On -Templates @('behavior-login-burst.yaml') -RateLimit 2
```

Mỗi lượt ghi JSONL, raw response và manifest riêng. Theo dõi 429/403, `Retry-After`, request ID và `rule.id` trong Kibana. Tăng/giảm giới hạn từ portal, không chỉnh `policy.json` khi portal đang chạy.

## 4. Elasticsearch và Kibana

Filebeat gửi sự kiện vào chỉ mục `waf-lab-YYYY.MM.DD`. Lần đầu mở Kibana, tạo Data View `waf-lab-*` với timestamp `@timestamp`. Discover dùng các truy vấn KQL:

```text
lab.stack : "finance-waf-lab"
event.dataset : "waf.behavior"
lab.route : "bypass"
event.dataset : "finance.lab" and event.action : "login_simulation"
http.response.status_code >= 400
```

Tạo dashboard từ Discover/Lens, nhóm theo `event.dataset`, `event.action`, `rule.id`, `http.response.status_code` và `lab.route`; dùng `http.request.id` để xem cùng request qua các nguồn log. Tạo Elasticsearch query alert cho `lab.route: bypass`, tăng 403/429, lỗi ingest và login thất bại; action email dùng SMTP `mailpit:1025`, rồi kiểm tra hộp thư tại port 8025. Kibana alert kiểm tra theo lịch, còn việc chặn request diễn ra đồng bộ tại WAF.

## 5. Failover và khắc phục lỗi

```powershell
docker compose -f lab/docker-compose.yml stop waf
# đợi ba lần health check; website demo tiếp tục mở ở tuyến bypass
docker compose -f lab/docker-compose.yml start waf
```

HAProxy dùng backend dự phòng khi health check WAF fail; request trên tuyến bypass đến trực tiếp `finance-vulnerable` và không chịu CRS, geo hay policy hành vi. Tìm `lab.route: "bypass"` và kiểm tra email ở Mailpit. Khi WAF khỏe lại, HAProxy dùng tuyến WAF.

Nếu service không healthy, xem `docker compose ... logs <service>`. Nếu ES không khởi động, tăng RAM Docker Desktop, kiểm tra log ES và dung lượng ổ đĩa. Nếu template không tìm thấy marker, kiểm tra Host header, chế độ WAF, log ứng dụng và kết quả trước/sau bản vá. Xem [scenarios.md](../docs/scenarios.md) để biết marker kỳ vọng và giới hạn của từng ca.
