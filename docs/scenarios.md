# CVE và tình huống kiểm thử

## CVE thật được ghim

| Fixture | Phiên bản dễ bị ảnh hưởng | Bản đối chứng đã vá | Bằng chứng mong đợi |
| --- | --- | --- | --- |
| CVE-2026-64642: middleware/proxy bypass với App Router, Turbopack và cấu hình một locale | Next.js 16.2.10 | Next.js 16.2.11 | Nuclei chỉ báo khi response chứa `LAB_PRIVATE_ACCOUNT`; redirect/login page không phải finding. Điều kiện và phiên bản theo [advisory](https://github.com/vercel/next.js/security/advisories/GHSA-6gpp-xcg3-4w24). |
| CVE-2026-64645: SSRF rewrite với hostname do request kiểm soát | Next.js 16.2.10 | Next.js 16.2.11 | Nuclei cần body `LAB_CANARY_REACHED_ONLY`; HTTP 200 chung không đủ. Canary chỉ nằm trong Docker network. [Advisory](https://github.com/vercel/next.js/security/advisories/GHSA-p9j2-gv94-2wf4). |

Hai ca này là fixture phụ thuộc điều kiện framework đã công bố. Chỉ ghi nhận chúng tái hiện khi image vulnerable qua kiểm tra canary/marker và image đã vá không trả marker. Nếu điều kiện i18n/App Router khiến build không hợp lệ hoặc probe không tương thích với release đã ghim, báo “chưa xác minh fixture”, không đổi finding dựa trên fingerprint phiên bản.

## Ca mô phỏng

| Template | Endpoint | Marker / ý nghĩa |
| --- | --- | --- |
| `simulated-sqli.yaml` | `/api/lab/search` | `LAB_SQLI_MARKER`; fixture trả dữ liệu seed giả khi query khớp dấu hiệu tautology, không truy cập DB. |
| `simulated-xss.yaml` | `/api/lab/xss` | `SIMULATED_XSS`; phản chiếu trong HTML phục vụ quan sát rule. |
| `simulated-idor.yaml` | `/api/lab/documents/{id}` | `SIMULATED_IDOR` và `LAB_FAKE_STATEMENT`; mọi nội dung đều giả. |
| `simulated-path.yaml` | `/api/lab/file` | `LAB_PATH_MARKER`; không đọc file hệ điều hành. |
| `simulated-upload.yaml` | `/api/lab/upload` POST JSON | Kiểm tra extension mô phỏng, không ghi file lên đĩa. |
| `behavior-login-burst.yaml` | `/api/lab/login` POST JSON | Sáu lần đăng nhập giả để kiểm tra policy đếm hành vi và header rule. |
| `behavior-rate-limit.yaml` | `/?lab_probe=` | Gửi burst giới hạn 35 request; chỉ chạy riêng khi đã bật rate policy. |
| `behavior-geo-policy.yaml` | `/` qua scanner IP `.20` | Fixture quốc gia `US`; không tra cứu địa chỉ địa lý thật. |
| `behavior-bot-declared-fanout.yaml` | Tám đường dẫn `/bot-probe-*` | Cần bật `bot_detection`, đặt `unique_paths=8`, `action=block`, WAF ở `On`; xác nhận header `X-WAF-Lab-Rule: bot_declared_fanout`. Đây là kiểm thử policy, không phải khai thác lỗ hổng. |
| `behavior-bot-spam.yaml` | Lặp `/` với query khác nhau | Cần bật `bot_detection`, đặt `spam_requests=10`, `spam_window_seconds=10`, `action=block`, WAF ở `On`; xác nhận 429 cùng header `X-WAF-Lab-Rule: bot_request_rate`. |
| `simulated-csrf.yaml` | `/api/lab/transfer` POST JSON | Giao dịch giả, luôn trả marker và không thay đổi số dư. |

Chuyển khoản/CSRF dùng API mô phỏng; chỉ trả marker và không thay đổi số dư hoặc gọi dịch vụ thanh toán. IDOR, CSRF và lỗi nghiệp vụ cần xác minh authorization trong ứng dụng. CRS/WAF có thể không xác định quyền sở hữu object hợp lệ.

Portal có tuning CRS 942100 trên duy nhất `/api/lab/search` để người học so sánh false positive/false negative. Không mở rộng ngoại lệ đó sang endpoint khác; log policy và đánh dấu request theo `http.request.id` để đối chiếu.

## Cách diễn giải

- **Finding hợp lệ:** template thấy marker fixture từ app/canary.
- **WAF chặn:** Coraza/guard log có cùng request ID và action block. Một 403 không tự chứng minh template đã khai thác thành công.
- **Bỏ sót:** app marker xuất hiện qua WAF trong chế độ On và không có quyết định block liên quan.
- **Chặn nhầm:** luồng tài chính bình thường bị chặn; ghi request ID, rule, endpoint và policy version.
- **Bypass:** `lab.route=bypass` nghĩa là HAProxy đã phục vụ trực tiếp từ origin vì WAF health down. Đánh giá riêng, không tính vào tỉ lệ block của WAF.
- **DetectionOnly:** log rule và fixture nhưng không ngăn request; chế độ On dùng cùng request để kiểm tra block.
