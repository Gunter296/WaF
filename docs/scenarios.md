# CVE và tình huống kiểm thử

## CVE templates lưu trữ

Các template CVE cũ còn trong repo để giữ lịch sử bài lab; chúng không còn là ca đang chạy. Finance đã bỏ rewrite lấy hostname từ request và proxy hiện không cấp quyền bằng cookie tĩnh. Vì vậy không dùng các template này để kết luận CVE còn tái hiện hoặc đã được vá. Chỉ khôi phục bài CVE riêng sau khi cập nhật fixture, kiểm tra điều kiện advisory và xác minh cả hai image.

| Fixture | Phiên bản dễ bị ảnh hưởng | Bản đối chứng đã vá | Bằng chứng mong đợi |
| --- | --- | --- | --- |
| CVE-2026-64642 middleware/proxy bypass | Template và advisory được lưu trữ; luồng finance hiện không cung cấp marker private page theo template cũ. | Chưa là ca kiểm thử khả dụng. |
| CVE-2026-64645 SSRF rewrite | Rewrite `/lab/ssrf/{host}/{path}` đã bị gỡ; canary không còn được finance gọi từ request. | Chưa là ca kiểm thử khả dụng. |

Các advisory vẫn là tài liệu tham khảo, không phải bằng chứng sản phẩm hiện tại còn dễ bị ảnh hưởng. Các template còn sót lại có thể không tương thích với source hiện tại.

## Ca mô phỏng

| Template | Endpoint | Marker / ý nghĩa |
| --- | --- | --- |
| `valid-traffic-corpus.yaml` | Search, file fixture, upload JSON và command fixture | Các response hợp lệ kỳ vọng status 200 cùng marker cụ thể; so sánh cùng template giữa direct, DetectionOnly và On. |
| `simulated-command-injection.yaml` | `/api/lab/command` POST JSON | Chuỗi `; echo LAB_CMDI_MARKER` chỉ được phân loại thành marker; endpoint không chạy shell hay lệnh hệ điều hành. |
| `positive-security-policy.yaml` | `/api/lab/positive` POST JSON | Một JSON hợp lệ được cho qua; sai URL, method, content type, file extension, JSON parameter hoặc JSON syntax kỳ vọng Coraza 403. |
| `simulated-sqli.yaml` | `/api/lab/search` | `LAB_SQLI_MARKER`; fixture trả dữ liệu seed giả khi query khớp dấu hiệu tautology, không truy cập DB. |
| `simulated-xss.yaml` | `/api/lab/xss` | `SIMULATED_XSS`; phản chiếu trong HTML phục vụ quan sát rule. |
| `simulated-idor.yaml` | `/api/lab/documents/{id}` | `SIMULATED_IDOR` và `LAB_FAKE_STATEMENT`; mọi nội dung đều giả. |
| `simulated-path.yaml` | `/api/lab/file` | `LAB_PATH_MARKER`; không đọc file hệ điều hành. |
| `simulated-upload.yaml` | `/api/lab/upload` POST JSON | Kiểm tra extension mô phỏng, không ghi file lên đĩa. |
| `behavior-login-burst.yaml` | `/api/lab/login` POST JSON | Sáu lần đăng nhập giả để kiểm tra policy đếm hành vi và header rule. |
| `behavior-rate-limit.yaml` | `/?lab_probe=` | Gửi burst giới hạn 35 request; chỉ chạy riêng khi đã bật rate policy. |
| `behavior-geo-policy.yaml` | `/` qua scanner IP `.20` | Fixture quốc gia `US`; không tra cứu địa chỉ địa lý thật. |
| `behavior-bot-normal-profile.yaml` | `/` và search hợp lệ với browser-style User-Agent | Hai request 200; chỉ kiểm tra heuristic user-agent/path của lab, không chứng minh client là người thật. |
| `behavior-bot-declared-fanout.yaml` | Tám đường dẫn `/bot-probe-*` | Cần bật `bot_detection`, đặt `unique_paths=8`, `action=block`, WAF ở `On`; xác nhận header `X-WAF-Lab-Rule: bot_declared_fanout`. Đây là kiểm thử policy, không phải khai thác lỗ hổng. |
| `behavior-bot-spam.yaml` | Lặp `/` với query khác nhau | Cần bật `bot_detection`, đặt `spam_requests=10`, `spam_window_seconds=10`, `action=block`, WAF ở `On`; xác nhận 429 cùng header `X-WAF-Lab-Rule: bot_request_rate`. |
| `simulated-csrf.yaml` | `/api/lab/transfer` POST JSON | Giao dịch giả, luôn trả marker và không thay đổi số dư. |

Chuyển khoản/CSRF dùng API mô phỏng; chỉ trả marker và không thay đổi số dư hoặc gọi dịch vụ thanh toán. IDOR, CSRF và lỗi nghiệp vụ cần xác minh authorization trong ứng dụng. CRS/WAF có thể không xác định quyền sở hữu object hợp lệ.

Tuning mới dành riêng cho `POST /api/transactions/reconcile/search`, tham parameter `expression`. Rule ID phải được xác nhận từ audit thực tế; không giả định 942100. Quy trình quản trị và bằng chứng bắt buộc được mô tả tại [finance-tuning-admin.md](finance-tuning-admin.md). Fixture `/api/lab/*` là nhóm marker riêng cho bài học cũ, không phải nghiệp vụ tài chính.

## Cách diễn giải

- **Finding hợp lệ:** template thấy marker fixture từ app/canary.
- **CVE-2026-64642:** template yêu cầu status 200 và marker riêng; redirect `307 /login` là hành vi từ chối của ứng dụng, không phải finding. Advisory công khai điều kiện phiên bản/kiến trúc nhưng trang đã tra không đưa request PoC; probe hiện tại chưa chứng minh CVE cho tới khi có request phù hợp và kiểm thử hai bản build.
- **WAF chặn:** Coraza/guard log có cùng request ID và action block. Một 403 không tự chứng minh template đã khai thác thành công.
- **Bỏ sót:** app marker xuất hiện qua WAF trong chế độ On và không có quyết định block liên quan.
- **Chặn nhầm:** luồng tài chính bình thường bị chặn; ghi request ID, rule, endpoint và policy version.
- **Bypass:** `lab.route=bypass` nghĩa là server được chọn đi thẳng tới origin. Dùng `lab.backend` + `lab.server` để phân biệt baseline chủ động (`finance_direct`/`finance`) với failover (`finance_waf_with_fallback`/`finance-fallback`). Đánh giá riêng, không tính vào tỉ lệ block của WAF.
- **DetectionOnly:** log rule và fixture nhưng không ngăn request; chế độ On dùng cùng request để kiểm tra block.
