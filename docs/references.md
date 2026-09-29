# Tài liệu tham khảo

Các tài liệu dưới đây dùng để chọn phạm vi lab, kiểm tra phiên bản và giải thích giới hạn của từng lớp. Phiên bản phụ thuộc được ghim trong `lab/`; không tự động đổi theo các trang tham khảo.

## Next.js và các CVE trong lab

- [CVE-2026-64642 / GHSA-6gpp-xcg3-4w24](https://github.com/vercel/next.js/security/advisories/GHSA-6gpp-xcg3-4w24): điều kiện App Router, Turbopack và một locale; advisory khuyên kiểm tra quyền trong đường xử lý dữ liệu phía server.
- [Bản sửa CVE-2026-64642, PR #96014](https://github.com/vercel/next.js/pull/96014): thay đổi bộ khớp middleware/proxy với i18n một locale.
- [CVE-2026-64645 / GHSA-p9j2-gv94-2wf4](https://github.com/vercel/next.js/security/advisories/GHSA-p9j2-gv94-2wf4): SSRF khi rewrite/redirect tạo hostname đích từ dữ liệu do request kiểm soát; lab chỉ truy cập canary nội bộ.

Hai CVE được chốt trong plan và ghim Next.js 16.2.10/16.2.11. Template chỉ báo khi marker fixture xuất hiện; bản build và probe cần được chạy thực tế trước khi gọi là tái hiện thành công.

## WAF, hành vi và failover

- [HAProxy health checks](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/reliability/health-checks/): kiểm tra trạng thái backend và chuyển tuyến dự phòng.
- [Coraza execution flow](https://www.coraza.io/docs/seclang/execution-flow/): thứ tự các phase và lý do rule hành vi phải đọc request trong giới hạn trước khi chuyển tiếp.
- [Coraza collections](https://www.coraza.io/docs/reference/internals/): giới hạn collection; lab dùng bộ đếm cục bộ trong tiến trình WAF và chấp nhận việc reset khi WAF restart.
- [OWASP CRS tuning](https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/): tuning bằng rule/ngoại lệ có phạm vi hẹp, tránh sửa rule gốc.
- [Coraza ctl actions](https://www.coraza.io/docs/seclang/actions/): ngoại lệ `ruleRemoveTargetById` và `ruleRemoveById` áp dụng trong một transaction.
- [Coraza audit JSON v3.7.0](https://github.com/corazawaf/coraza/blob/v3.7.0/internal/auditlog/auditlog.go): `messages` là trường cấp cao nhất dùng cho learning worker.
- [Caddy Admin API](https://caddyserver.com/docs/api): `/load` nhận Caddyfile và giữ cấu hình trước nếu cấu hình mới không hợp lệ.
- [OWASP IDOR Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html): kiểm tra quyền sở hữu và authorization phía ứng dụng cho từng object.
- [Coraza-Caddy releases](https://github.com/corazawaf/coraza-caddy/releases): plugin được ghim ở 2.6.1; phụ thuộc release tương ứng gồm Coraza 3.7.0 và CRS 4.25.0 LTS.
- [Coraza-Caddy transaction ID header](https://github.com/corazawaf/coraza-caddy): dùng `tx_id_req_header` để giữ request ID từ trusted proxy trong audit log; HAProxy xóa/ghi đè header do client gửi.
- [OWASP CRS security support](https://github.com/coreruleset/coreruleset/security): CRS 4.25.x là nhánh LTS có hỗ trợ bảo mật; image/phiên bản lab được cố định để kết quả lặp lại.

## Nuclei và quan sát log

- [Nuclei: Running Nuclei](https://docs.projectdiscovery.io/opensource/nuclei/running): cách chỉ định template, giới hạn request/giây, JSONL, tắt cập nhật template (`-duc`) và lưu raw request/response (`-sresp`).
- [Filebeat chạy trong Docker](https://www.elastic.co/guide/en/beats/filebeat/current/running-on-docker.html): mount cấu hình, quyền đọc log và gửi sự kiện vào Elasticsearch.
- [Kibana alerting](https://www.elastic.co/docs/explore-analyze/alerting/alerts): cảnh báo chạy theo lịch để phát hiện điều kiện đã xảy ra; quyết định chặn đồng bộ vẫn ở WAF.

## Diễn giải phạm vi

Các endpoint SQLi, XSS, IDOR, CSRF, path, upload, đăng nhập và lỗi nghiệp vụ là fixture mô phỏng. Chúng không phải CVE, không đọc file host, không gọi dịch vụ thanh toán và chỉ trả dữ liệu giả. Failover đưa request thẳng tới origin trong lab; mọi kết quả ở tuyến `bypass` cần được tách khỏi đánh giá hiệu quả WAF.
