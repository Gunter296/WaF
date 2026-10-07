# Hướng dẫn làm việc trong repo WaF

## Bối cảnh

Repo này chứa lab WAF với website tài chính vulnerable/patched, HAProxy, Caddy/Coraza và OWASP CRS, portal, pipeline log, learning worker và các scenario Nuclei. Hãy xác nhận cấu trúc và hành vi từ mã nguồn hiện tại; không coi phần mô tả này là bằng chứng sản phẩm đã hoạt động.

## Mục tiêu công việc

Khi được giao khắc phục lab, hãy ưu tiên:
1. Độ đúng của tuyến request và log theo X-Request-ID.
2. Fixture/scenario có kết quả phân biệt được vulnerable và patched.
3. Traffic hợp lệ và traffic tấn công có thể so sánh giữa bypass, DetectionOnly và On.
4. Positive security policy và exception có phạm vi hẹp.
5. Báo cáo có bằng chứng đối chiếu mục tiêu tuần 7–11.

## Trước khi thay đổi

- Đọc README, tài liệu lab và các file liên quan.
- Ghi nhận branch, Git status và diff hiện có. Không reset, ghi đè hoặc xóa thay đổi chưa commit của người dùng.
- Xác định lệnh chạy, mục tiêu và đường dẫn lưu kết quả từ repo; không đoán.
- Không đọc ra màn hình hoặc đưa vào báo cáo giá trị mật khẩu, token, cookie, khóa API hay nội dung `.env`.

## Quy tắc thực hiện

- Được sửa mã nguồn, cấu hình lab, template và bài thử khi yêu cầu của người dùng là bổ sung hoặc khắc phục.
- Chỉ quét service, Host và Docker network thuộc lab này. Không quét mục tiêu ngoài lab.
- Giữ payload an toàn, không phá hoại và không tạo giao dịch nghiệp vụ thật.
- Trước khi đổi runtime policy, ghi lại các giá trị hiệu lực ban đầu. Khôi phục sau khi thử và báo cáo metadata không thể phục hồi nguyên trạng.
- Không tự ý xóa volume, reset database, cài công cụ, nâng dependency, commit, push hoặc triển khai.
- Nếu cần build/recreate service để xác minh thay đổi, nêu rõ service và lý do trước khi thực hiện; tránh ảnh hưởng service ngoài lab.
- Không đánh dấu một mục tiêu là đạt nếu chỉ mới đọc mã nguồn mà chưa có bằng chứng kiểm thử phù hợp.

## Cách kiểm tra

- Kiểm tra phần bị ảnh hưởng sau mỗi thay đổi nhỏ.
- Với request WAF, đối chiếu HTTP status, marker ứng dụng, HAProxy, Caddy/Coraza và X-Request-ID khi có.
- Phân biệt WAF chặn, ứng dụng từ chối, scanner không gửi được request và thiếu bằng chứng.
- Kiểm tra cả trường hợp được phép và bị từ chối; kiểm tra trong và ngoài phạm vi exception.
- Cuối công việc, kiểm tra Git diff và Git status, tách thay đổi có sẵn ban đầu khỏi thay đổi mới.

## Báo cáo

Trả lời bằng tiếng Việt. Nêu file đã thay đổi, lý do, kết quả kiểm tra và những phần chưa xác minh.

Lập bảng so sánh các tính năng của dự án WaF với F5 BIG-IP Advanced WAF theo mục tiêu tuần 7–11. Với mỗi tính năng, ghi:
- Chức năng tương ứng trong dự án và bằng chứng thực tế.
- Chức năng của F5 dùng làm mốc so sánh, kèm nguồn tài liệu F5 nếu đã tra cứu.
- Điểm tương đồng, khác biệt và phần dự án chưa hỗ trợ.
- Mức đánh giá: Đạt / Đạt một phần / Chưa đạt / Chưa kiểm chứng.

Phân biệt chức năng đã kiểm thử với chức năng chỉ thấy trong mã nguồn. Không khẳng định dự án tương đương F5 BIG-IP hoặc đã được kiểm thử trên thiết bị F5 nếu chưa có bằng chứng.
