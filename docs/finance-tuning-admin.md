# Quản trị ca đối soát giao dịch

Tài liệu này dành cho quản trị viên lab. Không đưa đáp án rule hoặc thao tác exception lên giao diện người dùng.

## Phạm vi

Tình huống mới duy nhất là biểu thức đối soát tại `POST /api/transactions/reconcile/search`, tham số `expression`. Seed có merchant `O'Connor Market`; parser chấp nhận tên này trong chuỗi có nháy đơn được escape hoặc chuỗi nháy kép. Mọi truy vấn vẫn giới hạn theo account trong session và dùng tham số DB.

Route `/lab/ssrf/{host}/{path}` và cookie tĩnh `lab-session=demo-session` đã được gỡ. Trang `/lab` không còn liệt kê endpoint kiểm thử. Một số fixture cũ dưới `/api/lab/*` vẫn trả marker giả cho bài học cũ; chúng không đọc hoặc thay đổi bảng tài chính, không tạo session và không xuất hiện trong điều hướng nghiệp vụ. Chỉ dùng chúng trong lượt lab riêng. Template cũ có thể còn trong repo tham chiếu nhưng không phải đáp án cho ca tuning này.

## Ghi nhận false positive

1. Khởi động stack đầy đủ và xác nhận WAF `On`, blocking PL 1 trong portal. Không thay rule toàn cục hoặc tắt CRS.
2. Từ repo, chạy:

   ```sh
   cd lab/finance
   npm run traffic -- before
   ```

3. Chỉ coi ca là false positive CRS khi script ghi HTTP 403 và tìm được document Coraza cùng request ID, rule ID `942xxx`, target chứa `ARGS:expression`, `transaction.is_interrupted=true` hoặc quyết định block. Không suy ra từ status 403 đơn lẻ. Kết quả được ghi ở `lab/runtime/results/finance-tuning-before-*.json`.
4. Nếu không có rule và target cùng request ID, không tạo exception theo phỏng đoán. Kiểm tra log, Host và request parser; điều chỉnh biểu thức hợp lệ trong phạm vi bộ seed, chạy lại và lưu kết quả thực tế.

Script gửi login demo, đọc tài khoản và giao dịch bình thường, hai cách viết biểu thức hợp lệ, một biểu thức ngoài grammar, truy vấn giao dịch của tài khoản khác và một login không hợp lệ. Nó không ghi cookie hoặc mật khẩu vào artifact.

## Tạo ngoại lệ hẹp

Trong portal, tại phần tuning, tạo ngoại lệ với các giá trị lấy từ bằng chứng thực tế:

| Trường | Giá trị |
| --- | --- |
| Host | Host chính xác trong request, thường là `localhost` |
| Method | `POST` |
| Route | `/api/transactions/reconcile/search` |
| Rule ID | Rule `942xxx` đã thấy trong Coraza audit |
| Phạm vi | Target |
| Target | `ARGS:expression` |
| Lý do | Mô tả merchant có dấu nháy hợp lệ và request ID chứng minh false positive |
| Thời hạn | Ngắn, tối đa 30 ngày |

Lưu và áp dụng policy. Portal kiểm tra Host theo allowlist chính xác, method, path, rule, target, reason và expiry; sinh `ctl:ruleRemoveTargetById` chỉ trong request khớp. Audit ghi `tuning_exception_created` cùng metadata của ngoại lệ. Sau khi áp dụng, chạy `npm run traffic -- after`: biểu thức hợp lệ cần HTTP 200, còn biểu thức ngoài grammar bị parser từ chối hoặc WAF chặn. Login injection và truy cập giao dịch của account khác vẫn bị từ chối.

Thu hồi tại portal bằng nút thu hồi, lưu và áp dụng policy. Audit ghi `tuning_exception_revoked`. Chạy `npm run traffic -- revoked`; biểu thức trước đó cần lại bị WAF chặn. Policy và CRS tổng thể tiếp tục bật.

## Phân chia lớp bảo vệ

- Coraza/CRS nhận diện payload theo rule và quyết định chặn trước ứng dụng. Ngoại lệ chỉ bỏ đúng target cho một Host, method, route, rule và thời hạn.
- Parser chỉ chấp nhận cấu trúc biểu thức đã định nghĩa; nó không chuyển biểu thức người dùng thành SQL.
- PostgreSQL nhận giá trị bằng bind parameter. `account_id` luôn lấy từ session server, không từ request.
- Session ngẫu nhiên, cookie HttpOnly, hết hạn, logout và kiểm tra sở hữu bản ghi thuộc ứng dụng. WAF không cấp quyền truy cập dữ liệu.

Artifact chỉ ghi request ID, status, rule IDs, target names và quyết định. Bản thân request mẫu chỉ dùng fixture giả trong lab.
