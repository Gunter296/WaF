# Northstar Demo Bank

Website tài chính trong `lab/finance` dùng dữ liệu giả lưu trong PostgreSQL của lab. Không có tiền, ngân hàng hoặc cổng thanh toán thật.

## Chạy

Từ thư mục repo:

```sh
docker compose -f lab/docker-compose.yml config
docker compose -f lab/docker-compose.yml up --build -d postgres finance-vulnerable finance-patched waf edge
docker compose -f lab/docker-compose.yml ps finance-vulnerable finance-patched
```

Hai service finance chờ PostgreSQL healthy, sau đó chạy migration theo phiên bản và seed idempotent. Seed tạo ba tài khoản người dùng demo, một tài khoản admin, người thụ hưởng và 60 giao dịch giả ổn định ngoài dữ liệu mẫu ban đầu. Tổng cộng có 74 giao dịch ở database mới. Chạy lại không nhân bản fixture hoặc đặt lại số dư đã thay đổi. Stack đầy đủ cùng portal và log chạy theo hướng dẫn [lab](../lab/README.md).

## Tài khoản demo

Các tài khoản người dùng seed dùng cùng mật khẩu demo `demo1234`:

| Chủ tài khoản | Email | Tài khoản |
| --- | --- | --- |
| Nguyễn Minh An | `an.demo@northstar.test` | `NS-2048-7712` |
| Trần Khánh Linh | `linh.demo@northstar.test` | `NS-3106-4821` |
| Lê Minh Quang | `quang.demo@northstar.test` | `NS-5821-9064` |

Tài khoản quản trị:

| Vai trò | Email | Tài khoản | Mật khẩu seed mặc định |
| --- | --- | --- | --- |
| Quản trị viên | `admin@northstar.test` | `NS-0000-1001` | `admin12345` |

Sau khi đăng nhập, admin được chuyển tới `/admin` để xem mọi tài khoản và lịch sử giao dịch giả. Tài khoản thường không được truy cập trang này. Mật khẩu seed người dùng và admin có thể đặt lần lượt bằng `FINANCE_DEMO_PASSWORD` và `FINANCE_ADMIN_PASSWORD` trước lần seed đầu tiên. Có thể đổi mật khẩu admin trong mục Bảo mật; seed chạy lại không ghi đè mật khẩu đã đổi. Đây là tài khoản local dùng riêng cho lab, không dùng lại ở hệ thống khác.

## Nghiệp vụ

- Trang chủ hiển thị dữ liệu tài khoản khi đã đăng nhập.
- Dashboard có số dư, giao dịch phân trang, lọc, người thụ hưởng và chuyển khoản mô phỏng.
- Chuyển khoản trừ số dư người gửi trong transaction PostgreSQL, ghi lịch sử và cộng số dư nếu người nhận là tài khoản nội bộ. Mã idempotency ngăn gửi lặp do retry.
- Chi tiết và chứng từ chỉ trả về giao dịch thuộc tài khoản trong session hiện tại.
- Đối soát nhận biểu thức giới hạn theo cú pháp merchant, khoảng tiền và khoảng ngày. Parser từ chối cú pháp ngoài grammar; merchant, tiền và ngày đi vào query PostgreSQL bằng tham số. Điều kiện `account_id` lấy từ session luôn có trong truy vấn.
- Login xác minh scrypt trên server, cấp session ngẫu nhiên 256-bit và chỉ lưu SHA-256 digest trong DB. Cookie HttpOnly, SameSite=Lax, Secure khi request dùng HTTPS, hết hạn sau 12 giờ; logout xóa session.
- Trang đăng nhập có liên kết đăng ký tài khoản mới. Tài khoản mới có số dư 0 VND và mật khẩu tối thiểu 10 ký tự; không có giao dịch hoặc người thụ hưởng mặc định.
- Người dùng đã đăng nhập mở mục `Bảo mật` trên thanh điều hướng để đổi mật khẩu. Server kiểm tra mật khẩu hiện tại, thay salt/hash và thu hồi các session cũ trước khi cấp session mới. Mật khẩu không được ghi log.
- Admin có vai trò lưu trong PostgreSQL và được kiểm tra ở server khi render trang `/admin`. Bảng quản trị hiển thị toàn bộ tài khoản và giao dịch finance lab; không cấp vai trò admin từ form đăng ký.

## Kiểm thử cục bộ

Parser và tuning có thể kiểm tra bằng:

```sh
node --test lab/finance/tests/reconcile-filter.test.mjs
node --test lab/portal-ui/tuning.test.mjs
```

Kiểm thử tích hợp trong finance container dùng service PostgreSQL và tài khoản An:

```sh
docker compose -f lab/docker-compose.yml exec -T finance-vulnerable sh -lc 'FINANCE_TEST_PG=1 FINANCE_TEST_URL=http://finance-vulnerable:3000 FINANCE_TEST_EMAIL=an.demo@northstar.test FINANCE_TEST_PASSWORD="${FINANCE_DEMO_PASSWORD:-demo1234}" FINANCE_ADMIN_EMAIL=admin@northstar.test FINANCE_ADMIN_PASSWORD="${FINANCE_ADMIN_PASSWORD:-admin12345}" npm test'
```

Nếu không đặt `FINANCE_DEMO_PASSWORD`, seed local dùng giá trị demo trong bảng trên. Kiểm thử chuyển khoản tạo hai dòng lịch sử giả lập nhưng trả số dư của hai tài khoản về trước khi kết thúc.

Kiểm thử qua edge có thể chạy theo từng trạng thái policy bằng `FINANCE_WAF_STAGE=before`, sau khi admin đã lưu ngoại lệ bằng `FINANCE_WAF_STAGE=after`, và sau khi thu hồi bằng `FINANCE_WAF_STAGE=revoked` trước lệnh `npm test`.

Traffic bình thường và ca đối soát qua edge được tạo bằng:

```sh
cd lab/finance
npm run traffic -- before
```

Script ghi status HTTP, X-Request-ID và metadata Coraza tìm thấy trong Elasticsearch vào `lab/runtime/results/finance-tuning-*.json`. Nó không ghi cookie hay mật khẩu. Hướng dẫn thao tác ngoại lệ và chạy lại sau tuning nằm trong [tài liệu quản trị](finance-tuning-admin.md).

## Đọc log

Mỗi log nghiệp vụ JSON có request ID từ HAProxy, account ID giả lập, route, action, kết quả, policy version và số lượng kết quả khi phù hợp. Không ghi mật khẩu, cookie, session, toàn bộ biểu thức hoặc nội dung chuyển khoản nguyên văn. Tra `http.request.id` trong portal hoặc Kibana để đối chiếu sự kiện finance với HAProxy và Coraza.

## Giới hạn

Đây là bài lab đơn giản. Nó không có MFA, KYC, thanh toán thật, xử lý tranh chấp, bảo đảm sổ cái pháp lý hoặc kiểm định bảo mật độc lập. Cơ chế WAF không thay thế xác thực, phân quyền, parser giới hạn cú pháp và truy vấn tham số của ứng dụng.
