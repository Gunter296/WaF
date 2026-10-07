# Dựng finance WAF lab trên Ubuntu

Chỉ chạy với repo lab của bạn trên máy Ubuntu. Các cổng HTTP được Compose bind vào `127.0.0.1`; kết nối từ máy khác cần đường hầm SSH. Website chứa dữ liệu giả và ca kiểm thử cố ý mô phỏng lỗi.

## 1. Chuẩn bị host

Đọc và chạy **từng khối** trong [requirement.txt](../requirement.txt). File đó kiểm tra trước khi cài Git, curl, Docker Engine và Compose plugin, rồi chỉ nâng `vm.max_map_count` khi thấp hơn yêu cầu của Elasticsearch. Cần ít nhất khoảng 6 GiB RAM và 8 GiB dung lượng trống; build lần đầu có thể cần thêm dung lượng.

Nếu `sudo apt-get install docker-ce ...` báo xung đột với gói Docker cũ, xem [hướng dẫn Docker cho Ubuntu](https://docs.docker.com/engine/install/ubuntu/) trước khi thay thế gói; không xóa package/volume khi chưa biết chúng phục vụ dự án nào. Dùng `sudo docker` ở các lệnh dưới đây để không cần thêm tài khoản vào nhóm `docker`.

## 2. Lấy repo và kiểm tra cấu hình

Nếu đã có repo, vào thư mục đó; nếu chưa, clone remote hiện được cấu hình cho repo này:

```bash
git clone https://github.com/Gunter296/WaF.git
cd WaF
```

Chọn branch chứa phiên bản lab bạn muốn chạy. Các file vừa tạo hoặc còn thay đổi trên máy phát triển phải được commit và push lên branch đó trước khi Ubuntu có thể lấy qua `git clone`/`git pull`. Có thể chuyển nguyên checkout sang Ubuntu bằng cách sao chép repo nếu chưa muốn push.

Tất cả lệnh tiếp theo chạy tại **gốc repo** (nơi có thư mục `lab/`). Portal NTVDT mới là Compose override tùy chọn, nên dùng cả hai file để chạy giao diện này:

```bash
sudo docker compose -f lab/docker-compose.yml -f lab/docker-compose.portal-ui.yml config --quiet
```

Muốn đặt mật khẩu lab riêng, tạo `lab/.env` từ mẫu và sửa trước khi khởi động:

```bash
test -f lab/.env || cp lab/.env.example lab/.env
```

Compose đọc `.env` ở thư mục gốc repo theo mặc định. Vì file mẫu nằm trong `lab/`, hãy truyền `--env-file lab/.env` trong **mọi** lệnh Compose nếu bạn đổi hai biến `LAB_DB_PASSWORD` và `LAB_AUTOMATION_TOKEN`. Không cần thêm flag khi dùng giá trị mặc định chỉ dành cho máy lab.

## 3. Khởi động

```bash
sudo docker compose --env-file lab/.env -f lab/docker-compose.yml -f lab/docker-compose.portal-ui.yml up -d --build
sudo docker compose --env-file lab/.env -f lab/docker-compose.yml -f lab/docker-compose.portal-ui.yml ps
```

Lần đầu Docker cần mạng để pull image, cài dependency trong các Dockerfile và build WAF/finance. Đợi `waf`, hai biến thể finance, PostgreSQL và Elasticsearch healthy. Nếu một service chưa lên, xem log:

```bash
sudo docker compose --env-file lab/.env -f lab/docker-compose.yml -f lab/docker-compose.portal-ui.yml logs --tail=100 waf portal edge elasticsearch
```

Trên chính máy Ubuntu, mở:

| Thành phần | URL |
| --- | --- |
| Finance qua HAProxy/WAF | <http://127.0.0.1:8080> |
| Portal NTVDT | <http://127.0.0.1:8090> |
| Kibana | <http://127.0.0.1:5601> |
| Mailpit | <http://127.0.0.1:8025> |

Nếu Ubuntu là máy từ xa, mở đường hầm từ máy cá nhân: `ssh -L 8080:127.0.0.1:8080 -L 8090:127.0.0.1:8090 -L 5601:127.0.0.1:5601 -L 8025:127.0.0.1:8025 <user>@<ubuntu-host>`. Sau đó dùng các URL loopback trên máy cá nhân.

## 4. Kiểm tra luồng

```bash
curl -i http://127.0.0.1:8080/healthz
curl -i -o /dev/null -w 'finance HTTP %{http_code}\n' http://127.0.0.1:8080/
curl -i -o /dev/null -w 'portal HTTP %{http_code}\n' http://127.0.0.1:8090/
curl -fsS http://127.0.0.1:9200/_cluster/health
```

Website có tài khoản giả `an.demo@northstar.test` / `demo1234`. Host `direct.localhost` đi tới origin để lấy baseline và được ghi `lab.route=bypass`, backend/server `finance_direct/finance`; `patched.localhost` đi qua WAF tới bản Next.js đã vá. Có thể kiểm tra route bằng `curl -H 'Host: direct.localhost' http://127.0.0.1:8080/` và `curl -H 'Host: patched.localhost' http://127.0.0.1:8080/`. Khi WAF ngừng hoạt động, HAProxy chuyển tuyến `bypass` tới finance vulnerable qua `finance_waf_with_fallback/finance-fallback`; theo dõi backend/server để phân biệt với baseline.

## 5. Quét Nuclei trong mạng lab

Không cần cài Nuclei trên Ubuntu. Ví dụ quét **chỉ** fixture SQLi mô phỏng qua WAF, tối đa 2 request/giây:

```bash
sudo docker compose --env-file lab/.env -f lab/docker-compose.yml -f lab/docker-compose.portal-ui.yml --profile scanner run --rm nuclei \
  -u http://edge:8080 -H 'Host: localhost' \
  -t /templates/simulated-sqli.yaml -rl 2 -c 1 -pc 1 -ni -duc -j \
  -o /results/ubuntu-sqli.jsonl -sresp -srd /results/raw/ubuntu-sqli
```

Kết quả nằm ở `lab/runtime/results/`. Để so sánh, chạy lại lệnh với `-H 'Host: direct.localhost'` cho origin và `-H 'Host: patched.localhost'` cho bản vá; đặt tên file kết quả khác nhau mỗi lượt. Hai template CVE nằm ở `lab/nuclei-templates/`. Xem [kịch bản và ý nghĩa marker](scenarios.md): SQLi hiện là mô phỏng trên dữ liệu tĩnh, không truy vấn SQL. Đối chiếu `X-Request-ID` trong raw response với Coraza và HAProxy log; một HTTP 403 hoặc không có finding không tự chứng minh WAF đã chặn đúng payload.

## 6. Dừng, chạy lại, kiểm tra lỗi

```bash
sudo docker compose --env-file lab/.env -f lab/docker-compose.yml -f lab/docker-compose.portal-ui.yml stop
sudo docker compose --env-file lab/.env -f lab/docker-compose.yml -f lab/docker-compose.portal-ui.yml start
```

Nếu Elasticsearch không healthy, kiểm tra `sysctl vm.max_map_count`, RAM, dung lượng và `logs elasticsearch`. Nếu truy cập từ máy khác không được, kiểm tra đường hầm SSH; Compose chỉ publish loopback. Không chạy `down -v` trừ khi muốn xóa volume PostgreSQL/Elasticsearch/Filebeat của lab. Có thể xem thêm [README lab](../lab/README.md) để kiểm thử bot, learning, failover và Kibana.
