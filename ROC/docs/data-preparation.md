# Chuẩn bị dữ liệu Coraza/CRS và quy trình xác minh

Tài liệu này hướng dẫn chuẩn bị file cho công cụ offline. Nó không yêu cầu và không thực hiện sửa Elasticsearch, cấu hình Coraza hay chạy traffic lên hệ thống thật. Ví dụ trong repository là giả lập, chưa đại diện cho benchmark thực tế.

## 1. Chọn đúng đơn vị phân tích

Mỗi record phải biểu diễn một HTTP transaction. Một transaction có nhiều rule match vẫn chỉ là một hàng score tổng hợp. Không biến từng rule match thành request mới và không dùng số CVE/template làm mẫu số cho request-level metric.

Giữ khóa `run_id` + `request_id` ổn định. `request_id` mặc định đọc từ `transaction.id`. Nếu nhiều lần chạy tái sử dụng ID, `run_id` phân biệt chúng. Metadata nên có `dataset_source`, `configuration_id`, `group_id`, timestamp, method, template/CVE khi phù hợp, nhãn và nguồn gán nhãn.

Không tự cộng score theo PL và category thành tổng mới. Chỉ giữ tổng gốc đã có ý nghĩa rõ, hoặc feature dẫn xuất được khai báo tường minh như PL3+PL4. Không dùng thông tin sau response để quyết định ở cuối pha request.

## 2. Export offline từ Elasticsearch/Kibana

Xác định index/data stream/alias thực sự chứa transaction với người quản trị. **Tên data view Kibana không mặc nhiên là tên index.** Dùng cơ chế export được phép của môi trường, giới hạn đúng thời gian/run/configuration và ghi lại điều kiện lọc. Công cụ này không tự kết nối Elasticsearch và không chọn index thay bạn.

Xuất CSV UTF-8 với header rõ ràng, hoặc JSONL với một object JSON mỗi dòng. JSON Elasticsearch dạng cả response có `hits.hits` không phải JSONL transaction; cần tách mỗi hit thành một record và giữ các trường cần thiết trước khi chạy. Nếu giữ wrapper `_source`, khai báo mapping `_source.transaction.id`, `_source.crs_scores.inbound.blocking`, v.v.; công cụ không tự bóc wrapper.

Với Kibana Discover, chọn tải **CSV từng document**, giữ transaction ID, URI, score, threshold, run/config và metadata group nếu đã index. Xem [cấu hình Kibana mẫu](../configs/kibana-discover.example.yaml); header phải khớp mapping đã khai báo. Bảng Kibana đã aggregate/group-by không còn một dòng cho mỗi transaction nên không đủ để dựng ROC hoặc ghép nhãn request-level. Công cụ hiện nhận file export offline, chưa lấy trực tiếp từ Kibana API.

Một số bộ phát gắn CVE ID lên trước URI làm correlation aid, ví dụ `CVE-2021-12345/localhost`. Mặc định `uri_cve_prefix: true` tự tách prefix chuẩn `CVE-YYYY-N/`, lưu ID ở `cve_id` metadata rồi bỏ prefix khỏi URI; phần URI chỉ được ghi ra khi bật `export.include_uri`. ID CVE không sinh nhãn, không được dùng làm feature quyết định. Nếu trường cve_id tường minh khác prefix, giữ trường tường minh và ghi warning. Đặt `uri_cve_prefix: false` để tắt.

Kiểm tra export có đủ tất cả trang/batch, không bị giới hạn số bản ghi, và không chỉ bao gồm request có rule match. Nếu dataset legitimate không có log cho request không kích hoạt rule, FPR tính trên log sẽ bị selection bias. Ghi số request tool đã phát, request có audit log, request lỗi/timeout và số nhãn có tương quan được; không biến bản ghi thiếu thành score 0.

Ví dụ record JSONL (minh họa schema, không phải log thật):

```json
{"transaction":{"id":"tx-001","request":{"method":"GET","uri":"/example"},"response":{"status":200},"is_interrupted":false},"crs_score_summary":{"status":"complete"},"crs_scores":{"inbound":{"blocking":0,"detection":0,"threshold":5,"pl1":0,"pl2":0,"pl3":0,"pl4":0},"category":{"sqli":0,"xss":0,"rce":0}},"run_id":"collection-01","label":0,"dataset_source":"verified-legitimate","configuration_id":"waf-config-A","group_id":"legitimate-family-01"}
```

Chỉ đưa giá trị `0` vào record khi nguồn thực sự ghi score 0. Thiếu field, chuỗi rỗng/null hoặc score không parse được phải giữ thiếu. `summary_status=partial` không tự loại cả request: cohort chỉ loại khi thiếu score cần thiết.

Không export body, cookie, Authorization hay toàn bộ header vào bộ phân tích. Mặc định công cụ còn bỏ URI khỏi bảng chuẩn hóa và bản điều tra. Nếu bật `export.include_uri`, cân nhắc dữ liệu nhạy cảm trong query/path và thực hiện sanitize có ghi nhận trước khi nhập. Đừng để giá trị nhạy cảm vào metadata tùy chỉnh.

## 3. Nhãn riêng và bảng tương quan

Nhãn `1` nghĩa là request malicious đã được xác minh theo tiêu chí dataset; `0` là legitimate đã được xác minh; không đủ bằng chứng thì `unknown`. Request thăm dò/chuẩn bị nằm trong CVE template không mặc nhiên malicious. HTTP 200 không chứng minh exploit thành công; 403/interruption không chứng minh request malicious.

Coraza transaction ID và ID do WCB/customizednuclei cấp có thể khác nhau. Cần bảng tương quan tường minh, chẳng hạn được ghi nhận qua instrumentation/header ID trong lần thu thập được phép. Công cụ không tự inject ID. Bảng nhãn phải giữ một hàng cho mỗi khóa ghép ở phía file nhãn.

Ví dụ `labels.csv` sau khi tương quan:

```csv
collection_run,coraza_transaction_id,verified_label
collection-01,tx-001,0
collection-01,tx-002,1
collection-01,tx-003,unknown
```

```yaml
labels:
  path: ../private/labels.csv
  format: csv
  keys: {run_id: collection_run, request_id: coraza_transaction_id}
  label_field: verified_label
```

Nếu audit export có một khóa tương quan khác đã xác minh, ánh xạ nó trước:

```yaml
field_mapping:
  dataset_request_key: correlation.dataset_request_key
labels:
  path: ../private/labels.jsonl
  format: jsonl
  keys: {run_id: run_id, dataset_request_key: request_key}
  label_field: verified.label
```

`keys` luôn theo chiều **tên trường nội bộ → trường trong file nhãn**. Không ghép bằng thứ tự dòng, CVE đơn lẻ, timestamp gần nhất, hay truyền nhãn từ URI trước đó. Nhãn inline và nhãn file khác nhau là lỗi. Một khóa lặp ở file nhãn bị từ chối ngay cả khi label giống nhau để tránh join một-nhiều không mong muốn. Label không match được ghi số lượng và giữ unknown nếu không có nhãn inline.

Để phân tích từng loại tấn công, cung cấp `attack_category` từ quá trình gán nhãn đáng tin cậy và ghi `collection_manifest.attack_category_label_source`. Không suy category từ score cao nhất. SQLi-vs-legitimate chỉ đưa legitimate thật làm negative; các loại malicious khác bị loại khỏi phân tích con đó, không đổi thành negative.

## 4. Cấu hình WAF và collection manifest

Mỗi hàng nên có `configuration_id` tham chiếu một cấu hình thu thập cụ thể. Không gộp âm thầm DetectionOnly/On, phiên bản CRS hay PL khác nhau. Nếu input có nhiều cấu hình, chọn một `configuration_id` cho mỗi thí nghiệm/output riêng. Các hàng ngoài cấu hình được chọn được audit là `configuration_filter`. Hàng thiếu ID không được tự gán cấu hình dựa vào score; bổ sung từ bằng chứng lần thu thập.

Khai báo ít nhất các thông tin biết được sau trong `collection_manifest`; trường chưa biết ghi rõ `unknown` thay vì đoán:

```yaml
collection_manifest:
  coraza_version: unknown
  connector_version: unknown
  crs_version: unknown
  engine_mode: DetectionOnly
  blocking_pl: 1
  detection_pl: 4
  early_blocking: false
  reporting_level: 5
  audit_mode: 'On'
  threshold: 5
  exclusions: []
  body_limits: unknown
  dataset_version: unknown
  generator_version: unknown
  preprocessing: none
  sanitize: false
  inject_id: false
  concurrency: 1
  collection_start: '2026-01-01T00:00:00Z'
  collection_end: '2026-01-01T01:00:00Z'
  attack_category_label_source: Quy trình gán nhãn và phiên bản dữ liệu tương ứng.
```

Các giá trị trên chỉ là ví dụ cấu trúc. Mô tả body limits/exclusions nên đủ để biết chúng có ảnh hưởng tới score/khả năng quan sát request hay không. Ghi rõ tool phát, chế độ CVE/fuzz, dữ liệu đã sanitize/preprocess thế nào, có inject ID không, concurrency và phạm vi thời gian.

Để thu đủ dữ liệu score, yêu cầu tham chiếu khuyến nghị DetectionOnly, detection PL4, reporting level 5, audit On và tắt early blocking. Đây là hướng dẫn chuẩn bị một lần thu thập được phê duyệt; công cụ không tự áp dụng các cấu hình đó. Score từ DetectionOnly chỉ hỗ trợ mô phỏng quyết định, không phải chứng cứ engine đã chặn.

Nếu file thiếu threshold, có thể khai báo `baseline.fixed_threshold` từ manifest đã xác minh; không mặc định đoán là 5. Nếu threshold giữa các request khác nhau, ghi `baseline.variable_threshold_explanation` hoặc trường cùng tên trong collection manifest; kết quả được phân tầng theo threshold khi đánh giá test.

## 5. Grouping, duplicate và lỗi nguồn

Chọn group đủ rộng để giữ các payload gần trùng/cùng họ template trong cùng tập. Có thể dùng CVE khi nhiều template cùng CVE gần giống nhau. Với legitimate, dùng nguồn/họ request phù hợp; không dùng một group duy nhất cho tất cả traffic hợp lệ. Tên nhóm không được tạo riêng theo mỗi run nếu cùng họ request tái xuất hiện trong nhiều run và có nguy cơ leakage.

```yaml
field_mapping:
  request_family: verified_request_family
grouping:
  field: request_family
  allow_request_fallback: false
split: {test_size: 0.3, seed: 42}
```

Mỗi lớp cần xuất hiện trong ít nhất hai nhóm để có thể hiện diện ở cả development và test. Nhóm có thể chứa cả legitimate và malicious. Nếu thiếu nhóm, nên sửa/thu thập dữ liệu; chỉ bật `allow_request_fallback: true` khi chấp nhận và ghi rõ hạn chế của chia theo ID request riêng. Việc test có cả hai lớp trước khi loại missing không đảm bảo cohort sau loại missing còn cả hai lớp; công cụ kiểm tra lại và dừng nếu không còn.

Chọn duplicate policy rõ ràng: `error` để yêu cầu xử lý nguồn, `drop_identical` để loại lặp giống nhau, hoặc `keep_first` để giữ hàng đầu với audit. Nhãn mâu thuẫn luôn phải được sửa. Audit cho biết request bị bỏ và nguyên nhân; không tự coi duplicate là dữ liệu độc lập mới.

Nếu nguồn ghi request lỗi/timeout, đưa metadata `request_error` và `timeout` vào record/mapping. Công cụ thống kê chúng và loại khỏi ROC/tuning/test có giám sát, kèm lý do coverage; không tự coi timeout là block hay bypass. Các request không có audit score không thể được đánh giá như có score bằng 0; số liệu coverage cần phản ánh điều đó.

## 6. Chạy thí nghiệm và đọc báo cáo

Copy cấu hình mẫu sang một YAML riêng, đổi input, mapping/nhãn, configuration, grouping, manifest và `output_path`. Đặt `synthetic: false` chỉ khi dữ liệu thật. Chạy tuần tự:

```bash
crs-eval validate --config configs/experiment.yaml
crs-eval split --config configs/experiment.yaml
crs-eval explore --config configs/experiment.yaml
crs-eval tune --config configs/experiment.yaml
crs-eval evaluate --config configs/experiment.yaml
```

Trước khi xem metric, đọc `data_quality.json`, audit excluded, coverage từng lớp và số nhóm. Không so sánh ROC từng score trên cohort khác nhau như xếp hạng chính thức. Bảng `test_metrics.csv` dùng cùng cohort nên mới là so sánh trực tiếp policy. Ghi nhận policy vượt FPR target trên test; không tune lại để xóa vi phạm.

FP=0 trên ít legitimate không đủ chứng minh FPR rất nhỏ. Xem `1/N_legitimate`, số nhóm legitimate, số bootstrap hợp lệ và cảnh báo. Precision phụ thuộc prevalence mẫu. Unknown, request lỗi và mẫu thiếu score có thể làm kết luận chỉ áp dụng cho một phần traffic; ghi coverage cùng mọi kết quả.

Mọi thay đổi dataset hoặc config cần output riêng. Lưu các input, YAML, manifest, policy khóa, split và phiên bản runtime để tái lập. Nếu đã dùng test để thiết kế policy mới, phải coi test đó đã bị sử dụng cho phát triển và chuẩn bị holdout mới.

## 7. Quy trình người vận hành sau khi khóa policy

Đây là quy trình thủ công đề xuất; không có bước nào được CLI tự chạy:

1. Đọc biểu thức policy và required features trong `selected_policies.json`; kiểm tra phase, khả năng truy cập score ở cuối request và khác biệt giữa baseline mô phỏng với engine thật.
2. Chọn môi trường staging/replay được phép, backup cấu hình hiện tại, ghi người phê duyệt, phạm vi traffic, giới hạn tốc độ, thời gian thử, cơ chế dừng và rollback theo quy trình vận hành hiện có.
3. Người vận hành chuyển chính sách đã khóa sang cấu hình WAF phù hợp rồi review cách thực thi. Không giả định thay threshold tương đương hoàn toàn biểu thức AND/OR hoặc direct-block rule.
4. Replay traffic đã có nhãn, giữ nguyên tương quan request/run và ghi actual interruption từ engine trace đáng tin cậy. Ghi phiên bản, exclusions, giới hạn body và cấu hình thực chạy; không suy WAF block chỉ từ 403.
5. Chuẩn bị CSV đối chiếu tới request ban đầu và nhập cho công cụ qua `replay`. Nếu transaction ID replay khác ID cũ, cung cấp bảng tương quan; không ghép bằng thứ tự dòng.
6. So sánh prediction với actual interruption, xem FP/FN, discrepancy và lỗi/timeout. Không biến actual interruption thành nhãn malicious và không công bố request-level metric như CVE-level kết quả WCB.
7. Nếu cần triển khai thật, thực hiện quy trình phê duyệt/canary/rollback của hệ thống; công cụ offline này không thực hiện triển khai.

CSV replay hỗ trợ các trường tùy chỉnh bằng cấu hình sau; ví dụ header có thể là `original_run,original_tx,actual_interrupted`:

```yaml
replay:
  path: ../private/replay.csv
  keys: {run_id: original_run, request_id: original_tx}
  interrupted_field: actual_interrupted
  description: Actual interruption từ engine trace staging, được tương quan về transaction ban đầu.
```

File replay hiện hỗ trợ CSV, không có tùy chọn JSONL. Cả `run_id` và `request_id` phải có trong mapping; khóa phía replay phải duy nhất. Accepted values là `true`, `false`, `1`, `0`, rỗng hoặc `null`. Match thiếu giữ actual unknown. Khai báo replay thuộc cấu hình/provenance của thí nghiệm; thêm hoặc đổi file sau khi chạy yêu cầu output mới, không sửa trực tiếp manifest/policy khóa. Để đối chiếu lần replay thực hiện sau khi khóa chính sách trong một thí nghiệm mới, giữ nguyên dataset, split seed, search seed và thông số chọn policy, rồi xác minh biểu thức policy khóa mới trùng policy ban đầu trước khi diễn giải kết quả.

## Giới hạn còn lại

Công cụ xác minh cấu trúc, nhãn mâu thuẫn, tính nhất quán cohort và provenance; nó không biết nhãn đã đúng về mặt an ninh hay grouping đã bao phủ mọi near-duplicate. Không có kết nối Elasticsearch trực tiếp, streaming dữ liệu lớn, ML, tự sinh/chạy replay hoặc deployment. Bootstrap không thay thế thiết kế thu thập tốt và không giải quyết đầy đủ selection bias. Khi chưa có dữ liệu thật được chuẩn bị theo các bước trên, chỉ có thể xác nhận phần mềm và luồng chạy giả lập, không thể xác nhận hiệu quả WAF thực tế.
