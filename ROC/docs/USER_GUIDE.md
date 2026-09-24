# Hướng dẫn sử dụng CRS Threshold Evaluation

Công cụ đánh giá **offline theo từng HTTP transaction**. Nhãn `1` là malicious, nhãn `0` là legitimate; predicted positive nghĩa là chính sách **đề xuất chặn**. Điểm từ `DetectionOnly` chỉ dùng để mô phỏng. Dữ liệu trong `examples/` là **giả lập**; mọi con số sinh ra từ ví dụ này không phải benchmark WAF thực tế.

## 1. Cài đặt

Yêu cầu Python 3.10 trở lên. Từ thư mục gốc project:

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -e ".[test]"
```

Trên Linux/macOS, dùng `.venv/bin/python` thay cho `.venv\Scripts\python.exe`. Package tạo lệnh `crs-eval`; có thể dùng `python -m crs_eval` tương đương.

## 2. Chạy thử toàn bộ luồng

File `examples/synthetic.jsonl` đã có sẵn. Nếu cần tạo lại cùng dữ liệu, chạy `python examples/generate_synthetic.py`. Cấu hình `configs/experiment.example.yaml` ghi rõ `synthetic: true` và dùng đường dẫn tính từ thư mục chứa chính file YAML.

```powershell
.venv\Scripts\crs-eval.exe validate --config configs/experiment.example.yaml
.venv\Scripts\crs-eval.exe split --config configs/experiment.example.yaml
.venv\Scripts\crs-eval.exe explore --config configs/experiment.example.yaml
.venv\Scripts\crs-eval.exe tune --config configs/experiment.example.yaml
.venv\Scripts\crs-eval.exe evaluate --config configs/experiment.example.yaml
```

Mở `outputs/synthetic-demo/report.html` bằng trình duyệt; báo cáo chứa ảnh nhúng, xem được khi không có mạng. Muốn chạy thí nghiệm khác, sao chép YAML, đổi `input.paths`, `configuration_id`, `synthetic: false`, manifest thu thập và `output_path`. Thư mục output đã có dữ liệu của cấu hình hoặc input khác sẽ bị từ chối để tránh ghi đè thí nghiệm.

## 3. Chuẩn bị dữ liệu thật

Xuất audit log Coraza dạng JSONL hoặc CSV UTF-8 sang **file offline**. Tên Kibana data view không mặc định là tên Elasticsearch index; công cụ chỉ đọc file được nêu trong `input.paths`. JSONL chấp nhận object lồng nhau; CSV chấp nhận cột có tên chứa dấu chấm. Ánh xạ tên khác trong `field_mapping`; ví dụ:

```yaml
input:
  paths: [../data/audit.jsonl]
  format: jsonl
field_mapping:
  request_id: transaction.id
  inbound_blocking: crs_scores.inbound.blocking
  inbound_threshold: crs_scores.inbound.threshold
```

Mỗi dòng phải là một transaction; cần `request_id` ổn định và nên có `run_id`. Chọn một `configuration_id` rõ ràng; nếu file trộn cấu hình, chạy riêng từng cấu hình. `label` phải do nguồn xác minh cung cấp (`0`, `1` hoặc `unknown`). Công cụ không suy nhãn từ score, URI, 403, `interrupted`, CVE ID hay template. Nếu nhãn nằm ở file khác, cấu hình `labels` và các khóa tương quan ổn định:

```yaml
labels:
  path: ../data/labels.csv
  format: csv
  keys:
    run_id: run_id
    request_id: correlated_transaction_id
  label_field: label
```

Khi ID của tool phát request khác transaction ID Coraza, hãy chuẩn bị **bảng tương quan ID** trước; không ghép theo thứ tự dòng, thời gian gần nhất hoặc CVE ID đơn lẻ. File nhãn có khóa lặp, nhãn mâu thuẫn hoặc nhãn ngoài `0/1/unknown` sẽ gây lỗi kèm báo cáo chất lượng.

Với Kibana, ưu tiên **Discover → Download CSV → CSV (per document)** cho đúng các transaction đã lọc. Có thể dùng trực tiếp cột phẳng như `transaction.id`, `transaction.request.uri`, `crs_scores.inbound.blocking`; ánh xạ theo đúng header CSV. Cấu hình mẫu đầy đủ nằm ở [kibana-discover.example.yaml](../configs/kibana-discover.example.yaml). Bảng visualization đã aggregate như `count by URI`, histogram, hoặc tỷ lệ tổng hợp không đủ để chạy đánh giá request-level: hãy export từng document, giữ request ID và score, rồi ghép label/group qua correlation key. Công cụ chưa gọi Kibana/Elasticsearch API trực tiếp.

Nếu URI có dạng `CVE-2021-12345/localhost`, bật `uri_cve_prefix: true` (mặc định): loader tự tách prefix CVE thành metadata `cve_id=CVE-2021-12345` và giữ phần URI còn lại là `localhost`. Có thể có `/` đầu chuỗi; chỉ prefix khớp dạng CVE chuẩn mới bị tách. Nếu trường `cve_id` riêng đã có nhưng bất đồng, giữ giá trị explicit và ghi warning. Tách prefix **không gán malicious label** và CVE ID vẫn bị cấm làm feature quyết định. `export.include_uri: false` giữ URI khỏi normalized/output, nhưng việc tách CVE vẫn diễn ra trước khi bỏ URI. Đặt `uri_cve_prefix: false` nếu muốn giữ nguyên cả chuỗi.

Gán `group_id` theo họ payload/template/CVE cho traffic malicious và theo họ request/nguồn phù hợp cho traffic legitimate. Split được thực hiện theo nhóm để họ tương tự không xuất hiện ở cả development và test. Khi thiếu group, mặc định lệnh sẽ dừng; chỉ bật `grouping.allow_request_fallback: true` nếu chấp nhận cảnh báo về nguy cơ rò rỉ gần trùng. Không gom tất cả legitimate thành một group. Unknown được giữ trong thống kê chất lượng và loại khỏi supervised evaluation.

Lưu manifest thu thập trong `collection_manifest`: phiên bản Coraza/connector/CRS, engine mode, blocking/detection PL, early blocking, reporting level, audit mode, threshold, exclusions, body limits, phiên bản dữ liệu và tool phát, preprocessing/sanitize/inject-id, concurrency và thời gian thu thập. Ghi nguồn gán `attack_category` bằng `attack_category_label_source` nếu muốn phân tích theo loại tấn công. Hướng dẫn thu thập DetectionOnly, detection PL4, reporting level 5, audit On, early blocking tắt là hướng dẫn ngoài công cụ; chương trình không thay cấu hình WAF.

Mặc định quyết định dùng các score inbound. Score tùy biến cần khai báo trong `score_fields`, ánh xạ trong `field_mapping`, `feature_metadata.<tên>.phase: inbound` và `meaning`. Có thể khai báo feature dẫn xuất tường minh như tổng PL3 + PL4; điều này không thay đổi điểm CRS gốc. Không chọn URI, CVE ID, status, `interrupted` hoặc nhãn nguồn làm feature. `baseline.fixed_threshold` chỉ dùng để **điền threshold còn thiếu**; threshold ghi trong từng request vẫn có hiệu lực. Nếu threshold thay đổi theo dòng, khai báo `baseline.variable_threshold_explanation`.

`duplicate_handling` nhận `error` (mặc định), `drop_identical` hoặc `keep_first`. Mọi bản ghi bỏ đi có lý do trong `excluded_records.csv`; bản ghi mâu thuẫn và nhãn mâu thuẫn được nêu trong báo cáo. Score không hợp lệ hoặc thiếu tiếp tục là missing; không đổi thành zero. Request có `request_error` hoặc `timeout: true` trong nguồn được giữ trong báo cáo chất lượng nhưng loại khỏi ROC/tuning/test có giám sát, kèm lý do coverage; chúng không tự được tính là bypass hay block. URI chỉ được đưa vào bản xuất điều tra nếu đặt `export.include_uri: true`. Cookie, Authorization, header và body không được đưa vào dữ liệu chuẩn hóa.

## 4. Ý nghĩa từng lệnh và kết quả

| Lệnh | Công việc | File chính |
|---|---|---|
| `validate` | Đọc, ghép nhãn, chuẩn hóa, kiểm tra cấu hình/dữ liệu và duplicate | `data_quality.json`, `normalized_data.csv`, `excluded_records.csv` |
| `split` | Chia nhóm development/test theo seed, lưu khóa request và fingerprint | `split_manifest.csv` |
| `explore` | ROC, ROC-AUC, PR, Average Precision và **toàn bộ** ngưỡng từ development | `development_score_metrics.csv`, `development_threshold_candidates.csv`, ba ảnh ROC/PR |
| `tune` | Tìm threshold đơn và chính sách AND/OR trên development; khóa JSON | `policy_candidates.csv`, `policy_pareto.csv`, `selected_policies.json`, `policy_tradeoffs.png` |
| `evaluate` | Nạp chính sách khóa, đánh giá test cùng cohort, bootstrap và điều tra lỗi | `test_metrics.csv`, `test_predictions.csv`, `false_positives.csv`, `false_negatives.csv`, `policy_disagreements.csv`, `bootstrap_intervals.json`, `report.html` |

`experiment_manifest.json` chứa hash cấu hình/input, phiên bản thư viện, split và warnings. `actual_interruption_comparison.csv` là đối chiếu dự đoán với audit/replay, không phải nhãn ground truth. `test_group_metrics.csv` cho các phân tầng có dữ liệu. `excluded_development.csv` và `excluded_test.csv` giải thích mất coverage; `excluded_records.csv` gộp audit trail. Tất cả CSV metric có `split`, `cohort`, số mẫu và mẫu số.

Trong `development_threshold_candidates.csv`, `threshold_kind=all/none` là sentinel JSON an toàn, thể hiện chặn tất cả/không chặn ai. Một chính sách nhiều threshold tạo **một điểm** TPR/FPR; scatter/Pareto không phải ROC curve liên tục. Average Precision (AP) dùng `sklearn.metrics.average_precision_score`, không phải diện tích hình thang của PR. Chính sách đạt Recall development cao nhất trong ràng buộc FPR được chọn; hòa ưu tiên FPR thấp, số điều kiện ít rồi thứ tự cố định. Random search với `max_evaluations` và seed chỉ khảo sát một phần không gian, không bảo đảm tối ưu toàn cục. Test không được dùng để chọn lại threshold, kể cả khi FPR test vượt mục tiêu.

`test_metrics.csv` chứa TP/FP/TN/FN, Recall, FPR, precision, specificity, F1 và chênh lệch so baseline. Khi mẫu số bằng 0, metric là `null` kèm `undefined_reasons`. `bootstrap_intervals.json` là paired group bootstrap: cùng mẫu nhóm cho mọi chính sách, bỏ replicate thiếu một lớp, không tune lại. Khi FP=0, khoảng bootstrap có thể suy biến; đây không phải bằng chứng FPR thật bằng 0. Xem số legitimate request/group, độ phân giải FPR thực nghiệm `1/N_legitimate` và cảnh báo thiếu mẫu. Precision phụ thuộc tỷ lệ malicious của dataset, không suy rộng trực tiếp ra production.

## 5. Đối chiếu replay và triển khai có kiểm soát

V1 không chạy replay. Nếu có file kết quả replay riêng, có thể thêm:

```yaml
replay:
  path: ../data/replay.csv
  keys:
    run_id: run_id
    request_id: request_id
  interrupted_field: actual_interrupted
  description: Engine interruption from controlled replay with stable request IDs
```

File replay phải có khóa duy nhất và trường interruption dạng boolean; không diễn giải 403 là WAF block. Đối chiếu request-level này không tương đương chỉ số CVE/template-level của WCB. Khi muốn xem xét triển khai, con người cần rà lại FP/FN, tập test, manifest, policy đã khóa, rồi áp dụng/replay trong môi trường được kiểm soát và đo interruption thực tế; công cụ không tự ghi policy vào Coraza hoặc thay hệ thống thật.

## 6. Kiểm thử

```powershell
.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider
```

Giới hạn: chưa có benchmark trên audit log thật, chưa kết nối Elasticsearch trực tiếp, chưa tự triển khai WAF/replay, chưa làm ML. Hiệu quả chỉ mô tả traffic trong dataset đã đánh giá; HTTP 200 từ backend không chứng minh exploit thành công. Đọc thêm [README](../README.md), [chuẩn bị dữ liệu](data-preparation.md) và [bản đồ file/folder](PROJECT_MAP.md).
