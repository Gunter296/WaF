# Đánh giá threshold Coraza + OWASP CRS

Công cụ Python phân tích **offline ở mức từng HTTP transaction**: kiểm tra dữ liệu, chia development/test theo nhóm, phân tích ROC/PR, tìm threshold đơn và biểu thức AND/OR, sau đó đánh giá các chính sách đã khóa trên test. Công cụ giữ nguyên score CRS; không huấn luyện ML và không thay đổi WAF hay Elasticsearch.

**Dữ liệu trong `examples/` hoàn toàn giả lập. Các kết quả sinh từ cấu hình mẫu chỉ minh họa luồng chạy; chưa thực hiện benchmark trên Coraza/CRS thật.**

## Cài đặt và chạy toàn bộ ví dụ

Cần Python 3.10 trở lên. Chạy từ thư mục project:

```bash
python -m venv .venv
```

Kích hoạt môi trường bằng `source .venv/bin/activate` trên Linux/macOS, hoặc `.venv\Scripts\Activate.ps1` trong PowerShell. Sau đó:

```bash
python -m pip install -e ".[test]"
crs-eval validate --config configs/experiment.example.yaml
crs-eval split --config configs/experiment.example.yaml
crs-eval explore --config configs/experiment.example.yaml
crs-eval tune --config configs/experiment.example.yaml
crs-eval evaluate --config configs/experiment.example.yaml
```

Có thể thay `crs-eval` bằng `python -m crs_eval.cli`. Mở `outputs/synthetic-demo/report.html` để xem báo cáo tự chứa ảnh, không cần Internet/CDN. Dataset CSV và JSONL tương đương đã có sẵn; `python examples/generate_synthetic.py` tạo lại dữ liệu giả bằng seed cố định.

Tài liệu sử dụng chi tiết: [Hướng dẫn từng bước](docs/USER_GUIDE.md). Chú thích vai trò của từng file và thư mục: [Bản đồ project](docs/PROJECT_MAP.md).

Mỗi lệnh trả một tóm tắt JSON; lỗi cấu hình/dữ liệu trả exit code `2` kèm thông báo. `validate` lưu báo cáo chất lượng cả khi phát hiện lỗi dữ liệu có thể báo cáo được. Trình tự cần thiết là `split` trước `explore`/`tune`; `evaluate` yêu cầu đã `explore` và `tune`.

## Quy trình và ý nghĩa kết quả

1. `validate`: đọc CSV UTF-8 hoặc JSONL, ánh xạ trường, ghép nhãn có kiểm tra khóa, chuẩn hóa số/boolean, kiểm tra cấu hình WAF, nhãn, nhóm và duplicate. Không điền score thiếu bằng `0`.
2. `split`: chia nguyên nhóm vào development hoặc test, bảo đảm không giao nhóm và mỗi tập có hai lớp. Unknown được đánh dấu `excluded`.
3. `explore`: ROC-AUC, Precision–Recall, Average Precision và toàn bộ threshold của từng score trên development. Mỗi score có thể dùng cohort khả dụng riêng, vì vậy không dùng các dòng này để xếp hạng như thể cùng mẫu số.
4. `tune`: lập một cohort development đủ dữ liệu cho mọi chính sách cần so sánh, tìm chính sách dưới ràng buộc empirical FPR, xuất toàn bộ candidates, Pareto và chính sách khóa. Tất cả candidate values lấy từ development.
5. `evaluate`: kiểm tra khóa và provenance, áp dụng chính sách đã lưu lên cùng cohort test, xuất metric, uncertainty, FP/FN, disagreement và báo cáo. Lệnh này không gọi tuning và không sửa threshold khi test FPR vượt mục tiêu.

Positive là request có nhãn malicious (`1`); predicted positive là chính sách đề xuất chặn. Baseline tên `crs_anomaly_baseline_simulated`, với điều kiện `inbound_blocking >= inbound_threshold`. Threshold cố định chỉ được dùng khi được khai báo rõ. Đây không phải mô phỏng đầy đủ engine: direct-block rule, body/parser limit, exclusions, early interruption có thể làm kết quả thực tế khác.

Score càng cao luôn được hiểu là bằng chứng tấn công mạnh hơn. URI, CVE/template ID, HTTP status, `interrupted`, nguồn dữ liệu và nhãn không được dùng làm đặc trưng quyết định. Chỉ score đã biết khả dụng ở pha inbound được dùng cho chính sách inbound; score outbound/combined có thể lưu như dữ liệu bổ sung nhưng không đi vào quyết định này. Không cộng mọi score PL và category thành một tổng mới vì cùng rule có thể đóng góp vào nhiều đầu điểm.

## Cấu hình thí nghiệm

Tất cả đường dẫn tương đối trong YAML được tính từ **thư mục chứa file YAML**, bao gồm input, labels, replay và output. Xem cấu hình đầy đủ tại [`configs/experiment.example.yaml`](configs/experiment.example.yaml).

Để nạp CSV export từng document từ Kibana Discover, xem [`configs/kibana-discover.example.yaml`](configs/kibana-discover.example.yaml). Export đã tổng hợp theo URI/score không thể dùng làm dữ liệu đánh giá request-level. Prefix URI đúng mẫu `CVE-YYYY-N/uri` được tách tự động thành metadata `cve_id` và URI gốc; thao tác này không tạo nhãn malicious.

| Khóa | Ý nghĩa / mặc định |
|---|---|
| `input.paths`, `input.format` | Danh sách file offline; format `csv` hoặc `jsonl` |
| `field_mapping` | Tên nội bộ → tên cột hoặc đường dẫn JSON; các mục khai báo ghi đè mapping mặc định |
| `uri_cve_prefix` | Mặc định `true`; tách tiền tố URI dạng `CVE-YYYY-N/` sang metadata `cve_id` |
| `labels` | File nhãn riêng tùy chọn; `path`, `format`, `keys`, `label_field` |
| `configuration_id` | Chọn đúng một cấu hình; bắt buộc lựa chọn/chuẩn bị lại khi dữ liệu trộn cấu hình hoặc thiếu ID |
| `features` | Score phân tích và tìm threshold; mặc định inbound blocking/detection, PL1–4 và các category chuẩn |
| `score_fields` | Score bổ sung cần chuẩn hóa, mặc định `[]` |
| `feature_metadata` | Score tùy chỉnh cần `phase: inbound` và `meaning` trước khi dùng quyết định |
| `derived_features` | Phép `sum` được khai báo tường minh trên các score gốc; không sửa score CRS |
| `grouping.field` | Trường nhóm, mặc định `group_id` |
| `grouping.allow_request_fallback` | Mặc định `false`; override rõ ràng khi thiếu nhóm, có cảnh báo nguy cơ leakage |
| `split` | `test_size: 0.3`, `seed: 42` |
| `baseline` | `fixed_threshold` tùy chọn; `variable_threshold_explanation` khi threshold khác nhau giữa các request |
| `fpr_targets` | Mặc định `[0.001, 0.005, 0.01]`; tham số thí nghiệm, không phải khuyến nghị triển khai |
| `policy_families` | Các biểu thức AND/OR cấu trúc YAML; mặc định `[]`, các họ score đơn được thêm tự động |
| `search` | `max_evaluations: 2000`, `seed` mặc định bằng split seed |
| `bootstrap` | `iterations: 1000`, `confidence: 0.95`, seed mặc định bằng split seed; mẫu YAML dùng 500 iterations |
| `duplicate_handling` | `error` (mặc định), `drop_identical` hoặc `keep_first` |
| `export.include_uri` | Mặc định `false` |
| `collection_manifest` | Thông tin lần thu thập, phiên bản WAF/dataset/tool, nguồn nhãn loại tấn công |
| `synthetic` | Mặc định `false`; phải đặt `true` cho dữ liệu giả |
| `output_path` | Mặc định `../outputs/experiment`; mỗi thí nghiệm thay đổi cần thư mục riêng |

Score tùy chỉnh cần được khai báo trong `score_fields`, ánh xạ bằng `field_mapping` nếu tên ngoài khác tên nội bộ, rồi thêm vào `features` khi muốn tìm threshold. Mọi feature xuất hiện trong một policy family cũng phải có trong `features`.

Ví dụ feature dẫn xuất và họ chính sách:

```yaml
features: [inbound_blocking, sqli, rce, high_pl]
derived_features:
  high_pl: {sum: [pl3, pl4]}
policy_families:
  - name: inbound_category_pl
    expression:
      op: or
      children:
        - {feature: inbound_blocking, parameter: T_total}
        - {feature: sqli, parameter: T_sqli}
        - op: and
          children:
            - {feature: high_pl, parameter: T_high}
            - {feature: rce, parameter: T_rce}
```

Thiếu một thành phần thì tổng dẫn xuất cũng thiếu. V1 hỗ trợ tổng các score gốc được chỉ định, không hỗ trợ công thức Python tùy ý. Policy dùng AST gồm `op: and/or`, `children`, lá `feature` + `parameter` hoặc `threshold`, và `constant: true/false`; không dùng `eval`.

## Schema, nhãn và chất lượng dữ liệu

Một dòng phải là **một transaction**, không phải một rule match, CVE hay template. Mapping mặc định:

| Tên nội bộ | Trường ngoài |
|---|---|
| `request_id` | `transaction.id` |
| `timestamp` | `@timestamp` |
| `uri` | `transaction.request.uri` |
| `method` | `transaction.request.method` |
| `http_status` | `transaction.response.status` |
| `interrupted` | `transaction.is_interrupted` |
| `summary_status` | `crs_score_summary.status` |
| `inbound_blocking` | `crs_scores.inbound.blocking` |
| `inbound_detection` | `crs_scores.inbound.detection` |
| `inbound_threshold` | `crs_scores.inbound.threshold` |
| `pl1`, `pl2`, `pl3`, `pl4` | `crs_scores.inbound.pl1` … `crs_scores.inbound.pl4` |
| `sqli`, `xss`, `rce`, `lfi`, `rfi`, `phpi`, `http`, `sess` | `crs_scores.category.<tên score>` |
| `run_id`, `label`, `dataset_source`, `template_id`, `cve_id`, `group_id`, `attack_category`, `configuration_id`, `request_error`, `timeout` | Cột cùng tên |

JSON lồng nhau và CSV/cột JSON có dấu chấm đều được hỗ trợ. Khi cùng có cả khóa dấu chấm chính xác và đường dẫn lồng nhau, khóa chính xác được ưu tiên. CSV có cột nội bộ như `inbound_blocking` cần mapping tương ứng `inbound_blocking: inbound_blocking` nếu không dùng tên mặc định.

Nhãn là `0`, `1`, hoặc thiếu/`unknown`. Không suy nhãn từ score, 403, interruption, tiền tố CVE hay template. Coraza transaction ID không mặc nhiên bằng request ID của tool phát dữ liệu. File nhãn riêng phải có khóa tương quan xác minh được:

```yaml
labels:
  path: ../private/labels.csv
  format: csv
  keys:
    run_id: collection_run
    request_id: coraza_transaction_id
  label_field: verified_label
```

Khóa phía trái là trường nội bộ, phía phải là cột/đường dẫn trong file nhãn. Thiếu match giữ nhãn inline đã có hoặc unknown; không gán nhãn theo thứ tự dòng. Nhãn inline và nhãn ghép mâu thuẫn, hoặc khóa file nhãn trùng tạo join một-nhiều, đều bị từ chối. Không ghép chỉ bằng CVE/template/timestamp. Hướng dẫn tương quan và export Elasticsearch nằm trong [`docs/data-preparation.md`](docs/data-preparation.md).

`data_quality.json` ghi số document, transaction, lớp, nhãn không match/mâu thuẫn, missing/non-numeric từng score, `summary_status`, duplicate, số mẫu/nhóm theo nguồn/cấu hình, thống kê score theo nhãn, request lỗi và timeout đã có trong nguồn. Request có lỗi/timeout nguồn được loại khỏi ROC/tuning/test có giám sát và ghi lý do coverage; không tự trở thành bypass hay block. Unknown vẫn nằm trong `normalized_data.csv` nhưng không tham gia đánh giá có giám sát.

`summary_status=partial` dùng được nếu đủ score cho phép đánh giá. Score hằng số được đánh dấu; score toàn thiếu bị ghi lý do loại. Quyết định bỏ score khỏi tuning dựa trên **development**, không dựa vào test. `explore` ghi coverage riêng từng score; so sánh chính sách dùng một cohort chung và xuất coverage từng lớp cùng lý do loại. Một mẫu có thể thiếu nhiều score nên tổng số lý do loại có thể lớn hơn số mẫu bị loại.

Duplicate được kiểm tra theo `(run_id, request_id)`: `error` dừng; `drop_identical` chỉ loại bản ghi chuẩn hóa giống nhau; `keep_first` giữ bản đầu theo thứ tự input và ghi audit cho bản bỏ, kể cả khác score. **Nhãn mâu thuẫn vẫn là lỗi dù chọn `keep_first`.** Thiếu `run_id` được ghi cảnh báo và dùng `unspecified`; nên cung cấp run ID thật để tránh đụng transaction giữa các lần thu thập.

## Chia nhóm và chống rò rỉ

Nhóm phải phản ánh họ payload/request gần trùng. Có thể nhóm nhiều template cùng CVE vào cùng một nhóm rộng hơn. Legitimate cũng cần nhóm theo nguồn/họ request; không gom toàn bộ legitimate vào một nhóm chỉ vì không có CVE. Cùng chuỗi `group_id` qua nhiều run vẫn là cùng nhóm.

Splitter dùng seed, label và kích thước nhóm để tìm cách chia gần tỷ lệ mong muốn; không đọc giá trị score để quyết định. Tỷ lệ thực tế có thể khác `test_size` vì giữ nguyên nhóm. Nó lưu ID, group, split, fingerprint và số lớp/nhóm. Không đủ nhóm độc lập có hai lớp ở cả hai tập thì dừng với hướng sửa. Unknown không vào development/test.

Thiếu group mặc định là lỗi. `grouping.allow_request_fallback: true` tạo nhóm riêng theo `(run_id, request_id)` cho các hàng thiếu và ghi cảnh báo. Đây chỉ là override có chủ ý; nó không bảo đảm các payload gần trùng được tách an toàn. Công cụ không tự phát hiện near-duplicate.

Test chỉ dùng sau khi khóa policy. Tạo thư mục output mới không làm một test đã xem trở thành test độc lập mới; nếu dùng kết quả test để thiết kế lại policy, cần một holdout mới hoặc thiết kế đánh giá khác.

## Threshold, tìm kiếm và metric

Threshold hữu hạn dùng chính xác điều kiện `score >= threshold`, kể cả khi bằng ngưỡng. Tập candidate là tất cả giá trị score khác nhau trên development cùng hai sentinel JSON an toàn: `"all"` (luôn chặn), `"none"` (không chặn). CSV threshold dùng `threshold_kind` và giá trị trống cho sentinel; JSON không chứa `NaN`/`Infinity`.

Trong OR, sentinel `none` tắt lá; trong AND, sentinel `all` bỏ điều kiện lá đó. Muốn tắt cả nhánh OR phức hợp cần cấu hình giá trị làm nhánh thành false. Policy vẫn được đánh giá toàn bộ; công cụ không ghép các ngưỡng tối ưu riêng lẻ rồi coi đó là nghiệm tối ưu chung.

`explore` xuất đầy đủ threshold, không bỏ các điểm trung gian; hòa Recall thì ưu tiên FPR thấp hơn, rồi ngưỡng cao hơn với thứ tự `none > numeric > all`. Average Precision là `sklearn.metrics.average_precision_score`, không phải diện tích PR bằng quy tắc hình thang. ROC-AUC chỉ dùng cho score liên tục; scatter/Pareto của hard policy không được gọi là ROC hay gán ROC-AUC.

`tune` tự thêm các họ score đơn. Ngân sách `max_evaluations` tính cả một chính sách không chặn dự phòng cho mỗi họ; vì thế ngân sách tối thiểu phải bằng số họ. Phần còn lại chia vòng theo thứ tự cấu hình. Họ đủ ngân sách được exhaustive search, họ lớn hơn dùng random search có seed trên các tổ hợp khác nhau. Báo cáo ghi số tổ hợp, phần đã khảo sát và liệu đã exhaustive; random search không bảo đảm tối ưu toàn cục. Candidates khác tham số nhưng cùng prediction vẫn được giữ để audit.

Với từng FPR target, chọn Recall cao nhất thỏa **empirical development FPR ≤ target**; hòa thì FPR thấp hơn, ít điều kiện thực sự có hiệu lực hơn, thứ tự JSON chuẩn hóa, rồi tên họ. Lưu lựa chọn từng họ và lựa chọn tốt nhất trên tất cả ứng viên đã thử. `only_no_block_feasible` chỉ rõ khi mọi lựa chọn khả thi đều không chặn request nào. Pareto giữ các điểm không bị vượt trội đồng thời về TPR/FPR.

Metric có TP/FP/TN/FN, N, N malicious/legitimate, Recall/TPR, FPR, precision, specificity, F1, prevalence và độ phân giải empirical FPR. Mẫu số bằng `0` trả `null` kèm `undefined_reasons`, không gán thành `0`. CSV biểu diễn null bằng ô trống. Nhóm chỉ malicious không có FPR xác định. Phân tích category cần khai báo `collection_manifest.attack_category_label_source`; SQLi-vs-legitimate chỉ gồm malicious SQLi và legitimate, không biến malicious loại khác thành legitimate.

## Uncertainty và phạm vi suy luận

Paired group bootstrap lấy lại nguyên nhóm có hoàn lại, dùng cùng mẫu trong mỗi replicate cho baseline và mọi policy. Không tune lại. Báo cáo số replicate hợp lệ/bị bỏ, khoảng percentile cho metric và chênh lệch Recall/FPR so baseline. Replicate thiếu một lớp bị bỏ; metric không xác định có số replicate hợp lệ riêng.

FP quan sát bằng `0` có thể làm bootstrap FPR suy biến về `[0, 0]`; điều này **không chứng minh FPR thật hay độ bất định bằng 0**. Cần xem số legitimate request và số nhóm độc lập. Độ phân giải empirical FPR là `1 / N_legitimate`; target nhỏ hơn độ phân giải, hoặc quá ít legitimate, được cảnh báo. V1 không thêm khoảng tin cậy nhị thức giả định request độc lập. Bootstrap chỉ phản ánh uncertainty của mẫu test với policy đã chọn, không phản ánh uncertainty của toàn bộ quá trình chọn policy.

Precision phụ thuộc tỷ lệ malicious trong dataset; không suy trực tiếp sang production. DetectionOnly chỉ cho phép mô phỏng quyết định score. Backend 200 không chứng minh exploit thành công. Metric request-level không thể thay bằng số CVE/template bị chặn chia cho số request.

## Artifacts và bảo toàn thí nghiệm

| Artifact | Nội dung |
|---|---|
| `data_quality.json`, `normalized_data.csv` | Chất lượng và bảng transaction đã chuẩn hóa |
| `excluded_records.csv`, `excluded_validation.csv`, `excluded_development.csv`, `excluded_test.csv` | Audit loại mẫu theo giai đoạn; file giai đoạn xuất khi giai đoạn chạy |
| `split_manifest.csv` | Khóa request, group, label, split, lý do unknown |
| `development_score_metrics.csv`, `development_threshold_candidates.csv` | ROC/AP và bảng threshold từng score development |
| `policy_candidates.csv`, `policy_pareto.csv`, `selected_policies.json` | Candidates đã thử, Pareto, policy khóa và provenance |
| `test_metrics.csv`, `test_predictions.csv` | So sánh và prediction trên cùng cohort test |
| `false_positives.csv`, `false_negatives.csv`, `policy_disagreements.csv` | Điều tra FP/FN và request baseline đúng nhưng policy sai hoặc ngược lại |
| `test_group_metrics.csv` | Phân tầng theo nguồn, cấu hình, threshold và category có nguồn nhãn |
| `actual_interruption_comparison.csv` | Đối chiếu mô phỏng với interruption có sẵn hoặc replay được cung cấp |
| `bootstrap_intervals.json` | Uncertainty và số replicate hợp lệ |
| `roc_curves.png`, `roc_low_fpr.png`, `precision_recall_curves.png`, `policy_tradeoffs.png` | Biểu đồ có split, cohort/N và tên trục |
| `experiment_manifest.json`, `report.html` | Hash/version/cấu hình/giai đoạn và báo cáo HTML offline |

Manifest lưu hash file nguồn, cấu hình, dữ liệu chuẩn hóa, split, policy và phiên bản thư viện. Khi cấu hình hoặc file nguồn khác, output cũ bị từ chối: chọn `output_path` mới. Thư mục có dữ liệu nhưng không có manifest cũng bị từ chối. Có thể chạy lại giai đoạn với cùng provenance; đây không phải thư mục chỉ đọc tuyệt đối. Sau tuning không chia lại split trong cùng thí nghiệm; sau evaluate không tune lại. Evaluate kiểm tra hash của split và policy trước khi đọc. Hash là kiểm tra toàn vẹn/tái lập, không phải chữ ký chống sửa đổi ác ý.

Body, headers, cookie và Authorization không được xuất từ mapping. URI mặc định bị bỏ; chỉ bật `export.include_uri: true` khi cần điều tra và đã chuẩn bị dữ liệu phù hợp. Metadata và URI được cho phép vẫn có thể chứa dữ liệu nhạy cảm: bảo vệ thư mục output như dataset của bạn. Công cụ không tải dataset lên dịch vụ bên ngoài.

## Đối chiếu replay và triển khai có kiểm soát

V1 chỉ đọc kết quả replay riêng, không chạy replay. Có thể khai báo CSV trước khi bắt đầu thí nghiệm:

```yaml
replay:
  path: ../private/replay.csv
  keys:
    run_id: collection_run
    request_id: original_coraza_transaction_id
  interrupted_field: engine_interrupted
  description: Interruption xác nhận từ engine trace của lần replay có kiểm soát.
```

Replay cần cả `run_id` và `request_id`, khóa duy nhất, và interruption là `true/false/1/0` hoặc rỗng/`null`. Đây là quan sát đối chiếu, không phải ground-truth malicious label. HTTP 403 không tự được hiểu là WAF chặn. Nếu replay cấp transaction ID mới, chuẩn bị bảng tương quan tới request ban đầu. Không khai báo replay thì báo cáo dùng `interrupted` từ audit log; unknown vẫn unknown.

Sau khi đã khóa policy, người vận hành có thể tự thực hiện quy trình staging/replay được mô tả trong [`docs/data-preparation.md`](docs/data-preparation.md). Công cụ không sinh thay đổi cấu hình Coraza, không bật rule, không chạy scan và không triển khai chính sách lên hệ thống thật.

## Kiểm thử, giả định và giới hạn

```bash
python -m pytest -q
```

Tests bao phủ parsing CSV/JSONL, missing/null/boolean, nhãn và duplicate, group leakage, boundary `>=`/sentinel, confusion matrix tính tay, cohort chung, candidate chỉ từ development, policy AND/OR, seed/tie-break/Pareto, round-trip JSON, uncertainty và evaluate không tuning. Trong phiên xây dựng, **82 test đã qua**; kết quả mới nhất nên lấy từ lệnh trên trong môi trường của bạn.

V1 giữ dữ liệu trong bộ nhớ; chưa hỗ trợ streaming dataset rất lớn, kết nối Elasticsearch trực tiếp, ML/cross-validation hoặc thực thi WAF/replay. Nhãn, group và metadata collection được coi là do người dùng chuẩn bị đúng; công cụ kiểm tra cấu trúc/mâu thuẫn nhưng không tự xác minh exploit hay chất lượng nhãn. Việc phân nhóm chưa có phát hiện near-duplicate tự động. Search có ngân sách chỉ chứng nhận tối ưu trên không gian đã khai báo khi exhaustive. Tái lập cần cùng dữ liệu, cấu hình, seed và môi trường thư viện; manifest ghi lại phiên bản thực chạy.

Chưa có dữ liệu thật nên chưa thể kết luận mức Recall/FPR thực tế của bất kỳ cấu hình Coraza/CRS nào. Không suy hiệu quả ngoài phạm vi dataset đã cung cấp.
