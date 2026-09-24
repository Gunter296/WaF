# Chú thích từng file và thư mục

Tài liệu này mô tả vai trò của **từng file mã nguồn, cấu hình, ví dụ và tài liệu** trong project. Các file được sinh khi chạy nằm trong `outputs/`; `.venv/`, `.uv-cache/`, `__pycache__/` và cache pytest là file tạm của môi trường, không thuộc mã nguồn.

| File hoặc thư mục | Chức năng |
|---|---|
| `./` | Thư mục gốc của project Python và nơi chạy các lệnh cài đặt/kiểm thử. |
| `pyproject.toml` | Metadata package, thư viện yêu cầu, entry point `crs-eval` và cấu hình pytest. |
| `.gitignore` | Loại môi trường ảo, cache, build và output thí nghiệm khỏi version control. |
| `README.md` | Giới thiệu ngắn, khởi chạy và giới hạn quan trọng. |
| `configs/` | Nơi đặt YAML của từng thí nghiệm; đường dẫn trong YAML tính từ thư mục này. |
| `configs/experiment.example.yaml` | Cấu hình ví dụ **chỉ cho dữ liệu giả lập**, gồm mapping, split, feature, search, bootstrap và collection manifest. |
| `configs/kibana-discover.example.yaml` | Mẫu mapping CSV export per-document từ Kibana Discover và tách CVE prefix trong URI. |
| `examples/` | Fixture mô phỏng, không chứa audit log thật hay dữ liệu nhạy cảm. |
| `examples/generate_synthetic.py` | Sinh CSV và JSONL giả lập bằng seed cố định; gán nhãn và nhóm tường minh. |
| `examples/synthetic.jsonl` | Input JSONL lồng nhau để chạy ví dụ end-to-end. |
| `examples/synthetic.csv` | Dữ liệu tương đương dạng CSV cột dấu chấm, dùng kiểm thử loader. |
| `src/` | Mã nguồn theo chuẩn layout Python `src`. |
| `src/crs_eval/` | Package thực thi năm lệnh CLI và các phép đánh giá. |
| `src/crs_eval/__init__.py` | Khai báo package/version. |
| `src/crs_eval/__main__.py` | Cho phép chạy `python -m crs_eval`. |
| `src/crs_eval/config.py` | Đọc YAML, giải đường dẫn, default, kiểm tra score inbound và hash cấu hình. |
| `src/crs_eval/io.py` | Đọc CSV/JSONL, ánh xạ trường lồng nhau, ghép nhãn, chuẩn hóa, xử lý duplicate. |
| `src/crs_eval/validation.py` | Định nghĩa trường mặc định, parse kiểu, lỗi validation và báo cáo chất lượng. |
| `src/crs_eval/split.py` | Chia group development/test bằng seed, kiểm tra hai lớp và lưu split fingerprint. |
| `src/crs_eval/metrics.py` | Confusion matrix, tỷ lệ an toàn với mẫu số 0, common cohort và paired group bootstrap. |
| `src/crs_eval/roc.py` | ROC/PR/AP theo score trên development, bảng ngưỡng đầy đủ và chọn theo FPR target. |
| `src/crs_eval/policies.py` | AST chính sách AND/OR an toàn, inclusive `>=`, sentinel all/none và baseline mô phỏng. |
| `src/crs_eval/search.py` | Exhaustive hoặc random search có budget/seed, Pareto và khóa ứng viên thắng. |
| `src/crs_eval/reporting.py` | Tạo biểu đồ PNG có trục/chú giải và HTML tự chứa để xem offline. |
| `src/crs_eval/utils.py` | JSON nghiêm ngặt, hash/fingerprint và ghi CSV/JSON có kiểm soát. |
| `src/crs_eval/cli.py` | Điều phối `validate`, `split`, `explore`, `tune`, `evaluate`; kiểm tra provenance và ghi artifacts. |
| `tests/` | Kiểm thử chức năng và luồng tích hợp; không chứa dữ liệu thật. |
| `tests/test_data.py` | CSV/JSONL, parsing, label join, duplicate và split không giao nhóm. |
| `tests/test_metrics.py` | Metric tính tay, missing/cohort, threshold/ROC và bootstrap. |
| `tests/test_policies.py` | AST, AND/OR, sentinel, search budget, seed, tie-break và Pareto. |
| `tests/test_cli.py` | Chạy toàn bộ CLI, kiểm tra artifacts, provenance/lock và khả năng tái lập. |
| `docs/` | Tài liệu hướng dẫn vận hành và giải thích cấu trúc. |
| `docs/USER_GUIDE.md` | Hướng dẫn cài đặt, chuẩn bị dữ liệu, năm lệnh CLI và cách đọc kết quả. |
| `docs/PROJECT_MAP.md` | Chính file chú thích này; bảng chức năng từng file/folder. |
| `docs/data-preparation.md` | Chi tiết export/chuẩn bị nhãn, group và manifest từ hệ thống Coraza/CRS. |
| `outputs/` | Nơi CLI sinh artifacts theo `output_path`; mỗi cấu hình/input có output riêng. |

## Các file trong `outputs/<thí-nghiệm>/`

| File | Chú thích |
|---|---|
| `data_quality.json` | Tổng document/nhãn/duplicate, missing, phân bố score và lỗi/cảnh báo dữ liệu. |
| `normalized_data.csv` | Bảng đã chuẩn hóa; mỗi dòng là một transaction. |
| `excluded_records.csv` | Audit trail tổng hợp record bị loại, có lý do. |
| `excluded_validation.csv` | Bản ghi bị loại trong bước validation, như duplicate và unknown. |
| `excluded_development.csv`, `excluded_test.csv` | Lý do mất coverage trên hai phần dữ liệu. |
| `split_manifest.csv` | Khóa request, group, nhãn và split; dùng khóa để kiểm tra chính sách. |
| `development_score_metrics.csv` | ROC-AUC/AP và coverage theo score trên development. |
| `development_threshold_candidates.csv` | Toàn bộ ngưỡng điểm, confusion matrix và target đạt được. |
| `policy_candidates.csv` | Mọi chính sách đã thử và metric trên cùng cohort development. |
| `policy_pareto.csv` | Các chính sách không bị ứng viên khác vượt trội đồng thời về TPR/FPR. |
| `selected_policies.json` | Chính sách đã khóa, metric development, search budget, feature/cohort và hash. |
| `test_metrics.csv` | Kết quả test của baseline và mọi chính sách đã chọn trên cùng cohort. |
| `test_predictions.csv` | Dự đoán, nhãn và phân loại TP/FP/TN/FN theo request/policy. |
| `false_positives.csv`, `false_negatives.csv` | Request sai cần điều tra riêng. |
| `policy_disagreements.csv` | Request baseline và chính sách mới khác nhau; chỉ rõ bên nào đúng theo nhãn. |
| `test_group_metrics.csv` | Metric phân tầng theo nguồn, cấu hình, threshold hoặc loại tấn công có nguồn nhãn. |
| `actual_interruption_comparison.csv` | Đối chiếu proposed block với audit/replay interruption, không thay nhãn thật. |
| `bootstrap_intervals.json` | Khoảng tin cậy paired group bootstrap và số replicate hợp lệ. |
| `roc_curves.png`, `roc_low_fpr.png`, `precision_recall_curves.png` | Đồ thị score trên development; mẫu số ghi trong chú giải. |
| `policy_tradeoffs.png` | Scatter và Pareto của ứng viên nhiều chiều trên development. |
| `experiment_manifest.json` | Cấu hình, input hash, fingerprint, seed, split, thư viện và cảnh báo để tái lập. |
| `report.html` | Báo cáo offline tự chứa bảng, biểu đồ, uncertainty và giới hạn. |

Những file output chỉ xuất hiện sau lệnh tương ứng. Muốn hiểu thứ tự tạo và cách đọc chúng, xem [hướng dẫn sử dụng](USER_GUIDE.md).
