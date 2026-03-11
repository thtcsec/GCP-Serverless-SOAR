# 🧠 Kiến trúc Nội bộ: GCP Serverless SOAR

Một khung làm việc **Điều phối Bảo mật** nâng cao với tình báo đa nguồn, phát hiện bất thường AI/ML, và chiến lược cách ly chi tiết.

## 1. Các thành phần cốt lõi

*   **Tầng phát hiện (SCC, Cloud Audit Logs, Event Threat Detection, VPC Flow Logs):** Giám sát thời gian thực các hành vi lạm dụng Service Account, exfiltration từ Storage bucket, và bất thường mạng.
*   **Tầng Tình báo & Chấm điểm:**
    *   **VirusTotal:** Đối soát IP nguồn với cơ sở dữ liệu mối đe dọa toàn cầu (~70 engines).
    *   **AbuseIPDB:** Loại bỏ các máy quét và bot brute-force dựa trên điểm uy tín từ cộng đồng.
    *   **Phát hiện bất thường ML (Isolation Forest):** Phân tích hành vi sử dụng feature vector (`hour_of_day`, `day_of_week`, `ip_reputation_score`, `action_risk_level`, `request_frequency`) với fallback Z-Score.
    *   **Scoring Engine (0-100):** Tính toán động `risk_score` kết hợp độ tin cậy tình báo, mức độ nghiêm trọng, và anomaly boost (+15). Đầu ra: `IGNORE (<40)`, `REQUIRE_APPROVAL (40-70)`, `AUTO_ISOLATE (>70)`.
*   **Điều phối Luồng xử lý:**
    *   **Định tuyến sự kiện:** Eventarc → Pub/Sub Topic cho giao nhận sự kiện.
    *   **Bộ máy Workflow:** Cloud Workflows → Cloud Functions (Remediation Worker) + Cloud Run (Forensic Analyst).
    *   **Phê duyệt con người:** Tích hợp Slack/Jira cho quyết định human-in-the-loop.
    *   **Chuẩn hóa sự kiện:** Chuyển đổi sự kiện native thành schema `UnifiedIncident` để tương thích đa nền tảng.
    *   **Tương quan sự cố:** Nhóm các cảnh báo liên quan theo IOC chung (IP, tác nhân, ±5 phút) để phát hiện chiến dịch tấn công đa giai đoạn.
*   **Hệ thống phân cấp cách ly (Function > Process > Permissions > Network):**
    *   **Tầng Process:** Kill các tiến trình độc hại và cách ly file qua Compute Engine metadata script.
    *   **Tầng Permissions:** Thu hồi khóa SA, vô hiệu hóa Service Account, gỡ bỏ IAM bindings.
    *   **Tầng Network:** Chặn lưu lượng ra qua Firewall rule hoặc network tag (biện pháp cuối cùng).

## 2. Luồng Phản ứng

1.  **Làm giàu dữ liệu:** Khi nhận phát hiện, hệ thống truy vấn nhiều nguồn Tình báo và chạy phát hiện bất thường ML.
2.  **Chấm điểm:** Scoring Engine đánh giá tất cả tín hiệu và tính risk score kèm anomaly boost.
    *   Rủi ro thấp → **Ghi log & Bỏ qua**.
    *   Rủi ro trung bình → **Gửi cảnh báo (Chờ phê duyệt con người)**.
    *   Rủi ro cao → **Tự động cách ly** (kill process → thu hồi quyền → cách ly mạng).
3.  **Xử lý:**
    *   **Cách ly Process:** Kill các tiến trình nghi ngờ (xmrig, cryptominer) qua metadata script.
    *   **Khóa danh tính:** Vô hiệu hóa khóa SA, gỡ bỏ vai trò IAM.
    *   **Cách ly mạng:** Áp dụng Firewall rule.
    *   **Thu thập chứng cứ:** Chụp snapshot đĩa cứng cho đội IR.
4.  **Kiểm toán & Tuân thủ:** Tất cả hành động được ghi vào audit trail bất biến (Cloud Logging → GCS). Đầy đủ bối cảnh gửi lên Jira để quản trị.

## 3. Quan sát & Gia cố Bảo mật

*   **Cloud Monitoring Dashboard (Terraform):** Lượng thực thi function, tỷ lệ lỗi, MTTR, độ sâu Pub/Sub, trạng thái Cloud Workflows, Cloud Run metrics.
*   **Alerting Policies:** Tự động cảnh báo khi Cloud Function lỗi hoặc Pub/Sub tồn đọng.
*   **Xoay vòng bí mật:** Chính sách xoay 90 ngày cho tất cả API key qua Secret Manager.
*   **Audit Logger:** Nhật ký kiểm toán có cấu trúc cho mọi hành động SOAR với Cloud Logging + GCS lưu trữ.

## 4. Tại sao Serverless?
*   **Tiết kiệm:** Không phải trả tiền khi nhàn rỗi. Chi phí chỉ ~$5-15/tháng với lưu lượng vừa phải.
*   **Tốc độ:** Phản ứng trong mili giây, nhanh hơn bất kỳ nhân viên vận hành nào.
*   **Mở rộng:** Dù 1 hay 1.000 sự cố, GCP tự mở rộng Cloud Functions và Cloud Run để xử lý đồng thời.

---
**Kết luận:** Một hệ thống "Tự chữa lành" với tình báo đa tầng, phát hiện bất thường ML, và cách ly chi tiết — từ kill một tiến trình đến khóa toàn bộ mạng. 🛡️
