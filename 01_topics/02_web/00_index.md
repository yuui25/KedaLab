# 00_index（Web）
Web での入口・認証・認可・API・入力/設定を「境界（資産/信頼/権限/実行/運用）」で捉え、後続の深掘りに渡すための案内です。ChatGPT が読むだけで各ファイルの狙いが分かるように要約しています。

## 目的
- Web攻撃面をツール操作ではなく「意味→判断→次の一手」で回す共通言語を揃える。
- 認証/認可/入力/設定/運用の崩れ方を境界モデルで説明できるようにする。
- 次の検証へ持ち込む仮説A/Bと観測点を用意する（低アクティブ・許可スコープ内）。

## ガイドライン位置づけ
- ASVS：AuthN/AuthZ/Session/API/Config 項目の前提を固め、どこで満たし/破れるかを明示。
- WSTG：Information Gathering を起点に各カテゴリ（Auth/AccessControl/API/Client/Config）へ観測点を供給。
- PTES：Intelligence Gathering → Threat Modeling → Vulnerability Analysis の設計材料。
- MITRE ATT&CK：Discovery/Collection/Credential Access/Privilege Escalation を「Webの境界崩壊」として説明補助。

## 主なアウトプット
- 境界メモ（資産/信頼/権限/実行/運用）、入口一覧、外部依存一覧。
- 次の検証方針（仮説A/Bと観測点）を AuthZ/API/Input/Config へ接続。

## 読み進めのおすすめ
1) `01_web_00_recon_入口・境界・攻め筋の確定.md`（入口と対象/外部依存を固める）
2) 認証系 `02_authn_00_認証・セッション・トークン.md` → 個別論点（01–20）
3) 認可系 `03_authz_00_認可（IDOR BOLA BFLA）境界モデル化.md` → 個別論点（01–10）
4) API系 `04_api_00_権限伝播・入力・バックエンド連携.md` → 個別論点（01–12）
5) 入力/実行系 `05_input_00_入力→実行境界（テンプレ デシリアライズ等）.md` → 個別論点（01–20）
6) 設定/運用系 `06_config_00_設定・運用境界（CORS ヘッダ Secrets）.md` → 個別論点（01–12）
7) 追加トピック（ブラウザ境界/クリックジャック/暗号/決済など）を必要に応じて。

## ファイル概要（ダイジェスト）
- 01_web_00_recon_入口・境界・攻め筋の確定：入口/外部依存を境界で整理し次の検証に渡す。

- 認証（02_authn_*）
  - 00 認証・セッション・トークン総論：本人性成立点と拒否点。
  - 01 Cookie属性（Secure/HttpOnly/SameSite/Path/Domain）：クッキー境界。
  - 02 Session lifecycle（更新/失効/固定化/ローテーション）：セッション寿命管理。
  - 03 Token設計（Bearer/JWT/Refresh/Rotation）：トークン種別と寿命/検証。
  - 04 OIDC flow観測（state/nonce/code/PKCE）：OIDCの成立点。
  - 05 SAML flow観測（assertion/audience/recipient）：SAMLの成立点。
  - 06 MFA成立点と例外（step-up/device trust）：MFA適用とバイパス。
  - 07 Client storage（localStorage/sessionStorage）：ブラウザ保存境界。
  - 08 Device binding（IP/UA/fingerprint）：端末紐付け。
  - 09 Password policy（強度/漏えい照合/禁止語）。
  - 10 Password reset 回復経路（token/失効/多要素）。
  - 11 Account recovery 本人確認（サポート代行/回復コード）。
  - 12 Bruteforce rate-limit_lockout（例外パス）。
  - 13 Login CSRF / state設計。
  - 14 Logout 設計（RP/IdP/フロントチャネル）。
  - 15 Session concurrency（多端末/同時ログイン制御）。
  - 16 Step-up 再認証境界（重要操作）。
  - 17 Refresh token rotation 盗用検知。
  - 18 Token binding（DPoP/mTLS）観測。
  - 19 WebAuthn/Passkeys 登録・回復境界。
  - 20 Magic-link メールリンク認証の成立条件。

- 認可（03_authz_*）
  - 00 認可総論（IDOR/BOLA/BFLA）境界モデル。
  - 01 境界モデル（オブジェクト/ロール/テナント）。
  - 02 IDOR典型（一覧/検索/参照キー）。
  - 03 Multi-tenant 分離（org_id/tenant_id）。
  - 04 RBAC/ABAC 判定点（policy engine）。
  - 05 Mass assignment モデル結合境界。
  - 06 Privileged action 重要操作（承認/送金/権限）。
  - 07 GraphQL authz（field_level）。
  - 08 File access ダウンロード認可（署名URL）。
  - 09 Admin console 運用UIの境界。
  - 10 Object state 状態遷移と権限（draft/approved）。

- API（04_api_*）
  - 00 権限伝播・入力・バックエンド連携総論。
  - 01 権限伝播モデル（フロント/バックエンド/ジョブ）。
  - 02 GraphQL 境界（schema/introspection/query_cost）。
  - 03 REST filters（検索/ソート/ページング境界）。
  - 04 Webhook 受信側の信頼境界（署名/再送）。
  - 05 Webhook SSRF 送信側の到達性境界。
  - 06 Idempotency レースと二重実行。
  - 07 Async job 権限伝播（キュー/ワーカー）。
  - 08 File export エクスポート境界（CSV/PDF）。
  - 09 Error model 情報漏えい（例外/スタック）。
  - 10 Versioning 互換性と境界（v1/v2）。
  - 11 gRPC メタデータと認可境界。
  - 12 WebSocket/SSE 認証・認可境界。

- 入力/実行（05_input_*）
  - 00 入力→実行境界（テンプレ/デシリアライズ等）総論。
  - 01 テンプレート注入/SSTI。
  - 02 デシリアライズ/型混乱/ガジェット前提。
  - 03 SQLi（Oracle/MySQL/Postgre/MSSQL 各境界・プレースホルダ）。
  - 04 NoSQLi（MongoDB/Elasticsearch/Neo4j 各クエリ/スクリプト/型混乱）。
  - 05 Command injection（shell/args/env）。
  - 06 XSS（反射/格納/DOM）境界モデル。
  - 07 CSRF（token/samesite/API）。
  - 08 XXE（parser/blind/to-SSRF）。
  - 09 SSRF（reachability/url tricks/protocol/saas features/dns rebinding/parser差分）。
  - 10 Open redirect（遷移先信頼境界）。
  - 11 Path traversal（normalization/join/root）。
  - 12 File upload（validation/storage_path/execution_chain/image/archives）。
  - 13 Deserialization（JSON/YAML/XML object mapping）。
  - 14 Prototype pollution（sources/sinks）。
  - 15 Regex DoS（ReDoS検証）。
  - 16 CSV formula injection（export境界）。
  - 17 Email header injection（SMTP境界）。
  - 18 HTTP request smuggling（TE-CL/CL-TE/h2 frontend/observable signals）。
  - 19 Cache poisoning（keying/unkeyed/poisoned object）。
  - 20 CRLF injection（response splitting/downstream）。

- 設定/運用（06_config_*）
  - 00 設定・運用境界（CORS/ヘッダ/Secrets）総論。
  - 01 CORSと信頼境界（Origin/資格情報/プリフライト）。
  - 02 Secrets管理と漏えい経路（JS/ログ/設定/クラウド）。
  - 03 Security headers（CSP/HSTS/XFO等）。
  - 04 CSP 実務設計（report-only/違反収集）。
  - 05 Cache-Control 機微レスポンス境界。
  - 06 Debug endpoints（actuator/swagger）露出。
  - 07 Error pages 詳細表示と環境切替。
  - 08 Logging PII/secret（マスキング/相関）。
  - 09 CORS プリフライト cache と例外。
  - 10 CDN/WAF 運用境界（ルール例外/バイパス）。
  - 11 Secrets rotation 運用（回収/失効）。
  - 12 S3 presigned URL 期限と権限境界。

- 追加トピック
  - 07_browser_security_境界（SOP/CORS/CSP）：ブラウザの基本境界。
  - 08_clickjacking_境界（XFO/CSP frame-ancestors）：クリックジャック防御。
  - 09_mixed_content_境界（HTTPS移行）：混在コンテンツ制御。
  - 10_authn_to_authz_接続（claims_権限伝播）：AuthN→AuthZの橋渡し。
  - 11_logging_tracing_相関IDと証跡設計：ログ・トレースの相関設計。
  - 12_rate-limit_設計（API_key_user_ip）：レート制御設計。
  - 13_session_replay_再利用と検知（ua_ip_binding）：セッション再利用と検知。
  - 14_cryptography_境界（hash/kdf/sign/encrypt）：暗号利用の境界と選択。
  - 15_payment_重要操作境界（3DS/返金）：決済まわりの境界と再認証/返金リスク。

## 接続先
- ASM/OSINT の入口：`01_topics/01_asm-osint/00_index.md`
- ネットワーク側：`01_topics/03_network/01_enum_到達性→サービス→認証→権限推定.md`
- SaaS/IdP 側：`01_topics/04_saas/01_idp_連携（SAML OIDC OAuth）と信頼境界.md`
- ローカル証跡取得：`04_labs/01_local/02_proxy_計測・改変ポイント設計.md`, `04_labs/01_local/03_capture_証跡取得（pcap_har_log）.md`
