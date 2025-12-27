# 10_web_config_ops_設定・運用境界_初動
Webの設定/運用を「設定チェック」ではなく、外部に滲む境界（CORS/Headers/Secrets/Errors/Logging/CDN-WAF）を観測→分岐で固め、次の一手を決める。

## 目的（このプレイブックで到達する状態）
- 入口Top3?5のレスポンスから、設定/運用境界の状態（Yes/No/Unknown）を短時間で埋められる。
- “どこが崩れると何が起きるか” を、観測根拠（ヘッダ/ログ/挙動）で説明できる。
- 次に読むtopic（CORS/Secrets/Headers/Errors/Logging/WAF）と次に回す検証を分岐で選べる。

## 前提知識チェックリスト（先に確認）
- 境界：外部に滲むポイント（CORS/Headers/Secrets/Errors/Logging）
- 差分観測：代表URLのヘッダ/エラー差分
- 成立条件：どの設定が効いているか

## 前提（対象・範囲・制約）
- 対象：許可範囲のWeb（UI/API）、CDN/WAF/Reverse Proxy、ログ基盤（見られる範囲で）。
- 制約：大量リクエストやディレクトリ総当たりはしない。代表点だけで状態を作る。
- 前提ツール（最小限）：`curl`、ブラウザ（HAR）、（任意）`ripgrep`（JS断片探索）。
  - 理由：ヘッダ/エラー/JS断片の有無を短時間で確認できる。
  - 代替：`Invoke-WebRequest` / `Select-String` でも可。
- 参照すべきtopics：
  - `01_topics/02_web/06_config_00_設定・運用境界（CORS ヘッダ Secrets）.md`

## 入口で確定すること（最小セット）
- 代表URL（最大3つ）：トップ、ログイン、主要API（または主要操作1つ）。
- “外部に滲む” 観測対象：ヘッダ、エラーページ、JS資産、設定エンドポイント、ログ（見える範囲）。
- 完了条件：CORS/Headers/Secrets/Errors/Logging/CDN-WAF を Yes/No/Unknown で埋める。

## 所要時間の目安
- 全体：30〜45分

## 手順（分岐中心：迷うポイントだけ）

### Step 0：最初の5分（必ずやる / 目安: 5分）
- 目的：代表点のレスポンスから、設定境界の当たりを付ける。
- 観測ポイント：
  - 代表URL 3つのレスポンスヘッダを取る（未ログインでよい）。
  - 可能なら HAR を1回だけ取る（トップ→ログイン表示まで）。
- 証跡（最小）：
~~~~
# Windows (PowerShell)
$dir = Join-Path $HOME "keda_evidence\\web_config_10"
New-Item -ItemType Directory -Force $dir | Out-Null
Set-Location $dir
"base_url: ...`nurls: ..." | Set-Content -Encoding utf8 00_context.txt

# macOS/Linux (bash)
mkdir -p ~/keda_evidence/web_config_10
cd ~/keda_evidence/web_config_10
printf "base_url: ...\nurls: ...\n" > 00_context.txt
curl -sS -I "https://<BASE>/" | sed -n '1,60p' > 01_head_root.txt
curl -sS -I "https://<BASE>/login" | sed -n '1,80p' > 01_head_login.txt
~~~~
- 次の分岐：
  - ヘッダが取れた → Step 1へ
- 実際の観測例：
  - `01_head_root.txt` にCSPがない

### Step 1：セキュリティヘッダ（最低限）を状態化する（目安: 8分）
- 目的：ブラウザ境界（SOP/CSP等）の前提崩れを先に潰す。
- 観測ポイント（Yes/No/Unknown）：
  - `Content-Security-Policy`（あるか、report-onlyか）
  - `Strict-Transport-Security`（あるか）
  - `X-Frame-Options`/`frame-ancestors`（クリックジャッキング対策）
  - `Cache-Control`（機微レスポンスでの制御）
- 次の分岐：
  - CSPが弱い/ない → `01_topics/02_web/06_config_03_security_headers（CSP_HSTS_XFO等）.md`
  - キャッシュが怪しい → `01_topics/02_web/06_config_05_cache_control_機微レスポンスの境界.md`
- 実際の観測例：
  - `X-Frame-Options` が未設定

### Step 2：CORS境界（API/認証）を状態化する（目安: 8分）
- 目的：ブラウザからの越境可能性（認証情報付き）を確定する。
- 観測ポイント：
  - `Access-Control-Allow-Origin` / `-Credentials` / `-Headers` / `-Methods`
  - 認証付きAPIでの挙動（未ログイン/ログイン後の差）
- 次の分岐：
  - ワイルドカード/反射/資格情報付きが疑わしい → `01_topics/02_web/06_config_01_CORSと信頼境界（Origin_資格情報_プリフライト）.md`
  - API側の認証/認可が鍵 → `02_playbooks/05_api_権限伝播→検証観点チェック.md`
- 実際の観測例：
  - `Access-Control-Allow-Origin: *` が返る

### Step 3：Secrets/デバッグ露出を状態化する（JS/ログ/設定 / 目安: 8分）
- 目的：秘密情報が外部へ滲む経路を確定する。
- 観測ポイント（例）：
  - JSバンドル/設定JSONに `token`/`key`/`secret` が混じる兆候
  - `swagger`/`actuator`/`debug` などの露出
  - 詳細エラー（スタック/環境名/内部URL）
  - 検索方法（例）：`rg -n "token|secret|apiKey" <js_bundle>` / `Select-String -Pattern "token|secret|apiKey" -Path <file>`
- 次の分岐：
  - secrets露出が疑わしい → `01_topics/02_web/06_config_02_Secrets管理と漏えい経路（JS_ログ_設定_クラウド）.md`
  - debug endpoint が疑わしい → `01_topics/02_web/06_config_06_debug_endpoints（actuator_swagger）露出.md`
  - エラーページが詳細 → `01_topics/02_web/06_config_07_error_pages_詳細表示と環境切替.md`
- 実際の観測例：
  - JS内に `apiKey=` が含まれる

### Step 4：ログ/監査（相関できるか）を状態化する（目安: 6分）
- 目的：問題が起きた時に追えるか（相関キー/マスキング/保持）を確定する。
- 観測ポイント（Yes/No/Unknown）：
  - 相関ID（`X-Request-Id`等）があるか
  - PII/secret がログやエラーに出ないか（マスキング）
  - ログ取得/保持の根拠（見られる範囲で）
- 次の分岐：
  - PII/secret ログが疑わしい → `01_topics/02_web/06_config_08_logging_pii_secret（マスキング_相関）.md`
  - 監査ログが本体（SaaS含む） → `02_playbooks/08_saas_信頼→共有→監査ログ_初動.md`
- 実際の観測例：
  - `X-Request-Id` がレスポンスに含まれる

### Step 5：CDN/WAF/運用例外を状態化する（目安: 5分）
- 目的：境界が “コード” ではなく “運用” で崩れる地点を特定する。
- 観測ポイント：
  - ヘッダ/証明書/挙動からCDN/WAFの介在を推定
  - 例外運用（特定パス/特定IP/特定ヘッダでバイパス）があり得るか
- 次の分岐：
  - CDN/WAFが本体 → `01_topics/02_web/06_config_10_cdn_waf_運用境界（ルール例外_バイパス）.md`
- 実際の観測例：
  - `Server: cloudflare` が付与される

## 取得する証跡（目的ベースで最小限）
- 何のため：設定/運用の境界（外部に滲む点）を説明するため。
- 取得対象：代表URLのヘッダ、エラーのスクショ/本文、JS資産の手掛かり（ファイル名/断片）、ログ根拠（見える範囲）。
- 見るポイント：ヘッダの有無と整合、CORSの成立条件、secrets露出兆候、詳細エラー、相関ID/マスキング。

## コマンド例（例示は最小限）
~~~~
# ヘッダ観測（代表点）
curl -sS -I "https://<BASE>/" | sed -n '1,80p'

# エラーページ観測（意図的に404など）
curl -sS -i "https://<BASE>/this_path_should_not_exist" | sed -n '1,80p'
~~~~
- 何を観測する例か：ヘッダ/エラーページから、設定境界の当たりを付ける。
- 出力の注目点：CSP/HSTS/CORS、Server系ヘッダ、エラー本文の情報量、相関ID。
- 前提が崩れるケース：SPAやCDNでヘッダが代表点に出ない（HAR/別パスで補う）。

## よくある失敗と対処法
- 代表URLが多すぎる → 3本に絞る
- JS検索が雑すぎる → 正規表現で範囲を限定
- エラー観測が不足 → 404/405で意図的に確認

## バグバウンティでの注意点
- 大量リクエストは避ける（代表点のみ）
- Secrets/ログの扱いは慎重に（保存/共有ルール）
- レポートは「観測根拠（ヘッダ/断片）」を明記
## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS：
  - V7（Secrets）/V10（Logging）/V14（Config）を、外部に滲む観測点から短時間で状態化する。
- WSTG：
  - Configuration and Deployment Management を、分岐（CORS/Headers/Errors/Logging/WAF）で次の検証へ繋ぐ。
- PTES：
  - Intelligence Gathering → Vulnerability Analysis の “前提崩れ” を減らす。
- MITRE ATT&CK：
  - Credential Access（secret）/Defense Evasion（監査不足）/Collection（ログ/情報漏えい）の説明補助に使う。

## 報告（ガイドライン程度：数行で）
- 事実：CORS/Headers/Secrets/Errors/Logging/CDN-WAF の Yes/No/Unknown と根拠。
- 成立条件：どの設定がどの境界を守る/崩すか（観測根拠つき）。
- 影響：漏えい/越境/追跡不能のリスク（推定は推定と明記）。
- 対策方向性：CORS最小化、ヘッダ整備、secrets管理、エラー抑制、相関/マスキング、WAF例外管理。

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`01_topics/02_web/06_config_00_設定・運用境界（CORS ヘッダ Secrets）.md`
- 関連 playbooks：`02_playbooks/02_web_recon_入口→境界→検証方針.md`
- 関連 playbooks：`02_playbooks/05_api_権限伝播→検証観点チェック.md`
