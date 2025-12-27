# 00_index（02_playbooks）
`02_playbooks/` は「手順の網羅」ではなく、**最初の5分で手を動かし、観測→判断→次の一手**を決めるための導線です。
詳細な技術解説や攻撃手口は `01_topics/` に寄せ、playbook は **分岐（条件）と判断基準、最小証跡**に集中します。

## 目的（このプレイブック群で到達する状態）
- 入口（どこから入る）と境界（資産/信頼/権限/実行/運用）を、短時間で根拠付きで説明できる。
- “次に読むtopic” と “次に回す検証” を迷わず選べる（条件AならA、違えばB）。
- 後で説明できる最小証跡（HAR/pcap/ログ/設定スナップショット）を残せる。

## ガイドライン位置づけ
- ASVS：AuthN/AuthZ/Session/API/Secrets/Logging の「前提崩れ」を先に潰す。
- WSTG：Information Gathering を起点に、Auth/Access Control/API/Config へ観測点を供給。
- PTES：IG→VA→Exploitation→Post の接続を短く保つ（やることを増やさない）。
- MITRE ATT&CK：分類のためではなく、境界崩壊（Discovery/Credential/Lateral/Exfiltration等）の説明補助。

## 使い方（共通：最初の5分）
1) スコープ確認：許可/禁止、第三者宛通信の可否、時間制約、影響制約（変更/送信/大量アクセスの禁止）。
2) 代表点の確定：入口URL（3つまで）、代表ホスト（3つまで）、テストユーザ（2種以上：ロール/テナント差）。
3) 証跡の準備：HAR/pcap/ログの「どれを取るか」と相関キー（User/Host/Time/Destination/Identifier）。
4) 1回だけ観測：ログイン1回、代表API 1回、代表ポート 1回…のように“最小回数”で状態を掴む。
5) 分岐で次へ：AuthN/AuthZ/API/Input/Config/SaaS/NW/Exfil のどこが勝負かを決める。

## 収録プレイブック一覧（使う順の目安）
- `02_playbooks/01_asm_passive-recon_資産境界→優先度付け.md`：パッシブ中心で資産/信頼境界→深掘り優先度
- `02_playbooks/02_web_recon_入口→境界→検証方針.md`：Web入口を境界で整理→次の深掘り（AuthN/AuthZ/API/Input/Config）
- `02_playbooks/03_authn_観測ポイント（SSO_MFA前提）.md`：本人性/セッション材料/寿命/例外→次の深掘り
- `02_playbooks/04_authz_境界モデル→検証観点チェック.md`：所有/ロール/テナント/共有/状態→越権の成立条件
- `02_playbooks/05_api_権限伝播→検証観点チェック.md`：UI≠API前提で権限伝播/判定点/非同期/Webhook
- `02_playbooks/07_input_to_rce_入力→実行の導線.md`：入力がどこで解釈/実行に変わるか→優先度付け
- `02_playbooks/10_web_config_ops_設定・運用境界_初動.md`：CORS/Headers/Secrets/Logging/CDN-WAF で崩れる点を短時間で確定
- `02_playbooks/06_network_enum_to_post_列挙→侵入後の導線.md`：到達性→サービス→認証→権限→Post初動
- `02_playbooks/08_saas_信頼→共有→監査ログ_初動.md`：SaaSの信頼/共有/監査をYes/No/Unknownで埋める
- `02_playbooks/09_egress_exfil_出口評価（DNS_HTTP_SMB）.md`：DNS/HTTP(S)/SMB の出口成立と封じ方

## 作成テンプレ（参考）
- `99_templates/02_playbook-template.md`

---

## 使用参考例：`*.example.com` を与えられたとき
目的：`*.example.com` を「列挙して当てに行く」ではなく、**代表点（3〜5）で境界（資産/信頼/権限/運用）を確定**し、次に回す playbook を迷わず選ぶ。

### 事前の約束（事故防止）
- スコープ文面で **能動通信の許可範囲**（第三者ドメインへのアクセス可否、スキャン可否、回数/レート）を明文化してから動く。
- 代表点は最初は3つに固定：`example.com` / `login.example.com` / `api.example.com`（無ければ `www` `app` `admin` などに置換）。
- 以降は「差分観測」：**変えるのは1条件だけ**（未ログイン/ログイン、主体A/B、owner/tenant/role/scope 等）。

### 前提条件チェック（Phase 1 の前）
- [ ] スコープ文面で能動通信の許可範囲を確認済み（第三者ドメイン/スキャン/レート）
- [ ] テストアカウント（最低2つ：ロール差 or テナント差）を用意できるか確認（無理なら Unknown で進める）
- [ ] 必要なツール（PowerShell / ブラウザ / Proxy(HAR)）が利用可能
- [ ] 証跡保存先（`$HOME\keda_evidence`）の容量を確認

### Phase 1: 初期観測（30-40分）
開始：`02_playbooks/01_asm_passive-recon_資産境界→優先度付け.md`

```powershell
# 証跡ディレクトリ作成
$dir = Join-Path $HOME "keda_evidence\\asm_passive_01"
New-Item -ItemType Directory -Force $dir | Out-Null
Set-Location $dir

# スコープ記録
"scope: *.example.com`ndate: $(Get-Date -Format 'yyyy-MM-dd')`nseeds: example.com / login.example.com / api.example.com" |
  Set-Content -Encoding utf8 00_scope.txt

# DNS観測（委譲/外部依存の根拠）
try {
  Resolve-DnsName -Name example.com -Type NS | Out-File 01_dns_ns.txt
} catch {
  "DNS resolution failed (NS): $_" | Out-File 01_dns_ns.txt
}
try {
  Resolve-DnsName -Name api.example.com -Type CNAME | Out-File 01_dns_cname_api.txt
} catch {
  "DNS resolution failed (CNAME): $_" | Out-File 01_dns_cname_api.txt
}

# TLS観測（証明書の根拠）
# より確実（openssl がある場合）：
#   openssl s_client -servername api.example.com -connect api.example.com:443 2>$null |
#     openssl x509 -noout -issuer -subject -ext subjectAltName > 02_tls_cert_api.txt
try {
  $hostName = "api.example.com"
  $tcpClient = New-Object System.Net.Sockets.TcpClient($hostName, 443)
  $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, ({ $true }))
  $sslStream.AuthenticateAsClient($hostName)
  $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($sslStream.RemoteCertificate)
  $sanExt = $cert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.17" } | Select-Object -First 1
  @(
    "Subject: $($cert.Subject)"
    "Issuer: $($cert.Issuer)"
    "NotBefore: $($cert.NotBefore.ToString('s'))"
    "NotAfter: $($cert.NotAfter.ToString('s'))"
    ("SubjectAltName: " + $(if ($sanExt) { $sanExt.Format($false) } else { "N/A" }))
  ) | Out-File 02_tls_cert_api.txt
  $sslStream.Dispose()
  $tcpClient.Close()
} catch {
  "TLS certificate collection failed: $_`nTip: check browser DevTools (Security) or use openssl if available." | Out-File 02_tls_cert_api.txt
}

# HTTP観測（SSO/入口の根拠）
try {
  Invoke-WebRequest -Uri "https://login.example.com" -Method Head -UseBasicParsing |
    Out-File 03_http_head_login.txt
} catch {
  "HTTP head failed: $_" | Out-File 03_http_head_login.txt
}
```

結果から次を判断：
- 外部依存（CDN/WAF）が強い → `02_playbooks/02_web_recon_入口→境界→検証方針.md` または `02_playbooks/10_web_config_ops_設定・運用境界_初動.md`
- SSO入口が見える（`Location`でIdPへ遷移等） → `02_playbooks/03_authn_観測ポイント（SSO_MFA前提）.md`
- 自社運用寄り（入口がUI/API中心） → `02_playbooks/02_web_recon_入口→境界→検証方針.md`

### Phase 2: Web入口の確定（30-45分）
実行：`02_playbooks/02_web_recon_入口→境界→検証方針.md`

```powershell
$dir = Join-Path $HOME "keda_evidence\\web_recon_02"
New-Item -ItemType Directory -Force $dir | Out-Null
Set-Location $dir

# ブラウザでHAR取得（DevTools → Network → Preserve log → Save all as HAR）

# 代表点のヘッダ取得（根拠）
try {
  Invoke-WebRequest -Uri "https://example.com" -UseBasicParsing |
    Select-Object -ExpandProperty Headers | Out-File 02_head_root.txt
} catch {
  "Header fetch failed (root): $_" | Out-File 02_head_root.txt
}
try {
  Invoke-WebRequest -Uri "https://example.com/login" -MaximumRedirection 5 -UseBasicParsing |
    Out-File 02_head_login_follow.txt
} catch {
  "Header fetch failed (login): $_" | Out-File 02_head_login_follow.txt
}
```

分岐：
- SSO遷移あり → `02_playbooks/03_authn_観測ポイント（SSO_MFA前提）.md`
- API中心（UI≠APIやAPI比率が高い） → `02_playbooks/05_api_権限伝播→検証観点チェック.md`
- UI中心でAuthZが鍵（`id/tenant/role` の手掛かり） → `02_playbooks/04_authz_境界モデル→検証観点チェック.md`
- “外部に滲む”設定/運用が鍵（CORS/Headers/Secrets/Errors/Logging/WAF） → `02_playbooks/10_web_config_ops_設定・運用境界_初動.md`
- 入力→実行の導線が中心（テンプレ/ファイル/外部URL入力等） → `02_playbooks/07_input_to_rce_入力→実行の導線.md`

### Phase 3: 認証の観測（40-60分）
実行：`02_playbooks/03_authn_観測ポイント（SSO_MFA前提）.md`

```powershell
$dir = Join-Path $HOME "keda_evidence\\authn_03"
New-Item -ItemType Directory -Force $dir | Out-Null
Set-Location $dir

# ログインフローをHARで記録（1回だけで根拠を作る）

# OIDC well-known確認（候補がある場合）
try {
  Invoke-WebRequest -Uri "https://example.com/.well-known/openid-configuration" -UseBasicParsing |
    Out-File 02_oidc_wellknown.json
} catch {
  "OIDC well-known fetch failed: $_" | Out-File 02_oidc_wellknown.json
}
```

分岐：
- セッション寿命が長い/失効が弱そう → AuthN の session lifecycle topic へ（詳細は `03_authn` から辿る）
- 権限伝播が強い（claim/role/tenant/scope が鍵） → `02_playbooks/04_authz_境界モデル→検証観点チェック.md` または `02_playbooks/05_api_権限伝播→検証観点チェック.md`

### Phase 4: 認可の検証（35-50分）
実行：`02_playbooks/04_authz_境界モデル→検証観点チェック.md`

```powershell
$dir = Join-Path $HOME "keda_evidence\\authz_04"
New-Item -ItemType Directory -Force $dir | Out-Null
Set-Location $dir

# ユーザーA/Bで差分観測（HARで記録）
# 例：自分のリソース vs 他人のリソース（まず read-only）
```

分岐：
- UI≠API のズレ/サーバ側判定が怪しい → `02_playbooks/05_api_権限伝播→検証観点チェック.md`
- テナント境界が怪しい → AuthZ の multi-tenant topic へ（`04_authz` から辿る）
- 共有/外部ゲストが絡む → `02_playbooks/08_saas_信頼→共有→監査ログ_初動.md`

### Phase 5: API検証（35-50分）
実行：`02_playbooks/05_api_権限伝播→検証観点チェック.md`

```powershell
$dir = Join-Path $HOME "keda_evidence\\api_05"
New-Item -ItemType Directory -Force $dir | Out-Null
Set-Location $dir

# 代表API 3本で差分観測（主体差→所有差→テナント差→操作差）
# 例：GET /api/orders, GET /api/orders/{id}, PATCH /api/orders/{id}
```

### Phase 6: 設定・運用の確認（30-45分）
実行：`02_playbooks/10_web_config_ops_設定・運用境界_初動.md`

```powershell
$dir = Join-Path $HOME "keda_evidence\\web_config_10"
New-Item -ItemType Directory -Force $dir | Out-Null
Set-Location $dir

# セキュリティヘッダ確認（代表点）
try {
  Invoke-WebRequest -Uri "https://example.com" -UseBasicParsing |
    Select-Object -ExpandProperty Headers | Out-File 01_head_root.txt
} catch {
  "Header fetch failed (root): $_" | Out-File 01_head_root.txt
}

# CORS確認（例：Origin差分。実際のAPIパスは対象に合わせる）
# 注意：事前に HAR で API パス（例：/api/users, /api/orders, /graphql）を特定してから実行
$apiEndpoint = "/api/users"  # 実際のエンドポイントに置き換え
try {
  Invoke-WebRequest -Uri ("https://api.example.com" + $apiEndpoint) `
    -Headers @{ "Origin" = "https://evil.com" } `
    -UseBasicParsing |
    Select-Object -ExpandProperty Headers | Out-File 02_cors_test.txt
} catch {
  "CORS test failed: $_" | Out-File 02_cors_test.txt
}

# JS内のsecrets探索（取得済みのJSファイルに対して）
# Select-String -Pattern "apiKey|token|secret|client_id|redirect_uri" -Path <js_files>
```

### 並行実行可能な観測（状況に応じて）
- `02_playbooks/08_saas_信頼→共有→監査ログ_初動.md`
  - タイミング：Phase 2 で SSO/外部連携が見えた時点、または Phase 3 の後
  - 条件：SSO/外部連携/監査ログが勝負のとき
- `02_playbooks/09_egress_exfil_出口評価（DNS_HTTP_SMB）.md`
  - タイミング：Phase 1 の後（NW環境が分かっている場合）
  - 条件：NW環境（出口/監視/制限）が分かっているとき（未確認なら能動試験はしない）
- `02_playbooks/06_network_enum_to_post_列挙→侵入後の導線.md`
  - タイミング：ペネトレで内部NW/侵入後導線が含まれるとき
  - 条件：内部ネットワークへのアクセスが許可されている場合

### 実践的な実行順序（推奨）
- Day 1 (2-3時間): `01_asm_passive-recon` → `02_web_recon` → `03_authn`
- Day 2 (2-3時間): `04_authz` → `05_api` → `10_web_config_ops`
- 必要に応じて: `07_input_to_rce`（入力点が見つかった場合） / `08_saas`（SaaS連携が見える場合） / `09_egress_exfil`（NW環境が分かる場合）

### 最小成果物（レポート品質を上げるための“根拠の型”）
- `99_summary.md`：`入口（URL/host） | 境界（資産/信頼/権限/運用） | 外部依存 | 次playbook | 根拠（HAR/ヘッダ/DNS/TLS）`
- AuthZ/API：`主体A/B | リソース（self/other） | 期待拒否/実結果 | 境界変数（id/tenant/role/scope） | 拒否点（UI/Server）`
- Config/Ops：`CSP/HSTS/CORS/Secrets/Errors/Logging/CDN-WAF = Yes/No/Unknown + 根拠`
