# 04_keda_app_教材Webアプリ（自作）

目的：KedaLab の topics/playbooks を「観測→差分→分岐」で回せる **自作教材** を用意する。

---

## 何ができるか（この教材で回せる境界）
- AuthN：ローカルログイン（セッションCookie）/（任意）OIDCログイン（Keycloak）
- AuthZ：所有者/ロール/テナントの境界を、API差分として観測できる
- API：UI≠API 前提で、代表API 3本を差分で回せる（主体差/所有差/テナント差）
- Config/Ops：CORS/セキュリティヘッダ/エラー詳細/ログ相関ID を、設定で切り替えて観測できる
- Logging：監査イベント（ログイン/重要操作）をDBに残し、相関キーで追える

## 置き場所
- 実体（docker-compose/アプリ）：`04_labs/03_targets/keda_app/`

## まず回すべきPlaybook（最初の5分の導線）
- Web入口→境界：`02_playbooks/02_web_recon_入口→境界→検証方針.md`
- AuthN観測：`02_playbooks/03_authn_観測ポイント（SSO_MFA前提）.md`
- AuthZ差分：`02_playbooks/04_authz_境界モデル→検証観点チェック.md`
- API差分：`02_playbooks/05_api_権限伝播→検証観点チェック.md`
- 設定/運用：`02_playbooks/10_web_config_ops_設定・運用境界_初動.md`

---

## 構成（docker-compose）
~~~~mermaid
flowchart LR
  subgraph LAB["Keda Lab（Host-Only / 検証セグメント）"]
    AB["Attack Box\n(Browser + Proxy + HAR/pcap)"] -->|HTTP(S)| APP["keda-app\n(FastAPI)"]
    AB -->|OIDC (任意)| KC["keycloak (任意)\nOIDC Provider"]
    APP -->|SQL| DB["sqlite (volume)"]
    APP -->|OIDC (任意)| KC
  end
~~~~

### 役割
- Attack Box：Proxy/HARで観測・差分作成、必要時pcap
- keda-app：教材アプリ（UI + API + 監査ログ）
- keycloak：SSO/OIDC教材（任意。起動しなくてもローカルログインで回せる）

---

## 通信の流れ（代表）

### 1) ローカルログイン（セッションCookie）
~~~~mermaid
sequenceDiagram
  participant B as Browser
  participant A as keda-app
  B->>A: GET /login
  A-->>B: login form
  B->>A: POST /login (username/password)
  A-->>B: Set-Cookie: session=...
  B->>A: GET / (Cookie付き)
  A-->>B: 200 (login済みの表示)
~~~~

### 2) OIDCログイン（任意：Keycloak）
~~~~mermaid
sequenceDiagram
  participant B as Browser
  participant A as keda-app
  participant K as Keycloak
  B->>A: GET /oidc/login
  A-->>B: 302 Location: K /auth?client_id=...
  B->>K: GET /auth ...
  K-->>B: login page
  B->>K: POST credentials
  K-->>B: 302 back to A /oidc/callback?code=...
  B->>A: GET /oidc/callback?code=...
  A->>K: POST /token (code交換)
  K-->>A: id_token/access_token
  A-->>B: Set-Cookie: session=...
~~~~

---

## 起動（最短）
~~~~
cd 04_labs/03_targets/keda_app
docker compose up -d --build
~~~~

## 任意：OIDC（Keycloak）も使う
~~~~
cd 04_labs/03_targets/keda_app
OIDC_ENABLED=1 docker compose --profile oidc up -d --build
~~~~

補足：OIDCは教材用途の最小実装です（`id_token` の署名検証は行いません）。

## リセット（教材の前提：巻き戻し）
~~~~
cd 04_labs/03_targets/keda_app
docker compose down -v
~~~~

---

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS：V2/V3/V4/V10 を “差分観測” で回せる教材（認証/セッション/認可/ログ）
- WSTG：INFO→ATHN→ATHZ→APIT→CONF を、同一教材で「観測→差分→判断」に落とす
- PTES：Pre-engagement（教材）→ IG（観測）→ VA（差分）→（必要なら）Exploitation（成立条件の説明）
- MITRE ATT&CK：Discovery/Collection/Credential Access/Defense Evasion を “境界崩壊の説明補助” として扱える
