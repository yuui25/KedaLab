# keda_app（KedaLab 自作教材アプリ）

KedaLabの topics/playbooks を **観測→差分→分岐** で回すための自作教材です。

## 目的（この教材で到達する状態）
- AuthN/AuthZ/API/Config/Logging の境界を、実通信（HAR/Proxy）で説明できる
- 代表ユーザー（A/B、テナント差）で差分セットを作り、次の一手を選べる
- 破壊して学ぶ→即復帰（`down -v`）ができる

## 構成
- `keda-app`：教材Web/API（FastAPI）
- `db`：sqlite（volume）
- `keycloak`：任意（OIDC教材）

## 起動（ローカルログインだけでOK）
~~~~
docker compose up -d --build
~~~~

環境変数は `.env` で上書きできます（例は `.env.example`）。

起動後：
- App：`http://localhost:8080/`

## 任意：Keycloak（OIDC）も起動する
~~~~
OIDC_ENABLED=1 docker compose --profile oidc up -d --build
~~~~

補足：
- OIDCは教材用途の最小実装です（`id_token` の署名検証は行いません）。

## 使い方（差分セット）
- userA（一般）/ userB（管理）/ tenantB（別テナント）
- 自分のデータ / 他人のデータ
- UIで見える/見えない vs APIで通る/通らない（UI≠API）

## リセット
~~~~
docker compose down -v
~~~~

## 参照（KedaLab内）
- Playbook：`02_playbooks/02_web_recon_入口→境界→検証方針.md`
- Playbook：`02_playbooks/03_authn_観測ポイント（SSO_MFA前提）.md`
- Playbook：`02_playbooks/04_authz_境界モデル→検証観点チェック.md`
- Playbook：`02_playbooks/05_api_権限伝播→検証観点チェック.md`
- Playbook：`02_playbooks/10_web_config_ops_設定・運用境界_初動.md`
