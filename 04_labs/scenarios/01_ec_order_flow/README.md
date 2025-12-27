# 01_ec_order_flow（EC注文フロー）

## 背景（CTF風）
KedaMart は中小ECサイト。急拡大で注文・在庫・決済がAPI化され、権限境界の整理が追いついていない。
あなたは外部検証として「注文データの境界」と「認証/認可の成立条件」を観測し、改善提案を出す役割。

## 目的
- AuthN/AuthZ/API/設定/ログを “差分” で説明できる
- `kedaLab{...}` フラグを取得する

## 使用するplaybook（このシナリオで回す型）
- `02_playbooks/03_authn_観測ポイント（SSO_MFA前提）.md`
- `02_playbooks/04_authz_境界モデル→検証観点チェック.md`
- `02_playbooks/05_api_権限伝播→検証観点チェック.md`
- `02_playbooks/10_web_config_ops_設定・運用境界_初動.md`

## 使用するtopics（このシナリオで参照する技術）
- `01_topics/02_web/02_authn_01_cookie属性と境界（Secure_HttpOnly_SameSite_Path_Domain）.md`
- `01_topics/02_web/02_authn_02_session_lifecycle（更新_失効_固定化_ローテーション）.md`
- `01_topics/02_web/02_authn_13_login_csrf_認証CSRFとstate設計.md`
- `01_topics/02_web/02_authn_14_logout_設計（RP_IdP_フロントチャネル）.md`
- `01_topics/02_web/02_authn_15_session_concurrency（多端末_同時ログイン制御）.md`

## 使用するガイドライン
- MITRE ATT&CK: Discovery / Collection / Privilege Escalation
- ASVS: V2（AuthN）, V4（Access Control）, V10（Logging）
- WSTG: ATHN / ATHZ / APIT / CONF
- PTES: Intelligence Gathering → Vulnerability Analysis → Exploitation（成立条件の説明）

## クリア条件
- `kedaLab{...}` を取得し、成立条件と影響を説明できる

## 起動
~~~~
cd /04_labs/scenarios/01_ec_order_flow/env
docker compose up -d --build
~~~~

## リセット
~~~~
docker compose down -v
~~~~

## DBシード
- 初期データは `04_labs/scenarios/01_ec_order_flow/env/app/db_seed.sql`

## 証跡（推奨）
- メモテンプレ：`04_labs/scenarios/01_ec_order_flow/notes_template.md`

## ユーザー（初期）
- alice / alice（tenant-a, user）
- bob / bob（tenant-a, admin）
- carol / carol（tenant-b, user）

## 入口URL
- http://localhost:8080/
