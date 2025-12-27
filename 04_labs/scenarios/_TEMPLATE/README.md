# SCENARIO TEMPLATE README（シナリオ雛形）

## 背景（CTF風の設定）
- ここにシナリオの背景を書く

## 目的
- どの境界（AuthN/AuthZ/API/設定/ログ）を学ぶか

## 使用するplaybook（必ずパスで列挙）
- 例：`02_playbooks/03_authn_観測ポイント（SSO_MFA前提）.md`
- 例：`02_playbooks/04_authz_境界モデル→検証観点チェック.md`

## 使用するtopics（必ず `01_topics/...` のパスで列挙）
- 例：`01_topics/02_web/02_authn_01_cookie属性と境界（Secure_HttpOnly_SameSite_Path_Domain）.md`

## 使用するガイドライン
- MITRE ATT&CK（主に使う戦術）
- ASVS / WSTG / PTES（使う観点）

## クリア条件
- 例：`kedaLab{...}` の取得

## 起動
~~~~
docker compose up -d --build
~~~~

## リセット
~~~~
docker compose down -v
~~~~

## 証跡（推奨）
- `notes_template.md`（このシナリオ用のメモ雛形）
