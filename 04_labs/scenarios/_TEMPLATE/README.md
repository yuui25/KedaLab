# SCENARIO TEMPLATE README

## 背景（CTF風の設定）
- ここにシナリオの背景を書く

## 目的
- どの境界（AuthN/AuthZ/API/設定/ログ）を学ぶか

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

