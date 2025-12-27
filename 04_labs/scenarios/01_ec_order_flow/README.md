# 01_ec_order_flow（EC注文フロー）

## 背景（CTF風）
KedaMart は中小ECサイト。急拡大で注文・在庫・決済がAPI化され、権限境界の整理が追いついていない。
あなたは外部検証として「注文データの境界」と「認証/認可の成立条件」を観測し、改善提案を出す役割。

## 目的
- AuthN/AuthZ/API/設定/ログを “差分” で説明できる
- `kedaLab{...}` フラグを取得する

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

## ユーザー（初期）
- alice / alice（tenant-a, user）
- bob / bob（tenant-a, admin）
- carol / carol（tenant-b, user）

## 入口URL
- http://localhost:8080/

