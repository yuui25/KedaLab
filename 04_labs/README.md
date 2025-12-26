# 04_labs README

目的: 検証環境を最短で構築・起動し、topics/playbooks を「観測→差分→判断」で回せる状態にする。

---

## 構成（全体像）
~~~~
04_labs/
├─ 00_index.md
├─ 01_local/        # 作業端末/Proxy/証跡設計
├─ 02_virtualization/  # NAT/Host-Only/Bridge
├─ 03_targets/      # 教材ターゲット
├─ 04_cloud/        # クラウド(任意)
└─ 05_automation/   # 巻き戻し/IaC
~~~~

---

## 最短起動（ローカル検証）
前提:
- Docker が使える
- ブラウザ + Proxy が使える（Har/Proxyログを取る）

手順:
1) 作業端末/観測点の準備
   - `04_labs/01_local/00_index.md`
   - `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
   - `04_labs/01_local/03_capture_証跡取得（pcap_harl_log）.md`
2) ターゲット起動（keda_app）
   ~~~~
   cd 04_labs/03_targets/keda_app
   docker compose up -d --build
   ~~~~
3) 動作確認
   - App: http://localhost:8080/
4) 巻き戻し
   ~~~~
   docker compose down -v
   ~~~~

任意: OIDC を使う場合
~~~~
cd 04_labs/03_targets/keda_app
OIDC_ENABLED=1 docker compose --profile oidc up -d --build
~~~~

---

## 構成（keda_app）
~~~~mermaid
flowchart LR
  AB["Attack Box\nBrowser + Proxy + HAR/pcap"] --> APP["keda-app (FastAPI)"]
  APP --> DB["sqlite (volume)"]
  AB --> KC["Keycloak (optional)"]
  APP --> KC
~~~~

---

## 追加のしかた（今後の拡張ルール）
原則:
- 1つの新規教材 = 1つの境界を学べる構成に絞る
- 観測点（Proxy/HAR/pcap/ログ）を先に決める
- 巻き戻し（reset/snapshot）ができる前提を必ず書く

追加する場所:
- 新しい教材アプリ: `04_labs/03_targets/<name>/`
- 教材の説明: `04_labs/03_targets/<NN>_<name>_*.md`
- 追加したら `04_labs/03_targets/00_index.md` にリンク

---

## サンプルテンプレ（追加用）
~~~~
# 0X_<name>_概要.md

## 目的
- 何の境界を学ぶ教材か

## 構成
- どのサービス/コンテナで動くか

## 起動手順
- docker compose up -d --build

## リセット
- docker compose down -v

## 観測ポイント
- どの差分を見るか（未ログイン/ログイン/ロール/テナント等）

## 関連リンク
- topics/playbooks/labs へのリンク
~~~~

