# 04_labs README

検証環境の入口です。ここでは **起動方法** と **注意点** を明記します。

---

## 重要な注意点
- 本環境は教育目的です。**許可された環境のみ**で使用してください。
- 実システムへの適用・悪用は禁止です。
- 生成した証跡（HAR/ログ/pcap）は機密情報を含む可能性があるため、保管/共有に注意してください。

---

## 最短起動（チュートリアル: EC）
前提:
- Docker Desktop が使える
- ブラウザ + Proxy が使える（HAR/Proxyログを取る）

手順:
1) Docker Desktop セットアップ  
   - `04_labs/SETUP_DOCKER_DESKTOP.md`
2) チュートリアル環境の起動  
~~~~
cd 04_labs/scenarios/01_ec_order_flow/env
docker compose up -d --build
~~~~
3) 動作確認  
   - App: http://localhost:8080/
4) リセット  
~~~~
docker compose down -v
~~~~

---

## 構成（全体像）
~~~~
04_labs/
├─ README.md
├─ 00_index.md                  # シナリオ一覧
├─ SETUP_DOCKER_DESKTOP.md       # Docker導入
├─ SETUP_VIRTUALBOX.md           # VirtualBox導入
├─ SETUP_VMWARE.md               # VMware導入
└─ scenarios/
   ├─ _TEMPLATE/                 # 新規追加用テンプレ
   └─ 01_ec_order_flow/          # チュートリアル（EC）
~~~~

---

## 追加方法（最短）
1) `04_labs/scenarios/_TEMPLATE/` をコピー  
2) フォルダ名をシナリオ名に変更  
3) README / notes_template / writeup / env を埋める  
4) `04_labs/00_index.md` に1行で追記

