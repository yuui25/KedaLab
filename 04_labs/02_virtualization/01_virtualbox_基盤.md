<<<BEGIN>>>
# 01_virtualbox_基盤.md

## 目的（この技術で到達する状態）
- Attack Box（Linux VM）をVirtualBoxで用意し、Web/NW検証を「分離された視点」で回せる。
- NAT / Host-Only を使い分けて、到達性・境界（信頼/資産）を自分で設計できる。
- Proxy・証跡（HAR/Proxyログ/pcap）・巻き戻し（スナップショット）を前提に、検証を高速に反復できる。

## 前提（対象・範囲・想定）
- ホスト：Windows（想定）。VirtualBoxが利用可能。
- VM：Linux（Kali/Ubuntu等、任意）。ここでは“Attack Box”として扱う。
- 目的：検証のための観測・比較。実環境での破壊的検証や過負荷は前提にしない。
- 依存（関連ファイル）：
  - `04_labs/01_local/01_attack-box_作業端末設計.md`
  - `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
  - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
  - `04_labs/05_automation/02_snapshots_reset_検証の巻き戻し.md`
  - `04_labs/02_virtualization/03_networking_nat_hostonly_bridge.md`

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
- VirtualBox基盤で確定したいこと
  - **視点（どの端末・どの経路）**：ホスト直 / VM経由 / Proxy経由
  - **到達性**：VM→外部（NAT）、VM↔検証セグメント（Host-Only）
  - **証跡の置き場**：VM内に固定、または共有フォルダでホストに回収（どちらでも“固定”が重要）
  - **巻き戻し**：検証前にスナップショットを取り、壊して学ぶ→即復帰できる
- 境界の観点
  - 信頼境界：ホスト（普段環境）とVM（検証環境）を分離し、汚染を防ぐ
  - 資産境界：証跡・トークン・鍵がどこに残るかを管理（共有フォルダの扱いに注意）
  - 権限境界：VM内部でも最小権限を基本に、必要時のみ昇格

## 設計（まず決める：迷いどころを先に固定）
### 1) VMの役割（Attack Box）
- Proxy/計測の中核（必要に応じて）
- CLIツール実行、軽い自動化（スクリプト）
- 証跡（proxy/pcap/メモ）の保存・整理

### 2) ネットワーク方針（最小で強い）
- Adapter 1：NAT（外部疎通、更新、外部参照）
- Adapter 2：Host-Only（検証専用セグメント：ターゲットVM群との隔離）
- Bridgeは必要時のみ（実ネットワーク影響が増えるため、常用しない）

### 3) 証跡の保存方針（VM内固定 or 共有）
- 方針A（推奨）：VM内の `~/pentest-work/` に固定し、必要時にエクスポート
  - 利点：秘密情報の拡散を抑えやすい（資産境界が明確）
- 方針B：共有フォルダでホストへ回収
  - 利点：バックアップ・検索が容易
  - 注意：共有フォルダに秘密情報が残る（アクセス制御・保管期限を決める）

## 構築手順（最小：クリック羅列ではなく“狙い”付き）
> ここでは「動く最小構成」を作る。細かな最適化は後回し。

### Step 1：VirtualBox側の準備（ホスト）
- VirtualBoxをインストールし、ホストOSを再起動（必要なら）
- Host-Onlyネットワークを作成（VirtualBoxのネットワーク設定）
  - 目的：検証用セグメントをホストの普段環境から分離する

### Step 2：Attack Box VMを作成
- Linux ISO（または既存イメージ）でVMを作成
- VMの基本設定（目安）
  - CPU/メモリ：ホストと相談（最小構成で良い。重ければ増やす）
  - ディスク：証跡が増えるので余裕を持たせる（後で拡張できる前提でも可）
- ネットワーク設定（重要）
  - Adapter 1：NAT
  - Adapter 2：Host-Only（Step1で作ったもの）

### Step 3：VM初回起動・初期設定（VM内）
- OS初期設定（ユーザ、更新、時刻、言語など）
- 証跡用ディレクトリの固定（必須）
~~~~
mkdir -p ~/pentest-work/captures/{har,proxy,pcap} ~/pentest-work/notes
~~~~
- この時点で「保存先が固定」されていることが重要（後で比較できる）

### Step 4：疎通確認（視点を固定する）
- NAT疎通（VM→外部）を確認：更新/外部参照ができる状態にする
- Host-Only疎通（VM↔同セグメント）を確認：ターゲットVMを置く前提を固める
- “どの経路で観測しているか”をメモに残す（視点固定）
  - 例：`VM(NAT)→Internet` / `VM(Host-Only)→TargetNet`

### Step 5：Proxy運用を載せる（必要最小）
- Proxy自体の詳細は `04_labs/01_local/02_proxy_計測・改変ポイント設計.md` に従う
- ここでやるのは「配置の固定」
  - ブラウザがホスト側なら：ホスト→VM(Proxy)へ到達できること
  - ブラウザがVM側なら：VM内でProxy→対象が観測できること

### Step 6：巻き戻し（スナップショット）を“検証前に”標準化
- まず「クリーン状態」のスナップショットを1つ作る（必須）
- 検証ごとにスナップショットを切る（壊して学ぶ→即復帰）
- 詳細の運用は `04_labs/05_automation/02_snapshots_reset_検証の巻き戻し.md` に統合する

## 失敗時の切り分け（経験則ではなく分類で）
> “落とし穴”として書かず、原因分類で最小限の切り分けを書く。

### A：NAT疎通できない
- 観点：ホスト側のネットワーク、VirtualBoxのNAT設定、VM内のDNS/ルーティング

### B：Host-Onlyで疎通できない
- 観点：Host-OnlyネットワークのIP帯、VM側のNIC有効化、同一セグメントにいるか

### C：Proxyが見えない（通信が入らない/復号できない）
- 観点：どのクライアントの通信か（ホスト/VM/アプリ）、経路設定、証明書、プロトコル差
- 参照：`04_labs/01_local/02_proxy_計測・改変ポイント設計.md`

### D：証跡が散逸する
- 観点：保存先が固定されていない、命名メタ（対象/日時/視点/条件）が残っていない
- 参照：`04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`

## 完了条件（このファイルのDone）
- Attack Box VMが起動し、NATで外部疎通できる
- Host-Onlyネットワークが作成され、VMがそのセグメントに参加している
- `~/pentest-work/` に証跡保存先が固定されている
- “クリーン状態”のスナップショットが1つ存在する
- 視点（端末/経路）をメモで説明できる（例：VM経由、Proxy経由など）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS：
  - 検証土台として、認証/認可/API/設定/ログの成立条件を“観測可能”にするための基盤
- WSTG：
  - Information Gatheringを含む各テスト観点を、同条件で反復・比較できる環境（観測の固定）
- PTES：
  - Intelligence Gathering / Vulnerability Analysis / Exploitation を反復できる“実験基盤”
- MITRE ATT&CK：
  - Reconnaissance / Discovery の理解を、視点差（経路/到達性）として体験し整理する

## 参考（必要最小限）
- `04_labs/02_virtualization/03_networking_nat_hostonly_bridge.md`
- `04_labs/01_local/01_attack-box_作業端末設計.md`
- `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- `04_labs/05_automation/02_snapshots_reset_検証の巻き戻し.md`

## リポジトリ内リンク（最大3つまで）
- 関連 labs：`04_labs/02_virtualization/03_networking_nat_hostonly_bridge.md`
- 関連 labs：`04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- 関連 labs：`04_labs/05_automation/02_snapshots_reset_検証の巻き戻し.md`

---


<<<END>>>
