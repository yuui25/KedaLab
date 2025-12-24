<<<BEGIN>>>
# 00_index.md（仮想化基盤：視点分離・到達性・巻き戻しの全体像）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS：
  - このフォルダの位置づけ：認証/認可/API/設定/ログ等の“検証結果”が、環境差（経路差・到達性差）でブレないようにする前提基盤
  - 支えるポイント：同条件比較（差分）を成立させ、結論の再現性を上げる
- WSTG：
  - このフォルダの位置づけ：各テスト（認証/セッション/認可/API/設定）を実施する前に、観測点と経路を固定する
  - 支えるポイント：HTTP観測や改変が「どの視点（端末/経路）」で行われたかを説明可能にする
- PTES：
  - 該当フェーズ：Pre-engagement（環境準備）/ Intelligence Gathering（観測基盤）/ Vulnerability Analysis（差分の解釈）/ Exploitation（成立条件の切り分け）
  - 前後フェーズとの繋がり（1行）：仮想化で視点と到達性を固定すると、観測→解釈→検証の反復が“同条件”で回せる
- MITRE ATT&CK：
  - 該当戦術：Reconnaissance / Discovery / Collection（観測の土台）
  - 攻撃者の目的：到達性と境界を把握し、次の手（探索/侵入/横展開）を選ぶための前提を作る

## 目的（この仮想化基盤で到達する状態）
- ホスト（普段環境）と検証環境（VM）を分離し、**視点（どの端末・どの経路で観測したか）** を固定できる。
- NAT / Host-Only / Bridge を「用語」ではなく **到達性・観測・境界** の観点で使い分け、検証の差分比較ができる。
- Proxy・証跡（HAR/Proxyログ/pcap）・巻き戻し（スナップショット）を前提に、壊して学ぶ→即復帰の反復が回る。

## このフォルダで扱う範囲（02_virtualization）
- VirtualBox（または同等の仮想化）での Attack Box 基盤
- 検証ネットワークの設計（NAT / Host-Only / Bridge の意味と選択）
- 以降の labs（01_local の計測/証跡、05_automation の巻き戻し）を成立させる“前提条件”の固定

## 方針（必ず守る）
- 手順書ではなく設計書として書く（理由・境界・到達性・観測点が主役）。
- VMの作り方を網羅しない（“どの差分を取れるようにするか”が目的）。
- Bridge は必要時のみ（実ネットワークへ影響しやすく、制御が難しいため）。
- 迷ったら「最小で強い標準構成」に寄せ、必要になったら追加する。

## フォルダ構成（このフォルダ内）
~~~~
04_labs/02_virtualization/
├─ 00_index.md
├─ 01_virtualbox_基盤.md
└─ 03_networking_nat_hostonly_bridge.md
~~~~

## 設計の中核（仮想化で“技術”を上げるための要点）
### 1) 視点の分離（ホスト vs VM）
- 目的：普段環境の汚染（証跡/トークン混入、誤操作）を避け、検証の視点を固定する。
- 判断：
  - Web/NWを両方やるなら「Attack Box VM」を中心に据える方が、観測点（Proxy/pcap）を集約しやすい。

### 2) 到達性の設計（誰が誰に届くか）
- 目的：検証対象（Target VM）に対して、到達性を“意図通り”に作る。
- 判断（基本）：
  - Attack Box：NAT（外部参照/更新）＋ Host-Only（検証セグメント入口）
  - Target VM：Host-Only のみ（検証環境として隔離）

### 3) 観測点の集約（Proxy/pcap/保存先）
- 目的：観測（ログ/pcap/HAR）が散逸しないように、集約点を先に固定する。
- 接続：
  - Proxy設計：`04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
  - 証跡設計：`04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`

### 4) 巻き戻し（スナップショット）を“検証前”に標準化
- 目的：壊して学ぶ→即復帰を標準運用にする（学習効率と安全性が上がる）。
- 接続：
  - 巻き戻し運用：`04_labs/05_automation/02_snapshots_reset_検証の巻き戻し.md`

## 次に作る/読むファイル（このフォルダ内の推奨順）
1) `04_labs/02_virtualization/01_virtualbox_基盤.md`（Attack Boxを作る：視点/保存先/巻き戻しの入口）  
2) `04_labs/02_virtualization/03_networking_nat_hostonly_bridge.md`（到達性/観測/境界の設計：NAT/Host-Only/Bridge）  

## 手を動かす検証（このフォルダのDone）
- Attack Box VM が起動し、NATで外部参照ができる（更新/参照）
- Host-Only で Attack Box ↔ Target セグメントの“入口”が成立している
- 観測点（Proxy/pcap/保存先）が「どこで固定されるか」を説明できる
- “クリーン状態”のスナップショットが存在し、検証前に戻せる

## リポジトリ内リンク（最大3つまで）
- 関連 labs：`04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
- 関連 labs：`04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- 関連 labs：`04_labs/05_automation/02_snapshots_reset_検証の巻き戻し.md`

---

<<<END>>>
