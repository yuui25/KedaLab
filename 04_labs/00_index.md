<<<BEGIN>>>
# 00_index.md（検証環境：全体像と狙い）

## 目的（この検証環境で到達する状態）
- ペネトレ技術の「観測→解釈→利用→次の一手」を、手を動かして自走できる
- Web/NW/ASM/OSINT/SaaSの各topicsで扱う論点を、検証環境で確認し、成立条件と分岐を自分の言葉で説明できる
- 検証を高速に回すために「巻き戻し（snapshot/reset）」を前提に、仮説検証の反復を可能にする
- 環境構築そのものを学習として扱い、境界（資産/信頼/権限）を設計の主軸にできる

## 本Labsの方針（必ず守る）
- 環境は「作ること」が目的ではなく「技術理解を上げること」が目的
- 手順書ではなく「設計書」として書く（構成理由・境界・到達性・観測点・巻き戻しが主役）
- 1つのlabは“1つの学習目的（topicsの論点）”に結びつける（目的のない環境を増やさない）
- 取得する証跡は目的ベースで最小限（pcap/har/ログ/クラウド監査ログ等）。何のために取るかを必ず書く
- 破壊的検証は自前の検証環境でのみ行う（実環境での過剰試験を前提にしない）

## フォルダ構成（04_labs配下）
~~~~
04_labs/
├─ 00_index.md
├─ 01_local/
│  ├─ 00_index.md
│  ├─ 01_attack-box_作業端末設計.md
│  ├─ 02_proxy_計測・改変ポイント設計.md
│  └─ 03_capture_証跡取得（pcap/har/log）.md
│
├─ 02_virtualization/
│  ├─ 00_index.md
│  ├─ 01_virtualbox_基盤.md
│  ├─ 02_vmware_基盤.md
│  └─ 03_networking_nat_hostonly_bridge.md
│
├─ 03_targets/
│  ├─ 00_index.md
│  ├─ 01_web_targets_検証用アプリ選定.md
│  ├─ 02_api_targets_検証用API選定.md
│  └─ 03_ad_lab_検証用ドメイン構成.md
│
├─ 04_cloud/
│  ├─ 00_index.md
│  ├─ 01_aws_lab_構成と検証観点.md
│  ├─ 02_azure_lab_構成と検証観点.md
│  └─ 03_logging_クラウド監査ログの取り方.md
│
└─ 05_automation/
   ├─ 00_index.md
   ├─ 01_iac_terraform_or_bicep.md
   └─ 02_snapshots_reset_検証の巻き戻し.md
~~~~

## Labsの使い方（topicsとの連動）
- `01_topics/` の各ファイルには「手を動かす検証（Labs連動）」章を必ず置く
- その章では、以下を最低限書く
  - 参照するlabファイル（パス）
  - 取る証跡（har/pcap/ログ/監査ログ等）
  - 観測ポイント（どの差分を見るか、どの境界を確認するか）
- lab側には「どのtopicsの理解を上げるための環境か」を必ず書く（相互リンク）

## 学習目的で切る“環境セット”（増やしすぎない）
> まずは大枠を決め、各ファイルで詳細化する。

### セットA：Web観測・改変・再現（ローカル中心）
- 目的：HTTP/セッション/認可/API/入力の“観測→解釈→利用”を回す
- 主な要素：Attack Box、Proxy/計測、HAR/ログ、Web/APIターゲット

### セットB：NW列挙→侵入後の前提（仮想化中心）
- 目的：到達性→サービス→認証→権限推定、侵入後の前提（横展開の入口）を掴む
- 主な要素：仮想ネットワーク分離（NAT/Host-Only/Bridge）、NWターゲット、必要に応じてAD lab

### セットC：クラウド/外部依存（AWS/Azure）
- 目的：クラウド露出面、IAM境界、監査ログ、外部連携（SaaS含む）を“境界”として理解する
- 主な要素：最小構成のAWS/Azure lab、監査ログ取得、巻き戻し

## 証跡（観測）の基本方針
- 目的：再現性より「技術理解のための観測」
- 取得対象（例）
  - Web：har / proxyログ / アプリログ
  - NW：pcap / スキャン結果 / サービス応答ログ
  - クラウド：監査ログ（操作・認証・権限変更・通信）
- 観測の観点（差分）
  - 境界（資産/信頼/権限）がどこで変化しているか
  - 条件差（設定/環境/権限）で結果がどう変わるか
  - 攻め筋（仮説）が成立する条件が何か

## 巻き戻し（snapshot/reset）の前提化
- 目的：検証を高速に回し、仮説検証の反復回数を増やす
- 必須要素
  - VMスナップショットまたはIaC（必要最小限）
  - ターゲット初期化手順（壊したら戻せる）
  - ログの保存場所（後で比較できるように）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS：
  - labsは直接の要件ではなく、ASVSの検証・理解を支える“土台”として扱う（認証/認可/設定/ログ等）
- WSTG：
  - WSTGのテスト観点を実行・観測できる状態にする（特にINFO/認証/認可/API/設定）
- PTES：
  - Intelligence Gathering / Vulnerability Analysis / Exploitation / Post-Exploitation を検証可能にする基盤
- MITRE ATT&CK：
  - Discovery / Credential Access / Lateral Movement などの理解を、観測と環境で支える

## リポジトリ内リンク（最大3つまで）
- 関連 topics：01_topics/（各ファイルの「手を動かす検証」章）
- 関連 playbooks：02_playbooks/（分岐と判断の最短導線）
- 関連 cases：03_cases/（現実事例→検証観点への変換）

---


<<<END>>>