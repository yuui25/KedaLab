# 16_gpo_永続化と権限境界
GPOの二重構造（GPC/GPT）と権限（作成/編集/リンク）を分離し、永続化の成立条件を確定する

## 目標（この技術で到達する状態）
- GPOがどこに保存され、どう適用されるかを説明できる
- 永続化に繋がる操作を作成/編集/リンクに分解し、成立条件を言える
- 誰がどのOU/Domainにリンクできるか、どのGPOを編集できるかを根拠化できる
- 影響範囲（OU階層/リンク順/Enforced/Block/フィルタ/Loopback）を説明できる
- 是正（権限分離/Tier）と検知（AD変更＋SYSVOL変更＋適用ログ）まで提示できる

## 前提・対象・範囲・想定
### GPOはGPC（AD）＋GPT（SYSVOL）の二重構造
- GPC：ADのgroupPolicyContainer（参照情報）
- GPT：SYSVOL配下の実体（設定/スクリプト）
- クライアントはGPC→gPCFileSysPath→GPTの順で適用する

### 適用境界（Scope）
- リンク単位：Site / Domain / OU
- 絞り込み：Security Filtering / WMI Filtering / Loopback

### 永続化の成立条件（権限の分解）
- 作成（Create）/ 編集（Edit）/ リンク（Link）の組合せで成立条件が変わる

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 観測対象
- AD（GPO/OU/Domain）
  - GPO：displayName / name(GUID) / gPCFileSysPath / versionNumber / whenChanged / nTSecurityDescriptor
  - OU/Domain：gPLink / gPOptions
- SYSVOL
  - GPT.INI / Scripts / Preferences（XML）

### 境界の固定
- 資産境界：適用対象（Tier0/DC/基幹/一般端末）
- 信頼境界：委任主体が広すぎないか
- 権限境界：GPO編集権限とOUのgPLink変更権限の所在

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える
  - GPOはGPC/GPTの二段で成立し、適用範囲はgPLinkで決まる
  - 主体が作成/編集/リンクのどれを持つかで永続化の成立条件が変わる
- 言えない
  - 即座に侵害できる（到達性/監視/端末側制御が必要）
  - 本番での変更検証が安全にできる（検証OUが前提）

## 攻撃者視点での利用（意思決定：どれを先に見るか）
- 優先順位
  1) 高価値OU/Domainに対するLink権限
  2) 影響が広いGPOへのEdit権限
  3) Create＋Linkが揃う主体
  4) gPCFileSysPathの参照先変更
- 危険度が跳ねる状態
  - 低権限主体がDomain直下/上位OUのgPLinkを書ける
  - スクリプト/Preferencesを配るGPOに編集権限が委任されている
  - 監査がなく変更が追えない

## 次に試すこと（仮説A/B：条件で手が変わる）
### 仮説A：Link権限が緩い
- 次の一手
  - OU配下の資産価値（Tier）を確定
  - Create権限の有無を確認
  - OUのDACLを `15_acl_abuse` で裏取り

### 仮説B：Edit権限が緩い
- 次の一手
  - GPOの適用範囲を確定（リンク/継承/フィルタ）
  - GPOレポート（XML）で危険カテゴリの有無を確認
  - 監査（GPC/GPT変更）を確認

### 仮説C：参照境界が崩れている（gPCFileSysPath）
- 次の一手
  - 参照先共有のACL/署名/管理主体を確認
  - GPC属性変更監査を最優先で整備

### 仮説D：目立つ緩和がない
- 次の一手
  - 変更監査の整備
  - 他経路（`14_delegation` / `13_adcs` / `10_ntlm_relay` / `18_winrm` / `19_rdp` / `20_mssql`）へ

## 手を動かす検証（Labs連動：観測点を明確に）
### 実施方法（棚卸し→成立条件→影響→是正→検知）
- GPO一覧（GPC）を棚卸し
- OU/DomainのgPLinkを解析し適用範囲を確定
- 編集/リンク/作成の権限を分離して評価
- SYSVOLのGPT実体を読み取り、危険カテゴリの有無を確認
- 監査（AD変更＋SYSVOL変更＋適用ログ）を整備

### Lab最小構成
- DC/メンバーサーバ/クライアント
- OUを複数作り、リンク/継承/フィルタの差分を観測

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
# GPO一覧（RSAT）
Get-GPO -All | Select-Object DisplayName, Id, CreationTime, ModificationTime

# GPOレポート（XML）
Get-GPOReport -Guid <GPO_GUID> -ReportType Xml -Path .\\gpo_<GPO_GUID>.xml
~~~~
- ここで観測すること：GPOの一覧、内容、適用範囲の根拠
- 出力の注目点：gPCFileSysPath / versionNumber / gPLink
- 使えないケース：RSAT不可（LDAP/SMBで代替）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：最小権限/職務分離/変更管理でGPO権限を統制する
- WSTG：AD連携環境の前提としてGPO境界を観測する
- PTES：列挙→成立条件→影響→是正→検知で閉じる
- MITRE ATT&CK：Persistence/Defense Evasion/Lateral Movementに接続する配布チャネル

## 参考（必要最小限）
- Microsoft GPO / SYSVOL / GroupPolicy

## リポジトリ内リンク（最大3つまで）
- `01_topics/03_network/15_acl_abuse（AD権限グラフ）.md`
- `01_topics/03_network/05_scanning_到達性把握（nmap_masscan）.md`
- `01_topics/03_network/18_winrm_psremoting_到達性と権限.md`

## 深掘りリンク（最大8）
- `01_topics/03_network/05_scanning_到達性把握（nmap_masscan）.md`
- `01_topics/03_network/07_pivot_tunneling（ssh_socks_chisel）.md`
- `01_topics/03_network/11_ldap_enum_ディレクトリ境界（匿名_bind）.md`
- `01_topics/03_network/14_delegation（unconstrained_constrained_RBCD）.md`
- `01_topics/03_network/15_acl_abuse（AD権限グラフ）.md`
- `01_topics/03_network/18_winrm_psremoting_到達性と権限.md`
