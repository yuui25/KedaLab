# 20_mssql_横展開（xp_cmdshell_linkedserver）
MSSQLの横展開成立条件（権限/設定/連携）を観測で確定する

## 目標（この技術で到達する状態）
- 到達性（1433）と接続権限をYes/Noで判定できる
- xp_cmdshellの有効/無効と実行コンテキストを確定できる
- Linked Serverの認証方式/RPC OUT/データアクセスを確定できる
- “SQL横展開グラフ”として踏み抜き点を示せる
- 監査/検知まで落とし込める

## 前提・対象・範囲・想定
- 対象：MSSQLインスタンス（Windows/SQL認証）
- 本ファイルは評価/観測が中心（実行手順の詳細は扱わない）

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) 到達性境界
- 1433/TDSの到達性（必要に応じ1434/UDP）

### 2) 権限境界
- sysadmin相当かどうか

### 3) OS境界（xp_cmdshell）
- 有効/無効、実行コンテキスト（SQLサービス/Proxy）

### 4) DB間境界（Linked Server）
- 認証マッピング（現在の資格情報/固定資格情報/不可）
- RPC OUT / Data Access

### 5) 監査境界
- SQL監査＋OSプロセス＋ネットワーク相関

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える：到達性/権限/xp_cmdshell/Linked Serverの成立条件
- 言えない：即侵害できる（到達性/監視/運用で変わる）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- sysadmin＋xp_cmdshell有効＋強いサービスアカウントは踏み抜き点
- 固定資格情報Linked Server＋RPC OUTは横展開鎖になりやすい

## 次に試すこと（仮説A/Bの分岐と検証）
### 仮説A：sysadmin相当
- xp_cmdshell有効/無効と実行コンテキストを確定

### 仮説B：Linked Serverが存在
- 認証方式/RPC OUTの設定を確定し、グラフに落とす

### 仮説C：到達性が限定的
- 観測点を変える（踏み台/管理網）か、設計として報告

## 手を動かす検証（Labs連動：観測点を明確に）
~~~~
nmap -Pn -n -sT -p 1433 --open <target_ip>
SELECT IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin;
SELECT name, value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell';
SELECT server_id, name, product, provider, data_source FROM sys.servers WHERE is_linked = 1;
~~~~

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
SELECT IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin;
SELECT name, value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell';
~~~~
- ここで観測すること：権限境界とxp_cmdshellの有効性
- 出力の注目点：is_sysadmin / value_in_use
- 使えないケース：接続権限が無い

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：DB運用の権限/監査境界の設計
- WSTG：管理機能（拡張SP/分散クエリ）の露出/設定検証
- PTES：到達性→権限→設定→連携→監査で閉じる
- MITRE ATT&CK：T1505.001（SQL Stored Procedures）

## 参考（必要最小限）
- xp_cmdshell公式
- Linked ServerのSecurity/RPC OUT設定

## リポジトリ内リンク（最大3つまで）
- `01_topics/03_network/05_scanning_到達性把握（nmap_masscan）.md`
- `01_topics/03_network/18_winrm_psremoting_到達性と権限.md`
- `01_topics/03_network/19_rdp_設定と認証（NLA）.md`

## 深掘りリンク（最大8）
- `01_topics/03_network/05_scanning_到達性把握（nmap_masscan）.md`
- `01_topics/03_network/07_pivot_tunneling（ssh_socks_chisel）.md`
- `01_topics/03_network/10_ntlm_relay_成立条件（SMB署名_LLMNR）.md`
- `01_topics/03_network/26_credential_dumping_所在（LSA_DPAPI）.md`
