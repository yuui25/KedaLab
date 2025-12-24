## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS
  - 破れる：DB（MSSQL）は「業務中枢」かつ「権限が濃い」ため、設定（xp_cmdshell/CLR/Agent）と連携（Linked Server）が噛み合うと、Valid Accounts だけで横方向に“面”が広がる。特に **(a) sysadmin相当権限**、**(b) OS権限が強いSQLサービスアカウント**、**(c) Linked Serverが“共通資格情報で接続”** の組合せは、1台の侵害がドメイン全体へ波及し得る。
  - 満たす：xp_cmdshell は原則無効、やむを得ず使うなら短時間・最小権限・監査を強制。Linked Server は「誰が」「どの資格情報で」「どの操作（RPC OUT/データアクセス）」が可能かを設計で固定し、監査（SQL Audit/ログ）と相関（プロセス/ネットワーク）で検知可能にする。:contentReference[oaicite:0]{index=0}
- WSTG
  - 該当観点：WSTG-CONF の Network Infrastructure Configuration は、DBの管理機能（拡張SP/分散クエリ/リモート実行）を“運用のために許している入口”として棚卸し・設定検証する観点に直結。:contentReference[oaicite:1]{index=1}
- PTES
  - 位置づけ：到達性（1433/Browser）→ サービス同定 → 権限境界（ログイン/ロール）→ 設定境界（xp_cmdshell/CLR/Agent）→ 連携境界（Linked Server/RPC）を、推測でなく“設定値・権限・監査ログ”で確定して報告へ落とす。:contentReference[oaicite:2]{index=2}
- MITRE ATT&CK
  - T1505.001 SQL Stored Procedures：OSコマンド実行のために追加機能（例：xp_cmdshell）が必要になる場合がある、という整理が明示されている。:contentReference[oaicite:3]{index=3}
  - DET0181（Detection Strategy）：xp_cmdshell を含むストアド手続き悪用を、SQL監査ログ＋プロセス生成（Sysmon等）で相関する設計指針。:contentReference[oaicite:4]{index=4}

---

## タイトル
MSSQL：横展開リスク（xp_cmdshell / Linked Server）を“成立条件（権限・設定・委任）”で確定し、検知と是正へ落とす

---

## 目的（このファイルで到達する状態）
- MSSQL を起点に横展開が起きる（または起き得る）条件を、以下の観点で **Yes/No/Unknown** まで落として説明できる。
  1) 到達性：どこから 1433/TDS（必要に応じ Browser 1434/UDP 等）へ到達可能か
  2) 権限：誰が接続でき、サーバーロール（特に sysadmin）に入っているか
  3) xp_cmdshell：有効/無効、誰が実行でき、OS上でどのセキュリティコンテキストになるか
  4) Linked Server：存在有無、接続方式（現在の資格情報 / 固定資格情報 / 未定義は不可）と、Server Options（データアクセス/RPC OUT）がどうなっているか
  5) “横展開の連鎖”：SQLインスタンス間の連携（Linked Server）をグラフとして把握し、どこが“踏み抜き点”かを示せる
  6) 検知・証跡：SQL監査（手続き/設定変更）とOS/NSM（プロセス/接続）を相関できる

> 重要：本ファイルは **防御・評価（設定/権限/監査の確認）** を主目的とし、OSコマンド実行や横展開の“実行手順”そのもの（悪用可能な手順の詳細）は扱わない。

---

## 扱う範囲（本ファイルの守備範囲）
- 扱う
  - xp_cmdshell のリスク成立条件（有効化状態・実行権限・実行コンテキスト・Proxy）
  - Linked Server のリスク成立条件（認証マッピング・RPC OUT/データアクセス・委任）
  - “SQL横展開グラフ”の作り方（どの情報を収集し、どう判断するか）
  - 監査・検知の最小設計（SQL監査＋プロセス＋ネットワーク相関）
- 扱わない（別ファイルへ接続）
  - 侵入後の認証情報抽出 → `26_credential_dumping_所在（LSA_DPAPI）.md`
  - NTLM relay → `10_ntlm_relay_成立条件（SMB署名_LLMNR）.md`
  - RDP/WinRMの到達性 → `18_winrm...` `19_rdp...`
  - AD委任/証明書悪用 → `13_adcs...` `14_delegation...`

---

## 前提：xp_cmdshell と Linked Server が“何を増やすか”
### xp_cmdshell（危険性の本質）
- xp_cmdshell は「SQLからOSへ」境界を跨ぐ機能。
- 既定では新規インストールで無効が推奨され、利用は慎重に検討すべき、と明示されている。:contentReference[oaicite:5]{index=5}
- 実行コンテキスト：
  - sysadmin が呼ぶ場合：SQL Server サービスの実行アカウント（OS権限）で動く。:contentReference[oaicite:6]{index=6}
  - 非sysadmin が呼ぶ場合：Proxy（xp_cmdshell proxy credential）を用いる（設定されていないと失敗）。:contentReference[oaicite:7]{index=7}

### Linked Server（危険性の本質）
- Linked Server は「このSQLから別SQL/別データソースへ」境界を跨ぐ機能。
- 接続方式（Security Tab）の選択が “横展開の強さ” を決める：
  - 「現在のログインのセキュリティコンテキストで接続」
  - 「このセキュリティコンテキスト（固定資格情報）で接続」
  - 「未定義は接続させない」  
  などがあり、設計を誤ると “誰でも共通の強権限でリモート接続できる” 状態が生まれる。:contentReference[oaicite:8]{index=8}
- さらに Server Options（例：RPC OUT）で「リモート手続き呼び出し」を許すと、DB間で“やれること”が増える（＝境界が薄くなる）。:contentReference[oaicite:9]{index=9}

---

## 境界モデル（横展開が“成立する条件”を層で固定する）
### 境界1：到達性（1433/TDS、必要に応じ 1434/UDP）
- 外部/他セグメントから DB へ到達可能か（FW/ACL/経路）。
- “管理系・基幹系”は到達性を最小化し、踏み台やアプリ層からのみ許可するのが基本。

### 境界2：DB認証・権限（ログイン → ロール → 権限）
- ログインできるだけでなく、どこまでの権限があるかが決定的。
- 特に **sysadmin** は「DB上で事実上の全権」に近く、xp_cmdshell や設定変更の前提になりやすい。:contentReference[oaicite:10]{index=10}

### 境界3：OS境界（xp_cmdshell が跨ぐ）
- xp_cmdshell が有効なら、DB→OSへの橋が存在する。
- その橋を渡ったときの“権限”は、SQLサービスアカウント/Proxyに依存する。:contentReference[oaicite:11]{index=11}

### 境界4：DB間境界（Linked Server が跨ぐ）
- Linked Server の **認証マッピング** と **RPC OUT / Data Access** が跨ぎ方を決める。:contentReference[oaicite:12]{index=12}
- マッピングが「固定資格情報」だと、ローカル側の広い利用者が “同じ強権限” でリモートへ届く危険がある（設計/監査ポイント）。

### 境界5：監査境界（SQL監査＋OS/NSM相関で“見える化”）
- DET0181 のように、SQL手続き（xp_cmdshell等）とプロセス生成を相関する設計が現実的。:contentReference[oaicite:13]{index=13}

---

## 実施方法（最高に具体的）：観測→判断→次の一手
> ここでは “評価・確認の手順” に限定する（環境へ影響する設定変更や、OSコマンド実行の手順は記載しない）。

### 0) 事前に“SQL横展開台帳（グラフ前提）”を作る
- 対象SQLインスタンスごとに、最低限この項目を埋める（Unknown を残してよい）
  - `Instance`: hostname\instance / IP:port
  - `Reachability`: 観測元（あなた/踏み台/セグメント）→ 1433 到達（Yes/No/Filtered）
  - `Auth`: Windows統合 / SQL認証（許可の有無は“観測”として）
  - `Role`: sysadmin相当（Yes/No/Unknown）
  - `xp_cmdshell`: enabled（Yes/No/Unknown）
  - `xp_cmdshell context`: SQLサービスアカウント / Proxy（判明/不明）
  - `Linked Servers`: ある/ない、件数
  - `Linked Server security`: current context / fixed credential / not be made（判明/不明）
  - `Linked Server options`: data access / rpc out（判明/不明）
  - `Evidence`: コマンド出力/SQL監査設定/SSMSスクショの保存先

---

## 1) 到達性の確定（ネットワーク観測）
### 1-A) 観測（例：nmap）
- 目的：DBへ“そもそも届くのか”を、経路別に確定する。
~~~~
nmap -Pn -n -sT -p 1433 --open <target_ip>
~~~~
- 判断
  - open：FW/ACL上は通る（次は “MSSQLである” と “暗号化状態” へ）
  - filtered/closed：設計上の分離が効いている可能性（観測元を変えて再評価）

> 補足：SQL Server 2025 ではデータ転送の暗号が “より secure-by-default 方向” に進化している（TDS 8.0 / TLS 1.3 など）。新旧混在環境では「どのバージョンがどの暗号前提か」を台帳に切る。:contentReference[oaicite:14]{index=14}

---

## 2) 権限境界の確定（接続できる場合：最小の“情報取得”で判定）
### 2-A) 最小質問（この順で確定させる）
- 接続ユーザの “サーバーロール” を判定
- xp_cmdshell が “有効/無効” を判定
- Linked Server が “存在するか” を判定

#### 2-A-1) サーバーロール（sysadmin）判定（例：読み取りクエリ）
- 目的：横展開の成立条件の根（sysadmin相当か）を最初に確定する。
~~~~
SELECT IS_SRVROLEMEMBER('sysadmin') AS is_sysadmin;
~~~~
- 判断
  - 1：このアカウントは“設定変更・高権限操作”へ到達し得る（厳重に監査観点へ）
  - 0：権限境界（Proxy/JEA的な代替）を前提に評価する

---

## 3) xp_cmdshell の成立条件（有効/無効、実行コンテキスト）を確定
### 3-A) xp_cmdshell が有効か（読み取りで確定）
- 目的：推測でなく “サーバー構成オプション” として確定する。
~~~~
SELECT name, value_in_use
FROM sys.configurations
WHERE name = 'xp_cmdshell';
~~~~
- 判断
  - value_in_use = 1：xp_cmdshell 有効（OS境界が存在）
  - value_in_use = 0：無効（原則はこれが望ましい）:contentReference[oaicite:15]{index=15}

### 3-B) “誰が実行でき、どのOS権限で動くか” を評価項目に分解
- 重要な根拠（報告で必須）
  - sysadmin が呼ぶと、SQL Server サービスのセキュリティコンテキストで実行される。:contentReference[oaicite:16]{index=16}
  - 非sysadmin が呼ぶ場合は Proxy（##xp_cmdshell_proxy_account##）が必要で、なければ失敗する。:contentReference[oaicite:17]{index=17}

#### 3-B-1) Proxy の有無（“設定されているか”を確認する観点）
- 目的：非sysadminに開放されている可能性（= 実行範囲が広い）を判定。
- 根拠：Proxy credential を作成・削除するための手続きが明示されている。:contentReference[oaicite:18]{index=18}
- 判断
  - Proxyあり：非sysadminへ xp_cmdshell を開放している運用の可能性 → “誰に付与しているか（監査）” が必要
  - Proxyなし：原則 sysadmin に閉じる（ただし sysadmin 自体の統制が必須）

### 3-C) 次の一手（是正/運用の落としどころ）
- 原則：xp_cmdshell は無効のまま（Microsoftも “新規コードで使うべきではなく、一般に無効のままにすべき” と明記）。:contentReference[oaicite:19]{index=19}
- 例外（業務都合で必要）：
  - “必要な作業の間だけ有効化し、終わったら無効化” を運用手順に固定（監査ツール検知の可能性も考慮）。:contentReference[oaicite:20]{index=20}
  - Proxy を使う場合は Windows権限を最小化し、ローカル管理者/ドメイン高権限を避ける（設計・監査ポイント）。:contentReference[oaicite:21]{index=21}

---

## 4) Linked Server の成立条件（“どこまで跨げるか”）を確定
### 4-A) Linked Server の存在（一覧）を確定
- 目的：SQL→SQL の“横方向の線”を列挙する（グラフの辺）。
- 代表的な保管場所：`sys.servers` に Linked Server が記録される（is_linked=1）。:contentReference[oaicite:22]{index=22}
~~~~
SELECT server_id, name, product, provider, data_source, is_remote_login_enabled, modify_date
FROM sys.servers
WHERE is_linked = 1;
~~~~
- 判断
  - 0件：Linked Server 起点の横方向は薄い（ただし別方式がないか確認）
  - 1件以上：次で “Security/Options” を確認し、危険な接続方式を特定

### 4-B) “Security Tab の設計”を観測で確定（SSMSでも良い）
- 目的：Linked Server が「誰の資格情報で接続する」設計かを確定する。
- Security Tab の選択肢は、以下のように整理される（= 設計レビューの観点になる）。:contentReference[oaicite:23]{index=23}
  - 未定義のログインは接続させない（Not be made）
  - セキュリティコンテキスト無し（Be made without using a security context）
  - 現在のログインのセキュリティコンテキスト（Be made using the login's current security context）
  - 固定資格情報（Be made using this security context）

#### 判断（リスクの見立て）
- 固定資格情報（特に強権限）：
  - ローカル側の多くの利用者が、リモート側へ“同じ権限で”到達し得る（横展開の踏み抜き点になりやすい）
- 現在コンテキスト：
  - 委任（Kerberos delegation 等）やプロバイダ対応に依存し、成立条件が複雑（ただし設計としては“個人に紐づく”方向）

### 4-C) “Server Options（RPC OUT / Data Access）”の確認（危険な拡張を特定）
- 目的：Linked Server が「データ参照だけ」なのか「リモート手続き実行まで可能」なのかを切り分ける。
- RPC / RPC OUT の意味：リモート手続き呼び出し（RPC）を許可するオプションで、sp_serveroption により制御される。:contentReference[oaicite:24]{index=24}
- 管理上の重要点：sp_serveroption の実行には `ALTER ANY LINKED SERVER` 権限が必要（= 付与先が広いと設定が勝手に変わるリスク）。:contentReference[oaicite:25]{index=25}

> 分散クエリの代表的手段（4部構成名/OPENQUERY 等）は Microsoft Learn に整理がある。運用で使っている手段を台帳に記録し、“どこまで許しているか”の境界にする。:contentReference[oaicite:26]{index=26}

---

## 5) “SQL横展開グラフ”としてまとめる（報告が一気に強くなる）
### 5-A) グラフのノードとエッジ
- ノード：SQLインスタンス（A, B, C…）
- エッジ：A → B（Linked Server）
  - 属性：Security方式（current/fixed/none）、RPC OUT（on/off/unknown）、Data Access（on/off/unknown）
- ノード属性：xp_cmdshell（on/off）、sysadmin統制（強/弱）、SQLサービスアカウント（高権限か）

### 5-B) “踏み抜き点（Chokepoint）”の定義
- 例：次の条件を満たすノードは優先是正候補
  - sysadminが多い（統制弱い） AND xp_cmdshell 有効 AND SQLサービスアカウント権限が強い  
  - 固定資格情報Linked Server を持つ AND RPC OUT まで許可されている  
  - 監査が弱く、xp_cmdshell/手続き変更が検知できない

---

## 6) 検知・証跡（攻め筋ではなく“守りの相関設計”を固定する）
### 6-A) SQL側（監査ログ/監査機構）
- 監視対象（例）
  - ストアド手続き作成/変更（xp_cmdshell呼び出しを含む）
  - xp_cmdshell 設定変更（sys.configurations）
  - Linked Server の作成/変更（Security/Options）
- DET0181 は、SQL監査ログ（手続き/呼び出し）とプロセス生成の相関を推奨している。:contentReference[oaicite:27]{index=27}

### 6-B) OS側（プロセス生成）
- 監視対象（例）
  - SQL Server プロセス（sqlservr.exe）からの子プロセス生成（特に cmd.exe 等）
- ここは Sysmon EventCode=1 等で相関可能、というのが DET0181 の考え方。:contentReference[oaicite:28]{index=28}

### 6-C) ネットワーク側（NSM）
- 監視対象（例）
  - SQL Server ホストから “普段出ない” 横方向通信（SMB/RDP/WinRM/HTTP等）
- この観点は `18_winrm...` `19_rdp...` と相互参照し、横展開の“出口”を揃える。

---

## 7) 是正方針（最小コストで効く順）
1. 到達性を絞る：DBはアプリ/管理網のみ（セグメント境界で）
2. sysadmin を絞る：運用ロール分離・棚卸
3. xp_cmdshell を無効化（原則）／例外運用は短時間＋監査＋最小権限（Microsoftの推奨に沿う）:contentReference[oaicite:29]{index=29}
4. Linked Server の Security を見直す：固定資格情報の濫用を避け、“未定義は不可”を基本に
5. RPC OUT / Data Access の最小化：必要な用途に限定し、変更権限（ALTER ANY LINKED SERVER）を絞る:contentReference[oaicite:30]{index=30}
6. 監査の相関：DET0181（SQL監査＋プロセス生成）を設計として導入:contentReference[oaicite:31]{index=31}

---

## 参考URL（本文の根拠として使用：そのまま貼る）
- Server configuration: xp_cmdshell（既定無効・セキュリティ注意）  
  https://learn.microsoft.com/en-in/sql/database-engine/configure-windows/xp-cmdshell-server-configuration-option :contentReference[oaicite:32]{index=32}
- sp_xp_cmdshell_proxy_account（Proxy credential の作成/削除）  
  https://learn.microsoft.com/bs-latn-ba/sql/relational-databases/system-stored-procedures/sp-xp-cmdshell-proxy-account-transact-sql?view=fabric-sqldb :contentReference[oaicite:33]{index=33}
- xp_cmdshell の実行コンテキスト（sysadmin→SQLサービス、非sysadmin→Proxy）  
  https://documentation.help/tsqlref/ts_xp_aa-sz_4jxo.htm :contentReference[oaicite:34]{index=34}
- MITRE ATT&CK：T1505.001 SQL Stored Procedures（xp_cmdshell等の言及）  
  https://attack.mitre.org/techniques/T1505/001/ :contentReference[oaicite:35]{index=35}
- MITRE ATT&CK：DET0181（xp_cmdshell/CLR 等の検知相関）  
  https://attack.mitre.org/detectionstrategies/DET0181/ :contentReference[oaicite:36]{index=36}
- Linked Server の Security Tab（設計選択肢の整理）  
  https://documentation.help/entrmgr/em_5wxl.htm :contentReference[oaicite:37]{index=37}
- Linked Server：RPC/RPC OUT（sp_serveroption）例  
  https://docs.cloud.google.com/sql/docs/sqlserver/manage-linked-servers :contentReference[oaicite:38]{index=38}
- sp_serveroption 実行に必要な権限（ALTER ANY LINKED SERVER）  
  https://learn.microsoft.com/ja-jp/sql/database-engine/configure-windows/view-or-configure-remote-server-connection-options-sql-server?view=sql-server-ver17 :contentReference[oaicite:39]{index=39}
- 分散クエリ（OPENQUERY/4部構成名など）の概要（参考）  
  https://learn.microsoft.com/ja-jp/troubleshoot/sql/analysis-services/perform-distributed-query-olap :contentReference[oaicite:40]{index=40}
- Linked Server クエリに変数を渡す（OPENQUERY等の実運用上の注意）  
  https://learn.microsoft.com/ja-JP/troubleshoot/sql/admin/pass-variable-linked-server-query :contentReference[oaicite:41]{index=41}
- SQL Server 2025：secure-by-default（TDS 8.0/TLS 1.3、Linked Server等の言及あり）  
  https://techcommunity.microsoft.com/blog/sqlserver/secure-by-default-what%E2%80%99s-new-in-sql-server-2025-security/4424340 :contentReference[oaicite:42]{index=42}
- OWASP WSTG：Network Infrastructure Configuration  
  https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration :contentReference[oaicite:43]{index=43}
- PTES（参照元）  
  https://pentest-standard.readthedocs.io/ :contentReference[oaicite:44]{index=44}
- OWASP ASVS（参照元）  
  https://github.com/OWASP/ASVS :contentReference[oaicite:45]{index=45}

---

## 深掘りリンク（最大8）
- `05_scanning_到達性把握（nmap_masscan）.md`
- `06_service_fingerprint（banner_tls_alpn）.md`
- `07_pivot_tunneling（ssh_socks_chisel）.md`
- `10_ntlm_relay_成立条件（SMB署名_LLMNR）.md`
- `18_winrm_psremoting_到達性と権限.md`
- `19_rdp_設定と認証（NLA）.md`
- `26_credential_dumping_所在（LSA_DPAPI）.md`
- `27_persistence_永続化（schtasks_services_wmi）.md`
