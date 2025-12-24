## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS
  - 破れる：SNMP は「運用監視のための機能」だが、v1/v2c（community）は平文かつ実質“共有パスワード”として扱われがちで、露出するとネットワーク構成・資産情報・経路情報・ユーザ/プロセス等が一括で抜ける。書き込み（RW）まで有効だと設定改変（ACL/ルーティング/サービス起動停止）に直結し、横展開の前段情報が揃う。
  - 満たす：管理セグメント限定・ACL固定・v1/v2c無効化（可能なら）・v3（USM+VACM）で最小権限（Read View限定、Write禁止が基本）・監査ログ/フローでGETBULK/GETNEXTの異常を検知、を“設計”として固定する。
- WSTG
  - WSTG-CONF-01：インフラ構成管理の観点で、SNMPのような周辺管理プロトコルの露出・設定不備がアプリ/基盤全体リスクになるため、到達性・設定（認証/暗号/許可IP）・情報露出量を検証対象にする。
  - 根拠URL：https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration
- PTES
  - Information Gathering →（到達性）→（認証方式の特定：community/v3）→（列挙：MIB範囲・権限）→（影響評価：漏えい情報→攻め筋/守りの設計）→ Reporting。SNMPは“観測で確定できることが多い”ため、設定値と取得結果でYes/No/Unknownまで落とす。
  - 根拠URL：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK
  - T1602.001（SNMP (MIB Dump)）：ネットワーク機器等に対するSNMP列挙（MIBダンプ）を手口として明示。
  - 検知（DET0453）：大量OID列挙（GETBULK/GETNEXT）や非管理IPからのSNMP、community/認証失敗→成功の連鎖などを相関して検知する方針が整理されている。
  - 根拠URL（Technique / Detection）：https://attack.mitre.org/detectionstrategies/DET0453/

---

## タイトル
SNMP：community（v1/v2c）と v3（USM/VACM）の境界を“到達性→設定→取得できる情報”で確定する

---

## 目的（このファイルで到達する状態）
- 対象の SNMP について、推測ではなく **観測（到達性/応答/取得結果）と設定（許可IP/ユーザ/ビュー）** で次を説明できる。
  1) 到達性：どこから UDP/161（要求）・UDP/162（trap）が到達するか
  2) 方式：v1/v2c（community）か v3（USM/VACM）か、混在か
  3) 認証/暗号：v3 の securityLevel（noAuthNoPriv/authNoPriv/authPriv）が何か
  4) 権限：RO/RW（v1/v2c）や VACM View（v3）で「読めるOID範囲/書けるOID範囲」がどこまでか
  5) 情報露出：取得できた情報を “攻め筋に直結するカテゴリ” へ分類し、影響範囲を言語化できる
  6) 検知/証跡：SNMP列挙（GETBULK/GETNEXT）の異常を Blue が追える相関キーを提示できる

---

## 扱う範囲（本ファイルの守備範囲）
- 扱う
  - SNMP到達性（UDP 161/162）と“管理セグメント限定”の検証
  - v1/v2c（community）と v3（USM/VACM）の違い・境界・成立条件
  - 情報収集（read）を中心に、取得対象（OID/MIB）を“実務で効く粒度”で整理
  - 監査/検知（異常なwalk/bulkwalk、失敗→成功の連鎖）
- 扱わない（別ファイルへ接続）
  - 具体的なパスワード推測/総当たり（許可が無い限り実施しない）→ 認証監査の設計論点としてのみ触れる
  - 横展開の実行（RDP/WinRM等）→ `18_winrm...` `19_rdp...`
  - 共有経由持ち出し → `28_exfiltration...`

---

## 前提：SNMPの“境界”を決める3要素（ここが診断の背骨）
### 1) Transport/到達性（UDP 161/162）
- SNMPは典型的に UDP/161（要求）・UDP/162（Trap）を使用する（デフォルト）。  
  根拠URL：https://www.net-snmp.org/wiki/index.php/FAQ%3AGeneral_18
- まず到達性が広いと、それだけで “管理情報面” が露出する（監視用プロトコルは守りにくい）。

### 2) 認証・暗号（v1/v2c と v3）
- v1/v2c：community ＝ 共有秘密（実務上はパスワード扱い）。平文で取り扱われ得る点は古典的に問題化されている。  
  根拠URL（Microsoft bulletin：v1はsecurity by designがない/盗聴でcommunity取得可能）：https://learn.microsoft.com/en-us/security-updates/securitybulletins/2000/ms00-095
- v3：アーキテクチャは Security Subsystem / Access Control Subsystem を含む（USM/VACM）。  
  根拠URL（RFC3411）：https://www.rfc-editor.org/rfc/rfc3411  
  根拠URL（RFC3414 USM）：https://www.rfc-editor.org/info/rfc3414  
  根拠URL（RFC3415 VACM）：https://www.rfc-editor.org/rfc/rfc3415

### 3) アクセス制御（RO/RW と View）
- v1/v2c：RO/RW community の分離が重要（RWが残っていると“設定改変”へ直行）。
- v3：USM（ユーザ/鍵）＋ VACM（View）で「読めるOIDの範囲」「書けるOIDの範囲」を最小化できる。  
  根拠URL（VACM）：https://www.rfc-editor.org/rfc/rfc3415

---

## 境界モデル（事故が起きる組合せを“成立条件”で固定する）
### 境界1：到達性（管理セグメント以外から161に届く）
- “監視のため”に有効化されがちで、境界設計が緩いと外部/全VLANから到達してしまう。
- 結論の書き方：  
  - 「SNMPは管理セグメントからのみ到達可能（Yes/No）」  
  - 「許可IPがACLで固定されている（Yes/No/Unknown）」

### 境界2：v1/v2cが有効（community運用）
- 盗聴/設定漏えい/使い回しの影響が大きい（共有秘密の単一点）。
- ROだけでも情報漏えいが成立、RWがあると改変へ進む。

### 境界3：v3でも “弱い運用” がある（noAuthNoPriv 等）
- v3は設計上 Security Level を持ち、noAuthNoPriv / authNoPriv / authPriv がある。  
  根拠URL（概要例）：https://docs.oracle.com/cd/E19253-01/817-3000/security-5/index.html
- 結論の書き方：  
  - 「v3 authPriv が強制（Yes/No/Unknown）」  
  - 「noAuthNoPriv が許可（Yes/No/Unknown）」※許可されているなら設計レビュー対象

### 境界4：View（VACM）が広すぎる（MIB-2全開/企業MIB全開）
- “監視のための最小OID” を超えて、構成・経路・ユーザ・プロセス・ソフトウェア等が抜けると攻め筋に直結する。

### 境界5：検知が無い（大量GETNEXT/GETBULKが埋もれる）
- DET0453 が示す通り、異常な列挙はクエリ量/頻度/送信元/失敗→成功の相関で検知できる余地がある。  
  根拠URL：https://attack.mitre.org/detectionstrategies/DET0453/

---

## 実施方法（最高に具体的）：観測→判断→次の一手
> 注意：ここは “許可された診断” を前提とする。communityの推測や総当たりはスコープ/合意がない限り実施しない。  
> 代替：クライアントから提供された community/v3ユーザを用いて、露出範囲（View）と到達性を評価する。

---

## 0) 事前準備：SNMP観測台帳（必須）
- `target`: IP / ホスト名 / 機器種別（NW機器/サーバ/IoT）
- `observer`: 観測元（あなた/踏み台/pivot）とセグメント
- `reachability`: UDP/161, UDP/162（Yes/No/Filtered）
- `version`: v1/v2c/v3（観測根拠）
- `auth`: community名（提供されたもの）/ v3 user/securityLevel（提供されたもの）
- `view`: 取得可能なOID範囲（MIB-2のみ/IF-MIB/Host-Resources/企業MIB 等）
- `rw`: write可能の有無（Unknownでも良い：設定/運用で確定）
- `evidence`: コマンド出力（txt）、取得結果（snmpwalkログ）

---

## 1) 到達性：UDP/161（+162）を“経路別”に確定する
### 1-A) nmap（UDPは“open|filtered”が出やすい前提で、結果を言語化する）
~~~~
# まずはSNMP（161/udp）とTrap（162/udp）
sudo nmap -sU -Pn -n -p 161,162 --reason <target_ip> -oN snmp_udp_reach_<target>.txt

# 応答が鈍いときはレート/再送を調整（環境の許可範囲で）
sudo nmap -sU -Pn -n -p 161 --reason --max-retries 2 --host-timeout 30s <target_ip> -oN snmp_udp161_fast_<target>.txt
~~~~

#### 判断
- open / open|filtered：次は “SNMPとして応答するか” をアプリ層（snmpget）で確定する
- filtered：FW/ACL境界が効いている（観測元を変えて“設計どおり”かを確認）

#### 次の一手
- 管理セグメント外から到達している → 設計不備の一次所見（最重要）
- 管理セグメントからのみ到達 → 次の「露出範囲（View）」評価へ

---

## 2) 方式判定：v1/v2c（community）か v3（USM）か
> 目的：ツールの失敗理由を “設定/方式の違い” として説明できるようにする。

### 2-A) 最小の応答確認（sysDescr.0 で確認する）
- sysDescr.0（1.3.6.1.2.1.1.1.0）は “まず取る” 定番（OS/機器情報の入口）。
- v2c の例（※communityは提供された値を使用）
~~~~
snmpget -v2c -c <COMMUNITY_RO> <target_ip> 1.3.6.1.2.1.1.1.0
~~~~
- v3 の例（※ユーザ/鍵は提供された値を使用）
  - securityLevel（-l）は noAuthNoPriv/authNoPriv/authPriv のいずれか
  - -a/-A は認証、-x/-X は暗号（privacy）  
  - 共通オプションは snmpcmd(1) に整理。  
    根拠URL：https://www.net-snmp.org/docs/man/snmpcmd.html
~~~~
# authPriv の例（一般に推奨される最小ライン）
snmpget -v3 -l authPriv -u <V3USER> -a SHA -A '<AUTH_PASSPHRASE>' -x AES -X '<PRIV_PASSPHRASE>' <target_ip> 1.3.6.1.2.1.1.1.0
~~~~

#### 判断（失敗を“意味”に変換する）
- Timeout：到達性/ACL/送信元制限の可能性（まずネット境界）
- Authorization error / unknown user：v3ユーザ/USM設定の問題（方式境界）
- No Such Object：OIDが見えない（VACM View制限の可能性）
- v2cで取れるがv3で取れない：v3のView/ユーザ権限が絞られている（良い兆候の場合あり）
- v3で取れるがv2cも取れる：v1/v2cが残存（設計としてレビュー対象）

---

## 3) “情報収集（read）”の実務ターゲットOID（何を取るべきか）
> 方針：闇雲に全walkせず、まず “攻め筋に直結するカテゴリ” を優先して、必要なら拡張する。

### 3-A) まずは MIB-2 の system（機器の身元）
- system（1.3.6.1.2.1.1）：sysName, sysLocation, sysContact, sysUpTime など
~~~~
# v2c
snmpwalk -v2c -c <COMMUNITY_RO> -On <target_ip> 1.3.6.1.2.1.1

# v3（authPriv例）
snmpwalk -v3 -l authPriv -u <V3USER> -a SHA -A '<AUTH>' -x AES -X '<PRIV>' -On <target_ip> 1.3.6.1.2.1.1
~~~~
- snmpwalk の性質（GETNEXTでツリーを辿る）は man に明記。  
  根拠URL：https://netsnmp.org/man/snmpwalk.html

### 3-B) IF-MIB：インタフェース情報（ネットワーク構成が一気に見える）
- interfaces（1.3.6.1.2.1.2）や IF-MIB（ifTable 等）は、IP計画/VLAN/接続関係の推定に効く。
~~~~
snmpwalk -v2c -c <COMMUNITY_RO> -On <target_ip> 1.3.6.1.2.1.2
~~~~

### 3-C) IP/ルーティング/ARP近傍（機器なら最優先）
- ip（1.3.6.1.2.1.4）や route table は “次の到達性探索” を強烈に進める（横展開の前段）。
~~~~
snmpwalk -v2c -c <COMMUNITY_RO> -On <target_ip> 1.3.6.1.2.1.4
~~~~

### 3-D) Host Resources（サーバ系で効く：プロセス/ソフト/ストレージ）
- host（1.3.6.1.2.1.25）：実装により、稼働プロセス/インストール情報が露出する場合がある（View次第）。
~~~~
snmpwalk -v2c -c <COMMUNITY_RO> -On <target_ip> 1.3.6.1.2.1.25
~~~~

---

## 4) “大量取得”は snmpbulkwalk（v2c/v3）で効率化（ただし検知されやすい）
- snmpbulkwalk は GETBULK を用いてサブツリーを効率的に取得する、と明記。  
  根拠URL：https://www.net-snmp.org/docs/man/snmpbulkwalk.html
- 実務の使い分け
  - 小さな範囲：snmpget/snmpwalk（影響小）
  - テーブル系（IF/ARP/Route）：snmpbulkwalk（効率良いが、監視側には“異常”として見えやすい）

~~~~
# v2c：system配下をGETBULKで取得（例）
snmpbulkwalk -v2c -c <COMMUNITY_RO> -On -Cr10 <target_ip> 1.3.6.1.2.1.1

# -Cr<NUM> は max-repetitions（取得効率/負荷）に影響（manに記載）
~~~~

---

## 5) v3（USM/VACM）を“成立条件”で評価する（診断が薄くならない要点）
### 5-A) USM（ユーザ）側：securityLevel の確認
- SNMPv3のアーキテクチャは Security Subsystem（USM等）を含む。  
  根拠URL（RFC3411）：https://www.rfc-editor.org/rfc/rfc3411  
  根拠URL（RFC3414）：https://www.rfc-editor.org/info/rfc3414
- 評価テンプレ（Yes/No/Unknown）
  - authPriv（暗号あり）を使っている：Yes/No/Unknown
  - noAuthNoPriv を許可：Yes/No/Unknown（許可ならレビュー対象）
  - 認証/暗号アルゴリズム（例：SHA/AES）が指定されている：Yes/No/Unknown

### 5-B) VACM（View）側：見えるOID範囲を “結果” で確定する
- 方法：同じ資格情報で、MIB-2全体→個別（system/if/ip/host）へ段階的に試し、
  - 取れる（= Viewに含まれる）
  - No Such Object / authorization error（= View外/権限不足）
  を台帳へ落とす。
- VACM はアクセス制御モデルとして標準化。  
  根拠URL：https://www.rfc-editor.org/rfc/rfc3415

---

## 6) v1/v2c（community）を“運用リスク”として評価する（攻め方ではなく境界として）
### 6-A) community が“共有秘密”である点の根拠
- Microsoftの過去のBulletinは、SNMP community string がRO/RWの権限を与え得ること、SNMPv1にsecurity by designがないこと、盗聴でcommunityが得られ得ることを明記している。  
  根拠URL：https://learn.microsoft.com/en-us/security-updates/securitybulletins/2000/ms00-095

### 6-B) 診断で書くべき結論（テンプレ）
- 「SNMPv1/v2c が有効（Yes/No/Unknown）」
- 「RW community が存在（Yes/No/Unknown）」
- 「SNMPは管理セグメント限定（Yes/No）」
- 「取得可能情報：system/if/ip/host/企業MIB（列挙結果で確定）」
- 「検知：大量GETBULK/GETNEXTが監視されている（Yes/No/Unknown）」

---

## 7) 証跡・検知（Blue向け）：何を相関キーにするか
- DET0453 は、異常なSNMP列挙として
  - 大量OID（GETBULK/GETNEXT）
  - 非管理IPからのクエリ
  - community文字列の異常 / 認証失敗
  - メンテ時間外
  などを挙げ、syslog/flow/SNMP監査の相関を推奨している。  
  根拠URL：https://attack.mitre.org/detectionstrategies/DET0453/
- 相関キー（最低限）
  - srcIP（要求元） / dstIP（機器） / 時間窓 / SNMP version / community or v3 username / 失敗→成功の連鎖 / GETBULK頻度
- 実務の“最小ログ設計”案
  - Network：NetFlow/Zeek等で UDP/161 の頻度・バーストを基礎メトリクス化
  - Device：syslogで認証失敗/設定変更を拾う（可能なら）
  - NMS：監視サーバ以外からのSNMPクエリを原則アラート

---

## 8) 是正（最小コストで効く順）
1. 到達性：SNMPは管理セグメント（NMS）からのみ到達、ACLで送信元IP固定
2. v1/v2c：可能なら無効化（残すならROのみ、communityの使い回し禁止、盗聴前提で運用しない）
3. v3：authPriv を基本、USMユーザを個別化、VACM View を “監視に必要なOIDだけ” に最小化
4. 監査：SNMP列挙（GETBULK/GETNEXT）の異常検知（DET0453の観点）を導入
5. 定期棚卸：community/v3ユーザ/View/許可IPを変更管理（IaC/構成管理）に寄せる

---

## 参考URL（本文の根拠として使用：そのまま貼る）
- Net-SNMP FAQ：SNMPが使う典型ポート（161/udp, 162/udp）  
  https://www.net-snmp.org/wiki/index.php/FAQ%3AGeneral_18
- Net-SNMP man：snmpwalk（GETNEXTでツリー列挙）  
  https://netsnmp.org/man/snmpwalk.html
- Net-SNMP man：snmpbulkwalk（GETBULKで効率取得、-Cr 等）  
  https://www.net-snmp.org/docs/man/snmpbulkwalk.html
- Net-SNMP man：snmpcmd（共通オプション：-v/-l/-u/-a/-A/-x/-X 等）  
  https://www.net-snmp.org/docs/man/snmpcmd.html
- RFC3411：SNMPv3アーキテクチャ（Security/Access Control Subsystem）  
  https://www.rfc-editor.org/rfc/rfc3411
- RFC3414：USM（SNMPv3のユーザベースセキュリティ）  
  https://www.rfc-editor.org/info/rfc3414
- RFC3415：VACM（View-based Access Control Model）  
  https://www.rfc-editor.org/rfc/rfc3415
- Microsoft Security Bulletin（SNMP community のRO/RWと、SNMPv1の安全性前提の弱さに言及）  
  https://learn.microsoft.com/en-us/security-updates/securitybulletins/2000/ms00-095
- MITRE ATT&CK：SNMP（MIB Dump）の検知戦略（DET0453）  
  https://attack.mitre.org/detectionstrategies/DET0453/
- OWASP WSTG-CONF-01：Network Infrastructure Configuration  
  https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration
- PTES  
  https://pentest-standard.readthedocs.io/
- OWASP ASVS（参照元）  
  https://github.com/OWASP/ASVS

---

## 深掘りリンク（最大8）
- `05_scanning_到達性把握（nmap_masscan）.md`
- `06_service_fingerprint（banner_tls_alpn）.md`
- `07_pivot_tunneling（ssh_socks_chisel）.md`
- `08_firewall_waf_検知と回避の境界（観測中心）.md`
- `21_nfs_共有とroot_squash境界.md`
- `23_dns_internal_委譲とゾーン転送（AXFR）.md`
- `28_exfiltration_持ち出し経路（DNS_HTTP_SMB）.md`
- `09_smb_enum_共有・権限・匿名（null_session）.md`
