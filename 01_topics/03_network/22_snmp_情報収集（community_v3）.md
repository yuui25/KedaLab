# 22_snmp_情報収集（community_v3）

## 前提知識（最低限）
- v2cはcommunity、v3はUSM/VACM

## 具体例（注目点）
- 読み取り可能なOID範囲

## 時間目安
- 対象数とOID範囲に比例
SNMP の到達性・方式・権限・露出範囲を観測で確定し、検知と是正まで落とす。

## 目的（この技術で到達する状態）
- UDP/161・162 の到達性を Yes/No/Unknown で示し、許可IP/セグメントを根拠付きで説明できる
- 方式（v1/v2c community / v3 USM+VACM）と securityLevel（noAuthNoPriv/authNoPriv/authPriv）を観測で確定できる
- 取得できるOID範囲（View/RO-RW）から漏えい・改変リスクをカテゴリ別に説明できる
- GETBULK/GETNEXT の異常を追う相関キーを提示し、検知可否を判断できる
- 是正方針（到達性/方式/権限/検知/棚卸し）を優先度付きで提示できる

## 前提（対象・範囲・想定）
- 対象：NW機器/サーバ/IoT 等で SNMP が動作する資産
- 想定環境：オンプレ/クラウド問わず。管理セグメントと利用セグメントが分離している前提が望ましい
- できること/やらないこと：提供された community/v3ユーザのみ使用。総当たりや第三者宛は行わない
- 依存知識：SNMP 基本構造（MIB/OID）、USM/VACM の役割
- 扱う範囲：到達性・方式判定・情報露出・検知・是正
- 扱わない（別ユニット）：横展開の実行 → `18_winrm...` `19_rdp...`、共有経由持ち出し → `28_exfiltration...`

## 観測ポイント（プロトコル/データ/境界）
- Transport：UDP/161（要求）・UDP/162（Trap）への到達性と ACL
- 認証/暗号：v1/v2c の有無、v3 securityLevel と認証/暗号アルゴリズム
- 権限/範囲：community の RO/RW、VACM View に含まれるOID範囲
- 境界：管理セグメント外からの到達、許可IP固定の有無、noAuthNoPriv 許可の有無
- 重要差分：GETNEXT/GETBULK の頻度・失敗→成功の遷移、MIBカテゴリ別の露出量

## 結果の意味（言える/言えない）
- 確定できる：到達性（経路別）、方式と securityLevel、取得できるOID範囲、RW有無
- 推定できる：管理境界の運用（ACL/許可IP）、監視の強さ（失敗ログ/フロー有無）
- 言えない：パスワード強度・総当たり可否（スコープ外）、未提供資格の有無
- 状態パターン
  - A：v3 authPrivのみ・管理セグメント限定（堅牢）
  - B：v2c RO残存・View広い（情報露出高）
  - C：v2c RW残存・noAuthNoPriv許可（改変リスク高）

## 攻撃者視点での利用
- 狙い目：v2c RW・広いView・管理外セグメントからの到達
- 優先度：1) 到達性の有無 → 2) v1/v2cの存在 → 3) v3の securityLevel → 4) View/RW の広さ
- 攻め筋
  - 取得情報でネットワーク構成/認証系（DC/LDAP/Kerberos）を刈り出す
  - IF/Route/ARP から到達性マップを作り横展開の前提にする
- 見える/見えないでの戦略：到達不可なら管理セグメントでの観測依頼、v3のみなら View 評価に集中

## 次に試すこと（仮説と検証）
- 仮説A：管理外セグメントからUDP/161に届く  
  - 検証：nmap -sU で reach/open|filtered を取得  
  - 期待：open|filtered なら設計不備所見、filtered ならACL動作を確認
- 仮説B：v1/v2cが有効  
  - 検証：提供 community で sysDescr.0 を snmpget  
  - 期待：成功なら View 範囲を列挙、失敗なら v3 専念
- 仮説C：v3 が noAuthNoPriv/広いView  
  - 検証：v3ユーザで sysDescr → MIB-2 → IF/IP/Host を段階取得  
  - 期待：No Such Object/authorization error なら View が絞られている

## 手を動かす検証（観測点を明確に）
- 検証環境：`04_labs/` 連動は任意
- 証跡ディレクトリ（必須）
~~~~
mkdir -p ~/keda_evidence/snmp_22 2>/dev/null
cd ~/keda_evidence/snmp_22
~~~~
- 検証前提を固定：許可スコープのみ、提供資格のみ使用、Trap送信は行わない
- 相関キー：{srcIP/dstIP, Time, SNMP version, community or v3 user, 成否, GETBULK頻度}
- 到達性（UDP/161/162）
~~~~
sudo nmap -sU -Pn -n -p 161,162 --reason <target_ip> -oN snmp_udp_reach_<target>.txt
~~~~
- 方式判定と最小取得（sysDescr.0）
~~~~
snmpget -v2c -c <COMMUNITY_RO> <target_ip> 1.3.6.1.2.1.1.1.0
snmpget -v3 -l authPriv -u <V3USER> -a SHA -A '<AUTH>' -x AES -X '<PRIV>' <target_ip> 1.3.6.1.2.1.1.1.0
~~~~
- 情報収集（優先順：system → IF-MIB → IP/route → Host-Resources）
~~~~
snmpwalk -v2c -c <COMMUNITY_RO> -On <target_ip> 1.3.6.1.2.1.1
snmpwalk -v2c -c <COMMUNITY_RO> -On <target_ip> 1.3.6.1.2.1.2
snmpwalk -v2c -c <COMMUNITY_RO> -On <target_ip> 1.3.6.1.2.1.4
snmpwalk -v2c -c <COMMUNITY_RO> -On <target_ip> 1.3.6.1.2.1.25
~~~~
- GETBULK活用（検知されやすいので最小回数）
~~~~
snmpbulkwalk -v2c -c <COMMUNITY_RO> -On -Cr10 <target_ip> 1.3.6.1.2.1.1
~~~~
- VACM 評価：同資格で範囲を変えて No Such Object/authorization error を記録し View を確定

## コマンド/リクエスト例
- nmap -sU で 161/162 の open|filtered を確認（到達性の根拠）
- snmpget sysDescr.0（方式判定と資格の正否を確認）
- snmpwalk IF-MIB / IP / Host-Resources（構成・経路・プロセス露出を確認）
- snmpbulkwalk -Cr10 system（大量取得時の検知有無を確認）
- 使えないケース：提供資格が無い、管理セグメント外から ACL で遮断されている、Trap専用構成のみ

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS  
  - 破れる：v1/v2c（平文・共有秘密）や広いView/RWで構成・経路・プロセス情報が漏れる。RWなら設定改変も成立。  
  - 満たす：管理セグメント限定、ACL固定、v1/v2c無効化（またはRO限定）、v3 authPriv＋最小View、GETBULK異常検知を設計に組み込む。  
  - 参照：https://github.com/OWASP/ASVS
- WSTG  
  - WSTG-CONF-01：周辺管理プロトコルの露出・設定不備を検証（到達性/認証/許可IP/露出量）。  
  - 参照：https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration
- PTES  
  - Information Gathering → 到達性 → 認証方式特定 → 列挙（MIB/権限） → 影響評価 → Reporting。観測結果で Yes/No/Unknown まで落とす。  
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK  
  - T1602.001（SNMP / MIB Dump）  
  - Detection：DET0453（大量GETBULK/GETNEXT、非管理IP、失敗→成功連鎖を相関）  
  - 参照：https://attack.mitre.org/detectionstrategies/DET0453/

## 参考（必要最小限）
- Net-SNMP FAQ（161/udp, 162/udp）：https://www.net-snmp.org/wiki/index.php/FAQ%3AGeneral_18
- snmpwalk man（GETNEXT）：https://netsnmp.org/man/snmpwalk.html
- snmpbulkwalk man（GETBULK）：https://www.net-snmp.org/docs/man/snmpbulkwalk.html
- snmpcmd man（共通オプション）：https://www.net-snmp.org/docs/man/snmpcmd.html
- RFC3411（SNMPv3アーキテクチャ）：https://www.rfc-editor.org/rfc/rfc3411
- RFC3414（USM）：https://www.rfc-editor.org/info/rfc3414
- RFC3415（VACM）：https://www.rfc-editor.org/rfc/rfc3415
- Microsoft Bulletin（v1/コミュニティの弱さ）：https://learn.microsoft.com/en-us/security-updates/securitybulletins/2000/ms00-095
- DET0453： https://attack.mitre.org/detectionstrategies/DET0453/
- WSTG-CONF-01： https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration
- PTES：https://pentest-standard.readthedocs.io/
- OWASP ASVS：https://github.com/OWASP/ASVS

## リポジトリ内リンク（最大3つ）
- 関連 topics：`08_firewall_waf_検知と回避の境界（観測中心）.md`
- 関連 playbooks：なし
- 関連 labs / cases：任意

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
