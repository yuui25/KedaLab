# 技術インデックス — MITRE ATT&CK 観点

MITRE ATT&CK Enterprise Matrix の Tactic / Technique ID から kedalab の該当ファイルを引くための横断インデックス。

**主インデックスではない。** 技術名から引きたいときは [`TECHNIQUES_INDEX.md`](./TECHNIQUES_INDEX.md) を使う。
本ファイルは「報告書に ATT&CK ID を併記したい」「ATT&CK Tactic 軸でカバレッジを確認したい」「対象組織が提示した Technique ID から該当手順を引きたい」場合の参照用。

公式: https://attack.mitre.org/
ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/

> **AI Red Teaming は対象外。** LLM・機械学習システムへの攻撃は ATT&CK ではなく **MITRE ATLAS** で扱う。
> AI/ML 攻撃のマッピングは将来 `TECHNIQUES_INDEX_ATLAS.md` として別建てで作成予定。
> 現時点では [`TECHNIQUES_INDEX_AI_ML.md`](./TECHNIQUES_INDEX_AI_ML.md) を参照。

---

## 使い方

| 用途 | 引き方 |
|------|-------|
| 報告書に Technique ID を併記したい | 該当手順を実施した後、本表で kedalab ファイル → ATT&CK ID を逆引き |
| 対象組織の RFP に「ATT&CK T1558.003 を扱えること」とある | 本表の T1558.003 行から kedalab ファイルへ飛ぶ |
| ATT&CK Tactic 軸でテストカバレッジを示したい | Tactic 別セクションの kedalab 対応ファイル数を集計 |

---

## TA0043 Reconnaissance（偵察）

| Technique ID | 技術名 | kedalab ファイル |
|------|-------|--------|
| T1595.001 | Active Scanning: Scanning IP Blocks | `01_Reconnaissance/Network_Scanning.md` |
| T1595.002 | Active Scanning: Vulnerability Scanning | `01_Reconnaissance/Network_Scanning.md` / `02_Initial_Access/Edge_Appliance_CVEs.md` |
| T1595.003 | Active Scanning: Wordlist Scanning | `01_Reconnaissance/Web_Enumeration.md` |
| T1590.002 | Gather Victim Network Info: DNS | `01_Reconnaissance/DNS_Enumeration.md` |
| T1590.005 | Gather Victim Network Info: IP Addresses | `01_Reconnaissance/Network_Scanning.md` |
| T1592.002 | Gather Victim Host Info: Software | `01_Reconnaissance/Web_Enumeration.md` / `00_Playbook/00_OS_Identification.md` |
| T1592.004 | Gather Victim Host Info: Client Configurations | `01_Reconnaissance/Metadata_Analysis.md` |
| T1596.002 | Search Open Technical Databases: WHOIS | `01_Reconnaissance/DNS_Enumeration.md` |
| T1596.003 | Search Open Technical Databases: Digital Certificates | `01_Reconnaissance/TLS_Audit.md` |
| T1593.003 | Search Open Websites/Domains: Code Repositories | `01_Reconnaissance/Exposed_Files.md`（.git 露出） |

---

## TA0042 Resource Development（リソース開発）

| Technique ID | 技術名 | kedalab ファイル |
|------|-------|--------|
| T1588.005 | Obtain Capabilities: Exploits | `05_Tools_Reference/Searchsploit.md` |

---

## TA0001 Initial Access（初期アクセス）

| Technique ID | 技術名 | kedalab ファイル |
|------|-------|--------|
| T1190 | Exploit Public-Facing Application | `02_Initial_Access/Web_Vulnerabilities/*` / `02_Initial_Access/Edge_Appliance_CVEs.md` |
| T1133 | External Remote Services | `02_Initial_Access/Protocol_Exploitation.md` / `02_Initial_Access/Edge_Appliance_CVEs.md` |
| T1078.001 | Valid Accounts: Default Accounts | `02_Initial_Access/Default_Credentials.md` |
| T1078.002 | Valid Accounts: Domain Accounts | `02_Initial_Access/Credential_Discovery.md` |
| T1566 | Phishing（提案・スコープ系） | `02_Initial_Access/Social_Engineering.md` |
| T1566.001 | Phishing: Spearphishing Attachment | `02_Initial_Access/Social_Engineering.md` |
| T1566.002 | Phishing: Spearphishing Link | `02_Initial_Access/Social_Engineering.md` |
| T1091 | Replication Through Removable Media | `02_Initial_Access/Social_Engineering.md`（ベイティング） |
| T1606 | Forge Web Credentials（JWT 署名バイパス・alg:none・RS256→HS256・jwk インジェクション） | `02_Initial_Access/Web_Vulnerabilities/JWT_Attacks.md` |

---

## TA0002 Execution（実行）

| Technique ID | 技術名 | kedalab ファイル |
|------|-------|--------|
| T1059.001 | Command and Scripting Interpreter: PowerShell | `04_Post_Access_Windows_AD/Enumeration_Checklist.md` 等 AD 全般 |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | `04_Post_Access_Windows_AD/Enumeration_Checklist.md` |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | `03_Post_Access_Linux/Shell_Stabilization.md` |
| T1059.006 | Command and Scripting Interpreter: Python | `02_Initial_Access/Web_Vulnerabilities/Command_Injection.md` |
| T1203 | Exploitation for Client Execution | `02_Initial_Access/Web_Vulnerabilities/Electron_XSS_RCE.md` |
| T1569.002 | System Services: Service Execution | `02_Initial_Access/Protocol_Exploitation.md`（psexec/smbexec/wmiexec） |

---

## TA0003 Persistence（持続化）

> **注**: kedalab は侵入後の権限取得までを主スコープとしており、長期 Persistence は本番で原則禁止のため最小限の記載に留めている。

| Technique ID | 技術名 | kedalab ファイル |
|------|-------|--------|
| T1098 | Account Manipulation | `04_Post_Access_Windows_AD/ACE_Abuse/ForcePasswordChange.md` / `04_Post_Access_Windows_AD/ACE_Abuse/WriteDACL.md` |
| T1098.005 | Account Manipulation: Device Registration（Shadow Credentials） | `04_Post_Access_Windows_AD/ACE_Abuse/GenericAll.md` |
| T1136.002 | Create Account: Domain Account | `04_Post_Access_Windows_AD/Delegation_Attacks/Unconstrained.md`（マシンアカウント作成） |
| T1505.003 | Server Software Component: Web Shell | `02_Initial_Access/Web_Vulnerabilities/File_Upload.md` |
| T1037.003 | Boot or Logon Initialization Scripts: Network Logon Script | `01_Reconnaissance/SMB_Enumeration.md`（NETLOGON 列挙視点） / `04_Post_Access_Windows_AD/ACE_Abuse/GenericWrite.md`（logon script 設定） |

---

## TA0004 Privilege Escalation（権限昇格）

| Technique ID | 技術名 | kedalab ファイル |
|------|-------|--------|
| T1068 | Exploitation for Privilege Escalation | `03_Post_Access_Linux/Kernel_Exploits.md` / `04_Post_Access_Windows_AD/Buffer_Overflow_LocalService.md` / `04_Post_Access_Windows_AD/BYOVD.md` |
| T1548.001 | Abuse Elevation Control: Setuid and Setgid | `03_Post_Access_Linux/SUID_SGID.md` |
| T1548.002 | Abuse Elevation Control: Bypass UAC | `04_Post_Access_Windows_AD/Enumeration_Checklist.md`（Step 1.3 UAC バイパス） |
| T1548.003 | Abuse Elevation Control: Sudo and Sudo Caching | `03_Post_Access_Linux/Sudo_Misconfig.md` |
| T1134.001 | Access Token Manipulation: Token Impersonation | `04_Post_Access_Windows_AD/Privilege_Tokens.md`（SeImpersonate） |
| T1574.007 | Hijack Execution Flow: Path Interception by PATH Environment Variable | `03_Post_Access_Linux/PAM_Misconfig.md` |
| T1611 | Escape to Host | `03_Post_Access_Linux/Sudo_Misconfig.md`（Docker ブレイクアウト） |

---

## TA0005 Defense Evasion（防御回避）

| Technique ID | 技術名 | kedalab ファイル |
|------|-------|--------|
| T1685 | Disable or Modify Tools | `04_Post_Access_Windows_AD/Enumeration_Checklist.md`（Step 8 AMSI バイパス） / `04_Post_Access_Windows_AD/BYOVD.md`（BYOVD で EDR Kernel Callback 削除） |
| T1027 | Obfuscated Files or Information | `02_Initial_Access/Web_Vulnerabilities/JS_Obfuscation.md` |
| T1140 | Deobfuscate/Decode Files or Information | `02_Initial_Access/Web_Vulnerabilities/JS_Obfuscation.md` / `02_Initial_Access/Binary_Analysis.md` |
| T1550.002 | Use Alternate Authentication Material: Pass the Hash | `04_Post_Access_Windows_AD/Credential_Dumping.md` / `02_Initial_Access/Protocol_Exploitation.md`（WinRM PTH） |

---

## TA0006 Credential Access（認証情報窃取）

| Technique ID | 技術名 | kedalab ファイル |
|------|-------|--------|
| T1003.001 | OS Credential Dumping: LSASS Memory | `04_Post_Access_Windows_AD/Privilege_Tokens.md`（SeDebug） / `04_Post_Access_Windows_AD/Credential_Dumping.md` |
| T1003.002 | OS Credential Dumping: Security Account Manager | `04_Post_Access_Windows_AD/Privilege_Tokens.md`（SeBackup/SeTakeOwnership） / `04_Post_Access_Windows_AD/Credential_Dumping.md` |
| T1003.003 | OS Credential Dumping: NTDS | `04_Post_Access_Windows_AD/Credential_Dumping.md` |
| T1003.006 | OS Credential Dumping: DCSync | `04_Post_Access_Windows_AD/Credential_Dumping.md` |
| T1110.002 | Brute Force: Password Cracking | `05_Tools_Reference/Hashcat.md` |
| T1110.003 | Brute Force: Password Spraying | `05_Tools_Reference/Netexec.md` / `02_Initial_Access/Account_Lockout_Recon.md` |
| T1110.001 | Brute Force: Password Guessing | `02_Initial_Access/Default_Credentials.md`（hydra / medusa） / `01_Reconnaissance/SNMP_Enumeration.md`（コミュニティ文字列ブルート） |
| T1558.001 | Steal or Forge Kerberos Tickets: Golden Ticket | `04_Post_Access_Windows_AD/Kerberos_Attacks/Pass_The_Ticket.md` |
| T1558.002 | Steal or Forge Kerberos Tickets: Silver Ticket | `04_Post_Access_Windows_AD/Kerberos_Attacks/Pass_The_Ticket.md` |
| T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | `04_Post_Access_Windows_AD/Kerberos_Attacks/Kerberoasting.md` / `04_Post_Access_Windows_AD/ACE_Abuse/GenericWrite.md`（Targeted） |
| T1558.004 | Steal or Forge Kerberos Tickets: AS-REP Roasting | `04_Post_Access_Windows_AD/Kerberos_Attacks/ASREPRoasting.md` |
| T1187 | Forced Authentication | `04_Post_Access_Windows_AD/NTLM_Relay/Coerce.md` / `02_Initial_Access/MSSQL_Exploitation.md`（xp_dirtree） |
| T1555.003 | Credentials from Password Stores: Web Browsers | `04_Post_Access_Windows_AD/DPAPI_Browser_Creds.md` |
| T1555.004 | Credentials from Password Stores: Windows Credential Manager | `04_Post_Access_Windows_AD/DPAPI_Browser_Creds.md` |
| T1555.005 | Credentials from Password Stores: Password Managers | `02_Initial_Access/Credential_Discovery.md`（KeePass） |
| T1552.001 | Unsecured Credentials: Credentials In Files | `02_Initial_Access/Credential_Discovery.md`（.env / スクリプト埋め込み） |
| T1552.004 | Unsecured Credentials: Private Keys | `02_Initial_Access/Credential_Discovery.md` / `02_Initial_Access/SSH.md`（§5 鍵接続 / §8 ssh2john パスフレーズクラック / §10 Debian PRNG 弱鍵） |
| T1552.006 | Unsecured Credentials: Group Policy Preferences | `01_Reconnaissance/SMB_Enumeration.md` / `02_Initial_Access/Credential_Discovery.md` |
| T1557.001 | Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay | `04_Post_Access_Windows_AD/NTLM_Relay/Responder.md` / `04_Post_Access_Windows_AD/NTLM_Relay/ntlmrelayx.md` |
| T1557.003 | Adversary-in-the-Middle: DHCP Spoofing | `04_Post_Access_Windows_AD/NTLM_Relay/mitm6.md` |
| T1649 | Steal or Forge Authentication Certificates | `04_Post_Access_Windows_AD/AD_CS/*`（ESC1〜15 全般） |
| T1212 | Exploitation for Credential Access | `02_Initial_Access/SSH.md`（§9 CVE-2018-15473 ユーザー列挙） |

---

## TA0007 Discovery（探索）

| Technique ID | 技術名 | kedalab ファイル |
|------|-------|--------|
| T1018 | Remote System Discovery | `01_Reconnaissance/Network_Scanning.md` / `04_Post_Access_Windows_AD/Enumeration_Checklist.md` |
| T1046 | Network Service Discovery | `01_Reconnaissance/Network_Scanning.md` / `05_Tools_Reference/Nmap.md` / `01_Reconnaissance/SNMP_Enumeration.md`（UDP 161 ホスト発見） |
| T1057 | Process Discovery | `05_Tools_Reference/pspy.md` / `03_Post_Access_Linux/Enumeration_Checklist.md` |
| T1083 | File and Directory Discovery | `03_Post_Access_Linux/Enumeration_Checklist.md` / `04_Post_Access_Windows_AD/Enumeration_Checklist.md` |
| T1082 | System Information Discovery | `04_Post_Access_Windows_AD/Enumeration_Checklist.md`（Get-ComputerInfo） |
| T1033 | System Owner/User Discovery | `03_Post_Access_Linux/Enumeration_Checklist.md`（id） |
| T1049 | System Network Connections Discovery | `04_Post_Access_Windows_AD/Enumeration_Checklist.md`（netstat -ano） |
| T1069.002 | Permission Groups Discovery: Domain Groups | `05_Tools_Reference/BloodHound.md` |
| T1087.002 | Account Discovery: Domain Account | `01_Reconnaissance/LDAP_Enumeration.md` / `05_Tools_Reference/Impacket_Suite.md`（GetADUsers.py） / `05_Tools_Reference/Netexec.md`（RID bruteforce） |
| T1135 | Network Share Discovery | `01_Reconnaissance/SMB_Enumeration.md` |
| T1518 | Software Discovery | `01_Reconnaissance/Web_Enumeration.md`（フレームワーク特定） |
| T1201 | Password Policy Discovery | `02_Initial_Access/Account_Lockout_Recon.md` |

---

## TA0008 Lateral Movement（横展開）

| Technique ID | 技術名 | kedalab ファイル |
|------|-------|--------|
| T1021.001 | Remote Services: Remote Desktop Protocol | `04_Post_Access_Windows_AD/Enumeration_Checklist.md` |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | `02_Initial_Access/Protocol_Exploitation.md`（psexec/smbexec） |
| T1021.006 | Remote Services: Windows Remote Management | `02_Initial_Access/Protocol_Exploitation.md`（evil-winrm） |
| T1550.002 | Use Alternate Authentication Material: Pass the Hash | `04_Post_Access_Windows_AD/Credential_Dumping.md` |
| T1550.003 | Use Alternate Authentication Material: Pass the Ticket | `04_Post_Access_Windows_AD/Kerberos_Attacks/Pass_The_Ticket.md` / `04_Post_Access_Windows_AD/Delegation_Attacks/RBCD.md`（S4U チケット偽造） |
| T1570 | Lateral Tool Transfer | `05_Tools_Reference/Impacket_Suite.md` / `03_Post_Access_Linux/Kernel_Exploits.md`（python3 -m http.server） |

---

## TA0009 Collection（収集）

| Technique ID | 技術名 | kedalab ファイル |
|------|-------|--------|
| T1005 | Data from Local System | `03_Post_Access_Linux/Enumeration_Checklist.md` / `04_Post_Access_Windows_AD/Enumeration_Checklist.md` |
| T1039 | Data from Network Shared Drive | `01_Reconnaissance/SMB_Enumeration.md` |
| T1213 | Data from Information Repositories | `01_Reconnaissance/Exposed_Files.md` |
| T1602.001 | Data from Configuration Repository: SNMP (MIB Dump) | `01_Reconnaissance/SNMP_Enumeration.md` |

---

## TA0011 Command and Control（C2）

| Technique ID | 技術名 | kedalab ファイル |
|------|-------|--------|
| T1572 | Protocol Tunneling | `05_Tools_Reference/Chisel.md` |
| T1090 | Proxy | `04_Post_Access_Windows_AD/NTLM_Relay/ntlmrelayx.md`（socks モード） |
| T1071.001 | Application Layer Protocol: Web Protocols | `02_Initial_Access/Web_Vulnerabilities/Command_Injection.md`（リバースシェル配信） |

---

## ATT&CK Sub-Technique 別の AD CS Abuse（参考）

AD CS 攻撃（ESC1〜15）は ATT&CK 上では **T1649 Steal or Forge Authentication Certificates** に集約される。
個別 ESC のサブ分類は ATT&CK には存在しないため、kedalab 側の細分が事実上の参照軸となる。

| kedalab エントリ | ATT&CK | 補助 Tactic |
|---------------|--------|-----------|
| ESC1〜15 全般 | T1649 | TA0006 Credential Access |
| ESC8（NTLM Relay to AD CS） | T1649 + T1557.001 | TA0006 |

---

## PTES フェーズとの対応（参考）

ATT&CK とは別軸の参照フレームワーク。kedalab のフォルダ構成と PTES の7フェーズはほぼ一対一対応する。

| PTES フェーズ | kedalab |
|------------|--------|
| 1. Pre-Engagement Interactions | （技術ナレッジの対象外 — 計画書・RoE はサービス側で管理） |
| 2. Intelligence Gathering | `01_Reconnaissance/` |
| 3. Threat Modeling | `00_Playbook/`（攻撃フロー設計時に参照） |
| 4. Vulnerability Analysis | `01_Reconnaissance/` ＋ `02_Initial_Access/`（脆弱性特定） |
| 5. Exploitation | `02_Initial_Access/Web_Vulnerabilities/` / `02_Initial_Access/Edge_Appliance_CVEs.md` 等 |
| 6. Post-Exploitation | `03_Post_Access_Linux/` / `04_Post_Access_Windows_AD/` |
| 7. Reporting | （技術ナレッジの対象外 — 報告書テンプレートはサービス側で管理） |

> **注意**: PTES の Technical Guidelines は更新停止状態。フェーズ構造（何をすべきか）の参照には有効だが、具体的な攻撃手法は ATT&CK / OWASP WSTG に従う。

---

## 新規エントリ追加時のルール

新規に kedalab ファイルを追加した際、該当する ATT&CK Technique ID があれば本表にも追記する。**該当 ID が無い場合は無理に当てはめない**（一部の偵察手法・原状回復手順・Concept ファイル等は ATT&CK 範囲外）。

- **同じ Technique ID で kedalab ファイルが複数ある場合は1行に集約してスラッシュ区切りで書く**
  同一 Tactic 内では Technique ID の重複行を作らない（例: `T1562.001 | ... | A.md（AMSI 視点） / B.md（BYOVD 視点）`）。
  各ファイルの「どの観点か」を括弧書きで補足すると読みやすい。
- 1つの kedalab ファイルが複数 Technique にまたがる場合は、両方の行に同じファイル名を書いてよい（kedalab ファイル → 複数 ATT&CK ID 方向の N:N）
- **同じ Technique ID が複数 Tactic に登場するのは MITRE のクロス分類仕様**
  例: `T1550.002` Pass the Hash は TA0005 Defense Evasion と TA0008 Lateral Movement の両方に登場するが、
  これは ATT&CK 設計上の意図（同じ手法が複数の Tactic 目的で使われる）であり重複ではない。
  Tactic 軸でカバレッジを集計する場合に両方で正しくカウントされるよう、両 Tactic セクションに記載する。
- Sub-Technique がある場合は Sub-Technique ID（`T1078.001` 等）を優先して使う
- 完全な分類より「引きやすさ」を優先する
