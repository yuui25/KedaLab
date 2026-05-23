# 技術インデックス — OWASP WSTG v4.2 観点

OWASP Web Security Testing Guide v4.2 のテストカテゴリ・テストケース ID から kedalab の該当ファイルを引くための横断インデックス。

**主インデックスではない。** 技術名から引きたいときは [`TECHNIQUES_INDEX.md`](./TECHNIQUES_INDEX.md) を使う。
本ファイルは「Web ペネトレテストで WSTG カバレッジを示したい」「報告書に WSTG ID を併記したい」「対象組織が WSTG ID で要件指定してきた」場合の参照用。

公式: https://owasp.org/www-project-web-security-testing-guide/v42/

---

## 使い方

| 用途 | 引き方 |
|------|-------|
| Web ペネトレテストのテスト項目を WSTG に沿って網羅したい | カテゴリ別に kedalab ファイルが揃っているか確認 |
| 報告書に WSTG-INPV-05 のような ID 併記したい | 該当手順実施後、本表で kedalab ファイル → WSTG ID を逆引き |
| 対象組織 RFP に「WSTG-ATHN を全項目」とある | 該当カテゴリの行から kedalab ファイルへ飛ぶ |

> **網羅していない領域の扱い**: WSTG-BUSLOGIC（ビジネスロジック）、WSTG-APIT（API テスト）等は kedalab の現スコープ外。手動テスト・スコープ個別対応とする。

---

## WSTG-INFO（情報収集 / Information Gathering）

| WSTG ID | テスト項目 | kedalab ファイル |
|---------|-----------|--------|
| WSTG-INFO-02 | Fingerprint Web Server | `01_Reconnaissance/Web_Enumeration.md` |
| WSTG-INFO-03 | Review Webserver Metafiles for Information Leakage | `01_Reconnaissance/Web_Enumeration.md`（robots.txt） / `01_Reconnaissance/Exposed_Files.md` |
| WSTG-INFO-04 | Enumerate Applications on Webserver | `01_Reconnaissance/Web_Enumeration.md`（vhost ファジング） |
| WSTG-INFO-05 | Review Webpage Content for Information Leakage | `01_Reconnaissance/Web_Enumeration.md`（フッター・HTML ソース） |
| WSTG-INFO-06 | Identify Application Entry Points | `01_Reconnaissance/Web_Enumeration.md` |
| WSTG-INFO-08 | Fingerprint Web Application Framework | `01_Reconnaissance/Web_Enumeration.md`（Cookie 名 / Server ヘッダー / generator メタ） |
| WSTG-INFO-09 | Fingerprint Web Application | `01_Reconnaissance/Web_Enumeration.md`（/api/health 等） |

---

## WSTG-CONF（設定とデプロイ管理 / Configuration and Deployment Management）

| WSTG ID | テスト項目 | kedalab ファイル |
|---------|-----------|--------|
| WSTG-CONF-02 | Test Application Platform Configuration | `01_Reconnaissance/Exposed_Files.md`（phpinfo / server-status / server-info） |
| WSTG-CONF-03 | Test File Extensions Handling for Sensitive Information | `02_Initial_Access/Web_Vulnerabilities/File_Upload.md`（二重拡張子） |
| WSTG-CONF-04 | Review Old Backup and Unreferenced Files for Sensitive Information | `01_Reconnaissance/Exposed_Files.md`（.bak / .old / .swp / .tar.gz / .zip / .sql） |
| WSTG-CONF-05 | Enumerate Infrastructure and Application Admin Interfaces | `01_Reconnaissance/Exposed_Files.md`（Tomcat manager / JBoss / Spring Actuator / Jenkins） / `02_Initial_Access/Default_Credentials.md` |
| WSTG-CONF-07 | Test HTTP Strict Transport Security | `01_Reconnaissance/TLS_Audit.md`（HSTS / セキュリティヘッダー） |
| WSTG-CONF-09 | Test File Permission | `01_Reconnaissance/Exposed_Files.md`（.htaccess / .htpasswd / web.config / nginx.conf） |

---

## WSTG-IDNT（ID 管理 / Identity Management）

| WSTG ID | テスト項目 | kedalab ファイル |
|---------|-----------|--------|
| WSTG-IDNT-04 | Testing for Account Enumeration and Guessable User Account | `02_Initial_Access/Default_Credentials.md` / `02_Initial_Access/Account_Lockout_Recon.md` |
| WSTG-IDNT-05 | Testing for Weak or Unenforced Username Policy | `02_Initial_Access/Default_Credentials.md` |

---

## WSTG-ATHN（認証 / Authentication）

| WSTG ID | テスト項目 | kedalab ファイル |
|---------|-----------|--------|
| WSTG-ATHN-01 | Testing for Credentials Transported over an Encrypted Channel | `01_Reconnaissance/TLS_Audit.md` / `02_Initial_Access/FTP.md`（平文認証 / PCAP 抽出 / AUTH TLS 判定） |
| WSTG-ATHN-02 | Testing for Default Credentials | `02_Initial_Access/Default_Credentials.md` |
| WSTG-ATHN-03 | Testing for Weak Lock Out Mechanism | `02_Initial_Access/Account_Lockout_Recon.md` |
| WSTG-ATHN-06 | Testing for Browser Cache Weaknesses | （手動確認・kedalab 化候補） |
| WSTG-ATHN-07 | Testing for Weak Password Policy | `02_Initial_Access/Account_Lockout_Recon.md`（FGPP / msDS-PasswordSettings） |
| WSTG-ATHN-10 | Testing for Weaker Authentication in Alternative Channel | `02_Initial_Access/SSH.md` / `02_Initial_Access/FTP.md` / `02_Initial_Access/Protocol_Exploitation.md`（WinRM / Mail） / `02_Initial_Access/Web_Vulnerabilities/OAuth_Attacks.md`（ソーシャルログイン経路の信頼境界破り） |

---

## WSTG-ATHZ（認可 / Authorization）

| WSTG ID | テスト項目 | kedalab ファイル |
|---------|-----------|--------|
| WSTG-ATHZ-01 | Testing Directory Traversal File Include | `02_Initial_Access/Web_Vulnerabilities/Path_Traversal.md` |
| WSTG-ATHZ-02 | Testing for Bypassing Authorization Schema | `02_Initial_Access/Web_Vulnerabilities/IDOR.md` / `02_Initial_Access/Web_Vulnerabilities/Command_Injection.md`（is_admin=1） |
| WSTG-ATHZ-03 | Testing for Privilege Escalation | `02_Initial_Access/Web_Vulnerabilities/Command_Injection.md`（API パラメータ改ざん） |
| WSTG-ATHZ-04 | Testing for Insecure Direct Object References | `02_Initial_Access/Web_Vulnerabilities/IDOR.md` |

---

## WSTG-SESS（セッション管理 / Session Management）

| WSTG ID | テスト項目 | kedalab ファイル |
|---------|-----------|--------|
| WSTG-SESS-01 | Testing for Session Management Schema（JWT トークン構造・alg 検証・署名バイパス / OAuth id_token・access_token の検証） | `02_Initial_Access/Web_Vulnerabilities/JWT_Attacks.md` / `02_Initial_Access/Web_Vulnerabilities/OAuth_Attacks.md` |
| WSTG-SESS-09 | Testing for Session Hijacking | `02_Initial_Access/Web_Vulnerabilities/XSS.md`（Cookie スティーリング・stolen cookie ブラウザ植え替え） / `02_Initial_Access/Web_Vulnerabilities/OAuth_Attacks.md`（Implicit Flow Token Leakage） |

> SESS-02（Cookie 属性）/ SESS-04（Session Fixation）/ SESS-05（Exposed Session Variables）/ SESS-06（CSRF）/ SESS-07（Logout）は手動確認領域。kedalab に追加判定は WRITING_GUIDE.md の「網羅的に書こうとしない」方針に従う。

---

## WSTG-INPV（入力検証 / Input Validation）

最も kedalab 対応の厚いカテゴリ。

| WSTG ID | テスト項目 | kedalab ファイル |
|---------|-----------|--------|
| WSTG-INPV-01 | Testing for Reflected Cross Site Scripting | `02_Initial_Access/Web_Vulnerabilities/XSS.md` |
| WSTG-INPV-02 | Testing for Stored Cross Site Scripting | `02_Initial_Access/Web_Vulnerabilities/XSS.md` |
| WSTG-INPV-05 | Testing for SQL Injection | `02_Initial_Access/Web_Vulnerabilities/SQLi.md` |
| WSTG-INPV-09 | Testing for XML Injection / XXE | `02_Initial_Access/Web_Vulnerabilities/XXE.md` |
| WSTG-INPV-11 | Testing for XPath Injection | （手動・kedalab 化候補） |
| WSTG-INPV-12 | IMAP/SMTP Injection | （手動・kedalab 化候補） |
| WSTG-INPV-13 | Testing for Code Injection | `02_Initial_Access/Web_Vulnerabilities/Java_Deserialization_Bypass.md` / `03_Post_Access_Linux/Sudo_Misconfig.md`（YAML.load Gadget Chain） |
| WSTG-INPV-14 | Testing for Command Injection | `02_Initial_Access/Web_Vulnerabilities/Command_Injection.md`（OS コマンド・PDFKit CVE-2022-25765） |
| WSTG-INPV-17 | Testing for HTTP Request Smuggling | （手動・kedalab 化候補） |
| WSTG-INPV-18 | Testing for HTTP Incoming Requests | （リクエストヘッダー XSS は INPV-01/02 を参照） |
| WSTG-INPV-19 | Testing for Host Header Injection | （手動・kedalab 化候補） |
| WSTG-INPV-20 | Testing for Server-Side Request Forgery | `02_Initial_Access/Web_Vulnerabilities/SSRF.md` |
| WSTG-INPV-XX | Testing for Server-Side Template Injection（v4.2 で項目追加検討中） | （kedalab 化候補） |
| - | XSLT Injection（WSTG 未収載・MITRE T1059 系） | `02_Initial_Access/Web_Vulnerabilities/XSLT_Injection.md` |

---

## WSTG-CRYP（暗号化 / Cryptography）

| WSTG ID | テスト項目 | kedalab ファイル |
|---------|-----------|--------|
| WSTG-CRYP-01 | Testing for Weak Transport Layer Security | `01_Reconnaissance/TLS_Audit.md`（プロトコル/暗号スイート列挙・名前付き脆弱性） |
| WSTG-CRYP-04 | Testing for Weak Encryption | `02_Initial_Access/Binary_Analysis.md`（XOR / RC4 復号） |

---

## WSTG-CLNT（クライアントサイドテスト / Client-side Testing）

| WSTG ID | テスト項目 | kedalab ファイル |
|---------|-----------|--------|
| WSTG-CLNT-01 | Testing for DOM-Based Cross Site Scripting | `02_Initial_Access/Web_Vulnerabilities/XSS.md`（DOM 型 XSS） |
| WSTG-CLNT-04 | Testing for Client-side URL Redirect | `02_Initial_Access/Web_Vulnerabilities/Open_Redirect.md`（バイパス全般・`javascript:` スキーム経由 XSS 化・SSRF 連鎖） / `02_Initial_Access/Web_Vulnerabilities/XSS.md`（DOM 偽装・フィッシングリダイレクト） / `02_Initial_Access/Web_Vulnerabilities/OAuth_Attacks.md`（redirect_uri バイパス・Open Redirect 連鎖） |
| WSTG-CLNT-09 | Testing for Cross Origin Resource Sharing | （手動・kedalab 化候補） |

---

## WSTG-APIT（API テスト / API Testing）

| WSTG ID | テスト項目 | kedalab ファイル |
|---------|-----------|--------|
| WSTG-APIT-01 | Testing GraphQL | （現在 kedalab 未収載・将来追加候補） |

> Web API（REST / GraphQL / WebSocket）テストは現在 kedalab スコープ外。フル版ペネトレ対応時の追加候補。

---

## 関連する WSTG 範囲外の kedalab エントリ

WSTG はインフラ・OS・AD レイヤーをスコープ外としているため、以下は WSTG では引けない：

- ネットワーク偵察（nmap・SMB・LDAP・SNMP 列挙） → MITRE ATT&CK TA0007 Discovery で参照
- AD 攻撃全般（Kerberoasting / DCSync / AD CS / NTLM Relay 等） → MITRE ATT&CK TA0006 Credential Access
- Linux 権限昇格（SUID / sudo / Capabilities / Kernel Exploits） → MITRE ATT&CK TA0004 Privilege Escalation
- Windows 権限昇格（特権トークン / UAC バイパス / BYOVD） → MITRE ATT&CK TA0004 Privilege Escalation

ATT&CK 軸での参照は [`TECHNIQUES_INDEX_MITRE.md`](./TECHNIQUES_INDEX_MITRE.md) を使う。

---

## 新規エントリ追加時のルール

新規に Web 系 kedalab ファイルを追加した際、該当する WSTG ID があれば本表にも追記する。**該当 ID が無い場合は無理に当てはめない**（インフラ・AD・OS 系の手順は WSTG 範囲外）。

- 1技術が複数 WSTG ID にまたがる場合は両方の行に記載してよい
- WSTG ID は v4.2 ベース。バージョン更新時は本表全体の見直しが必要
- WSTG カバレッジ集計の際は「kedalab に対応ファイルがある WSTG ID 数 / WSTG ID 全数」で算出する
