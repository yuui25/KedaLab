# 技術インデックス — ペネトレプロセス・ガイドライン観点

NIST SP 800-115 / PTES の章・フェーズから kedalab の該当ファイルを引くための横断インデックス。

**主インデックスではない。** 技術名から引きたいときは [`TECHNIQUES_INDEX.md`](./TECHNIQUES_INDEX.md) を使う。
本ファイルは「ペネトレ全体プロセスをガイドラインに沿って確認したい」「報告書にガイドライン参照を併記したい」「顧客 RFP にガイドライン名指定がある」場合の参照用。

ガイドライン自体の概要・使い分けは [`06_Concepts/Pentest_Guidelines_Guide.md`](./06_Concepts/Pentest_Guidelines_Guide.md) を参照。

---

## 使い方

| 用途 | 引き方 |
|------|-------|
| ガイドラインに沿ってテスト項目の網羅を確認したい | 各章別セクションで kedalab 対応ファイルが揃っているか確認 |
| 報告書に NIST SP 800-115 §4.2 / PTES Intelligence Gathering のような参照を併記したい | 該当手順実施後、本表で kedalab ファイル → 章/フェーズを逆引き |
| 顧客要件に「NIST SP 800-115 準拠」「PTES に沿った実施」とある | 該当章・フェーズの行から kedalab ファイルへ飛ぶ |
| kedalab がカバーしない領域を把握したい | 各表の「kedalab 対象外」マーク付き行を参照 |

---

## NIST SP 800-115（Technical Guide to Information Security Testing and Assessment）

公式: https://csrc.nist.gov/pubs/sp/800/115/final
PDF: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf
発行: 2008年9月、ステータス Active（NIST SP 800-42 を置換）

### §3 Review Techniques（レビュー手法）

| 節 | テスト項目 | kedalab ファイル |
|----|---------|--------|
| 3.1 | Documentation Review | kedalab 対象外（文書レビューは案件依存）|
| 3.2 | Log Review | kedalab 対象外（防御側手法）|
| 3.3 | Ruleset Review | kedalab 対象外（防御側手法）|
| 3.4 | System Configuration Review | 関連: [`01_Reconnaissance/Exposed_Files.md`](./01_Reconnaissance/Exposed_Files.md)（設定誤公開）|
| 3.5 | Network Sniffing | [`01_Reconnaissance/SMB_Enumeration.md`](./01_Reconnaissance/SMB_Enumeration.md)（NTLM 観点）/ [`02_Initial_Access/FTP.md`](./02_Initial_Access/FTP.md)（§6 PCAP 経由の平文認証情報抽出）/ [`02_Initial_Access/Protocol_Exploitation.md`](./02_Initial_Access/Protocol_Exploitation.md)（Mail 平文） |
| 3.6 | File Integrity Checking | kedalab 対象外（防御側手法）|

### §4 Target Identification and Analysis Techniques（標的特定・解析手法）

| 節 | テスト項目 | kedalab ファイル |
|----|---------|--------|
| 4.1 | Network Discovery | [`01_Reconnaissance/DNS_Enumeration.md`](./01_Reconnaissance/DNS_Enumeration.md) / [`01_Reconnaissance/Network_Scanning.md`](./01_Reconnaissance/Network_Scanning.md) |
| 4.2 | Network Port and Service Identification | [`01_Reconnaissance/Network_Scanning.md`](./01_Reconnaissance/Network_Scanning.md) / [`05_Tools_Reference/Nmap.md`](./05_Tools_Reference/Nmap.md) |
| 4.3 | Vulnerability Scanning | [`02_Initial_Access/Edge_Appliance_CVEs.md`](./02_Initial_Access/Edge_Appliance_CVEs.md) / [`05_Tools_Reference/Searchsploit.md`](./05_Tools_Reference/Searchsploit.md) / [`05_Tools_Reference/CVE_Notes.md`](./05_Tools_Reference/CVE_Notes.md) |
| 4.4 | Wireless Scanning（Passive/Active/Bluetooth）| kedalab 対象外（ワイヤレス現スコープ外）|

### §5 Target Vulnerability Validation Techniques（脆弱性検証手法）

| 節 | テスト項目 | kedalab ファイル |
|----|---------|--------|
| 5.1 | Password Cracking | [`05_Tools_Reference/Hashcat.md`](./05_Tools_Reference/Hashcat.md) / [`04_Post_Access_Windows_AD/Credential_Dumping.md`](./04_Post_Access_Windows_AD/Credential_Dumping.md)（ハッシュ取得経路）|
| 5.2 | Penetration Testing | [`00_Playbook/`](./00_Playbook/) 全 Playbook / [`02_Initial_Access/`](./02_Initial_Access/) 全般 |
| 5.2.1 | Penetration Testing Phases（4-Stage Methodology）| [`06_Concepts/Pentest_Fundamentals.md`](./06_Concepts/Pentest_Fundamentals.md) / [`06_Concepts/Pentest_Guidelines_Guide.md`](./06_Concepts/Pentest_Guidelines_Guide.md) |
| 5.2.2 | Penetration Testing Logistics | [`06_Concepts/Pentest_Fundamentals.md`](./06_Concepts/Pentest_Fundamentals.md)（RoE 項目）|
| 5.3 | Social Engineering | [`02_Initial_Access/Social_Engineering.md`](./02_Initial_Access/Social_Engineering.md)（限定的記述）|

### §6 Security Assessment Planning（評価計画）

| 節 | 内容 | kedalab ファイル |
|----|------|--------|
| 6.1〜6.5 | 評価ポリシー策定・優先度・技法選定・計画策定 | [`06_Concepts/Pentest_Fundamentals.md`](./06_Concepts/Pentest_Fundamentals.md)（事前合意項目）|
| 6.6 | Legal Considerations | [`06_Concepts/Pentest_Fundamentals.md`](./06_Concepts/Pentest_Fundamentals.md)（法的・倫理的留意点）|
| Appendix B | Rules of Engagement Template | [`06_Concepts/Pentest_Fundamentals.md`](./06_Concepts/Pentest_Fundamentals.md)（RoE 項目セクション）|

### §7 Security Assessment Execution（評価実施）

| 節 | 内容 | kedalab ファイル |
|----|------|--------|
| 7.1 | Coordination | 各 Playbook 冒頭（[`00_Playbook/External_Service_Recon_Flow.md`](./00_Playbook/External_Service_Recon_Flow.md) 等の事前合意確認）|
| 7.2 | Assessing | [`00_Playbook/`](./00_Playbook/) 全 Playbook（実施作業）|
| 7.3 | Analysis | kedalab 対象外（報告書作成領域）|
| 7.4 | Data Handling（Collection/Storage/Transmission/Destruction）| kedalab 対象外（案件運用ポリシー領域）|

### §8 Post-Testing Activities（実施後活動）

| 節 | 内容 | kedalab ファイル |
|----|------|--------|
| 8.1 | Mitigation Recommendations | kedalab 対象外（報告書領域）|
| 8.2 | Reporting | kedalab 対象外（[`06_Concepts/CVSS_Scoring.md`](./06_Concepts/CVSS_Scoring.md) でスコア表現のみ）|
| 8.3 | Remediation/Mitigation | kedalab 対象外 |

---

## PTES（Penetration Testing Execution Standard）

公式 Main Page: http://www.pentest-standard.org/index.php/Main_Page
Technical Guidelines: http://www.pentest-standard.org/index.php/PTES_Technical_Guidelines

> **状態の注記:** Technical Guidelines 内に `<Contribution Needed>` の空白が複数残り（Exploitation 配下の Countermeasure Bypass / HIPS / DEP / ASLR 等）、公式サイトの応答も不安定（2026-05-19 時点）。**事実上維持停滞しているガイドライン**として扱い、引用時は古い情報である可能性に注意する。

### PTES メイン 7 フェーズ ↔ kedalab マッピング

| # | フェーズ | kedalab 対応 |
|---|---------|------------|
| 1 | Pre-engagement Interactions | [`06_Concepts/Pentest_Fundamentals.md`](./06_Concepts/Pentest_Fundamentals.md)（事前合意項目） |
| 2 | Intelligence Gathering | Technical Guidelines セクション表（後述）|
| 3 | Threat Modeling | kedalab 対象外（攻撃シナリオ設計は案件個別）|
| 4 | Vulnerability Analysis | Technical Guidelines セクション表（後述）|
| 5 | Exploitation | Technical Guidelines セクション表（後述）|
| 6 | Post Exploitation | Technical Guidelines セクション表（後述）|
| 7 | Reporting | kedalab 対象外（[`06_Concepts/CVSS_Scoring.md`](./06_Concepts/CVSS_Scoring.md) でスコア表現のみ）|

### PTES Technical Guidelines セクション ↔ kedalab マッピング

#### Intelligence Gathering

| PTES セクション | kedalab ファイル |
|---|---|
| OSINT / Corporate / Individuals | [`01_Reconnaissance/DNS_Enumeration.md`](./01_Reconnaissance/DNS_Enumeration.md)（公開 DNS 情報）/ [`01_Reconnaissance/Metadata_Analysis.md`](./01_Reconnaissance/Metadata_Analysis.md)（文書メタデータ）|
| Electronic Data / Document leakage / Metadata leakage | [`01_Reconnaissance/Metadata_Analysis.md`](./01_Reconnaissance/Metadata_Analysis.md) |
| Covert gathering / Physical / Dumpster diving / RF | kedalab 対象外（物理・ワイヤレス現スコープ外）|
| External Footprinting / Identifying IP Ranges / WHOIS | [`01_Reconnaissance/DNS_Enumeration.md`](./01_Reconnaissance/DNS_Enumeration.md) |
| External Footprinting / Active Reconnaissance / DNS Bruting / Port Scanning / Banner Grabbing | [`00_Playbook/External_Service_Recon_Flow.md`](./00_Playbook/External_Service_Recon_Flow.md) / [`01_Reconnaissance/Network_Scanning.md`](./01_Reconnaissance/Network_Scanning.md) |
| Internal Footprinting / Ping Sweeps / Port Scanning / SNMP Sweeps | [`00_Playbook/Internal_LAN_Pentest_Flow.md`](./00_Playbook/Internal_LAN_Pentest_Flow.md) / [`01_Reconnaissance/Network_Scanning.md`](./01_Reconnaissance/Network_Scanning.md) / [`01_Reconnaissance/SNMP_Enumeration.md`](./01_Reconnaissance/SNMP_Enumeration.md) |
| Internal Footprinting / SMB / Zone Transfers | [`01_Reconnaissance/SMB_Enumeration.md`](./01_Reconnaissance/SMB_Enumeration.md) / [`01_Reconnaissance/DNS_Enumeration.md`](./01_Reconnaissance/DNS_Enumeration.md) |

#### Vulnerability Analysis

| PTES セクション | kedalab ファイル |
|---|---|
| Active / Automated Tools / Network Vulnerability Scanners（OpenVAS）| [`02_Initial_Access/Edge_Appliance_CVEs.md`](./02_Initial_Access/Edge_Appliance_CVEs.md) / [`05_Tools_Reference/Searchsploit.md`](./05_Tools_Reference/Searchsploit.md) / [`05_Tools_Reference/CVE_Notes.md`](./05_Tools_Reference/CVE_Notes.md) |
| Active / Web Application Scanners | [`02_Initial_Access/Web_Vulnerabilities/`](./02_Initial_Access/Web_Vulnerabilities/) 全般 / [`06_Concepts/Web_Pentest_Tooling.md`](./06_Concepts/Web_Pentest_Tooling.md) |
| Passive Testing | kedalab 対象外（防御側ログ・トラフィック解析主体）|

#### Exploitation

| PTES セクション | kedalab ファイル |
|---|---|
| Precision strike / Exploit Development | [`00_Playbook/Linux_Attack_Flow.md`](./00_Playbook/Linux_Attack_Flow.md) / [`00_Playbook/Windows_AD_Attack_Flow.md`](./00_Playbook/Windows_AD_Attack_Flow.md) / [`02_Initial_Access/`](./02_Initial_Access/) 全般 |
| Countermeasure Bypass（AV / HIPS / DEP / ASLR 等）| PTES 側 `<Contribution Needed>` のため kedalab で別途扱う：[`04_Post_Access_Windows_AD/BYOVD.md`](./04_Post_Access_Windows_AD/BYOVD.md) / [`02_Initial_Access/Web_Vulnerabilities/JS_Obfuscation.md`](./02_Initial_Access/Web_Vulnerabilities/JS_Obfuscation.md) |

#### Post Exploitation

| PTES セクション | kedalab ファイル |
|---|---|
| Windows Post Exploitation / Blind Files / Non Interactive Command Execution | [`04_Post_Access_Windows_AD/Enumeration_Checklist.md`](./04_Post_Access_Windows_AD/Enumeration_Checklist.md) / [`04_Post_Access_Windows_AD/Credential_Dumping.md`](./04_Post_Access_Windows_AD/Credential_Dumping.md) |
| Linux Post Exploitation 系 | [`03_Post_Access_Linux/Enumeration_Checklist.md`](./03_Post_Access_Linux/Enumeration_Checklist.md) / [`03_Post_Access_Linux/`](./03_Post_Access_Linux/) 全権限昇格手法 |

#### Reporting

| PTES セクション | kedalab ファイル |
|---|---|
| Executive-Level Reporting / Technical Reporting | kedalab 対象外（[`06_Concepts/CVSS_Scoring.md`](./06_Concepts/CVSS_Scoring.md) でスコア表現観点のみ）|

---

## ガイドライン間のフェーズ対応

NIST SP 800-115 と PTES のフェーズ対応関係：

| NIST § | PTES フェーズ | 主な活動 |
|--------|-------------|---------|
| §6 + Appendix B RoE | Pre-engagement Interactions | スコープ確定・実施合意書 |
| §4.1 / §4.2 | Intelligence Gathering（External/Internal Footprinting）| 探索・サービス特定 |
| – | Threat Modeling | NIST に明示章なし |
| §4.3 | Vulnerability Analysis（Identification） | 脆弱性スキャナ実施 |
| §5.2 | Vulnerability Analysis（Validation）/ Exploitation | 実エクスプロイト |
| §5.2 Attack phase loopback | Post Exploitation | 横展開・追加情報収集 |
| §7 | （全フェーズ実施運用） | 調整・データ取扱 |
| §8 | Reporting | 報告書作成・修復提案 |

> 細部の粒度は両者で異なる。NIST は抽象的・観点ベース、PTES は具体的・ツール列挙ベース。

---

## kedalab がカバーしない領域（横断サマリー）

両ガイドラインで定義されているが kedalab スコープ外の領域：

| 領域 | 該当章・フェーズ | 代替参照 |
|------|----------------|---------|
| 文書・ログ・設定レビュー（防御側）| NIST §3.1〜§3.4 | 案件個別対応 |
| Wireless Scanning | NIST §4.4 / PTES RF | 案件個別対応 |
| Social Engineering 運用 | NIST §5.3 / PTES Covert | [`02_Initial_Access/Social_Engineering.md`](./02_Initial_Access/Social_Engineering.md)（限定的）|
| Threat Modeling | PTES Phase 3 | 案件個別対応 |
| 評価計画策定（事務・契約）| NIST §6 大部分 | [`06_Concepts/Pentest_Fundamentals.md`](./06_Concepts/Pentest_Fundamentals.md) |
| Data Handling 運用 | NIST §7.4 | 案件運用ポリシー |
| 報告書作成 | NIST §8 / PTES Reporting | [`06_Concepts/CVSS_Scoring.md`](./06_Concepts/CVSS_Scoring.md)（スコア表現のみ）|

これらが必要な場合は手動対応、または他ガイドライン（OWASP WSTG・MITRE ATT&CK）を併用する。
