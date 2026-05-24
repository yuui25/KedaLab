# 外部リファレンス集

> **このファイルの位置づけ:** kedalab で記述した技術ナレッジの参照元として使う外部リソースを集約する。各サービスページ・各技術を書く際の「最初に開く目次」として機能する。原典・コミュニティリファレンス・標準ドキュメント・ツール公式ドキュメント・ベンダーアドバイザリ・ワードリスト等を分類別にまとめる。
>
> WRITING_GUIDE の 06_Concepts/ スコープ「動作原理」とは性質が異なるが、kedaweb の概念タブで一覧したい性質上、例外として 06_Concepts/ に配置する（WRITING_GUIDE 該当節の例外規定を参照）。
>
> **対象読者:** kedalab に新しい技術ファイルを書こうとしている人、または既存技術の出典を辿りたい人。

---

> **⚠️ 重要 — 未検証 URL の取扱い**
>
> 以下のリンクは記憶ベースで **未検証**。プロジェクトの URL 移転・リポ rename・サイト閉鎖の可能性がある。
> **引用・参照する前に必ず WebFetch / ブラウザで実在確認**し、最新版が同一の意図を持つかも確認すること。
> リンク先のライセンスにも留意（特に PoC コード・ペイロード集を kedalab に転記する際は WRITING_GUIDE「有料学習コンテンツ由来の具体的なコード・リストはそのまま転記しない」原則を適用）。

---

## 1. 総合コミュニティリファレンス（複数フェーズを横断）

| 名称 | URL（要確認） | 性質 |
|---|---|---|
| **HackTricks**（Carlos Polop） | `https://book.hacktricks.wiki/` または `book.hacktricks.xyz/` | 全プラットフォーム・サービス別の網羅的攻撃手法集。最新性高い |
| **PayloadsAllTheThings**（swisskyrepo） | `https://github.com/swisskyrepo/PayloadsAllTheThings` | Web 中心のペイロード・bypass テクニック集 |
| **The Hacker Recipes**（Charlie Bromberg / mpgn 等） | `https://www.thehacker.recipes/` | AD 攻撃を中心に体系化 |
| **ired.team**（ZeroPointSecurity 系） | `https://www.ired.team/` | Red team / OffSec 系の手法集 |
| **InfoSec Reference**（rmusser01） | `https://github.com/rmusser01/Infosec_Reference` | リンク集の集大成（古めだが網羅性高い） |
| **0xdf 等の Writeup 系**（参考程度） | 各種ブログ | 演習ホスト個別解説。手法抽出にのみ使用、kedalab 公開側に固有値を持ち込まない |

---

## 2. PrivEsc 特化

| 名称 | URL（要確認） | 用途 |
|---|---|---|
| **GTFOBins** | `https://gtfobins.github.io/` | Linux: SUID / sudo / capabilities で悪用可能なバイナリ辞書 |
| **LOLBAS** | `https://lolbas-project.github.io/` | Windows: Living Off the Land Binaries（正規バイナリの悪用） |
| **LOLDrivers** | `https://www.loldrivers.io/` | 脆弱ドライバー（BYOVD 用） |
| **WADComs** | `https://wadcoms.github.io/` | Windows / AD 攻撃コマンドの状況別検索 UI |
| **PEASS-ng**（旧 PEASS） | `https://github.com/peass-ng/PEASS-ng` | WinPEAS / LinPEAS / MacPEAS の本家 |
| **g0tmi1k Linux Privesc**（古典） | `https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/` | 列挙のチェックリストの古典 |

---

## 3. AD 特化

| 名称 | URL（要確認） | 性質 |
|---|---|---|
| **adsecurity.org**（Sean Metcalf） | `https://adsecurity.org/` | AD 攻撃・防御の権威的解説 |
| **SpecterOps Blog**（harmj0y / wald0 等） | `https://posts.specterops.io/` | BloodHound・Kerberos・ACE 系研究 |
| **BloodHound Docs** | `https://bloodhound.specterops.io/` | クエリ集・運用ドキュメント |
| **AD-Attack-Defense**（infosecn1nja） | `https://github.com/infosecn1nja/AD-Attack-Defense` | 攻撃・防御セット |
| **Active Directory Exploitation Cheat Sheet**（S1ckB0y1337） | `https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet` | 単一 README 形式の網羅 |
| **Certipy / AD CS 攻撃解説**（ly4k） | `https://github.com/ly4k/Certipy` の README + 関連ブログ | ESC1-15 の参照元 |

---

## 4. Web 特化

| 名称 | URL（要確認） | 性質 |
|---|---|---|
| **OWASP WSTG**（Web Security Testing Guide） | `https://owasp.org/www-project-web-security-testing-guide/` | kedalab `TECHNIQUES_INDEX_WSTG.md` の原典 |
| **OWASP Cheat Sheet Series** | `https://cheatsheetseries.owasp.org/` | 防御中心だが診断にも有用 |
| **OWASP Top 10** | `https://owasp.org/www-project-top-ten/` | カテゴリ整理の標準 |
| **OWASP API Security Top 10** | `https://owasp.org/www-project-api-security/` | API 診断軸 |
| **PortSwigger Web Security Academy** | `https://portswigger.net/web-security` | 無料・実機ラボ付き Web 脆弱性網羅 |
| **PortSwigger Research**（James Kettle 等） | `https://portswigger.net/research` | HTTP smuggling 等の最先端研究 |
| **PayloadsAllTheThings の Web 系**（再掲） | 上記 §1 参照 | XSS / SQLi / Path Traversal 等 |

---

## 5. Reverse Shell / Payload 生成

| 名称 | URL（要確認） | 用途 |
|---|---|---|
| **PentestMonkey Reverse Shell Cheat Sheet** | `http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet` | 古典・bash/python/perl/nc バリエーション |
| **revshells.com** | `https://www.revshells.com/` | IP / ポート入力でペイロード生成 |
| **msfvenom 公式** | `https://docs.metasploit.com/` の該当章 | Metasploit ペイロード生成 |
| **HoaxShell**（rebooting reverse shell） | GitHub 検索 | Windows / HTTP ベースの代替 |

---

## 6. CVE / 脆弱性情報・PoC

| 名称 | URL（要確認） | 性質 |
|---|---|---|
| **CVE.org**（MITRE） | `https://www.cve.org/` | CVE ID の公式レジストリ |
| **NVD**（NIST） | `https://nvd.nist.gov/` | CVE + CVSS + CPE + 参照 |
| **Exploit-DB** | `https://www.exploit-db.com/` | PoC データベース（searchsploit の本家） |
| **CISA KEV カタログ** | `https://www.cisa.gov/known-exploited-vulnerabilities-catalog` | 実害確認済み CVE の公的リスト |
| **GitHub Security Advisories (GHSA)** | `https://github.com/advisories` | OSS の advisory 集 |
| **Vulners** | `https://vulners.com/` | 横断検索 |
| **Project Zero Issue Tracker** | `https://bugs.chromium.org/p/project-zero/issues/list` | Google P0 の disclosed bugs |

---

## 7. 標準・方法論

| 名称 | URL（要確認） | 性質 |
|---|---|---|
| **NIST SP 800-115** "Technical Guide to Information Security Testing and Assessment" | `https://csrc.nist.gov/publications/detail/sp/800-115/final` | kedalab `TECHNIQUES_INDEX_GUIDELINES.md` 原典 |
| **PTES (Penetration Testing Execution Standard)** | `http://www.pentest-standard.org/index.php/Main_Page` | フェーズ別の標準（古いが参照される） |
| **OSSTMM**（ISECOM） | `https://www.isecom.org/research.html` | 体系的方法論 |
| **MITRE ATT&CK** | `https://attack.mitre.org/` | kedalab `TECHNIQUES_INDEX_MITRE.md` 原典 |
| **MITRE D3FEND** | `https://d3fend.mitre.org/` | 防御側マッピング（参考） |
| **CERT/CC Vulnerability Disclosure Guidelines** | `https://vuls.cert.org/` または CERT/CC サイト | disclosure 方法論 |

---

## 8. AI / ML Red Teaming

| 名称 | URL（要確認） | 性質 |
|---|---|---|
| **OWASP Top 10 for LLM Applications** | `https://owasp.org/www-project-top-10-for-large-language-model-applications/` | LLM アプリ脅威の標準分類 |
| **OWASP Machine Learning Security Top 10** | `https://owasp.org/www-project-machine-learning-security-top-10/` | ML パイプライン脅威 |
| **MITRE ATLAS** | `https://atlas.mitre.org/` | AI 攻撃の ATT&CK 相当（kedalab 内で `TECHNIQUES_INDEX_ATLAS.md` 別建て予告あり） |
| **AI Village**（DEF CON 系） | `https://aivillage.org/` | コミュニティ・大会 |
| **NIST AI RMF (AI Risk Management Framework)** | `https://www.nist.gov/itl/ai-risk-management-framework` | リスク管理フレームワーク |
| **Awesome ML for Cyber Security**（jivoi 等） | `https://github.com/jivoi/awesome-ml-for-cybersecurity` | リンク集（要確認） |

---

## 9. SecLists / ワードリスト

| 名称 | URL（要確認） | 性質 |
|---|---|---|
| **SecLists**（danielmiessler） | `https://github.com/danielmiessler/SecLists` | ワードリスト・ペイロード・デフォルト認証情報の事実上の標準集。`Default-Credentials/` 配下を kedalab `Default_Credentials.md` から参照 |
| **rockyou.txt** | 各種 mirror（オリジナルは 2009 年漏洩） | ペネトレ用 Linux ディストリ標準同梱の弱パスワード辞書 |

---

## 10. awesome リスト（まとめのまとめ）

| 名称 | URL（要確認） |
|---|---|
| **awesome-pentest**（enaqx） | `https://github.com/enaqx/awesome-pentest` |
| **awesome-hacking**（Hack-with-Github） | `https://github.com/Hack-with-Github/Awesome-Hacking` |
| **awesome-red-teaming**（yeyintminthuhtut） | `https://github.com/yeyintminthuhtut/Awesome-Red-Teaming` |
| **awesome-cloud-security** | `https://github.com/4ndersonLin/awesome-cloud-security` または同類複数候補あり、要確認 |
| **awesome-windows-exploitation** | GitHub 検索（複数候補） |

---

## 11. 企業・研究機関ブログ

| 名称 | URL（要確認） |
|---|---|
| **SpecterOps Posts** | `https://posts.specterops.io/` |
| **Synacktiv** | `https://www.synacktiv.com/publications` |
| **NCC Group Research** | `https://research.nccgroup.com/` |
| **Rapid7 Blog** | `https://www.rapid7.com/blog/` |
| **Mandiant / Google Cloud TI** | `https://www.mandiant.com/resources/blog` |
| **Bishop Fox Blog** | `https://bishopfox.com/blog` |
| **Trail of Bits Blog** | `https://blog.trailofbits.com/` |
| **CrowdStrike Threat Reports** | `https://www.crowdstrike.com/global-threat-report/` |
| **Verizon DBIR** | `https://www.verizon.com/business/resources/reports/dbir/` |
| **Horizon3.ai Disclosures** | `https://horizon3.ai/attack-research/` |

---

## 12. ツール公式ドキュメント

| ツール | URL（要確認） |
|---|---|
| **Nmap** | `https://nmap.org/book/` |
| **Metasploit** | `https://docs.metasploit.com/` |
| **Burp Suite** | `https://portswigger.net/burp/documentation` |
| **Impacket** | `https://github.com/fortra/impacket` |
| **BloodHound** | `https://bloodhound.specterops.io/` |
| **NetExec**（旧 CrackMapExec） | `https://www.netexec.wiki/` |
| **Hashcat** | `https://hashcat.net/wiki/` |
| **John the Ripper** | `https://www.openwall.com/john/doc/` |
| **Certipy** | `https://github.com/ly4k/Certipy` |
| **Responder** | `https://github.com/lgandx/Responder` |
| **ntlmrelayx**（Impacket 内） | 上記 Impacket |
| **mitm6** | `https://github.com/dirkjanm/mitm6` |
| **nuclei**（ProjectDiscovery） | `https://docs.projectdiscovery.io/tools/nuclei/overview` |
| **ffuf** | `https://github.com/ffuf/ffuf` |
| **gobuster** | `https://github.com/OJ/gobuster` |

---

## 13. 個別ベンダー製品アドバイザリ（`Edge_Appliance_CVEs.md` の追跡先）

| ベンダー | URL（要確認） |
|---|---|
| **Citrix Security Bulletins** | `https://support.citrix.com/securitybulletins` |
| **Fortinet PSIRT Advisories** | `https://www.fortiguard.com/psirt` |
| **Ivanti Security Advisories** | `https://www.ivanti.com/blog/topics/security-advisory` |
| **Palo Alto Networks Security Advisories** | `https://security.paloaltonetworks.com/` |
| **F5 Security Advisories** | F5 サポートサイト内（K 番号で個別。トップは `https://my.f5.com/` 内）|
| **Microsoft Security Update Guide** | `https://msrc.microsoft.com/update-guide/` |
| **Cisco Security Advisories** | `https://sec.cloudapps.cisco.com/security/center/publicationListing.x` |
| **VMware Security Advisories**（Broadcom 移行後） | `https://www.broadcom.com/support/vmware-security-advisories` |

---

## 14. Cloud / Container / Kubernetes

| 名称 | URL（要確認） | 性質 |
|---|---|---|
| **HackTricks Cloud** | `https://cloud.hacktricks.wiki/`（または `.xyz/`） | クラウド・コンテナ・K8s 攻撃の網羅 |
| **Pacu**（AWS pentest） | `https://github.com/RhinoSecurityLabs/pacu` | AWS 攻撃フレームワーク |
| **kube-hunter**（廃止予定？） | `https://github.com/aquasecurity/kube-hunter` | K8s 列挙 |
| **kube-bench** | `https://github.com/aquasecurity/kube-bench` | CIS Benchmark チェック |
| **Cloud Security Alliance (CSA)** | `https://cloudsecurityalliance.org/research/` | 標準・ガイドライン |
| **PEACH / cloud isolation** 系研究（Wiz Research 等） | `https://www.wiz.io/blog` | 最新の Cloud 脆弱性研究 |

---

## 15. 日本語リソース（補助）

| 名称 | URL（要確認） | 性質 |
|---|---|---|
| **IPA セキュリティ関連情報** | `https://www.ipa.go.jp/security/` | 国内ガイドライン・注意喚起 |
| **JPCERT/CC** | `https://www.jpcert.or.jp/` | 国内 CSIRT。注意喚起・分析レポート |
| **JVN (Japan Vulnerability Notes)** | `https://jvn.jp/` | 国内向け脆弱性データベース |
| **NICTER / NISC** | `https://www.nict.go.jp/` / `https://www.nisc.go.jp/` | 観測・政策 |
| **「徳丸本」関連** | 書籍（徳丸浩 著）+ ブログ（要検索） | Web 診断の日本語デファクト |
| **MBSD 技術ブログ** | `https://www.mbsd.jp/` 内 | 国内ベンダー研究 |
| **Flatt Security Blog** | `https://flatt.tech/research` | 国内ベンダー研究 |

---

> **学習プラットフォーム（演習環境）について:** kedalab の **公開コンテンツでは演習環境名・コース名の明記は禁止**（WRITING_GUIDE「演習環境名・資格名・コース名の禁止」）。
> 学習プラットフォームの参照リストは `_workspace/tasks/fastpentest_external_service_catalog.md` §11.16（公開対象外）に集約する。

---

## 使い方ガイドライン

1. 本リストは **「最初に開く目次」** として使う。各サービス・各技術を kedalab に書く際の参照元として「どこを読みに行くか」を即引きする
2. **転記時の著作権配慮**: WRITING_GUIDE「有料学習コンテンツ由来の具体的なコード・リストはそのまま転記しない」を遵守。概念・原理は自分の言葉で書き直す
3. **URL は本ファイル更新時点で未検証**。kedalab 公開ファイル（00_-08_）に URL を載せる際は必ず WebFetch で実在確認＋最新版確認を行う
4. **演習環境名は kedalab 公開側で禁止**（学習プラットフォームは `_workspace/` 限定）
5. リンク切れに気づいたら本ファイルを更新する。リンク死亡が頻発するセクションは **Internet Archive / Wayback Machine** へのフォールバック URL も併記する

---

## 関連技術

- 関連：NIST SP 800-115 / PTES の章マッピング → `../TECHNIQUES_INDEX_GUIDELINES.md`
- 関連：MITRE ATT&CK Technique ID マッピング → `../TECHNIQUES_INDEX_MITRE.md`
- 関連：OWASP WSTG カテゴリマッピング → `../TECHNIQUES_INDEX_WSTG.md`
- 関連：CVE 研究の参照軸（NVD / KEV / Exploit-DB の使い分け）→ `./CVE_Research_Starter.md`
- 関連：MITRE ATT&CK の使い方ガイド → `./MITRE_ATTCK_Guide.md`
- 関連：OWASP WSTG の使い方ガイド → `./OWASP_WSTG_Guide.md`
- 関連：ペネトレ標準ガイドライン（NIST/PTES 等）の概要 → `./Pentest_Guidelines_Guide.md`
- 関連：Web 診断ツール群の使い分け → `./Web_Pentest_Tooling.md`
