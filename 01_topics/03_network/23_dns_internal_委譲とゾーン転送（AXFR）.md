# 23_dns_internal_委譲とゾーン転送（AXFR）
内部DNSの委譲とAXFR/IXFRの可否を観測で確定し、漏えいと是正まで落とす。

## 目的（この技術で到達する状態）
- DNS到達性（53/UDP, 53/TCP）を経路別に Yes/No/Unknown で説明できる
- 委譲先（NS/Glue）と管轄範囲を把握し、親子で境界が揃っているか判定できる
- AXFR/IXFR の許可条件（どのゾーンを誰が転送できるか）を根拠付きで示せる
- 転送で得たレコードをカテゴリ分けし、横展開に直結する影響を言語化できる
- 監査・是正（許可リスト/TSIG/到達性最小化/ログ相関）を提案できる

## 前提（対象・範囲・想定）
- 対象：内部DNS（社内ゾーン、AD統合DNS含む）
- 想定環境：オンプレ/クラウド混在可。Split-horizon を前提にしつつ外部露出の有無も確認
- できること/やらないこと：権威NSに対する最小回数のAXFR/IXFR試行のみ。辞書総当たりや第三者宛は禁止
- 依存知識：DNSのSOA/NS/Authority/Additional、AXFR/IXFRのTCP利用
- 扱う範囲：委譲追跡、AXFR/IXFR可否、取得レコード整理、監査・是正
- 扱わない（別ユニット）：外部OSINTサブドメイン列挙 → `01_topics/01_asm-osint/06_subdomain_列挙...`、AD LDAP列挙 → `11_ldap_enum...`、Kerberos/Delegation → `12_kerberos...` `14_delegation...`

## 観測ポイント（プロトコル/データ/境界）
- プロトコル：53/UDP（通常解決）と53/TCP（AXFR/大応答）
- 境界：内部クライアントから権威NSへのTCP到達性、外部からの到達可否
- 委譲：Authority/Additional に現れる NS/Glue、子ゾーンのNS到達性
- 転送可否：権威NS × ゾーン × 観測元 の AXFR/IXFR 成否
- 重要差分：親は堅牢でも子でAXFRが通る、逆引きゾーンでの漏えい、Split-horizon の崩れ

## 結果の意味（言える/言えない）
- 確定できる：到達性（UDP/TCP）、委譲先、AXFR/IXFR の成功/拒否/タイムアウト
- 推定できる：例外運用（セカンダリ以外に許可）、命名規則からの役割推定
- 言えない：キャッシュDNSのみを相手にした場合の権威判断
- 状態パターン
  - A：53/TCP閉鎖・AXFR拒否・委譲NS限定（良好）
  - B：TCP開放・親は拒否だが子ゾーンでAXFR成功（部分露出）
  - C：任意IPからAXFR成功（重大露出）

## 攻撃者視点での利用（意思決定：優先度・攻め筋）
- 狙い目：53/TCP開放＋権威NSへのAXFR許可、子ゾーン/逆引きゾーンの緩い転送
- 優先度：1) 到達性 2) 権威NS特定 3) AXFR/IXFR試行 4) レコードのカテゴリ整理
- 代表的な攻め筋
  - SRV（_ldap._tcp, _kerberos._tcp）でDCや認証基盤を確定し横展開へ
  - 管理/ジャンプ/監視/バックアップ系ホストを抽出し優先調査
- 戦略変更：AXFR不可なら Authority/Additional から委譲先を辿る、逆引きゾーンも確認

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：53/TCPが開いている  
  - 次の検証：nmap -sT 53/tcp、結果 open ならAXFR価値高  
  - 期待する観測：open なら後続AXFRを試行。filtered/closedなら設計として好ましい
- 仮説B：委譲先が別セグメント/別管理  
  - 次の検証：authority/additional で子NSを確認し、子NSへ SOA/NS/AXFR を試行  
  - 期待する観測：子でのみAXFR成功するケースを拾う。拒否なら設計通り
- 仮説C：逆引きゾーンが緩い  
  - 次の検証：in-addr.arpa の SOA/NS/AXFR を試行  
  - 期待する観測：AXFR成功でIP→ホスト名が大量露出。拒否なら設計通り

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境：任意。到達性・転送は本番構成に依存
- 取得する証跡：dig出力（txt）、nmap結果、必要に応じpcap
- 観測の取り方：権威NSを必ず指定し、キャッシュDNSは避ける
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ
    ~~~~
    mkdir -p ~/keda_evidence/dns_internal_23 2>/dev/null
    cd ~/keda_evidence/dns_internal_23
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 権威NSに対してのみAXFR/IXFRを実行（最小回数）
    - 第三者ドメイン・外部宛は対象外
  - 相関キー（最低限）
    - {srcIP, dstDNS, zone, Time, Result(成功/REFUSED/NOTAUTH/Timeout), Bytes}
  - 到達性確認
    ~~~~
    nmap -Pn -n -sT -p 53 --open <dns_ip> -oN dns_tcp53_<dns>.txt
    sudo nmap -Pn -n -sU -p 53 --open <dns_ip> -oN dns_udp53_<dns>.txt
    ~~~~
  - 権威特定（SOA/NS）
    ~~~~
    dig +noall +answer SOA <zone> @<dns_ip>
    dig +noall +answer NS  <zone> @<dns_ip>
    ~~~~
  - 委譲追跡（Authority/Additional を観測）
    ~~~~
    dig +norecurse +authority +additional NS <child_zone> @<dns_ip>
    dig +noall +answer NS  <child_zone> @<child_ns>
    dig +noall +answer SOA <child_zone> @<child_ns>
    ~~~~
  - AXFR/IXFR 試行（権威NSに対してのみ）
    ~~~~
    dig AXFR <zone> @<authoritative_ns> +time=5 +tries=1
    dig +noall +answer SOA <zone> @<authoritative_ns>
    dig IXFR=<serial_number> <zone> @<authoritative_ns> +time=5 +tries=1
    ~~~~
  - 逆引きゾーン（in-addr.arpa など）も同様に SOA/NS/AXFR を実施

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
dig AXFR <zone> @<ns>
dig +norecurse +authority +additional NS <child_zone> @<dns>
nmap -sT -p 53 <dns_ip>
~~~~
- この例で観測していること：AXFR許可/拒否、委譲先とGlue、TCP到達性
- 出力のどこを見るか：AXFR結果（成功/REFUSED/NOTAUTH/Timeout）、Authority/AdditionalのNS/Glue、nmapのopen/filtered
- この例が使えないケース：権威NSでなくキャッシュDNSを指定した場合、ゾーン名が未判明の場合

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS  
  - 破れる：AXFR/IXFR許可や緩い委譲でホスト・サービス・命名規則が一括漏えいし、後続攻撃を加速。  
  - 満たす：転送は権威セカンダリのみ許可（ACL+TSIG）、委譲NS/Glue最小化、内部DNSは管理ネットワークに限定し転送試行ログを監査。  
  - 参照：https://github.com/OWASP/ASVS
- WSTG  
  - WSTG-CONF-01：基盤設定検証としてDNS到達性/不要サービス/設定一貫性を確認。内部DNSのAXFRは典型的設定不備。  
  - 参照：https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration
- PTES  
  - 情報収集 → 到達性（53/UDP/TCP）→ 委譲追跡 → 転送可否 → 露出整理 → 報告。推測ゼロで Yes/No/Unknown を出す。  
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK  
  - T1590 Gather Victim Network Information（DNSを含むネットワーク情報収集）  
  - 参照：https://attack.mitre.org/techniques/T1590/

## 参考（必要最小限）
- dig man（AXFR/IXFR）：https://man7.org/linux/man-pages/man1/dig.1.html
- WSTG-CONF-01： https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration
- PTES： https://pentest-standard.readthedocs.io/
- MITRE T1590： https://attack.mitre.org/techniques/T1590/
- OWASP ASVS： https://github.com/OWASP/ASVS

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`11_ldap_enum_ディレクトリ境界（匿名_bind）.md`
- 関連 playbooks：なし
- 関連 labs / cases：任意

---

## 深掘りリンク（最大8）
- `05_scanning_到達性把握（nmap_masscan）.md`
- `06_service_fingerprint（banner_tls_alpn）.md`
- `07_pivot_tunneling（ssh_socks_chisel）.md`
- `11_ldap_enum_ディレクトリ境界（匿名_bind）.md`
- `12_kerberos_asrep_kerberoast_成立条件.md`
- `18_winrm_psremoting_到達性と権限.md`
- `19_rdp_設定と認証（NLA）.md`
- `20_mssql_横展開（xp_cmdshell_linkedserver）.md`
