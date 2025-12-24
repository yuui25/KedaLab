## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS
  - 破れる：内部DNSは「名前解決の基盤」だが、委譲・動的更新・ゾーン転送が緩いと、内部資産（DC/ファイル/DB/管理系）の棚卸しが“DNSだけで完了”する。特に AXFR/IXFR が許可されていると、ホスト名・サブドメイン・SRVレコード（AD関連）・管理系命名規則が漏えいし、以後の横展開（RDP/WinRM/SMB/LDAP 等）を加速する。
  - 満たす：ゾーン転送は “必要なセカンダリのみ” に限定（TSIG等で保護）、委譲（NS/Glue）は最小、内部DNS到達性は管理/サーバ網に限定し、監査（ゾーン転送試行・更新イベント）を相関できる形で固定する。
- WSTG
  - WSTG-CONF-01（Network Infrastructure Configuration）：DNSを含む基盤設定の検証（不要な情報露出、不要サービスの到達性、構成の一貫性）を求める。内部DNSのAXFRは典型の「設定不備＝情報露出」。  
    https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration
- PTES
  - 情報収集（内部名寄せ）→ 到達性（53/UDP/TCP）→ 委譲の追跡 → 転送可否（AXFR/IXFR）→ 漏えい情報の分類（攻め筋へ接続）→ 報告（影響と是正）、の順で推測ゼロに落とす。  
    https://pentest-standard.readthedocs.io/
- MITRE ATT&CK
  - T1590 Gather Victim Network Information：DNSを含むネットワーク情報収集に接続。
  - 具体的に DNS は OSINT/内部Recon双方で “命名規則と資産の露出” を生むため、転送可否は高価値観測点。  
    https://attack.mitre.org/techniques/T1590/

---

## タイトル
内部DNS：委譲（NS/Glue）とゾーン転送（AXFR/IXFR）の境界を“観測→設定→影響”で確定する

---

## 目的（このファイルで到達する状態）
- 対象環境の内部DNSについて、次を **Yes/No/Unknown** で説明できる。
  1) 到達性：どこから DNS（53/UDP と 53/TCP）に到達可能か（AXFRはTCP前提）
  2) 委譲：どのサブゾーンがどこへ委譲され、NS/Glueがどう露出しているか
  3) 転送：AXFR/IXFR が許可されるゾーンがあるか（どの送信元から/どのサーバへ）
  4) 漏えい：転送/列挙で取得できたレコードを “攻め筋に直結するカテゴリ” へ分類できる
  5) 証跡：dig出力・転送ログ・イベントログで根拠を残せる
  6) 是正：許可リスト化（セカンダリのみ）・TSIG/ACL・分離（内部外部）へ落とせる

---

## 扱う範囲（本ファイルの守備範囲）
- 扱う
  - 委譲の追跡（NS・SOA・Glue・authority/additional の読み方）
  - AXFR/IXFR（TCP 53）の成立条件と検証
  - 内部DNSで“刺さるレコード”（SRV/A/AAAA/CNAME/PTR 等）の分類
  - Windows DNS（AD連携）を想定した観測ポイント（SRV/ドメインコントローラの露出）
  - 監査/検知と是正（最小コスト順）
- 扱わない（別ファイルへ接続）
  - サブドメイン辞書総当たり（外部OSINTの詳細） → `01_topics/01_asm-osint/06_subdomain_列挙...`
  - AD LDAP列挙 → `11_ldap_enum...`
  - Kerberos/Delegation → `12_kerberos...` `14_delegation...`

---

## 前提：委譲とゾーン転送の“違い”（誤解しない）
### 委譲（Delegation）
- 親ゾーンが「子ゾーンはこのNSへ問い合わせよ」と指示する仕組み。
- DNS応答の Authority セクションに NS が出る、Additional に Glue（子NSのIP）が付くことがある。
- 観測でやること：
  - 親ゾーンの NS/DS（あるなら）を確認
  - 子ゾーンに対する NS を辿り、管理境界（別部門/別管理者）を推定する

### ゾーン転送（Zone Transfer：AXFR/IXFR）
- セカンダリDNSへゾーン全体（または差分）を複製する仕組み。
- AXFR/IXFR は **TCP** を使う（＝UDP到達だけでは評価が終わらない）。
- “意図した相手（セカンダリ）だけ”に許すのが原則。

---

## 前提：AXFR/IXFR が意味する“漏えいの質”
- 単発のDNS問い合わせ：知っている名前の確認に留まる
- AXFR：ゾーンの **全レコード** を一括取得でき、命名規則・役割・管理系ホストが露出する
- その結果、以降の探索（RDP/WinRM/SMB/MSSQL/LDAP 等）が “対象リスト確定” から始まる（時間短縮＝リスク増）

---

## 境界モデル（事故が成立する条件を固定する）
### 境界1：DNS到達性（53/UDP と 53/TCP）
- 53/UDP：通常の名前解決
- 53/TCP：大きな応答やAXFR/IXFRに不可欠
- 設計境界：
  - “クライアント” が 53/TCP に到達できる必要は基本ない（用途が限定的）
  - 53/TCP が広いと AXFR 試行が容易になる

### 境界2：委譲の管理境界（NS/Glue）
- 子ゾーンが別NSに委譲されている場合、そのNSが別セグメント/別管理であることがある。
- そこが “穴” だと、親は堅いのに子だけAXFR可、などが起こる。

### 境界3：転送の許可条件（誰がAXFRできるか）
- 典型の失敗：
  - “任意IPからAXFR可”
  - “内部のどこからでもAXFR可”
- 望ましい：
  - セカンダリDNSのIPだけ許可（ACL）
  - TSIG等で相互認証

### 境界4：分離（内部/外部DNS、Split-horizon）
- 外部に内部ゾーン情報が漏れないよう、内部ゾーンを外向きに提供しない設計が必要。
- 内部の委譲先NSが外部から到達できると、内部情報が外へ滲むことがある。

---

## 実施方法（最高に具体的）：観測→判断→次の一手
> 注意：DNSは運用影響は比較的小さいが、AXFR試行は監視されることがある。回数は最小、証跡は最大。

---

## 0) 事前準備：DNS観測台帳（必須）
- `zone_candidate`: 例）corp.local / internal.example / ad.example.com（対象で許可された範囲）
- `dns_servers`: 既知のDNSサーバIP（DHCP/端末設定/設計資料）
- `observer`: 観測元（あなた/踏み台）とセグメント
- `reach_udp_53`: Yes/No/Filtered（経路別）
- `reach_tcp_53`: Yes/No/Filtered（経路別）
- `delegations`: 子ゾーン→NS一覧（evidence付き）
- `axfr`: 可能/不可/unknown（サーバ×ゾーン×観測元）
- `records_exposed`: 取得レコードの分類（後述カテゴリ）
- `evidence`: dig出力ファイル（txt）、pcap（必要なら）

---

## 1) 到達性：53/UDP と 53/TCP を“経路別”に確定
### 1-A) nmap（UDP/TCPを分けて記録）
~~~~
# TCP 53（AXFR/大応答に必須）
nmap -Pn -n -sT -p 53 --open <dns_ip> -oN dns_tcp53_<dns>.txt

# UDP 53（通常名前解決）
sudo nmap -Pn -n -sU -p 53 --open <dns_ip> -oN dns_udp53_<dns>.txt
~~~~

#### 判断
- TCP 53 が閉じている/filtered：AXFR試行は困難（設計としては好ましい場合が多い）
- TCP 53 が開いている：次は “AXFRが許可されているか” を確認する価値が高い

---

## 2) DNSサーバの同定：SOA/NS を取り、権威を確認する（推測しない）
### 2-A) SOA（権威の起点）を確認
~~~~
# 既知ゾーンがある前提。ゾーン名が不明なら、後述の“委譲追跡”から候補を作る。
dig +noall +answer SOA <zone_candidate> @<dns_ip>
~~~~

### 2-B) NS（権威サーバ一覧）を確認
~~~~
dig +noall +answer NS <zone_candidate> @<dns_ip>
~~~~

#### 観測ポイント
- SOAのmname（プライマリ）
- NSレコードのFQDN（ns1/ns2等）と命名規則
- 以後、AXFR試行は “このNS（権威）” に対して行う（キャッシュDNS相手にしても意味が薄い）

---

## 3) 委譲の追跡：子ゾーンを見つけ、NS/Glueを観測する
> 目的：親が堅くても子で漏れるケースを拾う。

### 3-A) Authority/Additional を見て “委譲の形” を読む
~~~~
# +trace は外部DNSでは強力だが、内部では経路/ルートが成立しないことがあるため、
# まずは指定DNSに対して authority/additional を明示して観測する。
dig +norecurse +authority +additional NS <child_zone_candidate> @<dns_ip>
~~~~

#### 判断
- Authority に NS が出る：委譲が存在（親が子のNSを示している）
- Additional に A/AAAA（Glue）が付く：子NSのIPが応答で漏れる（到達性評価へ直結）

### 3-B) 子NS（Glueや解決結果）へ直接問い合わせ
~~~~
dig +noall +answer NS <child_zone_candidate> @<child_ns_ip_or_name>
dig +noall +answer SOA <child_zone_candidate> @<child_ns_ip_or_name>
~~~~

---

## 4) AXFR/IXFR 検証（最重要）：サーバ×ゾーン×観測元でYes/Noを確定
> ルール：必ず “権威NS” に対して、対象ゾーン名を指定し、TCPで試す。

### 4-A) AXFR（全転送）試行（dig）
~~~~
# 権威NSに対してAXFRを試行
dig AXFR <zone_candidate> @<authoritative_ns_ip_or_name> +time=5 +tries=1
~~~~

#### 結果の解釈（このまま報告に書ける）
- レコードが列挙される：AXFR 成功（重大な情報露出）
- `Transfer failed.` / `REFUSED` / `NOTAUTH`：AXFRは拒否されている（設計としては望ましい）
- Timeout：到達性（TCP 53）/ ACL / 中間FW を疑う（“拒否”とは別扱い）

### 4-B) IXFR（差分転送）も評価に含める（運用上、AXFRは拒否でもIXFRが残る例がある）
~~~~
# SOA serial を観測してから、IXFRを試す（digの挙動は実装/サーバ依存）
dig +noall +answer SOA <zone_candidate> @<authoritative_ns>
dig IXFR=<serial_number> <zone_candidate> @<authoritative_ns> +time=5 +tries=1
~~~~

> 注：IXFRの詳細挙動は実装依存が大きい。ここでは “転送が許可され得る” ことを評価観点として残し、必要ならDNS製品（BIND/Windows DNS等）の設定確認で確定する。

---

## 5) 取得レコードの“実務分類”（AXFR成功時：報告価値を最大化する）
> 方針：ただ貼るのではなく、「次の攻め筋へ直結する」カテゴリに分けて影響を言語化する。

### 5-A) カテゴリ（例：優先順）
1. 認証・ディレクトリ（AD）
  - `_ldap._tcp.dc._msdcs.<domain>` 等の SRV：DC位置、サイト、サービス露出
  - `_kerberos._tcp`：Kerberosの入口  
  - これらは LDAP/ケルベロスの次工程（11/12/14）へ直結する
2. 管理系ホスト（踏み台/監視/バックアップ）
  - `jump`, `bastion`, `mgmt`, `backup`, `monitor`, `vcenter` 等の命名
3. 基幹サーバ（DB/ファイル/メール）
  - `sql`, `db`, `fs`, `mail`, `exchange` など
4. ネットワーク基盤
  - `ns`, `dhcp`, `ntp`, `vpn`, `fw`, `wlc` など
5. 環境識別
  - `prod`, `stg`, `dev`、リージョン/拠点コード（命名規則）

### 5-B) “結果の出し方”（貼り付けで終わらない）
- AXFR結果のレコードを、上記カテゴリごとに件数と代表例を抜き出す（最大10例）
- それぞれに「次に何ができる（観測できる）」を1行で紐づける  
  例：
  - SRVでDC特定 → `11_ldap_enum` の対象ホスト確定、`12_kerberos` の前提確定
  - `sql-*` 露出 → `20_mssql` の到達性/権限境界へ
  - `jump-*` 露出 → `19_rdp` / `18_winrm` の到達性評価へ

---

## 6) PTR（逆引き）と委譲の組合せ（内部Reconで刺さる）
> ゾーン転送が不可でも、逆引きゾーン（in-addr.arpa）が緩いと“資産棚卸し”が進む。

### 6-A) 逆引きゾーン候補のSOA/NS確認
~~~~
# 例：10.0.0.0/24 の逆引きゾーン候補（ネットにより異なる）
dig +noall +answer SOA 0.0.10.in-addr.arpa @<dns_ip>
dig +noall +answer NS  0.0.10.in-addr.arpa @<dns_ip>
~~~~

### 6-B) 逆引きゾーンのAXFR（許可されていると“IP→ホスト名”が一括で出る）
~~~~
dig AXFR 0.0.10.in-addr.arpa @<authoritative_ns> +time=5 +tries=1
~~~~

---

## 7) 監査・検知（Blue向け）：何を相関キーにするか
- 攻撃者は通常、AXFRが通れば短時間で大量のレコードを取得する（TCP/53の特異なトラフィック）。
- 相関キー（最低限）
  - srcIP（転送要求元）
  - dstDNS（権威NS）
  - zone名
  - 失敗→成功の連鎖（REFUSEDが連続→成功など）
  - TCP/53のセッション量/バイト量
- 検知設計（最小）
  - DNSサーバログ（転送要求のログ）＋NetFlow/ZeekでTCP/53のフロー相関
  - “セカンダリDNS以外からのAXFR/IXFR” をアラート化

> 製品別ログ（Windows DNS/BIND）は環境依存なので、本ファイルでは “相関設計” を固定し、実装は環境側の運用標準へ落とす。

---

## 8) 是正（最小コストで効く順）
1. 転送制御：ゾーン転送は “必要なセカンダリDNSのみ” に限定（IP許可リスト）  
2. 相互認証：可能なら TSIG 等で転送を保護（製品機能で）  
3. 露出最小化：内部DNSは外部から到達しない（Split-horizon/分離）  
4. TCP/53の最小化：クライアントセグメントから権威DNSへのTCP/53を原則不要にする（用途がある場合のみ例外）  
5. 監査：転送要求（AXFR/IXFR）をログ化し、送信元IPでアラート化  
6. 委譲の棚卸：子ゾーンのNS/Glueが外部到達していないかも合わせて確認

---

## 参考URL（本文の根拠として使用：そのまま貼る）
- dig（BIND）マニュアル（AXFRなどの使い方含む）  
  https://man7.org/linux/man-pages/man1/dig.1.html
- OWASP WSTG-CONF-01：Network Infrastructure Configuration  
  https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration
- PTES  
  https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：T1590 Gather Victim Network Information  
  https://attack.mitre.org/techniques/T1590/
- OWASP ASVS（参照元）  
  https://github.com/OWASP/ASVS

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
