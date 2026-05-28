# DNS 調査（ドメインが渡された場合の起点）

> **スコープ**: 53/tcp・53/udp（標準 DNS）/ 5353/udp（mDNS）から、ドメインの基本レコード列挙・サブドメイン発見・AD 環境推測・技術スタック特定・既知の DNS 攻撃面（Zone Transfer / Subdomain Takeover / NSEC walking / Cache Snooping / DDNS Update / DNS Rebinding / Recursion 開放 / NDN bounce 漏洩）を扱う。**DoT (853/tcp) / DoH (443/tcp 上の HTTPS) は暗号化 DNS で本ファイル対象外**（recon としては別経路：TLS スキャン側で扱う）。**DNS C2 / DNS tunneling は post-access の通信経路で本ファイル対象外**。**Cache Poisoning（Kaminsky 型）は現代では実用度低く参考言及のみ**。**DNS amplification DDoS は kedalab スコープ外**（本番禁止）。

## 着火条件
- テスト開始時にドメイン名のみ渡され、IP が不明な状態
- IP は判明しているが、同一サーバー上の他のドメイン・サブドメインを探したい場合
- 外部公開 DNS サーバー（権威 NS / 公開 resolver）が発見済み（53/tcp / 53/udp）

## 環境前提
- 実行環境: テスター端末
- 必要なツール: `nslookup` / `dig` / `host`（標準同梱）、`nmap`（PTR 一括逆引き `-sL`）、`gobuster` / `ffuf` / `dnsenum` / `dnsrecon` / `dnscan` / `fierce`（ペネトレ用 Linux ディストリ標準搭載）、`subfinder`（パッシブ列挙ファーストチョイス・ProjectDiscovery、`go install` or `apt install subfinder`）、`amass`（パッシブ + アクティブ統合）、`nuclei`（Subdomain Takeover 検出ファーストチョイス・`go install` or `apt install nuclei` + `nuclei -update-templates`）、`subzy`（Takeover 補完・`go install`）、`fpdns`（要インストール: `apt install fpdns` or git clone）、`subjack`（メンテ停止・参考扱い）、`dns-triage`（BHIS 公開ツール、要 git clone + `pip3 install`）、`ldns-walk`（`apt install ldnsutils`）、`nsupdate`（`bind-utils` / `bind9utils` 同梱）、`swaks`（メール送信、`apt install swaks`）
- インターネットアクセス: 外部DNSに問い合わせる場合は必要。内部 DNS サーバー指定なら不要

## 先に確認すること

- **渡されたドメインは外部公開されているか、内部ドメインか**: 外部公開なら `dig [DOMAIN] @8.8.8.8` で確認、内部ならテスター側到達可能インターフェースから内部 DNS を指定（`@[INTERNAL_DNS_IP]`）
- **VPN 接続が必要な場合の名前解決経路**: `ip a` でテスター側到達インターフェース（環境による：物理 LAN・VPN・専用線）を確認し、同サブネットの DNS を `@` で明示指定
- **大量サブドメイン bruteforce はノイズ大**: §5 を実行する前に §1-§4 で基本情報を取り、必要最小限のワードリストに絞る
- **AXFR / NSEC walking / DDNS update は別経路の検知シグネチャを持つ**: §4 §11 §13 は本番でログ残存に注意

攻撃者の思考トレース: ドメイン渡しの初動では、まず §1-§3 で基本レコード（A / MX / NS / TXT）を引いて **ターゲット組織のクラウドサービス利用状況と AD 有無を判定**する。TXT レコードと MX レコードは **組織の業務基盤（M365 / Google Workspace / Atlassian / ProofPoint 等）を最も雄弁に語る**。次に §4 AXFR を試行（成功すれば **即重大 finding**）、失敗時は §5 サブドメイン bruteforce へ。AD 環境なら §8 SRV レコードで DC を特定、外部公開リソースのみなら §9 技術スタック特定で社会工学・既知 CVE への接続経路を作る。**§10-§16 は状況依存の追加攻撃面**で、特に §13 DDNS Update / §14 DNS Rebinding は内容次第で 02 へ carve out 候補。

---

## 1. A レコードで IP を特定する

**コマンド:**

```bash
# [Attacker] nslookup で確認（シンプル）
nslookup [DOMAIN]

# [Attacker] dig で確認（フィールドが明確・ANSWER SECTION で IP 抽出）
dig [DOMAIN] A
dig [DOMAIN] A +short    # IP のみ抽出（スクリプトに渡しやすい）

# [Attacker] AAAA（IPv6）も忘れずに
dig [DOMAIN] AAAA
dig [DOMAIN] AAAA +short
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 単一 A レコード（例: `192.0.2.100`）| 単一サーバー | その IP に `nmap -sC -sV` でポートスキャン → `Network_Scanning.md` |
| 複数 A レコード（ロードバランサー / CDN / マルチオリジン）| 複数 IP 構成 | 全 IP をスキャン対象に追加。各 IP の応答差異を観察 |
| AAAA レコードあり（IPv6） | IPv6 経路も有効 | IPv6 経由でのアクセス・別経路スキャンを試行（IPv6 が IPv4 より緩い設定の場合あり） |
| 解決失敗（`NXDOMAIN`） | ドメイン不存在 / 内部限定 | §2 内部 DNS 指定経路へ / typo の可能性 / `dig @8.8.8.8` で外部 DNS でも確認 |
| `SERVFAIL` | DNS サーバー側のエラー | 別 DNS サーバーで再試行（`@1.1.1.1` / `@9.9.9.9`） |
| CDN ホスト名（`*.cloudfront.net` / `*.akamai.net` / `*.fastly.net`）が返る | CDN 経由 | オリジン IP は別途特定が必要：(a) 証明書透明性ログ `crt.sh`、(b) Shodan / Censys で対象組織の証明書 CN/SAN 検索、(c) 過去 DNS 履歴 DB（SecurityTrails / DNSDB / VirusTotal）、(d) サブドメインの直接 A レコード（CDN 前段になっていない `dev.*` / `staging.*` から漏れることが多い）、(e) SSRF 経由でアプリから直接接続させる |

**nslookup の出力例と読み方：**

```
Server:   8.8.8.8          ← 問い合わせた DNS サーバー
Address:  8.8.8.8#53

Non-authoritative answer:
Name:     target.example.com
Address:  192.0.2.100     ← ここが対象 IP
```

**dig の出力例と読み方：**

```
;; ANSWER SECTION:
target.example.com.  300  IN  A  192.0.2.100
                               ↑          ↑
                               レコード種別   IP アドレス
```

フィールドは左から「名前 / TTL / クラス / レコード種別 / 値」の順。

**注意:** `dig` の `+short` 出力は **IP だけ**返ってきて見落としやすい。`ANSWER SECTION` に複数行あれば全部を意識する（ロードバランサーや CDN は複数 A レコードを返す）。`AAAA` を毎回見落とさない（IPv6 攻撃面の見落としは現代では致命的）。

---

## 2. 内部 DNS サーバーを指定して解決する（VPN 環境・内部ドメインの場合）

**コマンド:**

```bash
# [Attacker] @[INTERNAL_DNS_IP] で問い合わせ先を指定する
dig [DOMAIN] A @[INTERNAL_DNS_IP]
nslookup [DOMAIN] [INTERNAL_DNS_IP]

# [Attacker] 内部 DNS が判明していない場合、テスター側到達可能セグメントから推測
# 通常はゲートウェイか .1 / .53 / .254 等が DNS であることが多い
ip a                              # 自分の IP・サブネット確認
ip route                          # デフォルトゲートウェイ確認
nmap -sU -p 53 [SUBNET]/24        # サブネット内の DNS 探索（UDP 53）
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 内部ドメインが解決できる | 内部 DNS 経路成立 | §1-§16 を `@[INTERNAL_DNS_IP]` 経由で実行可能 |
| 外部ドメインは解決でき内部ドメインは `NXDOMAIN` | DNS スプリットビュー未対応 / DNS 不一致 | DNS サーバー側が内部ビューを持っていない可能性 |
| 全部 `connection timed out` | DNS が FW でブロック / ホスト到達不可 | 別 DNS / 別経路を試す。`tcpdump -i any port 53` で送受信確認 |
| `REFUSED` | DNS 側のアクセス制御 ACL で拒否 | 認可された送信元 IP 範囲外。VPN / ジャンプサーバー経由で再試行 |

**注意:** 内部 DNS は **テスター側到達可能インターフェース**（環境によって物理 LAN・VPN・専用線等が変わる）を `ip a` で確認してから指定する。複数インターフェースがある場合、間違ったインターフェース経由で問い合わせて失敗するケースが多い。

---

## 3. 主要レコードをまとめて確認する

**コマンド:**

```bash
# [Attacker] 全レコード種別を一括取得（実装依存・返さない DNS あり）
dig [DOMAIN] ANY

# [Attacker] レコード種別を個別に指定（確実）
dig [DOMAIN] MX                       # メールサーバー
dig [DOMAIN] NS                       # 権威 DNS サーバー
dig [DOMAIN] TXT                      # SPF・DKIM・サービス認証情報等
dig [DOMAIN] CNAME                    # 別名レコード
dig [DOMAIN] SOA                      # ゾーンの管理者情報
dig [DOMAIN] CAA                      # 証明書発行ポリシー
dig _dmarc.[DOMAIN] TXT               # DMARC ポリシー
dig default._domainkey.[DOMAIN] TXT   # DKIM（セレクター名は組織依存）
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| MX レコードが別ホストを指す | メールサーバーが別 IP | メールサーバー IP も調査対象に追加。§9 で MX ホスト名から防御製品を特定 |
| NS レコードが判明 | 権威 DNS サーバー特定 | §4 ゾーン転送（AXFR）を NS に対して試行 |
| TXT に `v=spf1 include:_spf.google.com` / `include:spf.protection.outlook.com` 等 | M365 / Google Workspace 利用 | §9 技術スタック特定で詳細解釈 |
| TXT に `google-site-verification=` / `MS=ms*` / `atlassian-domain-verification=` 等 | SaaS 利用が判明 | §9 へ。社会工学・該当 SaaS の既知 CVE 確認 |
| CNAME が `*.github.io` / `*.herokuapp.com` / `*.s3.amazonaws.com` 等を指す | サードパーティ依存 | §10 Subdomain Takeover 候補 |
| SRV `_ldap._tcp` / `_kerberos._tcp` が返る | AD 環境判定 | §8 AD SRV レコード列挙 |
| `_dmarc` ポリシーが `p=none` | DMARC reject / quarantine 未設定 | **重大 finding** — メールスプーフィング可能。報告書化 |
| DKIM セレクター解決失敗 | DKIM 未設定 | 同上、メールスプーフィング容易の finding |
| `dig ANY` が空または `NOTIMP` | サーバーが ANY 拒否 | 個別レコード種別を指定して取り直す |

**よく使うレコード種別と意味：**

| レコード | 意味 | ペネトレ上の注目点 |
|---------|------|----------------|
| A / AAAA | ドメイン → IPv4 / IPv6 | 対象 IP の特定。AAAA を見落とさない（IPv6 経路が別経路として開いている場合あり） |
| MX | メール配送先 | メールサーバーのIPも調査対象に。`*.mail.protection.outlook.com`（M365）/ `*.pphosted.com`（ProofPoint）/ `*.mimecast.com` 等でメールセキュリティ製品を特定 |
| NS | 権威 DNS サーバー | ゾーン転送（AXFR）の試行先。**外部委託型 NS**（`*.cloudflare.com` / `*.awsdns-*` / `*.akam.net` 等）と**自社運用 NS** の区別を意識 |
| TXT | 任意文字列 | **組織が使用するクラウドサービス・SaaS の判明源**（`v=spf1 include:` 句 / `google-site-verification=` / `MS=ms*`（Microsoft 365）/ `docusign=` / `atlassian-domain-verification=` / `adobe-idp-site-verification=` 等）。DKIM セレクター・DMARC ポリシーも含まれる |
| CNAME | 別名（エイリアス） | Subdomain Takeover の確認対象（→ §10） |
| PTR | IP → ドメイン（逆引き） | IP からホスト名を特定する際に使う |
| SRV | サービス → ホスト・ポート | AD 環境の判定（`_ldap._tcp` / `_kerberos._tcp` / `_gc._tcp`）に使う（→ §8） |
| DNSKEY / DS / NSEC / NSEC3 | DNSSEC 関連 | NSEC walking で全レコード列挙が可能な場合あり（→ §11） |
| CAA | 証明書発行ポリシー | `issue` / `issuewild` の許可範囲過大は finding 候補。crt.sh と組み合わせて発行履歴を確認 |

### 3.1 逆引き（PTR）と権威連鎖の追跡

A レコードで取得した IP から組織保有の周辺ホストを推定する。**所有 IP レンジが分かれば PTR スキャンで未公開ホスト名が一括取得できる**ことがある。

**コマンド:**

```bash
# [Attacker] 単一 IP の逆引き
dig -x [TARGET_IP] +short
nslookup [TARGET_IP]

# [Attacker] サブネット全体の PTR を一括取得（nmap のリストスキャン・ポートは叩かない）
nmap -sL [SUBNET]/24 | grep "(" | awk '{print $5, $6}'

# [Attacker] 大きいレンジを並列に逆引き
for i in $(seq 1 254); do dig -x [SUBNET].$i +short +time=1 +tries=1 | grep -v '^$' & done; wait

# [Attacker] 権威の連鎖を root から辿る（委任ミス・DNSSEC 検証ミスの観察）
dig [DOMAIN] +trace
dig [DOMAIN] +trace +dnssec        # DNSSEC chain も同時表示
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| PTR が `*.internal.[DOMAIN]` 等の内部命名 | 内部ホスト命名規則の漏洩 | 内部 DNS 経路がインターネット側に出ている（**finding**） |
| PTR が組織関連ホスト名を多数返す（同一サブネット内）| 所有 IP レンジが連続割当 | 周辺 IP もスキャン対象に追加 |
| `+trace` で途中の NS が `SERVFAIL` | 権威 NS の一部が応答しない | 残る NS だけで構成されていれば DoS 耐性低 finding |
| `+trace +dnssec` で `ad` フラグなし | DNSSEC validation 未設定 / 鍵不整合 | キャッシュポイズニング耐性が低い finding |

> **注意:** `nmap -sL` は **ポートを一切送信しない**（PTR クエリのみ）ため検知性は低いが、それでも大量 PTR クエリは DNS サーバー側でレート異常として観察される。本番では `/24` 単位までに留める。

---

## 4. ゾーン転送を試みる（NS が判明した場合）

設定ミスのある DNS サーバーは、全ドメインレコードを一括で返す（ゾーン転送）。**成功時は情報漏洩 finding 確定**。

**コマンド:**

```bash
# [Attacker] dig で 1 NS に対して AXFR 試行
dig AXFR [DOMAIN] @[NS_IP]

# [Attacker] ドメインを推測せず DNS 側に投げる（古い構成で稀に通る）
dig AXFR @[NS_IP]

# [Attacker] fierce — 全 NS に対して自動 AXFR 試行 + 失敗時に辞書サブドメイン bruteforce
fierce --domain [DOMAIN] --dns-servers [NS_IP]

# [Attacker] dnsrecon — AXFR 自動化（推奨）
dnsrecon -d [DOMAIN] -t axfr
dnsrecon -d [DOMAIN] -t axfr -n [NS_IP]

# [Attacker] host コマンドでも可（環境によっては dig より見やすい）
host -l [DOMAIN] [NS_IP]

# [Attacker] 全 NS に対して順次試行（複数 NS のうち 1 つだけ設定漏れがある典型ケース）
for ns in $(dig NS [DOMAIN] +short); do
  echo "=== $ns ==="
  dig AXFR [DOMAIN] @"$ns" | head -50
done
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `Transfer failed.` / `; Transfer failed.` | 通常状態（AXFR 拒否）| 他の NS でも試行。全 NS 失敗なら §5 サブドメイン bruteforce へ |
| `;; communications error to ...` | NS との TCP/53 接続失敗（FW or unreachable）| 別 NS / 別経路（VPN・到達可能インターフェース）から試行 |
| 全 DNS レコードが返る（数十〜数千行）| **AXFR 設定漏れ確定** | 全ホスト名・IP リスト化、`grep -E 'A\|AAAA\|CNAME\|MX\|TXT'` で抽出、内部サブドメイン優先調査 |
| 一部レコードのみ返る（partial AXFR）| 古い BIND の挙動。設定漏れの中途半端な状態 | 取れた範囲で活用、別 NS 再試行 |
| `NOTAUTH` / `REFUSED` rcode | NS が権威でない or 拒否 | 別 NS を試す |
| IXFR (Incremental) のみ通る | 差分転送のみ許可、全体は拒否 | `dig IXFR=0 [DOMAIN] @[NS]` で初回フル取得を試す（実装依存）|

**成功時の悪用方向:**

- 全 A / AAAA レコードを抽出 → スキャン対象 IP リストの母集合確定
- 内部サブドメイン（`internal.*` / `staging.*` / `dev.*` / `vpn.*` / `mail.*` / `*-test.*`）を優先 → 設定が緩い可能性
- HINFO / TXT レコード内に内部情報・バージョン情報の漏洩がないか grep
- 取得した内部 IP レンジが RFC 1918 私設アドレス空間（`10.0.0.0/8` / `172.16.0.0/12` / `192.168.0.0/16`）なら内部 DNS が外部に晒されている = **重大 finding**（※ ドキュメント例示用の `192.0.2.0/24` (TEST-NET-1, RFC 5737) と混同しない）

> **注意:** AXFR の試行は受動的だが、NS のアクセスログに `xfer-out` 記録が残る。本番で大量繰り返しは避ける。**情報漏洩 finding として 1 回成功すれば十分**で、複数 NS への試行も 1-2 回に絞る。

---

## 5. サブドメイン列挙（ブルートフォース）

**コマンド:**

```bash
# [Attacker] gobuster でサブドメインを総当たり
gobuster dns -d [DOMAIN] -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50

# [Attacker] ffuf（gobuster が使えない環境の代替）
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://[DOMAIN] -H "Host: FUZZ.[DOMAIN]" -fs [EXCLUDE_SIZE]

# [Attacker] dnsenum / dnsrecon でも同等
dnsenum --dnsserver [DNS_IP] --enum -p 0 -s 0 -o subdomains.txt -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt [DOMAIN]
dnsrecon -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -d [DOMAIN] -n [DNS_IP]

# [Attacker] dnscan（再帰サブドメイン bruteforce・https://github.com/rbsec/dnscan）
dnscan -d [DOMAIN] -r -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# [Attacker] IPv6 サブドメイン bruteforce
dnsdict6 -s -t [DOMAIN]

# [Attacker] パッシブ列挙ファーストチョイス — subfinder（高速・低ノイズ・複数ソース統合）
# https://github.com/projectdiscovery/subfinder
subfinder -d [DOMAIN] -all -silent -o subdomains_passive.txt

# [Attacker] 証明書透明性ログを直接叩く（subfinder のソースに含まれるが、結果検証用に単独実行も有用）
# https://crt.sh/?q=%25.[DOMAIN]&output=json
curl -s "https://crt.sh/?q=%25.[DOMAIN]&output=json" | jq -r '.[].name_value' | sort -u

# [Attacker] amass（パッシブ + アクティブ統合・より時間がかかる）
amass enum -d [DOMAIN]
```

> **パッシブ列挙の順序:** **`subfinder` を最初に回す**のが現在の定石（複数のパッシブソース＝crt.sh / VirusTotal / SecurityTrails / Shodan 等を内部で統合し、API キー無しでもデフォルトソースで成果が出る）。`amass` は時間がかかる分カバレッジが広く、subfinder で取り切れない場合の二段目。`crt.sh` 直叩きは結果の検証・特定ドメインの履歴確認用。

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `Found: dev.[DOMAIN]` / `staging.*` / `internal.*` / `test.*` | **本番より設定が緩い可能性が高い** | 優先して調査。`Web_Enumeration.md` / 認証スプレー等を本番より先に試す |
| `Found: vpn.*` / `remote.*` / `sslvpn.*` | VPN アプライアンス | `../02_Initial_Access/Edge_Appliance_CVEs.md` の既知 CVE 照合 |
| `Found: owa.*` / `mail.*` / `autodiscover.*` | オンプレ Exchange の可能性 | `../02_Initial_Access/Mail_Services.md` §8 Exchange CVE |
| `Found: api.*` / `dev-api.*` | API エンドポイント | `Web_Enumeration.md` / Swagger / OpenAPI 仕様の露出確認 |
| 解決結果が 0 件 | ワードリストとの不一致 | 大きいワードリスト（`subdomains-top1million-20000.txt`）/ パッシブ手法（crt.sh / amass）/ §11 NSEC walking 検討 |
| 大量に解決できる（数百以上） | ワイルドカード DNS（`*.[DOMAIN]` が全部解決） | gobuster の `--wildcard` フラグ排除 / 解決 IP が全部同じならワイルドカード判定 |

**注意:** **大量サブドメイン bruteforce はノイズが大きく検知される**。本番では SecLists の `subdomains-top1million-5000.txt` 程度に絞り、初動で必要分のみ。後で深掘りが必要になったら追加実行する。**パッシブ手法（crt.sh / amass passive モード）は痕跡なし**で先に試すのが筋。

---

## 6. /etc/hosts への登録

**コマンド:**

```bash
# [Attacker] 取得した IP を /etc/hosts に登録（テスト識別子マーカー付き）
echo "[TARGET_IP]  [DOMAIN] [HOSTNAME]  # kedalab-[CASE_ID]" | sudo tee -a /etc/hosts

# 例
echo "192.0.2.100  target.example.com target  # kedalab-[CASE_ID]" | sudo tee -a /etc/hosts

# [Attacker] 動作確認
dig [DOMAIN] +short        # DNS 経由（変わらず）
ping -c 1 [DOMAIN]         # hosts 優先で解決される
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `ping` が hosts 登録した IP に向かう | 登録成功 | Kerberos / LDAP / TLS の名前ベース認証が通る |
| hosts に書いたのに DNS 経由 IP に向かう | `/etc/nsswitch.conf` の `hosts:` 行で `files` が `dns` より後 | nsswitch.conf を確認して `files dns` の順に修正 |
| Kerberos `KRB_AP_ERR_MODIFIED` | IP 直打ちで SPN 解決不可 | hosts 登録 + FQDN 接続に切替（`../02_Initial_Access/Impacket_Exec.md` §9）|

**原状回復（必須）:**

```bash
# [Attacker] テスト識別子マーカーで一括削除
sudo sed -i.bak '/# kedalab-\[CASE_ID\]/d' /etc/hosts

# [Attacker] 削除確認
grep -E "kedalab-\[CASE_ID\]|[TARGET_IP]" /etc/hosts
```

**注意:** `/etc/hosts` への登録は **複数テストをまたいで作業する場合に混在する**リスクがある。**テスト識別子コメントマーカー方式**（`# kedalab-[CASE_ID]`）で識別可能にしておく。Kerberos・LDAP・TLS の認証は IP ではなくドメイン名を要求する場合があるため、登録しておかないと後工程でエラーが出る。

---

## 7. DNS バナー取得（version.bind / DNS サーバー製品特定）

DNS サーバーは HTTP のような明示的なバナーを持たないが、`version.bind` の CHAOS クラスクエリで BIND バージョンが返ることがある（多くは無効化されているが古い環境で残存）。

**コマンド:**

```bash
# [Attacker] BIND バージョン取得（CHAOS クラスの TXT）
dig version.bind CHAOS TXT @[DNS_IP]
dig version.server CHAOS TXT @[DNS_IP]   # 別名

# [Attacker] hostname.bind / authors.bind も試行
dig hostname.bind CHAOS TXT @[DNS_IP]
dig authors.bind CHAOS TXT @[DNS_IP]

# [Attacker] fpdns — DNS サーバー実装の fingerprint（BIND/PowerDNS/MS DNS/Unbound 識別）
# https://github.com/kirei/fpdns
fpdns [DNS_IP]

# [Attacker] nmap dns-nsid（RFC 5001 NSID 取得）
nmap -sU -p53 --script dns-nsid [DNS_IP]

# [Attacker] nmap で DNS 関連スクリプト一括
nmap -n --script "(default and *dns*) or fcrdns or dns-srv-enum or dns-random-txid or dns-random-srcport" [DNS_IP]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `version.bind. ... TXT "9.11.4-P2-RedHat-9.11.4-26.P2.el7_9.13"` | BIND バージョン漏洩 | searchsploit / CVE 照合（古い BIND は CVE 多数）|
| `version.bind. ... TXT "Microsoft DNS 6.1.7601 ..."` | Windows DNS（OS バージョン特定可能） | Windows Server 2008 R2 / 2012 等の古い OS なら別経路（SMB / RPC）も古い可能性 |
| `... TXT "PowerDNS Authoritative Server 4.x"` | PowerDNS 識別 | PowerDNS 固有の CVE 確認 |
| `REFUSED` / `version.bind. ... TXT "off"` / `"Erotica"` 等の偽装文字列 | バナー偽装または無効化 | バナーから OS 特定は諦め、別経路（SMB / 証明書）で OS 推定 |
| nmap NSID で 16 進文字列 | NSID 設定済み（管理者が識別子設定） | 単に運用情報、攻撃には直結しない |

> **注意:** バナー取得は **受動的だが、`CHAOS TXT` クエリは通常クエリと異なるため IDS で目立つ場合がある**。本番では 1 回で済ませる。

---

## 8. Active Directory SRV レコード列挙（外部から AD 推測）

ターゲットドメインが AD 環境かを判定する。`_ldap._tcp` / `_kerberos._tcp` 等の SRV レコードが返れば AD 確定。

**コマンド:**

```bash
# [Attacker] AD 関連 SRV レコード一括
dig SRV _ldap._tcp.[DOMAIN]
dig SRV _kerberos._tcp.[DOMAIN]
dig SRV _kpasswd._tcp.[DOMAIN]
dig SRV _gc._tcp.[DOMAIN]               # Global Catalog
dig SRV _ldap._tcp.dc._msdcs.[DOMAIN]   # Domain Controller の LDAP

# [Attacker] nmap で一括列挙
nmap --script dns-srv-enum --script-args "dns-srv-enum.domain='[DOMAIN]'"

# [Attacker] nslookup（dig が使えない環境）
nslookup -type=srv _kerberos._tcp.[DOMAIN]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `_ldap._tcp.[DOMAIN]. ... SRV 0 100 389 dc01.[DOMAIN].` | AD 確定 + DC ホスト名特定 | DC IP を `dig dc01.[DOMAIN]` で取得 → `/etc/hosts` 登録 → `RPC_Enumeration.md` / `LDAP_Enumeration.md` 起動 |
| `_kerberos._tcp.[DOMAIN]. ... SRV ... 88 ...` | Kerberos 露出（88/tcp 外部）| AS-REP / Username Enumeration（pre-auth エラー観察）の候補。本番では多くが内部のみ |
| 複数の DC が返る | AD マルチ DC 構成 | 各 DC を IP リスト化 → ロックアウト計測用に冗長性確認 |
| `_gc._tcp.[DOMAIN]` で応答 | Global Catalog（3268/tcp）露出 | LDAP の代替経路 |
| 全部空 | 非 AD or 内部のみ | 通常の Web / メール環境として扱う |

> **外部から AD SRV が見えること自体が finding**。本来は内部 DNS のみで提供すべきで、外部公開は設定不備。

---

## 9. 技術スタック特定（TXT / MX / サブドメイン / Third-Party SaaS 検出）

TXT / MX レコードと特徴的なサブドメインから、組織が使用しているクラウドサービス・SaaS・セキュリティ製品を特定する。社会工学（**業務メールに見せかけたフィッシング**）・特定サービスへの設定ミス確認の起点。

**コマンド:**

```bash
# [Attacker] TXT 全部取得（SPF / DKIM / 各種 verification トークン）
dig TXT [DOMAIN]
dig TXT _dmarc.[DOMAIN]                    # DMARC ポリシー
dig TXT default._domainkey.[DOMAIN]        # DKIM（セレクター名は組織依存・selector1 / google / k1 等も試行）

# [Attacker] MX レコード
dig MX [DOMAIN]

# [Attacker] dns-triage — 共通サブドメイン + 第三者サービス自動検出
# https://github.com/Wh1t3Rh1n0/dns-triage
git clone https://github.com/Wh1t3Rh1n0/dns-triage
cd dns-triage && pip3 install -r requirements.txt
python3 dns-triage.py [DOMAIN]
```

**TXT レコード解釈表（よく見るトークン）:**

| TXT 値の特徴 | 示唆されるサービス・製品 | 次のアクション |
|---|---|---|
| `v=spf1 include:_spf.google.com` | Google Workspace 利用 | Google アカウント前提の phishing 候補 |
| `v=spf1 include:spf.protection.outlook.com` | Microsoft 365 利用 | Azure AD / Entra ID 攻撃面（パスワードスプレー・Conditional Access bypass）|
| `v=spf1 include:_spf.pphosted.com` / `include:spf.mimecast.com` | ProofPoint / Mimecast | メールゲートウェイ bypass の既知手法確認 |
| `MS=ms[ALNUM]` | Microsoft 365 ドメイン検証 | Microsoft テナント確定 |
| `google-site-verification=` | Google Workspace ドメイン検証 | 同上（Google）|
| `atlassian-domain-verification=` | Atlassian（Confluence / Jira）利用 | Confluence / Jira の既知 CVE 確認 |
| `docusign=` | DocuSign 利用 | DocuSign 経由の社内文書詐取シナリオ |
| `adobe-idp-site-verification=` | Adobe IDP 連携 | Adobe SSO 経路の確認 |
| `_dmarc` ポリシーが `p=none` | DMARC reject / quarantine 未設定 | **重大 finding** — メールスプーフィング可能 |
| DKIM セレクターが存在しない | DKIM 未設定 | 同上（メールスプーフィング容易）|

**MX レコード解釈表:**

| MX ホスト名のパターン | 示唆 | 次のアクション |
|---|---|---|
| `*.mail.protection.outlook.com` | Microsoft 365 / Exchange Online | M365 攻撃面確認 |
| `*.google.com` / `*-smtp-in.l.google.com` | Google Workspace | 同上 |
| `*.pphosted.com` / `*.ppe-hosted.com` | ProofPoint | ProofPoint bypass 手法確認 |
| `*.mimecast.com` | Mimecast | 同上 |
| 自社ホスト名（`mail.[DOMAIN]` 等） | オンプレ Exchange / Postfix 可能性 | バナー取得 → ProxyLogon / ProxyShell / Exim CVE 確認 → [`../02_Initial_Access/Mail_Services.md`](../02_Initial_Access/Mail_Services.md) |

**サブドメイン名から推定される技術:**

| サブドメイン | 示唆されるサービス・インフラ |
|---|---|
| `securemail.` / `encrypt.` | 暗号化メールポータル（独自 phishing 経路として悪用可能）|
| `vpn.` / `remote.` / `sslvpn.` | VPN アプライアンス（Citrix / Fortinet / Ivanti / PAN-OS 等）→ [`../02_Initial_Access/Edge_Appliance_CVEs.md`](../02_Initial_Access/Edge_Appliance_CVEs.md) |
| `owa.` / `mail.` / `autodiscover.` | Exchange On-Premises（ProxyLogon / ProxyShell 候補）|
| `jamf.` / `*.jamfcloud.com` | Jamf MDM = Apple 端末が組織内に存在 |
| `*.servicenow.com` | ServiceNow（ITSM）|
| `*.atlassian.net` | Atlassian Cloud（Confluence / Jira）|
| `vpc.` / `*.amazonaws.com` 内部 | AWS 利用、AWS 攻撃面 |
| `*.azurewebsites.net` 内部 | Azure App Service 利用 |
| `git.` / `gitlab.` / `code.` | 自社 Git ホスティング、ソース漏洩経路 |

> **dns-triage ツール:** TXT / MX / 共通サブドメイン / 第三者サービスへの DNS 照会を自動化し、Microsoft Exchange Smart Host 検出・ProofPoint 検出等を一括出力する。BHIS 公開ツールで Python 製。本番でも軽量で実行可能。

> **社会工学への接続:** TXT / MX から判明したサービスを材料に、業務メール風 phishing の精度を上げられる（例: ProofPoint 検出 → ProofPoint からの quarantine 通知を装う）。具体的な phishing 手順は本ファイル範囲外 → [`../02_Initial_Access/Social_Engineering.md`](../02_Initial_Access/Social_Engineering.md)

---

## 10. Subdomain Takeover 検出

CNAME が指しているサードパーティサービス（GitHub Pages / Heroku / S3 / Azure / Cloudflare 等）が **未設定または廃止**されている場合、攻撃者が同名リソースを登録してサブドメイン乗っ取りができる。

**コマンド:**

```bash
# [Attacker] CNAME 一括確認（§5 で発見したサブドメイン全てに対して）
for sub in $(cat subdomains.txt); do
  dig CNAME "$sub" +short
done

# [Attacker] nuclei takeovers テンプレート — 現在の業界標準（テンプレートが頻繁に更新される）
# https://github.com/projectdiscovery/nuclei-templates
nuclei -l subdomains.txt -t http/takeovers/ -severity high,critical -o takeover_findings.txt

# [Attacker] subzy — fingerprint DB をメンテし続けている専用ツール（nuclei の補完）
# https://github.com/PentestPad/subzy
subzy run --targets subdomains.txt

# [Attacker] subjack — 古くからある定番だが現在メンテほぼ停止。誤検知・検知漏れ多
# https://github.com/haccer/subjack
subjack -w subdomains.txt -t 100 -timeout 30 -ssl -c fingerprints.json -v

# [Attacker] 手動確認 — CNAME 先に HTTP 接続して特定エラー文を観察
curl -sI https://[SUBDOMAIN]/
```

> **ツール選択:** **`nuclei -t http/takeovers/` を一次手段にする**（テンプレートが日次で追加・修正される）。`subzy` で fingerprint 多様性を補完。`subjack` はメンテ停止状態で誤検知・検知漏れが目立つため参考扱い。最終確認は必ず手動 `curl` で当該エラー文を観察してから finding 化する。

**観測される出力 → 次のアクション:**

| CNAME 先 | サードパーティ | takeover 可否判定 |
|---|---|---|
| `*.github.io` | GitHub Pages | HTTP 接続で `There isn't a GitHub Pages site here.` → GitHub アカウントで同名 repo 作成可能なら takeover 成立 |
| `*.herokuapp.com` | Heroku | `No such app` → Heroku で同名アプリ作成可能なら takeover |
| `*.s3.amazonaws.com` / `*.s3-website-*.amazonaws.com` | AWS S3 | `NoSuchBucket` → 同名 bucket を作成可能なら takeover（既知の濫用パターン）|
| `*.azurewebsites.net` / `*.cloudapp.net` | Azure | `404 Web Site Not Found` 等 → Azure で同名リソース作成可能なら takeover |
| `*.cloudfront.net` | CloudFront | CloudFront distribution が削除されていれば takeover 可能性 |
| `*.bitbucket.io` / `*.gitbook.io` | Bitbucket / GitBook | 同様の判定パターン |

> **重要:** **takeover の検証は finding 確認のみで止める**（本番では実際に外部リソースを取得しない）。攻撃成立の証跡として「該当エラー文の確認 + サードパーティで同名取得が可能であること」までを finding とする。**実際に乗っ取りを実行すると組織への影響が大きい**（合意外）。

> **対象組織との合意が必要:** subdomain takeover は **報告書 finding 化までが本番スコープ**、PoC 取得は事前合意必須。Bug Bounty プログラムでは PoC 取得が許可される場合あり。

---

## 11. DNSSEC NSEC walking（signed zone のレコード列挙）

DNSSEC で署名されたゾーンは NSEC レコードで「次に存在するレコード名」を返すため、これを辿ると **ゾーン内の全レコード名を網羅列挙できる**（NSEC3 は同様だがハッシュ化されている）。

**コマンド:**

```bash
# [Attacker] DNSKEY 確認（DNSSEC 有効性判定）
dig DNSKEY [DOMAIN] +dnssec
dig DS [DOMAIN] +short

# [Attacker] nmap で NSEC walking
nmap -sSU -p53 --script dns-nsec-enum --script-args dns-nsec-enum.domains=[DOMAIN] [NS_IP]

# [Attacker] NSEC3 の場合（ハッシュ化されているが辞書 bruteforce 可）
nmap -sSU -p53 --script dns-nsec3-enum --script-args dns-nsec3-enum.domains=[DOMAIN] [NS_IP]

# [Attacker] dnsrecon でも NSEC walking 可
dnsrecon -d [DOMAIN] -t zonewalk

# [Attacker] ldns-walk（NSEC zone walking 専用）
ldns-walk [DOMAIN] @[NS_IP]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| NSEC レコードのチェーンが順に取得できる | NSEC walking 成立 → ゾーン全レコード列挙完了 | §5 サブドメイン bruteforce を省略可能、全ホスト IP リスト化 |
| NSEC3 のハッシュチェーンのみ | ハッシュ化された名前空間 | ldns-walk / john-the-ripper 系の dictionary attack でハッシュ → 名前復元（成功率は辞書次第）|
| `NSEC` レコードなし | 非 DNSSEC ゾーン or NSEC3 opt-out | NSEC walking 適用外、§5 サブドメイン bruteforce へ |

> **NSEC walking は AXFR より静か**（通常クエリのチェーン）で IDS シグネチャに引っかかりにくい。ただし大量クエリは異常検知される場合あり。

---

## 12. Cache Snooping（DNS キャッシュからの解決履歴漏洩）

再帰問い合わせを許可している DNS サーバーに対して **非再帰クエリ**（`+norecurse`）を投げると、キャッシュにある場合だけ応答が返る。これでターゲット組織の DNS サーバーが過去に解決した外部ドメインの履歴を推測できる。

**コマンド:**

```bash
# [Attacker] 非再帰クエリでキャッシュ照会
dig [QUERY_DOMAIN] @[TARGET_DNS_IP] +norecurse

# [Attacker] 例：競合他社・特定サービスへの接続有無を確認
dig [QUERY_DOMAIN] @[TARGET_DNS_IP] +norecurse
dig [QUERY_DOMAIN] @[TARGET_DNS_IP] +norecurse
dig [QUERY_DOMAIN] @[TARGET_DNS_IP] +norecurse

# [Attacker] 応答時間も観察（キャッシュヒット = 即応・キャッシュミス = 遅延）
dig [DOMAIN] @[TARGET_DNS_IP] +norecurse +stats | grep "Query time"
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `ANSWER SECTION` にレコードが返る + `flags:` に `aa` 無し | キャッシュヒット = 過去に組織内で解決された（非権威・既キャッシュ応答） | 組織が利用しているサービスの推測材料 |
| `ANSWER SECTION` 空 + `AUTHORITY SECTION` のみ | キャッシュミス = 解決履歴なし | 別ドメインを試行 |
| `REFUSED` rcode | 非再帰クエリも拒否（適切な設定）| Cache Snooping 不可、次の手法へ |
| `Query time: 0 msec` | キャッシュヒット（応答時間ベース判定） | 同上、組織利用サービスの推測材料 |
| `Query time: 100+ msec` | キャッシュミス（外部問い合わせ発生）| 同上、未利用と推定 |

> **flags の読み方（誤読しやすい）:** dig 応答の `flags: qr rd ra` は **クエリの結果ではなくサーバー側の能力**を示す。`rd` は **リクエスト側のビットがエコーされて返ってくる**だけで、`+norecurse` を投げたかどうかとは独立。`ra` は **サーバーが再帰を許可しているか**であって、このクエリで再帰が起きたかではない。**Cache snooping の判定は `aa` 無し + ANSWER に値が入っているか**（非権威応答=キャッシュ済み）と Query time で行う。`+norecurse` を使う意義は「キャッシュ外を再帰解決させてしまう副作用を防ぐ」点にあり、応答の flags 解釈とは別軸。

> **使い道:** 業務利用サービスの推測（社会工学・ピンポイント攻撃の前提条件作り）。本番では低優先度の finding だが、競合分析・社内サービス推定の補助になる。

> **注意:** 大量クエリは異常検知される。1 セッションで 10-20 ドメイン程度に絞る。

---

## 13. DDNS Update（書込攻撃）

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須:
> - [x] 業務停止リスク（誤レコード書込で名前解決が止まる・メール配送が止まる）
> - [x] 不可逆な設定変更を含む（DNS レコード作成）
> - [x] SIEM / EDR で確実に検知される（DDNS update ログ・named.log の `update_signed` 系）
> - [ ] 持続化に該当
>
> 実施可否は事前合意で明示確認すること。**演習環境以外では「書込試行は行わず、ACL 不備を確認するまでが limit」とする運用が安全**。

Dynamic DNS（RFC 2136）の `UPDATE` メッセージは、ACL 不備で外部から DNS レコードを書き換えられる場合がある。AD 統合 DNS（Windows DNS）/ BIND の `allow-update { any; };` 設定漏れが典型。

**コマンド:**

```bash
# [Attacker] nsupdate で書込試行（実際の書込は行わず、ACL 反応だけ観察）
nsupdate -d
> server [TARGET_DNS_IP]
> zone [DOMAIN]
> update add test-[CASE_ID].[DOMAIN] 60 A 192.0.2.50
> send

# [Attacker] スクリプト経由
cat <<EOF | nsupdate -d
server [TARGET_DNS_IP]
zone [DOMAIN]
update add test-[CASE_ID].[DOMAIN] 60 A 192.0.2.50
send
EOF

# [Attacker] dnsrecon で DDNS テスト
dnsrecon -d [DOMAIN] -n [DNS_IP] -t std --update
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `; TSIG error with server: tsig indicates error` | TSIG（共有鍵認証）が要求されている | 認証なしの DDNS は不可、別経路へ |
| `update failed: REFUSED` | ACL で拒否（正常設定） | 別ゾーン・別 NS を試す |
| `update failed: NOTAUTH` | 当該 NS は権威でない | 権威 NS を再特定 |
| `; Sent ... bytes, ... received` + 即時 `dig test-[CASE_ID].[DOMAIN]` で書込レコードが返る | **DDNS update 成立（ACL 不備確定・重大 finding）** | **即停止 → 報告書 finding 化** + 原状回復（書込レコード削除） |
| Windows AD 統合 DNS で SecureUpdate のみ要求 | Kerberos 認証付き update のみ許可（既定） | AD 認証情報があれば書込可能 |

**事前準備（必須）:**

```bash
# [Attacker] nsupdate に渡す TSIG キーがあれば指定
nsupdate -k [keyfile]
# AD 統合 DNS で Kerberos 認証する場合は事前に kinit
kinit [USER]@[DOMAIN.UPPER]
nsupdate -g
```

**原状回復（必須）:**

```bash
# [Attacker] 書込んだレコードを必ず削除
cat <<EOF | nsupdate
server [TARGET_DNS_IP]
zone [DOMAIN]
update delete test-[CASE_ID].[DOMAIN] A
send
EOF
```

> **テスト識別子コメントマーカー方式**: 書込むレコード名は `test-[CASE_ID]` 接頭辞で識別可能にしておく。原状回復時に grep で確実に削除。

---

## 14. DNS Rebinding（同一オリジンポリシー迂回）

被害者のブラウザ等に対して、**短時間に異なる IP に解決変化させる** ことで、Same Origin Policy（SOP）を迂回して内部ネットワークの HTTP サービスにアクセスする攻撃。**本ファイルは検出と概念のみ**。実 exploit は Web アプリ攻撃側で扱う（[`../02_Initial_Access/Web_Vulnerabilities/SSRF.md`](../02_Initial_Access/Web_Vulnerabilities/SSRF.md) に rebinding 経由の SSRF 経路がある場合は参照）。

**攻撃の概要:**

1. 攻撃者が支配するドメイン（例: `rebind.attacker.test`）に **極めて短い TTL（1-3 秒）** を設定
2. 初回解決: 攻撃者サーバー IP（例: `203.0.113.50`）を返す → 被害者ブラウザがこのドメインから JS をロード
3. 数秒後: 同じドメインの解決を **被害者の内部 IP（例: `192.0.2.10`）** に切替
4. ブラウザは SOP 上は同一ドメインと判断 → 内部 IP に対して fetch / XHR 実行可能

**検出 / 確認:**

**コマンド:**

```bash
# [Attacker] 自分の管理 DNS で短 TTL + 動的回答の構成が可能か検証
dig rebind.attacker.test
sleep 5
dig rebind.attacker.test
# → 同じドメインで応答 IP が変わっていれば rebinding 構成成立

# [Attacker] 既存の rebinding サービスを利用した PoC（自前構築不要）
# https://lock.cmpxchg8b.com/rebinder.html
# https://rbndr.us/
```

**ターゲット側で確認すること（本番での finding 化条件）:**

- 内部 Web アプリが **`Host:` ヘッダー検証なし**で応答するか
- WebSocket / fetch / XHR が DNS rebinding 後の内部 IP に対してそのまま接続するか
- **緩和策の確認**: ブラウザの `Private Network Access` ポリシー / 内部 Web アプリの `Host:` 検証 / DNS リゾルバの RFC 1918 アドレスフィルタリング（`rebind-protect` 等）

> **使い道:** SSRF と組み合わせた内部リソース到達経路。クラウドメタデータ（`169.254.169.254`）への到達経路としても有名。

> **本番での扱い:** 概念検証は外部の rebinder サービスでデモ可能だが、**被害者の実ブラウザを使った PoC は明確に attack** で本番では合意必須。kedalab DNS ファイル範囲は「rebinding の構成が成立しうるかの DNS 側検証」まで。

---

## 15. Recursion 開放確認（DDoS amplification 悪用懸念の finding）

外部公開 DNS サーバーで再帰問い合わせが開放されていると、第三者攻撃の踏み台（amplification reflection）に悪用される懸念がある。**finding 化が主目的・実際の DDoS は kedalab スコープ外（本番禁止）**。

**コマンド:**

```bash
# [Attacker] 外部ドメインを問い合わせて recursion 可否確認
dig google.com A @[TARGET_DNS_IP]
# 応答の flags: に `ra` (recursion available) が含まれていれば recursion 開放

# [Attacker] 応答全体
dig google.com A @[TARGET_DNS_IP] +stats
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `flags: qr rd ra` (`ra` あり) + 正常応答 | **再帰開放確認・finding** | 報告書化（DDoS amplification 踏み台懸念）|
| `flags: qr rd` (`ra` なし) | 再帰閉鎖（正常設定）| finding なし |
| `REFUSED` rcode | 外部からの問い合わせ拒否（正常設定）| 同上 |

**増幅率の参考確認（実行禁止・finding 表現のための知識として）:**

- `dig ANY` / DNSSEC レコードはレスポンスサイズが極端に大きい → amplification factor 高
- **これらを攻撃の踏み台として実証する PoC は明確に DoS で本番禁止**。あくまで「再帰が `ra` フラグで開放されている事実」までを finding として記述する

> **公開 resolver と権威 DNS の区別:** ターゲットが**権威 DNS**（自社ドメインのレコードを提供）なら recursion は不要（閉鎖が正常）。**公開 resolver**（ISP / 8.8.8.8 等）なら recursion は仕様。設定意図と照合してから finding 判定する。

---

## 16. Mail to nonexistent account（NDN bounce で内部漏洩）

存在しないアドレス宛のメールを組織ドメインに送ると、NDN（Non-Delivery Notification）が返ってくる。**NDN ヘッダー内に内部メールサーバー名・IP・経由ホップが書かれていることがある**。

**コマンド:**

```bash
# [Attacker] 存在しないアドレスにテスト送信（SMTP 直接でも MUA でも可）
swaks --to nonexistent-[CASE_ID]@[DOMAIN] --from test@[ATTACKER_DOMAIN] \
      --server [TARGET_MX_HOST] --header "Subject: kedalab-[CASE_ID]"

# [Attacker] 返ってきた NDN のヘッダーを Received: 行で確認
# → 内部ホスト名 / 内部 IP / バージョン情報の漏洩を確認
```

**NDN ヘッダーで観察するポイント:**

| ヘッダー | 示唆 |
|---|---|
| `Received: from [INTERNAL_HOSTNAME] ([INTERNAL_IP]) by ...` | 内部メールリレー構成・RFC 1918 IP が露出する場合あり |
| `X-Original-Sender:` / `X-Originating-IP:` | 受信側内部 IP |
| `X-Mailer:` / `Server:` | メールサーバー製品・バージョン |
| `User-Agent:` | NDN を生成した MTA の特定（Exchange / Postfix / Exim） |

> **本番での扱い:** NDN bounce は受動的取得で finding として軽い。**ターゲットの spam フィルタが捨てる場合あり**、不達は不達として記録するに留める。

---

## 刺さらなかったとき

- 外部 DNS で名前解決できない → テスト経路（環境による）から内部 DNS を `@[TARGET_IP]` で直接指定する
- ゾーン転送が `Transfer failed` → 正常。AXFR は無効化されているのが一般的。§11 NSEC walking / §5 サブドメイン bruteforce へ
- サブドメイン列挙の結果が 0 件 → ワードリストを変える（`subdomains-top1million-20000.txt` 等の大きめのリストに切り替え）/ §11 NSEC walking で署名ゾーン全体を辿る
- nslookup で IP が返るが nmap が通らない → ファイアウォールがある可能性。`-Pn` で ping スキップして強制スキャン
- DNSSEC NSEC walking で NSEC レコードが返らない → NSEC3 opt-out / DNSSEC 未署名。dictionary bruteforce に戻る
- DDNS update が `REFUSED` で全部失敗 → 正常な ACL 設定。finding なし
- Cache snooping で全部 `REFUSED` → 非再帰問い合わせも拒否されている（適切な設定）
- IPv6 経路を見落とした疑い → `dig AAAA [DOMAIN]` / `dnsdict6 -s -t [DOMAIN]` で IPv6 サブドメイン列挙

## 注意点・落とし穴

- `dig ANY` は DNS サーバーの実装によって返さない場合がある。レコード種別を個別に指定して確認する
- /etc/hosts への登録は複数テストをまたいで作業する場合に混在するリスクがある。作業前後にファイルの内容を確認する
- **個別ブロック固有の注意は各 § 内の「注意:」を参照**。本セクションは複数ブロックを横断する話のみ
- **DNS Tunneling / C2（iodine / dnscat2）は本ファイル対象外** — post-exploitation の通信経路で、外部からの偵察では使わない。侵入後の C2 設計は別途扱う
- **DNS Cache Poisoning（Kaminsky 型）は本ファイル対象外** — 現代では Source Port Randomization + DNSSEC でほぼ封じ込め、本番ペネトレでの実用度は低い。古い resolver 検出までが limit
- **DNS amplification / reflection DDoS は kedalab スコープ外**（本番禁止）。§15 Recursion 開放確認は「再帰が開放されている事実」の finding 化までで止める
- **侵入後の Bind 設定ファイル調査**: Linux ホストに入った後、`/etc/bind/named.conf*` / `/etc/resolv.conf` / `/etc/host.conf` の確認は post-access 側で扱う（[`../03_Post_Access_Linux/Enumeration_Checklist.md`](../03_Post_Access_Linux/Enumeration_Checklist.md)）

### 本番での前提

- **事前合意の要否**: ★★（口頭確認可 — §1-§12 §15 §16 の受動的列挙）/ ★★★（書面承認必須 — §13 DDNS update / §14 DNS Rebinding PoC / §10 Subdomain Takeover の PoC 取得）
- **想定される SIEM / EDR 検知**:
  - 大量サブドメイン bruteforce → DNS クエリレート異常
  - AXFR 試行 → BIND `xfer-out` ログ / Windows DNS Event ID 6004
  - NSEC walking → 連続クエリパターン
  - DDNS update → `update_signed` / Windows DNS Event ID 4129
  - Cache snooping → `+norecurse` クエリの異常パターン
- **業務影響リスク**:
  - §13 DDNS update 書込試行で誤レコード → **メール配送停止 / 名前解決停止**
  - §10 Subdomain Takeover の PoC 取得後の放置 → 永続的乗っ取り状態が残る（必ず合意の範囲内で原状回復）
  - その他は受動的列挙のため通常リスクなし
- **原状回復必須項目**:
  - ✅ `/etc/hosts` に登録した行の削除
  - ✅ §13 DDNS で書込んだレコードの削除（`update delete` + dig で消失確認）
  - ✅ §10 Subdomain Takeover の PoC で取得したサードパーティリソースの解放
  - ✅ §16 NDN bounce で送信したテスト用メールアドレスの記録破棄
- **取得情報の取扱**: 列挙結果（サブドメイン一覧・内部 IP・TXT 漏洩）は機密として暗号化保管 / テスト完了時破棄 / 対象組織への返却
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

## 関連技術
- 前：テスト開始（ドメイン渡し）
- 前：到達可能 NS / DNS サーバーの発見 → `Network_Scanning.md`（53/tcp・53/udp）
- 関連：TLS 証明書経由のサブドメイン発見（CT logs / crt.sh）→ `TLS_Audit.md`
- 関連：§9 で見つけた技術スタック（M365 / ProofPoint / Atlassian 等）への直接攻撃 → 該当する CVE / bypass 経路
- 後：IP 特定後の OS 判定・ポートスキャン → `Network_Scanning.md`
- 後：vhost・サブドメインの詳細列挙 → `Web_Enumeration.md`
- 後：§8 で AD 確定 → AD 内部偵察（RPC / LDAP / Kerberos）→ `RPC_Enumeration.md` / `LDAP_Enumeration.md`
- 後：§9 で M365 / Exchange 検出 → メールサーバー攻撃 → `../02_Initial_Access/Mail_Services.md`
- 後：§9 で VPN / エッジアプライアンス検出 → 既知 CVE 照合 → `../02_Initial_Access/Edge_Appliance_CVEs.md`
- 後：§10 Subdomain Takeover で取得した CNAME 先に Web 経路がある場合の XSS 化 → `../02_Initial_Access/Web_Vulnerabilities/XSS.md`
- 後：§10 Subdomain Takeover を起点とした OAuth / SSO リダイレクト悪用 → `../02_Initial_Access/Web_Vulnerabilities/OAuth_Attacks.md` / `../02_Initial_Access/Web_Vulnerabilities/Open_Redirect.md`
- 後：§9 で判明したサービス・サブドメイン名を起点とした phishing → `../02_Initial_Access/Social_Engineering.md`
- 後：§14 DNS Rebinding 経由の SSRF / 内部 Web 攻撃 → `../02_Initial_Access/Web_Vulnerabilities/SSRF.md`
- 後：取得した認証情報 / 漏洩情報を使った辞書攻撃の事前ロック確認 → `../02_Initial_Access/Account_Lockout_Recon.md`
