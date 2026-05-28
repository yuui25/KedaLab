# TLS / SSL 設定の弱点確認

> **スコープ**: TLS ポートのプロトコル/暗号スイート列挙、証明書情報からの組織・製品・FQDN 推定、SNI/mTLS 判定、名前付き TLS 脆弱性（Heartbleed / POODLE / FREAK / Logjam / ROBOT / DROWN / Sweet32 / Ticketbleed）の該否判定、HSTS 等 TLS 関連セキュリティヘッダー確認まで。証明書 SAN から判明した追加 FQDN の vhost 列挙以降は `./Web_Enumeration.md`、Issuer から判明した製品の CVE 該否は `../02_Initial_Access/Edge_Appliance_CVEs.md` を参照。

## 着火条件

以下のいずれかに該当する場合:

- ポートスキャンで TLS を使うポートが開いている: `443` / `465` / `636` / `993` / `995` / `989` / `990` / `8443` / `3389`（RDP は TLS over TCP）/ 任意の `https-alt` ポート
- nmap の `ssl-cert` で証明書情報が引け、製品/組織のヒントを掘りたい
- 既知 TLS 名前付き脆弱性の該否を確認したい
- 監査要件として「古いプロトコル / 弱い暗号 / 証明書不一致」の検出が要求されている

## 環境前提

- 実行環境: テスター端末
- 必要なツール:
  - `nmap`（ペネトレ用 Linux ディストリ標準。`--script ssl-enum-ciphers` / `ssl-cert` / 個別 CVE スクリプトで簡易チェック）
  - `openssl s_client`（標準搭載。手動の 1 コマンド確認・証明書取得・プロトコル指定接続）
  - `sslscan`（高速一次チェック・単体バイナリ・古プロトコル対応。`apt install sslscan`）
  - `testssl.sh`（別途インストール要、bash + openssl 同梱バイナリで動く包括チェッカー。`git clone https://github.com/drwetter/testssl.sh` で取得。インターネット遮断 VLAN では事前にクローン済みのコピーを持ち込む。**ディストリ openssl が `-ssl3` 等を無効化していても testssl.sh 同梱の `bin/openssl.Linux.x86_64` で対応可能**）
  - `pyja3` / `tshark`（JA3 / JA3S フィンガープリント取得・任意）
  - `sslyze`（別途インストール要、`pip install --user sslyze`。JSON 出力で報告書化しやすい）
- オフライン代替: `testssl.sh` / `sslyze` が無い環境では `nmap --script ssl-enum-ciphers,ssl-cert,ssl-dh-params` + `openssl s_client` の組み合わせでカバーする

## 先に確認すること

- **対象が SNI を要求するか**: 同一 IP で複数 FQDN がホストされている可能性。SNI 無しでは別証明書が返る、または接続が切られる。`openssl s_client -servername [DOMAIN]` で明示
- **ロードバランサー / WAF / CDN の前段に居ないか**: CDN 配下の場合、観測される TLS 設定は CDN の設定であってオリジンの設定ではない
- **接続そのものが切られる挙動を見たら IPS / WAF のレート制限を疑い試行間隔を空ける**: testssl.sh の連続接続が発火源になりやすい
- **mTLS が要求されていないか**: クライアント証明書なしでは TLS 監査自体が成立しない。事前に確認する

**TLS 監査で見る軸（5 つ）:**

| 軸 | 何を見るか | 主なシグナル |
|----|----------|--------------|
| プロトコル | SSLv2 / SSLv3 / TLS1.0 / TLS1.1 / TLS1.2 / TLS1.3 のどれを受け入れるか | SSLv3 → POODLE 該当 / TLS1.0・1.1 → 監査要件で非推奨 / TLS1.3 のみ → 比較的健全 |
| 暗号スイート | RC4 / DES / 3DES / EXPORT / NULL / 匿名 DH / 弱い鍵長 | RC4 残存 → BAR Mitigations 該当 / EXPORT → FREAK・Logjam の足掛かり / 3DES → Sweet32 |
| 証明書 | CN / SAN / 発行者 / 有効期限 / 鍵長 / 署名アルゴリズム / 自己署名か | CN と接続 FQDN の不一致 / 期限切れ / SHA-1 署名 / 1024bit RSA / 内部 CA（社内 PKI の組織名が漏れる）|
| 既知 TLS 名前付き脆弱性 | Heartbleed / POODLE / CRIME / FREAK / Logjam / ROBOT / DROWN / Sweet32 / Ticketbleed | nmap 個別スクリプトまたは testssl.sh の Vulnerabilities セクションで一括判定 |
| HTTP セキュリティヘッダー（TLS 関連） | HSTS / HPKP（廃止だが残存）/ Upgrade-Insecure-Requests | HSTS なし → ダウングレード可、`includeSubDomains` / `preload` 有無も見る |

**攻撃者の思考トレース:** TLS 監査は「弱い暗号で接続を確立してからその先で何かする」攻撃というより、**証明書の中身を製品・組織推定の入口に使う**用途と、**監査基準（PCI DSS・FedRAMP・社内ポリシー）違反の検出**用途が中心。Heartbleed のような直接情報漏洩につながる古典脆弱性は今や稀だが、見つかれば即報告対象。最初は nmap で軽く当てて、必要なら testssl.sh で網羅し、報告化が要れば sslyze で JSON、深掘りは openssl s_client で手動、という順で重さを上げていく。

---

## 1. nmap での簡易確認（最初の一手）

**コマンド:**

```bash
# [Attacker] 暗号スイート + プロトコル一覧
nmap --script ssl-enum-ciphers -p 443 [TARGET]

# [Attacker] 証明書情報（CN / SAN / 発行者 / 有効期限）
nmap --script ssl-cert -p 443 [TARGET]

# [Attacker] DH パラメータ（Logjam 観点）
nmap --script ssl-dh-params -p 443 [TARGET]

# [Attacker] 個別 CVE スクリプト
nmap --script ssl-heartbleed -p 443 [TARGET]
nmap --script ssl-poodle -p 443 [TARGET]
nmap --script ssl-ccs-injection -p 443 [TARGET]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `ssl-enum-ciphers` に `TLSv1.0:` / `TLSv1.1:` セクションが存在 | TLS 1.0/1.1 受け入れ（監査要件で非推奨） | 報告対象。プロトコル別の最弱スイートも記録 |
| `ssl-enum-ciphers` に `SSLv3:` セクションが存在 | POODLE（CVE-2014-3566）該当 | 報告対象。§2 testssl.sh の Vulnerabilities で再確認 |
| スイート名に `RC4` | RC4 残存（BAR Mitigations 該当） | 報告対象 |
| スイート名に `3DES` / `DES-CBC3` | Sweet32（CVE-2016-2183）該当 | 報告対象 |
| スイート名に `EXPORT` | 輸出グレード暗号。FREAK / Logjam の足掛かり | §2 testssl.sh で FREAK / Logjam の該否を確認 |
| `least strength: C` 以下の総合判定 | 弱いスイートが残存 | 個別スイートを抽出して列挙 |
| `ssl-cert` に CN / SAN / Issuer が引けた | 組織・製品推定の手掛かり | §5 証明書読解へ |
| `ssl-dh-params` で `Diffie-Hellman Modulus Size: 1024` 以下 | Logjam（CVE-2015-4000）該当の可能性 | 報告対象 |
| `ssl-heartbleed` で `VULNERABLE` | OpenSSL < 1.0.1g | §下記注意（メモリダンプ繰り返し禁止）に従い 1 回確認のみ |

**注意:** `ssl-enum-ciphers` は対象のサーバ実装によっては偽の `least strength` を出すことがある。個別スイートの一覧と必ず照合する。

---

## 1.5. sslscan による高速一次チェック（軽量代替）

testssl.sh は包括的だが依存関係が多く実行速度も重い。**sslscan は単体バイナリ + 内蔵 OpenSSL で動き、古いプロトコル（SSLv2 / SSLv3 / TLS1.0 / TLS1.1）にデフォルト対応**しているため、初動の一次チェックに向く。CI / 大量ホストの一括スキャン・コンテナ内偵察にも適する。

**コマンド:**

```bash
# [Attacker] 単発実行（プロトコル / 暗号 / 証明書を一括）
sslscan [TARGET]:443

# [Attacker] SNI を明示（バーチャルホスト環境）
sslscan --sni-name=[DOMAIN] [TARGET]:443

# [Attacker] XML 出力（後段で grep / jq 風の処理を行う場合）
sslscan --xml=sslscan_out.xml [TARGET]:443

# [Attacker] 古いプロトコルだけ確認したい（速度優先）
sslscan --ssl3 --tls10 --tls11 --no-tls12 --no-tls13 [TARGET]:443

# [Attacker] STARTTLS 系（メール / IMAP / FTP / LDAP / MySQL / PostgreSQL）
sslscan --starttls-smtp [TARGET]:25
sslscan --starttls-imap [TARGET]:143
sslscan --starttls-ldap [TARGET]:389
sslscan --starttls-mysql [TARGET]:3306
sslscan --starttls-psql [TARGET]:5432
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `SSLv3   enabled` / `TLSv1.0  enabled` 等が赤で表示 | レガシプロトコル受け入れ | 報告対象（POODLE / BEAST 関連の足掛かり）|
| `Accepted` 行に `RC4` / `3DES` / `EXPORT` / `NULL` | 弱い暗号スイート | 報告対象 |
| `Signature Algorithm: sha1WithRSAEncryption` | SHA-1 署名（非推奨） | §5 で記録・PKI 監査項目 |
| `Heartbleed` セクションが `vulnerable` | OpenSSL < 1.0.1g | testssl.sh で再確認・本番では PoC 取得は 1 回まで |
| TLS1.3 のみ + `RSA Key Strength: 4096` 等の健全表示 | 比較的健全 | §2 testssl.sh スキップ判断材料 |

> **使い分け:** **初動・大量ホストには `sslscan`**（速い・単体・古プロトコル対応）。**深堀り・報告書用詳細・名前付き脆弱性網羅には `testssl.sh`**。`openssl s_client` が `-ssl3` 等で `unknown option` を返すディストリでも sslscan は内蔵 OpenSSL で対応する。

---

## 2. testssl.sh での包括チェック

**コマンド:**

```bash
# [Attacker] 単発実行（自動で全項目チェック）
./testssl.sh https://[TARGET]:443

# [Attacker] 報告書用に HTML / JSON 出力
./testssl.sh --htmlfile out.html --jsonfile out.json https://[TARGET]:443

# [Attacker] 速度優先（Vulnerabilities セクションのみ）
./testssl.sh -U https://[TARGET]:443
# -U = --vulnerable のショート版。Heartbleed・POODLE・FREAK・Logjam・ROBOT 等を一括判定

# [Attacker] 並列スキャン抑制（IPS 警報・WAF レート制限を避けたい場合）
./testssl.sh --sneaky --warnings batch https://[TARGET]:443
# --sneaky : User-Agent を一般的ブラウザに偽装
# --warnings batch : 対話プロンプトを抑制（出力を保存したいときに必須）
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `Protocols` セクションで赤表示（SSLv2 / SSLv3 / TLS1.0 等）| 危険なプロトコル受け入れ | 報告対象 |
| `Cipher Suites` に弱いスイート個別表示 | RC4 / 3DES / EXPORT / NULL 等 | §1 と同様に記録 |
| `Vulnerabilities` セクションに `VULNERABLE` | 名前付き脆弱性該当 | 該当 CVE を控え報告。Heartbleed の場合はメモリダンプ繰り返し禁止 |
| `Server's Certificate` の `Common Name (CN)` と接続 FQDN が不一致 | 証明書不整合 | 報告対象。§5 で SAN も合わせて確認 |
| `Local problem: No vulnerable cipher mapped` 等で停止 | 対象が ServerHello を返さない（古いハードウェア / 非標準 TLS スタック）| §1 nmap + §4 openssl s_client の手動確認に切替 |
| `Trust (hostname)` で `Connection refused` 連発 | IPS / WAF のレート制限発動 | `--sneaky` + `--warnings batch` + `-U` で接続数を絞る |

**注意:** testssl.sh は接続回数が多い。IPS / WAF のレート制限を発動させ、以降の調査用 IP が遮断される可能性。`--sneaky` / `--warnings batch` を併用し、必要に応じて `-U` で Vulnerabilities のみに絞る。

---

## 3. sslyze での JSON レポート化

**事前準備:** `pip install --user sslyze --break-system-packages` でインストール。

**コマンド:**

```bash
# [Attacker] 単発実行
sslyze [TARGET]:443

# [Attacker] JSON 出力（報告フォーマット化に便利）
sslyze --json_out=sslyze_out.json [TARGET]:443

# [Attacker] 個別チェック例
sslyze --tlsv1 --tlsv1_1 --tlsv1_2 --tlsv1_3 --certinfo --heartbleed --robot [TARGET]:443
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| JSON ファイルが生成 | 報告書テンプレートへの流し込みが可能 | 各 `scan_commands_results` を抽出して項目別にまとめる |
| `is_vulnerable_to_heartbleed: true` | Heartbleed 該当 | 報告対象。メモリダンプの繰り返し取得は避ける |
| `is_vulnerable_to_ccs_injection: true` | CVE-2014-0224 該当 | 報告対象 |
| `accepted_cipher_suites` に弱いスイートが含まれる | §1 と同様に記録 | プロトコル別に個別記載 |
| ConnectionError 系の例外 | 対象が標準スキャンを蹴る・mTLS 要求 | §4 openssl s_client の手動確認に切替 |

---

## 4. openssl s_client での手動確認

ツールに頼らず 1 コマンドで確認したい場合・対象が標準スキャンを蹴る場合に使う。

**コマンド:**

```bash
# [Attacker] 接続して証明書取得
openssl s_client -connect [TARGET]:443 -servername [DOMAIN] </dev/null 2>/dev/null \
  | openssl x509 -noout -text
# -servername : SNI を明示。バーチャルホスト環境で証明書が変わるなら必須

# [Attacker] 特定プロトコルを強制（受け入れの個別確認）
openssl s_client -tls1 -connect [TARGET]:443      # TLS1.0 受け入れか
openssl s_client -tls1_1 -connect [TARGET]:443    # TLS1.1 受け入れか
openssl s_client -ssl3 -connect [TARGET]:443      # SSLv3 受け入れか（POODLE）

# [Attacker] 特定暗号を強制（個別 cipher の受け入れ確認）
openssl s_client -cipher 'RC4-SHA' -connect [TARGET]:443

# [Attacker] Client 証明書要求（mTLS）の判定
openssl s_client -connect [TARGET]:443 </dev/null 2>&1 | grep -i "acceptable client certificate"
```

> **`-ssl3` / `-tls1` / `-tls1_1` の利用可否（ディストリビルド前提）:** Debian / Ubuntu / RHEL 系の OpenSSL 1.1.1 / 3.x は **`enable-ssl3` / `enable-tls1` / `enable-tls1_1` を無効化してビルドされていることが多い**。手元のコマンドで `unknown option -ssl3` / `-tls1` / `-tls1_1` が返ったらこのケース。fallback 経路:
>
> 1. **`nmap --script ssl-enum-ciphers -p 443 [TARGET]`** — プロトコル受け入れ可否を nmap 内部の SSL ライブラリで判定（最も確実）
> 2. **testssl.sh 同梱 openssl を直叩き** — `testssl.sh` リポジトリの `bin/openssl.Linux.x86_64` は古いプロトコル対応版のため、`./bin/openssl.Linux.x86_64 s_client -ssl3 -connect [TARGET]:443` で確認可能
> 3. **古い openssl を Docker で持ち込む** — `docker run --rm -it alpine:3.9 sh -c "apk add openssl && openssl s_client -ssl3 -connect [TARGET]:443"` 等で旧版を確保
> 4. **`sslscan`** — 単体バイナリで古いプロトコルもデフォルトで網羅（後述 §1.5）

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| ハンドシェイク成功（証明書が表示される） | 指定プロトコル / 暗号の受け入れ確定 | §5 で証明書フィールドを読解 |
| `handshake failure` / `sslv3 alert handshake failure` | 指定プロトコル / 暗号が拒否された | 健全な拒否。次の組合せを試す |
| `unable to get local issuer certificate` | 自己署名 or 社内 CA（信頼チェーン不完全だが接続は成立）| Issuer 文字列を組織情報として §5 で記録 |
| `Acceptable client certificate CA names` 出力 | mTLS 要求 | クライアント証明書が無いと TLS 監査は不可。事前合意で証明書発行を依頼するか、別経路を探す |
| SNI なしでは接続できない / 違う証明書が返る | バーチャルホスト構成（同一 IP で複数 FQDN）| `-servername` で各 FQDN を順に指定、または vhost ファジング（`./Web_Enumeration.md`）で FQDN を発見してから戻る |
| `ForceCommand` 設定等で即切断 | TLS は成立しているがアプリ層で拒否 | プロトコル/暗号の確認には足りる |

**注意:** `-servername` を付け忘れると SNI 無しでデフォルト証明書が返り、本来の vhost 用証明書が見えない。バーチャルホスト環境では必須。

---

## 5. 証明書 CN / SAN / Issuer からの組織・製品推定

§1 ssl-cert / §2 testssl.sh / §4 openssl s_client いずれかで証明書が取れた後、その中身を組織・製品推定の入口として読む。

**読むフィールドと読み方:**

```bash
# [Attacker] §4 で取得した証明書を整形して表示
openssl s_client -connect [TARGET]:443 -servername [DOMAIN] </dev/null 2>/dev/null \
  | openssl x509 -noout -text
```

| フィールド | 何を見るか |
|---|---|
| `Subject:` の CN | 証明書の主体名（接続 FQDN との一致確認） |
| `X509v3 Subject Alternative Name:` | SAN 一覧（vhost / 内部 FQDN の手がかり） |
| `Issuer:` | 発行者（社内 CA・公的 CA・アプライアンス自己署名 CA の見分け） |
| `Validity` | 有効期限（期限切れ検出） |
| `Public Key:` | 鍵長（1024bit RSA は弱） |
| `Signature Algorithm:` | SHA-1 署名（SHA1withRSA）は非推奨 |

**観測される出力 → 次のアクション:**

| 観測内容 | 推定される情報 | 次のアクション |
|---------|--------------|--------------|
| CN / SAN に内部 FQDN（`*.internal.[ORG].local` / `[HOST].corp.[ORG].local`）| 内部命名規則が漏れている。AD ドメイン名の手がかり | `../06_Concepts/Hosts_File_For_AD.md` 経由で AD 探索フローへ |
| Issuer に社内 CA 名（`[ORG] Internal CA` 等）| 社内 PKI の存在 | 後続の Web 列挙時に同じ CA 配下の他サービスを推定 |
| SAN に複数 FQDN が列挙 | vhost ファジング不要で対象 FQDN が一括判明 | 各 FQDN を `./Web_Enumeration.md` の対象に追加 |
| CN が `*.cloudflare.com` / `*.akamaized.net` / `*.azureedge.net` 等 | CDN 配下。観測している TLS 設定はオリジンではなく CDN | 「フロント側設定」と明示して記録、オリジン特定経路（DNS 履歴 / SAN / SSRF 等）を探す |
| Issuer に `Fortinet` / `Citrix` / `Palo Alto Networks` / `Pulse Secure` 等の製品名 | アプライアンス確定 | `../02_Initial_Access/Edge_Appliance_CVEs.md` で該当 CVE を当てる |
| Issuer が `Let's Encrypt` で SAN に開発系 FQDN（`dev.` / `staging.` / `test.`）| ステージング環境の混在。本番より緩い設定の可能性 | 各 FQDN を `./Web_Enumeration.md` / `./Exposed_Files.md` の対象に追加 |
| CN と接続 FQDN が不一致 | 証明書不整合（監査基準違反） | 報告対象 |
| `Not After:` が過去日 | 有効期限切れ | 報告対象 |
| `Signature Algorithm: sha1WithRSAEncryption` | SHA-1 署名（非推奨） | 報告対象 |
| `Public-Key: (1024 bit)` | 1024bit RSA（弱鍵長） | 報告対象 |

**注意:**

- 証明書の Issuer に社内 CA 名が出ている時は、その文字列を独立した情報として保管する。後続の AD 列挙・Web 列挙で「組織内命名規則」「サブドメイン候補」のヒントになる
- SAN は SAN ごとに別 FQDN として記録する。1 件の証明書から数十の vhost FQDN が判明することがある（vhost ファジング不要）

---

## 5.5. JA3 / JA3S フィンガープリントによる WAF / CDN / 製品推定

ClientHello（クライアント側）と ServerHello（サーバー側）の TLS ハンドシェイクパラメータを並べて MD5 ハッシュ化したものが JA3 / JA3S。**CDN・WAF・ロードバランサー・各種アプライアンスは自前の TLS スタック実装を持つため、JA3S 値が製品ごとに特徴的**になり、CN / SAN が generic な場合の補助的な製品判定に使える。

**コマンド:**

```bash
# [Attacker] JA3S 算出 — ssltools / pyja3 / Wireshark の filter で取得可能
# pyja3（要 `pip install pyja3`）でハンドシェイクをキャプチャ → 内部で JA3S 計算
sudo python3 -m pyja3 -t [TARGET]:443

# [Attacker] tshark 経由（パケットキャプチャから抽出）
tshark -i any -Y "tls.handshake.type==2" -T fields -e ip.src -e tls.handshake.ja3s 2>/dev/null
```

**観測される出力 → 次のアクション:**

| JA3S ハッシュの特徴 | 推定 | 次のアクション |
|---|---|---|
| 多数の公開 DB に「Cloudflare」「Akamai」「Fastly」と紐付け | CDN 配下 | オリジン IP は別途特定（`./DNS_Enumeration.md` の CDN オリジン特定経路）|
| Citrix / F5 / Palo Alto / Fortinet 等のアプライアンス署名と一致 | エッジアプライアンス | バージョン特定 → `../02_Initial_Access/Edge_Appliance_CVEs.md` |
| Nginx / Apache のデフォルト値と一致 | 一般的な Web サーバー | 製品判定の追加情報は不要 |

> **JA3S DB の参照:** abuse.ch SSL Blacklist の JA3 DB / SalesForce 公開リスト / 個別研究のフィンガープリント集など。**完全一致は判定の信頼性が高いが、ファイアウォール側で JA3 偽装している環境では役に立たない**ことに注意。CN / SAN / Issuer・HTTP ヘッダー（`Server:`）・favicon ハッシュなど他の証拠と組み合わせる。

---

## 6. HSTS / セキュリティヘッダー確認

**コマンド:**

```bash
# [Attacker] TLS 関連ヘッダーの抽出
curl -sI https://[TARGET]/ | grep -iE "strict-transport-security|content-security-policy|x-content-type-options|x-frame-options"
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `Strict-Transport-Security` ヘッダーなし | HSTS 未設定。ダウングレード攻撃の対策がない | 報告対象 |
| `Strict-Transport-Security: max-age=0` | HSTS が明示的に無効化されている | 報告対象 |
| `max-age=[短い値]`（< 31536000）| 短期間のみ強制（推奨は 1 年以上） | 報告対象 |
| `includeSubDomains` 欠落 | サブドメインは HTTPS 強制されていない | 観点として記録 |
| `preload` 欠落 | ブラウザ HSTS Preload List 未登録 | 観点として記録（必須ではない） |
| Web 全体のセキュリティヘッダーをまとめて見たい | TLS 観点だけでは不足 | `./Web_Response_Triage.md` のヘッダー一括チェックへ |

---

## 刺さらなかったとき（全体）

| 観測される症状 | 推定原因 | 代替手段 |
|--------------|---------|------|
| `connect: Connection refused` | 対象ポートで TLS を待ち受けていない | nmap でポート再確認。HTTPS なら他ポート（`8443` / `8080`）も確認 |
| 接続がすぐ切られる（TCP RST） | IPS / WAF のレート制限・パターン検知 | §2 testssl.sh の `--sneaky`、もしくは `nmap` の `--scan-delay` を使った間欠スキャンに切替 |
| `unable to get local issuer certificate` | 自己署名 or 社内 CA | 信頼チェーンは不完全だが接続自体は成立。Issuer 文字列を §5 で組織情報として記録 |
| `Acceptable client certificate CA names` 出力 | mTLS 要求 | クライアント証明書が無いと TLS 監査は不可。事前合意で証明書発行を依頼するか、別経路を探す |
| SNI なしでは接続できない / 違う証明書が返る | バーチャルホスト構成 | `-servername` で各 FQDN を順に指定、または vhost ファジング（`./Web_Enumeration.md`）で FQDN を発見してから戻る |
| testssl.sh が `Local problem: No vulnerable cipher mapped` で停止 | 対象が ServerHello を返さない（古いハードウェア / 非標準 TLS スタック）| §1 nmap + §4 openssl s_client の手動確認に切替 |
| 全項目 `not offered` / 接続不可 | 対象が CDN 配下で IP 直叩きを拒否、または別ポート（mTLS / IPSec / TLS-over-VPN）に動いている | DNS で実際のアクセス先 FQDN を確認、Web フロントから順に辿る |

## 注意点・落とし穴

- **CDN / ロードバランサー配下の場合、観測している TLS 設定はオリジンのものではない。** SAN・CNAME・IP の対応関係から CDN 該否を判断し、CDN 経由の値は「フロント側設定」と明示して記録する
- **対象が古い OpenSSL（< 1.0.1g）でかつ Heartbleed 該当の場合、ヒープメモリ内容が露出する。** 読み取り中心の監査でも検出だけに留め、メモリダンプの繰り返し取得は影響評価上避ける（1 回の `VULNERABLE` 判定で十分）
- **対象側の TLS 設定変更（管理画面のチェックボックス）に手を入れない。** 監査側は読み取り専用に徹する
- **個別ブロック固有の注意は各 §N ブロック内の「注意:」を参照。** 本セクションは複数ブロック横断の話のみを置く

### 本番での前提

- **事前合意の要否**: ★（§1 nmap・§4 openssl s_client・§5 証明書読解・§6 ヘッダー確認は技術的判断のみで実施可。§2 testssl.sh / §3 sslyze は接続数が多く IPS / WAF を発動させ得るため事前確認推奨）/ ★★★（§1 個別 CVE スクリプトのうち `ssl-heartbleed` 等の脆弱性確認系は影響評価の合意を確認）
- **想定される SIEM / EDR 検知**: WAF / IPS の「TLS スキャン」シグネチャ（testssl.sh / sslyze の連続接続パターン）、Heartbleed 検証時の対象 IDS シグネチャ、`ssl-heartbleed` 等 nmap 個別スクリプトのシグネチャ
- **業務影響リスク**: 読み取り中心のためサービス停止リスクは低いが、testssl.sh の連続接続でレート制限ベース遮断が発動した場合は以降の調査用 IP が遮断され、調査全体に影響
- **原状回復必須項目**: ✅ なし（読み取り専用。対象側の TLS 設定は変更しない）/ ✅ 取得した内部 FQDN / 社内 CA 名等の情報は暗号化保管
- **取得情報の取扱**: 証明書ダンプ・JSON レポートは暗号化保管、テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

## 関連技術

- 前：TLS ポートの発見 → `./Network_Scanning.md`
- 前：HTTPS で動く Web サービスのフィンガープリント中に証明書情報が必要になった場合 → `./Web_Enumeration.md`
- 後：SAN から判明した追加 FQDN を vhost / 直接アクセスで調査 → `./Web_Enumeration.md`
- 後：Web 全体のセキュリティヘッダー・Cookie 属性の一括チェック → `./Web_Response_Triage.md`
- 後：証明書の組織名・FQDN から推定したサブドメインで誤公開ファイルを探す → `./Exposed_Files.md`
- 後（アプライアンス特定時）：Issuer / SAN がアプライアンス製品の場合、製品名から既知 CVE を当たる → `../02_Initial_Access/Edge_Appliance_CVEs.md`
- 後：証明書から判明した製品/バージョンで CVE 検索 → `../05_Tools_Reference/Searchsploit.md`
- 関連：SSH バナーと同様の鍵/バナーからの組織推定軸 → `../02_Initial_Access/SSH.md`
