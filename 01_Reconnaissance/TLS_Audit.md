# TLS / SSL 設定の弱点確認

## このファイルの位置づけ

インターネット露出サービスのプロトコル・暗号スイート・証明書・既知 TLS 脆弱性を確認するための技術観点を集約する。
製品/組織の推定や Web 列挙の入口としても使う（証明書の CN/SAN がフィンガープリントになる）。

---

## TLS スキャンの実施判断

### 着火条件

以下のいずれかに該当した時点で TLS 監査を開始する。

- ポートスキャンで TLS を使うポートが開いている：`443` / `465` / `636` / `993` / `995` / `989` / `990` / `8443` / `3389`（RDP は TLS over TCP）/ 任意の `https-alt` ポート
- nmap の `ssl-cert` で証明書情報が引けた段階で、製品/組織のヒントを得たい
- 既知 TLS 名前付き脆弱性（Heartbleed・POODLE・FREAK・Logjam・ROBOT・DROWN・Sweet32・Ticketbleed 等）の該否を確認したい
- 監査要件として「古いプロトコル / 弱い暗号 / 証明書不一致」の検出が要求されている

### 環境前提

- 実行環境: テスター端末
- 必要なツール：
  - `nmap`（ペネトレ用 Linux ディストリ標準。`--script ssl-enum-ciphers` / `ssl-cert` / 個別 CVE スクリプトで簡易チェック）
  - `openssl s_client`（標準搭載。手動の 1 コマンド確認・証明書取得・プロトコル指定接続）
  - `testssl.sh`（別途インストール要、bash + openssl 同梱バイナリで動く包括チェッカー。`git clone https://github.com/drwetter/testssl.sh` で取得。インターネット遮断 VLAN では事前にクローン済みのコピーを持ち込む）
  - `sslyze`（別途インストール要、`pip install --user sslyze`。JSON 出力で報告書化しやすい）

オフライン代替：`testssl.sh` / `sslyze` が無い環境では `nmap --script ssl-enum-ciphers,ssl-cert,ssl-dh-params` + `openssl s_client` の組み合わせでカバーする。

### 観点・着眼点

**先に確認すること：**

- 対象が **SNI を要求するか**（同一 IP で複数 FQDN がホストされている可能性。SNI 無しでは別証明書が返る、または接続が切られる）
- ロードバランサー / WAF / CDN の前段に居ないか（CDN 配下の場合、観測される TLS 設定は CDN の設定であってオリジンの設定ではない）
- 接続そのものが切られる挙動を見たら、IPS / WAF のレート制限を疑い試行間隔を空ける

**TLS 監査で見る軸（5 つ）：**

| 軸 | 何を見るか | 主なシグナル |
|----|----------|--------------|
| プロトコル | SSLv2 / SSLv3 / TLS1.0 / TLS1.1 / TLS1.2 / TLS1.3 のどれを受け入れるか | SSLv3 → POODLE 該当 / TLS1.0・1.1 → 監査要件で非推奨 / TLS1.3 のみ → 比較的健全 |
| 暗号スイート | RC4 / DES / 3DES / EXPORT / NULL / 匿名 DH / 弱い鍵長 | RC4 残存 → BAR Mitigations 該当 / EXPORT → FREAK・Logjam の足掛かり / 3DES → Sweet32 |
| 証明書 | CN / SAN / 発行者 / 有効期限 / 鍵長 / 署名アルゴリズム / 自己署名か | CN と接続 FQDN の不一致 / 期限切れ / SHA-1 署名 / 1024bit RSA / 内部 CA（社内 PKI の組織名が漏れる）|
| 既知 TLS 名前付き脆弱性 | Heartbleed / POODLE / CRIME / FREAK / Logjam / ROBOT / DROWN / Sweet32 / Ticketbleed | nmap 個別スクリプトまたは testssl.sh の Vulnerabilities セクションで一括判定 |
| HTTP セキュリティヘッダー（TLS 関連） | HSTS / HPKP（廃止だが残存）/ Upgrade-Insecure-Requests | HSTS なし → ダウングレード可、`includeSubDomains` / `preload` 有無も見る |

**攻撃者の思考トレース：** TLS 監査は「弱い暗号で接続を確立してからその先で何かする」攻撃というより、**証明書の中身を製品・組織推定の入口に使う**用途と、**監査基準（PCI DSS・FedRAMP・社内ポリシー）違反の検出**用途が中心。Heartbleed のような直接情報漏洩につながる古典脆弱性は今や稀だが、見つかれば即報告対象。

**証明書 CN / SAN からの組織・製品推定（着眼点）：**

| 観測内容 | 推定される情報 |
|---------|--------------|
| CN / SAN に内部 FQDN（`*.internal.[ORG].local` / `[HOST].corp.[ORG].local`）| 内部命名規則が漏れている。AD ドメイン名の手がかり |
| Issuer に社内 CA 名（`[ORG] Internal CA` 等）| 社内 PKI の存在。後続の Web 列挙時に同じ CA 配下の他サービスを推定 |
| SAN に複数 FQDN が列挙 | vhost ファジング不要で対象 FQDN が一括判明 |
| CN が `*.cloudflare.com` / `*.akamaized.net` / `*.azureedge.net` 等 | CDN 配下。観測している TLS 設定はオリジンではなく CDN |
| Issuer に `Fortinet` / `Citrix` / `Palo Alto Networks` / `Pulse Secure` 等の製品名 | アプライアンス。`../02_Initial_Access/Edge_Appliance_CVEs.md` 該当 |
| Issuer が `Let's Encrypt` で SAN に開発系 FQDN（`dev.` / `staging.` / `test.`）| ステージング環境の混在。本番より緩い設定の可能性 |

---

## 手順

### Step 1：nmap での簡易確認（最初の一手）

```bash
# 暗号スイート + プロトコル一覧（標準搭載）
nmap --script ssl-enum-ciphers -p 443 [TARGET]   # [Attacker]

# 証明書情報（CN / SAN / 発行者 / 有効期限）
nmap --script ssl-cert -p 443 [TARGET]   # [Attacker]

# DH パラメータ（Logjam 観点）
nmap --script ssl-dh-params -p 443 [TARGET]   # [Attacker]

# 個別 CVE スクリプト
nmap --script ssl-heartbleed -p 443 [TARGET]   # [Attacker]
nmap --script ssl-poodle -p 443 [TARGET]   # [Attacker]
nmap --script ssl-ccs-injection -p 443 [TARGET]   # [Attacker]
```

**`ssl-enum-ciphers` 出力の読み方：**

各プロトコル（`TLSv1.0` / `TLSv1.1` / `TLSv1.2` / `TLSv1.3`）ごとにスイート一覧と評価グレード（A/B/C/D/E/F）が表示される。

| 出力例 | 意味 | 次のアクション |
|--------|------|--------------|
| `TLSv1.0:` セクションが存在 | TLS 1.0 受け入れ → 監査要件で非推奨 | 報告対象。プロトコル別の最弱スイートも記録 |
| スイート名に `RC4` | RC4 残存 | 報告対象（BAR Mitigations） |
| スイート名に `3DES` / `DES-CBC3` | Sweet32（CVE-2016-2183）該当 | 報告対象 |
| スイート名に `EXPORT` | 輸出グレード暗号。FREAK / Logjam の足掛かり | 報告対象 |
| `least strength: C` 以下の表示 | 弱いスイートが残存している総合判定 | 個別スイートを抽出して列挙 |

### Step 2：testssl.sh での包括チェック

```bash
# 単発実行（自動で全項目チェック）
./testssl.sh https://[TARGET]:443   # [Attacker]

# 報告書用に HTML / JSON 出力
./testssl.sh --htmlfile out.html --jsonfile out.json https://[TARGET]:443   # [Attacker]

# 速度優先（Vulnerabilities セクションのみ）
./testssl.sh -U https://[TARGET]:443   # [Attacker]
# -U = --vulnerable のショート版。Heartbleed・POODLE・FREAK・Logjam・ROBOT 等を一括判定

# 並列スキャン抑制（IPS 警報・WAF レート制限を避けたい場合）
./testssl.sh --sneaky --warnings batch https://[TARGET]:443   # [Attacker]
# --sneaky : User-Agent を一般的ブラウザに偽装
# --warnings batch : 対話プロンプトを抑制（出力を保存したいときに必須）
```

**typical 出力の読みどころ：**

- `Protocols`：受け入れるプロトコル一覧（赤＝危険、緑＝健全）
- `Cipher Suites`：弱いスイート個別表示
- `Vulnerabilities`：名前付き脆弱性の該否（`not vulnerable` / `VULNERABLE` で色分け）
- `Server's Certificate`：CN / SAN / Issuer / 有効期限 / 鍵長

### Step 3：sslyze での JSON レポート化

```bash
# 別途インストール
pip install --user sslyze --break-system-packages   # [Attacker]

# 単発実行
sslyze [TARGET]:443   # [Attacker]

# JSON 出力（報告フォーマット化に便利）
sslyze --json_out=sslyze_out.json [TARGET]:443   # [Attacker]

# 個別チェック例
sslyze --tlsv1 --tlsv1_1 --tlsv1_2 --tlsv1_3 --certinfo --heartbleed --robot [TARGET]:443   # [Attacker]
```

### Step 4：openssl s_client での手動確認

ツールに頼らず 1 コマンドで確認したい場合・対象が標準スキャンを蹴る場合に使う。

```bash
# 接続して証明書取得
openssl s_client -connect [TARGET]:443 -servername [DOMAIN] </dev/null 2>/dev/null \
  | openssl x509 -noout -text   # [Attacker]
# -servername : SNI を明示。バーチャルホスト環境で証明書が変わるなら必須

# 特定プロトコルを強制（受け入れの個別確認）
openssl s_client -tls1 -connect [TARGET]:443   # [Attacker]      # TLS1.0 受け入れか
openssl s_client -tls1_1 -connect [TARGET]:443   # [Attacker]    # TLS1.1 受け入れか
openssl s_client -ssl3 -connect [TARGET]:443   # [Attacker]      # SSLv3 受け入れか（POODLE）

# 特定暗号を強制（個別 cipher の受け入れ確認）
openssl s_client -cipher 'RC4-SHA' -connect [TARGET]:443   # [Attacker]

# Client 証明書要求（mTLS）の判定
openssl s_client -connect [TARGET]:443 </dev/null 2>&1 | grep -i "acceptable client certificate"   # [Attacker]
# 出力に該当行があれば mTLS。クライアント証明書なしでは先に進めない
```

**`openssl x509 -text` 出力で見るフィールド：**

- `Subject:` → CN（証明書の主体名）
- `X509v3 Subject Alternative Name:` → SAN 一覧（vhost / 内部 FQDN の手がかり）
- `Issuer:` → 発行者（社内 CA・公的 CA・アプライアンス自己署名 CA の見分け）
- `Validity` → 有効期限（期限切れの検出）
- `Public Key:` → 鍵長（1024bit RSA は弱）
- `Signature Algorithm:` → SHA-1 署名（SHA1withRSA）は非推奨

### Step 5：HSTS と関連ヘッダーの確認

```bash
curl -sI https://[TARGET]/ | grep -iE "strict-transport-security|content-security-policy|x-content-type-options|x-frame-options"   # [Attacker]
```

**HSTS の読み方：**

| 観測内容 | 意味 |
|---------|------|
| ヘッダーなし | HSTS 未設定。ダウングレード攻撃の対策がない |
| `max-age=0` | HSTS が明示的に無効化されている |
| `max-age=[短い値]` | 短期間のみ強制（推奨 ≧ 31536000 = 1 年） |
| `includeSubDomains` あり | サブドメインも HTTPS 強制 |
| `preload` あり | ブラウザ HSTS Preload List 登録向け |

---

## 刺さらなかったとき

| 観測される症状 | 推定原因 | 対処 |
|--------------|---------|------|
| `connect: Connection refused` | 対象ポートで TLS を待ち受けていない | nmap でポート再確認。HTTPS なら他ポート（`8443` / `8080`）も確認 |
| 接続がすぐ切られる（TCP RST） | IPS / WAF のレート制限・パターン検知。`testssl.sh` の連続接続を検知している可能性 | `--sneaky` で User-Agent 偽装、もしくは `nmap` の `--scan-delay` を使った間欠スキャンに切替 |
| `unable to get local issuer certificate` | 自己署名 or 社内 CA。信頼チェーンは不完全だが接続自体は成立 | `-noverify` 系オプションで継続。Issuer 文字列は組織情報として記録 |
| `Acceptable client certificate CA names` 出力 | mTLS 要求 | クライアント証明書が無いと TLS 監査は不可。事前合意で証明書発行を依頼するか、別経路を探す |
| SNI なしでは接続できない / 違う証明書が返る | バーチャルホスト構成（同一 IP で複数 FQDN） | `-servername` で各 FQDN を順に指定、または vhost ファジング（`Web_Enumeration.md`）で FQDN を発見してから戻る |
| testssl.sh が `Local problem: No vulnerable cipher mapped` 等で停止 | テスト対象側が ServerHello を返さず testssl 側ロジックが進めない（古いハードウェア / 非標準 TLS スタック） | `nmap --script ssl-enum-ciphers` + `openssl s_client` の手動確認に切替 |
| 全項目 `not offered` / 接続不可 | 対象が CDN 配下で IP 直叩きを拒否、または別ポート（mTLS / IPSec / TLS-over-VPN）に動いている | DNS で実際のアクセス先 FQDN を確認、Web フロントから順に辿る |

---

## 注意点・落とし穴

- **testssl.sh は接続回数が多い。**IPS / WAF のレート制限を発動させ、以降の調査用 IP が遮断される可能性。`--sneaky` / `--warnings batch` を併用し、必要に応じて `-U` で Vulnerabilities のみに絞る
- **nmap の `--script ssl-enum-ciphers` は対象のサーバ実装によっては偽の `least strength` を出すことがある。**個別スイートの一覧と照合する
- **CDN / ロードバランサー配下の場合、観測している TLS 設定はオリジンのものではない。**SAN・CNAME・IP の対応関係から CDN 該否を判断し、CDN 経由の値は「フロント側設定」と明示して記録する
- **証明書の Issuer に社内 CA 名が出ている時は、その文字列を独立した情報として保管する。**後続の AD 列挙・Web 列挙で「組織内命名規則」「サブドメイン候補」のヒントになる
- **Subject Alternative Name は SAN ごとに別 FQDN として記録する。**1 件の証明書から数十の vhost FQDN が判明することがある（vhost ファジング不要）
- **対象が古い OpenSSL（< 1.0.1g）でかつ Heartbleed 該当の場合、ヒープメモリ内容が露出する。**読み取り中心の監査でも検出だけに留め、メモリダンプの繰り返し取得は影響評価上避ける
- **対象側の TLS 設定変更（管理画面のチェックボックス）に手を入れない。**監査側は読み取り専用に徹する

---

## 関連技術

- 前：`./Network_Scanning.md`（TLS ポートの発見）
- 前：`./Web_Enumeration.md`（HTTPS で動く Web サービスのフィンガープリント中に証明書情報が必要になった場合）
- 後：`./Web_Enumeration.md`（SAN から判明した追加 FQDN を vhost / 直接アクセスで調査）
- 後：`./Exposed_Files.md`（証明書の組織名・FQDN から推定したサブドメインで誤公開ファイルを探す）
- 後：`../02_Initial_Access/Edge_Appliance_CVEs.md`（Issuer / SAN がアプライアンス製品の場合、製品名から既知 CVE を当たる）
- 後：`../05_Tools_Reference/Searchsploit.md`（証明書から判明した製品/バージョンで CVE 検索）
