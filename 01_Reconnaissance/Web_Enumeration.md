# Web列挙

## robots.txt の確認

### 着火条件
Webポートが開いており、まず手動でサイト構造を把握したい場合。**ディレクトリ列挙の前に必ず確認する。**

### 観点・着眼点

`robots.txt` はクローラーに「アクセスさせたくないパス」を伝えるファイルだが、**攻撃者にとっては隠しディレクトリの地図になる。**

`Disallow:` エントリに含まれるパスは「隠したい重要なページ」である可能性が高い：
- 管理画面（`/admin`, `/wp-admin`, `/panel` 等）
- CMSのインストールパス（`/cms`, `/[サイト固有のパス]` 等）
- 内部ドキュメント・バックアップ（`/private`, `/backup` 等)

**`robots.txt` 本文・トップページに DoS 保護・WAF・自動 IP ブロックの記載がある場合のシグナル：**

サイトの著者が `robots.txt` のコメントやトップページのアスキーアート部分に「we have DoS protection enabled / we ban bad IPs」のような記載をしている場合、**ディレクトリ列挙ツール（gobuster / ffuf / wfuzz）の使用を控える。** 大量リクエストで自分の IP がブロックされ、それ以降のあらゆるアクセスが遮断される。

| 観測される文言 | 推定される対策 | 次のアクション |
|--------------|-------------|-------------|
| 「DoS protection」「rate limiting」「we ban bad IPs」のような明示的告知 | IP ベースの自動ブロック（fail2ban 系・WAF・カスタムスクリプト） | ディレクトリ列挙は行わず、`robots.txt` の `Disallow` 記載パス・HTML ソースのコメント・JS 内のエンドポイント参照から手動で構造を把握する |
| 「Apache 4xx errors and bans bad IPs」のような具体記述 | 4xx 連発で BAN | 試行は手動で 1 リクエストずつ、404 が連発しないように既知パスから推測ベースで進める |
| トップページにアスキーアート + 警告文（playful な書き方） | 著者が手動で防御を入れている可能性 | 同上。「警告は出ているがガード自体は弱い」と決めつけない |

```bash
curl -s http://[TARGET]/robots.txt
```

**nmap の `-sC`（デフォルトスクリプト）を使った場合、スキャン結果に自動で表示される：**
```
| http-robots.txt: 1 disallowed entry
|_/writeup/
```

### 手順

```bash
# 直接取得
curl -s http://[TARGET]/robots.txt

# Disallow エントリを抽出
curl -s http://[TARGET]/robots.txt | grep -i "disallow\|allow"
```

**見つけたパスへのアクセスで確認すること：**
1. パスが存在するか（404 か 200/301 か）
2. CMSや特定のアプリが動いているか（ログインページ・フッター・バージョン情報）
3. バージョンが判明したら即 `searchsploit [アプリ名] [バージョン]` で CVE 検索

### 注意点・落とし穴

- `robots.txt` が存在しない（404）場合でも、`/sitemap.xml` や `/sitemap_index.xml` に同等の情報がある場合がある
- `Disallow: /` だけの場合は全ブロックで情報量が少ない。次のディレクトリ列挙に移る
- サブドメイン・vhost では `/robots.txt` が別になる場合があるため、vhost ごとに確認する

---

## ディレクトリ・エンドポイントの列挙

### 着火条件
80 / 443 / 8080 等のWebポートが開いている場合。

### 観点・着眼点

ブラウザで確認した後、以下を意識する：
- URLの構造に連番や予測可能なIDが含まれていないか（→ IDORの可能性）
- どのフレームワーク・言語を使っているか（エラーページ・ヘッダーから）
- ファイルのダウンロード機能があるか
- 管理者パネルへのリンクが存在しないか

### 手順

**ディレクトリ列挙（gobuster）**
```bash
gobuster dir -u http://[IP] -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -o gobuster_root_dir.txt
```

**拡張子を指定したファイル探索**
```bash
gobuster dir -u http://[IP] -w [WORDLIST] -x php,txt,html,bak -o gobuster_ext.txt
```

**vhost（仮想ホスト）のファジング**
```bash
# [Attacker] gobuster vhost — v3.6 以降は --append-domain がデフォルト false（明示しないと「ワードリストをそのまま Host: にセット」する挙動になる）
gobuster vhost -u http://[DOMAIN] -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain -o vhost_fuzz.txt

# [Attacker] ffuf 経由（gobuster バージョン差分を回避したい場合の代替）
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
  -u http://[DOMAIN]/ -H "Host: FUZZ.[DOMAIN]" -fs [EXCLUDE_SIZE] -o vhost_fuzz.json -of json
```
→ 発見したvhostは `/etc/hosts` に追加して再調査する（原理 → `../06_Concepts/Hosts_File_For_AD.md`）

**feroxbuster（Rust 製・再帰デフォルトの高速代替）**
```bash
# [Attacker] feroxbuster は再帰探索がデフォルト・自動拡張子付与・並列度が高い
feroxbuster -u http://[IP] -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,html,bak,txt --depth 4 -o feroxbuster.txt

# [Attacker] ステータスコードフィルタ + 拡張子探索
feroxbuster -u http://[IP] -w [WORDLIST] -s 200,204,301,302,307,401,403 -x php,asp,aspx,jsp
```

> **使い分け:** **ディレクトリ探索の初手は `feroxbuster`**（再帰・拡張子・並列がデフォルト最適化）。**vhost には `gobuster vhost` または `ffuf`**（ヘッダー操作が直感的）。`gobuster dir` は枯れていて安定だが、再帰や深いツリーには feroxbuster が早い。

### エンドポイントの連番・IDを確認する（IDOR）

URLが `/data/3` や `/download/5` のような形式の場合：
- ID を `0` や `1` から順に変えてアクセスを試みる
- 認可チェックなしで他ユーザーのデータが取得できる可能性がある

→ 詳細: `../02_Initial_Access/Web_Vulnerabilities/IDOR.md`

### 注意点・落とし穴

- gobuster は `--timeout` と `-t`（スレッド数）の調整でスキャンが安定する
- レスポンスサイズが同じものが大量にある場合はフィルタリングが必要（`--exclude-length`）
- vhost のファジングでは必ずベースドメインを `/etc/hosts` に登録してから実施する
- HTTPS の場合は `-k` オプションで証明書チェックをスキップ
- **`--append-domain` の挙動はバージョン依存:** gobuster **v3.2 で導入**され、**v3.6 でデフォルトが false に変更**された。`gobuster --version` で確認のこと。
  - **v3.1 以前**: 自動で `[wordlist].[domain]` 形式に結合する（明示不要）
  - **v3.2 ～ v3.5**: `--append-domain` を付ければ `[wordlist].[domain]` 形式
  - **v3.6 以降**: デフォルトは「ワードリストをそのまま Host: ヘッダー値にセット」する挙動。`[wordlist].[domain]` 形式にしたいなら `--append-domain` を明示。**この差を把握していないと「ワードリストが裸の文字列として送られて全件失敗」する事故が起きる**
  - 古い記憶（v3.1 以前の自動結合）と混同しやすいため、新環境では必ず `--append-domain` 明示 + 1 件で挙動確認
  - 困ったら ffuf 代替：`ffuf -w [WORDLIST]:FUZZ -u http://[DOMAIN]/ -H "Host: FUZZ.[DOMAIN]" -fw [FILTER]`

### 刺さらなかったとき・症状別の対処

**ファジング中にブラウザのログインセッションが切れる / 数回に1回しかログインできない：**

| 観測される症状 | 推定原因 | 対処 |
|--------------|---------|------|
| ファジング開始後にブラウザでログアウトされる | ロードバランサー / WAF が IP 単位でレート制限を発動。同一IPの大量リクエストでセッションを切る | スレッド数を絞る（`-t 5` 以下） / 遅延を入れる（`--delay 200ms`） |
| 大量の `429 Too Many Requests` | アプリ層のレート制限 | スレッド数を絞る + リクエスト間隔を空ける |
| 大量の `503` / `502` | バックエンドが詰まっている / WAF の throttle | ファジング停止して数分待ってから再開、ワードリストを短いものに変える |
| ブラウザでログインしても即ログアウト | セッションストアの IP/UA バインディング | ファジング停止中にブラウザで操作し、別IP からは触らない |
| 一定回数失敗で IP ブロック | WAF / IPS の自動遮断 | 停止して回避策（IP ローテーション・遅延）を考える。検知された証跡として記録 |

**ファジングと手動操作は分離する。** ロードバランサー配下のアプリでは、ファジング中の手動操作はセッションが切れる前提で動く。**まず手動でサイト構造把握 → ファジングはバックグラウンド走行 → 必要なら停止して手動再開**、の順序で進める。

```bash
# 例：負荷を抑えたファジング設定
gobuster dir -u http://[IP] -w [WORDLIST] -t 5 --delay 200ms -o gobuster_lowrate.txt
```

---

## Webアプリのフレームワーク・アプリ名の特定

### 着火条件
Webポートが開いており、どのアプリ・フレームワークで動いているかを判断したい場合。
**ディレクトリ列挙の前に、手動でサイトを一通り閲覧して行う。**

### 観点・着眼点

「Webアプリの名前＝フレームワーク名ではない」という前提を持つ。
「フィットネス管理ソフト X」「ERP製品 Y」のような **製品名（固有名詞）** が
フレームワーク扱いで searchsploit にヒットすることが多い。見落としがちなパターンを意識する。

**攻撃者の思考トレース：** ヘッダーに出ない場合でも、ページの「どこかにアプリ名は必ず書いてある」と考えて探す。
「Made using」「Powered by」「Copyright © [製品名]」などは作者・開発元が無意識に露出させていることが多い。

**確認する場所（優先順位順）：**

| 確認場所 | 見つかりやすい情報 |
|---------|----------------|
| ページ下部フッター | 「Powered by X」「Made using X v1.0」「© X Software」 |
| `/about`・`/contact`・`/info` 等のページ | アプリ名・バージョン・開発元の記載 |
| ログインページ | アプリ名・バージョン（フッターまたはタイトル）|
| HTTPレスポンスヘッダー | `Server:`・`X-Powered-By:`・`X-Generator:` |
| HTMLソース（`<meta name="generator">`） | CMS・フレームワーク名（**著作権年範囲・バージョン文字列も含むことが多い**） |
| **Cookie 名（特徴的な接頭辞・サフィックス）** | **CMS / フレームワーク名（`CMSSESSID` → CMS Made Simple、`PHPSESSID` → PHP、`JSESSIONID` → Java Servlet 系、`laravel_session` → Laravel、`wordpress_logged_in_*` → WordPress 等）** |
| エラーページ | スタックトレースからフレームワーク・言語が判明 |
| `/api/health`・`/version`・`/info` | APIバージョン情報 |

**Cookie 名からの CMS / フレームワーク識別表（よく当たるもの）：**

| Cookie 名 | 推定アプリ・フレームワーク |
|-----------|--------------------------|
| `CMSSESSID` | CMS Made Simple |
| `wordpress_logged_in_*` / `wp-settings-*` | WordPress |
| `JSESSIONID` | Java Servlet 系（Tomcat / Jetty / WildFly） |
| `PHPSESSID` | PHP（任意の PHP アプリ。CMS 種別までは絞れない） |
| `laravel_session` / `XSRF-TOKEN`（laravel_session 同居） | Laravel |
| `_session_id` + `_csrf_token` のペア | Rails 系 |
| `connect.sid` | Express.js（Node） |
| `ASP.NET_SessionId` | ASP.NET |
| `frontend` / `adminhtml` | Magento |
| `SimpleSAMLAuthToken` | SimpleSAMLphp |

**HTML `<meta name="generator">` の著作権年範囲からバージョンを推定する：**

`<meta name="generator" content="CMS Made Simple - Copyright (C) 2004-2019. All rights reserved." />` のように著作権年範囲が `[開始年]-[最終年]` の形で出ることがある。**最終年が「そのコピーがビルドされた年≒バージョンの目安」になる。** たとえば `2004-2019` なら 2019 年に出た最終バージョンを当たる（CMS Made Simple なら 2.2.x 系）。バージョン特定後は即 `searchsploit [製品名] [年/バージョン]` を実行する。

```bash
# robots.txt 確認（nmap -sC スキャンで自動取得される場合あり）
curl -s http://[TARGET]/robots.txt

# アプリ名候補を手動で調査するページを確認
curl -s http://[TARGET]/about
curl -s http://[TARGET]/contact
curl -s http://[TARGET]/login | grep -i "powered\|version\|copyright\|made"

# HTTP ヘッダーの確認
curl -sI http://[TARGET]/ | grep -i "server\|x-powered-by\|x-generator\|x-version"

# HTML ソースの meta タグ確認（generator メタタグからバージョン情報も拾う）
curl -s http://[TARGET]/ | grep -i "generator\|framework\|powered\|copyright"

# Cookie 名の確認（Set-Cookie ヘッダー + ブラウザ DevTools の Storage タブ）
curl -sI http://[TARGET]/ | grep -i "set-cookie"
# 出力例: Set-Cookie: CMSSESSID9d372ef93962=...; path=/
#  → CMSSESSID 接頭辞が見えた時点で CMS Made Simple がほぼ確定
```

**自動フィンガープリント — whatweb / Wappalyzer / favicon ハッシュ:**

```bash
# [Attacker] whatweb — Cookie 名・meta generator・favicon ハッシュを一括で当てる自動フィンガープリンタ
whatweb -a 3 http://[TARGET]/                  # -a 3 はもっとも深いプロビング
whatweb -a 3 --log-json=whatweb.json http://[TARGET]/

# [Attacker] favicon mmh3 ハッシュによる製品特定（CN / SAN / Server ヘッダーが generic でも当たる）
# https://github.com/devanshbatham/FaviconHash 等のスクリプトでも可
curl -sk https://[TARGET]/favicon.ico -o /tmp/favicon.ico
python3 -c "import mmh3, base64; print(mmh3.hash(base64.encodebytes(open('/tmp/favicon.ico','rb').read())))"
# 出力された hash 値で Shodan / FOFA / ZoomEye / 製品 DB を検索:
# Shodan: http.favicon.hash:[VALUE]
# → 同じ favicon を持つ全ホスト一覧が出る = 同一製品 / 同一テンプレ
# → アプライアンスや SaaS の特定で非常に有効（CN / SAN 偽装にも強い）

# [Attacker] nikto — 既知の誤公開ファイル・古いバージョン痕跡・典型的な設定不備を一括検出
nikto -h http://[TARGET]/ -o nikto.txt
nikto -h https://[TARGET]/ -ssl -Tuning x6   # x = 全プラグイン / 6 = path traversal 除外（ノイズ削減）
```

> **使い分け:**
> 1. **初手は `whatweb -a 3`** — 数秒で Cookie / meta generator / favicon / Server / X-Powered-By を一括判定
> 2. **ヒットしなかったら favicon ハッシュを mmh3 で取って Shodan / FOFA に投げる** — generic な Web サーバーでも、内部実装の favicon が異なれば特定可能
> 3. **`nikto` は最後** — 時間がかかるが、whatweb で取れない既知の誤公開・古いバージョン痕跡を網羅

> ブラウザ拡張 `Wappalyzer` も同等の機能を持つが、対話的な調査時はブラウザ拡張・自動化したい場合は CLI ツールを使い分ける。

**アプリ名が判明したら即 searchsploit で検索する：**

```bash
searchsploit "アプリ名"
searchsploit "アプリ名" [バージョン番号]
```

**シグナルと次のアクション：**

| 出力・観測内容 | 次のアクション |
|--------------|--------------|
| 「Made using [製品名] [バージョン]」等の文字列 | 製品名そのままを `searchsploit` に渡す |
| 「Powered by WordPress」等 | バージョンも確認してから `searchsploit wordpress [バージョン]` |
| ヘッダーに `X-Powered-By: ASP.NET` | Windows 確定 → Windows 攻撃手法へ |
| フッターに著作権年のみ（製品名なし） | ページソース全体を `grep` してフレームワーク痕跡を探す |
| **`Server: Werkzeug/x.x.x Python/x.x.x`** | **Python WSGI 系（典型は Flask）。デバッグモードのコンソール露出（`/console` PIN 認証バイパス）・任意ルート存在を確認。テストデプロイ・社内ツール・小規模 API でよく見られる** |
| **`Server: gunicorn/x.x.x` / `Server: uWSGI`** | **Python WSGI 系（Django / Flask 等）。バックエンドを特定したら `/admin` `/static/admin/css/base.css` 等で Django 判定、Cookie 名（`csrftoken` / `sessionid`）でも識別可能** |
| **`Server: Tornado/x.x.x`** | **Python 非同期 Web フレームワーク。WebSocket 系の機能・XSRF Cookie の確認** |
| **`Server: WSGIServer/x.x Python/x.x`** | **Django 開発サーバー（`runserver`）。本番に上がっている場合は `DEBUG=True` で詳細スタックトレースが出ることがある → エラーページ叩いて環境変数・SECRET_KEY 漏洩を確認** |
| **非標準ポート（5000 / 8000 / 8080 / 3000）に Python 系サーバー** | **開発・社内ツール・PoC 段階のアプリの可能性。認証薄め・入力検証ないことが多い → 入力フィールド全部に XSS / コマンドインジェクションを試す価値あり** |

### 刺さらなかったとき
- アプリ名がどこにも見つからない → ディレクトリ列挙で `/wp-admin`・`/admin`・`/phpmyadmin` 等の CMS 固有パスが見つかればそこから推定する
- searchsploit にヒットしない → Google で `"[製品名] exploit"` または `"[製品名] CVE"` を検索する

---

## Webアプリのバージョン特定と CVE 検索

### 着火条件
Webサービスが動いており、使用しているアプリケーション（Grafana, WordPress, Jenkins, GitLab 等）が特定できた場合。
バージョンが判明すれば既知 CVE を検索できる可能性がある。

### 観点・着眼点
**バージョンを確認できたら、ディレクトリ列挙より先に CVE 検索を行う。**
既知の重大脆弱性（パストラバーサル / RCE 等）があれば、そちらが最短経路になることが多い。

### 手順

**よく使われるバージョン確認エンドポイント:**

```bash
# Grafana
curl -s http://[IP]:[PORT]/api/health
# → {"commit":"...","database":"ok","version":"8.0.0"}

# 汎用: HTTP ヘッダーにバージョンが含まれることがある
curl -sI http://[IP]/ | grep -i "server\|x-powered-by\|x-version"

# ログインページやエラーページにバージョン表記がある場合
curl -s http://[IP]/login | grep -i "version\|v[0-9]"
```

**searchsploit で CVE を検索:**

```bash
# アプリ名 + バージョンで検索
searchsploit grafana 8.0

# CVE 番号がわかっている場合
searchsploit CVE-2021-43798

# エクスプロイトの内容を確認
searchsploit -x [PATH_FROM_RESULTS]

# 作業ディレクトリにコピー
searchsploit -m [PATH_FROM_RESULTS]
```

**NVD / GitHub でも確認:**

- https://nvd.nist.gov/vuln/search → バージョン + アプリ名で検索
- `site:github.com [アプリ名] [バージョン] exploit` または `CVE-[年]-[番号]`

### 注意点・落とし穴
- バージョンがページに表示されていない場合でも、`/robots.txt`・ソースのコメント・エラーメッセージに含まれることがある
- searchsploit の結果が古い PoC の場合、コードを読んで必要なパラメータ修正を行ってから実行する
- CVE がなくても「設定ファイルのデフォルト認証情報」（admin:admin 等）を試すことも忘れずに

### 関連技術
- searchsploit の詳細 → `../05_Tools_Reference/Searchsploit.md`
- 見つかった脆弱性がパストラバーサルの場合 → `../02_Initial_Access/Web_Vulnerabilities/Path_Traversal.md`

---
## Cookie の分類：third-party 除外と first-party テスト対象の絞り込み

### 着火条件

Webアプリの Cookie を確認し、「どれをテストすべきか」を素早く絞り込みたい場合。
Cookie が 20 個以上あって GA / Cloudflare / Akamai 等の third-party が混在していると、
テスト対象が埋もれる。

### 観点・着眼点

**先に確認すること：** 対象ドメインの Cookie を全件取得する前に、
プロキシ（Burp 等）でキャプチャした Raw リクエストの `Cookie:` ヘッダーに
third-party ベンダー名が分かる接頭辞（`_ga` / `_fbp` / `__cf_bm` 等）がすでに見えているか確認する。

**攻撃者の思考トレース：** third-party Cookie はセッション・認可・ビジネスロジックに関与しない。
「自社アプリが発行している Cookie だけ」に絞ることで、HttpOnly 欠落・Secure 欠落・弱い値など
本質的な問題に集中できる。

**分類の判断基準：**

| Cookie 名のパターン | 判断 |
|--------------------|------|
| `_ga` / `_ga_*` / `_gid` / `_gat_*` | Google Analytics → third-party、除外 |
| `__cf_bm` / `cf_clearance` / `__cfduid` | Cloudflare → third-party、除外 |
| `_abck` / `bm_sv` / `ak_bmsc` | Akamai Bot Manager → third-party、除外 |
| `_fbp` / `_fbc` | Meta/Facebook → third-party、除外 |
| `AWSELB` / `AWSALB` | AWS ELB スティッキーセッション → インフラ、除外 |
| `JSESSIONID` / `PHPSESSID` / `session` / `token` 等 | 自社 → **テスト対象** |
| 上記パターンに一致しない未知の名前 | 自社の可能性 → **テスト対象** |

**third-party を除外した後に確認すること：**

| 確認観点 | シグナル | 次のアクション |
|---------|---------|-------------|
| HttpOnly が付いていない | JS から読み取り可能 → XSS と組み合わせてトークン窃取できる | XSS の有無を確認 → `../02_Initial_Access/Web_Vulnerabilities/XSS.md` |
| Secure が付いていない | HTTP でも送信される | HTTP Strict-Transport-Security の有無も確認 |
| SameSite が None + Secure 欠落 | CSRF の余地 | CSRF トークンの有無・有効性を確認 |
| Cookie 値が Base64 / JWT 形式 | デコードで内部情報（user_id・role 等）が見える可能性 | 多重エンコード剥がし → `../02_Initial_Access/Web_Vulnerabilities/JS_Obfuscation.md`（多重エンコードセクション）|
| Expires / Max-Age が極端に長い（1 年超） | 長期有効なトークンはローテーションされない可能性 | トークン値の予測可能性・固定値かどうかを確認 |

### 手順

**事前準備（必須）：** プロキシを通じてキャプチャしたリクエストを `.txt` 等のファイルに保存しておく。

```bash
# [Attacker] Burp の "Save item" や "Copy as curl" 等で取得した
# Raw HTTP リクエストを request.txt として保存済みの場合

# cookie_classify.py（別途入手・Python 3 標準ライブラリのみ）で分類
python cookie_classify.py request.txt
# → "Unknown / likely first-party" に列挙されたものがテスト対象

# Cookie 文字列を直接渡す場合
python cookie_classify.py --cookie "sessionid=abc; _ga=GA1.2.xxx; __cf_bm=yyy"

# third-party 側も確認したい場合
python cookie_classify.py request.txt --show-thirdparty

# DevTools で確認する場合（ツール不要）
# F12 → Application → Storage → Cookies → 左ペインのドメイン別ツリーで
# 自社ドメイン配下 vs 外部ドメイン配下を目視で分類する
```

### 刺さらなかったとき

- Cookie が 1〜2 本しかなく third-party が混在していない → 全件をそのままテスト対象にする
- ドメイン直下に third-party Cookie がない（CDN / SPA 構成等）→ `localStorage` / `sessionStorage` に認証トークンが入っている可能性を DevTools で確認する

### 注意点・落とし穴

- `__Secure-` / `__Host-` 接頭辞の Cookie は Cookie Prefix（ブラウザの強制 Secure/Path 制限）を意味する。脆弱性として報告する前にブラウザ側の保護が有効かを確認する
- Cookie 名だけで判断できないケース（例：社内製ツールが `_ga_[ID]` 風の名前を偶然使っている）は、Cookie 値の形式と発行タイミング（ログイン前から存在するか）も合わせて判断する

### 関連技術

- 前：このファイル「Webアプリのフレームワーク・アプリ名の特定」（Cookie 名からの CMS 識別）
- 後：`../02_Initial_Access/Web_Vulnerabilities/XSS.md`（HttpOnly 欠落の悪用）
- 後：`../02_Initial_Access/Web_Vulnerabilities/JS_Obfuscation.md`（Base64 / JWT 形式の Cookie 値の多重デコード）
- 後：`./Web_Response_Triage.md`（Cookie 属性・セキュリティヘッダー・機微情報の一括スキャン）

> 原理（なぜ third-party Cookie の除外が重要か・Cookie Prefix の仕様） → `../06_Concepts/Web_Pentest_Tooling.md`

---

### 関連技術

- 前：`./Network_Scanning.md`（Webポートの発見）
- 前：`./DNS_Enumeration.md`（ドメイン渡しでサブドメイン・vhost を列挙してから Web へ）
- 後：`./TLS_Audit.md`（HTTPS で動作している場合のプロトコル/暗号/証明書監査・SAN からの vhost 抽出）
- 後：`./Exposed_Files.md`（バックアップ・設定ファイル・`.git/`・ディレクトリリスティング等の誤公開検出）
- 後：`../02_Initial_Access/Default_Credentials.md`（管理画面・ログインフォーム・特定製品のデフォルト認証情報試行）
- 後：`../02_Initial_Access/Account_Lockout_Recon.md`（ログインフォームに対する辞書攻撃前のロックアウトポリシー事前確認）
- 後：`../02_Initial_Access/Web_Vulnerabilities/IDOR.md`（連番IDを発見した場合）
- 後：`../02_Initial_Access/Web_Vulnerabilities/SQLi.md`（ログインフォームを発見した場合）
- 後：`../05_Tools_Reference/Searchsploit.md`（バージョン確認後の CVE 検索）
- 後：`../02_Initial_Access/Edge_Appliance_CVEs.md`（ログイン HTML タイトル / URL パス / favicon ハッシュ / Server ヘッダーがアプライアンス製品と一致した場合、ベンダー別既知 CVE 照合へ）
