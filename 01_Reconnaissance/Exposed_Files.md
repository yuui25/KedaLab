# 誤公開ファイル・ディレクトリの確認

## このファイルの位置づけ

バックアップファイル・設定ファイル・バージョン管理ディレクトリ・API 仕様ファイル・ディレクトリリスティング等、
**「Web サーバーに置きっぱなしになっている、置いてはいけないもの」**を検出するための着眼点・手順を集約する。
発見後の内容解析（クレデンシャル抽出・ソースコード復元等）の手順は別ファイルに任せ、ここは「どこを見て、どう拾うか」に徹する。

---

## 誤公開ファイル列挙の全体像

### 着火条件

Web サービスが応答しており、以下のいずれかに該当する。

- ディレクトリ列挙（gobuster / ffuf）後、ヒットしなかった隠しパス候補を網羅したい
- Web アプリのフレームワークが判明し、そのフレームワーク固有の誤公開パスを当たりたい
- `Server:` ヘッダーから Apache / Nginx / IIS が判明し、サーバー固有の機能（server-status / .htaccess / web.config）の誤公開を確認したい
- 開発系 FQDN（`dev.` / `staging.` / `test.`）が判明し、本番より緩い設定での誤公開を狙いたい

### 環境前提

- 実行環境：テスター端末
- 必要なツール：
  - `gobuster` / `ffuf` / `wfuzz`（ペネトレ用 Linux ディストリ標準。ディレクトリ列挙）
  - `curl`（標準搭載。手動検証）
  - `git-dumper`（別途インストール要、`pip install --user git-dumper --break-system-packages`。`.git/` 露出時のリポジトリ復元用）
  - `nuclei`（別途インストール要、`go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`。`exposures/` カテゴリのテンプレートが誤公開検出に強い。インターネット遮断 VLAN では事前テンプレートを同梱しておく）
  - `seclists`（別途インストール要だがペネトレ用 Linux ディストリには大抵パッケージ済み。`/usr/share/seclists/Discovery/Web-Content/` 配下のワードリストを利用）

### 観点・着眼点

**先に確認すること：**

- ディレクトリリスティングが有効かどうか（有効ならファイル列挙が一瞬で終わる）
- 404 が「素の 404」か「カスタム 404 で 200 を返している」か（ステータスコードと本文長で峻別）
- WAF / IPS のレート制限（`Web_Enumeration.md` の「症状別対処」表を参照）

**攻撃者の思考トレース：** 誤公開は「開発者が放置した跡」が大半。
**「開発フェーズの何かが残っていそうな場所」を狙う：**
バージョン管理ディレクトリ（`.git/` / `.svn/`）、デプロイ前の設定ファイル（`.env` / `config.php.bak`）、
動作確認用ファイル（`phpinfo.php` / `test.html`）、ツールが自動生成するメタファイル（`.DS_Store` / `Thumbs.db`）。
**本番固有の機能ではなく開発時の副産物を見る。**

**確認する誤公開カテゴリ（優先順位順）：**

| カテゴリ | 代表パス | 拾える情報 |
|---------|---------|----------|
| **クローラー向けヒント** | `/robots.txt` / `/sitemap.xml` / `/sitemap_index.xml` | 管理パス・除外パス（`Disallow:` がそのまま隠しパス漏洩）・全 URL リスト |
| バージョン管理ディレクトリ | `/.git/` / `/.svn/` / `/.hg/` / `/.bzr/` | ソースコード全体（git-dumper 等で復元） |
| 環境変数 / 設定ファイル | `/.env` / `/.env.local` / `/.env.production` / `/config.php` / `/database.yml` / `/settings.py` | DB 接続情報・API キー・SECRET_KEY |
| バックアップファイル | `index.php.bak` / `config.php~` / `*.old` / `*.save` / `*.swp` / `*.swo` / `*.tar.gz` / `*.zip` / `*.sql` | 旧バージョンのソース・DB ダンプ |
| サーバー設定ファイル | `/.htaccess` / `/.htpasswd` / `/web.config` / `/nginx.conf` | ルーティング・認証設定・内部パス |
| 動作確認用ファイル | `/phpinfo.php` / `/info.php` / `/test.php` / `/server-info` / `/server-status` | PHP 設定・Apache 内部状態・実 IP・モジュール構成 |
| API 仕様ファイル | `/swagger.json` / `/openapi.json` / `/api-docs` / `/v2/api-docs` / `/swagger-ui/` | 全 API エンドポイント仕様（裏 API の発見）|
| **`.well-known/` 配下** | `/.well-known/security.txt` / `/.well-known/openid-configuration` / `/.well-known/assetlinks.json` / `/.well-known/apple-app-site-association` | セキュリティ連絡先・OIDC エンドポイント全列挙・Android アプリ連携・iOS アプリ連携 |
| **クロスドメインポリシー** | `/crossdomain.xml` / `/clientaccesspolicy.xml` | Flash / Silverlight 用の許可元設定（`<allow-access-from domain="*">` の wildcard は古い CORS 緩和の名残・**今でも残存している**） |
| エディタ・OS のメタファイル | `/.DS_Store` / `/Thumbs.db` / `/.idea/` / `/.vscode/` | ディレクトリ内ファイル名一覧 |
| ディレクトリリスティング | 任意のディレクトリ末尾 `/` | そのディレクトリ内の全ファイル一覧 |
| 管理コンソール / モニタリング | `/manager/html`（Tomcat）/ `/jmx-console`（JBoss）/ `/actuator/`（Spring）/ `/admin/` | 管理機能の誤公開 |
| ログファイル | `/access.log` / `/error.log` / `/debug.log` / `/laravel.log` | リクエスト履歴・スタックトレース |
| **クラウドストレージ誤公開** | `https://[BUCKET].s3.amazonaws.com/` / `https://[ACCOUNT].blob.core.windows.net/[CONTAINER]/` / `https://storage.googleapis.com/[BUCKET]/` | バケット直接アクセスでの非公開オブジェクト読取 |

---

## カテゴリ別の確認手順

### クローラー向けヒント（robots.txt / sitemap.xml）

最初に当てる定石。`Disallow:` で除外されているパスがそのまま「隠したい場所＝面白い場所」のヒントになる。

```bash
# robots.txt — 管理者が「クローラーに見せたくない」と思った場所が列挙される（皮肉）
curl -s http://[TARGET]/robots.txt   # [Attacker]
# 出力例:
# User-agent: *
# Disallow: /admin/
# Disallow: /backup/
# Disallow: /api/internal/   ← これらを順に当てる

# sitemap.xml — 全公開 URL のリスト（裏 URL が含まれていることがある）
curl -s http://[TARGET]/sitemap.xml | grep -oE '<loc>[^<]+' | sed 's|<loc>||'   # [Attacker]
curl -s http://[TARGET]/sitemap_index.xml   # [Attacker]   # 分割 sitemap のインデックス
```

**読み方:** `robots.txt` の `Disallow:` は **アクセス禁止**ではなく **クローラーへのお願い**にすぎない。攻撃者から見れば「ここを見ろ」というヒントマップ。`sitemap.xml` も同様に SEO 用の全 URL リストで、ペネトレ的には「Web 列挙では出てこないが管理者が把握している URL」が混入していることがある。

### `.well-known/` 配下

RFC 8615 で定義された規定パス。OIDC や Android / iOS の deeplink 連携で必須のため、近年は出現率が高い。

```bash
# 代表エンドポイント
for p in security.txt openid-configuration jwks.json assetlinks.json apple-app-site-association \
         change-password mta-sts.txt openpgpkey; do
  curl -s -o /dev/null -w "%{http_code}  %{size_download}  $p\n" "http://[TARGET]/.well-known/$p"
done   # [Attacker]

# openid-configuration が見つかったら OIDC エンドポイント全列挙
curl -s http://[TARGET]/.well-known/openid-configuration | jq .   # [Attacker]
# → authorization_endpoint / token_endpoint / jwks_uri / userinfo_endpoint / introspection_endpoint
# → JWT 攻撃の足掛かり: ../02_Initial_Access/Web_Vulnerabilities/JWT_Attacks.md / OAuth_Attacks.md
```

| パス | 拾える情報 |
|---|---|
| `security.txt` | セキュリティ連絡先（VDP / Bug Bounty 範囲の確認に） |
| `openid-configuration` | OIDC 全エンドポイント・サポート algorithm（`HS256` 許容なら署名混乱攻撃の候補）|
| `jwks.json` | JWT 公開鍵（kid 構造の確認・JWKS injection 攻撃の起点） |
| `assetlinks.json` | Android アプリと連携している Web の関係（モバイル攻撃面の入口） |
| `apple-app-site-association` | iOS Universal Links 設定（同上）|
| `mta-sts.txt` | メールサーバーポリシー（MX 経路の確認） |

### クロスドメインポリシー（crossdomain.xml / clientaccesspolicy.xml）

Flash / Silverlight 時代の遺物だが、`<allow-access-from domain="*">` の wildcard 構成が今でも残存している。SOAP / 旧 RIA との互換性で削れず残されていることが多い。

```bash
curl -s http://[TARGET]/crossdomain.xml   # [Attacker]
curl -s http://[TARGET]/clientaccesspolicy.xml   # [Attacker]
```

**読み方:**

- `<allow-access-from domain="*"/>` → 任意オリジンからの認証付きリクエスト許容（**finding**・CORS 設定の緩和と同類のリスク）
- `<allow-http-request-headers-from domain="*" headers="*"/>` → 任意ヘッダー送信許容
- 現代ブラウザは Flash / Silverlight を切っているが、**SOAP クライアント・古い社内ツール経由で悪用される可能性**は残る

### クラウドストレージ誤公開（S3 / Azure Blob / GCS）

Web ホストの裏で利用しているクラウドストレージのバケットが未認証で公開されているケース。FQDN・サブドメイン・コミットログから bucket 名を推測する。

```bash
# AWS S3 — 未認証 ls
aws s3 ls s3://[BUCKET_NAME] --no-sign-request   # [Attacker]
aws s3 cp s3://[BUCKET_NAME]/[OBJECT] - --no-sign-request   # [Attacker]   # 単一オブジェクト取得

# ブラウザ / curl 直接（バケット listing が返るパターン）
curl -s https://[BUCKET_NAME].s3.amazonaws.com/   # [Attacker]
curl -s https://s3.amazonaws.com/[BUCKET_NAME]/   # [Attacker]   # 旧形式

# Azure Blob Storage — コンテナ listing
curl -s "https://[ACCOUNT_NAME].blob.core.windows.net/[CONTAINER_NAME]?restype=container&comp=list"   # [Attacker]

# Google Cloud Storage
curl -s "https://storage.googleapis.com/storage/v1/b/[BUCKET_NAME]/o"   # [Attacker]
gsutil ls gs://[BUCKET_NAME]/   # [Attacker]   # 認証無しでも動く場合あり

# Bucket 名の推測パターン
for prefix in "" "dev-" "staging-" "prod-" "backup-" "logs-" "assets-" "uploads-"; do
  for suffix in "" "-dev" "-staging" "-prod" "-backup" "-logs"; do
    name="${prefix}[ORG_NAME]${suffix}"
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://${name}.s3.amazonaws.com/")
    echo "$code  $name"
  done
done   # [Attacker]
```

**注意:** Bucket 名のスキャンは AWS / Azure / GCP 全体に対する横断試行になるため、**対象組織が所有していない bucket への試行は不正アクセス扱いになり得る**。スコープに明示されている bucket 名・ドメインから推測可能な範囲に限定する。

### バージョン管理ディレクトリの露出

`.git/` が残っている場合、リポジトリ全体を復元できる。**Web ペネトレで最大の戦果のひとつ**。

```bash
# 存在確認（HEAD が読めれば露出確定）
curl -s -o /dev/null -w "%{http_code}\n" http://[TARGET]/.git/HEAD   # [Attacker]
curl -s http://[TARGET]/.git/HEAD   # [Attacker]
# 期待出力: ref: refs/heads/main   ← この行が見えたら .git/ 露出確定

# 設定ファイルも確認（URL / リモート情報が出ることがある）
curl -s http://[TARGET]/.git/config   # [Attacker]

# git-dumper でリポジトリ復元
git-dumper http://[TARGET]/.git/ ./dumped_repo   # [Attacker]

# 復元後、過去コミットも含めて grep
cd ./dumped_repo
git log --all --oneline
git log -p --all | grep -iE "password|secret|api_key|token|aws_access"   # [Attacker]
```

**git-dumper が部分的に WAF で弾かれる場合の代替:**

```bash
# go-git-dumper — Go 実装で並列度高め
go install github.com/wnoa/go-git-dumper@latest
go-git-dumper http://[TARGET]/.git/ ./dumped_repo2

# GitTools の Dumper + Extractor（古典・index/pack 構造の解釈に強い）
# https://github.com/internetwache/GitTools
./gitdumper.sh http://[TARGET]/.git/ ./dumped_repo3
./extractor.sh ./dumped_repo3 ./extracted

# どれも `index` / `packed-refs` の取得可否で結果が分かれる。3 種類試して取れる範囲が最も広いものを採用
```

**`.svn/` / `.hg/` も同様の発想：**

| パス | 復元ツール |
|------|----------|
| `/.svn/entries`（旧 SVN）/ `/.svn/wc.db`（新 SVN） | `svn-extractor.py` 等 |
| `/.hg/` | `hg-dumper`、または `wget -r` で全体取得後 `hg log` |

### 環境変数 / 設定ファイル

```bash
# よくある名前を順に当てる
for p in .env .env.local .env.production .env.development .env.backup \
         config.php config.php.bak config.php~ wp-config.php wp-config.php.bak \
         database.yml settings.py local_settings.py; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://[TARGET]/$p")
  echo "$code  $p"
done   # [Attacker]
```

**`.env` 内の典型的なキー：**

```
APP_KEY=...
DB_HOST=...
DB_DATABASE=...
DB_USERNAME=...
DB_PASSWORD=...
MAIL_PASSWORD=...
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
JWT_SECRET=...
```

→ 内容解析の詳細は `../02_Initial_Access/Credential_Discovery.md` の「Web アプリ .env ファイルからの認証情報取得」セクションへ。

### バックアップファイル

エディタや管理者の操作で生成される拡張子バリエーションを総当たりする。

```bash
# 基幹ファイルのバックアップを当てる（拡張子バリエーション）
for base in index login config admin db backup users; do
  for ext in .bak .old .save .swp .swo "~" .orig .copy ".bak.txt"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "http://[TARGET]/${base}${ext}")
    echo "$code  ${base}${ext}"
  done
done   # [Attacker]

# 圧縮形式のフルバックアップ
for f in backup.zip backup.tar.gz site.zip www.tar.gz db.sql db.sql.gz dump.sql; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://[TARGET]/$f")
  echo "$code  $f"
done   # [Attacker]
```

**vim のスワップファイル `.swp` 命名規則：**

vim で開いていた `index.php` のスワップは `.index.php.swp`（先頭ドット + 元ファイル名 + `.swp`）。これも候補に入れる。

### サーバー設定ファイル

```bash
curl -s http://[TARGET]/.htaccess   # [Attacker]
curl -s http://[TARGET]/.htpasswd   # [Attacker]
curl -s http://[TARGET]/web.config   # [Attacker]
curl -s http://[TARGET]/nginx.conf   # [Attacker]
```

**読み方：**

- `.htaccess`：`RewriteRule` から内部ルーティングが判明、`AuthType Basic` の参照先 `AuthUserFile` パスが手がかり
- `.htpasswd`：Basic 認証のユーザー名 + bcrypt/MD5/crypt ハッシュ。即 `hashcat` 候補
- `web.config`：ASP.NET / IIS の設定。`<connectionStrings>` に DB 接続情報、`<machineKey>` が `__VIEWSTATE` 攻撃の足掛かり
- `nginx.conf`：`server_name` / `proxy_pass` から内部サービスの存在判明

### 動作確認用ファイル（phpinfo 等）

```bash
for f in phpinfo.php info.php test.php pinfo.php p.php phpinfo phpinfo.html; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://[TARGET]/$f")
  echo "$code  $f"
done   # [Attacker]
```

**`phpinfo()` 出力で見るべき項目：**

| 項目 | 拾える情報 |
|------|----------|
| `_SERVER["SERVER_ADDR"]` | 実 IP（CDN 配下なら裏の IP） |
| `_SERVER["DOCUMENT_ROOT"]` | サーバー上のフルパス（パストラバーサル攻撃で有用） |
| `disable_functions` | 使えなくされている関数（RCE 時の制約） |
| `allow_url_include` / `allow_url_fopen` | RFI 可否 |
| `Loaded Modules` | OpenSSL / curl / GD のバージョン |
| `$_ENV` / `Environment` | 環境変数（クレデンシャル混入の有無） |

**Apache の server-status / server-info：**

```bash
curl -s http://[TARGET]/server-status   # [Attacker]
curl -s http://[TARGET]/server-info   # [Attacker]
# server-status: 直近アクセスの URL / IP / リクエスト一覧（他クライアントの操作が観察できる）
# server-info: モジュール一覧 / 設定詳細
```

### API 仕様ファイル

```bash
# Swagger / OpenAPI の典型パス
for p in swagger.json swagger.yaml openapi.json openapi.yaml \
         api-docs v2/api-docs v3/api-docs \
         swagger-ui/ swagger-ui.html swagger/index.html \
         docs/ api/docs api/swagger; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://[TARGET]/$p")
  echo "$code  $p"
done   # [Attacker]

# JSON 形式が見つかったら一括で全エンドポイントを取り出す
curl -s http://[TARGET]/swagger.json | jq -r '.paths | keys[]'   # [Attacker]
```

API 仕様ファイルが露出している場合、**Web 列挙では出てこない裏 API**（`/api/internal/*` / `/api/admin/*` 等）が即時判明する。

### エディタ・OS のメタファイル

```bash
# .DS_Store（macOS）: バイナリだが内部にファイル名が ASCII で含まれる
curl -s http://[TARGET]/.DS_Store -o ds_store && strings ds_store | sort -u   # [Attacker]

# .idea / .vscode（IDE 設定。プロジェクト構造のヒント）
curl -s http://[TARGET]/.idea/workspace.xml   # [Attacker]
curl -s http://[TARGET]/.vscode/settings.json   # [Attacker]

# Thumbs.db（Windows）
curl -s -o thumbs http://[TARGET]/Thumbs.db && strings thumbs   # [Attacker]
```

### ディレクトリリスティング

```bash
# まず手動で末尾 / を付けて確認
curl -s http://[TARGET]/uploads/   # [Attacker]
curl -s http://[TARGET]/files/   # [Attacker]
curl -s http://[TARGET]/backup/   # [Attacker]
```

**ディレクトリリスティングが有効な場合のシグナル：**

| サーバー | レスポンス本文の特徴 |
|---------|------------------|
| Apache（`autoindex` 有効） | `<title>Index of /[PATH]</title>` / `[ICO]` / `Parent Directory` |
| Nginx（`autoindex on`） | `<h1>Index of /[PATH]/</h1>` / `<pre><a href="../">../</a>` |
| IIS | `<pre>` 内に `[ファイル名] [日時] [サイズ]` の表形式 |
| Tomcat | `Directory: /[PATH]` |
| Python `http.server` | `<title>Directory listing for /[PATH]</title>` |

**ヒットしたら即やること：**

1. 一覧から拡張子の珍しいファイル（`.sql` / `.bak` / `.tar.gz` / `.pem` / `.key`）を最優先で取得
2. 同じディレクトリの上位（`../`）も末尾スラッシュで確認

### 管理コンソール / モニタリング

```bash
# Tomcat
curl -s http://[TARGET]:8080/manager/html   # [Attacker]
# 401 が返れば Basic 認証あり → デフォルト認証情報を当たる
# → ../02_Initial_Access/Default_Credentials.md

# JBoss / WildFly
curl -s http://[TARGET]:8080/jmx-console/   # [Attacker]
curl -s http://[TARGET]:9990/console/   # [Attacker]

# Spring Boot Actuator
for p in actuator actuator/env actuator/health actuator/heapdump actuator/mappings actuator/info; do
  curl -s "http://[TARGET]/$p"   # [Attacker]
done

# Jenkins
curl -s http://[TARGET]:8080/manage   # [Attacker]
curl -s http://[TARGET]:8080/script   # [Attacker]   # Groovy console（認証突破時に RCE）

# Kibana / Elasticsearch
curl -s http://[TARGET]:5601/app/kibana   # [Attacker]
curl -s http://[TARGET]:9200/_cat/indices?v   # [Attacker]
```

`actuator/env` や `actuator/heapdump` は **クレデンシャルが平文で出ることがある最有力誤公開**。

### nuclei での一括チェック

```bash
# exposures カテゴリ（誤公開検出テンプレート）
nuclei -t exposures/ -u https://[TARGET]   # [Attacker]

# 範囲を絞る（バックアップ / 設定ファイル / トークン）
nuclei -t exposures/backups/ -t exposures/configs/ -t exposures/tokens/ -u https://[TARGET]   # [Attacker]
```

**シグナルと次のアクション：**

| nuclei 出力 | 次のアクション |
|------------|--------------|
| `exposures/configs/dotenv-cred-files` ヒット | 即 `.env` 取得 → `../02_Initial_Access/Credential_Discovery.md` |
| `exposures/files/git-config` / `exposed-git-folder` | `git-dumper` でリポ復元 |
| `exposures/configs/exposed-spring-actuator` | `/actuator/env` `/heapdump` を順に取得 |
| `exposures/apis/swagger-api` | `swagger.json` を取得して裏 API を列挙 |
| `exposures/logs/*` | ログから内部 IP / ユーザー名 / スタックトレース抽出 |

---

## 刺さらなかったとき

| 観測される症状 | 推定原因 | 対処 |
|--------------|---------|------|
| 何を当てても全て 200 が返る | カスタム 404 ハンドラ。本文長で判別する必要あり | (a) `curl -s -o /dev/null -w "%{http_code} %{size_download}\n"` で本文長も出力、ベースラインと差分を取る。(b) ffuf の自動キャリブレーション `ffuf -ac -w [WORDLIST] -u http://[TARGET]/FUZZ`（ランダム文字列で baseline を自動推定して同サイズを除外）。(c) `ffuf -fw [WORD_COUNT]` / `-fl [LINE_COUNT]` / `-fs [BYTE_SIZE]` でベースラインを明示除外 |
| 全て 403 で本文も同じ | WAF が誤公開検知パターンを一括ブロックしている | パスを URL エンコード / 大文字混在 / 末尾スラッシュ追加で揺らす |
| `.git/HEAD` だけ 200、`.git/config` 等は 403 | 部分的に WAF ルールがある。HEAD だけ通って他はブロック | `git-dumper` を当てる前に `index` / `packed-refs` の取得可否を確認、不可なら諦めて他の誤公開へ |
| ディレクトリリスティングが効かない | サーバーで `autoindex off`（Nginx）/ `Options -Indexes`（Apache）/ デフォルトドキュメントあり（IIS） | デフォルトドキュメント名（`index.html` / `default.aspx`）を直接取得して中身からヒントを得る、ワードリスト列挙に戻る |
| nuclei が大量の偽陽性を出す | 共通の WAF が任意パスで類似レスポンスを返している | 個別ヒットを `curl -s` で必ず手動再現してから採用 |
| Web ルートで何も出ないが、判明している vhost で出る | リスティング・誤公開がサブドメインに偏在 | TLS_Audit で発見した SAN・vhost ファジングで判明した FQDN を全部総当たり |

---

## 注意点・落とし穴

- **誤公開ファイル列挙は本文を取得するため通信量がディレクトリ列挙より増えやすい。** `.tar.gz` 等を不用意にダウンロードすると数 GB のトラフィックになる。HEAD リクエスト（`curl -I`）でサイズ確認してから GET に切り替える
- **`.git/` ダンプ前に履歴ファイル（`packed-refs` / `index`）の取得可否を確認する。** これらが 403 だと `git-dumper` が部分的にしか復元できない。中途半端な復元は時間を浪費するだけなので、見切りを早く付ける
- **`server-status` / `server-info` は他クライアントの実 URL が観測できる。** ただし「自分のリクエストパターン」も他者から見えていることを意識する（証跡を残しすぎない）
- **`actuator/heapdump` は数十〜数百 MB になる。** 取得後はオフラインで `strings` / `grep -aE "password|token"` で抽出する。ライブ環境への影響は読み取り 1 回のみに留める
- **`.DS_Store` / `Thumbs.db` を読むだけではディレクトリ一覧しか得られない。** 一覧から実ファイルを順に取得する手順までセットで行う
- **`config.php` 等が「200 で空白」を返す場合、PHP として実行されている可能性がある。** 拡張子をズラした名前（`config.php.bak` / `config.php~`）が本命
- **誤公開対応として WAF ルールが追加されている対象では、`.env` を直接当てても 403、`/%2e%2fenv` 等のエンコーディング揺らしが効くことがある。** 当て方を変えてから諦める

---

## 関連技術

- 前：`./Network_Scanning.md`（Web ポートの発見）
- 前：`./Web_Enumeration.md`（フレームワーク特定後、そのフレームワーク固有の誤公開パスへ）
- 前：`./TLS_Audit.md`（SAN から判明した FQDN 群を誤公開ファイル探索の対象にする）
- 後：`../02_Initial_Access/Credential_Discovery.md`（`.env` / `.git/` / `.htpasswd` から取り出した認証情報の処理）
- 後：`../02_Initial_Access/Default_Credentials.md`（Tomcat / JBoss / Jenkins 等の管理コンソールが見つかった場合のデフォルト認証情報試行）
- 後：`../02_Initial_Access/Web_Vulnerabilities/Path_Traversal.md`（`phpinfo` で `DOCUMENT_ROOT` 判明後・Apache CVE-2021-41773 / CVE-2021-42013 で `.htaccess` 直読みの経路）
- 後：`../02_Initial_Access/Web_Vulnerabilities/JWT_Attacks.md`（`.well-known/openid-configuration` / `jwks.json` 取得後）
- 後：`../02_Initial_Access/Web_Vulnerabilities/OAuth_Attacks.md`（OIDC エンドポイント特定後）
- 後：`../05_Tools_Reference/Searchsploit.md`（誤公開された設定ファイルから判明した製品/バージョンで CVE 検索）
