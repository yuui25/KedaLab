# 誤公開ファイル・ディレクトリの確認

> **スコープ**: バックアップ・設定ファイル・バージョン管理ディレクトリ・API 仕様・ディレクトリリスティング・管理コンソール等、「Web サーバーに置きっぱなしになっている、置いてはいけないもの」の検出に徹する。発見後の内容解析（クレデンシャル抽出・ソースコード復元等）は `../02_Initial_Access/Credential_Discovery.md` 等に委ね、ここは「どこを見て、どう拾うか」を扱う。

## 着火条件

Web サービスが応答しており、以下のいずれかに該当する。

- ディレクトリ列挙（gobuster / ffuf）後、ヒットしなかった隠しパス候補を網羅したい
- Web アプリのフレームワークが判明し、そのフレームワーク固有の誤公開パスを当たりたい
- `Server:` ヘッダーから Apache / Nginx / IIS が判明し、サーバー固有の機能（server-status / .htaccess / web.config）の誤公開を確認したい
- 開発系 FQDN（`dev.` / `staging.` / `test.`）が判明し、本番より緩い設定での誤公開を狙いたい

## 環境前提

- 実行環境：テスター端末
- 必要なツール：
  - `gobuster` / `ffuf` / `wfuzz`（ペネトレ用 Linux ディストリ標準。ディレクトリ列挙）
  - `curl`（標準搭載。手動検証）
  - `git-dumper`（別途インストール要、`pip install --user git-dumper --break-system-packages`。`.git/` 露出時のリポジトリ復元用）
  - `nuclei`（別途インストール要、`go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`。`exposures/` カテゴリが誤公開検出に強い。インターネット遮断 VLAN では事前テンプレートを同梱しておく）
  - `seclists`（`/usr/share/seclists/Discovery/Web-Content/` 配下のワードリスト）

## 先に確認すること

- ディレクトリリスティングが有効かどうか（有効ならファイル列挙が一瞬で終わる。§12）
- 404 が「素の 404」か「カスタム 404 で 200 を返している」か（ステータスコードと本文長で峻別。§刺さらなかったとき）
- WAF / IPS のレート制限（`Web_Enumeration.md` の §4 を参照）

**確認する誤公開カテゴリ（優先順位順の早見表）:**

| カテゴリ | 代表パス | 拾える情報 | ブロック |
|---------|---------|----------|---|
| クローラー向けヒント | `/robots.txt` / `/sitemap.xml` | 管理パス・除外パス・全 URL リスト | §1 |
| バージョン管理ディレクトリ | `/.git/` / `/.svn/` / `/.hg/` | ソースコード全体（復元） | §5 |
| 環境変数 / 設定ファイル | `/.env` / `/config.php` / `/settings.py` | DB 接続情報・API キー・SECRET_KEY | §6 |
| バックアップファイル | `*.bak` / `*.old` / `*.tar.gz` / `*.sql` | 旧バージョンのソース・DB ダンプ | §7 |
| サーバー設定ファイル | `/.htaccess` / `/.htpasswd` / `/web.config` | ルーティング・認証設定・内部パス | §8 |
| 動作確認用ファイル | `/phpinfo.php` / `/server-status` | PHP 設定・Apache 内部状態・実 IP | §9 |
| API 仕様ファイル | `/swagger.json` / `/openapi.json` / `/api-docs` | 全 API エンドポイント仕様（裏 API）| §10 |
| `.well-known/` 配下 | `/.well-known/openid-configuration` 等 | OIDC エンドポイント・アプリ連携 | §2 |
| クロスドメインポリシー | `/crossdomain.xml` | Flash/Silverlight 許可元（wildcard 残存）| §3 |
| エディタ・OS メタファイル | `/.DS_Store` / `/.idea/` | ディレクトリ内ファイル名一覧 | §11 |
| ディレクトリリスティング | 任意ディレクトリ末尾 `/` | ディレクトリ内全ファイル一覧 | §12 |
| 管理コンソール / モニタリング | `/manager/html` / `/actuator/` | 管理機能の誤公開 | §13 |
| クラウドストレージ誤公開 | `[BUCKET].s3.amazonaws.com` 等 | 非公開オブジェクト読取 | §4 |

**攻撃者の思考トレース:** 誤公開は「開発者が放置した跡」が大半。本番固有の機能ではなく**開発時の副産物**（バージョン管理ディレクトリ・デプロイ前の設定ファイル・動作確認用ファイル・ツール生成メタファイル）を狙う。

---

## 1. クローラー向けヒント（robots.txt / sitemap.xml）

最初に当てる定石。`Disallow:` で除外されているパスがそのまま「隠したい場所＝面白い場所」のヒントになる。

**コマンド:**

```bash
# [Attacker] robots.txt — 管理者が「見せたくない」と思った場所が列挙される（皮肉）
curl -s http://[TARGET]/robots.txt
# 出力例: Disallow: /admin/ / Disallow: /api/internal/  ← これらを順に当てる

# [Attacker] sitemap.xml — 全公開 URL のリスト（裏 URL が混入することがある）
curl -s http://[TARGET]/sitemap.xml | grep -oE '<loc>[^<]+' | sed 's|<loc>||'
curl -s http://[TARGET]/sitemap_index.xml   # 分割 sitemap のインデックス
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `Disallow:` に管理/内部パス | 隠しパスの地図 | 各パスを順に当てる → 該当カテゴリのブロックへ |
| `sitemap.xml` に Web 列挙で出ない URL | 管理者だけが把握する URL | その URL を直接アクセス |

**注意:** `robots.txt` の `Disallow:` はアクセス禁止ではなくクローラーへのお願いにすぎない。攻撃者から見れば「ここを見ろ」のヒントマップ。

---

## 2. `.well-known/` 配下

RFC 8615 で定義された規定パス。OIDC や Android / iOS の deeplink 連携で必須のため出現率が高い。

**コマンド:**

```bash
# [Attacker] 代表エンドポイントを一括確認
for p in security.txt openid-configuration jwks.json assetlinks.json apple-app-site-association \
         change-password mta-sts.txt openpgpkey; do
  curl -s -o /dev/null -w "%{http_code}  %{size_download}  $p\n" "http://[TARGET]/.well-known/$p"
done

# [Attacker] openid-configuration が見つかったら OIDC エンドポイント全列挙
curl -s http://[TARGET]/.well-known/openid-configuration | jq .
# → authorization_endpoint / token_endpoint / jwks_uri / userinfo_endpoint / introspection_endpoint
```

**観測される出力 → 次のアクション:**

| パス | 拾える情報 | 次のアクション |
|---|---|---|
| `security.txt` | セキュリティ連絡先（VDP / Bug Bounty 範囲）| 連絡先確認 |
| `openid-configuration` | OIDC 全エンドポイント・サポート algorithm | `HS256` 許容なら署名混乱攻撃候補 → `../02_Initial_Access/Web_Vulnerabilities/OAuth_Attacks.md` |
| `jwks.json` | JWT 公開鍵（kid 構造）| JWKS injection の起点 → `../02_Initial_Access/Web_Vulnerabilities/JWT_Attacks.md` |
| `assetlinks.json` / `apple-app-site-association` | アプリ連携 | モバイル攻撃面の入口 |
| `mta-sts.txt` | メールサーバーポリシー | MX 経路の確認 |

**注意:** OIDC エンドポイントの列挙は JWT / OAuth 攻撃の足掛かりになる。

---

## 3. クロスドメインポリシー（crossdomain.xml / clientaccesspolicy.xml）

Flash / Silverlight 時代の遺物だが、`<allow-access-from domain="*">` の wildcard 構成が今でも残存している。SOAP / 旧 RIA との互換性で削れず残されていることが多い。

**コマンド:**

```bash
# [Attacker]
curl -s http://[TARGET]/crossdomain.xml
curl -s http://[TARGET]/clientaccesspolicy.xml
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `<allow-access-from domain="*"/>` | 任意オリジンからの認証付きリクエスト許容 | **finding**（CORS 緩和と同類のリスク）として記録 |
| `<allow-http-request-headers-from domain="*" headers="*"/>` | 任意ヘッダー送信許容 | 同上 |

**注意:** 現代ブラウザは Flash / Silverlight を切っているが、SOAP クライアント・古い社内ツール経由で悪用される可能性は残る。

---

## 4. クラウドストレージ誤公開（S3 / Azure Blob / GCS）

Web ホストの裏で利用しているクラウドストレージのバケットが未認証で公開されているケース。FQDN・サブドメイン・コミットログから bucket 名を推測する。

**コマンド:**

```bash
# [Attacker] AWS S3 — 未認証 ls / 取得
aws s3 ls s3://[BUCKET_NAME] --no-sign-request
aws s3 cp s3://[BUCKET_NAME]/[OBJECT] - --no-sign-request
curl -s https://[BUCKET_NAME].s3.amazonaws.com/        # バケット listing が返るパターン
curl -s https://s3.amazonaws.com/[BUCKET_NAME]/        # 旧形式

# [Attacker] Azure Blob — コンテナ listing
curl -s "https://[ACCOUNT_NAME].blob.core.windows.net/[CONTAINER_NAME]?restype=container&comp=list"

# [Attacker] Google Cloud Storage
curl -s "https://storage.googleapis.com/storage/v1/b/[BUCKET_NAME]/o"
gsutil ls gs://[BUCKET_NAME]/

# [Attacker] Bucket 名の推測パターン（スコープ内に限定すること）
for prefix in "" "dev-" "staging-" "prod-" "backup-" "logs-" "assets-" "uploads-"; do
  for suffix in "" "-dev" "-staging" "-prod" "-backup" "-logs"; do
    name="${prefix}[ORG_NAME]${suffix}"
    code=$(curl -s -o /dev/null -w "%{http_code}" "https://${name}.s3.amazonaws.com/")
    echo "$code  $name"
  done
done
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `--no-sign-request` で ls が成功 | 未認証読取可能なバケット | オブジェクトを取得して認証情報・機微情報を探す |
| listing XML が返る | パブリック listing 有効 | オブジェクトキーを列挙して取得 |
| `AccessDenied` | 認証必須 | スコープ内なら他の bucket 名候補へ |

**注意:** Bucket 名のスキャンは AWS / Azure / GCP 全体への横断試行になるため、**対象組織が所有していない bucket への試行は不正アクセス扱いになり得る**。スコープに明示されている bucket 名・ドメインから推測可能な範囲に限定する。

---

## 5. バージョン管理ディレクトリの露出（.git / .svn / .hg）

`.git/` が残っている場合、リポジトリ全体を復元できる。**Web ペネトレで最大の戦果のひとつ**。

**コマンド:**

```bash
# [Attacker] 存在確認（HEAD が読めれば露出確定）
curl -s http://[TARGET]/.git/HEAD
# 期待出力: ref: refs/heads/main  ← この行が見えたら .git/ 露出確定
curl -s http://[TARGET]/.git/config            # URL / リモート情報が出ることがある

# [Attacker] git-dumper でリポジトリ復元 + 過去コミット grep
git-dumper http://[TARGET]/.git/ ./dumped_repo
cd ./dumped_repo && git log --all --oneline
git log -p --all | grep -iE "password|secret|api_key|token|aws_access"

# [Attacker] git-dumper が WAF で弾かれる場合の代替
go install github.com/wnoa/go-git-dumper@latest && go-git-dumper http://[TARGET]/.git/ ./dumped_repo2
# GitTools（古典・index/pack 構造に強い）: ./gitdumper.sh http://[TARGET]/.git/ ./d3 && ./extractor.sh ./d3 ./ext
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `.git/HEAD` で `ref: refs/heads/...` | `.git/` 露出確定 | `git-dumper` でリポ復元 → コミット履歴を grep |
| 復元後 grep で password/secret | ソース内に認証情報 | `../02_Initial_Access/Credential_Discovery.md` |
| `.svn/entries` / `.svn/wc.db` | SVN 露出 | `svn-extractor.py` 等で復元 |
| `.hg/` が読める | Mercurial 露出 | `hg-dumper` / `wget -r` 後 `hg log` |

**注意:** ダンプ前に `index` / `packed-refs` の取得可否を確認する。これらが 403 だと `git-dumper` が部分的にしか復元できず、中途半端な復元は時間を浪費する。3 種類のツールを試して取れる範囲が最も広いものを採用する。

---

## 6. 環境変数 / 設定ファイル（.env / config）

**コマンド:**

```bash
# [Attacker] よくある名前を順に当てる
for p in .env .env.local .env.production .env.development .env.backup \
         config.php config.php.bak config.php~ wp-config.php wp-config.php.bak \
         database.yml settings.py local_settings.py; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://[TARGET]/$p")
  echo "$code  $p"
done
```

**`.env` 内の典型的なキー:**

```
APP_KEY=...
DB_HOST=...   DB_DATABASE=...   DB_USERNAME=...   DB_PASSWORD=...
MAIL_PASSWORD=...
AWS_ACCESS_KEY_ID=...   AWS_SECRET_ACCESS_KEY=...
JWT_SECRET=...
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `.env` が 200 で平文の KEY=VALUE | DB 接続情報・API キー漏洩 | `../02_Initial_Access/Credential_Discovery.md`（.env セクション）|
| `config.php` が「200 で空白」 | PHP として実行されている | 拡張子をズラした `config.php.bak` / `config.php~` が本命（§7）|

**注意:** `config.php` 等が空白を返すのは PHP として実行されているため。バックアップ拡張子（§7）に切り替える。

---

## 7. バックアップファイル

エディタや管理者の操作で生成される拡張子バリエーションを総当たりする。

**コマンド:**

```bash
# [Attacker] 基幹ファイルのバックアップを当てる（拡張子バリエーション）
for base in index login config admin db backup users; do
  for ext in .bak .old .save .swp .swo "~" .orig .copy ".bak.txt"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "http://[TARGET]/${base}${ext}")
    echo "$code  ${base}${ext}"
  done
done

# [Attacker] 圧縮形式のフルバックアップ
for f in backup.zip backup.tar.gz site.zip www.tar.gz db.sql db.sql.gz dump.sql; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://[TARGET]/$f")
  echo "$code  $f"
done
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `*.bak` / `*~` が 200 | 旧バージョンのソース | ダウンロードして認証情報・ロジックを確認 |
| `db.sql` / `dump.sql` が 200 | DB ダンプ | テーブル内のハッシュ・認証情報を抽出 |
| `.index.php.swp` 等 | vim スワップ | `vim -r` で復元 |

**注意:** vim のスワップは `.[元ファイル名].swp`（先頭ドット + 元ファイル名 + `.swp`）。これも候補に入れる。大きな `.tar.gz` は `curl -I` でサイズ確認してから GET する。

---

## 8. サーバー設定ファイル（.htaccess / web.config / nginx.conf）

**コマンド:**

```bash
# [Attacker]
curl -s http://[TARGET]/.htaccess
curl -s http://[TARGET]/.htpasswd
curl -s http://[TARGET]/web.config
curl -s http://[TARGET]/nginx.conf
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `.htaccess` の `RewriteRule` / `AuthUserFile` | 内部ルーティング・認証参照先 | `AuthUserFile` パスを手がかりに `.htpasswd` を取得 |
| `.htpasswd` のユーザー名 + ハッシュ | Basic 認証のハッシュ | 即 `hashcat` 候補 → `../05_Tools_Reference/Hashcat.md` |
| `web.config` の `<connectionStrings>` / `<machineKey>` | DB 接続情報・ViewState 攻撃の鍵 | `__VIEWSTATE` 攻撃の足掛かり |
| `nginx.conf` の `proxy_pass` / `server_name` | 内部サービスの存在 | 内部サービスへのアクセス検討 |

**注意:** `web.config` の `<machineKey>` は ASP.NET ViewState のデシリアライズ攻撃の鍵になる。

---

## 9. 動作確認用ファイル（phpinfo / server-status）

**コマンド:**

```bash
# [Attacker] phpinfo 系
for f in phpinfo.php info.php test.php pinfo.php p.php phpinfo phpinfo.html; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://[TARGET]/$f")
  echo "$code  $f"
done

# [Attacker] Apache の server-status / server-info
curl -s http://[TARGET]/server-status   # 直近アクセスの URL / IP / リクエスト一覧
curl -s http://[TARGET]/server-info     # モジュール一覧 / 設定詳細
```

**観測される出力 → 次のアクション:**

| 項目 | 拾える情報 | 次のアクション |
|---|---|---|
| `_SERVER["SERVER_ADDR"]` | 実 IP（CDN 配下なら裏の IP） | 裏 IP への直接アクセス検討 |
| `_SERVER["DOCUMENT_ROOT"]` | サーバー上のフルパス | パストラバーサル攻撃で有用 → `../02_Initial_Access/Web_Vulnerabilities/Path_Traversal.md` |
| `disable_functions` | RCE 時の制約 | 使える関数を確認 |
| `allow_url_include` / `allow_url_fopen` | RFI 可否 | RFI 攻撃の判断材料 |
| `$_ENV` / `Environment` | 環境変数（クレデンシャル混入） | 認証情報を抽出 |
| `server-status` の他クライアント URL | 他者の操作が観察できる | 動的なエンドポイント発見 |

**注意:** `server-status` は他クライアントの実 URL が観測できるが、自分のリクエストパターンも他者から見えていることを意識する（証跡を残しすぎない）。

---

## 10. API 仕様ファイル（Swagger / OpenAPI）

**コマンド:**

```bash
# [Attacker] Swagger / OpenAPI の典型パス
for p in swagger.json swagger.yaml openapi.json openapi.yaml \
         api-docs v2/api-docs v3/api-docs \
         swagger-ui/ swagger-ui.html swagger/index.html docs/ api/docs api/swagger; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://[TARGET]/$p")
  echo "$code  $p"
done

# [Attacker] JSON が見つかったら全エンドポイントを取り出す
curl -s http://[TARGET]/swagger.json | jq -r '.paths | keys[]'
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `swagger.json` / `openapi.json` が 200 | API 仕様が露出 | `jq` で全パスを抽出 → 裏 API（`/api/internal/*` `/api/admin/*`）を発見 |
| `swagger-ui/` が表示される | 対話的 API ドキュメント | 各エンドポイントを直接叩いて認可不備を確認 |

**注意:** API 仕様ファイルが露出していると、Web 列挙では出てこない裏 API が即時判明する。

---

## 11. エディタ・OS のメタファイル

**コマンド:**

```bash
# [Attacker] .DS_Store（macOS）: バイナリだが内部にファイル名が ASCII で含まれる
curl -s http://[TARGET]/.DS_Store -o ds_store && strings ds_store | sort -u

# [Attacker] .idea / .vscode（IDE 設定。プロジェクト構造のヒント）
curl -s http://[TARGET]/.idea/workspace.xml
curl -s http://[TARGET]/.vscode/settings.json

# [Attacker] Thumbs.db（Windows）
curl -s -o thumbs http://[TARGET]/Thumbs.db && strings thumbs
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `.DS_Store` の strings にファイル名 | ディレクトリ内のファイル名一覧 | 一覧から実ファイルを順に取得 |
| `.idea/` / `.vscode/` が読める | プロジェクト構造のヒント | パス構造から他のファイルを推測 |

**注意:** メタファイルを読むだけではディレクトリ一覧しか得られない。一覧から実ファイルを順に取得する手順までセットで行う。

---

## 12. ディレクトリリスティング

**コマンド:**

```bash
# [Attacker] まず手動で末尾 / を付けて確認
curl -s http://[TARGET]/uploads/
curl -s http://[TARGET]/files/
curl -s http://[TARGET]/backup/
```

**ディレクトリリスティングが有効な場合のシグナル:**

| サーバー | レスポンス本文の特徴 |
|---------|------------------|
| Apache（`autoindex` 有効） | `<title>Index of /[PATH]</title>` / `Parent Directory` |
| Nginx（`autoindex on`） | `<h1>Index of /[PATH]/</h1>` / `<pre><a href="../">../</a>` |
| IIS | `<pre>` 内に `[ファイル名] [日時] [サイズ]` の表形式 |
| Tomcat | `Directory: /[PATH]` |
| Python `http.server` | `<title>Directory listing for /[PATH]</title>` |

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 上記シグナルが返る | リスティング有効 | `.sql` / `.bak` / `.tar.gz` / `.pem` / `.key` を最優先取得。上位 `../` も確認 |
| `403` / デフォルトドキュメント | リスティング無効 | デフォルトドキュメント名を直接取得、ワードリスト列挙に戻る |

**注意:** ヒットしたら拡張子の珍しいファイルを最優先で取得し、同じディレクトリの上位（`../`）も末尾スラッシュで確認する。

---

## 13. 管理コンソール / モニタリング

**コマンド:**

```bash
# [Attacker] Tomcat（401 なら Basic 認証 → デフォルト認証情報を当たる）
curl -s http://[TARGET]:8080/manager/html

# [Attacker] JBoss / WildFly
curl -s http://[TARGET]:8080/jmx-console/
curl -s http://[TARGET]:9990/console/

# [Attacker] Spring Boot Actuator
for p in actuator actuator/env actuator/health actuator/heapdump actuator/mappings actuator/info; do
  curl -s "http://[TARGET]/$p"
done

# [Attacker] Jenkins（script は Groovy console = 認証突破時に RCE）
curl -s http://[TARGET]:8080/manage
curl -s http://[TARGET]:8080/script

# [Attacker] Kibana / Elasticsearch
curl -s http://[TARGET]:5601/app/kibana
curl -s http://[TARGET]:9200/_cat/indices?v
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `manager/html` で 401 | Basic 認証あり | デフォルト認証情報を当たる → `../02_Initial_Access/Default_Credentials.md` |
| `actuator/env` / `actuator/heapdump` が 200 | **クレデンシャルが平文で出る最有力誤公開** | env を取得、heapdump を `strings` 解析 |
| Jenkins `/script` にアクセス可 | Groovy console | 認証突破時に RCE |
| Elasticsearch `_cat/indices` が返る | 認証なしの ES | インデックス内データを読取 |

**注意:** `actuator/heapdump` は数十〜数百 MB になる。取得後はオフラインで `strings` / `grep -aE "password|token"` で抽出し、ライブ環境への影響は読み取り 1 回のみに留める。

---

## 14. nuclei での一括チェック

**コマンド:**

```bash
# [Attacker] exposures カテゴリ（誤公開検出テンプレート）
nuclei -t exposures/ -u https://[TARGET]
# 範囲を絞る（バックアップ / 設定ファイル / トークン）
nuclei -t exposures/backups/ -t exposures/configs/ -t exposures/tokens/ -u https://[TARGET]
```

**観測される出力 → 次のアクション:**

| nuclei 出力 | 次のアクション |
|------------|--------------|
| `exposures/configs/dotenv-cred-files` | 即 `.env` 取得（§6）→ `../02_Initial_Access/Credential_Discovery.md` |
| `exposures/files/git-config` / `exposed-git-folder` | `git-dumper` でリポ復元（§5）|
| `exposures/configs/exposed-spring-actuator` | `/actuator/env` `/heapdump` を順に取得（§13）|
| `exposures/apis/swagger-api` | `swagger.json` で裏 API を列挙（§10）|
| `exposures/logs/*` | ログから内部 IP / ユーザー名 / スタックトレース抽出 |

**注意:** nuclei は共通 WAF が任意パスで類似レスポンスを返すと偽陽性を出す。個別ヒットは `curl -s` で必ず手動再現してから採用する。

---

## 刺さらなかったとき（全体）

| 観測される症状 | 推定原因 | 対処 |
|--------------|---------|------|
| 何を当てても全て 200 が返る | カスタム 404 ハンドラ | (a) `curl -w "%{http_code} %{size_download}\n"` で本文長も出力し差分を取る。(b) `ffuf -ac`（自動キャリブレーション）。(c) `ffuf -fw/-fl/-fs` でベースライン明示除外 |
| 全て 403 で本文も同じ | WAF が誤公開検知パターンを一括ブロック | パスを URL エンコード / 大文字混在 / 末尾スラッシュ追加で揺らす |
| `.git/HEAD` だけ 200、`config` 等は 403 | 部分的に WAF ルール | `git-dumper` 前に `index` / `packed-refs` の取得可否を確認、不可なら他の誤公開へ |
| ディレクトリリスティングが効かない | `autoindex off` / `Options -Indexes` / デフォルトドキュメント | デフォルトドキュメント名を直接取得、ワードリスト列挙に戻る |
| nuclei が大量の偽陽性 | 共通 WAF が類似レスポンス | 個別ヒットを `curl -s` で手動再現してから採用 |
| Web ルートで何も出ないが vhost で出る | 誤公開がサブドメインに偏在 | TLS_Audit の SAN・vhost ファジングで判明した FQDN を全部総当たり |

---

## 注意点・落とし穴

- **誤公開ファイル列挙は本文取得で通信量が増えやすい。** `.tar.gz` を不用意に GET すると数 GB になる。`curl -I` でサイズ確認してから GET に切り替える
- **`server-status` / `server-info` は他クライアントの実 URL が観測できる**が、自分のリクエストパターンも他者から見える
- **`actuator/heapdump` は数十〜数百 MB。** 取得後はオフラインで抽出する
- **`config.php` 等が「200 で空白」を返す場合、PHP として実行されている。** 拡張子をズラした名前が本命
- **WAF 追加対象では `.env` 直当てが 403 でも `/%2e%2fenv` 等のエンコード揺らしが効くことがある。** 当て方を変えてから諦める

> **個別ブロック固有の注意は各 §N の「注意:」を参照。**

---

## 関連技術

- 前：`Network_Scanning.md`（Web ポートの発見）
- 前：`Web_Enumeration.md`（フレームワーク特定後、そのフレームワーク固有の誤公開パスへ）
- 前：`TLS_Audit.md`（SAN から判明した FQDN 群を誤公開ファイル探索の対象にする）
- 後：`../02_Initial_Access/Credential_Discovery.md`（`.env` / `.git/` / `.htpasswd` から取り出した認証情報の処理）
- 後：`../02_Initial_Access/Default_Credentials.md`（Tomcat / JBoss / Jenkins 等の管理コンソールが見つかった場合）
- 後：`../02_Initial_Access/Web_Vulnerabilities/Path_Traversal.md`（`phpinfo` で `DOCUMENT_ROOT` 判明後・Apache CVE-2021-41773 / CVE-2021-42013）
- 後：`../02_Initial_Access/Web_Vulnerabilities/JWT_Attacks.md`（`.well-known/openid-configuration` / `jwks.json` 取得後）
- 後：`../02_Initial_Access/Web_Vulnerabilities/OAuth_Attacks.md`（OIDC エンドポイント特定後）
- 後：`../05_Tools_Reference/Searchsploit.md`（誤公開された設定ファイルから判明した製品/バージョンで CVE 検索）
