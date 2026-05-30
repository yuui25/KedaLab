# Web列挙

> **スコープ**: HTTP/HTTPS サービスの列挙フェーズ全般。robots.txt 等の手動把握〜フレームワーク/アプリ名の特定〜バージョン→CVE 検索〜ディレクトリ/vhost ファジング〜Cookie 分類までを扱う。HTTPS のプロトコル/証明書監査は `TLS_Audit.md`、誤公開ファイル検出は `Exposed_Files.md`、個別 Web 脆弱性の攻撃は `../02_Initial_Access/Web_Vulnerabilities/` を参照。

## 着火条件
80 / 443 / 8080 等の Web ポートが開いている場合。**ディレクトリ列挙の前に、まず手動でサイト構造とアプリ名を把握する。**

## 環境前提
- 実行環境: テスター端末
- 必要なツール: `curl` / `gobuster` / `feroxbuster` / `ffuf` / `whatweb` / `nikto`（いずれもペネトレ用 Linux ディストリ標準搭載）/ `searchsploit`（exploitdb 同梱）/ `python3`（mmh3 ライブラリは `pip install mmh3`）
- 外部リソース依存: favicon ハッシュ検索（Shodan / FOFA）はインターネットアクセス要。オフライン環境では `whatweb` / `nikto` のローカル判定に留める。ワードリスト（SecLists / dirbuster）は標準同梱

## 先に確認すること

- **レート制限・自動 IP ブロックの有無**: `robots.txt` 本文・トップページに「DoS protection」「we ban bad IPs」等の記載があれば、ディレクトリ列挙ツールを控える（§4 参照）。大量リクエストで自 IP がブロックされると以降のアクセスが全遮断される
- **手動把握とファジングの分離**: まず手動でサイト構造・アプリ名を把握（§1〜§3）→ ファジングはバックグラウンド走行（§4）。ロードバランサー配下ではファジング中の手動操作はセッションが切れる前提
- **vhost ごとの別コンテンツ**: `robots.txt` やアプリが vhost で異なることがある。vhost を発見したら `/etc/hosts` に登録して再調査

**攻撃者の思考トレース:** Web は「バージョンが分かれば既知 CVE が最短経路」になることが多い。だからファジングより先に「何のアプリの何版か」を手動 + whatweb で確定させ、CVE 検索を回す。ファジングは IP ブロックのリスクがあるため、防御告知を確認してから最後に回す。

---

## 1. robots.txt / sitemap の確認

**コマンド:**

```bash
# [Attacker] 直接取得
curl -s http://[TARGET]/robots.txt

# [Attacker] Disallow エントリを抽出
curl -s http://[TARGET]/robots.txt | grep -i "disallow\|allow"
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `Disallow: /admin` `/panel` 等のパス | 隠したい重要ページの地図 | 各パスへアクセスし 404/200/301 を確認 → §2 アプリ識別へ |
| `robots.txt` が 404 | 未設置 | `/sitemap.xml` `/sitemap_index.xml` に同等情報がある場合がある |
| `Disallow: /` のみ | 全ブロックで情報量が少ない | §4 ディレクトリ列挙へ |
| 「DoS protection」「we ban bad IPs」等の文言 | IP ベースの自動ブロック（fail2ban / WAF） | **ディレクトリ列挙を行わず**、Disallow パス・HTML コメント・JS 内エンドポイントから手動把握 |
| nmap `-sC` の `http-robots.txt: 1 disallowed entry` | スキャンで自動取得済み | その内容を起点に手動確認 |

**注意:** 警告文言が出ていても「ガード自体は弱い」と決めつけない。試行は手動で 1 リクエストずつ、404 を連発させない。サブドメイン・vhost では `/robots.txt` が別になるため vhost ごとに確認する。

---

## 2. フレームワーク・アプリ名の特定

「Web アプリの名前 ＝ フレームワーク名ではない」前提を持つ。「フィットネス管理ソフト X」「ERP 製品 Y」のような**製品名（固有名詞）**が searchsploit にヒットすることが多い。

**確認する場所（優先順位順）:**

| 確認場所 | 見つかりやすい情報 |
|---------|----------------|
| ページ下部フッター | 「Powered by X」「Made using X v1.0」「© X Software」 |
| `/about`・`/contact`・`/info` 等 | アプリ名・バージョン・開発元 |
| ログインページ | アプリ名・バージョン（フッター/タイトル）|
| HTTP レスポンスヘッダー | `Server:`・`X-Powered-By:`・`X-Generator:` |
| HTML `<meta name="generator">` | CMS・フレームワーク名（著作権年範囲・バージョン文字列も含むことが多い）|
| **Cookie 名（特徴的な接頭辞）** | CMS / フレームワーク名（下表）|
| エラーページ | スタックトレースからフレームワーク・言語 |
| `/api/health`・`/version`・`/info` | API バージョン情報 |

**Cookie 名からの CMS / フレームワーク識別表:**

| Cookie 名 | 推定アプリ・フレームワーク |
|-----------|--------------------------|
| `CMSSESSID` | CMS Made Simple |
| `wordpress_logged_in_*` / `wp-settings-*` | WordPress |
| `JSESSIONID` | Java Servlet 系（Tomcat / Jetty / WildFly） |
| `PHPSESSID` | PHP（CMS 種別までは絞れない） |
| `laravel_session` / `XSRF-TOKEN`（同居） | Laravel |
| `_session_id` + `_csrf_token` のペア | Rails 系 |
| `connect.sid` | Express.js（Node） |
| `ASP.NET_SessionId` | ASP.NET |
| `frontend` / `adminhtml` | Magento |
| `SimpleSAMLAuthToken` | SimpleSAMLphp |

**コマンド:**

```bash
# [Attacker] アプリ名候補を手動で調査するページを確認
curl -s http://[TARGET]/about
curl -s http://[TARGET]/login | grep -i "powered\|version\|copyright\|made"

# [Attacker] HTTP ヘッダー / meta / Cookie の確認
curl -sI http://[TARGET]/ | grep -i "server\|x-powered-by\|x-generator\|x-version\|set-cookie"
curl -s http://[TARGET]/ | grep -i "generator\|framework\|powered\|copyright"
# 出力例: Set-Cookie: CMSSESSID9d372ef93962=...; path=/  → CMS Made Simple がほぼ確定

# [Attacker] whatweb — Cookie 名・meta generator・favicon ハッシュを一括判定（初手）
whatweb -a 3 http://[TARGET]/                  # -a 3 はもっとも深いプロビング
whatweb -a 3 --log-json=whatweb.json http://[TARGET]/

# [Attacker] favicon mmh3 ハッシュによる製品特定（Server ヘッダーが generic でも当たる）
curl -sk https://[TARGET]/favicon.ico -o /tmp/favicon.ico
python3 -c "import mmh3, base64; print(mmh3.hash(base64.encodebytes(open('/tmp/favicon.ico','rb').read())))"
# 出力 hash で Shodan: http.favicon.hash:[VALUE] を検索 → 同一製品/同一テンプレのホスト一覧

# [Attacker] nikto — 既知の誤公開・古いバージョン痕跡・設定不備を一括検出（最後に）
nikto -h http://[TARGET]/ -o nikto.txt
nikto -h https://[TARGET]/ -ssl -Tuning x6   # x = 全プラグイン / 6 = path traversal 除外
```

**観測される出力 → 次のアクション:**

| 出力・観測内容 | 次のアクション |
|--------------|--------------|
| 「Made using [製品名] [バージョン]」等の文字列 | 製品名そのままを §3 `searchsploit` に渡す |
| 「Powered by WordPress」等 | バージョン確認 → `searchsploit wordpress [バージョン]` |
| ヘッダーに `X-Powered-By: ASP.NET` | Windows 確定 → Windows 攻撃手法へ |
| `<meta generator content="... Copyright (C) 2004-2019 ...">` | 最終年がバージョンの目安（2019 → CMS Made Simple 2.2.x 系）→ §3 |
| `Server: Werkzeug/x Python/x` | Python WSGI（典型は Flask）。`/console` PIN バイパス・デバッグモード露出を確認 |
| `Server: gunicorn` / `uWSGI` | Python WSGI（Django/Flask）。`/admin` `/static/admin/css/base.css`・Cookie `csrftoken`/`sessionid` で Django 判定 |
| `Server: WSGIServer/x Python/x` | Django 開発サーバー。`DEBUG=True` ならエラーページから SECRET_KEY 漏洩を確認 |
| 非標準ポート（5000/8000/8080/3000）に Python 系 | 開発・社内ツールの可能性。入力フィールドに XSS / コマンドインジェクションを試す価値あり |
| favicon ハッシュがアプライアンス製品と一致 | ベンダー別既知 CVE 照合 → `../02_Initial_Access/Edge_Appliance_CVEs.md` |

**注意:** ヘッダーにアプリ名が出ない場合でも「ページのどこかに必ず書いてある」と考えて探す。「Made using」「Powered by」「Copyright © [製品名]」は開発元が無意識に露出させていることが多い。ブラウザ拡張 `Wappalyzer` も同等。使い分けは **初手 whatweb -a 3 → ヒットなければ favicon ハッシュ → 最後に nikto**。

---

## 3. バージョン特定と CVE 検索

**バージョンを確認できたら、ディレクトリ列挙より先に CVE 検索を行う。** 既知の重大脆弱性（パストラバーサル / RCE 等）があればそちらが最短経路になることが多い。

**コマンド:**

```bash
# [Attacker] よく使うバージョン確認エンドポイント
curl -s http://[IP]:[PORT]/api/health         # Grafana → {"version":"8.0.0", ...}
curl -sI http://[IP]/ | grep -i "server\|x-powered-by\|x-version"
curl -s http://[IP]/login | grep -i "version\|v[0-9]"

# [Attacker] searchsploit で CVE を検索
searchsploit grafana 8.0
searchsploit CVE-2021-43798                    # CVE 番号がわかっている場合
searchsploit -x [PATH_FROM_RESULTS]            # エクスプロイト内容を確認
searchsploit -m [PATH_FROM_RESULTS]            # 作業ディレクトリにコピー
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| アプリ名 + バージョンが判明 | 既知 CVE 検索が可能 | searchsploit + NVD（`https://nvd.nist.gov/vuln/search`）で照合 → `../05_Tools_Reference/Searchsploit.md` |
| パストラバーサル系の CVE がヒット | 最短経路の可能性 | `../02_Initial_Access/Web_Vulnerabilities/Path_Traversal.md` |
| searchsploit にヒットしない | DB に未収録 | Google で `"[製品名] exploit"` / `"[製品名] CVE"` を検索 |
| CVE なし | 既知脆弱性なし | デフォルト認証情報（admin:admin 等）を試す → `../02_Initial_Access/Default_Credentials.md` |

**注意:** バージョンがページに表示されていなくても `/robots.txt`・ソースコメント・エラーメッセージに含まれることがある。searchsploit の結果が古い PoC の場合、コードを読んでパラメータ修正してから実行する。

---

## 4. ディレクトリ・エンドポイントの列挙（ファジング）

> **先に §1 でレート制限・IP ブロックの告知を確認すること。** 告知がある環境ではこのブロックを実行しない。

**コマンド:**

```bash
# [Attacker] feroxbuster（Rust 製・再帰デフォルト・初手推奨）
feroxbuster -u http://[IP] -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,html,bak,txt --depth 4 -o feroxbuster.txt
feroxbuster -u http://[IP] -w [WORDLIST] -s 200,204,301,302,307,401,403 -x php,asp,aspx,jsp

# [Attacker] gobuster dir（枯れていて安定）
gobuster dir -u http://[IP] -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster_root_dir.txt
gobuster dir -u http://[IP] -w [WORDLIST] -x php,txt,html,bak -o gobuster_ext.txt

# [Attacker] vhost ファジング — gobuster v3.6 以降は --append-domain がデフォルト false
gobuster vhost -u http://[DOMAIN] -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain -o vhost_fuzz.txt
# ffuf 代替（gobuster バージョン差分を回避）
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
  -u http://[DOMAIN]/ -H "Host: FUZZ.[DOMAIN]" -fs [EXCLUDE_SIZE] -o vhost_fuzz.json -of json

# [Attacker] 負荷を抑えたファジング（レート制限環境）
gobuster dir -u http://[IP] -w [WORDLIST] -t 5 --delay 200ms -o gobuster_lowrate.txt
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `/data/3` `/download/5` 等の連番 ID | IDOR の可能性 | ID を 0/1 から変えてアクセス → `../02_Initial_Access/Web_Vulnerabilities/IDOR.md` |
| vhost がヒット | 別コンテンツが存在 | `/etc/hosts` に追加して再調査（原理 → `../06_Concepts/Hosts_File_For_AD.md`）|
| 大量の `429 Too Many Requests` | アプリ層のレート制限 | スレッド数を絞る（`-t 5`）+ `--delay` |
| 大量の `503` / `502` | バックエンド詰まり / WAF throttle | 停止して数分待つ。ワードリストを短く |
| ファジング後にブラウザがログアウトされる | LB / WAF が IP 単位でレート制限・セッション切断 | スレッド数を絞る・遅延を入れる・手動操作と分離 |
| 一定回数失敗で IP ブロック | WAF / IPS の自動遮断 | 停止。IP ローテーション・遅延を検討。検知証跡として記録 |
| ログインフォームを発見 | 認証突破の入口 | `../02_Initial_Access/Web_Vulnerabilities/SQLi.md` / `../02_Initial_Access/Account_Lockout_Recon.md` |

**注意:** `--append-domain` の挙動はバージョン依存。**v3.1 以前**は自動結合、**v3.2〜v3.5** は `--append-domain` で結合、**v3.6 以降**はデフォルトで「ワードリストをそのまま Host: 値にセット」。把握していないと「裸の文字列が送られて全件失敗」する。`gobuster --version` で確認し、新環境では 1 件で挙動確認するか ffuf を使う。HTTPS は `-k`、サイズ一致ノイズは `--exclude-length` でフィルタ。

---

## 5. Cookie の分類（third-party 除外と first-party テスト対象の絞り込み）

Cookie が 20 個以上あって GA / Cloudflare / Akamai 等の third-party が混在すると、テスト対象が埋もれる。third-party Cookie はセッション・認可・ビジネスロジックに関与しないため除外する。

**分類の判断基準:**

| Cookie 名のパターン | 判断 |
|--------------------|------|
| `_ga` / `_ga_*` / `_gid` / `_gat_*` | Google Analytics → 除外 |
| `__cf_bm` / `cf_clearance` / `__cfduid` | Cloudflare → 除外 |
| `_abck` / `bm_sv` / `ak_bmsc` | Akamai Bot Manager → 除外 |
| `_fbp` / `_fbc` | Meta/Facebook → 除外 |
| `AWSELB` / `AWSALB` | AWS ELB → インフラ、除外 |
| `JSESSIONID` / `PHPSESSID` / `session` / `token` 等 | 自社 → **テスト対象** |
| 上記に一致しない未知の名前 | 自社の可能性 → **テスト対象** |

**コマンド:**

```bash
# [Attacker] 事前準備（必須）: プロキシ（Burp 等）でキャプチャした Raw リクエストを request.txt に保存
# cookie_classify.py（別途入手・Python 3 標準ライブラリのみ）で分類
python cookie_classify.py request.txt
python cookie_classify.py --cookie "sessionid=abc; _ga=GA1.2.xxx; __cf_bm=yyy"
python cookie_classify.py request.txt --show-thirdparty

# ツール不要: DevTools → F12 → Application → Storage → Cookies で
# 自社ドメイン配下 vs 外部ドメイン配下を目視分類する
```

**観測される出力 → 次のアクション（first-party に絞った後）:**

| 確認観点 | シグナル | 次のアクション |
|---------|---------|-------------|
| HttpOnly が付いていない | JS から読み取り可能 → XSS でトークン窃取 | `../02_Initial_Access/Web_Vulnerabilities/XSS.md` |
| Secure が付いていない | HTTP でも送信される | HSTS の有無も確認 |
| SameSite が None + Secure 欠落 | CSRF の余地 | CSRF トークンの有無・有効性を確認 |
| Cookie 値が Base64 / JWT 形式 | デコードで user_id・role 等が見える可能性 | 多重エンコード剥がし → `../02_Initial_Access/Web_Vulnerabilities/JS_Obfuscation.md` |
| Expires / Max-Age が極端に長い（1 年超） | ローテーションされない可能性 | 値の予測可能性・固定値かを確認 |

**注意:** `__Secure-` / `__Host-` 接頭辞は Cookie Prefix（ブラウザの強制 Secure/Path 制限）を意味する。報告前にブラウザ側保護が有効かを確認する。社内製ツールが `_ga_[ID]` 風の名前を偶然使うこともあるため、Cookie 値の形式と発行タイミング（ログイン前から存在するか）も合わせて判断する。原理（third-party 除外の重要性・Cookie Prefix 仕様）→ `../06_Concepts/Web_Pentest_Tooling.md`

---

## 刺さらなかったとき（全体）

| 状況 | 推定原因 | 代替手段 |
|------|---------|---------|
| アプリ名がどこにも見つからない | ヘッダー・フッターに露出なし | `/wp-admin`・`/admin`・`/phpmyadmin` 等の CMS 固有パスから推定（§4） |
| searchsploit にヒットしない | DB 未収録 | Google で `"[製品名] exploit"` / `CVE-[年]-[番号]` を検索 |
| ファジングで何も出ない | ワードリスト不適合 / WAF | 別ワードリスト（raft / SecLists）に変更、`-s` でステータスフィルタ調整 |
| Cookie が 1〜2 本で third-party 混在なし | 小規模アプリ | 全件をそのままテスト対象にする |
| ドメイン直下に Cookie がない（CDN / SPA） | トークンが別ストア | `localStorage` / `sessionStorage` を DevTools で確認 |
| IP ブロックされた | WAF / IPS 自動遮断 | 停止して回避策（IP ローテーション・遅延）。検知証跡として記録 |

---

## 注意点・落とし穴

- gobuster は `--timeout` と `-t`（スレッド数）の調整でスキャンが安定する。レスポンスサイズ一致が大量なら `--exclude-length` でフィルタ
- vhost ファジングでは必ずベースドメインを `/etc/hosts` に登録してから実施する
- HTTPS は `-k` で証明書チェックをスキップ
- CVE がなくても「設定ファイルのデフォルト認証情報（admin:admin 等）」を試すことを忘れない

> **個別ブロック固有の注意は各 §N の「注意:」を参照。**

---

## 関連技術

- 前：`Network_Scanning.md`（Web ポートの発見）
- 前：`DNS_Enumeration.md`（ドメイン渡しでサブドメイン・vhost を列挙してから Web へ）
- 後：`TLS_Audit.md`（HTTPS のプロトコル/暗号/証明書監査・SAN からの vhost 抽出）
- 後：`Exposed_Files.md`（バックアップ・設定ファイル・`.git/`・ディレクトリリスティングの誤公開検出）
- 後：`../02_Initial_Access/Default_Credentials.md`（管理画面・ログインフォームのデフォルト認証情報試行）
- 後：`../02_Initial_Access/Account_Lockout_Recon.md`（辞書攻撃前のロックアウトポリシー事前確認）
- 後：`../02_Initial_Access/Web_Vulnerabilities/IDOR.md`（連番 ID を発見した場合）
- 後：`../02_Initial_Access/Web_Vulnerabilities/SQLi.md`（ログインフォームを発見した場合）
- 後：`../05_Tools_Reference/Searchsploit.md`（バージョン確認後の CVE 検索）
- 後：`../02_Initial_Access/Edge_Appliance_CVEs.md`（ログイン HTML タイトル / URL パス / favicon ハッシュ / Server ヘッダーがアプライアンス製品と一致した場合）
