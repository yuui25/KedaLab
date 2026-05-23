# Web レスポンス一次トリアージ

## このファイルの位置づけ

Webアプリ診断の偵察フェーズで「キャプチャしたリクエスト/レスポンスを最初に読む」観点を集約する。
機微情報の漏洩・セキュリティヘッダーの欠落・Cookie 属性の不備・HTML 内の情報漏洩を
体系的にスキャンする手順を示す。詳しい攻撃手順は各 `02_Initial_Access/` ファイルを参照。

---

## リクエスト/レスポンスからの機微情報・設定不備スキャン

### 着火条件

- Burp / mitmproxy でキャプチャしたリクエスト＋レスポンスを初めて読むとき
- 「とりあえず何が出ているか全体像を把握したい」初動 5 分
- 静的にキャプチャした HAR ファイル・Burp Save Item を後追い解析するとき

### 環境前提

- 実行環境: テスター端末
- 必要なツール:
  - `sensitive_scan.py`（Python 3 標準ライブラリのみ。別途入手要）
  - Burp Suite Community（無料）または DevTools — ツールが使えない環境での代替手段として後述
- オフライン代替: スクリプト不要の場合は後述の「Burp / DevTools で代替する場合」の手順を使う

### 観点・着眼点

**先に確認すること：** スキャン対象が「リクエスト」か「レスポンス」か「両方入った 1 ファイル」かを確認する。
`sensitive_scan.py` は両方が混在していても自動で分離して処理するが、
Burp の "Save Item" はリクエスト+レスポンスが連結されたフォーマットで保存される。

**攻撃者の思考トレース：** 手動で全ヘッダーを目視するより先に、
「網羅的に列挙して人間が判断する」スキャンを 1 回通す。
スキャン結果のうち HIGH は即確認、MEDIUM は攻撃面として記録、LOW は必要に応じて確認する。

**検出対象のカテゴリと優先度：**

| カテゴリ | 主な検出内容 | 優先度 |
|---------|-----------|------|
| シークレット / トークン | AWS キー / GitHub トークン / JWT / PEM / Stripe / Slack 等 | HIGH |
| PII | メール / 電話 / 郵便番号 / クレジットカード（Luhn 検証付き）/ IBAN / SSN | HIGH |
| スタックトレース / エラー | Java/Python/PHP/SQL のエラー出力・内部パス漏洩 | HIGH |
| セキュリティヘッダー欠落 | CSP / HSTS / X-Content-Type-Options / Referrer-Policy / Permissions-Policy 等 | MEDIUM |
| Cookie 属性不備 | HttpOnly 欠落 / Secure 欠落 / SameSite 欠落 / 超長期 Expires | MEDIUM |
| 内部識別子 | UUID / MongoDB ObjectId / プライベート IP / 内部ホスト名 / Windows パス | MEDIUM |
| HTML フォーム値 | `<input>` の `value` / `<select>` の selected / `<textarea>` の中身 | MEDIUM |
| HTML コメント | `<!-- TODO -->` / 開発者コメント / 内部情報の埋め込み | LOW |
| 外部スクリプト読み込み | 外部 CDN / 不審なドメインからの JS 読み込み | LOW |
| デバッグ痕跡 | `console.log` / TODO/FIXME コメント | LOW |

**セキュリティヘッダー確認の観点（欠落 = 指摘対象）：**

| ヘッダー | 欠落した場合のリスク |
|---------|-----------------|
| `Content-Security-Policy` | XSS のインパクト拡大（外部スクリプト読み込み・exfil） |
| `Strict-Transport-Security` | SSL ストリッピング（HTTPS でも HTTP に落とせる） |
| `X-Content-Type-Options: nosniff` | MIME スニッフィングによるスクリプト実行 |
| `X-Frame-Options` / CSP `frame-ancestors` | クリックジャッキング |
| `Referrer-Policy` | クエリパラメータが Referer 経由で 3rd party に漏洩 |
| `Permissions-Policy` | カメラ / マイク / 位置情報への不要アクセス |
| `Cross-Origin-Opener-Policy` | XS-Leaks（サイドチャネル情報漏洩） |

**弱い設定がヒットしたときの次のアクション：**

| 観測内容 | 次のアクション |
|---------|-------------|
| CSP に `unsafe-inline` が含まれる | XSS があれば任意 JS 実行できる → XSS の有無を最優先で確認 |
| CSP に `unsafe-eval` が含まれる | `eval()` 系の動的コード実行が可能 → 同上 |
| `Referrer-Policy: no-referrer-when-downgrade` / `unsafe-url` | URL にセンシティブなパラメータがないか確認。あれば 3rd party への漏洩を報告 |
| サーバーヘッダー（`Server:` / `X-Powered-By:`）でバージョン露出 | `searchsploit` で既知 CVE 確認 → `Web_Enumeration.md` |
| `Set-Cookie` で HttpOnly 欠落 | XSS でのトークン窃取が可能 → `../02_Initial_Access/Web_Vulnerabilities/XSS.md` |

### 手順

**事前準備（必須）：** Burp の "Save Item"・DevTools の "Save as HAR" 等で
リクエスト/レスポンスをテキストファイルに保存しておく。

```bash
# [Attacker] 基本スキャン（初動 5 分に最適）
python sensitive_scan.py request.txt

# LOW 信頼度（MD5 風ハッシュ・TODO コメント等）を除いて絞り込む
python sensitive_scan.py request.txt --no-low

# 全件表示（省略なし）
python sensitive_scan.py request.txt --verbose

# 特定パターンのみ有効化（例: JWT と AWS キーだけ）
python sensitive_scan.py request.txt --only "JWT Token,AWS Access Key"

# 特定パターンを無効化（誤検知が多い場合）
python sensitive_scan.py request.txt --disable "MD5-like (32 hex),SHA1-like (40 hex)"

# 使えるパターン一覧を確認
python sensitive_scan.py --list-patterns
```

**社内固有のパターンを追加する場合：**

```python
# sensitive_patterns_user.py を同ディレクトリに作成して追記
PATTERNS = [
    # (名前, 正規表現, レベル)
    ("社内社員番号", r"\bEMP-\d{6}\b", "high"),
    ("社内案件 ID", r"\bPRJ-[A-Z]{2}-\d{4}\b", "medium"),
]
```

**Burp で代替する場合（スクリプト不要）：**

```
セキュリティヘッダー確認:
  Proxy History → レスポンスを選択 → Headers タブで目視

Cookie 属性確認:
  DevTools F12 → Application → Cookies → HttpOnly / Secure / SameSite 列

横断検索（API キー・PII 等）:
  Burp → Target → Engagement tools → Search → 正規表現で全レスポンスを検索
  例: AKIA[0-9A-Z]{16}   ← AWS キーパターン

DevTools での全レスポンス検索:
  Network タブ → Ctrl+Shift+F → キーワードまたは正規表現で検索
```

### 刺さらなかったとき

- スキャン結果が全部 LOW / MEDIUM で HIGH がない → 機密情報は返っていないと判断して次フェーズへ。ただし認証後のレスポンスも必ず確認する（未認証のレスポンスだけを見て「問題なし」としない）
- スキャン結果が大量で判断できない → `--no-low` で絞り込み、HIGH だけ先に片付ける

### 注意点・落とし穴

- セキュリティヘッダーの欠落は「問題が確認できる最初のレスポンス」で報告するが、
  全エンドポイントに欠落しているか・一部だけかを確認してから範囲を記述する
- `X-Frame-Options` と CSP `frame-ancestors` は重複する。後者が優先される。両方欠落した場合のみ確実にクリックジャッキング指摘可能
- Luhn 検証付きのクレジットカードパターンは誤検知が少ないが、テスト用カード番号（`4111111111111111` 等）が返っている場合はテストデータとして除外する
- `Server:` / `X-Powered-By:` ヘッダーは WAF / CDN が書き換えている場合があり、
  直接の証跡にならないことがある。エラーページや既知のパスから二重確認する

### 本番での前提

- **事前合意の要否**: ★（技術的判断のみ。キャプチャ済みデータの解析のみで外部への通信は不要）
- **業務影響リスク**: なし（パッシブ解析のみ）
- **取得情報の取扱**: スキャン結果に含まれる PII / シークレットは暗号化保管・案件終了時破棄
- **演習環境での扱い**: 制約なし

### 関連技術

- 前：`./Web_Enumeration.md`（Webアプリの初期偵察・Cookie 分類）
- 前：`./TLS_Audit.md`（HSTS 等 TLS 関連ヘッダーの詳細確認）
- 後：`../02_Initial_Access/Web_Vulnerabilities/XSS.md`（HttpOnly 欠落・CSP 弱体の悪用）
- 後：`../02_Initial_Access/Web_Vulnerabilities/JS_Obfuscation.md`（JWT / エンコード値の多重デコード）
- 後：`../02_Initial_Access/Web_Vulnerabilities/JWT_Attacks.md`（JWT が検出された場合の攻撃手順）
- 後：`../05_Tools_Reference/Searchsploit.md`（Server ヘッダーのバージョンから CVE 検索）

> 原理（なぜスクリプト・Burp・DevTools を使い分けるのか） → `../06_Concepts/Web_Pentest_Tooling.md`
