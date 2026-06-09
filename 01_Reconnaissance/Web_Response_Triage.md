# Web レスポンス一次トリアージ

> **スコープ**: Web アプリ診断の偵察フェーズで「キャプチャしたリクエスト/レスポンスを最初に読む」観点に徹する。機微情報の漏洩・セキュリティヘッダー欠落・Cookie 属性不備・HTML 内情報漏洩の体系的スキャンと、認証後レスポンスの再スキャンまで。検出後の個別攻撃手順は `../02_Initial_Access/Web_Vulnerabilities/` 各ファイルを参照。

## 着火条件

- Burp / mitmproxy でキャプチャしたリクエスト＋レスポンスを初めて読むとき
- 「とりあえず何が出ているか全体像を把握したい」初動 5 分
- 静的にキャプチャした HAR ファイル・Burp Save Item を後追い解析するとき

## 環境前提

- 実行環境: テスター端末
- 必要なツール:
  - `sensitive_scan.py`（Python 3 標準ライブラリのみ。別途入手要）
  - Burp Suite Community（無料）または DevTools — ツールが使えない環境での代替
  - `nuclei`（ライブスキャン用。別途インストール要。遮断 VLAN では事前テンプレート同梱）
- オフライン代替: スクリプト不要の場合は §2 の Burp / DevTools 手順を使う

## 先に確認すること

- スキャン対象が「リクエスト」か「レスポンス」か「両方入った 1 ファイル」かを確認する。`sensitive_scan.py` は混在しても自動分離するが、Burp の "Save Item" はリクエスト+レスポンス連結フォーマット
- **必ず認証後のレスポンスも再スキャンする**（§4）。漏洩の大半はログイン後に起きる

**検出対象のカテゴリと優先度:**

| カテゴリ | 主な検出内容 | 優先度 |
|---------|-----------|------|
| シークレット / トークン | AWS キー / GitHub トークン / JWT / PEM / Stripe / Slack 等 | HIGH |
| PII | メール / 電話 / 郵便番号 / クレジットカード（Luhn 検証）/ IBAN / SSN | HIGH |
| スタックトレース / エラー | Java/Python/PHP/SQL のエラー出力・内部パス漏洩 | HIGH |
| セキュリティヘッダー欠落 | CSP / HSTS / X-Content-Type-Options / Referrer-Policy 等 | MEDIUM |
| Cookie 属性不備 | HttpOnly / Secure / SameSite 欠落 / 超長期 Expires | MEDIUM |
| CORS 設定不備 | `Access-Control-Allow-Origin` の動的反射 / `null` 許可 / `Access-Control-Allow-Credentials: true` | MEDIUM |
| 内部識別子 | UUID / ObjectId / プライベート IP / 内部ホスト名 / Windows パス | MEDIUM |
| 分散トレーシングヘッダ | `traceparent` / `tracestate` / `traceresponse` / `baggage` の露出 → observability スタック特定・ベンダ判別・内部相関 ID 露出 | LOW |
| HTML フォーム値 | `input` の value 属性 / `select` の selected / `textarea` の中身 | MEDIUM |
| HTML コメント | `<!-- TODO -->` / 開発者コメント | LOW |
| 外部スクリプト読み込み | 外部 CDN / 不審なドメインからの JS | LOW |
| デバッグ痕跡 | `console.log` / TODO/FIXME | LOW |

**セキュリティヘッダー確認の観点（欠落 = 指摘対象）:**

| ヘッダー | 欠落した場合のリスク |
|---------|-----------------|
| `Content-Security-Policy` | XSS のインパクト拡大（外部スクリプト読み込み・exfil） |
| `Strict-Transport-Security` | SSL ストリッピング（HTTPS でも HTTP に落とせる） |
| `X-Content-Type-Options: nosniff` | MIME スニッフィングによるスクリプト実行 |
| `X-Frame-Options` / CSP `frame-ancestors` | クリックジャッキング |
| `Referrer-Policy` | クエリパラメータが Referer 経由で 3rd party に漏洩 |
| `Permissions-Policy` | カメラ / マイク / 位置情報への不要アクセス |
| `Cross-Origin-Opener-Policy` | XS-Leaks（サイドチャネル情報漏洩） |

**攻撃者の思考トレース:** 手動で全ヘッダーを目視するより先に「網羅的に列挙して人間が判断する」スキャンを 1 回通す。HIGH は即確認、MEDIUM は攻撃面として記録、LOW は必要に応じて確認。そして未認証で問題なくても、ログイン後のレスポンスでやり直すまでがトリアージ。

---

## 1. sensitive_scan.py による機微情報スキャン

**コマンド:**

```bash
# [Attacker] 事前準備（必須）: Burp "Save Item" / DevTools "Save as HAR" でリクエスト/レスポンスを request.txt に保存

# [Attacker] 基本スキャン（初動 5 分に最適）
python sensitive_scan.py request.txt
python sensitive_scan.py request.txt --no-low                 # LOW 信頼度を除外
python sensitive_scan.py request.txt --verbose                # 全件表示
python sensitive_scan.py request.txt --only "JWT Token,AWS Access Key"   # 特定パターンのみ
python sensitive_scan.py request.txt --disable "MD5-like (32 hex)"       # 誤検知の多いパターン無効化
python sensitive_scan.py --list-patterns                      # 使えるパターン一覧
```

**社内固有のパターンを追加する場合（`sensitive_patterns_user.py` を同ディレクトリに作成）:**

```python
PATTERNS = [
    # (名前, 正規表現, レベル)
    ("社内社員番号", r"\bEMP-\d{6}\b", "high"),
    ("社内プロジェクト ID", r"\bPRJ-[A-Z]{2}-\d{4}\b", "medium"),
]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| HIGH（AWS キー / JWT / PEM 等） | シークレット漏洩 | 即確認。JWT は `../02_Initial_Access/Web_Vulnerabilities/JWT_Attacks.md` |
| HIGH（スタックトレース / 内部パス） | 内部構造の漏洩 | パストラバーサル・内部 IP の足掛かりに |
| MEDIUM（内部識別子・フォーム値） | 攻撃面 | 記録して後続フェーズで活用 |
| 全部 LOW / MEDIUM で HIGH なし | 未認証では機密なし | **§4 認証後の再スキャンを必ず実施** |

**注意:** Luhn 検証付きのクレジットカードパターンは誤検知が少ないが、テスト用カード番号（`4111111111111111` 等）はテストデータとして除外する。

---

## 2. セキュリティヘッダー / Cookie 属性の確認（Burp / DevTools）

スクリプトが使えない環境でも目視で確認できる。

**手順（スクリプト不要）:**

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

**観測される出力 → 次のアクション:**

| 観測内容 | 示唆 | 次のアクション |
|---------|------|-------------|
| CSP に `unsafe-inline` / `unsafe-eval` | XSS があれば任意 JS 実行 | XSS の有無を最優先確認 → `../02_Initial_Access/Web_Vulnerabilities/XSS.md` |
| `Referrer-Policy: unsafe-url` / `no-referrer-when-downgrade` | URL パラメータが 3rd party に漏洩 | センシティブなパラメータの有無を確認 |
| `Server:` / `X-Powered-By:` でバージョン露出 | 既知 CVE の可能性 | `searchsploit` → `Web_Enumeration.md` |
| `Set-Cookie` で HttpOnly 欠落 | XSS でトークン窃取が可能 | `../02_Initial_Access/Web_Vulnerabilities/XSS.md` |
| `Set-Cookie` で SameSite=None / 属性なし、かつ状態変更が Cookie のみで認証される | クロスサイトから状態変更を強制できる可能性 | `../02_Initial_Access/Web_Vulnerabilities/CSRF.md` |
| `Access-Control-Allow-Origin` がリクエスト `Origin` を動的反射 / `null` 許可 / `Allow-Credentials: true` | クロスオリジンで認証済みレスポンスを窃取できる可能性 | `../02_Initial_Access/Web_Vulnerabilities/CORS.md` |

**注意:** `X-Frame-Options` と CSP `frame-ancestors` は重複し後者が優先される。両方欠落した場合のみ確実にクリックジャッキング指摘可能。`Server:` / `X-Powered-By:` は WAF / CDN が書き換えていることがあり直接の証跡にならない場合がある。CORS の ACAO 反射確認は任意の `Origin:` ヘッダーを送って反射可否を見る軽い能動テストを伴う（手順は `../02_Initial_Access/Web_Vulnerabilities/CORS.md` §1）。`*` + credentials はブラウザが拒否するため、実害判定は ACAO 反射と `Allow-Credentials` の組み合わせで行う。

---

## 3. Burp 拡張 / nuclei によるライブスキャン

`sensitive_scan.py` はキャプチャ済みデータの解析、**`nuclei` は対象へのライブクエリ**で使い分ける。両方を組み合わせて死角を減らす。

**Burp 拡張（BApp Store からインストール・パッシブ常駐）:**

| 拡張名 | 機能 | 主な検出対象 |
|---|---|---|
| TruffleHog | レスポンス本文を API キー / シークレット正規表現で自動スキャン | AWS / GCP / Azure / Stripe / Slack 等 |
| Retire.js | JS ライブラリ参照を解析し既知脆弱バージョンを警告 | jQuery 1.x / Angular 旧版 / Bootstrap 等 |
| Active Scan++ | スキャナーチェックの拡張（GraphQL / Cache poisoning 等） | アクティブスキャン補完 |
| JS Miner | JS ファイル内のエンドポイント / シークレット抽出 | 隠れ API / 内部ドメイン |
| Secrets Finder | TruffleHog 同等 | 各社シークレット |

**コマンド:**

```bash
# [Attacker] exposures / tokens / misconfig 系テンプレートでまとめてスキャン
nuclei -u https://[TARGET] -t http/exposures/tokens/ -t http/exposures/configs/ -t http/misconfiguration/ \
  -severity medium,high,critical -o nuclei_triage.txt

# [Attacker] レスポンス内のシークレット網羅
nuclei -u https://[TARGET] -t http/exposures/tokens/ -o nuclei_tokens.txt

# [Attacker] 認証後 cookie / Authorization を渡してスキャン（§4 と連動）
nuclei -u https://[TARGET] -t http/exposures/ -t http/misconfiguration/ \
  -H "Cookie: session=[VALUE]" -H "Authorization: Bearer [TOKEN]" -o nuclei_auth.txt
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| TruffleHog / nuclei tokens がヒット | クラウドキー漏洩 | 即確認・該当サービスへの影響評価 |
| Retire.js が old & vulnerable を警告 | 既知脆弱 JS ライブラリ | バージョンの CVE を確認 |
| JS Miner が隠れ API / 内部ドメイン | 裏エンドポイント | 各エンドポイントを直接叩いて認可不備を確認 |

**注意:** Burp 拡張をパッシブ常駐させると、本ファイルの観点（シークレット漏洩・古ライブラリ・JS 内エンドポイント）の多くを手動チェック前に自動で網羅できる。

---

## 4. 🚨 認証後レスポンスの再スキャン（最重要）

> **[HIGH IMPACT]** 「未認証で問題なし」と判断するだけは絶対に NG。Web アプリのシークレット漏洩・PII 露出の大半は**ログイン後のページ・認証付き API レスポンス**で起きる。トリアージは **(1) 未認証 → (2) ロール別の認証後（一般ユーザー / 管理者 / 開発者など）** の各段階でやり直す。

**やり直す対象と着目点:**

| やり直す対象 | 着目点 |
|---|---|
| ログイン直後のリダイレクト先（ダッシュボード） | 内部 ID・社員番号・部署コード・JWT・API キーが HTML / JSON に埋め込まれていることが多い |
| `/api/me` / `/api/users/[ID]` 等のユーザー情報 API | PII（メール / 電話 / 住所）・内部 role 名・グループ ID |
| 管理者ロールでの `/admin/*` 配下 | 管理者専用設定値・他ユーザーのトークン・LDAP / DB 接続情報 |
| エラー時のスタックトレース（ログイン後 API で 500 系を起こす） | ファイルパス / クラス名 / DB スキーマ / 内部 IP |
| Cookie 取得後の再 nuclei スキャン | `-H "Cookie: session=..."` 付きでテンプレ実行（§3）|

**手順:**

1. 未認証スキャン（§1〜§3）
2. **テストアカウント（一般 / 管理者の最低 2 ロール）でログイン → Burp で全リクエスト再キャプチャ**
3. キャプチャを `sensitive_scan.py` / nuclei / Burp 拡張で**もう一度通す**
4. 認証後だけに現れる検出を本番 finding として扱う

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 認証後にのみ HIGH 検出 | 認可後の漏洩 | 本番 finding として記録 |
| 管理者ロールで他ユーザーのトークン | 権限分離不備 | IDOR / 認可不備として深堀り → `../02_Initial_Access/Web_Vulnerabilities/IDOR.md` |

**注意:** 未認証スキャンだけで「問題なし」と結論を出さない。最低でも一般ユーザーと管理者の 2 ロールで再キャプチャする。

---

## 5. 分散トレーシングヘッダの偵察（observability スタック特定）

W3C Trace Context（W3C Recommendation, 2021）と W3C Baggage が定義する伝播ヘッダ。マイクロサービス間でリクエストを相関させるためのもので、**認証・認可機構ではない**。リクエスト/レスポンスに出ていたら「観測基盤の採用」「観測ベンダの判別」「内部相関 ID 体系の露出」が拾える。価値はスタック特定と情報露出が主体（Cookie 名や `Server:` ヘッダーからのフィンガープリンティングと同じ粒度）。

**手順（Burp / DevTools 目視 or grep）:**

```
リクエスト・レスポンス両方で確認（伝播ヘッダなので両方向に出る）:
  traceparent / tracestate / traceresponse / baggage

形式の読み方:
  traceparent: 00-<32hex trace-id>-<16hex span-id>-<2hex flags>
               │  trace-id            span-id         flags(下位bit 01=sampled)
               version
  tracestate:  <vendorkey>=<value>,...   ← ベンダキーで観測 SaaS / 実装を特定
  baggage:     key=value,...             ← アプリ任意文脈(KV)をサービス間で伝播

grep 例:
  grep -iE '^(traceparent|tracestate|traceresponse|baggage):' captured.txt
```

**観測される出力 → 次のアクション:**

| 観測内容 | 示唆 | 次のアクション |
|---------|------|-------------|
| `traceparent` / `traceresponse` が存在 | OTel / Jaeger / Zipkin 系の分散トレーシング採用が確定 | 観測 UI（Jaeger / Zipkin / Grafana 等）が外部公開されていないか確認 → `Exposed_Files.md`（管理コンソール誤公開） |
| `tracestate` のベンダキー（`dd=` / `b3` / 独自キー） | 観測 SaaS / 実装の特定（`dd=`→Datadog、`b3`→Zipkin/B3 系 等） | スタック情報として記録。製品別の既定エンドポイント・露出 UI を確認 |
| `trace-id` がエラー画面 / レスポンス本文に反射 | 内部相関 ID 体系の露出 | 情報露出 finding 候補。反射するなら `tracestate` 無検証時の注入も確認 |
| `baggage` / `tracestate` に `user` / `tenant` / `role` 等の identity 相当 | 信頼境界違反の疑い（下流が値を信頼すると認可不備に直結） | 値を差し替えてテナント越境 / 権限昇格を確認 → `../02_Initial_Access/Web_Vulnerabilities/IDOR.md` |

**注意:**

- `traceparent` 単体は認証・認可トークンではないので、これ自体で侵入はできない。実利は **(1) 観測スタック特定（フィンガープリンティング）** と **(2) 内部相関 ID 露出（情報漏洩）**。
- `tracestate` / `baggage` は値の文字種が緩く、**無検証で収集 → トレース閲覧 UI に表示**する実装だと log injection → 観測 UI のストアド XSS の媒体になりうる。成立は観測基盤側のサニタイズ不備が前提で、実装依存。
- `baggage` にアプリが identity / tenant / role を載せ、下流サービスがそれを信頼して認可判断に使うアンチパターンでは、値の改竄が**なりすまし・権限昇格・テナント越境**に直結する（外部信頼境界を越えて素通しする構成が前提）。〔この経路の成立条件・PoC は実装依存。明確な公開出典は未確認〕
- sampled flag（`01`）を大量送信すると観測パイプラインの負荷・トレースストレージ・従量課金 SaaS の課金額が膨らむ DoS レバーになりうる。負荷を伴うテストは合意範囲内で。
- これらは外部レスポンスに出ていなくても内部では伝播していることが多い。**外部に漏れていること自体**が情報露出 finding。

---

## 刺さらなかったとき（全体）

| 状況 | 推定原因 | 対処 |
|------|---------|------|
| スキャン結果が全部 LOW / MEDIUM で HIGH がない | 未認証では機密が返っていない | 次フェーズへ。ただし**必ず §4 認証後の再スキャンを実施** |
| スキャン結果が大量で判断できない | ノイズが多い | `--no-low` で絞り込み、HIGH だけ先に片付ける |
| nuclei が偽陽性を出す | 共通 WAF が類似レスポンス | 個別ヒットを手動再現してから採用 |

---

## 注意点・落とし穴

- セキュリティヘッダーの欠落は「問題が確認できる最初のレスポンス」で報告するが、全エンドポイントに欠落しているか・一部だけかを確認してから範囲を記述する
- `Server:` / `X-Powered-By:` ヘッダーは WAF / CDN が書き換えている場合があり、エラーページや既知のパスから二重確認する

> **個別ブロック固有の注意は各 §N の「注意:」を参照。**

---

## 本番での前提

- **事前合意の要否**: ★（技術的判断のみ。キャプチャ済みデータの解析が主体。§3 nuclei のライブスキャンはアクティブ通信を伴うため対象組織との合意範囲を確認）
- **業務影響リスク**: なし（パッシブ解析）/ 軽微（nuclei ライブスキャン）
- **取得情報の取扱**: スキャン結果に含まれる PII / シークレットは暗号化保管・テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：`Web_Enumeration.md`（Web アプリの初期偵察・Cookie 分類）
- 前：`TLS_Audit.md`（HSTS 等 TLS 関連ヘッダーの詳細確認）
- 後：`../02_Initial_Access/Web_Vulnerabilities/XSS.md`（HttpOnly 欠落・CSP 弱体の悪用）
- 後：`../02_Initial_Access/Web_Vulnerabilities/CSRF.md`（SameSite=None/欠落 + Cookie のみ認証の状態変更）
- 後：`../02_Initial_Access/Web_Vulnerabilities/CORS.md`（ACAO 動的反射 / Allow-Credentials の緩い CORS ヘッダーを検出した場合）
- 後：`../02_Initial_Access/Web_Vulnerabilities/JS_Obfuscation.md`（JWT / エンコード値の多重デコード）
- 後：`../02_Initial_Access/Web_Vulnerabilities/JWT_Attacks.md`（JWT が検出された場合）
- 後：`../02_Initial_Access/Web_Vulnerabilities/IDOR.md`（認証後の認可不備）
- 後：`../05_Tools_Reference/Searchsploit.md`（Server ヘッダーのバージョンから CVE 検索）

> 原理（なぜスクリプト・Burp・DevTools を使い分けるのか）→ `../06_Concepts/Web_Pentest_Tooling.md`
