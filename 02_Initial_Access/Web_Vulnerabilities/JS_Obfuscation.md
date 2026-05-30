# 難読化JavaScript解析 / 多重エンコード検出

> **スコープ**: 難読化 JS のデコード（ソースマップ確認〜DevTools〜eval 置換〜obfuscator.io 系ツール）と、API レスポンス・Cookie の多重エンコード解析。API エンドポイント・認証情報・攻撃面の抽出が目的。JWT が検出された場合は `JWT_Attacks.md`、IDOR が検出された場合は `IDOR.md` を参照。

## 着火条件

- Web アプリのページソースに `eval(function(p,a,c,k,e,d){...})` 等の難読化 JS が含まれる
- `/js/*.min.js` に API エンドポイントや隠し機能のヒントが埋め込まれている可能性がある
- 招待コード・隠し API パス・認証フローが JS 内にハードコードされていることがある
- Cookie 値・クエリパラメータ・Authorization ヘッダーの値が何らかのエンコードで見づらい

## 環境前提

- 実行環境: テスター端末
- 必要なツール: ブラウザ（DevTools）/ `npx synchrony` / `npx de4js`（Node.js が必要）/ `sourcemapper`（`pip install sourcemapper`）/ `python3`
- オフライン代替: DevTools（§2・§3）と Python（§6）はオフラインで完結。§4 ツールは npm 経由が必要（事前取得が必要）

## 先に確認すること

- **難読化形式を先に判定する**（適切なツールが変わる）:

| パターン | 難読化形式 | 最適ツール |
|---------|----------|------|
| `eval(function(p,a,c,k,e,d){...})` | Dean Edward's Packer | eval → console.log 置換 or de4js（§3）|
| `atob('...')` 内の長い文字列 | Base64 埋め込みコード | ブラウザ Console で `atob(...)` を実行（§3）|
| `_0x1a2b` 等の変数名 + 文字列配列 + 難読化ループ | **obfuscator.io 系**（現代的難読化の主流）| `synchrony deobfuscate`（§4）|
| `_0x` 変数名 + string array shuffle + control-flow flattening | obfuscator.io 高強度設定 | `synchrony deobfuscate`（§4）|

- **デコード後に確認すべきこと**: API エンドポイントの URL パス / HTTP メソッドとパラメータ名 / エンコーディング種別 / 別 API を呼び出す関数

**攻撃者の思考トレース:** 難読化 JS は必ずデコード可能（ブラウザ上で動作するため）。最初に§1 のソースマップを確認する（あれば一切の手間が省ける）。なければ難読化形式を判定してから最適ツールを選ぶ。多重エンコードも「何層あるか」を自動判定して攻撃面を評価する方が手動より早い。

---

## 1. ソースマップ（`.js.map`）の確認（**最優先・特効薬**）

難読化 / minify された JS を解読する前に、**ソースマップが公開されていないか**を確認する。あれば元の TypeScript / ES2019+ コードが**そのまま**手に入る。

**コマンド:**

```bash
# [Attacker] JS ファイルの末尾コメントでソースマップ参照を確認
curl -s https://[TARGET]/js/app.min.js | tail -5
# 出力例: //# sourceMappingURL=app.min.js.map

# [Attacker] .map ファイルを直接取得
curl -s https://[TARGET]/js/app.min.js.map -o app.min.js.map
curl -s https://[TARGET]/static/js/main.chunk.js.map
curl -s https://[TARGET]/assets/js/bundle.js.map

# [Attacker] sourcemap ファイルから元ソースを取り出す
pip install sourcemapper
sourcemapper -url https://[TARGET]/js/app.min.js.map -output ./extracted_src/
# 手動: .map の `sources` 配列と `sourcesContent` が元ファイルパスと内容
python3 -c "
import json; m = json.load(open('app.min.js.map'))
for p, c in zip(m['sources'], m.get('sourcesContent', [])):
    print(f'=== {p} ==='); print(c[:200])
"
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `.map` が 200 で返る | ソースマップが公開されている | `sourcemapper` で元ソースを復元。API エンドポイント・認証ロジックを直接読む |
| DevTools Sources に `webpack://` / `ng://` ツリー | ソースマップが自動ロードされている | Source タブで元コードを直接読める |
| `.map` が 404 | ソースマップ非公開 | §2〜§4 の解析ツールへ |

**注意:** ブラウザで DevTools → Sources タブを開くと「webpack://」ツリーが現れていれば自動ロード済み。コード補完や元ファイル名で検索できる。

---

## 2. DevTools Pretty Print（最も手早い）

**手順:**

```
1. F12 で DevTools を開く
2. Sources タブ → 対象の JS ファイルを選択
3. 左下の「{}（Pretty Print）」ボタンをクリック → コードが整形される
4. 関数名・URL を目視で確認する
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| API パス・認証トークン・エンドポイントが読める | 通常の minify のみ（難読化なし）| そのままエンドポイントを叩く |
| `_0x1a2b` 等の意味不明な変数名が続く | obfuscator.io 系 | §4 専用ツールへ |

---

## 3. ブラウザ Console で eval → console.log 置換

**コマンド（ブラウザ Console）:**

```javascript
// 元の難読化コード（例）
// eval(function(p,a,c,k,e,d){...}('...', 24, 24, '...'.split('|'), 0, {}))

// eval を console.log に置き換えて実行
console.log(function(p,a,c,k,e,d){...}('...', 24, 24, '...'.split('|'), 0, {}))
// → デコードされた JS が Console に出力される
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| デコードされた JS が Console に出力される | Dean Edward's Packer 形式 | API エンドポイント・エンコード種別を特定して §5 へ |
| 何も変わらない / エラー | obfuscator.io 系（多段難読化）| §4 専用ツールへ |

**注意:** ブラウザ Console に JS を貼り付けて実行すると、**そのページのドメインの権限**で動作する。外部への CORS 制限はかかるが、**ターゲット自身への API 呼び出し・Cookie アクセス・DOM 操作は完全に可能**。`fetch('/api/admin/users')` を貼り付けるとそのページのセッションで管理 API を叩ける。

---

## 4. obfuscator.io 系 / 現代難読化ツール

`eval → console.log` 置換が効かない `_0x` 系（obfuscator.io 形式）は専用ツールを使う。

**コマンド:**

```bash
# [Attacker] synchrony — 最も対応範囲が広い（obfuscator.io 系の事実上標準）
npx synchrony deobfuscate obfuscated.js
npx synchrony deobfuscate obfuscated.js --output clean.js

# [Attacker] de4js — Web UI + CLI（Dean Edward's Packer / obfuscator.io 系対応）
npx de4js obfuscated.js
# または Web UI: https://de4js.kshift.me/ に貼り付け

# [Attacker] js-deobfuscator（synchrony が刺さらない場合の代替）
npm install -g js-deobfuscator
js-deobfuscator --input obfuscated.js --output clean.js
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `clean.js` に可読な JS が出力される | デオブファスケーション成立 | API エンドポイント・認証ロジックを読んで攻撃面を特定 |
| 出力が依然として意味不明 | 独自 obfuscator / 多段難読化 | §1 ソースマップに戻る。または手動解析 |
| `_0x` 変数名が多段になっている | 高強度設定 | `synchrony` → beautifier.io → 手動解析 の順で試す |

**注意:** デコードされた JS に新たな API エンドポイント（`/api/v1/...`）が含まれる場合、そのエンドポイントを直接叩くのが次の手。多段階難読化の場合は段階ごとにデコードが必要。

---

## 5. API レスポンスのエンコーディング確認

JS を解析して API エンドポイントを特定した後、そのレスポンスがさらにエンコードされている場合がある。

**コマンド:**

```bash
# ROT13（Linux コマンド）
echo "Va beqre gb trarengr..." | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# ROT13（Python）
python3 -c "import codecs; print(codecs.decode('Va beqre...', 'rot_13'))"

# Base64
echo "NkZQQjAtTFc4SkYtR0VZMlAtTzE5WEQ=" | base64 -d
```

**観測される出力 → 次のアクション:**

| `enctype` / `encoding` 値 | デコード方法 | 次のアクション |
|---|---|---|
| `ROT13` | `echo "..." \| tr 'A-Za-z' 'N-ZA-Mn-za-m'` | デコード結果が「次の API エンドポイントに POST せよ」という指示が出ることがある |
| `BASE64` | `echo "..." \| base64 -d` | デコード結果を確認して攻撃面を特定 |
| `BASE32` | `echo "..." \| base32 -d` | 同上 |

**注意:** `enctype` / `encryptionType` / `encoding` フィールドを必ず確認する。デコードするとさらに「次の API に POST せよ」という指示が出ることがある。

---

## 6. 多重エンコードの自動検出・再帰デコード

**着火条件:** Cookie 値・クエリパラメータ・ボディ・Authorization ヘッダーの値が「何かエンコードされているが何重か分からない」場合。

**多重エンコードが疑われるシグナル:**

| 観測パターン | 疑われるエンコード | 確認手順 |
|------------|---------------|---------|
| `%25` / `%2B` / `%252F` 等のパーセント記号が多い | URL ダブルエンコード（`%25` = `%`）| 2 回以上 URL デコードを繰り返す |
| `eyJ` で始まる文字列 | JWT（header.payload.signature 構造）| `.` で 3 分割 → 各部を Base64URL デコード → JSON |
| 長い英数字列（`[A-Za-z0-9+/=]{8,}` 形式）| Base64 | デコードして中身がテキストか確認 |
| `%1f%8b` または Base64 デコード後に非テキスト bytes | gzip 圧縮 | gzip 解凍 → テキスト化 |
| `=?UTF-8?B?...?=` 形式 | MIME encoded-word | MIME デコード |
| `xn--` を含むドメイン名 | Punycode / IDN | punycode デコード |

**コマンド:**

```bash
# [Attacker] decode_layers.py（Python 3 標準ライブラリのみ）
python decode_layers.py --string "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.xxx"
python decode_layers.py request.txt --all   # Cookie / クエリ / ボディを一括デコード

# Burp Decoder タブで手動チェーン（ツール不要）
# Decoder → 貼り付け → "Decode as" で URL / Base64 / HTML を順番に適用

# DevTools Console で手動デコード
decodeURIComponent("%25%37%42%22a%22%3A1%25%37%44");   # URL デコード
atob("eyJ1c2VyIjoiYWRtaW4ifQ==");                      # Base64
JSON.parse(atob("eyJ1c2VyIjoiYWRtaW4ifQ==".replace(/-/g,'+').replace(/_/g,'/')));  # JWT
```

**デコード後の確認事項と次のアクション:**

| 最終的な中身 | 着眼点 | 次のアクション |
|------------|------|------------|
| `{"user":"admin","role":"user"}` のような JSON | `role` / `is_admin` / `uid` を改ざんして再エンコード・再送 | IDOR / 権限昇格 → `IDOR.md` |
| UUID / 連番 ID | 他ユーザーの ID に差し替えて再送 | IDOR → `IDOR.md` |
| 平文のユーザー名・パスワード | Basic 認証の Base64 → credential reuse 確認 | `../Credential_Discovery.md` |
| JWT | `alg` / `kid` / `jku` 等の攻撃面を確認 | `JWT_Attacks.md` |
| 内部パス / ホスト名 | SSRF・パストラバーサルの入力面 | `SSRF.md` / `Path_Traversal.md` |

**注意:** Base64 と Base64URL は文字セットが異なる（`+/` vs `-_`）。JWT で変換しないとデコード文字化けする。Burp Decoder の "Smart decode" は 1 段しか剥がさないので多重の場合は手動で繰り返す。

---

## 刺さらなかったとき（全体）

| 状況 | 推定原因 | 代替手段 |
|---|---|---|
| ソースマップが 404 | 非公開 | §2〜§4 の解析ツールへ |
| `synchrony` で出力が依然として難読 | 独自 obfuscator / 多段難読化 | beautifier.io で整形後に手動解析 |
| 自動検出で「no encoding detected」| 値が短い（8 文字未満）か独自エンコード | Burp Comparer で正常値と比較して差分を見る |
| Base64 デコードで文字化けバイナリ | 非テキスト（バイナリプロトコル）| `file` コマンドでマジックバイトを確認 |

---

## 注意点・落とし穴

- `eval` → `console.log` 置換が効く場合がほとんどだが、多段階難読化は段階ごとにデコードが必要
- JWT の署名を改ざんすると検証失敗するが、`alg: none` に変えると検証をスキップするサーバーがある → `JWT_Attacks.md` 参照
- `_0x` 形式でも synchrony が刺さらない場合は js-deobfuscator / beautifier.io + 手動解析の組み合わせで対応する

---

## 関連技術

- 前：Web ディレクトリ・エンドポイント列挙で JS ファイルを発見 → `../../01_Reconnaissance/Web_Enumeration.md`
- 後：発見した API エンドポイントへのコマンドインジェクション → `Command_Injection.md`
- 後：デコード結果が JWT だった場合の攻撃手順 → `JWT_Attacks.md`
- 後：デコード結果に ID が含まれていた場合 → `IDOR.md`
- 関連：多重エンコードの識別方法・各エンコード形式の原理 → `../../06_Concepts/Web_Pentest_Tooling.md`
