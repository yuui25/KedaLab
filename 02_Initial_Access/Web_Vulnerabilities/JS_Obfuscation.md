# 難読化JavaScript解析

## 着火条件
- Webアプリのページソースに `eval(function(p,a,c,k,e,d){...})` 等の難読化JSが含まれる
- `/js/*.min.js` にAPIエンドポイントや隠し機能のヒントが埋め込まれている可能性がある
- 招待コード・隠しAPIパス・認証フローがJS内にハードコードされていることがある

## 観点・着眼点

難読化JSはソースを読めなくするためのものだが、**ブラウザ上で動作するため必ずデコード可能**。
`eval()` の引数を `console.log()` に置き換えるだけで内容が見える。

**確認すべきシグナル：**

| パターン | 難読化形式 | 対処 |
|---------|----------|------|
| `eval(function(p,a,c,k,e,d){...})` | Dean Edward's Packer | evalをconsole.logに置換 or de4js |
| `atob('...')` 内の長い文字列 | Base64埋め込みコード | `atob(...)` をConsoleで実行 |
| 意味不明な変数名（`_0x1a2b` 等） | 変数名難読化 | beautifier.io + 目視 |

**デコード後に確認すべきこと：**

- APIエンドポイントのURLパス
- HTTPメソッド（GET / POST / PUT 等）とパラメータ名
- エンコーディング種別（Base64 / ROT13 等）
- 別のAPIを呼び出す関数の存在

## 手順

## 方法1: ブラウザのDevTools（最も手早い）

1. F12 でDevToolsを開く
2. **Sources** タブ → 対象のJSファイルを選択
3. 左下の **`{}`（Pretty Print）** ボタンをクリック → コードが整形される
4. 関数名・URLを目視で確認する

## 方法2: ブラウザConsoleで eval を console.log に置き換える

```javascript
// 元の難読化コード（例）
eval(function(p,a,c,k,e,d){...}('...', 24, 24, '...'.split('|'), 0, {}))

// Console で eval を console.log に置き換えて実行
console.log(function(p,a,c,k,e,d){...}('...', 24, 24, '...'.split('|'), 0, {}))
// → デコードされたJSがConsoleに出力される
```

## 方法3: オンラインツール

- [de4js](https://de4js.kshift.me/) — Dean Edward's Packer 専用、そのまま貼り付けるだけ
- [beautifier.io](https://beautifier.io/) — 汎用コード整形

## APIレスポンスのエンコーディング確認

JSを解析してAPIエンドポイントを特定したあと、そのAPIのレスポンスがさらにエンコードされている場合がある。

```
レスポンス例:
{
    "data": "Va beqre gb trarengr gur vaivgr pbqr...",
    "enctype": "ROT13"
}
```

**`enctype` / `encryptionType` / `encoding` フィールドを必ず確認する：**

| enctype値 | デコード方法 |
|----------|-----------|
| `ROT13` | `echo "..." \| tr 'A-Za-z' 'N-ZA-Mn-za-m'` |
| `BASE64` | `echo "..." \| base64 -d` |
| `BASE32` | `echo "..." \| base32 -d` |

```bash
# ROT13（Linuxコマンド）
echo "Va beqre gb trarengr..." | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# ROT13（Python）
python3 -c "import codecs; print(codecs.decode('Va beqre...', 'rot_13'))"

# Base64
echo "NkZQQjAtTFc4SkYtR0VZMlAtTzE5WEQ=" | base64 -d
```

## 注意点・落とし穴
- `eval` を `console.log` に置き換えるだけで読める場合がほとんどだが、多段階難読化の場合は段階ごとにデコードが必要
- デコードされたJSに新たなAPIエンドポイント（`/api/v1/...`）が含まれる場合、そのエンドポイントを直接叩くのが次の手
- レスポンスの `enctype` が `ROT13` の場合、デコードするとさらに「次のAPIエンドポイントに POST せよ」という指示が出ることがある。指示に従って POST リクエストを送る
- ブラウザのConsoleはページのドメインに紐付いているため、難読化JSをConsoleに直接貼り付けて実行しても安全に動作する（外部サイトへのリクエストはCORSで制限される）

---

## 多重エンコードの自動検出・再帰デコード

## 着火条件

- Cookie 値・クエリパラメータ・ボディ・Authorization ヘッダーの値が「何かエンコードされているが何重か分からない」場合
- Burp Decoder で 1 層剥がしたら別のエンコードが出てきた、を繰り返しているとき
- JWT の `alg` ヘッダーや `payload` の中身を素早く確認したい場合

## 観点・着眼点

**攻撃者の思考トレース：** エンコード層が多いと「まず何がかかっているか」を判定するコストが高い。
URL エンコードの中に Base64 がある、その中に gzip、さらにその中に JSON、というケースは珍しくない。
層の深さを手動で数えるより先に、自動判定ツールで「何層あるか・最終的に何が出てくるか」を把握してから
攻撃面を評価する。

**多重エンコードが疑われるシグナル：**

| 観測パターン | 疑われるエンコード | 確認手順 |
|------------|---------------|---------|
| `%25` / `%2B` / `%252F` 等のパーセント記号が多い | URL ダブルエンコード（`%25` = `%` の URL エンコード） | 2 回以上 URL デコードを繰り返す |
| `eyJ` で始まる文字列（Base64URL） | JWT（header.payload.signature 構造） | `.` で 3 分割 → 各部を Base64URL デコード → JSON |
| 長い英数字列（`[A-Za-z0-9+/=]{8,}` 形式） | Base64 | デコードして中身がテキストか確認 |
| `%1f%8b` または Base64 デコード後に非テキスト bytes | gzip 圧縮 | gzip 解凍 → テキスト化 |
| `A` / `\x41` を含む文字列 | Unicode / JS エスケープ | `\u` / `\x` を文字に展開 |
| `=?UTF-8?B?...?=` 形式 | MIME encoded-word（メールヘッダー経由など） | MIME デコード |
| `xn--` を含むドメイン名 | Punycode / IDN | punycode デコード |

## 手順

**事前準備（必須）：** デコード対象の値をファイルに書き出すか、コマンドラインで直接渡せる形にしておく。

```bash
# [Attacker] decode_layers.py（Python 3 標準ライブラリのみ）

# 文字列を直接渡す（最も手早い）
python decode_layers.py --string "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.xxx"

# Raw HTTP リクエストファイルを食わせて Cookie / クエリ / ボディを一括デコード
python decode_layers.py request.txt --all
# --cookies  : Cookie 値だけ
# --query    : クエリパラメータだけ
# --body     : ボディパラメータだけ

# Burp の Decoder タブで手動チェーンする場合（ツール不要）
# Decoder → 貼り付け → "Decode as" で URL / Base64 / HTML を順番に適用
# Inspector（右ペイン）: 値を選択すると即時デコード（1 値ずつ）
# Hackvertor 拡張（入っている場合）:
#   <@unbase64><@urldecode>...</@urldecode></@unbase64> のタグ形式で自動チェーン

# DevTools Console で手動デコードする場合
# URL デコード
decodeURIComponent("%25%37%42%22a%22%3A1%25%37%44");
# Base64
atob("eyJ1c2VyIjoiYWRtaW4ifQ==");
# JWT の payload を確認
JSON.parse(atob("eyJ1c2VyIjoiYWRtaW4ifQ==".replace(/-/g,'+').replace(/_/g,'/')));
```

**デコード後に確認すること：**

| 最終的な中身 | 着眼点 |
|------------|------|
| `{"user":"admin","role":"user"}` のような JSON | `role` / `is_admin` / `uid` を改ざんして再エンコードし再送（→ IDOR / 権限昇格） |
| UUID / 連番 ID | 他ユーザーの ID に差し替えて再送（→ IDOR） |
| 平文のユーザー名・パスワード | Basic 認証の base64 → credential reuse 確認 |
| JWT | `alg` / `kid` / `jku` 等の攻撃面を確認 → `JWT_Attacks.md` |
| 内部パス / ホスト名 | SSRF・パストラバーサルの入力面として利用 |

## 刺さらなかったとき

- 自動検出で「no encoding detected」 → 値が短すぎる（8 文字未満）か、独自エンコードの可能性。Burp Comparer で正常値と比較して差分を見る
- Base64 デコードで文字化けバイナリが出た → 非テキスト（バイナリプロトコル / 独自フォーマット）。`file` コマンドでマジックバイトを確認する

## 注意点・落とし穴

- Base64 と Base64URL は文字セットが異なる（`+/` vs `-_`）。変換せずにデコードすると文字化けする
- JWT の署名を改ざんすると検証失敗するが、**`alg: none`** に変えると検証をスキップするサーバーがある → `JWT_Attacks.md` 参照
- Burp Decoder の "Smart decode" は 1 段しか剥がさない。多重の場合は手動で繰り返す必要がある

## 関連技術

- 前：Webディレクトリ・エンドポイント列挙でJSファイルを発見 → `../../01_Reconnaissance/Web_Enumeration.md`
- 後：発見したAPIエンドポイントへのコマンドインジェクション → `./Command_Injection.md`
- 後：デコード結果が JWT だった場合の攻撃手順 → `./JWT_Attacks.md`
- 後：デコード結果に ID が含まれていた場合 → `./IDOR.md`
- 関連：多重エンコードの識別方法・各エンコード形式の原理 → `../../06_Concepts/Web_Pentest_Tooling.md`
