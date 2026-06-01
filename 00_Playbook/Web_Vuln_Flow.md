# Web脆弱性調査フロー（Webのみスコープ向け）

**シェル取得を目的としない、Webアプリの脆弱性を網羅的に洗い出すスコープ向けのPlaybook。**

SaaS・クラウドWebアプリ・APIのみを対象とした診断スコープで使う。

> **ペネトレとしてWebシステムを起点にシェル取得を目指す場合は、このファイルではなく `Linux_Attack_Flow.md` の Step 2 から進めること。**
> このファイルはWeb診断スコープ（脆弱性の網羅的な洗い出し）専用。
>
> **本番の場合**：本フローに入る前にスコープ・実施可否・除外エンドポイント（決済・本番データ等）について事前合意を確認すること。

---

## 開始条件の確認

**このファイルを開いたら最初にここを読む。** 手元にある情報によってスタート位置が変わる。

| 提供されている情報 | 開始位置 |
|------------------|---------|
| URL / ドメインのみ | Step 0（スコープ確認）→ Step 1（偵察）から始める |
| 認証情報（ID/パス）付き | Step 0 を確認後、Step 2 を**認証後の機能にも適用**する。認証後エンドポイントへの IDOR・権限昇格も確認対象 |
| 認証情報なし・ブラックボックス | Step 1 から始めて、ログインフォームが見つかり次第 SQLi・デフォルト認証情報を確認 |
| 「JWT を使っている」と事前に判明 | Step 1 完了後、Step 2 の JWT 行と Step 3「4層目」を優先して確認する |

---

## フロー概要

```
[Step 0: スコープ確認]
       ↓
[Step 1: 偵察]                         → 01_Reconnaissance/
   ├─ ポートスキャン
   ├─ ディレクトリ列挙
   ├─ vhost ファジング
   └─ レスポンス一次トリアージ          → Web_Response_Triage.md
       ├─ Cookie 分類（third-party 除外 → テスト対象を絞る）
       └─ 機微情報・設定不備スキャン（セキュリティヘッダー / Cookie 属性 / PII / APIキー）
       ↓
[Step 2: 機能別の脆弱性確認]           → 02_Initial_Access/Web_Vulnerabilities/
   ├─ ログインフォーム → SQLi / デフォルト認証情報
   ├─ JWT（eyJ...）   → JWT_Attacks.md（Step 3「4層目」へ）
   ├─ エンコードされた値（Cookie / クエリ / ボディ） → 多重デコード → 攻撃面の評価
   ├─ URLパラメータ   → IDOR / パストラバーサル
   ├─ ユーザー入力反映 → XSS
   ├─ 外部URLパラメータ → SSRF
   ├─ XMLアップロード  → XXE / XSLT インジェクション
   ├─ OS コマンド受け取り → Command Injection
   └─ 難読化JS / 不明機能 → JS_Obfuscation / 01_Unknown_Tech_Research
       ↓
[Step 3: 認証・認可の横断確認]
   ├─ 1層目：認証なしアクセス（Broken Access Control）
   ├─ 2層目：低権限 → 高権限（is_admin=1 等のパラメータ改ざん）
   ├─ 3層目：横断アクセス（IDOR）
   └─ 4層目：JWT 検出時のみ（alg 確認 → 署名バイパス）
       ↓
[Step 4: バージョン確認 → CVE 検索]   → 05_Tools_Reference/Searchsploit.md
```

---

## Step 0：スコープの確認

作業開始前に以下を明確にする：

- **対象ドメイン・IPレンジ** — どこまで触ってよいか
- **除外エンドポイント** — 管理画面・決済フロー・本番データに触れる操作の要承認範囲
- **認証情報の有無** — 「認証後の機能」もスコープに含まれるか

---

## Step 1：偵察

### ポートスキャン

```bash
nmap -sC -sV -oN nmap_initial.txt [TARGET_IP]   # [Attacker]
```

- 80/443以外のポートが開いていれば必ず確認する（管理ポート・APIポート等）
- 参照 → `../01_Reconnaissance/Network_Scanning.md`

### ディレクトリ列挙

```bash
# gobuster（ペネトレ用Linuxディストリ標準）
gobuster dir -u http://[TARGET] -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,js,txt   # [Attacker]

# wfuzz（ペネトレ用Linuxディストリ標準。レスポンスコードや文字数でフィルタリングしやすい）
wfuzz -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  --hc 404 \
  http://[TARGET]/FUZZ   # [Attacker]

# wfuzz でファイル拡張子も含めて列挙する場合
wfuzz -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  --hc 404 \
  -z list,php-html-js-txt \
  "http://[TARGET]/FUZZ.FUZ2Z"   # [Attacker]

# wfuzz の主なフィルタオプション
#   --hc [code]   : 指定コードのレスポンスを非表示（--hc 404,403 のようにカンマ区切り）
#   --sc [code]   : 指定コードのレスポンスのみ表示
#   --hl [lines]  : 指定行数のレスポンスを非表示（同じ行数 = 同じエラーページを除外）
#   --hw [words]  : 指定ワード数のレスポンスを非表示
#   -t [threads]  : スレッド数（デフォルト 10）
```

- robots.txt・sitemap.xml も手動確認する
- 参照 → `../01_Reconnaissance/Web_Enumeration.md`

### vhostファジング

```bash
gobuster vhost -u http://[TARGET] -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain   # [Attacker]
# 注意：--append-domain は gobuster v3.2以降。古いバージョンでは ffuf を使う。
```

- 発見したvhostは `/etc/hosts` に追加してから再調査する
- 参照 → `../01_Reconnaissance/Web_Enumeration.md`

### レスポンス一次トリアージ

**ディレクトリ列挙と並行して（または直後に）実施する。**
Burp でキャプチャしたリクエスト＋レスポンスをテキストファイルに書き出し、以下の順で確認する。

**① Cookie の分類（third-party 除外 → テスト対象を絞る）**

| 確認方法 | 操作 |
|---------|------|
| DevTools | F12 → Application → Cookies → 左ペインのドメインツリーで自社 / 外部を目視分類 |
| スクリプト | `python cookie_classify.py request.txt`（80 以上のベンダーパターンと照合し first-party を列挙） |

→ 詳細: `../01_Reconnaissance/Web_Enumeration.md`（Cookie 分類セクション）

**② 機微情報・設定不備スキャン**

```bash
# [Attacker] 初動 5 分の全体俯瞰（LOW を除いて絞り込み）
python sensitive_scan.py request.txt --no-low
```

優先して確認するシグナル：

| 検出内容 | 次のアクション |
|---------|-------------|
| JWT / AWS キー / PEM → HIGH | 即確認・Step 2「4層目」または認証面の評価へ |
| CSP / HSTS 欠落 → MEDIUM | XSS のインパクト評価に活用（Step 2 XSS 行参照） |
| HttpOnly 欠落の Cookie → MEDIUM | XSS が刺さった場合のセッション窃取が可能 |
| `Server:` / `X-Powered-By:` でバージョン露出 → MEDIUM | Step 4 CVE 検索へ |

→ 詳細: `../01_Reconnaissance/Web_Response_Triage.md`

---

## Step 2：機能別の脆弱性確認

発見した機能・要素ごとに以下の表で確認すべき脆弱性を特定する：

| 発見した機能・要素 | 確認すべき脆弱性 | 参照先 |
|-----------------|----------------|--------|
| ログインフォーム | SQLi・デフォルト認証情報 | `../02_Initial_Access/Web_Vulnerabilities/SQLi.md` |
| **Authorization ヘッダーに `Bearer eyJ...` がある / Cookie に `eyJ` で始まる値がある** | JWT 操作・署名バイパス（alg:none / 弱い秘密鍵 / RS256→HS256 切り替え / kid インジェクション / jku 差し替え） → Step 3「4層目」へ | `../02_Initial_Access/Web_Vulnerabilities/JWT_Attacks.md` |
| **「Login with Google / GitHub / Microsoft」等のソーシャルログインボタンがある / `/oauth/authorize` `/.well-known/openid-configuration` が存在する / リクエストに `redirect_uri=` `state=` `client_id=` が観測される** | OAuth フロー攻撃（redirect_uri バイパス → 被害者 code 奪取 / state 欠落 → アカウント連携乗っ取り / Implicit Token Leak / id_token 検証バイパス / email・sub 信頼性 / PKCE 欠落 / client_secret 漏洩）。id_token が JWT なら Step 3「4層目」と併用 | `../02_Initial_Access/Web_Vulnerabilities/OAuth_Attacks.md` |
| **URL パラメータに `redirect=` `return=` `next=` `url=` `dest=` `continue=` `target=` 等が観測される / ログイン後・ログアウト後の遷移先が URL 制御 / JS に `location.href = userInput` が存在** | Open Redirect（バイパス全般 / `javascript:` スキーム → XSS 化 / SSRF 302 follow 防御回避 / OAuth `redirect_uri` バイパス構成要素 / Referer 経由 token 漏洩）。単独では低スコアだがチェーンで化ける | `../02_Initial_Access/Web_Vulnerabilities/Open_Redirect.md` |
| URLに連番IDがある | IDOR | `../02_Initial_Access/Web_Vulnerabilities/IDOR.md` |
| **状態変更（メール/パスワード変更・送金・設定変更）が Cookie だけで認証され、CSRF トークンが無い / 欠落時に検証されない / 値が検証されない** | CSRF（SameSite 別成立条件・GET 化・Content-Type/JSON 回避 → PoC で被害者操作を偽造） | `../02_Initial_Access/Web_Vulnerabilities/CSRF.md` |
| **認証済みの機微データ（個人情報・APIキー・トークン）を返す API のレスポンスに `Access-Control-Allow-Origin` が動的反射 / `Allow-Credentials: true` が付く** | CORS 設定不備（Origin 反射 / null origin / 部分一致 allowlist → クロスオリジンで認証済みレスポンス窃取） | `../02_Initial_Access/Web_Vulnerabilities/CORS.md` |
| ファイルダウンロード機能 | パストラバーサル・IDOR | `../02_Initial_Access/Web_Vulnerabilities/Path_Traversal.md` |
| ユーザー入力がページに反映される | XSS（反射型・格納型） | `../02_Initial_Access/Web_Vulnerabilities/XSS.md` |
| **反映される入力に `{{7*7}}` / `${7*7}` / `#{7*7}` を入れると `49` が表示される（式が評価される）** | SSTI（エンジン特定 → エンジン別 RCE）。`49` でなく文字列のままなら XSS 側へ | `../02_Initial_Access/Web_Vulnerabilities/SSTI.md` |
| **XSS が刺さったが Cookie が HTTPOnly で `document.cookie` が空** | localStorage / sessionStorage トークン窃取・キーロギング・保存パスワード autofill 窃取（HTTPOnly 保護外の窃取面） | `../02_Initial_Access/Web_Vulnerabilities/XSS.md`（§4 Cookie 以外の窃取） |
| **フォーム入力に `<script>` を入れたら「不正検知」エラーページが返り、エラーページに自分のリクエストヘッダー（User-Agent / Referer / IP）が反射されている** | ヘッダー注入経由の XSS（フィルタが本文にしかかかっていない設計） + 「管理者にレポート送信」文言があれば Blind XSS の発火条件 | `../02_Initial_Access/Web_Vulnerabilities/XSS.md`（ヘッダー注入経路 + Blind XSS シグナル） |
| 問い合わせ・サポート・苦情フォームなど、入力内容がその場では反射されないが「管理者がレビューします」旨の表示がある | Blind XSS（運用者ブラウザでロード時に発火） | `../02_Initial_Access/Web_Vulnerabilities/XSS.md`（Blind XSS） |
| **stolen cookie で管理画面に入れた → そこに新しい入力フォーム（日付・ホスト名・URL等）がある** | 管理者専用APIにコマンドインジェクションがある典型パターン | `../02_Initial_Access/Web_Vulnerabilities/Command_Injection.md` |
| 外部URLを受け付けるパラメータ | SSRF | `../02_Initial_Access/Web_Vulnerabilities/SSRF.md` |
| **URLを入力するフォームがある（PDF生成・プレビュー・スクリーンショット等）** | コマンドインジェクション（バックティック注入）または SSRF。レスポンスヘッダーで言語・ライブラリを確認し searchsploit でCVE検索 | `../02_Initial_Access/Web_Vulnerabilities/Command_Injection.md`（PDFKit セクション） |
| APIが `host`/`ip`/`cmd` 等を受け取る | OSコマンドインジェクション | `../02_Initial_Access/Web_Vulnerabilities/Command_Injection.md` |
| JSソースが難読化されている | JS解析 → 隠しAPIの発見 | `../02_Initial_Access/Web_Vulnerabilities/JS_Obfuscation.md` |
| **Cookie 値・クエリパラメータ・ボディ値が `eyJ`（Base64URL）/ `%25`（二重URLエンコード）/ 長い英数字列など「何かエンコードされている」形式** | 多重エンコードを剥がして中身を確認 → ID・role・JWT が出たら改ざんして再送（IDOR / 権限昇格 / JWT攻撃）。内部パスが出たら SSRF / パストラバーサル | `../02_Initial_Access/Web_Vulnerabilities/JS_Obfuscation.md`（多重エンコードセクション） |
| XMLファイルのアップロード機能がある | XXE（ファイル読み込み・SSRF転用・Blind OOB） | `../02_Initial_Access/Web_Vulnerabilities/XXE.md` |
| XSLTファイルのアップロード・選択機能がある / XML+XSLTを組み合わせた変換機能がある | XSLTインジェクション（フィンガープリント → XXE-via-XSLT / PHP拡張 / Java拡張） | `../02_Initial_Access/Web_Vulnerabilities/XSLT_Injection.md` |
| **対象が Electron デスクトップアプリ（.exe / .dmg / AppImage）で、`.html()` / `innerHTML` / `dangerouslySetInnerHTML` 等の HTML 挿入 sink にユーザー入力が届く** | XSS → RCE 昇格（`nodeIntegration: true` + `contextIsolation: false` が揃えば OS コマンド実行まで。揃わなければ XSS 止まり） | `../02_Initial_Access/Web_Vulnerabilities/Electron_XSS_RCE.md` |
| **Java アプリがネットワーク経由で `ObjectInputStream` デシリアライズを行い、allowlist（許可クラスリスト）防御が実装されている** | Java デシリアライズ allowlist バイパス（`resolveClass()` のみ override で `resolveProxyClass()` 未 override → ysoserial ガジェットチェーンで RCE） | `../02_Initial_Access/Web_Vulnerabilities/Java_Deserialization_Bypass.md` |
| **上のどれにも当てはまらない機能に当たった** | 機能を観察 → 英語で言語化 → 脆弱性クラスを特定するフロー | `01_Unknown_Tech_Research.md` |

**確認の進め方：**

- Burp Suiteで全リクエストをキャプチャしながら操作する
- パラメータが変わるたびに上の表を参照して「この機能は何を確認すべきか」を意識する
- 1つの機能に複数の脆弱性が重なる場合がある（例：ファイルアップロード → IDOR + パストラバーサル）

---

## Step 3：認証・認可の横断確認

認証・認可の確認は3層で行う。上から順に確認すること。

**1層目：認証なしアクセス（最も重大）**

未ログイン状態で認証後のエンドポイントを直接叩く。

- `/dashboard`・`/admin`・`/api/v1/users` 等を未ログイン状態でアクセスする
- 200 が返る・コンテンツが表示される → Broken Access Control（認証バイパス）
- 401 / 302（ログインページへリダイレクト）→ 認証は機能している。2層目へ進む

**2層目：低権限→高権限**

一般ユーザーでログインし、管理者専用エンドポイントを直接叩く。

1. 低権限アカウント（一般ユーザー）でログインし、高権限エンドポイントのURLを直接叩く
2. APIエンドポイントに対して `is_admin=1` `role=admin` 等のパラメータ改ざんを試す

**3層目：横断アクセス（IDOR）**

別ユーザーのリソースにアクセスできるか確認する。

1. 別ユーザーのオブジェクトID（ファイルID・注文IDなど）に連番を変えてアクセスできるか確認する

- 参照 → `../02_Initial_Access/Web_Vulnerabilities/IDOR.md`

**4層目：JWT を使った認証の場合（Step 2 で JWT を検出したとき）**

セッション管理に JWT が使われている場合は以下を順に試す：

1. JWT をデコードして `alg` フィールドを確認する（`eyJ` 2 つ目を base64 デコード）
2. `alg: none` を受け付けるか試す → 最もリスクが高い実装ミス
3. `alg` が `HS256` → 弱い秘密鍵のブルートフォース（hashcat mode 16500）
4. `alg` が `RS256` → 公開鍵を使った HS256 切り替え / jku 差し替えを試みる
5. ヘッダーに `kid`・`jku`・`x5u`・`jwk` フィールドがあれば → 各インジェクション手法を試みる

- 参照 → `../02_Initial_Access/Web_Vulnerabilities/JWT_Attacks.md`

---

## Step 4：バージョン確認 → CVE検索

Webアプリのバージョン情報が判明した場合：

```bash
# バージョン確認方法（例）
# - /api/health / /api/version などのエンドポイント
# - HTTPレスポンスヘッダー（X-Powered-By・Server）
# - ページフッター・About画面

searchsploit [ソフトウェア名] [バージョン]   # [Attacker]
```

- 参照 → `../05_Tools_Reference/Searchsploit.md`

---

## 関連技術

- 前：`00_OS_Identification.md`（OS・スコープの初期確認）
- 後：`../02_Initial_Access/Web_Vulnerabilities/XSS.md`（入力点が反映される場合）
- 後：`../02_Initial_Access/Web_Vulnerabilities/SQLi.md`（DB アクセスする入力点）
- 後：`../02_Initial_Access/Web_Vulnerabilities/Command_Injection.md`（OS コマンド呼び出し系・PDFKit 等）
- 後：`../02_Initial_Access/Web_Vulnerabilities/IDOR.md`（連番 ID / 直接参照）
- 後：`../02_Initial_Access/Web_Vulnerabilities/SSRF.md`（URL を受け取るフォーム）
- 後：`../02_Initial_Access/Web_Vulnerabilities/SSTI.md`（入力に `{{7*7}}` 等を入れて式が評価される場合）
- 後：`../02_Initial_Access/Web_Vulnerabilities/CSRF.md`（Cookie のみ認証の状態変更リクエスト）
- 後：`../02_Initial_Access/Web_Vulnerabilities/CORS.md`（認証済み機微データ API の緩い CORS ヘッダー）
- 後：`../02_Initial_Access/Web_Vulnerabilities/JWT_Attacks.md`（JWT ベースの認証）
- 後：`../02_Initial_Access/Web_Vulnerabilities/OAuth_Attacks.md`（OAuth / OIDC ソーシャルログイン）
- 後：`../02_Initial_Access/Web_Vulnerabilities/Open_Redirect.md`（リダイレクト系パラメータ / 単独 + OAuth・SSRF・XSS への連鎖）
- 後：`../02_Initial_Access/Web_Vulnerabilities/Path_Traversal.md`（パスを受け取るパラメータ）
- 後：`../02_Initial_Access/Web_Vulnerabilities/XXE.md` / `../02_Initial_Access/Web_Vulnerabilities/XSLT_Injection.md`（XML/XSLT 処理）
- 後：`../02_Initial_Access/Web_Vulnerabilities/File_Upload.md`（アップロード機能）
- 後：`../02_Initial_Access/Web_Vulnerabilities/Electron_XSS_RCE.md`（対象が Electron デスクトップアプリで XSS → RCE 昇格を狙う場合）
- 後：`../02_Initial_Access/Web_Vulnerabilities/Java_Deserialization_Bypass.md`（Java デシリアライズ + allowlist 防御を崩す場合）
- 後：`01_Unknown_Tech_Research.md`（Step 2 でどの脆弱性クラスにも当てはまらない機能に当たった場合の調査フロー）
- 関連：`Linux_Attack_Flow.md`（Web を起点にシェル取得を目指すペネトレスコープの場合はこのファイルではなく Linux_Attack_Flow.md の Step 2 へ）
