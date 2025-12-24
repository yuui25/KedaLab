## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - この技術で満たす/破れる点：ワンタイム認証（OTP相当）の安全な実装（単回性/短寿命/失効/漏洩対策）、ログイン状態遷移の安全性（Login CSRF/セッション更新）、トークン取り扱い（URL露出・ログ・Referer）、アカウント列挙防止（存在判定）、レート制御（12）、回復導線の強度（11/19との整合）
  - 支える前提：magic-link は「メール到達＝本人性」とみなす設計になりやすく、リンク漏洩/自動踏み/転送/誤送信が即“認証突破”に直結する
- WSTG：
  - 該当テスト観点：Authentication Testing（Passwordless/Magic Link、Account Enumeration、Login CSRF）、Session Management（Session Fixation、Token Handling）
  - どの観測に対応するか：リンク発行（request）、リンク消費（consume）、セッション発行、トークン失効、列挙・レート制御・リダイレクト設計を観測して成立条件を切る
- PTES：
  - 該当フェーズ：Vulnerability Analysis（成立条件の分解、漏洩面の特定）、Exploitation（許可範囲での最小検証：テストアカウント）
  - 前後フェーズとの繋がり（1行）：13（state/ログインCSRF）と同型の状態遷移として評価し、11（回復）・19（パスキー回復）と整合させ、12（レート制御）で悪用可能性を下げる
- MITRE ATT&CK：
  - 戦術：Initial Access / Credential Access / Persistence
  - 目的：メールリンク（認証トークン）の奪取・再利用・転送を通じた不正ログイン、または弱い回復導線としての悪用（※手順ではなく成立条件の判断）

## タイトル
magic-link_メールリンク認証の成立条件

## 目的（この技術で到達する状態）
- magic-link（メールリンク認証）を「リンク発行」「リンク消費」「セッション発行」「失効/再利用防止」「周辺漏洩面（URL/ログ/Referer/自動踏み）」に分解し、どこが危険かを証跡付きで評価できる
- “成立条件” を曖昧にせず、単回性・TTL・バインディング（端末/セッション/メールアドレス/目的操作）・リダイレクト設計・列挙防止を具体的にチェックできる
- エンジニアが直すべき点を「トークンを何に紐付け」「どこで保管し」「どこで無効化し」「どの副作用（自動踏み）をどう吸収するか」まで落とし込める
- 11（回復）、19（パスキー運用）、13（state/CSRF）、12（レート制御）と整合する“パスワードレスの安全基準”を提示できる

## 前提（対象・範囲・想定）
- 対象：
  - リンク発行：POST /auth/magic-link/request（メール送信）
  - リンク消費：GET /auth/magic-link/consume?token=...（または /verify 等）
  - 状態遷移：consume後のセッション発行（Set-Cookie）、またはトークン交換（短命コード→セッション）
  - 例外導線：登録/ログイン/回復で共通トークンを使い回す実装
- 想定する境界：
  - メールは転送・誤送信・共有・自動スキャン（セキュリティ製品/メールクライアントのリンク先読み）が起きる
  - URLはログ（アクセスログ、プロキシ、解析ツール）に残り得る
  - クロスドメイン遷移でRefererに漏れる（設計次第）
- 安全な範囲（最小検証の基本方針）：
  - テストアカウントで、リンクの単回性・TTL・失効・セッション更新・列挙/レート制御を少数回の観測で切り分ける
  - 実運用ユーザへメール送信しない（誤送信を誘発しない）
  - “盗み” の実演ではなく、漏洩し得る面と、漏洩しても成立しない設計かを評価する

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) magic-link を「2段階（発行→消費）」で固定し、境界を列挙する
- 発行（request）
  - 入力：email（または userId）、目的（login/signup/recovery 等）
  - 出力：画面メッセージ（成功/失敗の出し方）、メール送信、レート制御、監査ログ
- 消費（consume）
  - 入力：token（URLクエリ/フラグメント）、付随パラメータ（return_to 等）
  - 出力：ログイン確定（セッション発行）または追加ステップ（確認画面、再認証）
- 重要：この2点が“同じセキュリティ強度で守られている”ことが要件。片方が弱いと破綻する。

### 2) トークン設計：単回性・短寿命・目的束縛（scope）が主役
- 要件A：単回性（one-time）
  - 1回消費したトークンは必ず無効化され、再アクセスでログインが成立しない
- 要件B：短寿命（TTL）
  - 数分〜十数分程度（要件により）で期限切れになり、期限切れの明確な失敗となる
- 要件C：目的束縛（scope）
  - login用トークンで recovery を実行できない、または逆（目的混同がない）
  - “目的” はサーバ側で保持し、URLパラメータで変更できない
- 要件D：主体束縛（subject binding）
  - トークンは特定のメールアドレス/ユーザに紐付く（別ユーザに転用できない）
- 観測で確定したい点
  - “tokenがJWTだから安全” ではなく、サーバ側で単回失効を持つか（DBで消費フラグ/nonce管理）
  - 期限切れ/再利用時の応答（エラー種別、監査ログ）

### 3) バインディング（紐付け）設計：漏洩しても成立しない方向を作る
magic-linkの実務上の弱点は「URLとして外に出る」こと。漏洩前提でバインディングを検討する。
- 代表バインディング
  - セッション束縛：request時の未認証セッションに紐付け、同一ブラウザでのみ消費可能にする
  - デバイス束縛：device_id（15/18の概念）に紐付ける（モバイルで有効）
  - 追加確認：消費後に再認証（16）または二次確認（パスキー等）を要求（重要操作用途の場合）
- 観測焦点
  - “別ブラウザ/別端末” でもリンク消費でログインできてしまうか（バインディング無しの兆候）
  - バインディングがある場合、失敗時に安全に落ちるか（アカウント列挙を誘発しない）

### 4) URL漏洩面：tokenが「どこに残るか」を観測で潰す
- 典型漏洩面
  - ブラウザ履歴、サーバアクセスログ、プロキシログ、分析タグ、エラー報告、リファラ、外部リダイレクト
- 観測で確定したい点（設計判断に直結）
  - tokenがクエリ（?token=）に載るか、フラグメント（#token=）か
    - フラグメントは通常サーバへ送られないが、JS/計測で漏れる可能性がある（過信しない）
  - consume後に token を即座にURLから消すか（302でtoken無しURLへ遷移、履歴に残さない）
  - Referrer-Policy が適切か（no-referrer 等、少なくとも外部へtokenが送られない）
  - return_to の扱い（オープンリダイレクトがあると token を外部へ送れる）
- 実務結論
  - tokenをURLに出す以上、“消費後に即除去（302）＋Referrer制御＋return_to allowlist” は最低ライン。

### 5) 自動踏み（メールセキュリティ製品/プレビュー）の吸収ができているか
- 現実の問題
  - メールゲートウェイ/AV/クライアントがリンク先を自動でGETし、トークンが“勝手に消費”される
- 良い設計の方向性（成立条件）
  - GET一発でログイン確定しない（確認画面＋POSTで確定、または短命コード交換）
  - “消費” は idempotent ではなく、正規ユーザ操作（同一セッション/追加確認）で完了する
  - 自動踏みを検知して無効化する場合も、ユーザが詰まらない導線（再送/別手段）が必要
- 観測焦点
  - consumeがGETだけで完了していないか
  - “確認→確定” の2段階があるか（UI/HTTPで裏取り）

### 6) Login CSRF/取り違え耐性：13と同型（state設計が必要）
- magic-linkは「未認証→認証済み」への状態遷移そのもの
- 観測焦点
  - consumeトークンが「誰の操作で、どのセッションを認証済みにするか」を束縛しているか
  - セッション固定化（session fixation）対策：ログイン確定時にセッションIDがローテーションするか
  - return_to（遷移先）がトークンに安全に束縛されているか（allowlist/署名）

### 7) アカウント列挙（enumeration）と送信乱用（abuse）：request側の必須防御
- 列挙の観測
  - “存在するメール” と “存在しないメール” で応答が変わる（文言/時間/ステータス/挙動）
- 乱用の観測
  - 同一IP/同一メールへの連打で送信できる（スパム/DoS/嫌がらせ）
- 要件（12へ接続）
  - 返却メッセージは常に同一（存在判定を漏らさない）
  - rate-limit（IP/メール/デバイス/指紋）と、段階的な追加認証（captcha/step-up）を設計する
  - 監査ログと通知（異常送信）を運用に渡す

### 8) magiclink_key_boundary（後工程に渡す正規化キー）
- 推奨キー：magiclink_key_boundary
  - magiclink_key_boundary = <purpose>(login|signup|recovery|mixed|unknown) + <consume_style>(get_only|get+confirm|code_exchange|unknown) + <one_time>(yes/no/unknown) + <ttl_hint> + <binding>(none|session|device|stepup|mixed|unknown) + <token_exposure>(query|fragment|cookie|unknown) + <referrer_control>(yes/no/unknown) + <redirect_allowlist>(yes/no/unknown) + <enumeration_resistance>(yes/no/unknown) + <confidence>
- 記録の最小フィールド（推奨）
  - request_endpoint / consume_endpoint
  - purpose（用途）
  - consume_style（確定の仕方）
  - one_time / ttl_hint / invalidate_on_use
  - binding（セッション/端末/追加確認）
  - token_exposure（URL形態、302で除去されるか）
  - return_to_handling（allowlist/署名/開放）
  - rate_limit（有無と単位：12）
  - evidence（HAR、レスポンス文言、ヘッダ、ログ、設定断片）
  - action_priority（P0/P1/P2）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える（確定できる）：
  - トークンが単回・短寿命で、再利用/期限切れが安全に失敗するか
  - consumeがGET一発で完了するか（自動踏み耐性）、確認段階があるか
  - トークンがURL/Referer/リダイレクトで漏れ得る設計か（Referrer-Policy/return_to）
  - request側が列挙・乱用に耐えているか（文言統一、レート制御、監査）
  - ログイン確定時のセッション更新（session rotation）があるか（固定化耐性）
- 推定（根拠付きで言える）：
  - バインディング無し＋GET確定＋URLクエリ露出は、リンク漏洩/自動踏みで不正ログインが成立し得る可能性が高い
  - recovery用途とlogin用途が混在（purpose混同）すると、回復導線が弱い入口になりやすい（11/19へ波及）
- 言えない（この段階では断定しない）：
  - メール経路の実際の安全性（転送/誤送信/ゲートウェイ挙動）※ただし設計が吸収できるかは評価できる

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- 優先度（P0/P1/P2）
  - P0：
    - トークン再利用が可能（単回性なし）またはTTLが長すぎる
    - consumeがGET一発でログイン確定し、バインディングも無い（漏洩＝即ログイン）
    - return_toが開放され、tokenが外部へ送られ得る（オープンリダイレクト＋Referer漏洩）
    - requestでメール存在判定ができる（列挙）＋送信乱用が可能（スパム/嫌がらせ）
  - P1：
    - 単回/TTLはあるが、例外パス（特定クライアント/モバイル/管理画面）で弱い
    - 監査/通知が薄い（不正送信・不正ログインに気づけない）
    - 自動踏み耐性が無く、ユーザが頻繁にリンク失効（運用上の問題がセキュリティ回避を生む）
  - P2：
    - 設計は堅牢だがUX負荷/可用性課題（再送導線が弱い等）
- “成立条件”としての整理（技術者が直すべき対象）
  - tokenを単回・短寿命・目的束縛し、消費後に即失効
  - consumeを2段階（確認/交換）にして自動踏みを吸収
  - セッションローテーション、Referrer-Policy、return_to allowlistで漏洩面を閉じる
  - request側は列挙/乱用を12の枠組みで抑える（同一メッセージ、rate-limit、監査）

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：トークンが単回・短寿命ではない（再利用/長寿命）
  - 次の検証（少数回）：
    - 同一リンクを再度踏んだ時にログインが成立しないことを確認（再利用の扱い）
    - 一定時間後（TTL相当）に期限切れになるかの兆候を確認（短寿命）
  - 判断：
    - 再利用可/長寿命：P0
- 仮説B：consumeがGET一発で完了し、自動踏み・漏洩に弱い
  - 次の検証：
    - consume直後に302でtoken無しURLへ遷移するか（履歴/ログ対策）
    - 確認画面やPOST確定があるか（2段階か）
    - 別ブラウザ/別端末でも成立してしまうか（バインディング有無の兆候）
  - 判断：
    - GET確定＋バインディング無し：P0
    - 2段階/束縛あり：堅牢寄り。次はreturn_to/Referer（仮説C）へ
- 仮説C：return_to/Refererでtokenが外部へ漏れる設計
  - 次の検証：
    - return_to が allowlist/署名で制御されているか（開放なら危険）
    - Referrer-Policy が適切か（外部遷移でtokenが送られない）
  - 判断：
    - 開放/Referrer弱い：P0〜P1
- 仮説D：request側が列挙/乱用に弱い（12未整備）
  - 次の検証：
    - 存在する/しないメールで応答差がないか（文言・時間・挙動）
    - 連続送信が抑止されるか（レート/追加検証）
  - 判断：
    - 列挙/乱用可：P0〜P1（運用被害も大きい）

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/` ）：
  - `04_labs/02_web/02_authn/20_magic_link_boundary/`
    - 構成案：
      - request：メール送信をモック（ログ/キュー）して、token生成・TTL・単回性を切替できる
      - consume：GET確定方式 と 2段階（confirm/POST）方式を切替できる
      - 例外：return_to allowlist ON/OFF、Referrer-Policy ON/OFF を切替し、漏洩面を観測できる
      - 監査ログ：magiclink_issued、magiclink_consumed、magiclink_expired、magiclink_reused、magiclink_abuse_detected を必ず出す
- 取得する証跡（深く探れる前提：HTTP＋周辺ログ）
  - HTTP：HAR（request、メール内URL、consume、302遷移、セッション発行）
  - ヘッダ：Referrer-Policy、Cache-Control、Location（リダイレクト）
  - アプリログ：token生成/TTL/消費フラグ、目的束縛、セッションローテーション
  - 監査ログ：送信回数、失敗理由、異常検知（12）
- 観測の設計（誤判定を避ける）
  - “自動踏み” は実環境差が大きいので、設計として吸収できるか（GET確定か/2段階か）で評価する
  - 2段階の場合、confirmトランザクションが単回・短寿命で照合されるか（13同型）を確認する

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
# 例：リンク発行（擬似）
POST /auth/magic-link/request
  { "email": "user@example.com", "purpose": "login" }

# 例：リンク消費（擬似）
GET /auth/magic-link/consume?token=MLT_...
# 望ましい：ここで即ログイン確定せず、302で token 無しURLへ + 確認/交換へ誘導

POST /auth/magic-link/confirm
  { "transaction": "TX_...", "csrf": "..." }

# 観測すること（擬似）
- tokenが単回・短寿命か（再利用/期限切れ）
- consumeがGET一発で完了しないか（自動踏み耐性）
- return_toが開放されていないか、Referrerで漏れないか
- requestが列挙/乱用に耐えるか（同一応答・レート制御）
~~~~
- この例で観測していること：
  - magic-linkの“成立条件（漏洩しても成立しない/自動踏みで壊れない）”が満たされているか
- 出力のどこを見るか（注目点）：
  - 再利用時の挙動、TTL、302でtoken除去、Referrer-Policy、return_toの制御、requestの応答一貫性
- この例が使えないケース（前提が崩れるケース）：
  - メール送信が外部SaaSでブラックボックス（→アプリ側のtoken設計、consume挙動、ログ/監査で評価する）

## 参考（必要最小限）
- OWASP ASVS（パスワードレス、トークン管理、ログイン状態遷移、列挙防止）
- OWASP WSTG（Passwordless/Magic Link、Login CSRF、Session Fixation、Account Enumeration）
- 実運用上の注意点（自動踏み、URL漏洩面、return_to設計、Referrer制御）

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/02_authn_13_login_csrf_認証CSRFとstate設計.md`
- `01_topics/02_web/02_authn_11_account_recovery_本人確認（サポート代行_回復コード）.md`
- `01_topics/02_web/02_authn_19_webauthn_passkeys_登録・回復境界.md`