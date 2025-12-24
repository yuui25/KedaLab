## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - この技術で満たす/破れる点：ログイン/SSO/OAuthコールバックのCSRF耐性（state/nonce/PKCE/CSRFトークン）、セッション生成・切替の安全性（session fixation/アカウント混同）、リダイレクト設計（return_to等のオープンリダイレクト混入）
  - 支える前提：認証は「未認証→認証済み」へ状態遷移するため、CSRFが成立すると“本人の意思と異なる認証状態”を作られる
- WSTG：
  - 該当テスト観点：Authentication Testing（Login CSRF / Session Fixation / OAuth CSRF(state) / Account Linking）
  - どの観測に対応するか：ログインPOST、SSO開始、/authorize、/callback、アカウント連携（connect/link）を“状態遷移点”として列挙し、CSRF防御（token/state/Origin）とセッション更新を検証する
- PTES：
  - 該当フェーズ：Vulnerability Analysis（成立条件の切り分け）、Exploitation（許可されたテストアカウントで最小検証）
  - 前後フェーズとの繋がり（1行）：12の試行抑止と並び、13は「本人意思と無関係に認証状態を作れる」入口を確定し、14/15/16/20の検証優先度に繋げる
- MITRE ATT&CK：
  - 戦術：Initial Access / Credential Access
  - 目的：被害者を攻撃者が用意した認証状態へ誘導（アカウント混同・連携乗っ取り・セッション切替の強制）し、後続の不正操作を成立させる（※ここでは手順ではなく成立条件の判断）

## タイトル
login_csrf_認証CSRFとstate設計

## 目的（この技術で到達する状態）
- 認証CSRF（Login CSRF / OAuth CSRF / Account Linking CSRF）を「状態遷移の安全性」の問題として整理し、どの入口が危険かを優先度付きで判断できる
- state/nonce/PKCE/CSRFトークンの“役割分担”を崩さずに、実装・設定・運用（IdP/RP境界）まで含めて確認観点を固定できる
- エンジニアが直すべき箇所を「どの値を」「どこに保存し」「何と紐付け」「いつ失効させるか」まで落とし込める（実装方針が決まる粒度）
- 後続（14 logout、15 concurrency、16 step-up、17 rotation、18 token binding、19 passkeys、20 magic-link）の“例外パス”を作らないための共通原則（state設計）を提示できる

## 前提（対象・範囲・想定）
- 対象：以下の“認証状態が変わる”入口すべて（UI/API/SSO/連携）
  - 直接ログイン：/login（フォームPOST）、/api/login 等
  - SSO開始：/sso/start、/oauth/authorize（RP→IdP遷移）
  - コールバック：/oauth/callback、/sso/callback（code/id_token受領→セッション発行）
  - アカウント連携：/connect、/link、/settings/sso/connect（「既存ログイン中」＋「外部IdPと紐付け」）
- 想定する境界：
  - RP（アプリ）と IdP（外部/社内）が分離している（責任分界が必要）
  - フロントチャネル（ブラウザリダイレクト）とバックチャネル（トークン交換）が混在する
- 安全な範囲（最小検証の基本方針）：
  - 実ユーザへ影響しない（テストアカウント/検証環境が前提）
  - “本人意思と異なる認証状態が作れるか” を、少数回で成立条件として切り分ける
  - state/nonce等の推測・強制突破ではなく、「検証/照合が無い・弱い」設計欠陥を観測で確定する

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) 認証CSRFを「3つの型」に分ける（どれを守れていないかが直結する）
- 型A：直接ログインのCSRF（フォーム/JSONログインが第三者起点で成立）
  - 典型影響：被害者が“攻撃者アカウント”でログインした状態になる（アカウント混同）
  - 観測焦点：ログインPOSTにCSRFトークン/Origin検証があるか、ログイン時にセッションIDが更新されるか
- 型B：OAuth/OIDCのCSRF（state検証不備でコールバックが成立）
  - 典型影響：セッションが別ユーザの認証結果に紐付く（ログイン混同）、または想定外のreturn_toへ遷移
  - 観測焦点：/authorizeのstate生成と、/callbackでのstate照合（単回/短寿命/紐付け）
- 型C：アカウント連携（link/connect）のCSRF（“ログイン中のユーザ”に外部IdPを勝手に紐付け）
  - 典型影響：以後、外部IdPログインで当該アカウントに入れる（永続化しやすい）
  - 観測焦点：連携開始/完了が「本人操作」かを担保する再認証・CSRF・確認画面・監査ログ

### 2) “state設計” は単なる乱数ではない（何に紐付けるかが本質）
state（および類似のトランザクションID）に求める要件を、実装判断に落とす。
- 必須性（やらないと何が起きるか）
  - stateは「リクエストとレスポンスの結びつき」を保証する（第三者起点のコールバック混入を防ぐ）
- 生成要件
  - 高エントロピー（推測困難）
  - 1リクエスト1state（再利用不可）
  - 短寿命（例：数分）
- 検証要件（“照合項目”を明示する）
  - stateが一致するだけでなく、以下の束縛（binding）を持つと強い：
    - ユーザの未認証セッション（ログイン開始時点のセッション）に紐付く
    - client_id / redirect_uri / response_type / scope などの“取引条件”に紐付く（差し替え耐性）
    - return_to（遷移先）を state に内包する場合は、値のホワイトリスト化・署名/暗号化が必須
- 保存方式（どこに置くか）
  - 推奨：サーバサイドセッションに保存（state→メタ情報のマップ）
  - 代替：署名/暗号化した一時トークンとしてcookieに保存（改ざん耐性が必須）
  - 禁止寄り：URL/JSで平文保持のみ、照合せずに“あることだけ”確認する設計

### 3) OIDCのnonce、PKCEとの役割分担（混同すると穴が残る）
- nonce：
  - 主に id_token のリプレイ/取り違え対策（stateの代替ではない）
  - 観測焦点：nonceがid_token内に反映され、RPで照合されているか
- PKCE：
  - 主に “code横取り耐性”（認可コードを盗られても交換できない）であり、CSRF（ログイン混同）を単独で解決しない
  - 観測焦点：code_verifierがサーバ側に保持され、token交換で必須になっているか（public clientは特に）
- 結論：
  - state（CSRF/取り違え）＋ nonce（id_token整合）＋ PKCE（code横取り）を揃えて初めて設計が閉じる

### 4) Cookie / SameSite / Origin/Referer の位置づけ（補助線として使う）
- SameSite：
  - “クロスサイト送信されるcookie” を制御するが、認証フロー（トップレベル遷移）では Lax でも送られることが多い
  - したがって SameSite は補助。state/CSRF検証の代替にはならない
- Origin/Referer検証：
  - 直接ログインPOST（型A）には有効な補助線になりやすい（ただし例外/互換性を考慮）
  - OAuth/OIDC（型B）はリダイレクト主体でOriginが期待通りにならない場合があるため、stateが主役

### 5) “セッション更新” が無いと認証CSRFが連鎖する（session fixation/アカウント混同）
- 観測で確定したい点：
  - ログイン成功（またはコールバック完了）時に、セッションIDがローテーション（再発行）されるか
  - 既存の未認証セッション属性（カート等）を引き継ぐ場合、その引き継ぎルールが安全か（ユーザID混同が起きないか）
- ありがちな破綻：
  - “同じセッションのまま user_id を付け替える” 実装だと、CSRFと相性が悪い（固定化/取り違えが起きやすい）

### 6) 収束のための正規化キー（後工程に渡す）
- 推奨キー：state_key_design
  - state_key_design = <flow>(login|oidc|link) + <entrypoint> + <state_storage>(server|cookie|none|unknown) + <binding>(sess|client|redirect|return_to|none) + <single_use>(yes/no) + <ttl_hint> + <confidence>
- 記録の最小フィールド（推奨）
  - flow / entrypoint / callback
  - state_present（有無）・nonce_present・pkce_present（有無）
  - validation_observed（照合の証跡：失敗時挙動、エラー種別）
  - session_rotate_on_auth（yes/no/unknown）
  - return_to_handling（allowlist/signed/open/unknown）
  - evidence（HAR、レスポンス要約、Cookie差分、時刻）
  - action_priority（P0/P1/P2）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える（確定できる）：
  - 認証状態遷移点（login/callback/link）の一覧と、CSRF防御（CSRF token/state/Origin等）の有無・一貫性
  - stateが「あるだけ」か「照合され、単回/短寿命で、適切に束縛されている」かの差
  - 認証完了時のセッション更新（ローテーション）の有無
  - return_to 等の遷移先パラメータが、stateに安全に束縛されているか（or 危険な開放があるか）
- 推定（根拠付きで言える）：
  - state検証が弱い場合、ログイン混同/連携混入が成立し得る（ただし影響の確定はテストアカウントで最小検証が必要）
  - セッション更新が無い場合、CSRF以外のセッション系リスク（固定化）と連鎖しやすい
- 言えない（この段階では断定しない）：
  - IdP内部の実装詳細（ただしRP側で必要な検証が欠けている事実は示せる）
  - 実ユーザへの影響範囲（検証環境/テストアカウントでの再現が前提）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- 優先度（P0/P1/P2）
  - P0：
    - /callback が state照合なしで完了し、セッション発行まで到達する（または強い兆候）
    - アカウント連携（link/connect）がCSRF防御なし、または再認証なしで成立する（永続化しやすい）
    - 認証完了時にセッションIDが更新されず、取り違え/固定化の余地が大きい
  - P1：
    - stateはあるが単回性/束縛が弱い（return_to差し替え、client/redirect束縛なし等）
    - 入口差分（UIは強いがAPI/モバイル/別フローが弱い）で例外パスがある
  - P2：
    - 防御はあるが運用上の例外（特定クライアントだけ検証スキップ、debugフラグ等）が残る
- “攻め筋”ではなく“成立条件”としての整理
  - stateが「照合されない」「単回でない」「セッションに束縛されない」うち、どれが欠けると危険度が跳ねるかを明確化する
  - 連携（link）は “一度成功すると永続化” しやすいため、同じ欠陥でもP0化しやすい
- 後続への接続（意思決定）
  - 11（account recovery）で回復が弱い場合、13の欠陥はATOに直結しやすい（回復→ログイン誘導の連鎖）
  - 16（step-up）でも同じ state/CSRF 設計が必要（重要操作の再認証がCSRFで突破されると意味が無い）
  - 14（logout）/15（concurrency）でセッション境界を整えないと、CSRF耐性があっても混同が残る

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：直接ログイン（型A）のCSRF耐性が弱い
  - 次の検証（少数回・テストアカウント前提）：
    - ログインPOSTにCSRFトークンが必須か、無効/欠落でどう失敗するか（失敗の仕方が一定か）
    - Origin/Refererの扱い（チェック有無、例外条件）を観測
    - ログイン成功時にセッションIDが更新されるか（Set-Cookie差分）を観測
  - 判断：
    - CSRF必須＋セッション更新あり：型Aは堅牢。型B/Cへ重点移動
    - CSRF無し or 例外パスあり：P1〜P0（入口統一・CSRF必須化・セッション更新を改善提案）
- 仮説B：OAuth/OIDC（型B）のstate設計が弱い（“あるだけ”）
  - 次の検証：
    - /authorizeでstateが生成されるか（RP起点か、固定値か）
    - /callbackでstate不一致/欠落時に確実に失敗するか（成功しないか）を観測
    - stateの単回性（同一stateの再利用で失敗する兆候）とTTL（期限切れ挙動）を観測
    - return_to を state に内包している場合、allowlist/署名/暗号化のいずれかがあるかを確認
  - 判断：
    - 照合なし/単回性なし：P0
    - 照合ありだが束縛弱い：P1（binding強化、return_toの設計見直し）
- 仮説C：アカウント連携（型C）がCSRF/再認証で守られていない
  - 次の検証：
    - link/connect完了が「既存セッション＋外部IdP認可」だけで成立していないか（再認証/確認画面の有無）
    - 連携の監査ログ（誰がいつ何を連携したか）と通知（本人通知）があるか
  - 判断：
    - 再認証なし/監査なし：P0（永続化リスクが高い）
    - 統制あり：型Bのstate束縛（client/redirect/return_to）へ重点移動

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/` ）：
  - `04_labs/02_web/02_authn/13_login_csrf_state/`
    - 構成案：
      - RP：フォームログイン＋OIDC（authorization code + PKCE）＋アカウント連携（connect）
      - IdP：簡易（Keycloak等）で十分。RP側のstate/nonce/PKCE検証を観測できるようにする
      - 監査ログ：認証成功、state検証失敗、連携イベント、セッション更新（発行/破棄）を必ず出す
- 取得する証跡（深く探れる前提：HTTP＋周辺ログ）
  - HTTP：HAR（/login、/authorize、/callback、/connect の一連）、Cookie差分（Set-Cookie）
  - アプリログ：state生成/保存/照合ログ、失敗理由、session rotateのイベント
  - IdPログ：認可コード発行、token発行（RP側の照合欠落と切り分ける）
  - 設定：SameSite/secure/httpOnly、redirect_uri allowlist、return_to allowlist
- 観測の設計（“状態遷移点”で確定する）
  - 認証完了の定義を固定：セッションCookieが発行され、ユーザIDが確定し、保護ページに到達すること
  - 失敗の定義を固定：state/CSRF不一致時にセッションが発行されないこと（ログで裏取り）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
# 例：観測対象の代表エンドポイント（擬似）
POST /login
GET  /oauth/authorize?client_id=...&redirect_uri=...&response_type=code&scope=...&state=...&nonce=...&code_challenge=...
GET  /oauth/callback?code=...&state=...
POST /account/link/complete   (または /connect/callback 等)

# 例：state設計の“記録”として残したい項目（擬似）
- state: 生成元（RPか）、保存先（サーバセッションか）、単回性（再利用で失敗するか）
- nonce: id_token照合の有無（ログで確認できるか）
- セッション更新: 認証完了時に Set-Cookie がローテーションするか
~~~~
- この例で観測していること：
  - state/nonce/PKCEの存在ではなく「照合され、束縛され、単回で失効する」か
- 出力のどこを見るか（注目点）：
  - state不一致/欠落時の挙動（成功しないこと）、Set-Cookie差分、return_toの取り扱い、link/connect時の再認証有無
- この例が使えないケース（前提が崩れるケース）：
  - 完全にIdP主導で、RPがstateを作らずログイン開始がIdPから来る（その場合は“RPが検証すべきトランザクション束縛”がどこにあるかを先に整理）

## 参考（必要最小限）
- OWASP ASVS（認証状態遷移、CSRF、セッション更新）
- OWASP WSTG（Login CSRF / OAuth state / Session Fixation）
- OAuth 2.0 / OpenID Connect の state / nonce / PKCE の意図（役割分担を崩さないための設計原則）

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/02_authn_12_bruteforce_rate-limit_lockout（例外パス）.md`
- `01_topics/02_web/02_authn_16_step-up_再認証境界（重要操作_再確認）.md`
- `01_topics/02_web/02_authn_20_magic-link_メールリンク認証の成立条件.md`
