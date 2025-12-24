# 02_authn_04_sso_oidc_flow観測（state_nonce_code_PKCE）.md

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS：V2（Authentication）を中心に、V3（Session Management）/ V4（Access Control）/ V13（API）へ接続。OIDCは「本人性の成立点」と「外部IdPとの信頼境界」を作るため、state/nonce/PKCE・リダイレクト境界・トークン取り扱いを観測で確定する。
- WSTG：OAuth/OIDCは、AuthenticationだけでなくAuthorization側の弱点（トークン/クライアント/AS）に直結するため、WSTGの OAuth Weaknesses を「どの観測差分に落とすか」で扱う（項目名列挙で終えない）。
- PTES：Intelligence Gathering（IdP/境界特定）→ Vulnerability Analysis（フロー成立点の切り分け）→ Exploitation（最小差分の再現）→ Reporting（証跡）に直結。
- MITRE ATT&CK：Valid Accounts / Credential Access / Defense Evasion の“目的”に接続。OIDCフローの観測は「どの資産（セッション/トークン）が、どの境界（フロント/バック）で再利用され得るか」を確定する作業。

## 目的（この技術で到達する状態）
- OIDC（SSO）のフローを、用語暗記ではなく **通信の成立点（どこで状態が変わるか）** と **境界（資産/信頼/権限）** で説明できる。
- state/nonce/code/PKCE が **どこで生成・保持・検証されているか** を観測で押さえ、推測で断言しない（yes/no/unknown に落とす）。
- 「アプリのセッション（Cookie）」と「IdPのセッション」「トークン（ID/Access/Refresh）」を混ぜずに切り分け、次の検証（MFA/クライアント保存/端末紐付け/認可）へ繋げる。

## 前提（対象・範囲・想定）
- 対象：許可された範囲のWebアプリ（Relying Party）と、連携するIdP（Authorization Server / OpenID Provider）。
- 想定：OIDCの主流は Authorization Code Flow（多くはPKCE併用）。SPA/モバイル等でクライアント種別が混在することがある。
- 依存（観測基盤）：
  - `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
  - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- 前段の接続（境界の前提）：
  - `01_topics/01_asm-osint/03_http_観測（ヘッダ/挙動）と意味.md`（リダイレクト/Set-Cookie/ヘッダ観測）
  - `01_topics/02_web/02_authn_認証・セッション・トークン.md`（認証の成立点・鍵の特定）

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) まず「OIDCが始まる入口」と「越境点」を確定する
- 入口（RP側）：ログインボタン/認証誘導URL（どのURLで 302 が始まるか）
- 越境点（IdP側）：IdPドメインへの遷移（authorization endpoint へのリクエスト）
- 戻り点（RP側）：redirect_uri（callback）に戻った瞬間（どのレスポンスでRP側セッションが成立するか）

### 2) フロントチャネルで観測するパラメータ（“ある/ない”をまず確定）
IdPへ飛ぶリクエスト（/authorize 相当）で、最低限次を観測する。
- `client_id`：どのクライアントとして認証しているか（テナント差がある場合は特に重要）
- `redirect_uri`：どこへ戻る前提か（信頼境界の固定点）
- `response_type`：`code` か（または `id_token` / `token` を含むか）
- `scope`：`openid` の有無（OIDC成立の最低条件）
- `state`：CSRF/フロー混線の防止（後述：検証の所在を観測で確定）
- `nonce`：ID Token の再利用防止（戻り後にID Tokenを使う場合に重要）
- PKCE：`code_challenge` / `code_challenge_method`（S256等）

### 3) バックチャネルで観測する交換（Token Endpoint）
RP（またはSPAのBFF等）が token endpoint にアクセスする場合、次を観測する。
- `grant_type=authorization_code` の有無
- `code` の送信先（token endpoint）と、`redirect_uri` の再提示有無
- PKCE：`code_verifier` が送られているか
- クライアント認証：client_secret 相当が使われているか（public client か confidential client かの判断材料）
- 返却：ID/Access/Refresh 相当が **どこに現れるか**
  - レスポンスボディ（JSON）なのか
  - Set-Cookie（HttpOnly Cookie）として保存されるのか
  - ブラウザ側（フロント）に露出するのか

### 4) セッションの“橋渡し”を観測する（RP Cookie と IdP Cookie）
- IdP側Cookie：IdPドメインで発行される Cookie（SSO継続に効く資産）
- RP側Cookie：RPドメインで発行される セッションCookie（アプリで「ログイン済み」判定に効く資産）
- 確定したいこと：
  - RPが「IdPのトークン」を直接認証状態として使っているのか、RP独自セッションに変換しているのか
  - SameSite/Domain/Path により、SSO遷移で送信条件が変わっていないか（Cookie境界と結合して判断）

### 5) 観測の最小セット（証跡として残す）
- HAR（ブラウザ）＋ Proxyログ（Set-Cookie / Cookie / Location / Authorization）＋ 検証メモ（いつ・どこで状態が変わったか）
- メモ項目（固定）
  - IdPドメイン / RPドメイン / callback URL
  - state / nonce / code_challenge の有無（値自体は秘匿扱い。共有時はマスク）
  - トークンの露出箇所（Authorizationヘッダ/ボディ/Cookie/ストレージ）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える（観測で断定できる）
  - OIDCフローの種類（code中心か、フロントにトークンが返るか）
  - 越境点（どのドメイン/どのエンドポイントで本人性が成立するか）
  - state/nonce/PKCE が「存在するか」（まずyes/no）
  - トークンが「どこに現れるか」（露出面：ブラウザ/サーバ/HttpOnly Cookie）
- 推定（追加観測で強くなる）
  - state/nonce/PKCE が「検証されているか」（拒否挙動・エラー・ログで補強が必要）
  - クライアント種別（public/confidential）と、その前提が守られているか
- 言えない（この段階の限界）
  - IdP/RP内部の設定値（登録された redirect_uri の一覧、JWKローテーション運用等）
  - “安全/危険”の断定（まず境界と成立点を固め、次ファイルで差分検証する）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- 優先度（最初に固める判断材料）
  1) **トークン露出面**：ブラウザ側にID/Access/Refreshが露出する設計か（次は「クライアント保存」へ直結）
  2) **state/nonce/PKCEの有無**：無い/弱いなら、フロー混線・コード横取り・再利用の窓が広がる方向
  3) **セッション橋渡しの形**：RP独自セッションに変換しているなら、次はCookie/ライフサイクルが主戦場
  4) **越境する境界の数**：サブドメイン混在/複数テナント/複数IdPは、誤設定の攻撃面が増える
- 具体例（“状態”が次の検証を変える）
  - 「code+PKCEで、トークンはサーバ側のみ」：まずRPセッション（Cookie/失効/ローテーション）を深掘りする
  - 「フロントにトークンが返る/保存される」：クライアント保存（localStorage等）とXSS連鎖の評価を優先する
  - 「IdPセッションが強く効き、RPは薄い」：ログアウト境界（RPログアウト vs IdPログアウト）を最優先で観測する

## 次に試すこと（仮説A/Bの分岐と検証）
### 仮説A：OIDCは code+PKCE で、RPが独自セッションへ変換している（一般的なWeb）
- 次に試すこと
  - callback直後の Set-Cookie を基準に、RPセッションの鍵とスコープ（Domain/Path/SameSite）を確定する
  - ログアウト後に「IdP側SSOで即復帰する」かを観測し、失効境界（RP/IdP）を分離する
- 期待する観測
  - “本人性がどこで成立し、どこで切れるか”を yes/no/unknown で言える

### 仮説B：SPAで、トークンがブラウザに露出・保存される（BFF無し/薄い）
- 次に試すこと
  - トークンが localStorage / sessionStorage / memory / IndexedDB のどこに置かれるかを観測で確定する
  - 更新（Refresh）や silent renew の挙動（どのリクエストで更新が走るか）をProxyで押さえる
- 期待する観測
  - “露出面と再利用窓”を切り分けでき、次の `02_authn_07_client_storage` へ直結する

### 仮説C：state/nonce/PKCE は見えるが、検証が怪しい（拒否が弱い/挙動が揺れる）
- 次に試すこと（安全な最小差分）
  - 1つの値だけを変更したリクエストで、失敗として処理されるか（エラー/再認証/ログ）を確認し、unknown を潰す
- 期待する観測
  - “存在する”から一歩進み、“検証されている/いない/不明”まで落とせる

### コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
# 目的：フロー入口の観測（リダイレクトとパラメータを保存）
# - Location に authorize URL が出るか
# - state/nonce/code_challenge の有無を“存在確認”する
curl -i -L "https://rp.example.com/login"
~~~~

## 参考（必要最小限）
- 親（入口）：`01_topics/02_web/02_authn_認証・セッション・トークン.md`
- 関連（Cookie境界）：`01_topics/02_web/02_authn_01_cookie属性と境界（Secure_HttpOnly_SameSite_Path_Domain）.md`
- 関連（セッション寿命）：`01_topics/02_web/02_authn_02_session_lifecycle（更新_失効_固定化_ローテーション）.md`
- 関連（トークン）：`01_topics/02_web/02_authn_03_token設計（Bearer_JWT_Refresh_Rotation）.md`
- 外部（WSTG）：Testing for OAuth Weaknesses / OAuth Client Weaknesses（観測差分に落とすために参照）
- 外部（OWASP Cheat Sheet）：OAuth 2.0 Security Cheat Sheet（フローと保護点の整理に使用）

---
