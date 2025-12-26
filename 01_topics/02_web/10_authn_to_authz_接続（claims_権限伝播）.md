# 10_authn_to_authz_接続（claims_権限伝播）
本人確認の結果を"権限判断"へ安全に接続し、サービス境界を跨いでも意味が崩れない状態にする

---

## 目的（この技術で到達する状態）
- 認証（AuthN）の成果物（session / token / claims）を、認可（AuthZ）の判断へ接続する「接続部」を、境界として説明できる。
- claimsの"出どころ"と"信頼できる範囲"を分類できる（IdP発行 / 自社発行 / 中継付与 / クライアント自己申告）。
- claims→内部権限（role/permission/tenant/scope）へのマッピングを、実装パターン別に整理できる。
- 権限伝播（Browser→BFF→API→Worker/Job→Audit）で、何が落ちる/変わると危険かを観測で確定できる。
- 失効・権限変更・step-up（再認証）といった"時間要素"を、権限境界として扱える。
- 次の一手を仮説A/Bで選べる（「検証が弱い」ならAuthN寄りに、「伝播が壊れている」ならAPI/ジョブ寄りに）。

## 前提（対象・範囲・想定）
- 対象：AuthN→AuthZ の接続点（claims / 権限伝播 / マッピング / 失効反映）
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - OIDC/SAML等のSSO環境、マイクロサービスアーキテクチャ、BFF（Backend-for-Frontend）パターン
  - 非同期処理（Queue/Job）、API Gateway/Proxyによる認証済みヘッダ付与
  - multi-tenant / RBAC / ABAC 環境
- できること/やらないこと（安全に検証する範囲）：
  - できる：許可されたスコープ内での観測（リクエスト/レスポンス/ログの確認）、トークン/claimsの構造確認
  - やらない：実際のトークン改変・権限昇格の実行、許可されていない対象への検証
- 依存する前提知識（必要最小限）：
  - OIDC/SAMLの基本、JWT/トークンの基本構造、RBAC/ABACの基本概念
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：
    - AuthN→AuthZ の接続点（claims / 権限伝播 / マッピング / 失効反映）
    - OIDC（ID token / Access token）、SAML assertion、セッション（Cookie）、内部JWT、API Gateway付与ヘッダ、ジョブ/キューの権限文脈
    - multi-tenant / RBAC / ABAC における「境界情報（tenant/org、role、scope、object scope）」の運び方
  - 扱わない（別ユニットへ接続）：
    - 認証方式そのものの深掘り → `02_authn_0x_*.md`
    - 認可の典型（IDOR/BOLA/BFLA）の詳細 → `03_authz_0x_*.md`
    - API連携の詳細（非同期/権限伝播の一般形） → `04_api_01_権限伝播モデル（フロント_バックエンド_ジョブ）.md`
    - トークン設計の細部 → `02_authn_03_token設計（Bearer_JWT_Refresh_Rotation）.md`

---


## 観測ポイント（何を見ているか：プロトコル/データ/境界）
> "どのclaimsが使われているか"を、リクエスト/レスポンスの1点だけで判断しない。
> **Hop（経路）ごとに「入力→正規化→判定→伝播」を見る**。

- 観測対象（プロトコル/データ構造/やり取りの単位）：
  - ブラウザ→BFF：Cookie（セッション） / Authorization（Bearer） / CSRF系（あれば）
  - BFF→API：どのヘッダ/トークンでユーザ文脈を渡しているか（Bearer / 内部JWT / 認証済みヘッダ）、claimsの中身（sub、tenant/org、roles/scopes、amr/acr、auth_time）
  - API→下流サービス：サービス間呼び出しでのユーザ文脈の扱い（on-behalf-of / 代理実行）、権限判定点（Guard/Policy middleware/Resolver/SQLフィルタ）
  - API→Async Job/Queue：ジョブ投入時の情報（user_id / tenant_id / permission snapshot / request_id）、実行時の権限再評価の有無
  - 監査ログ：principal / tenant / action / object / decision / reason / request_id
- 境界の観点：
  - 資産境界（管理主体・委託先・対象範囲の線引き）：
    - ブラウザ、BFF（Backend-for-Frontend）、API Gateway、各マイクロサービス、Worker/Job、監査ログ/権限DB、IdP
    - "ログイン後に呼ばれるAPI"の呼び出しパターン（BFF経由か直APIか）
  - 信頼境界（外部連携・第三者・越境ポイント）：
    - IdP（外部/社内）→ RP（自社）への主張（claims/assertion）
    - Gateway/Proxyが付与する「認証済みヘッダ」や「内部トークン」
    - メッセージング基盤（Queue/Topic）やWebSocket中継が"誰の権限文脈"を運ぶか
    - claimsの"出どころ"と信頼ランク：
      - ランクS：IdP発行の Access token / SAML assertion（署名検証・aud/iss等検証済み）、自社発行の内部トークン（署名検証・aud固定・有効期限短・用途限定）
      - ランクA：OIDC ID token の多くのclaims（主にログインUI向け、API権限の根拠にするとズレが出やすい）、表示名・メール・プロフィール系
      - ランクB：中継が付与する"認証済みヘッダ"（`X-User`, `X-Email`, `X-Groups`, `X-Tenant`等） - 外部から注入できる経路があると即座に崩れる
      - ランクC：クライアント自己申告・UI状態（ローカルストレージのフラグ、URLパラメータ、JS変数等） - AuthZ根拠にしてはいけない
  - 権限境界（権限の切替/伝播/委任）：
    - "ログインした"と"管理操作できる"の境界
    - テナント/組織境界（org_id/tenant_id）を跨げるかどうか
    - step-up（再認証/MFA）で許される操作が増える境界
    - 権限変更（降格/解除）と、既存セッション/トークンの残存の境界（時間境界）
    - "権限の根拠"がどこにあるか（token内か、DB/Policyか）
    - BFFでの正規化（principal/tenant決定）が一貫しているか
    - 代理実行に切り替わると、**"誰の権限で動いたか"の監査境界**が重要になる
- 重要なフィールド/差分/状態（「ここが変わると意味が変わる」点）：
  - 接続パターン：トークン中心（claimsが権限の"主"） vs サーバ状態中心（claimsは"識別子"で、権限はDB/Policy側が主）
  - 権限伝播の欠落/置換：フロントではtenantが見えているがAPIでは欠落、Jobでは固定値、サービス間でrole表現が違う
  - 時間境界：権限変更/失効が反映されない（降格後も操作が可能、古いトークンで継続できる、ジョブが過去権限で実行される）
  - "投入時は権限あり、実行時は権限なし" のズレ（逆も）

---

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が"確定"できるか：
  - どのトークン/claimsが、どの境界（フロント/バック/キュー/WS）で、何の判断（ロール/テナント/オブジェクトスコープ）に使われているか
  - 接続パターン（トークン中心 vs サーバ状態中心）の有無
  - 権限伝播の欠落/置換の有無（フロントではtenantが見えているがAPIでは欠落、Jobでは固定値、サービス間でrole表現が違う）
  - 権限変更/失効が反映されない状態（降格後も操作が可能、古いトークンで継続できる、ジョブが過去権限で実行される）
- 何が"推定"できるか（推定の根拠/前提）：
  - 検証が厳密か（iss/aud/exp/署名検証、kid/鍵管理、clock skew、nonce/state等）
  - claims→内部権限へのマッピングが安定か
  - 伝播時に欠落/置換/再解釈がないか
  - 権限の根拠がどこにあるか（token内か、DB/Policyか）
- 何は"言えない"か（不足情報・観測限界）：
  - 実際の権限昇格の成功の有無（観測だけでは確定できない）
  - 例外クライアント/環境での成立可能性（対象範囲を境界として明記する必要がある）
  - 権限判定の実装詳細（Policy/Guard/Resolverの内部ロジック）
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：サーバ状態中心で一貫（比較的堅牢）
    - 正常：トークンは識別子（sub等）に限定し、権限はDB/Policyが主、失効/権限変更が反映されやすい
  - パターンB：トークン中心で"claims=権限"が直結（設計要件が厳しい）
    - 境界がズレている：roles/scopes/tenant を token claims から直接判定、token検証が厳密で、発行/失効/変更の同期が仕様化されていれば成立するが、同期が曖昧だと「降格が効かない」「古い権限で動く」が起きやすい
  - パターンC：混在（最も事故が出やすい）
    - 異常：AサービスはDB参照、Bサービスはtoken roles参照、フロントはtoken rolesでUIを出し分け、APIはDBで判定（または逆）、"通る/通らない"の揺れが増え、例外経路が生まれやすい
  - パターンD：ヘッダ付与モデル（信頼境界が一点に集中）
    - 境界がズレている：Gateway/Proxyが `X-User` 等を付与し、下流はそれを信じる、外部からそのヘッダを注入できる経路があると即崩壊する
  - パターンE：非同期/バッチで権限文脈が断絶
    - 境界がズレている：ジョブはサービス権限で動き、ユーザの権限境界が曖昧、監査境界（誰の依頼で何が起きたか）と、実行時の再評価要件が焦点になる

---

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す"狙い目"：
  - claims の誤用（用途違いのトークンを権限根拠にする）
    - APIがID tokenを受け入れている、aud/issが曖昧、用途が混ざっている
    - "ログインに使う主張"が"API権限"に転用され、境界が崩れやすい
  - 権限変更/失効が反映されない（時間境界の破綻）
    - 降格後も操作が可能、古いトークンで継続できる、ジョブが過去権限で実行される
    - 運用上の権限管理が無意味になり、内部不正・退職者・委託の境界が崩れる
  - 伝播の欠落/置換（BFF→API→Job で意味が変わる）
    - フロントではtenantが見えているがAPIでは欠落、Jobでは固定値、サービス間でrole表現が違う
    - テナント跨ぎ、管理操作の迂回、監査不能（誰の操作か不明）に繋がる
  - "認証済みヘッダ"の注入可能性（信頼境界の破壊）
    - 外部から到達できる経路で `X-User` 等がそのまま下流に届く、除去されていない
    - サービス全体が"ヘッダ1本"でなりすまし可能になる（影響半径が大きい）
- 優先度の付け方（時間制約がある場合の順序）：
  1. BFF→API（権限伝播の主戦場）での観測（どのヘッダ/トークンでユーザ文脈を渡しているか、claimsの中身）
  2. 権限判定点（Policy/Guard/Resolver）の特定と、どのリソース境界で判定しているかの確認
  3. 非同期/バッチの"代理実行"で、監査境界が成立しているかの確認
  4. "認証済みヘッダ"モデルの場合は、注入不可を担保する境界（除去/固定/mTLS/内部限定）の確認
- 代表的な攻め筋（この観測から自然に繋がるもの）：
  - 攻め筋1：claims の誤用（用途違いのトークンを権限根拠にする）
    - 成立条件：APIがID tokenを受け入れている、aud/issが曖昧、用途が混ざっている
    - 結果："ログインに使う主張"が"API権限"に転用され、境界が崩れる
  - 攻め筋2：権限変更/失効が反映されない（時間境界の破綻）
    - 成立条件：降格後も操作が可能、古いトークンで継続できる、ジョブが過去権限で実行される
    - 結果：運用上の権限管理が無意味になり、内部不正・退職者・委託の境界が崩れる
  - 攻め筋3：伝播の欠落/置換（BFF→API→Job で意味が変わる）
    - 成立条件：フロントではtenantが見えているがAPIでは欠落、Jobでは固定値、サービス間でrole表現が違う
    - 結果：テナント跨ぎ、管理操作の迂回、監査不能（誰の操作か不明）に繋がる
  - 攻め筋4："認証済みヘッダ"の注入可能性（信頼境界の破壊）
    - 成立条件：外部から到達できる経路で `X-User` 等がそのまま下流に届く、除去されていない
    - 結果：サービス全体が"ヘッダ1本"でなりすまし可能になる（影響半径が大きい）
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）：
  - トークン中心とサーバ状態中心が混在している場合：サービスごとに権限の意味が違うため、例外経路を優先的に確認
  - ヘッダ付与モデルの場合：外部からそのヘッダを注入できる経路があると即崩壊するため、"注入不可"を構造で担保する境界を確認
  - 非同期/バッチで権限文脈が断絶している場合：監査境界（誰の依頼で何が起きたか）と、実行時の再評価要件が焦点になる

---

## 次に試すこと（仮説A/Bの分岐と検証）
> ここが最重要。条件が違うと次の手が変わる形で書く。

- 仮説A：トークン検証が厳密で、権限根拠が一貫している
  - 成立条件：サーバ状態中心で一貫している、またはトークン中心でtoken検証が厳密で、発行/失効/変更の同期が仕様化されている
  - 次の検証（AuthZ側へ寄せる）：
    1) 権限判定点（Policy/Guard/Resolver）を特定し、どのリソース境界で判定しているかを洗う
    2) テナント境界（org/tenant）とオブジェクト境界（resource owner）の両方で、判定が揃っているかを見る
    3) 非同期/バッチの"代理実行"で、監査境界が成立しているかを確認する
  - 期待する観測（成功/失敗時に何が見えるか）：
    - 成功：権限判定点が特定でき、テナント境界とオブジェクト境界で判定が揃っている
    - 失敗：問題は「IDOR/BOLA/BFLAの実装」寄りになりやすい（境界モデルの精度が重要）
- 仮説B：トークン検証が曖昧、または用途が混ざっている（AuthN寄りの問題）
  - 成立条件：APIがID tokenを受け入れている、aud/issが曖昧、用途が混ざっている
  - 次の検証（接続部の是正に直結）：
    1) 受け入れているトークン種別と用途を整理（ID token / Access token / Session / Internal token）
    2) iss/aud/exp/署名検証、kid/鍵管理、clock skew、nonce/state等（方式に応じた要件）を"仕様"として固定できるか確認
    3) "認証済みヘッダ"モデルの場合は、注入不可を担保する境界（除去/固定/mTLS/内部限定）を優先的に見る
  - 期待する観測：
    - 成功：トークン種別と用途が整理され、検証要件が"仕様"として固定できる
    - 失敗："ログインに使う主張"が"API権限"に転用され、境界が崩れやすい
- 仮説C：混在しており、サービスごとに権限の意味が違う
  - 成立条件：AサービスはDB参照、Bサービスはtoken roles参照、フロントはtoken rolesでUIを出し分け、APIはDBで判定（または逆）
  - 次の検証（伝播・マッピングの統一）：
    1) canonical principal（唯一のユーザ識別子）を決め、sub/email/idのどれが主かを固定
    2) canonical authorization source（DB/Policy vs token claims）を決め、混在を減らす
    3) tenant/role/scope の表現を統一し、サービス間の変換点を減らす（変換するなら変換規則を仕様化）
  - 期待する観測：
    - 成功：canonical principalとcanonical authorization sourceが決まり、混在が減る
    - 失敗："通る/通らない"の揺れが増え、例外経路が生まれやすい、テナント境界の混線や、管理操作の抜け道が出やすい
- 仮説D：非同期ジョブで権限文脈が断絶している
  - 成立条件：ジョブはサービス権限で動き、ユーザの権限境界が曖昧
  - 次の検証（時間境界の設計へ）：
    1) "投入時スナップショット"と"実行時再評価"のどちらが要件か決める（重要操作ほど再評価寄り）
    2) request_id と principal/tenant をログ相関できる形で残す（監査境界）
    3) ジョブに必要な最小権限を定義し、サービス権限の過大付与を避ける（最小権限）
  - 期待する観測：
    - 成功：監査境界（誰の依頼で何が起きたか）と、実行時の再評価要件が明確になる
    - 失敗："投入時は権限あり、実行時は権限なし" のズレ（逆も）が設計として問われる

---

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/02_web/10_authn_to_authz_01_token_vs_db_authority/`（候補）
    - `04_labs/02_web/10_authn_to_authz_02_gateway_asserted_headers_boundary/`（候補）
    - `04_labs/02_web/10_authn_to_authz_03_async_job_context_and_revocation/`（候補）
- 取得する証跡（目的ベースで最小限）：
  - リクエスト：Authorization/Cookie/主要ヘッダ
  - トークン：iss/aud/exp/sub/tenant/roles/scopes（見える範囲）
  - 判定ログ：principal/tenant/action/object/decision/reason/request_id
  - 監査ログ：principal / tenant / action / object / decision / reason / request_id
- 観測の取り方（どの視点で差分を見るか）：
  - Hop（経路）ごとに「入力→正規化→判定→伝播」を見る
    - ブラウザ→BFF：Cookie（セッション） / Authorization（Bearer） / CSRF系（あれば）、"ログイン後に呼ばれるAPI"の呼び出しパターン（BFF経由か直APIか）
    - BFF→API：どのヘッダ/トークンでユーザ文脈を渡しているか（Bearer / 内部JWT / 認証済みヘッダ）、claimsの中身（sub、tenant/org、roles/scopes、amr/acr、auth_time）
    - API→下流サービス：サービス間呼び出しでのユーザ文脈の扱い（on-behalf-of / 代理実行）、権限判定点（Guard/Policy middleware/Resolver/SQLフィルタ）
    - API→Async Job/Queue：ジョブ投入時の情報（user_id / tenant_id / permission snapshot / request_id）、実行時の権限再評価の有無
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/authn_to_authz 2>/dev/null
    cd ~/keda_evidence/authn_to_authz
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可されたスコープ** のみ
      - 観測は **代表点の抽出** のみ（全サービスを網羅しない）
      - トークン/claimsの構造確認は **読み取りのみ**（改変は行わない）
  - 相関キー（最低限）を作る（後で必ず効く）
    - Host（対象ドメイン）
    - Path（対象パス）
    - Time（観測時刻）
    - Principal（ユーザ識別子：sub/email/id）
    - Tenant（テナント/組織：org_id/tenant_id）
    - Token-Type（トークン種別：ID token / Access token / Session / Internal token）
    - Claims（claimsの中身：roles/scopes/tenant等）
    - Request-ID（相関キー）
    - Decision（許可/拒否）
    - Reason（ポリシー/理由）

---

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は"手段"であり"結論"ではない。必ず「何を観測している例か」を添える。

~~~~
# 目的は「claimsを眺める」ではなく、
# 1) どのHopで（BFF/API/Job）、
# 2) どのデータ（token/headers/db）を根拠に、
# 3) どの判定（tenant/role/object scope）をしているか
# を"差分"で確定すること。

# 記録の最低セット（例）：
# - リクエスト：Authorization/Cookie/主要ヘッダ
# - トークン：iss/aud/exp/sub/tenant/roles/scopes（見える範囲）
# - 判定ログ：principal/tenant/action/object/decision/reason/request_id
~~~~

- この例で観測していること：
  - どのHopで（BFF/API/Job）、どのデータ（token/headers/db）を根拠に、どの判定（tenant/role/object scope）をしているか
  - 権限伝播の欠落/置換の有無（フロントではtenantが見えているがAPIでは欠落、Jobでは固定値、サービス間でrole表現が違う）
  - 権限変更/失効が反映されない状態（降格後も操作が可能、古いトークンで継続できる、ジョブが過去権限で実行される）
- 出力のどこを見るか（注目点）：
  - リクエスト：Authorization/Cookie/主要ヘッダ（どのヘッダ/トークンでユーザ文脈を渡しているか）
  - トークン：iss/aud/exp/sub/tenant/roles/scopes（見える範囲）、claimsの中身
  - 判定ログ：principal/tenant/action/object/decision/reason/request_id（権限判定点の特定）
  - 監査ログ：principal / tenant / action / object / decision / reason / request_id（監査境界の確認）
- この例が使えないケース（前提が崩れるケース）：
  - 許可されていないスコープへの検証（倫理・法的問題）
  - 実際のトークン改変・権限昇格の実行（目的は観測であり、攻撃ではない）
  - 権限判定の実装詳細（Policy/Guard/Resolverの内部ロジック）は観測できない

---

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：認証と認可の接続、権限伝播
  - 該当要件（可能ならID）：認証と認可の接続、権限伝播
  - このファイルの内容が「満たす/破れる」ポイント：
    - 破れる：認証が成立しても、**その後の「権限決定・権限伝播」**で境界が崩れると、IDOR/BOLA/BFLAのような典型だけでなく、(1) 不正なclaimsを"権限"として採用、(2) フロント/バック/ジョブで権限解釈がズレる、(3) テナント境界がclaimsに乗らず混線、(4) 失効/権限変更が反映されず"過去の権限"で動く、などの形で **認可が形骸化**する。
    - 満たす：AuthN（本人確認）で得た識別子を **一貫したプリンシパル**へ正規化し、AuthZ（権限判定）に使うデータ（roles/scopes/entitlements/tenant等）を **信頼できるソース**から供給し、サービス境界を跨いでも同じ意味で解釈されるようにする。トークン検証（iss/aud/exp等）・権限同期（変更/失効）・権限伝播（BFF→API→ジョブ）を「仕様」として固定する。
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：認証テストと認可テストの間にある"接続部"
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：
    - どのトークン/claimsが、どの境界（フロント/バック/キュー/WS）で、何の判断（ロール/テナント/オブジェクトスコープ）に使われているかを観測で確定する。
    - "JWTを改変して通るか"に寄せず、(1) 検証が厳密か、(2) claims→内部権限へのマッピングが安定か、(3) 伝播時に欠落/置換/再解釈がないか、を証跡で示す。
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Recon、Vulnerability Analysis、Exploitation
  - 前後フェーズとの繋がり（1行）：
    - Reconで得た認証方式（Cookie/Session/JWT/OIDC/SAML）から、権限判断点（Policy/Guard/Resolver/Service）までを繋ぎ、どこで境界が切り替わるか（権限伝播点）をモデル化してから検証する。
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Valid Accounts（T1078）、Privilege Escalation（T1068）、Lateral Movement（T1021）
  - 攻撃者の目的（この技術が支える意図）：
    - 有効アカウントの悪用、権限昇格、横展開（サービス間）に接続し得るが、本ファイルは"成立条件の観測と固定"を主眼とする。
    - 特に、認証後の権限データ（claims/ヘッダ/内部トークン）がサービス境界を越えて伝播する構造は、攻撃者にとって「一度通れば他も通る」面になるため、境界設計として扱う。
  - 参照：https://attack.mitre.org/tactics/TA0003/（Persistence）、https://attack.mitre.org/tactics/TA0004/（Privilege Escalation）、https://attack.mitre.org/tactics/TA0008/（Lateral Movement）

## 参考（必要最小限）
- OAuth 2.0 Authorization Framework - https://tools.ietf.org/html/rfc6749
- OpenID Connect Core 1.0 - https://openid.net/specs/openid-connect-core-1_0.html
- SAML 2.0 Technical Overview - https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html
- OWASP: Authentication Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- OWASP: Authorization Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html

## リポジトリ内リンク（最大3つまで）
- 関連 topics：
  - `01_topics/02_web/02_authn_03_token設計（Bearer_JWT_Refresh_Rotation）.md`（トークン設計の細部）
  - `01_topics/02_web/03_authz_00_認可（IDOR BOLA BFLA）境界モデル化.md`（認可の典型）
  - `01_topics/02_web/04_api_01_権限伝播モデル（フロント_バックエンド_ジョブ）.md`（API連携の詳細）
- 関連 playbooks：
  - （該当するplaybookがあれば記載）
- 関連 labs / cases：
  - `04_labs/02_web/10_authn_to_authz_01_token_vs_db_authority/`（候補）
  - `04_labs/02_web/10_authn_to_authz_02_gateway_asserted_headers_boundary/`（候補）
  - `04_labs/02_web/10_authn_to_authz_03_async_job_context_and_revocation/`（候補）

---

## 深掘りリンク（最大8）
- `01_topics/02_web/02_authn_03_token設計（Bearer_JWT_Refresh_Rotation）.md`
- `01_topics/02_web/02_authn_04_sso_oidc_flow観測（state_nonce_code_PKCE）.md`
- `01_topics/02_web/02_authn_05_sso_saml_flow観測（assertion_audience_recipient）.md`
- `01_topics/02_web/02_authn_16_step-up_再認証境界（重要操作_再確認）.md`
- `01_topics/02_web/03_authz_00_認可（IDOR BOLA BFLA）境界モデル化.md`
- `01_topics/02_web/03_authz_04_rbac_abac_判定点（policy_engine）.md`
- `01_topics/02_web/03_authz_03_multi-tenant_分離（org_id_tenant_id）.md`
- `01_topics/02_web/04_api_01_権限伝播モデル（フロント_バックエンド_ジョブ）.md`
