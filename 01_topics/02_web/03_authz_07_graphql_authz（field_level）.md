## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - この技術で満たす/破れる点：リソース単位の認可（BOLA/IDOR）、最小権限（フィールド単位の開示制御）、マルチテナント分離（03）、重要操作の保護（06）、入力の信頼境界（05）、監査（誰がどのフィールドにアクセス/実行したか）
  - 支える前提：GraphQLは「1つのエンドポイントに複数のデータ取得/操作が集約」され、従来の“エンドポイント単位の認可”が破綻しやすい。AuthZをresolver/field単位で成立させないと、静かに漏れる。
- WSTG：
  - 該当テスト観点：Authorization Testing（IDOR/BOLA、アクセス制御の迂回）、API Testing（GraphQL特有：field-level、nested access、introspectionの露出は設計判断として扱う）
  - どの観測に対応するか：同一Queryでも「フィールド差分」「ネスト差分」「変数差分」でAuthZの抜けを特定し、入口不一致（RESTでは守るがGraphQLで漏れる等）を確定する
- PTES：
  - 該当フェーズ：Information Gathering（Schema/Operationの把握、型・関係の地図化）、Vulnerability Analysis（field/resolverの認可漏れ、tenantコンテキスト崩壊）、Exploitation（許可範囲での最小差分検証：2ユーザ/2テナント）
  - 前後フェーズとの繋がり（1行）：02/03/04/05/06の“境界モデル”をGraphQLの「PEP=resolver」「PDP=policy」「PIP=context/loader」に写像し、漏れをfield-levelで特定して08/09/10へ波及を評価する
- MITRE ATT&CK：
  - 戦術：Discovery / Collection / Privilege Escalation / Impact
  - 目的：GraphQLの集約性（1リクエストで多情報）とfield-levelの抜けを利用して、越境閲覧・権限昇格・重要操作の成立条件を満たす（※手順ではなく成立条件の判断）

## タイトル
graphql_authz（field_level）

## 目的（この技術で到達する状態）
- GraphQLの認可を「エンドポイントの権限」ではなく、(1)Schema上の公開面（型/フィールド/操作）、(2)Resolverでの強制点（PEP）、(3)コンテキスト/属性の信頼境界（PIP）、(4)データローダ/キャッシュ/フェデレーションなどの例外経路、に分解し、実務で再現性ある評価ができる
- “一覧/検索/参照（02）”の考え方をGraphQLに移植し、ネスト（関係）・フィールド（最小開示）・ノード参照（グローバルID）で起きる典型バグを短時間で切る
- エンジニアに対して、どこで強制すべきか（resolver/policy/DB/RLS/loader）、何を信頼すべきでないか（クライアント提供ID/tenant）、どう監査すべきか（operation/field/decision）を具体化できる
- 08（ファイルDL）、09（管理UI/管理API）、10（状態遷移）へ、GraphQL特有の“抜けやすい入口”として接続できる

## 前提（対象・範囲・想定）
- 対象：GraphQL API（単一エンドポイント `/graphql` が多いが、複数endpoint/サブグラフも想定）
- 想定する構成（混在前提）
  - BFF（SPA用GraphQL）＋バックエンドREST/DB
  - Apollo等のFederation（サブグラフ）/Gateway
  - DataLoader等のバッチ/キャッシュ
  - Persisted Query（クエリ固定）/複数操作（operationName切替）
- 検証の安全な範囲（ペネトレ/TLPT/バグバウンティで実務的）
  - 2ユーザ×2テナント（可能なら）で、同一Queryをフィールド差分・変数差分で比較し、漏れを最小回数で確定する
  - “大量列挙”より「漏れるフィールド/ resolver」を特定し、Impact（漏洩量/操作成立）を根拠付きで示す
  - 重要操作（Mutation）は、確認画面・dry-run・テストデータでの最小実行に留め、監査/状態差分を証跡化する

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) GraphQL AuthZの地図：Query/Mutation/Subscription と Field-level
GraphQLの認可は、粒度が複数ある。まず“どの粒度で守っている想定か”を切り分ける。
- 粒度A：オペレーション単位（Query/Mutationのroot field単位）
  - 例：`query adminDashboard` はadminのみ
- 粒度B：型/フィールド単位（field-level）
  - 例：`User.email` は本人/管理者のみ、`User.mfaSecrets` は常に不可
- 粒度C：オブジェクト単位（resource-level）
  - 例：`Project(id)` の参照は tenant/メンバー関係で制御
- 粒度D：条件単位（state/attribute）
  - 例：`Invoice.pdf` は `state=issued` かつ `role=accounting` のみ

実務結論：GraphQLはB/C/Dが混ざりやすい。Aだけで守ると抜ける。

### 2) 強制点（PEP）＝ Resolver だが、Resolverは“複数階層”に存在する
GraphQLの落とし穴は「root resolverで守ったつもり」が成立しないこと。
- Root resolver（Query/Mutation直下）
  - `project(id)` を守っても、`node(id)` や `search` が別口で同じデータへ到達する可能性
- Nested resolver（型のフィールド）
  - `Project.members` / `User.permissions` / `Invoice.lineItems` など
  - ここが抜けると「親が見えても子は見えないべき」の境界が崩れる（最小開示違反）
- Default resolver（自動でプロパティを返す）
  - 典型：ORMのモデルをそのまま返す設計で、フィールドごとの制御が置かれずに漏れる
- Federation / subgraph resolver
  - Gateway側で守ったつもりでも、サブグラフで抜ける（または逆）

観測で確定したい点：
- PEPがどこに置かれているか（rootのみ/fieldごと/混在）
- “別入口（node/search/admin）”でPEPを迂回できないか（入口増殖）

### 3) 認可判断点（PDP）と属性供給（PIP）：contextが崩れると全て崩れる
GraphQLはリクエスト内で多数のresolverが動くため、コンテキスト（actor/tenant）伝播が生命線。
- PDPの典型
  - `can(actor, action, resource)` のような共通policy
  - directiveベース（`@auth` 等）※実装により強弱差が大きい
  - Gatewayでの事前フィルタ（粗い）
- PIPの典型
  - `context.user`（認証主体）
  - `context.tenant`（テナント確定：03）
  - `context.scopes/roles`（ロール：04）
  - `context.requestId`（監査相関）
- 崩壊パターン（典型）
  - tenant_id/org_id を variables から受け取り、そのまま採用（client_influenced：03/05）
  - Resolverがcontextを使わず、引数のIDだけでDB取得（BOLA/IDOR：02）
  - DataLoader/キャッシュにtenantやuserがキーに入っていない（越境混入：03のキャッシュ問題がGraphQLで再燃）
  - Subscriptions（WebSocket）で認証/tenantが更新されない、または初回だけで固定される

### 4) GraphQL特有の“参照キー”と到達経路：node / connection / search
02（IDOR）の観点をGraphQLに写像する。
- node(id) / Node interface（グローバルID）
  - “どの型でもIDで取れる”設計は強力だが、AuthZが甘いと越境の入口になる
  - 観測焦点：nodeで取得できる型、取得後のフィールド開示が適切か
- connection（edges/nodes）とページング
  - 一覧が増殖しやすい（`users`, `projects`, `invoices` など）
  - 観測焦点：フィルタがtenant/関係で必須化されているか、検索が全体インデックス化していないか
- search（全文検索/横断検索）
  - REST同様に越境の最頻出（03の検索基盤問題）
  - 観測焦点：検索結果に他tenant混入が無いか、結果からnode/getへ到達できるか

### 5) Field-levelの典型漏洩：最小開示（Minimization）が崩れるポイント
- PII/秘密情報フィールド
  - email/phone/address、請求情報、APIキー、2FA/回復情報、内部メモ
- “関係で見えてはいけない”フィールド
  - `User.roles/permissions`（権限情報は漏れると二次被害）
  - `Project.adminNotes`、`AuditLog.details`
- “状態で見えてはいけない”フィールド（10）
  - draftの内容、未公開URL、審査中の情報
- 観測の作法
  - 同一オブジェクトを「本人/他人」「同一テナント/別テナント」「viewer/admin」で比較し、どのフィールドだけ漏れるかを確定する
  - フィールドが `null` で落ちるのか、`errors` に出るのか、値が返るのかを区別（“漏れていない”の定義を曖昧にしない）
  - “親が見えても子が見えてはいけない”の境界を特定（例：Projectは見えるがmembers.emailは不可）

### 6) Mutation（重要操作）のAuthZ：GraphQLは“入力の形”がMA（05）に寄りやすい
GraphQLのMutationは入力型（Input Object）で表現され、mass-assignmentの温床になりやすい。
- 危険パターン
  - `updateUser(input: UpdateUserInput!)` の input が広すぎる（role/tenant/stateが混入）
  - ネスト更新（members[].role、settings.visibility 等）で抜ける
  - 認可チェックが「更新後の値」で走る（05のTOCTOU型）
- 観測焦点（06へ接続）
  - 重要操作（approve/transfer/grant-role）が専用Mutationとして分離されているか
  - step-up（AuthN 16）相当の追加ガードがMutation実行に必須か
  - idempotency/二重実行防止があるか（GraphQLでも同じ要求）

### 7) DirectiveベースAuthZの落とし穴（“宣言しているだけ”を避ける）
- よくある設計
  - `@auth(requires: ADMIN)` のような宣言
- 典型の破綻
  - directiveが一部の型/フィールドにしか適用されていない（抜けがある）
  - directiveが “UI向け” のヒントで、サーバ強制ではない（実装依存）
  - FederationでdirectiveがGatewayで解釈されず、サブグラフで無視される
- 観測焦点
  - directiveの有無ではなく「実際にdenyになるか」をフィールド差分で確定する（宣言と挙動の一致）

### 8) エラーと部分レスポンス：GraphQLは“部分成功”が起きる
GraphQLは、レスポンスの一部だけエラーでも、他フィールドは返る。これが情報漏洩の温床になる。
- 典型例
  - unauthorizedフィールドだけerror、しかし周辺メタデータ（存在/件数/関係）が返り続ける
- 観測焦点
  - 認可失敗時に「存在が漏れる」か（列挙・推測の材料）
  - `errors[].extensions` などに内部情報（role要求、内部ID、SQL）が出ないか
  - `null` 返却方針が一貫しているか（仕様として設計されているか）

### 9) キャッシュ/Loader/Batching：越境混入の最頻出（03のGraphQL版）
- DataLoaderのキー設計
  - 正しい方向：キーに `tenant_id` と `user_id`（または権限集合）を含める
  - 危険：`id` のみでキャッシュし、別テナント/別ユーザの結果が混入
- CDN/エッジキャッシュ
  - GraphQLはPOSTが多いが、Persisted QueryやGET化（APQ）でキャッシュ事故が起きる
- 観測焦点（HTTPだけでも推定可能）
  - 同一リクエスト形状で、ユーザ切替/テナント切替時に応答が不自然に一致する（混入の兆候）
  - レスポンスヘッダ（Cache-Control等）とログイン状態の整合

### 10) Federation（Apollo等）/ マイクロサービス：AuthZの分散がdriftを生む
- 典型構造
  - Gatewayが認証し、subgraphがデータ提供
- 破綻パターン
  - Gatewayは認証済み前提でsubgraphに丸投げ、subgraphは“内部用”前提でAuthZを実装していない
  - 逆にsubgraphでAuthZしているが、Gateway側のフィールド合成で漏れる
- 観測焦点
  - どの層が最終責任を持つか（PDP/PEPの分担）
  - 管理系フィールド/内部フィールドがsubgraphから露出していないか（09へ）

### 11) graphql_authz_key_boundary（正規化キー：後続へ渡す）
- 推奨キー：graphql_authz_key_boundary
  - graphql_authz_key_boundary = <schema_visibility>(introspection_on|introspection_off|unknown) + <entrypoints>(node|search|connections|mutations|subscriptions|mixed|unknown) + <pep_granularity>(root_only|field_level|mixed|unknown) + <pdp_location>(in_app_policy|directive|gateway|subgraph|mixed|unknown) + <pip_trust>(server_verified|client_influenced|mixed|unknown) + <tenant_guard>(yes/no/partial/unknown) + <loader_cache_tenant_keyed>(yes/no/unknown) + <partial_error_policy>(consistent|leaky|unknown) + <confidence>
- 記録の最小フィールド（推奨）
  - operationName / query形状（固定化）
  - variables（tenant/id/filter）
  - 返った型/フィールド（漏れたフィールド名）
  - denyの形（null / errors / 403相当）
  - ユーザ/テナント差分（A/B）
  - evidence（HAR、レスポンス差分、エラー断片、設定断片）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える（確定できる）：
  - GraphQLにおける入口（node/search/connection/mutation）ごとの認可強制の一貫性
  - フィールド単位での最小開示が成立しているか（PII/権限情報/状態依存）
  - tenantコンテキストがresolver/loader/キャッシュまで一貫して適用されているか（03）
  - Mutationが“専用コマンド化”され、重要操作の追加ガード（06/16）があるか
- 推定（根拠付きで言える）：
  - PEPがrootのみの場合、nested field/resolverで漏れる可能性が高い（入口増殖）
  - Loader/キャッシュにtenantキーが無い兆候がある場合、越境混入の事故が起き得る（高リスク）
  - directive宣言が多いのに挙動差分が薄い場合、宣言が強制に繋がっていない可能性
- 言えない（この段階では断定しない）：
  - Schema全体の完全網羅（introspectionが無い/運用で隠される場合）。ただし入口固定と差分観測で高リスク部位は評価できる。

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- 優先度（P0/P1/P2）
  - P0：
    - node/search/connection で他人/他テナントのオブジェクトへ到達し、機微フィールドが返る
    - Mutationで role/tenant/state/owner など危険属性が更新できる（05/06/10の複合）
    - Loader/キャッシュ混入の兆候（ユーザ切替で不自然に同一応答、tenant境界が崩れる）
    - 管理系フィールド/操作がGraphQL経由で露出（09）
  - P1：
    - rootは守るが、nested fieldで一部フィールドだけ漏れる（最小開示違反）
    - partial error が一貫せず、存在/件数/関係のメタ情報が漏れる（列挙材料）
    - Federationの境界が曖昧（どこで守るか不明）
  - P2：
    - 認可は堅牢だが複雑で、運用/回帰でdriftしやすい（監査・テスト設計不足）
- “成立条件”としての整理（技術者が直すべき対象）
  - PEPをfield/resolver単位まで落とし、入口（node/search/connection/派生）に例外を作らない
  - tenant/role/state/owner の属性はサーバ側で確定し、variables入力を信頼しない（03/04/05）
  - Loader/キャッシュキーにtenant/user（または権限集合）を必須化する
  - Mutationは専用コマンド化し、重要操作に追加ガード・idempotency・監査を入れる（06）
  - 部分レスポンスの方針（null/errors）を設計として統一し、存在漏洩を抑える

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：入口（node/search/connection）でスコープ強制が不一致
  - 次の検証（最小差分）：
    - 同一操作形状で userA/userB（同一テナント）差分、tenantA/tenantB差分を観測
    - node/searchの戻りから、関連フィールド（nested）を追加して差分が広がるかを見る
  - 判断：
    - 到達+漏洩：P0（02/03/08/10へ波及評価）
- 仮説B：field-level最小開示が崩れている（nested fieldで漏れる）
  - 次の検証：
    - “同一オブジェクト”に対し、フィールドだけ変えたQueryで返却差（値/null/error）を比較する
  - 判断：
    - 機微フィールド返却：P0〜P1
- 仮説C：MutationがMA的で危険属性が混ざる
  - 次の検証：
    - Input型（レスポンス/JS/エラー）から危険属性候補を抽出し、反映兆候（レスポンス/後続GET）を観測
  - 判断：
    - role/tenant/state/owner が動く兆候：P0（05/06/10）
- 仮説D：Loader/キャッシュ混入
  - 次の検証：
    - 同一Query形状でユーザ/テナントを切替し、応答が不自然に一致/混在しないかを観測（少数回）
  - 判断：
    - 混入兆候：P0〜P1（運用事故リスクも高い）
- 仮説E：Federation境界でdrift
  - 次の検証：
    - 入口（Gateway）とデータ提供（subgraph）で、認可結果が矛盾する兆候（あるフィールドだけ別口で返る等）を観測
  - 判断：
    - 矛盾：P1（設計負債。監査/テスト整備が必要）

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/` ）：
  - `04_labs/02_web/03_authz/07_graphql_field_level_authz/`
    - 構成案：
      - 2テナント×複数ロール（viewer/editor/admin）
      - 入口：node/search/connections、Mutation（update/approve/grant-role）、Subscription（任意）
      - PEP切替：root-only / field-level / directive / policy関数
      - PIP切替：tenantをserver_verified / client_influenced
      - Loader切替：tenant_keyed / id_only（混入を再現）
      - partial error 方針：null返し/エラー返し/混在（存在漏洩の比較）
      - 監査ログ：operationName、fieldPath、decision、tenant、actor、target を必ず出す
- 取得する証跡（深掘り向け：HTTP＋周辺ログ）
  - HTTP：同一Query形状の差分（フィールド差分/変数差分/ロール差分/テナント差分）
  - レスポンス：dataの形、null位置、errorsのpath/extension（内部漏洩が無いか）
  - ログ：resolverのdecision理由、contextのtenant確定値、loaderキー（取れる場合）
  - 監査：field-levelアクセス履歴（否認防止/調査）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
# GraphQLは通常 POST /graphql（擬似）
POST /graphql
{ "operationName": "GetProject",
  "query": "query GetProject($id: ID!){ project(id:$id){ id name owner{ id email } } }",
  "variables": { "id": "P123" } }

# 観測すること（擬似）
- 同じ project(id) でも、owner.email が返る/返らない（field-level）
- tenant/role差分で返るフィールドが変わるか（最小開示）
- errors と null の出方が一貫しているか（存在漏洩の抑制）
~~~~
- この例で観測していること：
  - “同一オブジェクト”に対するフィールド開示の境界と、resolver/loaderがtenant/roleを強制しているか
- 出力のどこを見るか（注目点）：
  - data内の値/null、errors[].path、フィールド単位の差分、tenant/role差分の一貫性
- この例が使えないケース（前提が崩れるケース）：
  - Persisted Queryでquery本文を送れない（→operationName/IDで固定化された操作を差分観測し、返却フィールドの境界を評価する）

## 参考（必要最小限）
- OWASP ASVS（Authorization、最小権限、監査）
- OWASP WSTG（Authorization Testing、API Testing：GraphQLの認可はfield/resolver単位で観測）
- PTES（入口固定→差分観測→成立条件の確定）
- MITRE ATT&CK（Discovery/Collection：GraphQLは1リクエストで多情報になり得るため、最小開示が重要）

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/03_authz_02_idor_典型パターン（一覧_検索_参照キー）.md`
- `01_topics/02_web/03_authz_05_mass-assignment_モデル結合境界.md`
- `01_topics/02_web/03_authz_03_multi-tenant_分離（org_id_tenant_id）.md`

## 次（08以降）に進む前に確認したいこと（必要なら回答）
- 08 file_access：
  - GraphQLで署名URLを返す設計（`file { signedUrl }`）がある場合、field-levelと同時に「署名対象（tenant/期限/権限）」まで一体で書く（08と密結合）
- 09 admin_console：
  - GraphQLにadmin操作（ユーザ検索/権限付与/監査閲覧）が混在している場合、operationName/role境界と例外パスの観点を強める
- 10 object_state：
  - GraphQLは状態（draft/published）に応じたフィールド開示が崩れやすいので、state×fieldのマトリクスを強めに書く
