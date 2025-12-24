## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - この技術で満たす/破れる点：入力データの受理境界（許可フィールド制御）、権限属性（role/is_admin/owner/tenant_id）の保護、サーバ側のソース・オブ・トゥルース（誰が何を決めるか）、重要操作の追加ガード（06）、監査（変更したフィールドと理由）
  - 支える前提：AuthNが強くても、モデル結合（DTO→ORM）が甘いと「権限属性を更新できる」＝AuthZ崩壊になる。IDORより静かに深刻化しやすい。
- WSTG：
  - 該当テスト観点：Authorization Testing（Privilege Escalation）、Input Validation（過剰受理）、API Testing（Mass Assignment）、Business Logic（仕様外フィールド更新）
  - どの観測に対応するか：リクエスト本文（JSON/form/multipart）に“送ってはいけない属性”を混ぜたときの反映兆候を、差分（レスポンス/後続GET/監査ログ）で観測する
- PTES：
  - 該当フェーズ：Information Gathering（モデル/フィールドの発見：レスポンス/スキーマ/JS）、Vulnerability Analysis（結合境界の特定）、Exploitation（最小差分検証：テストアカウント）
  - 前後フェーズとの繋がり（1行）：04で整理したPIP（属性の信頼境界）を、05で「入力→モデル結合→永続化」の境界として検証し、06/03/10へ波及（権限/tenant/state の改変）を評価する
- MITRE ATT&CK：
  - 戦術：Privilege Escalation / Persistence / Defense Evasion
  - 目的：権限属性・所有者・テナント・状態・重要フラグを不正に更新し、昇格・永続化・検知回避を成立させる（※手順ではなく成立条件の判断）

## タイトル
mass-assignment_モデル結合境界

## 目的（この技術で到達する状態）
- Mass Assignment を「フレームワークの罠」ではなく、(1)入力受理（どのフィールドを受け取るか）、(2)結合（DTO/params→domain/ORM）、(3)権限決定（サーバ側の真実）、(4)永続化と監査、の境界として分解し、実務で再現性を持って評価できる
- “更新できてはいけない属性” を体系化し、IDOR/テナント越境/重要操作/状態遷移とどう繋がるかを即座に判断できる
- エンジニアに対して「allowlist/denylist」「コマンドモデル分離」「サーバ側上書き」「監査ログ」を、どこに入れるかまで具体化できる
- 後続（06/10/03/09/07/08）へ、mass-assignment が波及する典型（昇格/越境/公開/承認/添付権限）を明確に渡せる

## 前提（対象・範囲・想定）
- 対象：REST/SPA/MVC いずれでも起きる（入力形態の違い：JSON/PATCH/form/multipart）
- 想定する結合パターン（混在前提）
  - 自動バインディング：リクエストボディをそのままモデルへ（危険）
  - DTO/Serializer 経由：許可フィールドを宣言できる（堅牢化しやすいが漏れうる）
  - 手動マッピング：安全になりやすいが、別の欠陥（漏れ・整合崩れ）が出る
- 検証の安全な範囲（実務的）
  - 変更系の検証はテストアカウント・テストデータで行い、必ず巻き戻し前提を持つ
  - “大量フィールド送信”で壊すのではなく、危険属性の最小セットで差分観測する
  - 直接の不正更新を避けたい場合は、反映兆候（レスポンス/監査/後続GET）で評価する

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) Mass Assignment は「入力受理の境界」そのもの（AuthZの別表現）
- IDOR（02）：他人のオブジェクトに届く
- Mass Assignment（05）：自分のオブジェクトに対しても “やってはいけない変更” ができる
- Multi-tenant（03）：tenant_id/org_id を変えられると越境が成立する
- 状態遷移（10）：state（draft→approved 等）を変えられると承認フローが崩れる
- 重要操作（06）：is_admin/limit/approved_by 等が変えられるとImpactが最大化する

結論：05はAuthZの「属性改変による崩壊」を扱う。

### 2) 危険属性の分類（まず“何を送ったらダメか”を固定する）
危険属性はアプリごとに違うが、分類で漏れを減らせる。
- 権限・ロール系
  - role / roles / is_admin / is_staff / permissions / scope / plan_tier
- 所有者・主体系
  - owner_id / user_id / created_by / assigned_to / approver_id
- テナント・分離系（03直結）
  - tenant_id / org_id / workspace_id / project_id（“所属”を決める属性）
- 状態・公開性・フラグ系（10直結）
  - status/state（draft/approved/published）、is_public、visibility、deleted_at
- 金額・上限・重要条件系（06直結）
  - amount、limit、approved、paid、risk_level、mfa_required
- 監査・整合性系
  - created_at/updated_at、audit fields、version、signature、checksum
- 参照キー・外部連携系
  - external_id、provider、webhook_url、callback_url（SSRF等にも波及し得るが、ここでは“権限境界”として扱う）

### 3) 入力面の発見（ペネトレで“どのフィールドが存在するか”を集める）
- 観測源（優先順）
  1. レスポンスJSON（GET/詳細）
  2. エラーメッセージ（validation errorで許可フィールド一覧が出ることがある）
  3. フロントJS（state/フォーム定義、API schema）
  4. OpenAPI/GraphQL schema（ある場合）
  5. 管理UI（09）やモバイルのAPI差分
- 重要な見方
  - “レスポンスに返ってくるフィールド” と “更新APIが受け取るフィールド” は一致しない（不一致がバグの温床）
  - PATCH/PUT の差（部分更新が危険になりやすい）
  - multipart（プロフィール/添付）に JSON が混ざる場合、サーバ側で一括マップされやすい

### 4) 結合境界の破綻パターン（典型）
#### 4.1 Allowlistが無い（または広すぎる）
- 症状：未知フィールドを送っても無視されず、永続化/反映される
- 原因モデル：リクエストボディ→ORMをそのままマップ、Serializerが`fields="__all__"`相当

#### 4.2 Allowlistはあるが “ネスト/配列/関連” が抜ける（最頻出）
- 症状：トップレベルは守るが、`profile.is_admin`、`members[].role` 等のネストで抜ける
- 原因モデル：ネストしたDTO/サブモデルに別Serializerがあり、そこが緩い

#### 4.3 サーバが決めるべき属性をクライアント入力で上書きしている
- 症状：owner_id、tenant_id、state などが入力で決まる
- 原因モデル：PIP（04）が client_influenced になっている

#### 4.4 “更新後の値” で認可される（TOCTOU型の崩壊）
- 症状：更新前は権限無しだが、更新リクエスト内でrole/ownerを変えることで通る
- 原因モデル：認可チェックが「永続化後」や「更新されたDTO」に対して走る

#### 4.5 管理API/内部APIだけ緩い（例外パス）
- 症状：通常APIは守るが、/admin-api /internal /bulk /import で許可フィールドが広い
- 原因モデル：管理用のDTOがそのまま外部へ露出（09へ直結）

### 5) 観測の作法（HTTPだけでも“反映”を確定する）
Mass Assignment は「受け取ったか」ではなく「反映されたか」を確定する必要がある。
- 反映確定の優先順（証跡強度）
  1. 更新直後レスポンスに反映値が出る
  2. 後続GETで反映値が出る（更新直後に再取得）
  3. エラーが変化する（フィールド型検証が走るなど＝受理している兆候）
  4. 監査ログ（取れる場合）にフィールド変更が残る
- 反映が見えにくい場合の扱い
  - “無視された”と断定せず、受理（binding）された兆候（validationエラー、ログ断片）を根拠に評価する
  - 更新APIが非同期反映の場合は、反映タイミングを考慮して後続GETで確認する

### 6) 重要フィールド更新を「重要操作（06）」として再定義する
- 結論：以下を更新できるAPIは、通常更新ではなく“重要操作”として扱うべき
  - role/permissions（権限付与）
  - tenant_id/org_id（所属変更）
  - state（承認/公開）
  - 支払い/上限/承認フラグ
- 観測で確定したい点
  - これらのフィールドが通常update（/profile/update等）で更新できないか
  - 更新できるなら、step-up/二人承認/監査など追加ガードがあるか（06/16の接続）

### 7) mass_assignment_key_boundary（正規化キー：後続へ渡す）
- 推奨キー：mass_assignment_key_boundary
  - mass_assignment_key_boundary = <input_shape>(json|patch|form|multipart|graphql|mixed|unknown) + <binding_style>(auto|serializer_allowlist|manual|mixed|unknown) + <sensitive_fields_exposed>(role|tenant|owner|state|billing|mixed|unknown) + <nested_risk>(yes/no/unknown) + <pre_authz_check>(before_bind|after_bind|unknown) + <admin_api_exceptions>(present/none/unknown) + <evidence_level>(http_only|http+logs|unknown) + <confidence>
- 記録の最小フィールド（推奨）
  - update_endpoints（代表3〜8本）
  - input_shape（JSON/PATCH/form/multipart）
  - 送信した危険属性（最小セット）
  - 反映の証跡（レスポンス/後続GET/エラー差分）
  - 影響（role/tenant/owner/state/billing どれが動くか）
  - action_priority（P0/P1/P2）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える（確定できる）：
  - どの更新入口で、危険属性が受理/反映される可能性があるか（特にtenant/role/owner/state）
  - 結合境界（binding_style）がどのモデルに近いか（自動/allowlist/手動）と、抜けが出やすい箇所（ネスト/管理API）
  - 認可チェックの順序（更新前/更新後）の兆候（TOCTOU型の危険）
- 推定（根拠付きで言える）：
  - client_influenced な属性が存在する場合、IDORや越境と組み合わさるとImpactが急増する（02/03）
  - ネストや配列で抜ける場合、GraphQL/バッチ/インポートで再発しやすい（07/09）
- 言えない（この段階では断定しない）：
  - すべてのフィールド網羅（スキーマ非公開の場合）。ただし分類により高リスク属性は十分評価できる。

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- 優先度（P0/P1/P2）
  - P0：
    - role/is_admin/permissions が更新できる（権限昇格）
    - tenant_id/org_id が更新できる（越境/データ移送）
    - state/visibility が更新できる（非公開→公開、承認迂回：10）
    - owner_id/created_by 等が更新できる（所有権奪取：02と結合）
    - 管理API/インポート/バッチで広いフィールドが通る（09）
  - P1：
    - トップレベルは守るが、ネスト/配列で抜ける兆候
    - 監査ログが無い/薄い（検知・追跡が困難）
  - P2：
    - 反映はしないが、受理（バインド）している兆候がある（将来の回帰バグリスク）
- “成立条件”としての整理（技術者が直すべき対象）
  - 許可フィールドは allowlist（コマンドモデル単位）で宣言し、モデル全体をバインドしない
  - サーバが決める属性（tenant/owner/role/state）は入力を無視し、サーバ側で上書きする
  - 認可チェックは「更新前のリソース」と「意図した変更（コマンド）」に対して行い、更新後値で判断しない
  - 管理APIは別境界（別認証・別PEP・別DTO）で守り、露出を防ぐ（09）

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：自動バインディングで広く受理している
  - 次の検証（最小差分）：
    - 更新APIに、危険属性（role/tenant/owner/state）の最小セットを混ぜたときの反映兆候を観測
  - 判断：
    - 反映あり：P0
    - エラーが変化：受理兆候→P1（実装回帰や別入口での反映を疑う）
- 仮説B：ネスト/関連で抜ける
  - 次の検証：
    - ネスト構造（profile、members[]、settings{}）に危険属性があり得るかをレスポンス/JSから抽出し、最小差分で観測
  - 判断：
    - 反映あり：P0〜P1（影響次第）
- 仮説C：管理API/インポートだけ緩い
  - 次の検証：
    - /admin /internal /bulk /import /export の入力形態を観測し、DTOが広い兆候を探す
  - 判断：
    - 緩い：P0（09へ接続）
- 仮説D：認可チェック順序が危険（更新後値で許可）
  - 次の検証：
    - “権限条件となる属性”を更新するリクエストが通る兆候を観測（role/owner/state）
  - 判断：
    - 兆候あり：P0（04/06/10へ接続）

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/` ）：
  - `04_labs/02_web/03_authz/05_mass_assignment_binding_boundary/`
    - 構成案：
      - update API（PUT/PATCH/FORM/multipart）を複数用意し、binding_style を切替（auto/allowlist/manual）
      - 役割・テナント・所有者・状態の危険属性を持つモデル（project/task/user）
      - ネスト更新（members[].role、settings.visibility）を用意
      - 監査ログ：changed_fields、old/new、actor、tenant、reason を必ず出す
      - 例外入口：admin/import/bulk を用意し、漏れを再現
- 取得する証跡（深掘り向け：HTTP＋周辺ログ）
  - HTTP：更新リクエストと直後レスポンス、後続GET
  - 差分：同じ更新を別ロール/別tenantで実施し、認可の一貫性を観測
  - ログ：バインディングされたフィールド、拒否理由、changed_fields
  - 監査：危険属性の変更が記録されるか（検知性）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
# 典型の更新（擬似）
PATCH /api/profile
{ "display_name": "yuui", "timezone": "Asia/Tokyo" }

# 観測用の危険属性混入（擬似：最小セット）
PATCH /api/profile
{ "display_name": "yuui", "is_admin": true, "tenant_id": "T2", "role": "admin", "state": "approved" }

# 観測すること（擬似）
- 危険属性が無視されるか、エラーになるか、反映されるか
- レスポンス/後続GETで反映が確認できるか
- 管理APIやインポートで同じ属性が通らないか（例外パス）
~~~~
- この例で観測していること：
  - “受理（binding）”と“反映（persist）”の境界、そして権限属性がクライアント入力に影響されないこと
- 出力のどこを見るか（注目点）：
  - changed_fields、反映値、エラー差分、入口差分（admin/import/bulk）、監査ログ
- この例が使えないケース（前提が崩れるケース）：
  - 更新APIがほぼ存在しない/すべてサーバ側自動処理（→06/10/09の“重要操作・状態・運用境界”が主戦場になる）

## 参考（必要最小限）
- OWASP ASVS（入力受理、権限属性の保護、監査）
- OWASP WSTG（API：Mass Assignment、Authorization Testing）
- PTES（差分観測で反映を確定し、例外パスを特定する）
- MITRE ATT&CK（Privilege Escalation：権限属性の改変）

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/03_authz_04_rbac_abac_判定点（policy_engine）.md`
- `01_topics/02_web/03_authz_03_multi-tenant_分離（org_id_tenant_id）.md`
- `01_topics/02_web/03_authz_06_privileged_action_重要操作（承認_送金_権限）.md`

## 次（06以降）に進む前に確認したいこと（必要なら回答）
- 06 privileged_action：
  - 重要操作の代表例として「権限付与」「送金/支払」「承認/公開」「メール変更/2FA変更」まで含めて、強めに書いてよいか
- 10 object_state：
  - 状態（draft/approved/published）を持つ典型ドメイン（記事/請求/申請/取引）を例にしてよいか（汎用でも可）
