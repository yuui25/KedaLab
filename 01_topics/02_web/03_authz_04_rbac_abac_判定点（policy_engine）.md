# 03_authz_04_rbac_abac_判定点（policy_engine）
RBAC/ABACを「用語説明」で終わらせず、(1)権限モデル（role/attribute）、(2)判定点（PEP/PDP）、(3)データスコープ（tenant/object/state）を結合した"実装の地図"として把握する

---

## 目的（この技術で到達する状態）
- RBAC/ABACを「用語説明」で終わらせず、(1)権限モデル（role/attribute）、(2)判定点（PEP/PDP）、(3)データスコープ（tenant/object/state）を結合した“実装の地図”として把握できる
- 認可バグの根本原因を「ロール不足」ではなく、「判定点の抜け」「属性の信頼境界」「例外パス」「policy drift（仕様と実装のズレ）」として切り分けられる
- エンジニアに対して、どこを統一/必須化すべきか（policy engine導入/統一ガード/DB制約/監査）を具体化できる
- 後続（05 mass-assignment、06 重要操作、07 GraphQL、09 管理UI、10 状態遷移）へ、RBAC/ABACが破綻しやすい判定点を明示して接続できる

## 用語（最小）
- 境界：責任/権限/到達性が切り替わる地点
- 差分観測：1条件だけ変えて比較する観測
- 成立条件：何が揃うと成立/不成立が決まるか

## 前提（対象・範囲・想定）
- 対象：Web/APIの認可（endpoint/操作/オブジェクト単位）
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - マルチテナント（03）とIDOR（02）が存在し得る（RBAC/ABACはそれらを"どこで防ぐか"の枠組み）
- できること/やらないこと（安全に検証する範囲）：
  - できること：2〜3ロール（例：viewer/editor/admin）× 2テナント × 代表操作（read/write/admin）で差分観測する
  - やらないこと："大量試行"ではなく、判定点の抜けを狙って入口差分を見つける（API/管理UI/非同期/GraphQL等）
- 依存する前提知識（必要最小限）：
  - `01_topics/02_web/03_authz_00_認可（IDOR BOLA BFLA）境界モデル化.md`
  - `01_topics/02_web/03_authz_02_idor_典型パターン（一覧_検索_参照キー）.md`
  - `01_topics/02_web/03_authz_03_multi-tenant_分離（org_id_tenant_id）.md`
  - `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
  - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：
    - RBAC/ABACを「用語説明」で終わらせず、(1)権限モデル（role/attribute）、(2)判定点（PEP/PDP）、(3)データスコープ（tenant/object/state）を結合した"実装の地図"として把握する
    - 認可バグの根本原因を「ロール不足」ではなく、「判定点の抜け」「属性の信頼境界」「例外パス」「policy drift（仕様と実装のズレ）」として切り分ける
    - エンジニアに対して、どこを統一/必須化すべきか（policy engine導入/統一ガード/DB制約/監査）を具体化する
  - 扱わない（別ユニットへ接続）：
    - policyの全容（内部実装が見えない場合）。ただし"観測された入口差分"から欠陥の所在は絞れる → 別ユニット

## 想定時間
- 目安：20〜40分（環境/SSO有無で前後）

## ツール選定の根拠（代替）
- HAR/Proxy：成立点と差分を最小回数で記録できる
- 代替：ブラウザ開発者ツール/サーバログ/設定画面

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) まず「権限モデル」を3軸で表現する（RBAC/ABACを混在前提で扱う）
- 軸A：操作（action）
  - read / list / search / create / update / delete / approve / export / manage_users など
- 軸B：対象（resource）
  - object（invoice, project, file, user 等）と階層（project→task→comment 等）
- 軸C：条件（condition）
  - tenant境界（03）、所有者（owner）、状態（10）、関係（member）、危険操作（06）、時間/場所/端末（15/18の概念）
- RBACの位置づけ
  - 条件が主に role に集約されたモデル（role→許可操作）
- ABACの位置づけ
  - 条件が属性（resource/actor/context）で表現されるモデル（attributes→許可操作）
- 実務結論
  - 多くの実装は RBAC+ABAC の混在。重要なのは「条件がどこで評価されるか（判定点）」。

### 2) 判定点（PEP/PDP）を特定する：ここが“抜け”の発生源
#### 2.1 PEP（強制点）の典型と危険
- API Gateway / Reverse Proxy
  - 強いが、アプリ内部の“別経路”（内部サービス間、ジョブ、GraphQL）が抜けることがある
- Middleware（共通ガード）
  - 強いが、例外ルート（/internal、/health、/webhook、/admin-api 等）が除外されやすい
- Handler/Controller内チェック
  - 実装漏れが頻発（典型的にIDOR/越境の温床：02/03）
- Resolver単位（GraphQL）
  - フィールド/リゾルバ単位で漏れやすい（07へ接続）
- 非同期ジョブ/キュー/バッチ
  - “誰の権限で実行するか”が曖昧になりやすい（03の3.6）
- 観測で確定したい点
  - 入口ごとにPEPが同じか（API/管理UI/GraphQL/ファイル/非同期）
  - “PEPを迂回する入口”が存在しないか（例外パスの発見）

#### 2.2 PDP（判断点）：policyがどこにあるかで監査・一貫性が決まる
- アプリ内policy関数（例：can(user, action, resource)）
- フレームワークのpolicy（RBAC/ACL）
- 外部policy engine（OPA等）/ central authorization service
- DB側（RLS等）で事実上のpolicyを強制
- 観測で確定したい点
  - “deny理由”やdecisionログが取れるか（監査/調査の可否）
  - policyが複数系統に分裂していないか（APIはA、管理UIはB、検索はC）

### 3) PIP（属性の取得）と信頼境界：ABACが壊れる原因の大半
ABACは「属性が正しい」ことが前提。属性がクライアント入力に寄ると崩れる。
- 典型の属性
  - actor：user_id、roles、tenant_id、groups、entitlements
  - resource：owner_id、tenant_id、state、classification
  - context：ip、device_trust、session_age、risk_score、time
- 信頼境界の判断
  - tenant_id/org_id をリクエストから受け取っていないか（03）
  - owner_id/role をクライアントの送信値に依存していないか（05へ接続）
  - “resource属性” を取得せず、IDだけで判断していないか（IDOR/越境の温床）
- 観測の作法
  - roleやtenantが「トークンクレーム」「セッション」「DB参照」のどれで確定しているかを推定する
  - 変更系（update）で属性が“更新後の値”で判定されていないか（TOCTOU/05へ接続）

### 4) policy drift（仕様と実装のズレ）を起こす典型パターン
- 入口増殖
  - UI→API→内部API→GraphQL→ジョブ→エクスポート→ファイル、のどこかでPEPが抜ける
- 例外パス
  - /admin-api /internal /debug /bulk /import /export /reports などで免除される
- リソース階層の崩れ
  - 親で許可したつもりが子で未チェック（project OK → task 未チェック）
- 状態遷移との結合ミス（10）
  - draftは見えるがapprovedは見えない、等の条件が入口ごとに不一致
- 管理者概念の混同（system admin vs tenant admin）
  - tenant内adminをシステムadminとして扱ってしまう（09/03）

### 5) 実務での“チェック設計”に落とす：RBAC/ABACの必須チェックセット
- 最低限のチェック式（概念）
  - allow ⇐ authenticated
        ∧ actor.tenant == resource.tenant
        ∧ role_allows(action)  （RBAC）
        ∧ attributes_allow(actor, resource, context) （ABAC）
        ∧ additional_guard_for_privileged(action, context) （06）
- 観測で確定したい点
  - tenant一致（03）が常に入っているか
  - resource取得が常に行われているか（IDだけで判断していないか）
  - 重要操作で追加条件（step-up、2人承認等）が入っているか（06）
  - 一覧/検索/参照/派生で同じ式が適用されているか（02）

### 6) policy_engine_key_posture（正規化キー：後続へ渡す）
- 推奨キー：policy_engine_key_posture
  - policy_engine_key_posture = <model>(rbac|abac|mixed|unknown) + <pep_coverage>(gateway|middleware|handler|resolver|mixed|unknown) + <pdp_location>(in_app|framework|external_engine|db_rls|mixed|unknown) + <pip_trust>(server_verified|client_influenced|mixed|unknown) + <tenant_guard>(yes/no/partial/unknown) + <decision_logging>(yes/no/partial/unknown) + <exception_paths>(present/none/unknown) + <confidence>
- 記録の最小フィールド（推奨）
  - roles（観測できたロール一覧）
  - attributes（tenant/state/owner 等の軸）
  - pep_points（入口ごとの強制点）
  - pdp_points（policyの所在）
  - pip_sources（属性の根拠：claim/session/db）
  - endpoints（代表：list/search/get/update/admin/export/file/graphql）
  - evidence（HAR、deny/allow差分、ログ断片、設定断片）
  - action_priority（P0/P1/P2）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が"確定"できるか：
  - 認可がRBAC/ABACのどの混在モデルで、どこがPEP/PDPになっているか（入口別）
  - 属性（tenant/owner/state/role）がどこから来ていて、クライアント影響を受ける余地があるか
  - 例外パスや入口増殖によるpolicy適用漏れの可能性（重点検証ポイント）
- 何が"推定"できるか（推定の根拠/前提）：
  - PEPがhandler分散で、入口が多いほど、IDOR/越境/重要操作の抜けが起きやすい
  - PIPがクライアント入力に寄るほど、mass-assignmentや属性改ざんに弱くなる（05）
  - decisionログが弱いと、侵害時に検知・追跡が困難（運用上の重大リスク）
- 何は"言えない"か（不足情報・観測限界）：
  - policyの全容（内部実装が見えない場合）。ただし"観測された入口差分"から欠陥の所在は絞れる。
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：PEPが分散していて例外パスがある → 入口（api/admin/export/file/graphql/job）ごとに同一操作のdeny/allow差分が出るかを見る
  - パターンB：PIPがクライアント影響を受ける（属性が信頼できない） → update/createで "本来サーバが決めるべき属性（owner/role/tenant/state）" が入力に含まれていないかを観測
  - パターンC：tenant guard が一部入口で抜ける → テナントA/Bで代表API（search/file/admin/get）を固定して差分観測（03の手法を流用）
  - パターンD：重要操作の追加ガードが無い → 承認/権限付与/送金など"重要操作"が、通常updateと同じ判定で成立する兆候を観測

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- 優先度（P0/P1/P2）
  - P0：
    - 例外パス（admin/internal/export/file/graphql/job）でPEPが抜けている兆候
    - tenant guard（03）が入口ごとに不一致（越境が成立し得る）
    - PIPがクライアント入力に影響される兆候（owner/role/tenantを送ると通る等：05へ直行）
    - 重要操作（承認/送金/権限付与）が“通常操作と同じ判定”で通る兆候（06へ直行）
  - P1：
    - policyはあるが、入口差分で一部だけ挙動が怪しい（drift）
    - decisionログが無い/薄い（追跡不能）
  - P2：
    - モデルは堅牢だが、role/attribute設計が複雑で運用ミスが起きやすい（過剰権限・誤付与）
- “成立条件”としての整理（技術者が直すべき対象）
  - PEPを統一（ミドルウェア/ゲートウェイ/共通ガード）し、例外パスをなくす
  - PDPを中央化し、入口増殖でもpolicy driftしない形にする（policy engine/共通policy）
  - PIP（属性）はサーバ検証を原則にし、クライアント入力を信頼しない
  - decisionログ（allow/deny/理由/属性）を監査に残す

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：PEPが分散していて例外パスがある
  - 次の検証（最小差分）：
    - 入口（api/admin/export/file/graphql/job）ごとに同一操作のdeny/allow差分が出るかを見る
  - 判断：
    - 差分あり：P0〜P1（例外パス候補を特定し、05/06/07/09へ分岐）
- 仮説B：PIPがクライアント影響を受ける（属性が信頼できない）
  - 次の検証：
    - update/createで “本来サーバが決めるべき属性（owner/role/tenant/state）” が入力に含まれていないかを観測
    - エラーやレスポンスに属性が反映される兆候がないかを観測
  - 判断：
    - 兆候あり：05（mass-assignment）を優先して深掘る
- 仮説C：tenant guard が一部入口で抜ける
  - 次の検証：
    - テナントA/Bで代表API（search/file/admin/get）を固定して差分観測（03の手法を流用）
  - 判断：
    - 越境兆候：P0（03/02へ戻って横展開）
- 仮説D：重要操作の追加ガードが無い
  - 次の検証：
    - 承認/権限付与/送金など“重要操作”が、通常updateと同じ判定で成立する兆候を観測
  - 判断：
    - 兆候あり：06へ直行

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/` ）：
  - `04_labs/02_web/03_authz/04_rbac_abac_policy_decision_points/`
    - 構成案：
      - 入口：REST（list/search/get/update）、Admin API、Export、File DL、GraphQL、Job/Webhook
      - PEP切替：gateway/middleware/handler/resolver のどこで強制するかを切替
      - PDP切替：in-app policy / external engine / DB RLS を切替
      - PIP切替：tenant/role/owner を server_verified / client_influenced に切替（05の再現）
      - decisionログ：decision, reason, attributes を必ず出す（差分観測が目的）
- 取得する証跡（深掘り向け：HTTP＋周辺ログ）
  - HTTP：入口別のdeny/allow差分（同一操作を複数入口で）
  - ログ：decision理由、参照した属性（tenant/role/state/owner）、例外パスのヒット
  - 設定断片：policy設定（ロール表、ルール、例外ルート）
  - 監査：誰が何を許可/拒否されたか（後追い可能性）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
# 代表入口（擬似）
GET  /api/items/123                # 通常API
GET  /api/items/search?q=...        # 検索（漏れやすい）
GET  /admin/items/123               # 管理入口（例外になりやすい）
GET  /export/items.csv              # エクスポート（大量漏洩）
GET  /files/999/download            # 添付（本文は守るが抜けやすい）
POST /graphql                       # Resolver単位で漏れやすい
POST /jobs/run                      # 非同期/内部実行（権限文脈が曖昧）

# 観測すること（擬似）
- 入口が変わっても同じ認可結果になるか（PEPの一貫性）
- tenant/role/state/owner の属性がどこから来るか（PIPの信頼境界）
- 重要操作に追加ガードがあるか（06）
~~~~
- この例で観測していること：
  - “RBAC/ABACの方式”ではなく「判定点の抜け」と「属性の信頼境界」を見つける
- 出力のどこを見るか（注目点）：
  - 入口差分、例外パス、属性の根拠、decisionログの有無、tenantガードの一貫性
- この例が使えないケース（前提が崩れるケース）：
  - 入口が単一で単純なアプリ（→05/06/10のような“条件の複雑さ”が主戦場になる）

## 観測が失敗した場合
- 変数を1つに絞り、差分が出る条件を再設定する
- HARが取れない場合は、画面遷移とレスポンスのスクショで代替する
- ログ/設定が見られるなら、挙動の根拠として添える

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：認可判断の一貫性（中央集権/統一）、最小権限、権限昇格防止、マルチテナント境界の一貫適用（03と接続）、重要操作の追加条件（06と接続）、監査（decision・理由・属性）
  - 該当要件（可能ならID）：V4（Access Control）
  - このファイルの内容が「満たす/破れる」ポイント：
    - 満たす：RBAC/ABACは"方式"ではなく「判定点（どこで決めるか）」が重要。方式が正しくても判定点が分散・例外化すると破綻することを観測で確定し、以後の検証観点を外さないための基盤。
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：Authorization Testing（Role/Attributeベース、Access Control Bypass）、Business Logic（権限境界の例外パス）、API Testing（policy適用漏れ）
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：policyが適用される入口と適用されない入口を差分で特定し、判定理由（deny/allow）を証跡化する
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Information Gathering（権限モデル把握：role/attribute/tenant）、Vulnerability Analysis（判定点の欠落・例外パス）、Exploitation（最小差分検証：ロール差分/属性差分）
  - 前後フェーズとの繋がり（1行）：02/03で抽出した"入口とスコープ軸"を、04で「どこで誰が判断しているか（PDP/PEP）」に落とし込み、05/06/09/10の具体欠陥へ分岐する。
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Privilege Escalation / Defense Evasion / Discovery / Impact
  - 攻撃者の目的（この技術が支える意図）：判定点の例外（管理API、内部ジョブ、GraphQL resolver 等）を狙って権限昇格・横展開を成立させる（※手順ではなく成立条件の判断）。
  - 参照：https://attack.mitre.org/tactics/TA0004/（Privilege Escalation）、https://attack.mitre.org/tactics/TA0005/（Defense Evasion）、https://attack.mitre.org/tactics/TA0007/（Discovery）、https://attack.mitre.org/tactics/TA0040/（Impact）

## 参考（必要最小限）
- OWASP Application Security Verification Standard: https://github.com/OWASP/ASVS
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- PTES (Penetration Testing Execution Standard): https://pentest-standard.readthedocs.io/
- MITRE ATT&CK: https://attack.mitre.org/

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`01_topics/02_web/03_authz_00_認可（IDOR BOLA BFLA）境界モデル化.md`
- 関連 topics：`01_topics/02_web/03_authz_03_multi-tenant_分離（org_id_tenant_id）.md`
- 関連 topics：`01_topics/02_web/03_authz_05_mass-assignment_モデル結合境界.md`

---

## 深掘りリンク（最大8）
- `01_topics/02_web/03_authz_00_認可（IDOR BOLA BFLA）境界モデル化.md`
- `01_topics/02_web/03_authz_01_境界モデル（オブジェクト_ロール_テナント）.md`
- `01_topics/02_web/03_authz_02_idor_典型パターン（一覧_検索_参照キー）.md`
- `01_topics/02_web/03_authz_03_multi-tenant_分離（org_id_tenant_id）.md`
- `01_topics/02_web/03_authz_05_mass-assignment_モデル結合境界.md`
- `01_topics/02_web/03_authz_06_privileged_action_重要操作（承認_送金_権限）.md`
- `01_topics/02_web/03_authz_07_graphql_authz（field_level）.md`
- `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`

---
