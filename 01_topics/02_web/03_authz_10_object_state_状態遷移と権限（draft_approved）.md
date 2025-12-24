## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - この技術で満たす/破れる点：認可の一貫性（状態に応じた許可/禁止）、ビジネスルール強制（workflow/approval）、最小権限（state別の開示/操作制御）、マルチテナント境界（03）、重要操作（承認/公開/取消）の追加ガード（06）、監査（誰が状態を変えたか）
  - 支える前提：AuthZは「誰が何をするか」だけでなく「“いつ/どの状態で”できるか」。状態遷移が崩れると、承認/公開/支払などの中核が抜ける。
- WSTG：
  - 該当テスト観点：Business Logic Testing（ワークフロー/承認）、Authorization Testing（状態によるアクセス制御）、API Testing（不正遷移・二重実行・競合）、Session Management（step-up境界がstate操作に必要か）
  - どの観測に対応するか：状態モデルを「状態×操作」の行列表に落とし、許可/拒否の一貫性を入口別（UI/REST/GraphQL/admin/job）に差分観測して確定する
- PTES：
  - 該当フェーズ：Information Gathering（状態の列挙：UI表示/レスポンス/ログ）、Vulnerability Analysis（不正遷移・例外パス・TOCTOU）、Exploitation（最小差分検証：テストオブジェクト）
  - 前後フェーズとの繋がり（1行）：04（判定点）と06（重要操作）で定義した“追加ガードと強制点”を、10で「状態遷移（workflow）の強制」に落とし込み、02/05/09の例外パスで崩れないかを評価する
- MITRE ATT&CK：
  - 戦術：Impact / Privilege Escalation / Defense Evasion
  - 目的：本来禁止の遷移（draft→approved、approved→cancel 等）を成立させ、承認迂回・不正支払・公開・復元・証拠隠滅を達成する（※手順ではなく成立条件の判断）

## タイトル
object_state_状態遷移と権限（draft_approved）

## 目的（この技術で到達する状態）
- “状態遷移”を、UIの表示条件ではなく「サーバが強制する認可・ビジネスルール」としてモデル化し、状態バグ（不正遷移/飛び級/巻き戻し/二重実行/競合）を短時間で見つけられる
- 状態（state）をAuthZの条件（ABAC）として扱い、(1)許可操作、(2)開示フィールド、(3)派生物（ファイル/エクスポート）、(4)重要操作の追加ガード、(5)監査、を状態ごとに整合させられる
- エンジニアに「状態はクライアント入力で更新させない」「専用コマンド化」「遷移表とテスト」「監査/否認防止」を具体的に伝えられる
- 06（承認/送金/権限）・05（MA）・02（IDOR）・09（管理面）・07（GraphQL）・08（ファイル）と接続し、Impact評価ができる

## 前提（対象・範囲・想定）
- 対象：状態を持つ業務オブジェクト全般
  - 例：申請（draft→submitted→approved/rejected）、記事（draft→published）、請求（draft→issued→paid）、取引（pending→settled）、サポートチケット（open→resolved→closed）
- 状態は通常、以下を同時に変える
  - 許可される操作（edit/approve/cancel）
  - 表示される情報（フィールド/添付/ログ）
  - 実行される副作用（通知、課金、外部連携）
- 検証の安全な範囲（実務的）
  - テスト用オブジェクトを作成し、状態遷移を少数回で観測する（飛び級/巻き戻し/二重実行は特に慎重）
  - 重要操作（承認/支払/公開）は06の枠組みで、dry-run/テスト環境を優先する
  - 証跡は「状態のbefore/after」「拒否理由」「入口差分」で確定する

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) 状態モデルを“列挙”し、stateをサーバ側の真実にする
- 状態の列挙（発見源）
  - UIのラベル（下書き/承認待ち/公開）
  - APIレスポンス（status/stateフィールド）
  - 監査ログ（action）
  - GraphQL schema（enum）
- 重要：stateが “入力（クライアント）” で書き換えられる設計は危険（05）
- 観測で確定したい点
  - stateがどこで決まるか（サーバ計算/DB/入力）
  - stateがレスポンスにどう表れるか（フィールド名、値の集合）

### 2) 状態×操作の行列表（State-Action Matrix）を作る（最重要）
状態遷移の評価は、行列表でしかブレなくなる。
- 行：状態（draft / submitted / approved / rejected / canceled / archived 等）
- 列：操作（read, list, search, edit, submit, approve, reject, cancel, delete, restore, export, download）
- 観測の要点
  - “readは常にOK”ではない（draftは本人のみ等）
  - “editはdraftのみ”のはずが、approvedでもできると破綻
  - export/download が状態と無関係に常にできると漏洩（08）
- 入口別の比較が必要（drift検出）
  - UI → REST → GraphQL → admin → job/webhook（04/09/07）

### 3) 不正遷移の典型パターン（実務で頻出）
#### 3.1 飛び級（skip transition）
- 例：draft→approved が直接成立する（承認フロー迂回）
- 典型原因
  - `state="approved"` を更新で受理（05）
  - approveが通常更新に混入（06）
  - admin APIが露出（09）

#### 3.2 巻き戻し（rollback transition）
- 例：approved→draft に戻せる（再編集/証拠改ざん/再承認回避）
- 典型原因
  - 状態遷移の制約が弱い（DB/アプリともに）
  - “復元/取消”の権限が過剰（09/06）

#### 3.3 二重実行（double commit）/ 再送による重複
- 例：同じapproveが二度走る、二重課金
- 典型原因
  - idempotency無し（06）
  - 競合制御（楽観/悲観ロック）が無い

#### 3.4 競合（race）による不整合
- 例：approveとcancelが同時に通り、矛盾状態になる
- 典型原因
  - 状態チェックと更新が原子的でない（TOCTOU）
  - “確認→実行”の2段階に整合が無い（06）

#### 3.5 状態依存の開示漏れ（field-level / derivative）
- 例：draftの本文は隠すが、preview/thumbnail/exportで出る（07/08）
- 典型原因
  - 開示制御がUIのみで、API/派生に適用されない（04）

### 4) 判定点（PEP/PDP）を状態遷移に写像する（04との接続）
- PEP（強制点）
  - 遷移コマンド（/submit /approve /publish /cancel）
  - 更新API（危険：generic_update）
  - GraphQL mutation（07）
  - admin API（09）
- PDP（判断）
  - can(user, action, resource, state) のように state を条件に入れる必要
- 観測で確定したい点
  - state条件が“どの入口でも”同じロジックで評価されるか（driftの有無）

### 5) 重要操作（06）としての状態遷移：承認/公開/確定は追加ガードが必要
- 追加ガードの代表
  - step-up（再認証）、二人承認、上限、理由必須、時間帯制限
- 観測で確定したい点
  - 状態遷移（approve/publish/finalize）が通常操作より強いガードになっているか
  - “誰が承認したか”が監査に残るか（否認防止）

### 6) マルチテナント（03）と状態：tenant越境＋状態操作は最悪
- 典型事故
  - 他テナントのオブジェクトを approve/cancel できる（IDOR/越境＋重要操作）
- 観測で確定したい点
  - state遷移の対象特定（object_id）に tenant束縛が必ず入るか（03）

### 7) object_state_key_boundary（正規化キー：後続へ渡す）
- 推奨キー：object_state_key_boundary
  - object_state_key_boundary = <state_model_known>(yes/no/partial/unknown) + <transition_style>(dedicated_commands|generic_update|mixed|unknown) + <state_guard_strength>(strong|weak|unknown) + <idempotency>(yes/no/unknown) + <race_handling>(atomic|non_atomic|unknown) + <entrypoint_consistency>(consistent|drift|unknown) + <derivative_leaks>(present/none/unknown) + <audit_strength>(strong|partial|weak|unknown) + <confidence>
- 記録の最小フィールド（推奨）
  - states（列挙した状態一覧）
  - transition endpoints（submit/approve/cancel等）
  - state-action matrix（要約：OK/NGの差分）
  - 入口差分（UI/REST/GraphQL/admin）
  - evidence（before/after、拒否理由、監査ログ断片）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える（確定できる）：
  - 状態遷移が専用コマンドとして守られているか、またはgeneric_updateで崩れ得るか
  - state条件が入口別に一貫しているか（drift）
  - 飛び級/巻き戻し/二重実行/競合の兆候（整合性）
  - 状態依存の開示（フィールド/派生物）が守られているか（07/08）
  - 監査・否認防止（誰が状態を変えたか）の強度
- 推定（根拠付きで言える）：
  - 遷移がgeneric_updateに混入している場合、MA（05）やadmin例外（09）で破綻しやすい
  - 競合制御が弱い場合、実運用で事故（重複/矛盾）が起きやすい
- 言えない（この段階では断定しない）：
  - 全ての状態の網羅（大規模システムでは状態が多い）。ただし主要遷移（承認/公開/確定）に絞れば高リスクは評価できる。

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- 優先度（P0/P1/P2）
  - P0：
    - 飛び級（draft→approved/published/finalized）が成立
    - stateが通常更新で書き換え可能（05）
    - 他テナント/他人のオブジェクトで状態操作が成立（02/03＋06）
    - 二重実行で二重課金/二重承認が成立し得る（06）
    - 状態で隠すべき情報が派生物（export/preview/file）で漏れる（07/08）
  - P1：
    - 入口別に遷移条件が不一致（UIではNG、APIでOK）
    - 巻き戻しが過剰に許可される（証拠改ざん/監査回避）
    - 監査が弱く、責任追跡が困難
  - P2：
    - 設計は堅牢だが、例外運用（サポート/管理）で穴が開きやすい（09/11）
- “成立条件”としての整理（技術者が直すべき対象）
  - stateはクライアント入力で更新させず、専用コマンドでのみ遷移させる（05/06）
  - 状態遷移の前提条件（ロール/関係/tenant/state）を共通policyで強制（04）
  - idempotency・原子性（チェック＋更新）で二重実行と競合を封じる
  - 状態依存の開示（field/file/export）を一貫して制御（07/08）
  - 監査ログを必須化し、理由・request_idを残す（否認防止）

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：遷移がgeneric_updateで成立している
  - 次の検証（最小差分）：
    - 更新APIで state/status フィールドが受理・反映される兆候を観測（05）
  - 判断：
    - 反映あり：P0（飛び級確定）
- 仮説B：入口driftがある（UIはNG、API/GraphQL/adminでOK）
  - 次の検証：
    - 同一オブジェクト/同一遷移で、入口別に拒否/許可を比較（04/07/09）
  - 判断：
    - 不一致：P1（重要遷移ならP0寄り）
- 仮説C：二重実行・競合がある
  - 次の検証：
    - 再送/同時実行に対して、結果（状態/応答）が一貫するかを少数回で観測（06）
  - 判断：
    - 不整合：P0〜P1（Impact次第）
- 仮説D：派生物で状態依存開示が漏れる
  - 次の検証：
    - export/preview/file で、状態に応じた開示が一貫するか観測（07/08）
  - 判断：
    - 漏れ：P0（機密度次第）

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/` ）：
  - `04_labs/02_web/03_authz/10_object_state_workflow_authorization/`
    - 構成案：
      - 状態モデル：draft→submitted→approved/rejected→archived
      - 遷移：submit/approve/reject/cancel/restore
      - 入口：REST、GraphQL、admin API、job（自動承認など）
      - 実装切替：専用コマンド vs generic_update、原子更新あり/なし、idempotencyあり/なし
      - 派生：export/file/preview を用意し、state依存の開示漏れを再現
      - 監査：before/after、actor、tenant、reason、request_id を必ず出す
- 取得する証跡（深掘り向け：HTTP＋周辺ログ）
  - HTTP：遷移リクエスト、更新リクエスト、入口別差分
  - 状態差分：before/after（レスポンスや後続GET）
  - ログ：遷移判定（deny理由）、競合制御、idempotency
  - 監査：承認者・理由・時刻・相関ID

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
# 良い：専用遷移コマンド（擬似）
POST /api/requests/123/submit
POST /api/requests/123/approve

# 危険：通常更新で遷移が成立（擬似）
PATCH /api/requests/123
{ "state": "approved" }

# 観測すること（擬似）
- stateが入力で反映されない（無視/エラー）か
- 入口別（REST/GraphQL/admin）で同じ遷移条件が強制されるか
- 再送で二重実行・矛盾が起きないか
~~~~
- この例で観測していること：
  - 状態遷移がサーバ強制で、入口差分やMAで崩れないこと
- 出力のどこを見るか（注目点）：
  - transition_style、entrypoint_consistency、idempotency、race_handling、derivative_leaks、audit_strength
- この例が使えないケース（前提が崩れるケース）：
  - 状態が外部システムで決まる（→戻りの状態更新APIと監査・整合性に評価軸を寄せる）

## 参考（必要最小限）
- OWASP ASVS（ビジネスルール、認可、監査）
- OWASP WSTG（Business Logic / Authorization：workflow）
- PTES（成立条件モデル化→差分観測→証跡）
- MITRE ATT&CK（Impact：承認/公開/支払の成立）

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/03_authz_06_privileged_action_重要操作（承認_送金_権限）.md`
- `01_topics/02_web/03_authz_05_mass-assignment_モデル結合境界.md`
- `01_topics/02_web/03_authz_09_admin_console_運用UIの境界.md`

## 次（このAuthZセットの次）に進む前に確認したいこと（必要なら回答）
- 次のサブトピック（今後の候補）：
  - もしこのままAuthZの次を続けるなら、Web系では「API設計差分（REST/GraphQL/Batch）」「監査ログ設計」「権限テスト自動化（回帰防止）」へ分割すると運用価値が上がる
