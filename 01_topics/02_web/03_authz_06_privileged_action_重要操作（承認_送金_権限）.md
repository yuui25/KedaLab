## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - この技術で満たす/破れる点：重要操作の追加認証（step-up）、高リスク操作の多重防御（RBAC/ABAC+追加条件）、トランザクション整合（状態遷移と二重実行防止）、マルチテナント境界（03）、監査・否認防止（誰が何をいつ承認したか）
  - 支える前提：通常のAuthZが正しくても、重要操作が“通常更新API”として露出すると、IDOR/MA/例外パスでImpactが最大化する。
- WSTG：
  - 該当テスト観点：Authorization Testing（Privilege Escalation）、Business Logic（承認/送金/権限付与）、Session Management（step-up境界）、API Testing（再実行・二重請求・不正状態遷移）
  - どの観測に対応するか：重要操作を「入力→事前条件→承認→実行→監査」に分解し、どこが欠けると成立するかをHTTP差分で観測する
- PTES：
  - 該当フェーズ：Information Gathering（重要操作の列挙：ボタン/エンドポイント/イベント）、Vulnerability Analysis（成立条件と防御の欠落）、Exploitation（最小差分検証：テストトランザクション）
  - 前後フェーズとの繋がり（1行）：02/05で見つかるIDOR/MAが、06の重要操作に波及すると一気に致命傷になるため、06では“追加ガードと整合性”で成立条件を閉じ、10（状態遷移）に接続する
- MITRE ATT&CK：
  - 戦術：Privilege Escalation / Impact / Defense Evasion
  - 目的：承認・送金・権限付与などの高Impact操作を、例外パスや状態遷移の穴で成立させる（※手順ではなく成立条件の判断）

## タイトル
privileged_action_重要操作（承認_送金_権限）

## 目的（この技術で到達する状態）
- “重要操作”を、機能名ではなく「高Impactで取り返しがつきにくい」「不正が起きた時の責任が重い」「自動化されやすい」という観点で定義し、対象システムから漏れなく列挙できる
- 重要操作を (1)認可（RBAC/ABAC）、(2)追加ガード（step-up/二人承認/上限/時間）、(3)トランザクション整合（idempotency/再実行防止/競合）、(4)監査・否認防止、に分解し、成立条件を短時間で評価できる
- エンジニアへ「この操作は通常更新APIにしてはいけない」「専用コマンド化・追加認証・監査」が必要、という設計指示を具体化できる
- 02（IDOR）/05（MA）/03（越境）/10（状態遷移）を“重要操作に波及したときの危険度”として統合的に評価できる

## 前提（対象・範囲・想定）
- 対象の代表カテゴリ（汎用）
  - 承認：申請承認、公開、ワークフロー、KYC/本人確認、取引承認
  - 送金/支払：振込、払い戻し、請求確定、サブスク課金、クーポン付与
  - 権限：ロール付与、グループ管理、管理者昇格、APIキー発行、2FA/回復手段変更
  - セキュリティ設定：メール変更、パスワード変更、パスキー/2FA登録削除（AuthNの19/11と接続）
- 検証の安全な範囲（実務的）
  - 重要操作は“実行”を避け、可能なら確認画面/事前条件チェック/ドライラン/テスト環境での最小実行に留める
  - 変更・課金・通知が走る場合は、テスト用の金額/宛先/ダミーで設計されている範囲に限定する
  - 証跡（HTTP/監査ログ/状態遷移）を最優先に、少数回の差分観測で確定する

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) 重要操作は「専用コマンド（Command）」として扱われているか
- 良い設計の兆候
  - `/approve`, `/submit`, `/finalize`, `/grant-role`, `/transfer` のように“意図が明確な専用エンドポイント/コマンド”
  - リクエストボディが「何をするか」を表現し、任意フィールド更新（MA）ではない
- 危険設計の兆候
  - 重要操作が `/resource/{id}` の一般UPDATE（PATCH/PUT）で実現されている
  - `status=approved` や `role=admin` のような属性更新で重要操作が成立する（05/10の典型）
- ここで確定したいこと
  - “重要操作が通常更新に混ざっていないか” を最初に見る（危険度の判定が早い）

### 2) 成立条件モデル：重要操作を 6フェーズで分解する
重要操作の評価は、以下のどこが欠けると成立するかで行う。
1. 対象特定（object_id/tenant）
2. 事前条件（preconditions：状態・権限・上限・承認者など）
3. 追加ガード（step-up / 2人承認 / out-of-band / 再確認）
4. 実行（commit）
5. 事後処理（通知、ログ、セッション失効、ローテーション）
6. 監査・否認防止（who/when/what/why、証跡）

この分解により、どの入口でも同じ観測ができる。

### 3) 追加ガード（step-up等）を“境界”として扱う（AuthN 16と接続）
- 重要操作に必要な追加ガードの代表
  - step-up（再認証）：直近ログイン、パスキー、2FA再確認
  - 強い本人確認：決済PIN、回復コード、サポート検証（11）
  - 2人承認：maker-checker（承認者分離）
  - 上限/レート：日次上限、送金上限、権限付与の制限
  - デバイス/条件：信頼端末、地理/ASN、リスクスコア（15/18の概念）
- 観測で確定したい点
  - “重要操作だけ”追加ガードが働くか（通常操作と同じなら危険）
  - 追加ガードがUIだけで、API直叩きで迂回できないか（PEP抜け：04/09）

### 4) トランザクション整合（idempotency・二重実行防止）があるか
重要操作は「同じ操作を2回実行できる」だけで重大事故になる。
- 観測対象
  - Idempotency-Key（ヘッダやトークン）
  - 2段階（prepare→commit）や確認画面（commitはPOST）
  - 一度実行したら再実行不可（状態遷移で封じる：10）
- 典型の破綻
  - リトライで二重請求/二重送金/二重付与が起きる
  - 競合（同時承認）で不正状態になる（race）
- 観測で確定したい点
  - 重要操作に“重複排除”が設計されているか（HTTP応答や状態変化の一貫性）

### 5) 事前条件（preconditions）と状態遷移（10）の一貫性
- 事前条件の例
  - draftのみ承認可能、approvedは再承認不可
  - maker（申請者）は承認不可
  - 支払は残高/限度/本人確認が満たされていること
  - 権限付与は上位ロールのみ可能（04）
- 典型の破綻
  - 状態遷移がAPI入口ごとに不一致（UIでは制限、APIで抜ける）
  - “状態を先に変える”ことでガードを迂回（05/10）
- 観測で確定したい点
  - 状態がサーバ側の真実になっており、クライアント入力で書き換えられないか（05）
  - 重要操作の条件がすべての入口で同じか（04）

### 6) 監査・否認防止（誰が・何を・なぜ）を最小フィールドで評価する
重要操作は「実行されたか」だけでなく、「説明可能か」が要求になる。
- 監査に必要な最小フィールド
  - actor_id（実行者）
  - tenant_id/org_id（分離軸）
  - action（approve/transfer/grant-role 等）
  - target（object_id / 対象識別子）
  - before_state / after_state（10）
  - request_id / idempotency_key（相関）
  - reason/comment（承認理由）
  - channel（UI/API/admin/job）
- 観測で確定したい点
  - 重要操作だけでも監査が残るか（一般ログでは不足）
  - “拒否”もログに残るか（攻撃検知に重要）

### 7) privileged_action_key_boundary（正規化キー：後続へ渡す）
- 推奨キー：privileged_action_key_boundary
  - privileged_action_key_boundary = <action_class>(approve|payment|role_grant|security_setting|export|mixed|unknown) + <command_style>(dedicated_command|generic_update|mixed|unknown) + <additional_guard>(stepup|two_person|limits|device|none|mixed|unknown) + <idempotency>(yes/no/unknown) + <state_guard>(strong|weak|unknown) + <tenant_guard>(yes/no/partial/unknown) + <audit_strength>(strong|partial|weak|unknown) + <confidence>
- 記録の最小フィールド（推奨）
  - endpoints（prepare/commitがあれば両方）
  - preconditions（状態・ロール・関係）
  - additional_guard（何が要求されるか）
  - idempotency/再実行挙動
  - evidence（HAR、状態差分、監査ログ断片、UI確認画面）
  - action_priority（P0/P1/P2）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える（確定できる）：
  - 重要操作が専用コマンドとして分離され、追加ガードと整合性があるか
  - 重要操作が通常更新（MA/状態更新）で成立していないか（危険設計）
  - テナント・ロール・状態の条件が入口ごとに一貫しているか（02/03/04/10の統合評価）
  - 二重実行防止と監査の強度（実務要件）
- 推定（根拠付きで言える）：
  - 重要操作がgeneric_update型なら、MA（05）と組み合わさって突破される可能性が高い
  - 追加ガードがUIのみなら、API/管理/ジョブ経路で抜ける可能性が高い（04/09）
- 言えない（この段階では断定しない）：
  - 金銭的損失の最大値（限度・実運用設定次第）。ただし成立条件からリスクは示せる。

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- 優先度（P0/P1/P2）
  - P0：
    - 重要操作が通常更新（PATCH/PUT）で成立（status/role/limit 等の更新で完結）
    - 追加ガード（step-up/2人承認/上限）が無い、またはAPI直叩きで迂回できる
    - テナント/所有/ロール条件が不一致（IDOR/越境が波及）
    - 再実行防止が無く、二重実行の兆候（同一requestで2回成立し得る）
    - 監査が無い/弱い（否認防止不可、検知不可）
  - P1：
    - 追加ガードはあるが例外パス（admin/internal/job）で抜ける
    - 状態遷移が入口ごとに曖昧（10）
  - P2：
    - 設計は堅牢だがUX/運用が弱く、例外運用（サポート代行等）で迂回が起きやすい（11/09）
- “成立条件”としての整理（技術者が直すべき対象）
  - 重要操作を専用コマンド化し、入力の意味を限定（MAを構造的に排除）
  - 追加ガード（step-up/2人承認/上限）を必須化し、PEPで強制（UIに置かない）
  - idempotency と状態遷移で二重実行を封じる
  - 監査ログを強化（actor/tenant/target/before/after/request_id/reason）

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：重要操作がgeneric_updateで成立している
  - 次の検証（最小差分）：
    - 重要フィールド（role/state/limit/approved等）が通常updateで更新できる兆候を観測（レスポンス/後続GET）
  - 判断：
    - 反映あり：P0（05/10へ連鎖）
- 仮説B：追加ガードがUIのみで、APIで迂回できる
  - 次の検証：
    - UI操作時の裏API（HAR）を特定し、同じAPIが“追加ガード無し”で叩けないかを差分で観測
  - 判断：
    - 迂回兆候：P0（04のPEP抜け）
- 仮説C：再実行防止が弱い（idempotency無し）
  - 次の検証：
    - 同一操作の再送/リトライで、応答や状態が一貫するか（重複が起きないか）を観測
  - 判断：
    - 不一致/重複兆候：P0〜P1（Impactにより）
- 仮説D：状態遷移の不一致がある（10）
  - 次の検証：
    - 状態別（draft/approved）で、重要操作が拒否/許可される条件が入口ごとに一致するか観測
  - 判断：
    - 不一致：P1（設計欠陥。重要操作ではP0寄り）

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/` ）：
  - `04_labs/02_web/03_authz/06_privileged_actions_approve_payment_role/`
    - 構成案：
      - 重要操作：approve（状態遷移）、transfer（送金）、grant-role（権限付与）
      - 2段階（prepare→commit）と idempotency のON/OFFを切替
      - 追加ガード：step-up（直近再認証）/2人承認/上限を切替
      - 入口：通常API、admin API、job/webhook を用意し、例外パスを再現
      - 監査ログ：actor/tenant/target/before/after/request_id/reason/decision を必ず出す
- 取得する証跡（深掘り向け：HTTP＋周辺ログ）
  - HTTP：prepare/commit（ある場合）、確認画面、エラー、再送時の応答
  - 状態差分：before/after（10）
  - ログ：idempotencyキー、重複排除、追加ガードの判定、拒否理由
  - 監査：承認/送金/権限付与の履歴（否認防止）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
# 良い：専用コマンド（擬似）
POST /api/requests/123/approve
{ "reason": "checked" }

# 危険：通常更新で重要操作が成立（擬似）
PATCH /api/requests/123
{ "state": "approved" }   # これで承認が完了するなら危険（05/10）

# 送金：idempotencyが必要（擬似）
POST /api/transfers
Idempotency-Key: IK_...
{ "to": "dest", "amount": 1000 }

# 観測すること（擬似）
- 重要操作が専用コマンド化されているか
- step-up/追加ガードが必須か（UIだけでないか）
- idempotency と状態遷移で二重実行が封じられているか
- 監査（who/when/what/why）が残るか
~~~~
- この例で観測していること：
  - 重要操作が“通常更新/属性更新”で成立しないこと、追加ガードと整合性・監査があること
- 出力のどこを見るか（注目点）：
  - command_style、additional_guard、idempotency、state_guard、audit_strength、入口差分（admin/job）
- この例が使えないケース（前提が崩れるケース）：
  - 重要操作が外部決済等の外部システムで完結（→戻りの状態遷移/監査/権限付与の境界を主対象にする）

## 参考（必要最小限）
- OWASP ASVS（高リスク操作の保護、再認証、監査）
- OWASP WSTG（Business Logic / Authorization：重要操作）
- PTES（成立条件モデル化→最小差分観測）
- MITRE ATT&CK（Impact：高価値操作の達成）

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/03_authz_05_mass-assignment_モデル結合境界.md`
- `01_topics/02_web/03_authz_10_object_state_状態遷移と権限（draft_approved）.md`
- `01_topics/02_web/02_authn_16_step-up_再認証境界（重要操作_再確認）.md`

## 次（07以降）に進む前に確認したいこと（必要なら回答）
- 07 GraphQL：
  - GraphQLが実在しない場合でも、field-level authz を“概念として”一般APIのネスト/関連に置き換えて書いてよいか
- 09 admin console：
  - 管理UIが別ドメイン/別IdPか同一かで、例外パスの書き方が変わる（どちらも一般化は可能）
