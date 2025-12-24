# 11_scim_jit_provisioning_境界（権限初期値）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回）
- ASVS：V2（認証・アカウント管理）、V3（セッション管理：SaaS側トークン運用含む）、V4（アクセス制御：ロール/グループ/テナント境界）、V14（設定：外部連携・プロビジョニング設定の安全な運用）
- WSTG：WSTG-ATHN（アカウント作成/管理・SSO運用の例外パス）、WSTG-ATHZ（ロール/グループによる権限付与の検証）、WSTG-CONF（連携設定・トークン/鍵の保護、ログ/監査）
- PTES：Vulnerability Analysis（成立条件・設定不備の特定）→ Exploitation（検証環境での再現）→ Post-Exploitation（権限維持/横展開の入口確認）→ Reporting（境界・影響・再現手順）
- MITRE ATT&CK：Credential Access / Persistence / Privilege Escalation / Discovery（例：T1078 Valid Accounts、T1098 Account Manipulation、T1136 Create Account、T1556 Modify Authentication Process）

## 目的（この技術で到達する状態）
SCIM（System for Cross-domain Identity Management）および JIT（Just-In-Time）Provisioning を「認証連携の便利機能」ではなく、**権限初期値（default role）と権限伝播（group/role mapping）を決める“境界”**として捉え、次の状態に到達する。

- どこが“アカウントの真実（source of truth）”かを言語化できる（HR/IdP/SaaSのどこがマスターか）
- どのタイミングで“アカウントが作られる/更新される/無効化される”かを説明できる（JIT vs SCIM 同期）
- “作られた瞬間の権限”が何で決まるかを特定できる（初期ロール・グループ付与・アプリロール）
- 権限が過大になりうる経路（例外パス）を列挙できる（既存アカウントとの紐付け、属性欠落時のデフォルト、グループ同期遅延、解除漏れ）
- 検証の観測点（IdPログ/SCIMログ/SaaS監査ログ）と相関キー（userId/externalId/requestId）を設計できる

## 前提（対象・範囲・想定）
- 対象は「SaaS へのユーザ/グループ供給」方式のうち、以下を含む。
  - SCIM 2.0（RFC 7643/7644 ベース）でのユーザ/グループ同期
  - SAML/OIDC の JIT Provisioning（初回ログイン時の自動作成）
  - IdP 側（Okta / Microsoft Entra ID / Google Workspace 等）の “プロビジョニング機能” と SaaS 側の “受け口（SCIM endpoint / JIT設定）”
- ペンテスト観点のゴールは「壊す」ではなく、**境界の誤設定で“権限が増える/残る/消えない”状態**を再現可能に示すこと。
- 前提として、以下は環境ごとに差が大きい（ここを最初に確定する）。
  - “アプリへの割当（assignment）” と “グループ push” の意味が製品ごとに違う
  - 役割（role）を SCIM 属性で渡せるか（roles/entitlements/custom extension）・SaaSが受けるか
  - Deprovision（無効化/削除）が “active=false” なのか “削除” なのか
- 検証は原則 04_labs での再現が望ましい（特に “誤設定→ログで追える” を作る）。

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) 境界モデル（資産/信頼/権限）を先に固定する
- 資産境界：ユーザ属性（氏名・メール・部署・職務・雇用状態）を管理している主体はどこか（HR / IdP / SaaS）
- 信頼境界：SaaS が信じる入力はどこか
  - JIT：SAML Assertion / OIDC Claims（IdP署名済み）を信じて「作成/更新」する
  - SCIM：SCIM Bearer Token / Basic / OAuth（IdP→SaaS API）を信じて「作成/更新/無効化」する
- 権限境界：SaaS 内の “ロール/グループ/アプリロール/チーム/ワークスペース” がどの入力で決まるか
  - 初期権限（default role / default group）
  - グループ同期（SCIM Groups + membership）
  - 属性→ロール変換（department/title/costCenter → role）や、AppRoleAssignments のような IdPロール同期

### 2) JIT Provisioning の観測（初回ログインで何が起きるか）
観測対象（データ/境界）は「初回ログインの一回」で固定できる。
- SAMLの場合（例）
  - NameID（どの識別子で紐付くか：email? immutable ID?）
  - 属性（email、givenName、surname、groups、role 等）
  - Audience / Recipient / ACS URL（SaaS側受け口の境界）
  - 署名（assertion/response）と証明書ローテーション
- OIDCの場合（例）
  - sub（不変ID）と email（可変）どちらで紐付くか
  - groups/roles クレームがあるか、スコープに依存するか
  - claims の欠落時に SaaS がどう振る舞うか（デフォルトロール適用、拒否、保留）

観測ログ
- IdP：サインインログ（誰が、どのアプリに、どの条件で、どのクレームで）
- SaaS：ユーザ作成イベント、ロール付与イベント、グループ参加イベント、初回ログインイベント

### 3) SCIM の観測（“同期”で何が起きるか）
SCIMは “どのHTTPが飛ぶか” より “その結果としてSaaSが何を状態として持つか” が本体。

観測すべきSCIMの要素（プロトコル/データ）
- Resources：/Users, /Groups, /ServiceProviderConfig, /Schemas, /ResourceTypes
- 識別子の使い分け
  - id：SaaS側が発行するリソースID（不透明）
  - externalId：IdP側の識別子（IdP→SaaS紐付けに使うことが多い）
  - userName：ログインID/メールを置くことが多い（必ずしも不変ではない）
- 更新方式
  - PUT（全置換）か PATCH（差分）か
  - group membership の更新が “Group側のmembers” で来るのか “User側のgroups” で来るのか
- 無効化
  - DELETE か active=false（PATCH/PUT）か
  - “無効化＝アクセス不能” なのか “無効化＝ライセンス解除のみ” なのか（SaaSで差が出る）

観測ログ（相関キーを決める）
- IdP：Provisioning logs（requestId、対象user/group、成功/失敗、レート制限、リトライ）
- SaaS：SCIM受信ログ（リクエストID、actor=IdP integration、対象ID、適用結果）
- 監査ログに “同期ソース（SCIM/JIT/手動）” が出るか（最重要）

### 4) “権限初期値” の観測（このファイルの核心）
権限が決まる“最初の瞬間”は、JIT/SCIMいずれでも発生する。観測点は以下。

- 作成時のロールがどこで決まるか
  - SaaSの default role（例：Member/Viewer/User）設定
  - IdP→SaaS 属性マッピング（role/entitlements/custom attribute）
  - グループ→ロール割当（IdP group push → SaaS group → SaaS role）
- 属性欠落時のデフォルト挙動
  - displayName が無い、department が無い、country が無い等の“欠落”で、SaaSが何を入れるか
  - “空なら管理者” のような危険デフォルトがないか（現実には稀だが、カスタム実装SaaS/社内SaaSで起きる）
- 既存アカウントとの紐付け
  - 既にSaaS側に手動作成された admin アカウントが存在し、JIT/SCIM がそれに “結合” してしまう条件
  - 結合キーが email のみだと、メール同一性の扱いが境界になる（エイリアス、同姓同名、ドメイン変更）

## 結果の意味（その出力が示す状態：何が言える/言えない）
### A) 「JITが有効」＝“サインインの成功”がアカウント作成権を持つ
- 言えること
  - IdPでサインインできる主体は、SaaS側に “存在” を作れる（少なくとも Member として）
  - 初期権限は、SaaS default + 受け取ったクレーム + グループ/ロール設定に依存する
- 言えないこと
  - JITだけで “必ず” 権限が上がるとは言えない（上がるかは mapping 次第）
  - SaaS側のロール/グループ運用が適切なら、JITは単にオンボーディング手段に過ぎない

### B) 「SCIMが有効」＝“同期が成功する主体”がアカウント状態を支配する
- 言えること
  - SCIM token を持つ主体（IdP integration）が、ユーザ作成/更新/無効化を行える（SaaS内の権限状態を継続的に変えられる）
  - グループ同期がある場合、membership変更が “ロール付与” に直結する構成が多い
- 言えないこと
  - SCIM=常に安全ではない（むしろ運用の誤りで “解除漏れ” が起こりやすい）
  - “削除” と “無効化” の意味はSaaSで違い、ログだけでは判別できない場合がある（UI/監査イベントで確認が必要）

### C) 「権限初期値が危ない」状態の定義（判定基準）
以下のいずれかを満たすと、境界の観点で “危ない状態” と判定できる。

- 初期ロールが想定より高い（Member ではなく Admin/Owner が付き得る）
- 初期ロールは低いが、グループ同期が “広すぎる” ため結果的に高権限が付く（例：Everyone→Admin相当）
- Deprovision が遅延/失敗しても検知できず、権限が残る（退職者・異動者・一時委託）
- 既存アカウントとの結合キーが弱く、意図せず高権限アカウントへ結合し得る
- “手動変更” が IdP 側に反映されず、SaaS側で権限が逸脱しても放置される（双方向不整合）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
※ここは「実務の侵入後/横展開で何を優先するか」を決めるための“意思決定”として書く。

### 1) 優先度が上がる観測結果（攻め筋の価値が高い）
- SaaS側で “SCIM/JITで作成されたユーザ” が広く存在し、ロール差が大きい
- グループ→ロール割当が “少数の高権限グループ” で運用されている（運用ミスの影響が大きい）
- Deprovision の失敗・遅延がログに出ている（レート制限、エラー、リトライの蓄積）
- 既存アカウントの結合が email 依存（sub/externalIdを使っていない）

### 2) 典型的な攻め筋（“境界”が壊れる形）
- 権限初期値の取り込み
  - JITで作成されるが “どのグループに入るか” がIdP側条件次第（例：動的グループ/属性ルール）
  - SCIMで roles/entitlements を受ける実装で、IdP側の role mapping が過大
- 権限解除漏れの悪用（永続化）
  - 退職/異動でもSaaS側ロールが残る（SCIM無効化が active=false だけで “所有権” が残る等）
- 結合キー誤設定の悪用
  - 既存の管理者アカウントへ結合し得る条件（同一email、同一UPN、エイリアス）を探す

### 3) 次の仮説（A/Bに分ける）
- 仮説A：初期権限は「SaaS default」主導
  - ならば、SaaS側の default role / default group / 招待制の設定が主戦場
- 仮説B：初期権限は「IdP mapping（属性/グループ）」主導
  - ならば、IdP側の割当条件、グループ同期範囲、ロール変換式、例外パス（除外ルール）が主戦場

## 次に試すこと（仮説A/Bの分岐と検証）
ここでは “確認項目” ではなく、**再現可能な検証手順（観測→解釈→次の手）**に落とす。

### 共通：最初に取るべき証跡（相関できる形）
- IdP側
  - 対象アプリの Provisioning logs（ユーザ作成/更新/無効化、グループpush、失敗理由）
  - サインインログ（JITが絡む場合）
- SaaS側
  - 監査ログ（user created/updated/deactivated、role changed、group membership changed）
  - “変更の発生源” が出るなら必ず取得（SCIM/JIT/手動/API key）
- 相関キーの候補（最低どれか1つで結ぶ）
  - userName/email（可変なので補助）
  - externalId（IdP起点の紐付けで最重要になりやすい）
  - SaaS userId（SaaS監査ログの主キー）
  - requestId / correlationId（IdP provisioningとSaaS受信ログの結合）

### 仮説A：SaaS default が強い（初期権限がSaaS側で決まる）
狙い：SaaS側の“デフォルト/例外”を確認し、JIT/SCIMでも過大権限にならないかを見る。

1) SaaS管理画面で default role / default access / auto-join の設定を確認
- “新規ユーザの既定ロール”
- “自動的に参加するワークスペース/プロジェクト”
- “ドメイン一致で自動参加” のような機能

2) JIT有効なら「属性欠落時」を再現
- IdP側で、テストユーザに対して “role/groups 相当のクレームを出さない” 状態を作る（可能なら）
- 初回ログインさせ、SaaS側で付いたロール/所属を監査ログで確認

3) SCIM有効なら「グループ同期なし/あり」で差分を確認
- “ユーザ作成だけ” の状態（グループpush無効/対象外）で作られたユーザのロールを確認
- “グループpush有効” にしてから再同期して、ロールが変化するかを確認

判定
- どの条件でも “最小権限（Viewer等）” から始まるなら、SaaS default は健全
- 条件によって “管理者相当が付く/自動で高権限グループに入る” があるなら、境界破綻

### 仮説B：IdP mapping が強い（初期権限がIdP側で決まる）
狙い：IdP側の割当条件・グループ同期・ロール変換が「権限境界」になっていることを突き止める。

1) IdPの “割当（assignment）” と “グループpush” を分解して理解する
- 製品によっては「グループをpushしてもユーザは作られない」「ユーザ割当しないと作られない」がある。
- 例：Okta系の多くで “Push groups はユーザプロビジョニングと別物” である旨が明記されるケースがある（SaaSドキュメント側にも注意書きがある）。

2) “権限に直結する入力” を特定する（どの属性がロールを動かすか）
- roles/entitlements/custom extension が SCIM payload に含まれるか（IdP側の attribute mapping を確認）
- グループ名（displayName）が SaaS側のロール割当に使われるか（同名グループで結合される実装が多い）
- “Everyone” のような広いグループが割当/同期に含まれていないか

3) 例外パス（除外ルール）を確認
- スコープ（同期対象）を “All users” にしていないか（Entra等でよくある誤設定）
- 条件付きアクセス/サインオンポリシーの例外により、想定外のユーザがJITできない/できるが起きていないか
- Deprovision を “無効化のみ” にしており、SaaS側の所有権/トークン/外部連携が残らないか

4) 手を動かす検証（安全な範囲での再現）
- テストユーザを “低権限グループ→高権限グループ” に移し、SaaS側で role change が起きるかを監査ログで追う
- 逆（高→低）に戻し、解除が確実に起きるか、遅延/失敗があるかを見る
- Deprovision（無効化/削除）を行い、SaaS側で「ログイン不可」「API token無効」「所有権移譲」などがどう扱われるか確認

SCIMの通信確認（“やりすぎない”最小例：意味の理解が目的）
~~~~
# 例：SCIM 2.0で「このSaaSは何をサポートするか」を読む（読み取り専用が基本）
curl -sS -H "Authorization: Bearer <SCIM_TOKEN>" https://<scim_base>/ServiceProviderConfig | jq
curl -sS -H "Authorization: Bearer <SCIM_TOKEN>" https://<scim_base>/ResourceTypes | jq
curl -sS -H "Authorization: Bearer <SCIM_TOKEN>" https://<scim_base>/Schemas | jq

# 例：ユーザ検索（filterの意味＝結合キーを推測する材料）
curl -sS -H "Authorization: Bearer <SCIM_TOKEN>" \
  "https://<scim_base>/Users?filter=userName%20eq%20%22alice@example.com%22" | jq
~~~~
解釈の要点
- ServiceProviderConfig：PATCH対応、フィルタ対応、認証方式など（“境界の仕様”）
- ResourceTypes/Schemas：roles/entitlements などの拡張有無（“権限伝播できるか”）
- filter：SaaSがどの属性で検索/結合しているかのヒント

### 追加：解除漏れ（永続化）を“境界”として証明する観測
- IdP側で無効化したのに、SaaS側が “active=false にならない/ログインできる” を再現できるか
- SaaS側でユーザを手動で復活/権限変更しても、IdP側に戻らない（ドリフト）を示せるか
- “同期失敗が検知されない” 状態（監査が取れていない/アラートがない）を示せるか

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回）
- ASVS
  - V2：アカウント作成・プロビジョニング（自動作成/JIT、無効化/削除、再有効化）の制御と監査
  - V4：ロール/グループの付与・剥奪が一貫して最小権限であること（デフォルト権限、例外パス、解除漏れ）
  - V14：外部連携（SCIMトークン、IdP設定）の安全な運用、鍵/トークン保護、ログ保全
- WSTG
  - WSTG-ATHN：JITが有効なときのアカウントライフサイクル検証（作成/結合/無効化）
  - WSTG-ATHZ：グループ/ロール同期による権限境界検証（付与/剥奪、遅延、ドリフト）
  - WSTG-CONF：プロビジョニング設定の露出/誤設定、監査ログの完全性
- PTES
  - Vulnerability Analysis：設定・同期・ログから“成立条件”を特定
  - Exploitation：テストユーザでの差分再現（低→高→低、無効化）
  - Post-Exploitation：解除漏れ/権限残存を永続化リスクとして評価
  - Reporting：境界（資産/信頼/権限）で説明し、再現手順とログ根拠を添付
- MITRE ATT&CK
  - T1078 Valid Accounts：JIT/SCIMで作られた正規アカウントの悪用
  - T1098 Account Manipulation：グループ/ロール変更（プロビジョニング経由）
  - T1136 Create Account：自動作成（JIT/SCIM）を足場にする
  - T1556 Modify Authentication Process：SSO/JIT設定変更（運用者侵害時の影響評価）

## 参考（必要最小限）
- RFC 7643（SCIM Core Schema）：https://www.rfc-editor.org/rfc/rfc7643.html
- RFC 7644（SCIM Protocol）：https://www.rfc-editor.org/rfc/rfc7644
- RFC 7643（RFC Editor Info）：https://www.rfc-editor.org/info/rfc7643
- Microsoft Entra：SCIMアプリの属性マッピング（roles含む）：https://learn.microsoft.com/en-us/entra/identity/app-provisioning/customize-application-attributes
- Atlassian：Oktaでのユーザプロビジョニング（グループpushとユーザ同期の関係）：https://support.atlassian.com/provisioning-users/docs/configure-user-provisioning-with-okta/
- Okta（Developer）：SCIM / Group operations（実装側観点）：https://developer.okta.com/docs/api/openapi/okta-scim/guides/scim-11/
- 参考（運用差分の理解に有用）：Figma（Oktaのpush groups注意）：https://help.figma.com/hc/en-us/articles/25516157472791-Manage-workspaces-and-billing-groups-via-SCIM-in-Okta
- 内部リンク（地続き）
  - ../04_saas/01_idp_連携（SAML OIDC OAuth）と信頼境界.md
  - ../04_saas/05_okta_サインオンポリシーとトークン境界.md
  - ../04_saas/04_azuread_条件付きアクセス（CA）と例外パス.md
