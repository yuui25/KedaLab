# 03_m365_権限境界（アプリ登録_Consent）

## ガイドライン対応（冒頭）
- ASVS：V2（認証）/V4（アクセス制御）/V14（設定）/V15（ログ）を「SaaS側の同意・権限付与・監査」で満たす/破れる観点として扱う（アプリ同意＝外部主体に権限を“委任”する設定変更）。
- WSTG：Webアプリそのものではなく「外部IdP/クラウド設定のテスト前提」を支える（認証設定・セッション・アクセス制御の前提条件の検証として位置づける）。
- PTES：Intelligence Gathering → Threat Modeling → Vulnerability Analysis（設定/権限境界の特定）→（必要に応じて）Exploitation（許可された範囲での検証）→ Reporting。
- MITRE ATT&CK：T1671（Cloud Application Integration）を中心に、Discovery/Privilege Escalation/Persistence（“同意”が成立した場合の権限獲得と維持）に接続。

## 目的（この技術で到達する状態）
Microsoft 365 / Microsoft Entra ID（旧Azure AD）において、**「アプリ登録（Application）」「エンタープライズアプリ（Service Principal）」「同意（Consent）」「権限（Delegated/Application Permissions）」「ロール（Directory Roles / App Roles）」**が作る権限境界を、監査ログと設定値から**状態として言語化**し、次の意思決定（攻め筋/優先度/検証）に直結させる。

到達目標（状態定義）：
- だれが（主体）/なにに（対象API・リソース）/どの権限で（Delegated vs Application）/どのスコープで（ユーザー単位 vs テナント全体）/どの経路で（ユーザー同意・管理者同意・管理者同意ワークフロー）付与できるかを、**再現可能な観測**で説明できる。
- “同意が危険”の一般論ではなく、**このテナントはどの境界が開いている/閉じている**を結論として出せる。

## 前提（対象・範囲・想定）
対象：
- Microsoft Entra ID（テナント）＋ Microsoft 365（Graph/Exchange/SharePoint/Teams等）
- アプリの表現：  
  - **Application object（アプリ定義）**：App registrations（ホームテナント）  
  - **Service principal（アプリ実体）**：Enterprise applications（各テナントのインスタンス）

想定する“権限境界”の軸（このファイルの物差し）：
- 資産境界：テナント内データ（メール/ファイル/チャット/ディレクトリ）に対するAPIアクセス
- 信頼境界：外部アプリ（マルチテナント/検証済み発行元/ギャラリー）を“社内主体”として扱ってよいか
- 権限境界：同意（Consent）が「ユーザー単位」か「テナント全体」か、また Delegated/Application のどちらか

スコープ（このファイルで“やらない”こと）：
- フィッシング手口の具体化や、無許可での同意誘導の実施手順は扱わない（診断は必ず許可された合意範囲で、テナント管理者と手順・影響を擦り合わせた上で行う）。
- Defender 製品個別の設定網羅はしない（ただし、監査ログ/相関の観測点は示す）。

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) “同意”が発生するオブジェクト境界（Application / Service Principal）
観測したい状態：
- アプリ定義（Application）と、テナント内実体（Service Principal）がどう増えるか  
  → “誰がアプリを増やせるか”は **攻撃面（Attack Surface）** になる。

見る場所（管理画面）：
- Entra 管理センター
  - **App registrations**（Application object）
  - **Enterprise applications**（Service principal）

見る場所（意味）：
- Application：redirect URI、credentials（client secret/cert）、API permissions（要求）
- Service principal：実際に付与された**同意（OAuth2PermissionGrant / AppRoleAssignment）**、割り当て、CA適用、テナント固有設定

根拠（一次情報）：
- アプリが追加される経路、Application と Service Principal の関係（同意の初回で SP が作られ得る等）  
  https://learn.microsoft.com/en-us/entra/identity-platform/how-applications-are-added

### 2) “同意ポリシー”境界（ユーザー同意の可否・条件）
観測したい状態（この差が攻め筋を分ける）：
- ユーザーが同意できるか（ON/OFF）
- 同意できる条件（検証済み発行元のみ、低リスク権限のみ 等）
- 既存の同意付与は変わらない（＝過去に付与された同意の棚卸しが必要）

見る場所（管理画面）：
- Entra 管理センター → Enterprise applications / Consent and permissions（UI名称は更新されることがある）
- もしくは Microsoft Graph / PowerShell で authorizationPolicy / permissionGrantPolicies を参照

見るべき代表ドキュメント（設定の“状態”を規定する一次情報）：
- User consent 設定（既定、Graph/PowerShell例、既存同意は影響しない等）  
  https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent
- App consent policies（microsoft-user-default-*, Microsoft managed policy、条件セットの考え方）  
  https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-app-consent-policies

観測の具体（実務で迷わない最小セット）：
- テナントの user consent が
  - 無効（＝ユーザー同意で新規権限が増えない）
  - Microsoft 推奨（managed）/ low / legacy 等のどれか
- “Verified publisher 限定”が効いているか（＝信頼境界が狭いか）
- “高影響”の委任権限（例：Mail/Files/Sites/Chat 等）がユーザー同意に含まれていないか（＝権限境界が広い）

### 3) “ステップアップ同意”境界（リスク検出→管理者同意へ強制）
観測したい状態：
- 「リスクの高い同意要求」が検出された場合に、ユーザー同意から**管理者同意へステップアップ**するか
- そのステップアップ時に、**管理者同意ワークフロー**へ誘導されるか（運用導線）

根拠（一次情報）：
- Risk-based step-up consent（既定有効、挙動、監査イベントの示唆）  
  https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-risk-based-step-up-consent

### 4) “管理者同意ワークフロー”境界（申請→レビュー→承認の運用）
観測したい状態：
- ユーザーが同意できない場合に、管理者へ申請できるか
- 誰がレビュー担当か（承認権限を持つか）
- 申請が監査可能か（ログが残るか）

根拠（一次情報）：
- Admin consent workflow 概要（申請導線、レビュー画面、通知）  
  https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/admin-consent-workflow-overview

### 5) “検証済み発行元（Verified publisher）”境界（信頼のラベル）
観測したい状態：
- マルチテナントアプリが publisher verified か（同意画面に verified 表示）
- publisher domain が設定/検証されているか（同意画面の信頼情報）

根拠（一次情報）：
- Publisher domain 構成（.well-known 配置など）  
  https://learn.microsoft.com/en-us/entra/identity-platform/howto-configure-publisher-domain
- Publisher verified の手順・前提（Partner ID 等）  
  https://learn.microsoft.com/en-us/entra/identity-platform/mark-app-as-publisher-verified

### 6) “既存同意（棚卸し）”境界（過去の付与が残存する）
観測したい状態：
- 既に付与された Admin consent / User consent が何か
- 取り消し（revoke）できるか（ポータルの制約、Graph/PowerShellが必要か）
- 重要：User consent の revoke は UI だけでは完結しない場合がある（運用と手順が要る）

根拠（一次情報）：
- Review/revoke permissions（Admin consent と User consent の扱い差分、権限要件）  
  https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/manage-application-permissions

### 7) ログ（観測→相関→証跡）境界
最低限押さえる“相関キー”：
- actor（誰が）：ユーザー/管理者/サービスプリンシパル
- target（何に）：アプリ（AppId/ServicePrincipalId）、リソース（Graph 等）
- change（何を変えた）：同意付与、権限追加、ロール付与
- when（いつ）：時刻
- where（どこから）：IP、デバイス、アプリケーション（ポータル/Graph/PowerShell）

MITREの検知戦略（“何をログで見るべきか”の裏取り）：
- Cloud Application Integration（T1671）の検知戦略（同意付与・アプリ登録・権限付与の相関）  
  https://attack.mitre.org/detectionstrategies/DET0539/

## 結果の意味（その出力が示す状態：何が言える/言えない）
ここは「設定値→状態」へ翻訳する章。結論を次の型で出す。

### A. ユーザー同意が“実質可能”な状態
成立条件（例）：
- user consent が許可されている（legacy/managed/low 等）
- 同意可能な権限が広い、または verified publisher 制限が弱い
- ステップアップ同意が無効、または運用上機能していない（申請導線が潰れている等）

意味：
- “ユーザー”を起点に、外部アプリへ委任権限が付与され得る  
  → **信頼境界が「同意画面の判断」に委ねられている**状態
- 既存同意の棚卸しが未実施だと、過去の付与が継続している可能性が高い

言えないこと（誤解防止）：
- ユーザー同意がONでも、すべての権限が付与できるわけではない（admin consent 必須権限は別）
- CA や アプリ割り当て必須設定により、実行時にブロックされる場合がある（＝“同意できた”と“使える”は別）

### B. 管理者同意が“実質可能”な状態（承認権限が分散/過剰）
成立条件（例）：
- 管理者/アプリ管理者ロールが広く付与されている
- admin consent workflow のレビュワーが多い/承認基準が曖昧
- 監査ログのレビューが追いついていない

意味：
- “誰が承認できるか”が権限境界  
  → ここが緩いと **テナント全体に効く権限付与（tenant-wide consent）**が成立し得る

### C. 防御的に堅い状態（同意の境界が狭い）
成立条件（例）：
- ユーザー同意が無効、または verified publisher + 低リスク権限に限定
- リスクベースのステップアップ同意が有効で、ワークフローが運用されている
- 既存同意の棚卸しと revoke が定期実施されている

意味：
- 同意は“運用を含む統制”として機能している  
  → 認証/SSOの強化だけでは守れない **クラウド権限の横口** を閉じている

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
※本章は“攻めの再現手順”ではなく、**ペンテストでの優先度付けと仮説設計**として書く。

### 優先度が上がる観測結果（＝攻め筋が増える状態）
- ユーザー同意が広い（legacy/managedでも例外が多い、低リスク分類が甘い）
- verified publisher 制限が弱い（未知アプリが混ざる余地）
- 既存の同意付与が多い（特に Graph の高影響 delegated、または application permissions）
- “アプリ登録できる主体”が広い（開発者以外も App registration 可能、管理統制が弱い）
- 監査ログ相関ができていない（付与イベントとサインイン/データ操作が繋がらない）

### “同意”が成立した場合に起きること（影響の型）
- Delegated permissions：ユーザー権限の範囲でデータアクセス（ただし継続的なトークン/セッション管理が絡む）
- Application permissions：ユーザー非依存で広域アクセス（テナント全体のデータ面に直結しやすい）
- いずれも「外部アプリ＝新しい主体」が生まれる点が本質  
  → IAMの主体モデルが拡張され、監視対象が増える

### 仮説の立て方（最短で“境界の弱点”へ寄せる）
- 仮説1：ユーザー同意が許可されており、例外/分類が甘い → “ユーザー起点の委任”が成立する余地
- 仮説2：管理者同意の承認境界が広い（ロール過多/ワークフロー緩い）→ “テナント全体の同意”が成立する余地
- 仮説3：既存同意が放置されている → “過去の付与”が最大の攻撃面になっている

## 次に試すこと（仮説A/Bの分岐と検証）
ここは「診断手順（観測→判断→次）」として最も具体化する。  
前提：必ずテナント管理者と合意した検証範囲で実施し、影響を最小化する（新規アプリ作成や権限付与を伴う検証は原則“検証用テナント/検証用アプリ”で行う）。

### 手順0：証跡設計（最初に決める）
- 相関キーを固定する：  
  - 検証用ユーザー（UPN）  
  - 検証用アプリ名（prefix 例：keda-lab-<date>-consent-test）  
  - 検証開始/終了時刻  
- 取得するログ（最低限）：  
  - Entra の Audit logs（ApplicationManagement）  
  - Entra の Sign-in logs  
  - Microsoft 365 Unified Audit Log（可能なら）  
- 成果物の型：  
  - 「設定値（スクショ/JSON）」「ログ（イベントID/時刻/actor/target）」「結論（状態）」を1セットにする

### 仮説A：ユーザー同意が実質可能か？
1) 設定の観測（UI or Graph）
- user consent が “無効 / 有効（どのポリシー）” かを確定する  
  根拠：User consent 設定の一次情報  
  https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent
- app consent policies（Microsoft managed / low / legacy など）の適用状態を確認する  
  根拠：App consent policies  
  https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-app-consent-policies

2) 判断（状態に落とす）
- 有効かつ条件が緩い → 「ユーザー起点の委任が成立し得る」  
- 有効だが verified publisher / low risk に限定 → 「ユーザー起点の委任は限定的」  
- 無効 → 「ユーザー起点では増えない（ただし既存同意は別）」に分類

3) 次の一手（検証の分岐）
- A-1：有効で緩い  
  → “既存同意の棚卸し”を最優先（新規検証より、現実の露出面が大きい）
- A-2：有効だが限定  
  → “例外（除外）”の有無、低リスク分類の妥当性を確認
- A-3：無効  
  → “管理者同意/既存同意/アプリ登録経路”へ進む

### 仮説B：リスクベースのステップアップが効いているか？
1) 設定の観測
- step-up consent の有効/無効（既定有効、PowerShellで制御）  
  根拠：Risk-based step-up consent  
  https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-risk-based-step-up-consent

2) 判断
- 有効 ＋ admin consent workflow 有効 → “危険同意が運用導線に流れる”  
- 有効だが workflow 無効 → “止まるが申請導線がない（現場は抜け道を作りがち）”  
- 無効 → “ユーザー同意のリスク緩和が弱い”として優先度を上げる

3) 次の一手
- Workflow のレビュー担当/承認権限（RBAC）と監査の回り方を確認（次の仮説Cへ）

### 仮説C：管理者同意ワークフローが“承認境界”として機能しているか？
1) 観測
- ワークフローが有効か、レビュワーは誰か、承認権限と分離されているか  
  根拠：Admin consent workflow  
  https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/admin-consent-workflow-overview

2) 判断
- レビュワーが多すぎる/承認権限者が広い/基準が曖昧 → “テナント全体同意が通る境界”が広い
- 監査ログが追えていない → “承認後の利用”の検知が弱い

3) 次の一手
- 承認イベント（Audit）と、その後のサインイン/データアクセス（Sign-in / Unified Audit）を相関できるか確認  
- “T1671 の検知戦略”に沿ったログ相関ができるかをチェック  
  https://attack.mitre.org/detectionstrategies/DET0539/

### 仮説D：既存同意が最大の攻撃面になっていないか？
1) 観測（棚卸し）
- Enterprise applications の Permissions から Admin consent / User consent を確認し、不要なものを洗い出す  
  根拠：Review permissions / revoke  
  https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/manage-application-permissions

2) 判断（状態）
- 高影響 delegated が多数 → “ユーザー権限での横口”が多い
- application permissions が付与された外部アプリがある → “ユーザー非依存の主体”が存在
- オーナー不明/用途不明が多い → “運用境界”が崩れている

3) 次の一手
- revoke の可否（UI/Graph）と、revoke 後の影響範囲（利用停止・業務影響）を合意形成
- “いつ・誰が・何に”付与したかを監査ログから引き直し、恒久対策（ポリシー/申請導線/分類）へ戻す

### 最小コマンド例（必要時のみ：観測の再現性確保）
※ツール紹介ではなく「観測の固定化」目的。実施は最小限に留める。

~~~~
# Graph PowerShell（例：権限は最小に。読み取りと変更を分ける）
# 読み取り：Policy.Read.All
Connect-MgGraph -Scopes "Policy.Read.All"

# 変更：Policy.ReadWrite.Authorization（変更は合意のある検証環境で）
Connect-MgGraph -Scopes "Policy.ReadWrite.Authorization"
~~~~

（具体の API パス例やポリシーIDの扱いは、User consent 設定ドキュメントの手順に従い、現状取得→差分適用→証跡保存の順で行う）  
https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent

## ガイドライン対応（末尾：このファイルで“どう使うか”）
- ASVS：
  - V4（アクセス制御）：外部アプリに付与される権限が最小化され、テナント全体同意が統制されているか（同意＝権限付与の制御）。
  - V14（設定）：ユーザー同意/同意ポリシー/ワークフロー/検証済み発行元の設定が意図通りか。
  - V15（ログ）：同意付与・権限追加・アプリ登録が監査可能で、相関できるか。
- WSTG：
  - 認証/認可テストの“前提”として、外部IdP/SaaS設定が権限境界を壊していないかを確認（WSTGを直接なぞるのではなく、Webテストの前に境界を確定する役割）。
- PTES：
  - Intelligence Gathering：テナント設定（同意/ワークフロー/発行元）と既存同意の棚卸し。
  - Threat Modeling：同意が成立した場合の影響（delegated/application）をモデル化。
  - Vulnerability Analysis：緩い境界（ユーザー同意・管理者同意運用・既存同意放置）を特定。
  - Reporting：状態（A/B/C）で結論化し、具体の統制（ポリシー/ワークフロー/棚卸し）へ落とす。
- MITRE ATT&CK：
  - T1671（Cloud Application Integration）：アプリ統合/同意付与を起点にした権限獲得・継続利用を想定し、Audit/Sign-in/Unified Audit を相関して検知可能性を評価する。  
    https://attack.mitre.org/detectionstrategies/DET0539/

## 参考（必要最小限）
- How and why apps are added to Microsoft Entra ID（Application/Service principal の関係）  
  https://learn.microsoft.com/en-us/entra/identity-platform/how-applications-are-added
- Configure how users consent to applications（ユーザー同意設定・既存同意は変わらない）  
  https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent
- Manage app consent policies（既定ポリシー/managed policy の考え方）  
  https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-app-consent-policies
- Configure risk-based step-up consent（リスク検出→管理者同意へ）  
  https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-risk-based-step-up-consent
- Admin consent workflow overview（申請・レビュー運用）  
  https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/admin-consent-workflow-overview
- Publisher domain / Publisher verified（信頼ラベルの前提）  
  https://learn.microsoft.com/en-us/entra/identity-platform/howto-configure-publisher-domain  
  https://learn.microsoft.com/en-us/entra/identity-platform/mark-app-as-publisher-verified
- Review permissions granted to enterprise applications（棚卸し・revoke）  
  https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/manage-application-permissions
~~~~
