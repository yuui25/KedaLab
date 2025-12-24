# 12_audit_logs_取得と相関（誰が何をいつ）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回）
- ASVS：V7（Error Handling and Logging）を中心に、認証・認可の意思決定ログ（V7.2）、ログ保護（V7.3）、時刻同期（V7.3.4）を満たす/破れる観点として扱う
- WSTG：構成・運用テストの「Log Access Control / Log Review」を中心に、ログ閲覧面のアクセス制御と監視運用の有効性として扱う（WSTG-CONF-02 のログ観点）
- PTES：Reporting（証跡の再現性・時系列・根拠）および Post-Exploitation（横展開/永続化の痕跡を追う）に接続
- MITRE ATT&CK：Discovery / Credential Access / Lateral Movement / Persistence / Defense Evasion（※“監査ログがあることで観測できる/欠けることで追えない”を境界として扱う）

---

## 目的（この技術で到達する状態）
SaaS（M365 / Entra ID / Okta / Google Workspace / GitHub / Slack / Atlassian 等）において、監査ログを「取得できる状態」に加え、  
**(1) 誰が（主体）**、**(2) 何を（操作/イベント）**、**(3) いつ（時刻）**、**(4) どこから（端末/IP/ネットワーク）**、**(5) どの経路で（セッション/トークン/アプリ）**を、**相関キーで繋いで時系列に復元**できる状態にする。

ここでいう“相関”は、単なる検索ではなく以下を満たすこと：
- 1つの“疑わしい起点”（例：特定ユーザ、特定IP、特定アプリ、特定トークン）から、関連イベントを漏れにくく辿れる
- 同一操作が複数ログ面（IdP / SaaS / API / 端末）に分散しても、同一系列として束ねられる
- 調査結果が「再現可能な根拠（抽出条件・ログID・期間・フィルタ）」として残せる

---

## 前提（対象・範囲・想定）
- 対象：SaaS 監査ログ（管理者操作、認証/認可イベント、アプリ同意、権限付与、データアクセス、設定変更、外部連携、API操作、ユーザ/グループ変更）
- 範囲：ペンテスト/診断では「許可された操作のみ」で検証し、監査ログの“残り方”を観測する（運用/IRでは実テナントで調査）
- 境界：
  - 資産境界：どのテナント/組織/ワークスペースが対象か（複数テナントの混在に注意）
  - 信頼境界：IdP（Entra/Okta/Google）と SaaS 本体（Slack/GitHub/Atlassian 等）でログ面が分かれる
  - 権限境界：監査ログ閲覧権限・エクスポート権限・APIアクセス権限が分離される（“見えない”＝“無い”ではない）
- “結果の使い方”前提：ログは「事実の断片」であり、**欠落の理由（設定/ライセンス/保持/収集遅延）**が意思決定に直結する

---

## 観測ポイント（何を見ているか：プロトコル/データ/境界）

### 1) 監査ログの“最小差分セット”（相関のための必須フィールド）
どのSaaSでも、まず次のフィールドが揃うかを確認する（揃わない場合、相関設計は別ルートが必要）。

- 時刻：event_time（UTC推奨） / 収集時刻（ingest_time）
- 主体：actor（user/service principal/app）  
  - user_id（UPN/email/subject）  
  - actor_type（User / Admin / App / ServicePrincipal / Bot）
- 操作：action（event_name / operation / verb）＋ outcome（success/fail）
- 対象：target（resource_id / object_id / app_id / group_id / repo_id など）
- 発生元：source（ip / user_agent / device / geo / network）
- 相関キー：request_id / correlation_id / session_id / trace_id / audit_record_id  
  - これが無い場合、相関は「時刻＋主体＋対象＋IP」等の近似になる（精度が落ちる＝境界）

#### 取り扱い上の境界（機微情報）
- “セッショントークン/アクセストークンの生値”はログに残さない・残っていても保護対象（ASVS V7.1/7.2 の考え方）
- “復旧に必要な相関”は、トークン生値ではなく **jti のような識別子**や **ハッシュ化**などで担保する（可能な設計で）

---

### 2) 取得面（UI/API/エクスポート）と“取得できること”自体が境界
監査ログは「見られる」だけでなく、「出せる」「統合できる」「保持できる」まで含めて到達性を判定する。

- UI：短期の調査・一次確認（検索条件の保存性が弱い場合がある）
- API：再現性ある抽出（自動化・定期取得・SIEM連携の前提）
- エクスポート：長期保管、分析（BigQuery / Log Analytics / S3 等）
- 保持（retention）：過去に遡れる期間が“調査可能性”の上限

---

### 3) 相関の主戦場（IdP×SaaS×ネットワーク×端末）
SaaSの多くは「IdPログ」と「SaaS内部ログ」が分離される。相関は次の接続点が要。

- IdP側（認証・トークン発行・条件付きアクセス・MFA・端末準拠）
- SaaS側（管理操作・権限付与・データアクセス・外部連携・API操作）
- ネットワーク側（プロキシ/CASB/VPN/出口IP）：SaaSログのIPが“プロキシIP”になる境界
- 端末側（EDR/OSログ）：SaaS操作の“起点端末”特定に必要

---

### 4) “観測すべきイベントカテゴリ”の優先順位（侵害/悪用に直結）
以下を優先して観測・取得設計する（全列挙ではなく、判断に直結する順）。

1. 認証イベント：成功/失敗、MFA、リスク、条件付きアクセスの適用/例外
2. 権限イベント：ロール付与/剥奪、グループ変更、管理者昇格、アプリ同意（OAuth/SCIM）
3. 構成変更：監査ログ設定/保持/エクスポート、SSO/SCIM設定、外部連携追加
4. データアクセス：メール/ファイル/リポジトリ/チャンネル/ページ閲覧・ダウンロード・共有
5. API利用：トークン発行/失効、PAT・Bot・App、異常なAPI呼び出し
6. 永続化の痕跡：新規アプリ、Webhook、連携、秘密情報（Secrets）追加、鍵/証明書更新

---

## 結果の意味（その出力が示す状態：何が言える/言えない）

### 状態1：監査ログが“取れている”が“相関できない”
- 例：イベントはあるが request_id/correlation_id が無い、IPが常に同じ（プロキシ）、actorが“app@”で人が追えない
- 言える：監査ログは“存在”するが、追跡精度は境界で落ちる
- 言えない：個別端末起点の断定、1操作の完全な鎖（chain）の断定

→ 意思決定：追加のログ源（IdP詳細、プロキシログ、端末ログ）を要求する、またはログ設計（相関ID/転送）を改善する

---

### 状態2：監査ログが“取れていない”（空/欠落/期間外）
欠落は「侵害の証拠」ではなく、まず“設計/設定/契約/収集遅延”の可能性を切り分ける。

- 典型要因（境界として扱う）：
  - 保持期間が短い（調査が期間外）
  - 対象ログがそのプランでは提供されない
  - 監査ログが無効/部分有効
  - エクスポート未設定（集中保管が無い）
  - 収集遅延（近傍時刻でまだ出ない）
- 言える：現状、当該期間の事実復元ができない（調査不能境界）
- 次の手：別ソース（IdP/端末/ネットワーク）へ切替、または保持/エクスポートの再設計を提案する

---

### 状態3：ログ閲覧/抽出が“分離統制されている”
- 言える：ログ自体の改ざん耐性・アクセス統制の成熟度が高い（WSTGの観点にも接続）
- 言えない：運用者が同一人物でない限り、迅速な調査ができるとは限らない（運用プロセスが必要）

---

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
※ここでは“攻撃手順”ではなく、監査ログが示す「意思決定上の観測価値」を記載する。

### 1) 権限獲得の“到達点”を短時間で確定できる
- 監査ログで追いたい問い：
  - 管理者ロールはいつ/誰が付与したか
  - OAuth同意（Admin consent / user consent）はいつ発生したか
  - SCIM/JITで新規ユーザがいつ作られ、初期ロールがどう付いたか
- これが取れる状態＝“横展開/永続化”の起点を固定できる

### 2) 認証経路（IdP）と操作面（SaaS）を繋ぐと、侵害の“入口”が見える
- IdP側：サインイン成功、MFAの成否、条件付きアクセス適用、リスク検出
- SaaS側：管理操作、データアクセス、連携追加
- 接続点：user_id / app_id / ip / time / correlation_id（ある場合）

### 3) 防御回避の“結果”が観測できるかが境界
- 監査ログ設定変更（無効化、保持短縮、エクスポート停止）が監査ログに残るか
- “残らない”場合：SaaS単体では追えない＝外部保全（SIEM/ログ転送）が必須

---

## 次に試すこと（仮説A/Bの分岐と検証）

### 0) まず決める（調査の骨格）
- 起点（Start Point）を1つ決める：user / ip / app / repo / channel / admin action
- 時間窓（Time Window）を固定する：前後±30分 → ±24h → 直近7日…（段階的に拡大）
- “対象テナント/組織”を固定する：ログの混在（別テナント）を避ける

---

### 仮説A：IdPログとSaaSログが相関キーで繋がる（高精度相関が可能）
やること（順序固定）：
1) IdP側で「起点」のログを引く（認証・トークン発行・条件付きアクセス）
2) 同一の user_id / app_id / ip / correlation_id で SaaS側の監査ログを引く
3) 連続する操作を「時系列チェーン」として並べる（誰→何→いつ→どこから）
4) 追加で “設定変更/権限付与”が含まれていないかを確認（侵害の拡大点）

成果物（最低限）：
- 抽出条件（期間・フィルタ）
- 監査レコードID（各SaaSの event_id）
- 相関に用いたキー（user_id/ip/correlation_id 等）
- 代表イベント5〜10個の時系列（UTCで統一）

---

### 仮説B：相関キーが欠ける/ログ面が分断（中〜低精度相関しかできない）
やること（代替ルート）：
1) “近似相関”に切り替える：time ±Δ + user_id + target + ip（重み付け）
2) IPがプロキシ/共有出口の可能性がある場合：端末/EDR、プロキシログ、CASBログを要求
3) actor が app/bot の場合：app_id/installation_id/secret更新履歴を辿る
4) 監査ログ欠落が疑われる場合：保持/有効化/エクスポート設定を確認し、別ソースへ拡張

成果物（最低限）：
- “断定できない理由”を境界として明記（相関キー欠落、IP共有、保持不足）
- 追加で必要なログ源（IdP/端末/ネットワーク/外部SIEM）と理由

---

### 実施方法（最高に具体的）：主要SaaS別の取得ルートと相関キー

#### A) Microsoft 365（Purview 監査ログ / Unified Audit Log）
目的：M365ワークロード（Exchange/SharePoint/OneDrive/Teams等）の操作・管理イベントを追う。

- UI（一次調査）：
  - Microsoft Purview（コンプライアンス）で Audit 検索（Search the audit log）
  - 期間、アクティビティ、ユーザ、IP等でフィルタし、イベント詳細を確認
- API（再現性/自動化）：
  - Office 365 Management Activity API で統一監査ログを取得（Common schema / record id 等）

相関で重要なフィールド例（Common schema観点）：
- Id（監査レコードID）
- CreationTime（UTC）
- Operation（操作名）
- UserId（主体）
- ClientIP（ただしサービス/条件で“利用者IPでない/NULL”があり得る）
- Workload / ObjectId / AppAccessContext（アプリ文脈）

~~~~
# 例：Office 365 Management Activity API（概念）
# 1) サブスクリプション開始 → 2) コンテンツ取得 → 3) スキーマに従い正規化して保存
# （実運用では、SIEM / ストレージへ転送し保持・検索性を担保）
~~~~

観測の判定：
- UserId が “app@” 等の場合、人の操作ではなくアプリ主体（権限境界の切替）を疑う
- ClientIP がプロキシ/信頼アプリのIPになり得るため、端末起点断定はIdP/端末ログと併用

---

#### B) Microsoft Entra ID（サインインログ / 監査ログ）
目的：認証の入口（成功/失敗/条件付きアクセス/リスク）と、ディレクトリ変更（ユーザ/グループ/ロール/アプリ）を追う。

- 取得経路：
  - Entra 管理センターのサインインログ/監査ログ（UI）
  - Azure Monitor / Log Analytics へ診断設定でエクスポート（SIEM相関の前提）
  - Microsoft Graph（監査ログAPI）で directoryAudits / sign-ins を取得（自動化）

相関の典型キー：
- user（UPN/objectId）
- app（client_id / service principal）
- ip / userAgent / deviceId
- requestId / correlationId（ある場合）
- conditionalAccessStatus / appliedPolicies（“例外パス”の検証）

判断：
- “条件付きアクセスが適用された/スキップされた/失敗した”は、入口の境界（認証経路の分岐）として扱う
- “管理操作（ロール付与/アプリ登録/同意）”は永続化・横展開の起点

---

#### C) Okta（System Log）
目的：OktaをIdPとして使う環境で、認証/ポリシー/管理操作/連携を追う。

- 取得経路：
  - Okta Admin Console（System Log）
  - System Log API（自動取得、SIEM連携）

相関で重要な観測点：
- actor（user / admin / app）
- eventType（何が起きたか）
- outcome（成功/失敗）
- client（ip / userAgent）
- debugContext / transaction / request（Oktaが提供する相関情報）

~~~~
# 例：Okta System Log API（概念）
# 期間とフィルタ（actor, eventType, outcome, ip など）で収集し、eventId をキーに保全する
~~~~

---

#### D) Google Workspace（Admin audit / Reports API / BigQuery export）
目的：Google Workspaceでの管理操作・認証関連・データ操作を追う。

- 取得経路（代表）：
  - Admin Console の監査ログ（カテゴリ別）
  - Reports API（Activities）で自動抽出
  - BigQuery へのログエクスポート（長期保管・横断分析）

相関の観測点：
- actor（admin/user）
- event name / parameters（操作と対象）
- ip / device / application（ログ種別により差）
- export された行の eventId（提供される場合）と ingest_time（BigQuery）

判断：
- BigQuery まで流せるなら “保持/横断検索”の境界を越えられる（調査可能性が上がる）
- UIのみで保持も短い場合、調査は期間に強く制約される（調査不能境界を明示）

---

#### E) GitHub（Organization audit log）
目的：Org権限・リポジトリ操作・認証・トークン・設定変更を追う。

- 取得経路：
  - Organization audit log（UI）
  - Audit log API（再現性ある抽出）

相関の観測点：
- actor（誰が）
- action（何を）
- repo/org（どこに）
- ip / user agent（可能な範囲）
- event id（監査ID）

判断：
- PAT / GitHub App / Actions 由来の操作は actor が “app” 側に寄るため、Appインストール/権限/秘密情報更新履歴と束ねて追う

---

#### F) Slack（Audit Logs）
目的：ワークスペース/Orgの管理操作、ユーザ・アプリ・設定変更、データ操作の兆候を追う。

- 取得経路：
  - Slack Audit Logs API（Enterprise Grid等、利用可否はプラン/権限に依存）

相関の観測点：
- actor（user/app）
- action（event type）
- entity（target）
- context（ip, user agent など提供される範囲）
- event_id（監査ID）

判断：
- Bot/App の操作が増えるほど、人起点の追跡には “インストール/トークン発行/権限変更”ログが要になる

---

#### G) Atlassian（Organization audit logs / export）
目的：Atlassian組織（Jira/Confluence等）での管理操作・認証・権限変更を追う。

- 取得経路：
  - Atlassian organization の audit log（UI）
  - CSVエクスポート（提供される場合）

相関の観測点：
- actor / action / target
- ip（提供される範囲）
- exportファイルの行IDや時刻（UTC化して扱う）

---

### 相関の“実務テンプレ”（どのSaaSでも共通で使う）
1) UTCへ正規化（event_time）
2) 主体（actor）を正規化（user_id / app_id / actor_type）
3) 対象（target）を正規化（resource_id / type）
4) 起点キーを決める（user_id or ip or app_id）
5) 近傍時刻でイベントを束ね、操作列を作る
6) “権限が動くイベント”を別枠で抽出（ロール/グループ/同意/連携/秘密情報）
7) 欠落がある場合は境界として明記し、追加ログ源へ分岐

~~~~
# 例：相関イベントの正規化レコード（概念）
event_time_utc: 2025-12-23T09:12:34Z
source_system: "EntraID" | "M365Audit" | "Okta" | "GWS" | "GitHub" | "Slack" | "Atlassian"
event_id: "..."            # そのSaaSの監査レコードID
actor_type: "user" | "admin" | "app" | "service_principal"
actor_id: "user@domain" | "0000-...-0000" | "appId"
action: "SignIn" | "Add member" | "Grant admin consent" | ...
outcome: "success" | "failure"
target_type: "group" | "app" | "repo" | "channel" | ...
target_id: "..."
ip: "x.x.x.x" | null
user_agent: "..." | null
correlation_id: "..." | null
request_id: "..." | null
notes: "IP is proxy egress" 等
~~~~

---

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回）
- ASVS：
  - V7.2：認証・認可の意思決定がログに残り、調査に必要なメタデータが揃う（ただし機微情報を残さない）
  - V7.3：ログの保護（改ざん/削除/閲覧制御）と時刻同期（UTC運用の強さ）
- WSTG：
  - WSTG-CONF-02（ログアクセス制御/ログレビューの観点）：ログ閲覧UI/APIのアクセス制御、分離統制、監視/レビュー運用が成立しているか
- PTES：
  - Reporting：抽出条件・証跡ID・時系列・相関キーを“再現可能”に残す
  - Post-Exploitation：横展開/永続化に繋がる権限イベントを“起点固定”できる形で整理
- MITRE ATT&CK：
  - Discovery：アカウント/権限/資産の探索イベントが残るか
  - Credential Access：認証失敗/トークン/アプリ同意の兆候が追えるか
  - Lateral Movement / Persistence：ロール付与、連携追加、アプリ作成、設定変更が監査できるか
  - Defense Evasion：監査ログ設定や収集経路の変更が“監査ログに残る/外部保全される”かが境界

---

## 参考（必要最小限）
- Microsoft Purview：監査ログ検索（Search the audit log）  
  https://learn.microsoft.com/en-us/purview/audit-search
- Office 365 Management Activity API schema（Unified Audit Logの共通スキーマ）  
  https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema
- Microsoft Graph：Microsoft Entra 監査ログAPI（auditLogs）  
  https://learn.microsoft.com/en-us/graph/api/resources/security-auditlogroot?view=graph-rest-1.0
- Microsoft Entra：診断設定/ログエクスポート（例：Log Analytics 連携の考え方）  
  https://learn.microsoft.com/en-us/entra/id-protection/howto-export-risk-data
- Okta：System Log API  
  https://developer.okta.com/docs/reference/api/system-log/
- Google Workspace：Reports API（Audit / Activities）  
  https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities
- Google Workspace：ログの BigQuery エクスポート（概要/最新情報）  
  https://workspaceupdates.googleblog.com/2024/07/expanding-log-exports-to-bigquery.html
- GitHub：Organization audit log API（REST）  
  https://docs.github.com/en/rest/orgs/orgs?apiVersion=2022-11-28#get-the-audit-log-for-an-organization
- Slack：Audit Logs API  
  https://api.slack.com/admins/audit-logs
- Atlassian：Organization audit logs（Admin）  
  https://support.atlassian.com/organization-administration/docs/view-audit-logs/
- Atlassian：audit log CSV export  
  https://support.atlassian.com/organization-administration/docs/export-your-audit-log-to-a-csv-file/
- OWASP ASVS（V7 Logging）  
  https://wiki.owasp.org/images/d/d4/OWASP_Application_Security_Verification_Standard_4.0-en.pdf
- OWASP WSTG（WSTG-CONF-02：ログアクセス制御/ログレビュー）  
  https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration
