## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS
  - SaaSの「外部連携」は、アプリ本体の脆弱性というより **認証・認可・秘密情報・監査**の設計問題として現れる。評価対象は (1) 連携の入口（トークン/同意/署名）、(2) 権限境界（誰の権限で何へ到達できるか）、(3) 失効/棚卸し、(4) 監査ログ（追跡可能性）。
- WSTG
  - WSTGの観点は「SaaS機能に対する同等の観測」として当てる。例：認証（トークン種別・更新・失効）、認可（ユーザ権限とAPI到達性の一致）、セッション/トークン管理、ログ/監査の有無。
- PTES
  - 位置づけ：Intelligence Gathering（連携の棚卸し）→ Threat Modeling（境界と権限伝播）→ Vulnerability Analysis（過剰権限・失効不備・監査欠落）→ Post-Exploitation（横展開・永続化が可能かの条件分解）→ Reporting（運用改善とガードレール提案）。
- MITRE ATT&CK
  - 代表戦術：Discovery / Credential Access / Lateral Movement / Persistence / Defense Evasion
  - 代表技術（例）：Valid Accounts、Steal Application Access Token、Trusted Relationship（SaaS連携の信頼関係悪用）、Account Manipulation（権限/同意/アプリの追加）

---

# Atlassian（Jira/Confluence/Bitbucket等）外部連携と権限境界

---

## 目的（この技術で到達する状態）
- Atlassian Cloud（Jira/Confluence/Bitbucket など）における外部連携を、次の観点で **「境界としてモデル化」** し、診断・運用改善へ落とせる。
  1) 連携の種類（APIトークン / OAuth 2.0(3LO) / Marketplace Apps(Forge/Connect) / Webhook/Automation / IdP/SCIM）を分類できる  
  2) 「誰の権限で」「どのデータ境界を跨いで」「どの操作が可能か」を説明できる（権限伝播の言語化）  
  3) 失効・棚卸し・監査（追跡可能性）まで含めて優先度と次の一手を決められる  
  4) 攻撃者視点（横展開・永続化・データ持ち出し）を、具体的な成立条件として分解できる

---

## 前提（対象・範囲・想定）
- 対象：Atlassian Cloud（組織・サイト・製品（Jira/Confluence等））における外部連携全般
- 想定ロール：
  - 組織管理者（Organization admin）またはサイト/製品管理者（Site admin / Product admin）が得られると、観測の解像度が上がる
  - 一般ユーザ権限のみの場合でも「ユーザ同意のOAuth（3LO）」や「個人APIトークン運用」など、境界の漏れ筋は観測できる
- スコープ境界の定義（本ファイルの統一語彙）
  - 資産境界：どのサイト/製品/スペース/プロジェクトまでが対象か
  - 信頼境界：Atlassian外（外部アプリ/外部IdP/外部ストレージ/外部CI等）との接続点
  - 権限境界：管理者→製品管理→プロジェクト/スペース→オブジェクト単位で、権限が切り替わる地点
- 注意：本ファイルは「不正アクセス手順」ではなく、**正当な診断/運用設計のための観測と判断**を目的とする（契約・VDP・社内規程に従う）

---

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) 連携の“型”を先に確定する（同じ「外部連携」でも境界が全く違う）
Atlassianで現場に出る外部連携は、概ね次の型に収束する。

- 型A：APIトークン（Basic auth相当）
  - 個人ユーザの API token（スクリプト/手動ツールが典型）
  - サービスアカウントの API token（運用連携の典型：期限・スコープが設定されるケースが増える）
  - 観測する境界：トークンの寿命、スコープ、発行主体（個人/サービス）、失効手段、外部ユーザ制御、監査ログ

- 型B：OAuth 2.0（3LO：ユーザ同意）
  - ユーザが同意画面でスコープを許可し、アクセストークンでAPIへ到達する
  - 観測する境界：要求スコープ、同意の主体（誰が同意できるか）、トークン寿命/更新、テナント紐付け、stateなどCSRF系防御の有無（アプリ側）

- 型C：Marketplace/カスタムアプリ（Forge / Connect）
  - “アプリがアドオンとしてサイトにインストール”され、製品データへ到達する
  - 観測する境界：アプリの権限（スコープ/許可）、どのデータが対象か、ブロック/許可（Data security policy）、Webhook/Lifecycleの署名検証、インストール秘密情報の保護

- 型D：Webhook / Automation（外部へ出る・外部から入る）
  - Jira Automationの外部送信、Webリクエスト、Incoming webhook 等
  - 観測する境界：送信先（信頼境界）、署名/相互認証、再送/リトライ、秘密情報の露出、どの権限で実行されるか（オーナー/ルール実行ユーザ）

- 型E：IdP/プロビジョニング（SAML SSO / SCIM / ユーザ管理）
  - Atlassian Guard（旧Access系）の領域：SSO強制、ユーザ/グループ同期
  - 観測する境界：ローカルログイン残存、例外パス（外部ユーザ・ブレークグラス）、監査ログ

結論：
- まず「型」を確定しないと、観測すべきログ・設定・成立条件がズレて薄くなる。

---

### 2) “権限伝播”の最小モデル（誰の権限がどこへ届くか）
外部連携を権限境界として捉えると、評価軸は次の3つに収束する。

1) 主体（Principal）
- ユーザ（人）
- サービスアカウント（運用主体）
- アプリ（Forge/Connect/3LOアプリ）
- 自動化ルール（Automation rule identity）

2) 資格情報（Credential / Token）
- API token（個人/サービス）
- OAuth access token / refresh token（3LO）
- Connect JWT / インストールシークレット（Connect）
- Webhook署名（HMAC等）や相互TLS等（外部連携側）

3) 到達点（Resource boundary）
- 組織/サイト（admin.atlassian.comの管理領域）
- 製品（Jira/Confluence等）
- スペース/プロジェクト
- オブジェクト（Issue/Page/Attachment等）

観測で作るべき“最低限の表”
- 行：連携（アプリ/トークン/ルール/連携先）
- 列：主体 / 資格情報 / スコープ / 到達点（サイト→製品→プロジェクト/スペース）/ 可能操作（R/W/Admin）/ 監査ログ / 失効手段

---

### 3) UIでの観測（実務で迷わない「見る場所」）
#### 3.1 組織側（admin.atlassian.com）
- セキュリティ/データ保護系
  - Data security policies：Marketplace/カスタムアプリのブロック/許可（App access rules）
  - 外部ユーザの API token access 制御（外部ユーザにAPIトークンでのアクセスを許可するか）
- 監査ログ
  - 組織監査ログ（Audit log）：管理操作、アプリ、場所/IP、実行主体、対象（サイト/ユーザ）を観測

#### 3.2 製品側（Jira/Confluenceの管理）
- Jira/Confluence管理 → Apps / Manage apps：インストール済みアプリ一覧、権限要求、設定
- グローバル権限 / プロジェクト権限 / スペース権限：アプリが“どの境界まで影響を持つか”の裏付け

#### 3.3 開発者コンソール（developer.atlassian.com）
- OAuth 2.0(3LO) の設定：リダイレクトURI、スコープ、クライアント設定
- どのアプリがどのスコープを要求し、誰が同意する設計か（同意画面の文言はスコープ依存）

---

### 4) プロトコル/データ面の観測（HTTP/APIで「到達性」を固める）
「この権限で、実際にどこまで見えるか」を固めるには、最小限のAPI呼び出しで良い。

- API token（Basic auth相当）での到達性（Jira例）
~~~~
# ユーザ(メール) + API token で、どこまで読めるかを“差分”で確認する（例）
# 例のために書式のみ。実値は環境に合わせる。
curl -sS -u "user@example.com:${API_TOKEN}" \
  "https://<your-domain>.atlassian.net/rest/api/3/myself"

# 重要：次は「見えてはいけない対象（別プロジェクト等）」が 403 になることを確認する
curl -sS -u "user@example.com:${API_TOKEN}" \
  "https://<your-domain>.atlassian.net/rest/api/3/project/<KEY>"
~~~~

- OAuth 2.0(3LO) の境界は「スコープ」と「同意主体」で決まる
  - スコープが広いほど、同意さえ取れれば到達性が広がる
  - 同意後に発行される access token は期限がある（運用上は refresh token の扱いが支配的）

- Connect/Forge は「アプリがサーバとして信頼される」ため、アプリ自体が強い到達性を持ちうる
  - 特に Connect は JWT（qsh等）で“改ざんされていないリクエスト”を担保する設計で、Webhook/Lifecycle/iframeの境界が分かれる

---

## 結果の意味（その出力が示す状態：何が言える/言えない）
観測結果は、単なる設定一覧ではなく「状態」として言語化する。

### 状態1：個人APIトークン依存の連携が多い
- 言えること
  - 連携の主体が “人” に寄り、退職・異動・権限変更で破綻しやすい
  - トークンが漏えいした場合、当人の権限で横展開する（権限境界が個人アカウントに吸収される）
- 言えないこと
  - それが直ちに脆弱性とは限らない（寿命・IP制御・監査・保管方法でリスクが上下）

### 状態2：サービスアカウントのAPIトークンが長寿命・広スコープ
- 言えること
  - “運用連携”の名で高権限が固定化され、漏えい時の被害半径が最大化しやすい
  - 失効・棚卸し・監査ができないと「永続化」になる
- 言えないこと
  - そのサービスが不要かどうかは業務要件次第（代替経路の提案が必要）

### 状態3：3LOアプリの同意がユーザ任せ（ガードレール無し）
- 言えること
  - ユーザが不用意に広スコープへ同意できると、SaaSの信頼境界が“ユーザの判断”に委ねられる
  - 外部アプリ側の侵害・設定ミスが、Atlassianデータへ波及しうる
- 言えないこと
  - Atlassian側だけで完全に防げるとは限らない（同意フローはアプリ実装や運用統制が関与）

### 状態4：Marketplaceアプリのアクセス制御（ブロック/許可）が効かない例外がある
- 言えること
  - “ブロックしたつもり”でも到達できるアプリ種別があると、信頼境界の制御点が崩れる
  - 許可リスト運用は「例外の把握」が必須になる
- 言えないこと
  - 例外＝即危険ではない（用途・データ範囲・監査・代替統制で評価）

### 状態5：監査ログが取れていない / 追跡粒度が足りない
- 言えること
  - 侵害の有無判断、範囲特定、恒久対策の効果測定ができない
  - “誰が・いつ・何を・どのアプリで” が残らないと、連携は実質的にブラックボックスになる

---

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
※ここは「やり方」ではなく「攻撃者が狙う状態＝優先度」を明確にする。

### 優先度が上がる状態（＝攻撃価値が高い）
1) 広範囲スコープのトークン（特に運用主体/サービスアカウント）  
2) ユーザ同意で広スコープが成立し、組織として抑止できない（同意のガードレール不在）  
3) Marketplaceアプリが多く、データ到達範囲が整理されていない（アプリ棚卸し不在）  
4) Webhook/Automation が外部へデータを出す（送信先が“第三者境界”）  
5) 監査ログで追えない（侵害の検知/証跡が弱い）

### 代表的な“狙い”の分解（成立条件ベース）
- Discovery：どのプロジェクト/スペース/ユーザに到達できるか（API/アプリ）
- Credential Access：トークン/シークレットの露出（CIログ、設定画面、第三者アプリ側侵害）
- Lateral Movement：Atlassian→他SaaS/CI/CD/チケット運用を経由して横展開（Trusted Relationship）
- Persistence：アプリ追加、同意済みトークン維持、Automationルール維持、サービスアカウントの固定化
- Defense Evasion：監査ログ無効化/欠落、例外パス（ブレークグラス・外部ユーザ制御の不備）

---

## 次に試すこと（仮説A/Bの分岐と検証）
### 入口：最小の棚卸し（30〜60分で“地図”を作る）
- (1) インストール済みアプリ一覧（Forge/Connect/その他）をエクスポート/記録
- (2) API token の運用主体（個人/サービス）と用途を列挙
- (3) 監査ログが見えるか・何日分あるか・アプリ/管理操作が追えるかを確認
- (4) Data security policy（アプリブロック/許可）の有無と例外（効かないアプリ種別）を確認

#### 仮説A：連携が「個人APIトークン」中心
- 検証（観測→意味→次の手）
  - 観測：どのシステムがどの個人トークンで動くか、退職/権限変更時の手順があるか
  - 意味：トークン漏えい＝当人権限の“持ち運び”、棚卸し不備＝実質的な永続化
  - 次の一手：サービスアカウント化＋期限＋スコープ最小化＋失効手順＋監査（誰が使ったか）

#### 仮説B：サービスアカウントはあるが「長寿命・広スコープ」
- 検証
  - 観測：期限、スコープ、保管場所（CI変数/Secrets Manager等）、利用元IP/実行環境
  - 意味：漏えい時の半径が最大。検知が弱いと“気づけない永続化”になる
  - 次の一手：短命化（期限/ローテ）、最小スコープ、実行元制限、監査ログ相関（CIログと接続）

#### 仮説C：3LO（ユーザ同意）アプリが多い／同意制御が弱い
- 検証
  - 観測：要求スコープ、同意主体（誰が同意できるか）、同意の棚卸しと撤回手順
  - 意味：ユーザ判断が境界になる。フィッシング/誤同意のリスクが上がる
  - 次の一手：同意ポリシー・許可リスト、監査（同意イベント）と教育、過剰スコープの排除

#### 仮説D：Marketplaceアプリが多く「ブロック/許可」統制が未整備
- 検証
  - 観測：Data security policy の有無、ブロック対象外の例外、アプリごとのデータ到達範囲
  - 意味：“第三者境界”が拡大し、事故/侵害時の影響範囲が読めない
  - 次の一手：許可リスト化（必要最小限）、例外アプリの代替検討、アプリの監査ログ/契約レビュー

#### 仮説E：Webhook/Automation が外部へデータを送っている
- 検証
  - 観測：送信先、送信データ（PII/添付/URL）、署名検証の有無、リトライ/再送
  - 意味：データの信頼境界が外部へ出る。受信側の改ざん・なりすましが成立しうる
  - 次の一手：署名/相互認証、送信データ最小化、送信先ドメイン制限、監査ログ相関

---

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回）
- ASVS（例）
  - V2（認証）：トークン種別、失効、MFA/SSO強制、サービスアカウント運用
  - V3/V4（セッション/アクセス制御）：権限境界（プロジェクト/スペース/オブジェクト）、APIの到達性一致
  - V14（設定）：外部連携の許可/ブロック、例外パス、監査ログ、秘密情報管理
- WSTG（例）
  - WSTG-ATHN：トークン/同意の成立点、期限、撤回
  - WSTG-ATHZ：APIでの到達性がUI権限と一致するか（403/404の差分）
  - WSTG-SESS：トークン更新/失効、再利用（漏えい時の半径）
  - WSTG-CONF / WSTG-INFO：監査ログ、設定露出、エラーからの情報漏えい（SaaSでも同等に評価）
- PTES
  - Intelligence Gathering：アプリ/トークン/連携先の棚卸し
  - Threat Modeling：主体×資格情報×到達点の権限伝播モデル化
  - Vulnerability Analysis：過剰権限、失効不備、例外パス、監査欠落
  - Post-Exploitation：横展開/永続化の成立条件（サービスアカウント固定化、同意維持）
  - Reporting：許可リスト、短命化、監査相関の提案
- MITRE ATT&CK（例）
  - Discovery：Cloud/SaaSのリソース列挙（プロジェクト/スペース/ユーザ）
  - Credential Access：トークン窃取（アプリトークン/サービスアカウント）
  - Lateral Movement：Trusted Relationship（SaaS連携経由の横展開）
  - Persistence：アプリ追加/同意維持/自動化ルール維持
  - Defense Evasion：監査ログ不備、例外パスの悪用

---

## 参考（必要最小限）
- Atlassian OAuth 2.0 (3LO) 実装（認可コードフロー・consent・state）  
  - https://developer.atlassian.com/cloud/oauth/getting-started/implementing-oauth-3lo/
- OAuth 2.0(3LO) / Forge のスコープ（例：Assetsだが“同意画面＝スコープ”の読み替えに使える）  
  - https://developer.atlassian.com/cloud/assets/assets-rest-api-guide/scopes-for-oauth-2-3LO-and-forge-apps/
- Connect Apps のセキュリティ（JWT、インストールシークレット、Lifecycleの検証など）  
  - https://developer.atlassian.com/cloud/forms/security/security-for-connect-apps/
- Connect JWT（qsh等のクレーム理解）  
  - https://developer.atlassian.com/cloud/jira/platform/understanding-jwt-for-connect-apps/
- Jira Cloud：Basic auth は API token 前提（REST到達性がUI権限と同等である点の確認に使う）  
  - https://developer.atlassian.com/cloud/jira/platform/basic-auth-for-rest-apis/
- Basic auth（パスワード等）廃止・API token / OAuth / Connect への誘導（方針の根拠）  
  - https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-basic-auth-and-cookie-based-auth/
- サービスアカウントのAPI token（期限・スコープ設定）  
  - https://support.atlassian.com/user-management/docs/manage-api-tokens-for-service-accounts/
- 監査ログ（組織監査ログの見方：actor/app/IP等）  
  - https://support.atlassian.com/security-and-access-policies/docs/view-audit-log-activities/
- Marketplace/カスタムアプリのブロック（Data security policy / App access rules）  
  - https://support.atlassian.com/security-and-access-policies/docs/block-app-access/
- App access rule の例外（ブロックできないアプリ種別がある、という境界の根拠）  
  - https://support.atlassian.com/security-and-access-policies/docs/apps-that-cannot-be-blocked-by-app-access-rules/
- API token access の概念（外部ユーザ制御の観点）  
  - https://support.atlassian.com/security-and-access-policies/docs/what-is-api-token-access/

---

## 自リポジトリ内リンク（地続き）
- 01_topics/04_saas/01_idp_連携（SAML OIDC OAuth）と信頼境界.md
- 01_topics/04_saas/02_saas_共有・外部連携・監査ログの勘所.md
- 02_playbooks/14_saas_oauth_同意→横展開→永続化の導線.md（作成時に相互参照）
