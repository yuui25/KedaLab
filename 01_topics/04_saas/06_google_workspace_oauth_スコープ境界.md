# Google Workspace OAuth スコープ境界（最小権限・管理者制御・DWDの分岐）

## ガイドライン対応（冒頭サマリ）
- ASVS：V2（認証/セッション）, V4（アクセス制御）, V10（ログ/監査）, V14（設定/運用）を「OAuth同意・トークン・スコープ制御」の観点で適用
- WSTG：認証/認可の設計検証（SSO/OAuth連携）, 設定・運用の検証（第三者連携/ログ）を「スコープ=権限境界」として観測
- PTES：Intelligence Gathering→Threat Modeling→Vulnerability Analysis（SaaS設定/連携）→Post-Exploitation（トークン悪用/持続）へ接続
- MITRE ATT&CK：Credential Access / Discovery / Lateral Movement / Collection / Exfiltration を「OAuth同意とスコープ」で地続き化

## 目的（この技術で到達する状態）
Google Workspace における OAuth スコープを「権限境界」として扱い、次を“観測→解釈→意思決定”できる状態にする。
- どのアプリが、誰の Google データへ、どの範囲（スコープ）でアクセスできるかを説明できる
- 管理者の API Controls（Trusted/Limited/Blocked、サービス制限、スコープ制限、未設定アプリ方針）により「同意が成立する境界」を判断できる
- Domain-Wide Delegation（DWD）がある場合に「個人同意の境界」を飛び越える構造を説明できる
- 監査（Token audit）で “いつ/誰が/どのアプリに/どのAPI（スコープ相当）を許可・失効したか” を追跡し、対処（ブロック/失効/OU分離）へ繋げられる

## 前提（対象・範囲・想定）
- 対象：Google Workspace（管理対象アカウント）を利用する組織。Google APIs（Gmail/Drive/Calendar/Directory 等）に対する OAuth 2.0 アクセス
- 対象の“境界”：
  - 資産境界：Workspace 内のデータ（Gmail、Drive、Calendar、Directory 等）
  - 信頼境界：サードパーティ/社内アプリ（OAuth クライアント）・Marketplace アプリ・サービスアカウント
  - 権限境界：OAuth スコープ、Admin Console の API Controls（Trusted/Limited/Blocked/スコープ制限）、DWD（全社委任）
- 想定ロール：
  - ペンテスター：許可された範囲で設定・挙動・ログを確認し、成立条件を“状態”で示す
  - Blue/管理者：許可の最小化、監査、インシデント時の失効・封じ込めを実行
- 安全範囲：
  - 実運用での検証は「実データへ影響しない範囲（閲覧系/テストOU/テストアカウント）」を優先
  - “ユーザーに同意させる” 行為や不審アプリの作成・拡散は実環境では行わない（必要なら専用テナント/ラボで再現）

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) スコープそのもの（権限の粒度）
- スコープは「何のデータに」「どの操作で」アクセスするかを表す権限要求
  - 例：Gmail の読み取り/送信/設定変更、Drive の全ファイル/ユーザー選択ファイル、Directory（ユーザー/グループ）など
- 観測観点（粒度）：
  - read-only / modify / full-access（“読み”と“書き”の境界）
  - user-selected file（Drive の file スコープ系） vs 全Drive（drive）
  - 設定系（gmail.settings.*）は “持続化（転送/フィルタ）” に直結しやすい境界

### 2) 同意（Consent）の形態（誰が許可したか）
- ユーザー同意：当該ユーザーのデータに限定（ただしスコープが強ければ当該ユーザーの範囲で強い）
- 管理者同意/管理者制御：
  - API Controls により、特定アプリを Trusted/Limited/Blocked に設定可能（OU単位もあり得る）
  - 未設定アプリ（unconfigured）に対し「全面許可/Sign-inのみ/全面拒否」などのポリシーが境界になる
- Marketplace / ドメインインストール：ユーザー同意画面を迂回する導線があり得る（組織側のインストール設計が境界）

### 3) Domain-Wide Delegation（DWD）の有無（個人同意を越える境界）
- サービスアカウント（または OAuth クライアント）が、管理者によりドメイン全体の委任を受けると
  - “ユーザー個別の同意” ではなく “管理者の委任” が権限境界になる
  - 付与されたスコープの範囲で、対象ユーザーになりすまして API を呼べる（なりすまし先ユーザーが範囲）
- 観測ポイント：
  - Admin Console で DWD 登録の有無（Client ID と scopes のリスト）
  - スコープが Directory/Gmail/Drive など高権限領域に及んでいないか（最小化できているか）

### 4) 管理者の API Controls（許可/制限の“強制力”）
- 観測ポイント（Admin Console）：
  - Security → Access and data control → API controls
    - Manage Third-Party App Access（アプリ単位：Trusted/Limited/Blocked、OU適用）
    - Manage Google Services（サービス/高リスクスコープの制限）
    - Settings → Unconfigured third-party apps（未設定アプリの既定動作）
    - （提供状況により）スコープ単位での制限（特定 API scopes のみ許可）
- “結果の強制”として重要な状態：
  - サービスが Restricted だと、未信頼アプリは該当スコープを取得できない（既存トークンが失効される挙動がある）【https://support.google.com/a/answer/13152743】
  - 特定アプリを Trusted にすると、制限を上書きして通す（例外パス）【https://support.google.com/a/answer/13152743】

### 5) 監査ログ（誰が何を許可/失効したか）
- 観測ポイント：
  - OAuth Token audit log（Admin Console / Reports API）
    - authorize / revoke のイベント
    - app_name, client_id, api_name 等（どのAPIが使われたか）【https://developers.google.com/workspace/admin/reports/v1/appendix/activity/token】
- ここは「境界の事後検証」：同意の成立・解除が追えるかが重要【https://workspaceupdates.googleblog.com/2014/11/increased-visibility-and-control-with.html】

### 6) プロトコル/実通信の観測（ペンテスター視点）
- OAuth フロー観測（ブラウザ/ログ）：
  - authorization request（scope, client_id, redirect_uri, response_type, state, nonce/PKCE）
  - token exchange（access_token/refresh_token の発行条件）
- “観測してはいけないもの”：
  - 実運用のアクセストークン/リフレッシュトークンを無闇に収集・保管しない（証跡要件に従い最小化・マスキング）

## 結果の意味（その出力が示す状態：何が言える/言えない）
### 状態1：ユーザーは任意の第三者アプリに同意できる（未設定アプリが許可）
- 言えること：
  - “ユーザーの判断”がスコープ境界になる（= ソーシャルエンジニアリング耐性が支配的）
  - Shadow IT が発生しやすい（後追いの監査が生命線）
- 言えないこと：
  - 管理者が見えていない/止められない、とは限らない（Token audit や後続のブロックで抑止可能）

### 状態2：未設定アプリは Sign-in のみ許可（基本プロフィールのみ）
- 言えること：
  - OAuth を使った “データアクセス” は抑制できているが、「ログイン用途の乱立」は残る
  - ユーザーはサインイン可能でも、Gmail/Drive 等のスコープ取得は原則できない（設計次第）
- 次の論点：
  - “ログインだけ許可” が想定通りの境界になっているか（例外：Trusted アプリ、Marketplace インストール、DWD）

### 状態3：特定アプリが Trusted（例外パス）
- 言えること：
  - そのアプリは制限を上書きして、Restricted サービス/高リスクスコープに到達し得る【https://support.google.com/a/answer/13152743】
  - Trust は「運用上の例外」であり、最小化/レビュー/OU分離が必要
- 追加の意味：
  - “Trusted = 企業が責任を持つ” という意味になる。侵害時の影響範囲はスコープで決まる

### 状態4：サービス制限（Restricted）＋高リスクスコープ制限
- 言えること：
  - 典型的に Gmail/Drive の強スコープ（送信/読み取り/全Drive等）を未信頼アプリが取得できない【https://support.google.com/a/answer/13152743】
  - 既存トークンが失効される運用を取ると、封じ込めが速くなる（ただし業務影響も大）
- 言えないこと：
  - “全て安全” ではない（許可されたスコープ内でのデータ流出は残る）

### 状態5：Domain-Wide Delegation（DWD）あり
- 言えること：
  - 個別同意の境界を越え、管理者委任のスコープが“実質的な全社権限境界”になる【https://developers.google.com/workspace/classroom/guides/key-concepts/domain-wide-delegation】
  - 誤って広いスコープを付与すると、侵害時の横展開/収集が加速する
- 重要な解釈：
  - DWD は「少数の強権限クライアント」を作る。監査・鍵管理・OU適用・スコープ最小化が必須

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
※ここは“攻撃手順”ではなく「成立条件が揃った時に何が起こり得るか」を状態として整理する。

### 1) 収集（Collection）の最短化：メール/ドライブ
- Gmail/Drive の強スコープが取得可能な状態（未設定許可、Trusted 例外、DWD など）があると
  - “ユーザーの権限範囲”でメール・ファイルがAPIで収集可能になる
- 優先度判断：
  - 役職者（経理/人事/役員補佐など）のアカウントで、強スコープが成立すると影響が大

### 2) 持続（Persistence）に繋がるスコープ
- 設定系スコープ（例：Gmail settings）が許可されると、転送/フィルタ等の“継続的な観測”に繋がり得る
- したがって「読み取り」より「設定変更」が危険という判断軸が成立する

### 3) 横展開（Lateral）/特権領域への接続
- Directory（ユーザー/グループ）系スコープや、DWD による広範な委任があると
  - ユーザー・グループの構造把握（Discovery）が加速し、攻撃計画が立てやすくなる
- ただし “Workspace 管理者権限” そのものではない（境界はあくまでスコープ＋付与形態）

### 4) 同意を狙う社会的導線（Consent の境界が緩い場合）
- 未設定アプリ許可が広いと、ユーザー同意が“実質的な権限昇格点”になり得る
- 防御上の要点は「同意の前に止める（API Controls）」か「同意後に即検知（Token audit）」か

## 次に試すこと（仮説A/Bの分岐と検証）
以下は「診断で回す順序」を、分岐で固定化する。

### 仮説A：未設定アプリが広く許可されている（Consent が広い）
1) 現状把握（管理者/Blueと合意した範囲で）
- Admin Console：API controls の Settings → Unconfigured third-party apps の方針確認【https://support.google.com/a/answer/13152743】
- Accessed apps 一覧で “実際に使われているアプリ” を把握（ユーザー数/Requested services）【https://support.google.com/a/answer/13152743】

2) 影響が大きい順に“境界”を分類（判断）
- Gmail/Drive の高リスクスコープに到達しているアプリは最優先でレビュー（収集/持続の可能性が高い）
- Verified status（Googleの検証）と、社内の承認状況を突合【https://support.google.com/a/answer/13152743】【https://developers.google.com/identity/protocols/oauth2/production-readiness/google-workspace】

3) 次の一手（制御）
- 未承認アプリ：Blocked または Limited へ（OU分離が可能なら段階的に）【https://support.google.com/a/answer/13152743】
- 例外的に必要なアプリのみ Trusted（最小OU、期限付きレビュー前提）

### 仮説B：未設定アプリは Sign-in のみ/全面拒否（Consent が狭い）
1) 例外パス（Trusted/DWD/Marketplace）を先に疑う
- Trusted になっているアプリが実質的に “制限上書き” していないか【https://support.google.com/a/answer/13152743】
- DWD が存在しないか（Client ID と scopes）【https://developers.google.com/workspace/classroom/guides/key-concepts/domain-wide-delegation】

2) “サービス制限” の状態確認（Gmail/Drive）
- Manage Google Services で Restricted の有無、かつ高リスクスコープ制限の有無【https://support.google.com/a/answer/13152743】

3) 次の一手（監査で担保）
- Token audit を SIEM 等へ連携し、authorize/revoke を相関（アプリ名・client_id・api_name・ユーザー）【https://developers.google.com/workspace/admin/reports/v1/appendix/activity/token】
- “新規 authorize が発生したらレビュー” の運用（承認ワークフロー）を設計【https://support.google.com/a/answer/16484119】

### 仮説C：DWD が存在する（強権限クライアントがいる）
1) DWD の棚卸し（最優先）
- 管理者：Domain wide delegation の一覧（Client ID と scopes）をエクスポート/記録【https://developers.google.com/workspace/cloud-search/docs/guides/delegation】【https://developers.google.com/workspace/classroom/guides/key-concepts/domain-wide-delegation】

2) スコープ最小化の判断
- “なぜそのスコープが必要か” をアプリ機能要件に分解し、read-only/限定スコープへ寄せる
- Directory/Gmail/Drive の強スコープが混在していないか（横断的な収集が可能になるため）

3) 次の一手（鍵と運用）
- サービスアカウント鍵（もし存在する場合）の保管/ローテーション/利用監査を強化
- 監査ログ（Token audit だけでなく Admin/Drive/Gmail のログ）と相関して“なりすまし呼び出し”を追える形にする

### 仮説D：インシデント対応（不審アプリ/漏えい懸念がある）
- まず封じ込め：
  - 該当アプリを Blocked（または Trusted を外す）【https://support.google.com/a/answer/13152743】
  - 必要に応じて該当サービスを Restricted に寄せ、未信頼アプリのトークンを失効させる【https://support.google.com/a/answer/13152743】
- その上で事後追跡：
  - Token audit で authorize/revoke の時系列、対象ユーザー、api_name を抽出【https://developers.google.com/workspace/admin/reports/v1/appendix/activity/token】
  - 影響範囲（どのデータ領域にアクセスできたか）を、許可スコープから逆算して整理

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回）
- ASVS
  - V2（認証）：OAuth による外部アプリ連携を“認証の拡張”として扱い、同意・トークン失効・端末/セッション制御を運用要件に落とす
  - V4（アクセス制御）：スコープを「データアクセス権限」として最小化・例外管理（Trusted/DWD）を実装・運用で担保
  - V10（ログ/監査）：Token audit（authorize/revoke）を含む監査ログで追跡・検知・相関（ユーザー/アプリ/client_id/api）
  - V14（設定）：API Controls（未設定アプリ方針、サービス制限、アプリ許可）をセキュア設定基準として維持
- WSTG
  - 認証/連携：SSO/OAuth 同意フローの観測（要求スコープ、許可の成立条件、失効）
  - 設定/運用：第三者アプリ制御（allowlist/deny、Trusted例外）、ログ監査（Token audit）の検証
  - （関連が薄い場合の接続）Webアプリ単体の脆弱性ではなく「外部連携が認証・認可境界を広げる前提」を支える
- PTES
  - Intelligence Gathering：利用中アプリ・許可スコープ・DWD の棚卸し（境界の把握）
  - Threat Modeling：攻撃者目的（収集/持続/横展開）に対し、どのスコープが鍵かをモデル化
  - Vulnerability Analysis：API Controls の設定不備（未設定許可、Trusted過多、DWD過剰スコープ）
  - Post-Exploitation：トークン/許可が残る前提での持続・収集リスクを評価（対処は失効/制限/監査）
- MITRE ATT&CK
  - Credential Access：Token（認可情報）を起点としたアクセス（※トークン窃取自体の手順ではなく“成立時の影響”を評価）
  - Discovery：Directory/ユーザー情報の把握（許可スコープがある場合）
  - Collection：Gmail/Drive 等のデータ収集（スコープが成立する境界）
  - Persistence：設定系スコープがある場合の継続的アクセス（転送/フィルタ等の“状態”）
  - Exfiltration：API 経由での持ち出し（許可スコープと監査ログの相関で評価）

## 参考（必要最小限）
- Google Workspace Admin Help：Control which third-party & internal apps access Google Workspace data  
  https://support.google.com/a/answer/13152743
- Google Workspace Admin Help：Review & manage third-party app access requests  
  https://support.google.com/a/answer/16484119
- Google Developers：OAuth Token Audit Activity Events（Reports API / applicationName=token）  
  https://developers.google.com/workspace/admin/reports/v1/appendix/activity/token
- Google Developers：Additional considerations for Google Workspace（OAuth app verification/管理者制御の文脈）  
  https://developers.google.com/identity/protocols/oauth2/production-readiness/google-workspace
- Google Developers：Domain-wide delegation（概念と設定手順の例）  
  https://developers.google.com/workspace/classroom/guides/key-concepts/domain-wide-delegation
- Google Developers：Perform Google Workspace domain-wide delegation of authority（Admin console の導線例）  
  https://developers.google.com/workspace/cloud-search/docs/guides/delegation
- Google Workspace Developers：OAuth consent screen / scopes（Workspace 開発者向け）  
  https://developers.google.com/workspace/guides/configure-oauth-consent
- Google Workspace Updates：スコープ単位の制御（機能アップデート）  
  https://workspaceupdates.googleblog.com/2024/12/configure-third-party-apps-by-select-api-scopes-general-availability.html
- Google Workspace Updates：OAuth token audit reporting（authorize/revoke の監査）  
  https://workspaceupdates.googleblog.com/2014/11/increased-visibility-and-control-with.html
