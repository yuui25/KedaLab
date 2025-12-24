# Azure AD / Microsoft Entra 条件付きアクセス（CA）と例外パス

## ガイドライン対応（冒頭：要点）
- ASVS：V2（認証）/ V3（セッション）/ V4（アクセス制御）/ V14（設定）を、IdP側の「条件付き制御」「例外」「監査可能性」で支える
- WSTG：WSTG-ATHN（認証）/ WSTG-SESS（セッション）/ WSTG-CONF（設定）を、アプリではなく「IdP側で観測・強制されているか」を検証対象にする
- PTES：Intelligence Gathering → Threat Modeling → Vulnerability Analysis（設定監査）→（必要なら）Exploitation（許可された範囲の再現）→ Reporting
- MITRE ATT&CK：Valid Accounts を前提に「どこで追加条件（MFA/デバイス/場所/クライアント）を課すか・抜け道はどこか」を評価する（詳細は末尾）

---

## 目的（この技術で到達する状態）
- 「Microsoft Entra 条件付きアクセス（Conditional Access: CA）」が、対象ユーザ/アプリ/条件に対して“意図通りに”強制されている状態を、**観測（ログ）で説明できる**ようになる。
- “CAがあるから安全”ではなく、**例外パス（適用されない・回避される・守れていない経路）を列挙し、優先度付きで潰す**判断ができるようになる。
- 監査・ペンテスト実務として、次をセットで回せるようにする：
  - ポリシー設計（含む/除外、条件、制御）
  - 影響評価（Report-only / What If）
  - 実測（Sign-in logs の CA タブ）
  - 例外パスの棚卸し（レガシー、ブートストラップ、サービスアカウント、ワークロードID 等）

## 前提（対象・範囲・想定）
- 対象は **Microsoft Entra ID（旧 Azure AD）** の Conditional Access（ユーザ対象 + 必要に応じて Workload identities 対象）。
- 実務でよくある “境界” を前提にする：
  - 資産境界：テナント（Tenant）/ 対象サブスクリプション / 対象クラウドアプリ（例：M365, Azure, 企業SaaS）
  - 信頼境界：外部IdP連携、B2Bゲスト、第三者SaaS、ネットワーク（社内/社外・Named location）
  - 権限境界：ユーザ（一般/特権）・デバイス（準拠/非準拠）・クライアント（モダン/レガシー）・トークン（発行/継続/失効）
- 本ファイルは「手を動かす」前提だが、**不正利用を目的とした回避手順の提供はしない**。検証は必ず許可されたテナント・テストアカウントで行う。

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) CAポリシーの“適用スコープ”が境界そのもの
- Assignments（Users or workload identities）
  - Include：誰に当てるか（All users / 特権ロール / グループ）
  - Exclude：誰を外すか（緊急用アカウント、運用アカウント、例外グループ）
- Target resources（Resources / Cloud apps）
  - Include：何に当てるか（All resources / 特定アプリ）
  - ユーザアクション/認証コンテキスト（Authentication context）を使う場合は “重要操作境界” を形成
- Conditions（条件は「どの入口を塞ぐか」を定義）
  - Locations（Named location / 国 / IP レンジ）
  - Client apps（Browser / Mobile apps and desktop clients / Exchange ActiveSync / Other clients＝レガシー）
  - Device platform / Device state / Filter for devices（Intune準拠やデバイスフィルタ）
  - Risk（User risk / Sign-in risk / 〔Workload〕Service principal risk）
- Access controls
  - Grant：Block / Require MFA / Require compliant device / Require approved client app / Authentication strength / Terms of use 等
  - Session：Sign-in frequency / Persistent browser / App enforced restrictions など（“セッション継続境界”）

### 2) “観測の主役”は Sign-in logs の Conditional Access タブ
- 1回のサインインで **複数のCAポリシーが評価**されうる（＝単一ポリシーの確認で終わらせない）。
- 各サインインイベントで最低限見る：
  - Conditional Access policies（適用/不適用/Report-only結果）
  - 結果（Success / Failure / Not Applied / Report-only: *）
  - 失敗理由（ブロック理由、要求未達の制御）
  - Client app / 端末情報 / IP / Location / Resource（どの入口から来たか）
- “Not Applied” は「安全」ではなく、**適用されない理由**が重要（例：対象外、除外、ブートストラップ等）。

### 3) 影響評価の“二段構え”
- What If tool（シミュレーション）
  - 条件を入力して、該当ポリシーがどう評価されるかを事前確認
- Report-only（実測ベースの影響確認）
  - 本番ユーザ影響を出さずに、現実のサインインログで「本来ブロック/要求されるはず」を観測

### 4) 例外パスは「適用されない入口」か「要求できない入口」
例外パスを “型” で整理して観測する（後工程の潰し込みが楽になる）：
- 型A：ポリシーの除外（Exclude users/groups / Exclude locations / Exclude device platforms）
- 型B：レガシー認証（Other clients / Exchange ActiveSync）
- 型C：ブートストラップ（Circular dependency 回避で CA 評価されないシナリオ）
- 型D：非ユーザ主体（サービスプリンシパル / ワークロードID / マネージドID等の扱い差）
- 型E：資産側で迂回（アプリがEntra以外の認証入口を持つ、ローカルログイン残存 等）

## 結果の意味（その出力が示す状態：何が言える/言えない）
### 1) 「CAが効いている」の定義は “ログで説明できる” こと
- “ポータルにポリシーがある” は事実だが、**効いている証明ではない**。
- 効いている状態：
  - 対象のサインインで、意図したポリシーが Conditional Access タブに出現
  - 意図した条件（場所/端末/クライアント/リスク）が一致している
  - 意図した制御（Block/MFA/準拠端末/強度）が結果として反映されている

### 2) よく出る結果の読み方（状態として）
- Success：
  - そのサインインに対して、適用ポリシーの要求が満たされた
- Failure：
  - そのサインインに対して、ポリシー要求が満たせずブロック/失敗（“境界で止まった”）
- Not Applied：
  - 条件が一致しない、または除外、または評価対象外シナリオ
  - 重要：Not Applied の理由が “設計意図通り” か “抜け道” かで意味が逆になる
- Report-only:*：
  - 影響評価。実際にはブロック/要求しないが「もしOnならどうなるか」を示す

### 3) 複数ポリシー適用の意味
- サインインは「該当する複数ポリシーを同時に満たす」必要がある（実務上は **要求が積み上がる** と捉える）。
- 1つでも Block のポリシーが該当すれば、原則としてブロック（=最も強い制御が勝つ）。
- よって、設計レビューでは「個々のポリシー」ではなく **組み合わせで成立する最終境界** を作図できることが重要。

### 4) レガシー認証の意味（Other clients / EAS）
- レガシー認証は、MFAやデバイス状態を扱えず、CAの要求（MFA/準拠端末等）でブロックされやすい。
- しかし「レガシーを明示的に狙わないポリシー」だと、**ユーザは“ユーザ名+パスワードだけ”で通れる入口が残る**ため、例外パスになりやすい。
- 実務では「レガシー遮断ポリシー（Block legacy）」を別に作るのが基本。

### 5) Workload identities（サービスプリンシパル）に対する意味
- “ユーザ向けCA” はサービスプリンシパルのトークン要求を守らない。
- Workload identities へのCAは、別のスコープ（Users or workload identities）で、主に「場所/リスクによるブロック」に寄る（ユーザのMFAは使えないため）。
- ここが抜けると、ユーザを固めても **アプリ/自動化（SP）経路が穴** になり得る。

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
※ここでは、攻撃者が“何を狙うか”という意思決定を、守る側（監査/ペンテスト）で逆利用する観点として整理する。

### 1) 最優先は「例外パスの探索」
攻撃者は “強い制御を突破” より “制御が掛からない入口” を探す。よく狙われる順序：
- レガシー認証が残っている（Other clients / EAS）
- 除外ユーザ（緊急用/運用用）が存在し、その資格情報が狙える
- Named location / Trusted IP の誤設定（広すぎる許可、VPN/プロキシ前提の抜け）
- デバイス条件の穴（BYOD許可、準拠判定の抜け、プラットフォーム条件の扱い）
- 重要操作を認証コンテキストで守っていない（“ログインは強いが操作が弱い”）
- サービスプリンシパル/ワークロードIDが対象外（自動化・CI/CD・統合アプリが穴）

### 2) “設計意図と現実のズレ” を突く
- 「全ユーザMFA必須」でも、Client apps 条件が未設定/誤設定なら、レガシー入口が残る可能性がある。
- 「社内IPのみ許可」でも、Trusted IP の定義が現実より広い/第三者回線を含むなら意味が薄れる。
- 「準拠端末必須」でも、例外グループや特定アプリ除外が増えるほど、境界が崩れる。

### 3) 目的別の“攻め筋”に変換する（防御側の棚卸し）
- 目的：社外からの侵入 → Locations / Client apps / MFA の抜けを探す
- 目的：特権奪取 → 特権ロールに対する強度（phishing-resistant等）と緊急用除外の運用を探る
- 目的：横展開 → セッション制御（サインイン頻度/永続ブラウザ）とトークン失効境界を探る
- 目的：自動化/連携経由 → Workload identities のCAと監査ログの可視性を探る

## 次に試すこと（仮説A/Bの分岐と検証）
ここは「実務で回す順序」を固定し、毎回同じ手順で差分比較できるようにする。

### 0) 事前に用意する“検証素材”（最低限）
- テストユーザ（一般ユーザ1、特権相当1、例外候補1）
- テスト用のNamed location（許可IP/拒否IP を明確化）
- テスト用デバイス条件（準拠端末/非準拠端末のどちらかを作れる状態）
- 監査閲覧の権限（最低：Sign-in logs を読めるロール）

---

### 仮説A：CAが意図通り強制されている（＝例外が管理されている）
#### A-1. “観測で証明”する（Sign-in logs → CAタブ）
1) Microsoft Entra admin center  
   Entra ID → Monitoring & health → Sign-in logs  
2) 対象のサインインを選び、**Conditional Access タブ**を開く  
3) 以下をチェックし、1サインイン=1行でメモ化（後で比較する）
   - 適用されたポリシー名（複数あるか）
   - 結果（Success/Failure/Not applied/Report-only）
   - ブロック/要求の内容（MFA/準拠/強度/場所 等）
   - Client app / IP / Location / Resource
4) “意図した条件” を満たす/満たさないサインインを2パターン作り、差分で確認
   - 例：許可IP→Success、拒否IP→Failure（ブロック理由が場所由来であること）

#### A-2. What If tool で “設計と実測が一致” するか確認
- What If tool で「ユーザ/アプリ/条件」を入力し、評価結果を確認する。
- 注意：What If はサービス依存性を評価しない等の制約があるため、最終判断は実測ログで行う。

#### A-3. Report-only の評価運用が回っているか
- 新規/変更ポリシーがいきなり On ではなく、Report-only → 影響確認 → On の順になっているか。
- insights and reporting workbook を使って、特定ポリシーの影響（Success/Failure/Not applied）を時系列で見られる状態か。

---

### 仮説B：例外パスが残っている（＝“CAがあるのに抜ける入口”がある）
ここでは “例外パスの型” ごとに検証する。重要なのは「再現」ではなく「入口の存在を観測で証明」すること。

#### B-1. 型A（除外）: Exclude users/groups が “肥大化” していないか
1) 各ポリシーの Assignments を棚卸しし、Exclude の一覧を抽出する
2) 除外理由を分類する（緊急用/運用都合/業務要件/不明）
3) “不明” がある時点で優先度高（例外パスが説明できない）
4) 検証：除外ユーザのサインインログで、意図したポリシーが Not Applied になっていないかを確認

メモ用（差分管理）：
~~~~
- ポリシー名:
  Include:
  Exclude:
  対象アプリ:
  条件:
  要求/ブロック:
  例外理由（運用根拠）:
~~~~

#### B-2. 型B（レガシー）: Other clients / Exchange ActiveSync が遮断できているか
1) “レガシー遮断” ポリシーが存在するか（Block access）
2) 対象：All resources（または最低限 Exchange Online 等）になっているか
3) Conditions → Client apps が **Exchange ActiveSync / Other clients** を狙う設定になっているか
4) 除外：最低1アカウント除外（ロックアウト回避の運用）になっているか（ただし除外を増やしすぎない）
5) Sign-in logs で legacy の利用状況を確認し、「残っている業務要件」があるなら代替（モダン化）計画に繋げる

#### B-3. 型C（ブートストラップ）: Not Applied の “正当な理由” を分類できるか
- Sign-in logs で Not Applied が多い場合、それが
  - ただの条件不一致（設計通り）なのか
  - ブートストラップ（循環依存回避）なのか
を切り分ける。  
この切り分けができないと「守れていないのか/守るべきでないのか」が判断不能になる。

#### B-4. 型D（ワークロードID）: サービスプリンシパル経路が穴になっていないか
1) “ユーザ向けCA” の外側にある資産を列挙
   - Enterprise apps / App registrations（重要な連携、CI/CD、運用自動化）
2) Workload identities のCAが必要なものを選ぶ（特に高権限スコープのGraphアクセス等）
3) 条件はまず Locations（許可IP）で始め、Report-only で影響を観測
4) Service principal sign-ins のログで CA タブを見て、意図通りブロック/評価されているか確認

#### B-5. 型E（資産側迂回）: SaaS/アプリ側に “別入口” が残っていないか
- CAは “Entra で認証する入口” にしか掛からない。以下があると別境界になる：
  - アプリのローカルログイン/非常用ログイン
  - 旧IdPやBasic認証が残るAPI
  - 管理者用の別ドメイン/別テナント/別認証経路
- 監査では、SaaS側の認証方式一覧と、Entra側の対象アプリ一覧が一致するかを突き合わせる。

---

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回）
### ASVS
- V2 認証：IdP側での追加条件（MFA/認証強度/場所/リスク）を「認証境界」として実装・監査する
- V3 セッション：サインイン頻度、永続ブラウザ、継続評価（必要に応じて）を「セッション継続境界」として扱う
- V4 アクセス制御：認証コンテキスト等で“重要操作”に追加条件を要求し、権限境界の切替点を明確化する
- V14 設定：例外（Exclude）やレガシー許可を構成不備として扱い、監査ログで追跡できる状態にする

### WSTG
- WSTG-ATHN：SaaS/アプリの認証がEntraに寄っている場合、アプリ単体ではなくIdPで成立条件を検証する
- WSTG-SESS：再認証要求、長期セッション、永続セッション等がCAのSession controlsでどう表現されるか確認する
- WSTG-CONF：例外/レガシー/Named location/デバイス条件などの設定が、実測ログで裏取りできるかを確認する  
  （該当が薄い場合でも「この技術が支える前提＝認証境界の可視化」として接続する）

### PTES
- Intelligence Gathering：テナント構成・対象アプリ・運用アカウント・例外グループの把握
- Threat Modeling：攻撃者は例外パスを狙う前提で、抜け道（レガシー/除外/別入口）をモデル化
- Vulnerability Analysis：CAポリシー設計のレビューと、ログでの実測確認（Report-only/What If含む）
- Exploitation（許可された範囲のみ）：テストアカウントで条件差分（場所/クライアント/デバイス）を再現し、境界の実効性を確認
- Reporting：例外パスの型別に、影響・再現条件・是正方針（優先度）を提示

### MITRE ATT&CK
- TA0006 Credential Access：Valid Accounts 前提で、追加条件（MFA/強度/場所）を突破せずに“掛からない入口”を探す動機に接続
- TA0005 Defense Evasion：ポリシー対象外経路（レガシー/除外/別入口）を使うことが回避の本質になる
- TA0008 Lateral Movement：特権ロールのCA強度不足や例外運用が、横展開/権限拡大の前提になる
- TA0003 Persistence：サービスプリンシパル/連携アプリに対する制御欠落は永続化（長期アクセス）の前提になる

## 参考（必要最小限）
- Conditional Access で適用されたポリシーをサインインログで確認する（CAタブ）  
  https://learn.microsoft.com/en-us/entra/identity/monitoring-health/how-to-view-applied-conditional-access-policies
- サインインログの詳細（Conditional Access / Report-only / Not Applied の扱い）  
  https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-basic-info-sign-in-logs
- Report-only mode（評価結果の意味、見方）  
  https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/concept-conditional-access-report-only
- Conditional Access insights and reporting workbook（複数ポリシーの影響を可視化）  
  https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-insights-reporting
- What If tool（評価APIによるシミュレーション）  
  https://learn.microsoft.com/en-us/entra/identity/conditional-access/what-if-tool
- 条件（Client apps / Device platform 等）  
  https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/concept-conditional-access-conditions
- レガシー認証のブロック（Other clients / EAS を明示的に遮断）  
  https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/block-legacy-authentication
- 認証強度（Authentication strengths：カスタム強度含む）  
  https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strength-advanced-options
- Workload identities 向け Conditional Access（サービスプリンシパル対象、ログの見方）  
  https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity
- CA導入計画（緊急用アカウント除外等の設計質問を含む）  
  https://docs.azure.cn/en-us/entra/identity/conditional-access/plan-conditional-access
