# Okta サインオンポリシーとトークン境界

ガイドライン対応（先頭要約）：
- ASVS：認証強度（MFA/段階的認証）、セッション管理（有効期限/失効/継続ログイン）、トークン取り扱い（Refresh/再利用検知）、監査ログ
- WSTG：認証/セッションの観測（MFAの要求点、セッション固定・継続、トークン/セッションの失効）
- PTES：Intelligence Gathering→Threat Modeling→Vulnerability Analysis（IdP設定・ポリシー・ログから成立条件を分解）
- MITRE ATT&CK：Valid Accounts（T1078）、Web Session Cookie（T1550.004）/Steal Web Session Cookie（T1539）等の前提（“強い認証”がどこで効いているかを境界として確認）

---

## 目的（この技術で到達する状態）
Okta（IdP）における「サインオン（=セッション確立・再認証要求）」と「トークン（OIDC/OAuth）」を、運用・攻撃の両面で **境界として分解**し、次を“自分で回せる”状態にする。

- サインオン（Global Session Policy / App Sign-in Policy）の **適用順序・停止条件・例外パス** を説明できる
- セッション（Oktaセッション）とトークン（Access/ID/Refresh）が **同じものではない** ことを前提に、どこで切り替わるか（権限境界/信頼境界）を説明できる
- 「MFAを入れているのに突破される」系の事故が、だいたい **どの境界の欠落** で起きるかを、観測→解釈→次の一手で詰められる
- 監査ログ（System Log）で、ポリシー評価・セッション開始・再認証要求・トークン更新を **相関**できる

---

## 前提（対象・範囲・想定）
- 対象
  - Okta（Identity Engine / Classic Engine のどちらか）
  - Okta管理下のアプリ（SAML/OIDC/OAuth、Okta管理アプリ、カスタムアプリ、API Service App 等）
- 範囲
  - 許可された環境（自社テナント、ラボ、契約範囲）での **設定レビュー / 観測 / 安全な検証** を想定
  - “侵入手順”ではなく、**成立条件・境界の確認** を中心に扱う
- 用語（このファイル内での使い分け）
  - グローバルセッション：Oktaの「全体セッション」を制御（セッションの最大寿命/アイドル、永続Cookie 等）
  - アプリサインイン：アプリごとの再認証要求・認証強度（例：高リスクアプリだけMFA強化）
  - トークン：OIDC/OAuth（Access/ID/Refresh）。セッションと寿命や失効条件がズレることがある

---

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) “どのポリシーが効いたか”を観測する（ポリシー境界）
- 観測対象
  - Global Session Policy（旧称：Okta sign-on policy）
  - App Sign-in Policy（旧称：App sign-on policy / アプリレベルの認証ポリシー）
- 観測で欲しい状態
  - 「どの条件（ネットワークゾーン/リスク/デバイス/ユーザー属性/グループ）で、どのルールがマッチしたか」
  - 「ルール評価は優先度順で止まる」＝上位ルールの“例外”が下位の強いルールを無効化していないか

### 2) “セッションがどう確立・継続したか”を観測する（セッション境界）
- ブラウザ観測（利用者側）
  - OktaドメインのCookie（例：sid 等）の有無、Expires/Max-Age、SameSite、Domain/Path
  - “Stay signed in” と永続Cookieの関係（管理側で永続Cookieを許可しているか）
  - Idle Timeout / Max Lifetime に到達したときの挙動（強制再認証か、静的リダイレクトか）
- 管理者観測（Okta側）
  - セッション開始（user.session.start 等）
  - ポリシー評価（policy.evaluate.sign_on 等）
  - MFAチャレンジ/成功イベント（factor検証、認証ステップの進行）

### 3) “トークンがどこで発行/更新/失効したか”を観測する（トークン境界）
- 観測対象（OIDC/OAuth）
  - Authorization Code / PKCE / Device Code 等のフロー
  - Token Endpoint での交換（Access/ID/Refresh）
  - Refresh による再発行（回転しているか、長寿命か、取り消しが効くか）
- データ観測
  - JWTなら exp/iat/aud/iss/scp（スコープ）/cid（クライアント）など
  - Opaqueなら introspection の可否と結果
- 重要な境界
  - “セッションが切れてもトークンが使える/更新できる”設計が存在し得る
  - “アプリに到達できる”ことと“トークンが更新できる”ことは別（IdP・AS・RSの信頼境界）

### 4) “例外パス”を観測する（運用・移行・例外の境界）
- Identity Engine / Classic Engine混在
  - 同じ「サインオン」に見えても、評価パイプラインが異なり、MFA要求点がズレる
- API Service App / 直接トークン発行
  - 人間のサインオン（Global Session）を経由しない到達点がある
- 共有ポリシーの副作用
  - “共有App Sign-in Policy”を複数アプリに適用すると、1個の変更が多アプリに波及する

---

## 結果の意味（その出力が示す状態：何が言える/言えない）
### A. Global Session Policy を観測して言えること
- 言えること（状態）
  - Okta全体のセッションが「最大寿命」「アイドル」「永続Cookie許可」などで、どの程度“継続”できるか
  - ルールは **優先度順に評価され、最初に一致したルールで止まる**（=例外ルールの影響が強い）
  - “グローバルはセッションの有効性、アプリは再認証頻度”という役割分担になっている（設計意図）
- 言えないこと（限界）
  - それだけで「特定アプリに入るときに必ずMFAが要求される」とは限らない（アプリ側ポリシーが別）

### B. App Sign-in Policy を観測して言えること
- 言えること（状態）
  - アプリ単位で「追加の認証（強いAuthenticator要求）」「再認証頻度」を制御できているか
  - 1アプリに付けられるポリシーは基本的に1つで、共有ポリシーを複数アプリに割り当てる構造がある
- 言えないこと（限界）
  - “アプリポリシーが強い”だけでは、Oktaセッション自体が無制限に継続して良いとはならない（グローバルが別）

### C. トークン観測で言えること
- 言えること（状態）
  - Access Token の寿命が短いか/長いか、Refresh Token が回転しているか、どのクライアント/スコープで発行されているか
  - “トークンが資産（API/データ）に到達するための鍵”として、失効・回収・再利用検知が設計されているか
- 言えないこと（限界）
  - トークンが短寿命でも、Refresh が長寿命で保護が弱いと“実質長寿命”になる（設計全体で評価が必要）

---

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
ここでは「攻撃者がどう使うか」を、**防御側・診断側が意思決定に使える形**へ落とす。

### 1) 最優先で狙われる“境界の薄いところ”
- “例外ルール（除外ユーザー/除外ネットワーク/除外条件）”が上位にある
  - 典型：運用都合（VIP/特定拠点/レガシーアプリ）で例外を置き、強いルールが下位に落ちる
- “グローバルは弱い/アプリで強化”設計なのに、アプリ側が未保護
  - 典型：新規アプリが共有デフォルトポリシーのまま、強化されていない
- “トークンが長生きする” or “Refreshが回転しない/失効が弱い”
  - 典型：端末やブラウザに残り続ける（端末紛失・マルウェア・ログ漏えいで致命傷）

### 2) 攻撃者は何を“再利用”するか（セッション/トークンの違い）
- セッション再利用（WebセッションCookie）
  - MFAを踏まずにWeb到達できる状態が生まれる（端末・ブラウザ・Cookieの境界）
- トークン再利用（Access/Refresh）
  - API到達、バックグラウンドでの継続アクセス、アプリ外の自動化が可能になる（AS/RS境界）
- したがって診断では「Web到達」だけでなく「API到達」「更新（Refresh）」「失効」の4点セットで見る

### 3) 次の仮説（優先度付けに直結）
- 仮説H（High）：強い認証が“アプリ到達点”で効いていない（=アプリポリシー漏れ）
- 仮説M（Medium）：強い認証は効いているが、セッション継続（永続Cookie/長寿命）が強すぎる
- 仮説H（High）：Refresh Tokenが長寿命かつ回転/再利用検知が弱い（=持ち出し耐性が低い）
- 仮説M：監査ログが取れない/相関できない（=侵害時に気づけない）

---

## 次に試すこと（仮説A/Bの分岐と検証）
※「操作手順の丸写し」ではなく、**診断で迷わない分岐（A/B）**に落とす。  
※コマンドやツールは“例”に留め、観測→解釈を主にする。

### 0) 最初に“エンジン差”を確定する（前提分岐）
- 仮説A：Identity Engine（Global Session Policy / App Sign-in Policy を併用評価）
- 仮説B：Classic Engine（名称や評価点が異なる、AuthNパイプライン差が出る）

確認（例）：
- 管理画面のポリシー名称（Global Session Policy / App Sign-in Policies 表記）
- Okta公式の該当ガイドに従い、同じ概念でも呼び名が違うことを前提に読む

### 1) Global Session Policy の“停止条件”を検証する（セッション境界）
狙い：例外ルールが“強いルール”を無効化していないか、セッション継続が過剰でないか。

- 仮説A：上位ルールに “Allow + MFA緩い” があり、実質的に強制MFAが回避される経路がある
  - 検証観測：
    - ルール優先順位
    - 条件（ネットワークゾーン、リスク、デバイス条件、除外ユーザー/グループ）
    - “Everyone”相当のキャッチオールが上位で止めていないか
- 仮説B：ルールは適切だが、セッション寿命が長すぎ、再認証がほぼ発生しない
  - 検証観測：
    - Maximum session lifetime / idle time の値
    - 永続Cookie許可（usePersistentCookie）と “Stay signed in” の組み合わせ
    - ブラウザ再起動後もセッションが復活するか（永続化の境界）

（安全な実施例：ブラウザプロファイルを分けて、Cookie削除/新規デバイス扱い/別IP扱いの差分だけを見る）

### 2) App Sign-in Policy の“未保護アプリ”を潰す（アプリ境界）
狙い：「グローバルで緩め、アプリで強化」の設計は“漏れ”が致命傷になりやすい。

- 仮説A：共有デフォルトポリシーのままのアプリが存在する（強度が不足）
  - 検証観測：
    - どのアプリがどのポリシーに割り当てられているか
    - 共有ポリシー変更が他アプリに波及していないか（意図しない緩和）
- 仮説B：アプリは強いが、条件が緩い（例：特定グループだけ強化、残りが抜ける）
  - 検証観測：
    - グループ条件の網羅性（“対象外”ができていないか）
    - 管理者/特権アプリの“除外ユーザー”が広すぎないか

### 3) トークン境界を“寿命・更新・失効・再利用検知”で分解する
狙い：Accessが短くてもRefreshが長いと、実質“長期継続”になる。

- 仮説A：Refresh Token が回転している（盗用検知が成立する前提がある）
  - 検証観測：
    - Refreshで新しいRefreshが返る（回転）設計か
    - 再利用（reuse）時の検知/失効/ログがあるか
- 仮説B：Refresh Token が固定で長寿命、取り消しが弱い（持ち出し耐性が低い）
  - 検証観測：
    - Refreshの寿命（ポリシー/AS設定）
    - 失効操作（ユーザー無効化、セッション終了、アプリのトークン取り消し）がどこまで効くか
- 仮説C：API Service App がサインオンを経由せずに権限を得ている（人間のMFAとは別世界）
  - 検証観測：
    - 該当クライアントの発行方式（Client Credentials等）
    - 監査ログに “誰がどのクライアントで何のスコープを得たか” が残るか

（JWTの中身を見る例：）
~~~~
# Access TokenがJWTの場合（例）
# 1) ヘッダ/ペイロードをデコードし、exp/iat/aud/iss/scp/cid を確認
# 2) “どの資産（aud）に効くか” と “いつ切れるか（exp）” を境界としてメモする
~~~~

### 4) ログ相関で“効いた境界”を証拠化する（監査境界）
狙い：設定レビューだけだと「実際に効いたか」が抜けやすい。ログで確定させる。

- 仮説A：ポリシー評価がSystem Logで追える（policy.evaluate.sign_on 等）
  - 観測：
    - DebugContext / DebugData に評価情報（ネットワーク/振る舞い/リスク）が含まれるか
- 仮説B：ログはあるが相関できない（session context が分断）
  - 観測：
    - user.session.start と policy評価 と MFAイベントを同一のコンテキストで追えるか
    - 追えない場合は “収集不足” が境界欠落（検知不能）になっている

---

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回）
- ASVS
  - 認証（MFA/Authenticator要求、ステップアップ、例外パス管理）
  - セッション管理（アイドル/最大寿命、ログアウト、失効、継続ログイン設計）
  - トークン/クレデンシャル管理（Refreshの回転・再利用検知、保管・取り消し、クライアント種別ごとの境界）
  - 監査ログ（重要イベントの記録、相関可能性）
- WSTG
  - 認証テスト：MFAの要求点が“本当に”重要到達点で発火するか（アプリ別に差が出る）
  - セッション管理テスト：セッション継続、ログアウト/失効、Cookie属性・持続性の観測
  - （SaaS前提の接続）IdP設定不備はアプリ実装の外側で起きるため、WSTG項目は“観測と検証の翻訳”として使う
- PTES
  - Intelligence Gathering：IdP/アプリ連携方式、ポリシー構成、ログ取得性の把握
  - Threat Modeling：例外パス（特権・拠点・レガシー・APIクライアント）を攻撃面としてモデル化
  - Vulnerability Analysis：未保護アプリ、過剰なセッション継続、トークン寿命/更新/失効の弱点を仮説検証
  - Reporting：境界（どこで強制され、どこで抜けるか）で再現性のある指摘に落とす
- MITRE ATT&CK
  - Valid Accounts（T1078）：認証が破られた前提で、どの到達点が守られている/いないか
  - Web Session Cookie（T1550.004）：セッション再利用の前提として、永続Cookie/長寿命が効いてしまう境界
  - Steal Web Session Cookie（T1539）：端末側のCookie奪取が成功した場合に、MFAや再認証がどこで効くか
  - （SaaS共通）トークン悪用は“認証の外側”で継続し得るため、失効・再利用検知・ログ相関が重要になる

---

## 参考（必要最小限）
- Okta Developer: Configure a global session policy and app sign-in policies
  - https://developer.okta.com/docs/guides/configure-signon-policy/main/
- Okta Help (Identity Engine): Add a global session policy rule（ルール評価の優先順、永続Cookie、グローバルとアプリの役割）
  - https://help.okta.com/oie/en-us/content/topics/identity-engine/policies/add-okta-sign-on-policy-rule.htm
- Okta Help (Identity Engine): Okta policies and rules（ポリシー種別と役割の整理）
  - https://help.okta.com/oie/en-us/content/topics/identity-engine/policies/about-policies.htm
- Okta Developer: Understand the token lifecycle（Access/ID/Refreshの基本と取り扱い）
  - https://developer.okta.com/docs/concepts/token-lifecycles/
- Okta Help (Classic Engine): Behavior Detection System Log events（policy評価・セッション文脈のログ観測）
  - https://help.okta.com/en-us/content/topics/security/behavior-detection/logs-behavior-detection.htm
- MITRE ATT&CK: Valid Accounts（T1078）
  - https://attack.mitre.org/techniques/T1078/
- MITRE ATT&CK: Detect Use of Stolen Web Session Cookies（Web Session Cookie | T1550.004）
  - https://attack.mitre.org/detectionstrategies/DET0074/
- MITRE ATT&CK: Detection of Web Session Cookie Theft（Steal Web Session Cookie | T1539）
  - https://attack.mitre.org/detectionstrategies/DET0509/
