## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - この技術で満たす/破れる点：Refresh Token の安全管理（回転・失効・最小権限スコープ）、盗用検知（reuse）と対応（全失効/再認証）、トークン保護（保管場所、バインディング）、ログアウト時のrevoke（14と接続）、同時セッション管理（15と接続）
  - 支える前提：アクセス・トークンが短命でも、refresh が漏洩すると長期の不正利用が成立し、ログアウト/パスワード変更でも遮断できない設計が起き得る
- WSTG：
  - 該当テスト観点：Session Management / Authentication Testing（Token-based auth、Refresh token handling、Logout/Revocation、Anomalous token use）
  - どの観測に対応するか：/token（refresh grant）、回転（refresh更新）、失効、reuse検知、例外パス（mobile/api）が一貫しているかを観測する
- PTES：
  - 該当フェーズ：Vulnerability Analysis（長期トークンの欠陥、遮断不能の発見）、Post-Exploitation（持続性評価：遮断のしやすさ）
  - 前後フェーズとの繋がり（1行）：14（logout）で“終わる”か、15（concurrency）で“切れる”か、16（step-up）で“重要操作を守る”かと結合し、侵害後の被害抑止の実効性を評価する
- MITRE ATT&CK：
  - 戦術：Persistence / Defense Evasion / Credential Access
  - 目的：refresh token を利用して継続アクセス、盗用が検知されない/遮断されない条件を作る（※手順ではなく成立条件の判断）

## タイトル
refresh_token_rotation_盗用検知（reuse）

## 目的（この技術で到達する状態）
- refresh token を「長期セッション資産」として扱い、回転（rotation）・失効（revocation）・盗用検知（reuse）の設計が閉じているかを証跡つきで評価できる
- “回転している” の定義を曖昧にせず、単回性・古いトークンの扱い・例外（並行リクエスト/ネットワーク遅延）まで含めて設計判断できる
- 盗用検知（reuse）発火時の対応（全失効/再認証/通知/監査）を、運用まで含めて具体化できる
- 後続（18 token binding（DPoP/mTLS）、19 passkeys、20 magic-link）へ、トークン盗用の耐性をどこで担保するかの入力を渡せる

## 前提（対象・範囲・想定）
- 対象：
  - OAuth2/OIDC の token endpoint（grant_type=refresh_token）
  - refresh token の保管場所（ブラウザ/モバイル/バックエンド）
  - ログアウト/全端末ログアウト/パスワード変更時のトークン失効（14/15と接続）
  - 監査ログ（token発行/回転/失敗/reuse検知）
- 想定する境界：
  - public client（SPA/モバイル）と confidential client（サーバ）で refresh の扱いが異なる
  - 複数デバイス/同時セッション（15）があると、refresh の“並行”が発生する
  - IdP（外部）を使う場合、RP側でrefreshを持たないこともある（責任分界が必要）
- 安全な範囲（最小検証の基本方針）：
  - 盗用（第三者利用）そのものを行わず、テストアカウントで “再利用の扱い” を少数回観測する
  - 回転の成立条件は、同一端末/同一セッション内の手順で確認し、過度な試行は避ける
  - 本番での検証は遮断（全失効）を誘発し得るため、許可と巻き戻しが前提

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) refresh rotation を「3要素」で定義する（“回っている”の誤解を潰す）
- 要素A：refresh token が更新される（new_refresh が発行される）
- 要素B：古い refresh token が無効化される（single-use）
- 要素C：古い refresh token の再利用（reuse）を検知し、適切な対応が走る（盗用検知）

Aだけ満たしてB/Cが無い場合、「実質回転していない」（複製・横展開に弱い）。

### 2) “単回性” のモデル：どの単位で single-use なのか
- 単位の例
  - グローバル単回：refreshは常に1回だけ使える（最も厳格）
  - デバイス単位：device_idごとにrefresh系列を持つ（多端末に現実的）
  - セッション単位：同一ログインセッションの範囲で単回（セッション境界が重要）
- 観測で確定したい点
  - refreshを使うたびに新refreshが返るか
  - 直前のrefreshが即座に無効化されるか（再利用の扱いで判断）
  - 並行リクエスト（同時にrefreshを投げた時）の挙動（“正当な競合”をどう扱うか）
    - 競合耐性の設計が無いと、正当ユーザが自滅（ログアウト）する

### 3) reuse検知（盗用検知）の“発火条件”を観測する
- reuse検知が意味すること
  - “古いrefreshが再び使われた”＝漏洩/複製の強い兆候
- 観測焦点（深掘り）
  - 再利用時の応答：401/invalid_grant、特定エラーコード、リトライ抑止（12と接続）
  - 発火時の副作用：
    - 現行refresh系列の全失効（token family revoke）
    - セッション強制終了（15/14と接続）
    - 再認証要求（16と接続）
    - 通知（本人へ）と監査ログ（相関キー付き）
- 重要：reuse検知だけあって “何も対応しない” と、検知しても被害抑止にならない

### 4) token family（系列）概念：どこまで巻き込んで失効するか
- 失効範囲の候補
  - 同一refreshのみ失効（弱い：盗用側が先に回転すると防げない）
  - 同一デバイス系列を全失効（現実的）
  - 同一ユーザ全失効（強いがUX影響大。侵害時には有効）
- 観測で確定したい点
  - reuse検知後に、他端末のrefreshが生きているか（15と結合）
  - パスワード変更/全端末logoutでrefreshが確実に死ぬか（14/15）

### 5) refresh の保管境界（どこに置くか）が盗用耐性を決める
- ブラウザ（SPA）の場合（設計上の難所）
  - localStorage等に置くとXSSで即漏洩（このプロジェクトではXSS自体は別ファイルだが、境界として明示）
  - BFF（Backend For Frontend）に寄せてブラウザにrefreshを持たせない設計が多い
- モバイルの場合
  - OS保護領域（Keychain/Keystore）に置く設計が一般的
  - device binding（18）と組み合わせやすい
- 観測焦点
  - refreshがブラウザに渡っているか（レスポンス/保存先の挙動）
  - refreshがcookieで付与される場合、HttpOnly/SameSite/Secure等（補助線）
  - “サーバだけがrefreshを保持する” 設計なら、盗用検知がログ中心になる（監査が必須）

### 6) 例外パス：mobile/api/SSOで回転が崩れる
- 典型例外
  - webは回転するが、mobileは固定refresh（長期）で運用
  - APIクライアント（PAT等）は別体系で失効できない
  - IdP側は回転しているが、RP側セッションが長期で遮断できない
- 観測の作法
  - 入口とクライアント種別（client_id）ごとに、回転/失効/reuseの挙動を比較する
  - 15と同様、「webだけ見て安全と判断しない」

### 7) rotation_key_posture（後工程に渡す正規化キー）
- 推奨キー：rotation_key_posture
  - rotation_key_posture = <client_type>(spa|mobile|server|mixed|unknown) + <rotation>(yes/no/unknown) + <single_use>(yes/no/unknown) + <reuse_detect>(yes/no/unknown) + <reuse_response>(revoke_family|revoke_token_only|none|unknown) + <family_scope>(device|user|unknown) + <logout_revoke>(yes/no/unknown) + <confidence>
- 記録の最小フィールド（推奨）
  - token_endpoint / grant_type
  - client_id（観測できる場合）
  - rotation_observed（new_refreshが返る）
  - old_refresh_behavior（invalidになる/まだ使える）
  - reuse_behavior（検知/副作用）
  - logout_effect（logout後にrefreshが使えるか）
  - evidence（HAR、ログ、設定断片）
  - action_priority（P0/P1/P2）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える（確定できる）：
  - refreshが回転しているか（A）、古いrefreshが無効化されるか（B）、reuseが検知され対応するか（C）
  - 失効範囲（tokenのみ/系列/ユーザ全体）の兆候（挙動とログから）
  - logout/全端末logout/パスワード変更とrefresh失効が整合しているか（14/15と接続）
  - client種別や入口で例外パスがあるか（web/mobile/api）
- 推定（根拠付きで言える）：
  - refreshがブラウザに露出している場合、XSS等で盗用される前提が強くなる（設計上の境界）
  - reuse検知が無い/弱い場合、長期不正利用の抑止が困難（侵害時の遮断が効きにくい）
- 言えない（この段階では断定しない）：
  - 実際の盗用経路（XSS/端末侵害等）※ここでは“盗用された場合にどうなるか”の耐性を見る

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- 優先度（P0/P1/P2）
  - P0：
    - refreshが固定（回転しない）かつ長寿命で、logout/パスワード変更でも失効しない兆候
    - 回転しても古いrefreshが使い回せる（single-useでない）
    - reuse検知が無く、再利用しても系列が生き続ける（盗用抑止なし）
  - P1：
    - 回転/単回性はあるが、例外パス（mobile/api）が固定refresh
    - reuse検知はあるが、対応が弱い（tokenのみ失効で系列が残る等）
    - 並行リクエストに弱く、正当ユーザが頻繁に切断される（運用/UX問題）
  - P2：
    - 設計は堅牢だが、監査/通知が薄い（侵害時の可視性が不足）
- “成立条件”としての整理（技術者が直すべき対象）
  - refreshを単回・短寿命化し、token family を定義して失効範囲を決める
  - reuse検知→自動遮断（少なくとも系列失効）→再認証（16）→通知/監査、までを閉じる
  - 入口/クライアントで例外パスを作らない（web/mobile/api統一）

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：回転していない（固定refresh）
  - 次の検証（少数回）：
    - refresh実行のたびに new_refresh が返るか（同一値が継続していないか）を観測
    - 一度refreshした後も、同じrefreshが再び通るか（単回性の欠落兆候）
  - 判断：
    - 固定/再利用可：P0
- 仮説B：回転はするが、単回性が弱い（古いrefreshがまだ使える）
  - 次の検証：
    - refresh→新refresh発行→直前refreshの再利用がどう扱われるかを観測（invalid_grant等）
  - 判断：
    - 旧refreshが通る：P0
    - 旧refreshが無効：次はreuse検知の副作用（仮説C）へ
- 仮説C：reuse検知はあるが、対応範囲が弱い/不明
  - 次の検証：
    - 再利用時に、現行refreshやセッションがどうなるか（全失効か、当該だけか）を観測
    - 全端末logout/パスワード変更後にrefreshが使えるか（遮断設計の整合）
  - 判断：
    - 系列/全体が残る：P1〜P0（対応範囲を強化）
    - 系列が無効化され、再認証になる：堅牢寄り
- 仮説D：例外パス（mobile/api/SSO）で回転が崩れる
  - 次の検証：
    - client_id別（web/mobile）に回転挙動を比較し、統一されているかを観測
  - 判断：
    - 例外あり：P1（場合によってはP0）

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/` ）：
  - `04_labs/02_web/02_authn/17_refresh_rotation_reuse/`
    - 構成案：
      - token endpoint（refresh grant）を実装し、回転ON/OFF、単回性ON/OFF、reuse検知ON/OFFを切替可能にする
      - device_id単位のtoken family（擬似）を持たせ、失効範囲（device/user）を切替できるようにする
      - 監査ログ：refresh_issued、refresh_rotated、refresh_reuse_detected、family_revoked、user_revoked を必ず出す
- 取得する証跡（深く探れる前提：HTTP＋周辺ログ）
  - HTTP：HAR（token endpoint、refresh連続、旧refresh再利用の挙動）
  - アプリログ：token family id、失効イベント、再認証要求
  - 監査ログ：reuse検知時刻、端末/UA/IP、対応アクション
  - 設定断片：refresh TTL、reuse対応範囲、logout時revokeの有無
- 観測の設計（誤判定を避ける）
  - 並行リクエストの影響（正当競合）を区別するため、連続実行と“ほぼ同時実行”を分けて観測し、設計意図と一致するかを見る
  - 検知が発火すると全失効になる設計の場合、検証はテストアカウントで最小回数に限定する

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
# 例：refresh grant（擬似）
POST /oauth/token
  grant_type=refresh_token
  refresh_token=RT_OLD
  client_id=...

# 観測すること（擬似）
- レスポンスに new_refresh が含まれるか（rotation）
- RT_OLD を再度使ったときに invalid_grant になるか（single-use）
- 再利用が検知された場合に、現行RTも含めて失効するか（family revoke）
~~~~
- この例で観測していること：
  - 回転（A）・単回性（B）・reuse検知と対応（C）が閉じているか
- 出力のどこを見るか（注目点）：
  - tokenレスポンス、エラーコード、以後のトークン利用可否、監査ログのイベント
- この例が使えないケース（前提が崩れるケース）：
  - refreshがブラウザに露出せず、サーバが保持する（→サーバログ/監査ログ中心で評価する）

## 参考（必要最小限）
- OWASP ASVS（トークン管理、失効、長期セッション、盗用検知）
- OWASP WSTG（Token-based auth、Logout/Revocation）
- OAuth 2.0 / OIDC（refresh token rotation と盗用検知（reuse）概念）

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/02_authn_14_logout_設計（RP_IdP_フロントチャネル）.md`
- `01_topics/02_web/02_authn_15_session_concurrency（多端末_同時ログイン制御）.md`
- `01_topics/02_web/02_authn_18_token_binding（DPoP_mTLS）観測.md`
