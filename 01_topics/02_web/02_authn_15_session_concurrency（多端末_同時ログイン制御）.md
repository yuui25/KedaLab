## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - この技術で満たす/破れる点：セッションの一意性/管理（多端末・多ブラウザ）、セッション失効（logout/全端末logout）、リスクベース制御（新規端末/異常IP）、Remember-me/Refresh Tokenの長期セッション管理、監査ログ（セッション作成/失効/並行数）
  - 支える前提：「ログインできること」ではなく「どれだけのセッションが同時に生きるか」を制御できないと、漏洩後の被害抑止（containment）が効かない
- WSTG：
  - 該当テスト観点：Session Management（Session Timeout / Session Invalidation / Concurrent Sessions / Remember Me）
  - どの観測に対応するか：同一ユーザの同時セッション数、端末識別、セッション一覧表示、失効API、異常検知/通知を観測して成立条件を切る
- PTES：
  - 該当フェーズ：Vulnerability Analysis（長期セッション・残存の欠陥、運用境界）、Post-Exploitation（侵害後の持続性/遮断の容易さを評価）
  - 前後フェーズとの繋がり（1行）：14 logout（終了）と 17 refresh rotation（長期トークン）を結合して「終わらない/増え続けるセッション」が残るかを確定し、16 step-up（重要操作）で境界を締める
- MITRE ATT&CK：
  - 戦術：Persistence / Defense Evasion
  - 目的：追加セッションを作って残す、長期トークンで居座る、ユーザのログアウトでは遮断されない状態を作る（※手順ではなく成立条件の判断）

## タイトル
session_concurrency（多端末_同時ログイン制御）

## 目的（この技術で到達する状態）
- “同時ログイン制御” を「最大セッション数の制限」だけでなく、端末識別・セッション一覧・失効・通知・監査まで含めた“遮断設計”として整理できる
- セッション（cookie）と長期トークン（refresh/remember-me/device token）を統一モデルで扱い、どれが「増える」「残る」「切れない」かを観測で確定できる
- 侵害を想定した実務判断（漏洩時にユーザ/運用がどう遮断できるか、どのログが必要か）を、HTTP観測＋サーバ/IdPログで説明できる
- 後続（16 step-up、17 rotation、18 token binding、19 passkeys）へ、「再認証境界」「トークン束縛」「盗用検知」の入力を渡せる

## 前提（対象・範囲・想定）
- 対象：
  - RPセッション：ブラウザcookie（セッションID）/サーバセッション
  - 長期資産：refresh token、remember-me、device token（モバイル含む）
  - 管理面：セッション管理画面（devices/sessions）、全端末ログアウト、端末名/最終利用
  - SSO環境：IdPセッションと、RP側のセッション/トークンの二重管理（責任分界）
- 想定する境界：
  - 多端末（PC/スマホ）、多ブラウザ、同一端末のプロファイル違い
  - NAT/モバイル回線/VPNでIPが揺れる（IPのみで端末識別できない）
  - SPA/ネイティブアプリで refresh token を前提にする
- 安全な範囲（最小検証の基本方針）：
  - テストアカウントで、少数の端末/ブラウザを使い分けて“同時性と失効”を観測する
  - “漏洩を模した行為（盗用）” はしない。あくまで設計欠陥（遮断不能/残存）を観測で確定する
  - 重要操作の検証（16）や盗用検知（17）は別ファイルへ分離し、ここでは“同時性/失効/可視化”に集中する

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) 同時ログイン制御を「3つの設計ゴール」に分解する
- ゴールA：増やさない（制限）
  - 最大同時セッション数（例：無制限/5台/1台）
  - 新規ログイン時に古いセッションをどう扱うか（自動失効/拒否/ユーザ選択）
- ゴールB：見える（可視化）
  - ユーザが “どの端末がログイン中か” を確認できる（端末名/場所/最終利用/作成時刻）
  - 運用側が “誰が何セッション持つか” を監査できる（セッションIDではなく主体軸）
- ゴールC：切れる（遮断）
  - 現在端末のlogoutだけでなく “全端末ログアウト” ができる
  - 盗用が疑われる場合、refresh/remember-me等も含めて確実に無効化できる

※ペネトレでは、ゴールC（切れる）が欠落すると被害が長期化するため優先度が上がる。

### 2) 「セッション」を構成要素に分解する（cookieだけ見ない）
- 典型構成要素
  - ブラウザセッションcookie（短命/更新あり）
  - リフレッシュトークン（長命、回転する場合あり：17と接続）
  - デバイス識別子（device_id、trusted_device cookie、mobile device token）
  - サーバ側セッションレコード（user_id、device_id、issued_at、last_seen、ip/ua、revoked）
- 観測で確定したい点
  - “同時性のカウント単位” が何か（cookie単位/refresh単位/device単位）
  - 同一ユーザが複数端末でログインした時に、サーバにセッションレコードが増えるか
  - “最後に使った端末だけ生きる” のか、“全て生き続ける” のか

### 3) 端末識別（device binding）の強度：見える/切れるの前提
- 端末識別が弱いと起きること
  - セッション一覧が役に立たない（全部「Unknown device」）
  - revokeが粗くなる（全端末logoutしかできない、誤遮断）
  - 盗用検知（17）の入力が不足する
- 観測焦点（深掘り）
  - device_id の発行タイミング（初回ログイン時/初回アクセス時）
  - device_id の保存場所（cookie/localStorage/Keychain等）
  - device_id の再生成条件（cookie削除、ブラウザ変更、アプリ再インストール）
  - “信頼済み端末（remember this device）” の有無と、信頼の寿命/解除方法

### 4) セッション一覧UI/API（可視化）の観測：存在するだけでなく整合性を見る
- 観測対象
  - /settings/devices, /sessions, /security/sessions 等
  - 一覧API（/api/sessions）
- 重要フィールド（最小）
  - session_id（内部用でもよいが参照キーが必要）
  - created_at / last_seen
  - ip / geo / user_agent（精度は問わないが、相関に使える）
  - device_name / device_id
  - auth_strength（MFA済み/step-up済み等が区別できると強い：16と接続）
  - token_type（web session / refresh / api token など）
- 整合性チェック
  - 新しい端末でログイン→一覧に増えるか
  - revoke→対象だけ消えるか（選択的失効の有無）
  - logout→一覧が更新されるか（14と整合）

### 5) 失効（revoke/invalidate）モデルの切り分け：どこを切れば本当に切れるか
- 失効の種類
  - “現在セッションのみ” のログアウト（cookie削除＋サーバ失効）
  - “特定端末のセッション失効”（device_idやsession_id指定）
  - “全端末ログアウト”（user_id配下の全セッション/全refresh無効化）
  - “パスワード変更で全失効”（侵害時の定石だが、実装が弱いと残る）
- 観測焦点
  - 失効APIがどのスコープで効くか（sessionだけ切ってrefreshが残る等）
  - 失効後に “静かに復活” しないか（refreshで再発行、remember-meで再ログイン）
  - 失効がIdPにも波及するか（SSO時の責任分界：14と接続）

### 6) 同時ログイン制御の「例外パス」：ここが最も破綻しやすい
- 典型例外パス
  - モバイルアプリだけ無制限（webと別基盤）
  - APIトークン（personal access token）が一覧/失効に入らない
  - “remember-me” が一覧に出ず、revokeできない
  - step-up済みセッションが別扱いで残る（16と接続）
  - SSOでRP logoutしてもIdPセッションが残り、再ログインで即復活（14と接続）
- 観測の作法
  - 「webで切れた＝全部切れた」と判断しない
  - 入口ごと（web/mobile/api/SSO）に、一覧表示と失効が一貫しているかを確認する

### 7) concurrency_key_control（後工程に渡す正規化キー）
- 推奨キー：concurrency_key_control
  - concurrency_key_control = <scope>(web|mobile|api|mixed) + <count_unit>(session|device|refresh|unknown) + <max_concurrent>(n|unlimited|unknown) + <revoke_granularity>(current|device|all|unknown) + <list_visibility>(yes/no/partial) + <exception_path>(none|present|unknown) + <confidence>
- 記録の最小フィールド（推奨）
  - scope（対象：web/mobile/api）
  - count_unit（カウント単位）
  - max_concurrent（制限値）
  - list_visibility（一覧の有無）
  - revoke_granularity（失効粒度）
  - password_change_effect（全失効するか）
  - sso_boundary（IdP/RPどこまで効くか）
  - evidence（HAR、一覧UIスクショ、ログ、設定断片）
  - action_priority（P0/P1/P2）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える（確定できる）：
  - 同時セッションが増える条件（端末/ブラウザ差、ログイン入口差）
  - 一覧可視化の有無と整合性（増える/消える/一致する）
  - 失効（revoke）がどの範囲に効くか（current/device/all）と、例外パスの有無
  - “パスワード変更で全失効” のような侵害時の遮断が成立するか（少数回の観測で兆候を取る）
- 推定（根拠付きで言える）：
  - 端末識別が弱い場合、盗用検知や選択的遮断が困難（17/18へ波及）
  - SSO境界が曖昧な場合、ユーザは切ったつもりでも復活しやすい（14へ波及）
- 言えない（この段階では断定しない）：
  - 実侵害後の横展開（盗用/複製）※ここでは成立条件の評価に留める

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- 優先度（P0/P1/P2）
  - P0：
    - セッション/refreshが一覧に出ず、個別失効も全失効も効かない（遮断不能）
    - logoutしてもrefreshやremember-meで即復活する（14/17と連鎖して“終わらない”）
    - パスワード変更でも既存セッションが残る（侵害時の標準手当が効かない）
  - P1：
    - 無制限同時セッションで、端末識別が弱く、盗用検知に必要な情報が欠落
    - webは制御できるがmobile/apiが例外パス（運用境界破綻）
  - P2：
    - 制御はあるがUX/運用副作用が大きい（誤遮断、端末名不明で管理不能）
- “成立条件”としての整理（技術者が次に何を直すべきか）
  - どの資産を失効させれば「本当に切れるか」（session vs refresh vs remember-me）
  - どのキーで端末を束ねるべきか（device_id設計）
  - どの面を一覧/失効に統合すべきか（例外パス潰し）

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：同時セッションが無制限で、遮断が弱い
  - 次の検証（少数端末で十分）：
    - ブラウザA/B（別プロファイル）＋モバイル（可能なら）でログインし、一覧が増えるか/識別できるかを確認
    - “全端末ログアウト” がある場合、実行後に各端末で保護リソースへ到達できないことを確認
  - 判断：
    - 切れない/復活する：P0（失効の範囲と長期トークンの扱いが破綻）
    - 切れるが見えない：P1（可視化不足、監査/ユーザ防御の欠落）
- 仮説B：一覧/失効はあるが例外パスがある（mobile/api/remember-me）
  - 次の検証：
    - webで失効→mobileが残る、またはその逆が起きないかを確認
    - remember-meが一覧に出るか、revokeで消えるかを確認（存在する場合）
  - 判断：
    - 例外あり：P1〜P0（統合が必要）
- 仮説C：SSO境界で復活する（IdPセッション残存）
  - 次の検証：
    - RP全端末logout後に、IdP側セッションが残り即復帰するか（14と同じ観測）
    - IdPログアウト/セッション終了との整合（SLO有無）を証跡化
  - 判断：
    - 復活：P1（要件次第で重大。説明/導線/設計が必要）
- 仮説D：パスワード変更で全失効しない
  - 次の検証：
    - パスワード変更後、別端末の既存セッションが生きていないかを確認（少数回）
    - refresh token が無効化されるか（17へ接続）
  - 判断：
    - 残る：P0（侵害対応の基本が破綻）

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/` ）：
  - `04_labs/02_web/02_authn/15_session_concurrency/`
    - 構成案：
      - RP：セッションcookie＋refresh token（回転ON/OFF切替）＋remember-me（任意）
      - 端末：ブラウザ2種（プロファイル分離）＋モバイル（任意）
      - セッション一覧UI/API：/sessions を実装し、revoke（device/all）を実装して挙動差を観測
      - 監査ログ：session_created/session_revoked/token_revoked を必ず出す
- 取得する証跡（深く探れる前提：HTTP＋周辺ログ）
  - HTTP：HAR（各端末ログイン、一覧取得、revoke実行、保護ページ再アクセス）
  - Cookie/Storage：session cookie、remember-me cookie、device_id cookie/localStorageの差分
  - アプリログ：セッションレコードの作成/失効、device_id紐付け、refresh無効化
  - 監査ログ：誰がいつどの端末を失効したか、全端末logout実行の記録
  - IdPログ（SSO時）：セッション終了、SLOイベント
- 観測の設計（誤差を減らす）
  - “端末差” を作るため、同一ブラウザでもプロファイルを分ける（cookie共有を避ける）
  - 失効後の確認は「保護リソース到達性」で統一（UI表示の揺れを避ける）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
# 例：セッション一覧と失効（擬似）
GET  /settings/sessions
POST /api/sessions/revoke         { session_id: "..." }   # 端末/セッション単位
POST /api/sessions/revoke_all     {}                      # 全端末

# 例：観測すること（擬似）
- revoke後に他端末の保護ページが 401/302 になるか
- refresh/remember-me が残って静かに復活しないか
- 一覧の last_seen が更新され、端末識別が機能しているか
~~~~
- この例で観測していること：
  - “見える/切れる” が成立しているか（同時性の管理として機能しているか）
- 出力のどこを見るか（注目点）：
  - 一覧の端末識別、revokeの応答、保護ページ到達性、token refreshの有無（Network）
- この例が使えないケース（前提が崩れるケース）：
  - 端末一覧が無く、セッション制御がサーバ内部のみ（→監査ログ/設定で代替証跡を取る）

## 参考（必要最小限）
- OWASP ASVS（セッション管理、失効、長期トークン）
- OWASP WSTG（Concurrent Sessions、Remember Me、Session Termination）
- 侵害時対応の観点（全端末logout、パスワード変更での遮断、監査ログ）

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/02_authn_14_logout_設計（RP_IdP_フロントチャネル）.md`
- `01_topics/02_web/02_authn_16_step-up_再認証境界（重要操作_再確認）.md`
- `01_topics/02_web/02_authn_17_refresh_token_rotation_盗用検知（reuse）.md`
