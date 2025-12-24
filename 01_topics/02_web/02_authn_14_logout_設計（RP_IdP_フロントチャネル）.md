## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - この技術で満たす/破れる点：セッション終了の完全性（サーバ側無効化、トークン失効）、ログアウトCSRF、SSO連携時の責任分界（RP/IdP）、フロントチャネル/バックチャネルでの状態整合、ログアウト後の再利用防止（キャッシュ/Remember-me/Refresh Token）
  - 支える前提：ログアウトは「認証状態の終了」を宣言する境界であり、設計が弱いと“ユーザの期待”と“実際の認証状態”が乖離する
- WSTG：
  - 該当テスト観点：Session Management / Authentication Testing（Logout Functionality / Session Termination / CSRF）
  - どの観測に対応するか：ログアウト要求、セッション破棄、トークン失効、SSOログアウト（SLO）、フロントチャネルでの多RP整合を観測する
- PTES：
  - 該当フェーズ：Vulnerability Analysis（状態遷移の欠陥、責任分界の穴）、Exploitation（許可範囲での最小検証）
  - 前後フェーズとの繋がり（1行）：13のstate設計、15の同時ログイン、17のrefresh rotationと結合し「終了できないセッション/トークン」が残るかを確定する
- MITRE ATT&CK：
  - 戦術：Persistence / Defense Evasion
  - 目的：ログアウト後も有効なセッション/トークンを残して継続利用、またはユーザ操作を妨害（ログアウト誘発）して再認証に誘導する（※手順ではなく成立条件の判断）

## タイトル
logout_設計（RP_IdP_フロントチャネル）

## 目的（この技術で到達する状態）
- ログアウトを「ブラウザ表示の退出」ではなく「認証状態（セッション/トークン/連携状態）の無効化」として分解し、何が“確実に終わる/終わらない”かを説明できる
- RP（アプリ）・IdP（SSO）・ブラウザ（フロントチャネル）の責任分界を明確化し、設計/設定/実装で直すべき箇所を特定できる
- ログアウトの例外パス（CSRF、キャッシュ、複数RP、端末多重、Refresh Token残存）を、HTTP観測＋周辺ログ（IdP/監査）で最小回数で切り分けられる
- 後続（15 concurrency、16 step-up、17 rotation、18 token binding、19 passkeys、20 magic-link）へ、ログアウト境界の“観測点”を渡せる

## 前提（対象・範囲・想定）
- 対象：以下の“終了”が絡む面をすべて対象にする
  - RPセッション（cookie/session id）
  - RPの長期トークン（remember-me、refresh token、device token）
  - IdPセッション（SSOセッション、IdP cookie）
  - SLO（Single Logout）または同等のログアウト連携
- 想定する境界：
  - RP単体（SSOなし）
  - RP + IdP（OIDC/SAML）でのログアウト（フロントチャネル/バックチャネル）
  - 複数RP（複数アプリが同一IdPにぶら下がる）
- 安全な範囲（最小検証の基本方針）：
  - テストアカウントで実施（ログアウト誘発は影響が軽いが、運用アカウントでは避ける）
  - “ログアウトできていない” を確定するために必要な最小リクエストのみ行う（保護リソースへの到達性で判断）
  - 破壊的操作ではないが、監査ログ・IdPログがある場合は必ず裏取りする

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) ログアウトを「3層」に分解する（どこが終わっていないかを特定する）
- 層A：ブラウザ状態（cookie/ストレージ/キャッシュ）
  - 観測焦点：Set-Cookieによる削除、localStorageのクリア、キャッシュ制御（戻るボタンで見える/見えない）
- 層B：RPサーバ側状態（セッション無効化、トークン失効）
  - 観測焦点：サーバがセッションIDを失効させるか（サーバセッション型）、JWT等の無効化設計（ブラックリスト/短命化/回転）
- 層C：IdP状態（SSOセッションの終了）
  - 観測焦点：RPログアウト後にIdPセッションが残り、再ログインが自動化されないか（“見かけ上ログアウトしたのに即ログイン復帰”）

この3層のうち、どれが要件か（ユーザ期待/セキュリティ要件）を明示するのが設計の肝。

### 2) ログアウト経路（入口）を列挙する：UIだけではなくAPI/連携を含む
- 代表入口（例）
  - UI：GET/POST /logout
  - API：POST /api/logout、/session/revoke
  - トークン失効：POST /oauth/revoke（IdPまたはRPのrevoke endpoint）
  - SLO：/saml/logout、/oidc/logout、frontchannel_logout_uri、backchannel_logout_uri（設定に依存）
- 観測の作法
  - “どの入口が正式か” を確定し、他入口が例外パスになっていないか（片方だけがセッション破棄する等）を見る
  - GETで副作用が起きる設計（ログアウトCSRFの温床）かどうかを記録する

### 3) ログアウトCSRF（強制ログアウト）を「許容/不許容」で整理する
- 強制ログアウトは、機密性より可用性/UXの問題になりやすいが、以下の副作用がある：
  - 再認証への誘導（フィッシング/偽ログイン画面と組み合わせやすい）
  - 重要操作の中断（業務妨害）
- 観測焦点（HTTPで確定しやすい）
  - ログアウトが GET で成立するか
  - CSRFトークン/Origin検証があるか
  - SameSite/Referer等の補助線が効いているか
- 設計判断の軸
  - “ログアウトCSRFは許容する” 場合でも、遷移や通知、再認証導線の安全性（13/20）とセットで扱う

### 4) SSO（OIDC/SAML）ログアウトの責任分界：RPだけ終わっても意味がない/逆もある
- 代表パターン
  - パターンA：RPログアウトのみ（IdPセッションは残る）
    - 結果：再ログインが即時に成立し、ユーザが「ログアウトできない」と感じる
  - パターンB：IdPログアウトのみ（RPセッションは残る/別RPが残る）
    - 結果：RP側で保護リソースがまだ見える（危険）
  - パターンC：RP + IdPの整合（SLO or それに準ずる）
    - 結果：期待に近いが、フロントチャネル由来で「全RPの終了」を完全に保証できないことがある（限界を明示）
- 観測で確定したい点
  - RPログアウト後、保護リソースにアクセスするとどうなるか（401/302/再認証）
  - IdPログアウト後、別RPのセッションが残るか（多RP環境）
  - frontchannel/backchannelのどちらが設定されているか、設定断片（メタデータ/Well-known/IdP設定画面）で裏取りできるか

### 5) トークン（refresh/remember-me）とログアウト：セッション終了の“抜け道”を潰す
- 抜け道になりやすい資産
  - refresh token：ログアウトしても、リフレッシュで再度アクセストークンが取れる
  - remember-me：ブラウザ再起動後に自動ログインが復活する
  - device token：端末紐付けが弱いと横展開する
- 観測焦点
  - ログアウト時に refresh token が revoke されるか（少なくともサーバ側で無効化されるか）
  - “全デバイスからログアウト” の有無と、その実装（15/17へ接続）
  - ログアウト後に、静かにトークン再発行が走っていないか（Network/HARで裏取り）

### 6) logout_key_boundary（後工程に渡す正規化キー）
- 推奨キー：logout_key_boundary
  - logout_key_boundary = <pattern>(rp_only|idp_only|rp+idp|unknown) + <entrypoint> + <method>(GET|POST|mixed) + <csrf_protection>(yes/no/unknown) + <server_invalidate>(yes/no/unknown) + <token_revoke>(refresh/rememberme/none/unknown) + <front_back_channel>(front|back|both|none|unknown) + <confidence>
- 記録の最小フィールド（推奨）
  - entrypoint（URL/method）
  - session_cookie_change（削除/更新の有無）
  - server_invalidate（ログ/挙動からの裏取り）
  - idp_session_ended（再ログイン挙動/IdPログから）
  - token_revoke（revoke endpoint呼び出し有無）
  - multi_rp_effect（他RPへ波及するか）
  - evidence（HAR、Cookie差分、設定断片、監査ログ）
  - action_priority（P0/P1/P2）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える（確定できる）：
  - ログアウトがどの層（ブラウザ/RP/IdP）まで効いているかの切り分け
  - ログアウト入口（GET/POST/API/連携）の一貫性と、CSRF耐性の有無
  - ログアウト後に残る“再認証不要の抜け道”（refresh/remember-me等）の兆候
  - SSO環境での責任分界（RPだけ終わる/IdPまで終わる/不明）と、設計上の限界点
- 推定（根拠付きで言える）：
  - frontchannelのみのSLOでは完全性が難しく、端末・ブラウザ条件で残存が起き得る（設定と挙動から）
  - ログアウトCSRFが許容されている場合、フィッシング誘導と結合するリスクが上がる（13/20と接続）
- 言えない（この段階では断定しない）：
  - IdP内部の完全なSLO処理（ただしRP側の期待と実態の乖離は示せる）
  - 監査/運用（通知や監査ログの保存期間）までの断定（設定資料が必要）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- 優先度（P0/P1/P2）
  - P0：
    - ログアウト後も保護リソースが同一セッションで閲覧可能（RPサーバ側無効化が欠落の強い兆候）
    - ログアウト後もrefresh/remember-meで静かに再認証なしで復活する（“終了できない”）
  - P1：
    - SSOでRPログアウトしてもIdPセッションが残り、即ログイン復帰する（設計/期待の乖離。要件次第で重大）
    - 入口差分（/logout と /api/logout 等）で挙動が分裂し、例外パスがある
  - P2：
    - ログアウトCSRF（GET副作用）が成立するが、影響が可用性中心で、対策優先度は要件次第
- “成立条件”としての整理
  - どの資産（cookie/refresh/IdPセッション）が残ると、どの影響（継続利用/即復帰/妨害）が出るかを対応付ける
- 後続への接続（意思決定）
  - 15（session concurrency）：ログアウトが“現在端末のみ”か“全端末”かの境界確認に直結
  - 17（refresh rotation）：ログアウト時のrevoke/無効化が無いと回転しても残存で破綻する
  - 16（step-up）：重要操作の再認証はログアウト/再ログイン境界とも整合している必要がある

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：RPログアウトは動いているが、サーバ側無効化が弱い（cookie削除のみ）
  - 次の検証（少数回）：
    - ログアウト後に同一cookieで保護ページへ到達できないか（302→login等になるか）を確認
    - Set-Cookieで削除されても、同じセッションIDがサーバで生きていないか（ログで裏取り）
  - 判断：
    - 到達できる：P0（サーバ側無効化/セッション失効が欠落）
    - 到達できない：次はIdP/トークン残存（仮説B/C）へ
- 仮説B：SSO環境でIdPセッションが残り、ログアウトが“見かけだけ”
  - 次の検証：
    - RPログアウト→再アクセスで、IdPログイン画面を経ずに戻るか（即復帰）
    - IdPログアウト（提供される場合）→RP再アクセスで、確実に再認証になるか
    - frontchannel/backchannelの設定断片（IdP設定/metadata/.well-known）を証跡化する
  - 判断：
    - 即復帰：P1（要件次第で重大。SLO設計/“全アプリからログアウト”導線/説明の改善が必要）
- 仮説C：refresh/remember-me が残り、ログアウト後に静かに復活する
  - 次の検証：
    - ログアウト時に /revoke 相当が呼ばれるか、refresh tokenが無効化されるか（HAR/ログ）
    - ログアウト後にバックグラウンドで token refresh が成功しないか（Networkで観測）
  - 判断：
    - 復活する：P0（ログアウト境界が破綻）
    - 復活しない：ログアウト境界は概ね整合。次は15/17/16へ

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/` ）：
  - `04_labs/02_web/02_authn/14_logout_design/`
    - 構成案：
      - RP：セッションcookie＋refresh token（rotation対応）
      - IdP：OIDC（frontchannel/backchannel logout を切替できる）
      - 2つのRP（multi-RP）を用意し、“SLOの限界/整合” を観測できるようにする
- 取得する証跡（深く探れる前提：HTTP＋周辺ログ）
  - HTTP：HAR（logout要求、保護リソース再アクセス、token refreshの有無）
  - Cookie差分：Set-Cookie（削除/更新）、SameSite/Secure/HttpOnly
  - アプリログ：session invalidation、token revoke、logout event
  - IdPログ：session end、SLOイベント、front/back channel通知
  - 設定断片：logout endpoint、frontchannel/backchannel設定、post_logout_redirect_uri allowlist
- 観測の設計
  - “ログアウト完了” の定義を固定：
    - RP保護リソースに再アクセス→再認証が必要（セッションが残っていない）
    - refresh/remember-meで静かに復活しない
    -（要件により）IdPセッションも終了している

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
# 例：ログアウト入口と、その後の到達性（擬似）
POST /logout
GET  /account   (保護ページ)

# 例：SSOログアウト関連（擬似）
GET /oidc/logout?post_logout_redirect_uri=...&id_token_hint=...
POST /oauth/revoke { token=refresh_token }

# 観測すること（擬似）
- logout後に保護ページへ到達できるか（=RP側が終わっているか）
- revokeが呼ばれるか（=トークンが終わっているか）
- SSOで即復帰するか（=IdPセッションが残るか）
~~~~
- この例で観測していること：
  - RP/IdP/トークンの“どれが終わっていないか”の切り分け
- 出力のどこを見るか（注目点）：
  - Set-Cookie、保護ページのステータス（401/302）、revoke呼出、IdPリダイレクト挙動
- この例が使えないケース（前提が崩れるケース）：
  - SPAでログアウトがクライアントのみ（localStorage削除）に見える場合（→API logout/refreshの挙動とセットで観測）

## 参考（必要最小限）
- OWASP ASVS（セッション終了、トークン失効、SSO責任分界）
- OWASP WSTG（Logout/Session Termination、CSRF）
- OIDC/SAMLのログアウト（frontchannel/backchannel、SLOの限界と設計判断）

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/02_authn_13_login_csrf_認証CSRFとstate設計.md`
- `01_topics/02_web/02_authn_15_session_concurrency（多端末_同時ログイン制御）.md`
- `01_topics/02_web/02_authn_17_refresh_token_rotation_盗用検知（reuse）.md`
