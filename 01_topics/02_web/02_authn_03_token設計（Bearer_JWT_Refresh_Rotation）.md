<<<BEGIN>>>
# 02_authn_03_token設計（Bearer_JWT_Refresh_Rotation）
「JWTっぽい」「Bearerっぽい」を雰囲気で扱わず、**どのトークンが、どの境界（資産/信頼/権限）を越えて、どこで検証されているか**を説明する

---

## 目的（この技術で到達する状態）
- 「JWTっぽい」「Bearerっぽい」を雰囲気で扱わず、**どのトークンが、どの境界（資産/信頼/権限）を越えて、どこで検証されているか**を説明できる。
- 発行・提示・更新（Refresh）・失効（Revocation）・ローテーション（Rotation）の挙動を、**通信差分で yes/no/unknown** まで落とせる。
- 認証（身元）と認可（権限）を混同せず、トークンの設計上の論点（寿命・スコープ・対象サービス）を整理できる。

## 前提（対象・範囲・想定）
- 対象：Authorizationヘッダ（Bearer）、Cookie内トークン、SPA/モバイル向けAPIトークン、SSO連携で発行されるID/Access/Refreshトークン。
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - SPA/モバイル向けAPI、SSO連携、CDN/WAFが一般的。
- できること/やらないこと（安全に検証する範囲）：
  - 観測は最小限の差分セットのみ（破壊的試験や過剰負荷は行わない）。
- 依存する前提知識（必要最小限）：
  - `01_topics/02_web/02_authn_00_認証・セッション・トークン.md`
  - `01_topics/02_web/02_authn_01_cookie属性と境界（Secure_HttpOnly_SameSite_Path_Domain）.md`
  - `01_topics/02_web/02_authn_02_session_lifecycle（更新_失効_固定化_ローテーション）.md`
  - `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
  - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：
    - トークンの種類（Access/Refresh/ID）と役割の切り分け
    - Bearer、JWT、署名検証、スコープ/ロール、RefreshとRotationの挙動
    - 発行・提示・更新・失効・ローテーションの観測と差分検証
  - 扱わない（別ユニットへ接続）：
    - Cookie属性の詳細 → `01_topics/02_web/02_authn_01_cookie属性と境界（Secure_HttpOnly_SameSite_Path_Domain）.md`
    - セッションライフサイクルの詳細 → `01_topics/02_web/02_authn_02_session_lifecycle（更新_失効_固定化_ローテーション）.md`
    - 権限伝播の詳細 → `01_topics/02_web/04_api_01_権限伝播モデル（フロント_バックエンド_ジョブ）.md`

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) どこにトークンが載るか（提示点）
- Authorizationヘッダ：`Authorization: Bearer <token>`
- Cookie：`Cookie: <name>=<token>`
- ボディ：`{"token":"..."}`（更新/交換系APIに多い）
- ここで確定したいこと：
  - “どのリクエストで”トークンが使われるか（全APIか、一部か）
  - “どの単位で”トークンが変わるか（ログイン、一定時間、操作、権限変更）

### 2) トークンの種類（役割の切り分け）
- Access：APIアクセスのための短寿命トークン
- Refresh：Access再発行のための長寿命トークン（更新APIでのみ使われる想定）
- ID：本人情報（表示・同意・セッション確立の補助）※API認可に使われるとは限らない
- 重要：ラベルは実装依存。**実際にどこへ送られているか**で役割を確定する。

### 3) 境界（Boundary）
- 資産境界：トークンが指すセッション・権限が資産
- 信頼境界：発行者（IdP/認証基盤）と利用者（API/リソースサーバ）の信頼関係
- 権限境界：scope/role/tenant 等がどこで評価されるか（トークン内か、サーバ側参照か）

## トークン設計の論点（意味→判断→次の一手）
### 1) Bearer（所持者が主体になれる）
- 意味：提示できる者が主体として扱われる（所持＝利用可能）
- 判断：
  - トークンの再利用窓（寿命/失効）が短いほど、影響が限定されやすい
  - 長寿命・失効なし・再利用許容があると、影響面が広がる方向
- 次の一手：
  - 「寿命」「失効」「再発行」の挙動を差分で確定（後述の最小差分セット）

### 2) JWT（構造化されたクレーム）
- 意味：ヘッダ/ペイロード（クレーム）/署名の構造を持つことが多い
- 判断：
  - “JWTっぽい”は見た目だけで断定しない（ただし観測の入口にはなる）
  - クレーム（iss/aud/exp/nbf/iat/jti/sub 等）が、どの境界（対象サービス、寿命、一意性）に効くかが重要
- 次の一手：
  - まず「クレームが何を表すか」を観測し、API側の挙動（期限切れ/対象外/スコープ不足）と対応付ける

### 3) 署名検証（どこで検証されるか）
- 意味：発行者の署名を検証し、改ざんを防ぐ（通常はAPI/ゲートウェイで検証）
- 判断：
  - “どこが検証主体か”が分からないと、失効・ローテーション・鍵更新の説明が曖昧になる
- 次の一手：
  - 検証エラー時の挙動（401、エラーヘッダ、ログ）を証跡化し、検証点の候補（Gateway/サービス）を絞る

### 4) スコープ/ロール（権限の粒度）
- 意味：同じ主体でも操作権限が違う（read/write/admin 等）
- 判断：
  - トークン内にスコープがある場合：権限境界が“トークン発行時”に固まる設計になりやすい
  - サーバ側参照の場合：権限境界が“リアルタイム参照”になりやすい（失効/変更が効きやすいこともある）
- 次の一手：
  - 権限変更（ロール変更、テナント切替）後に、トークンが変わるか/変わらないかを差分で観測する

### 5) RefreshとRotation（更新の安全性）
- 意味：Accessを短寿命にしても、Refreshが長寿命で再利用可能だと実質的な窓が広がる
- 判断：
  - Rotationあり：更新のたびにRefreshが置換され、古いRefreshが無効になる方向
  - Rotationなし：Refreshが同じで使い回しになりやすく、再利用窓が広がる方向
- 次の一手：
  - 更新APIの前後でRefreshが変わるか（Set-Cookie/レスポンス）、古いRefreshで更新ができるか（差分）を観測して結論を出す

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が"確定"できるか：
  - トークンがどこで提示され、どのAPIに効いているか（提示点の確定）
  - Access/Refresh相当の更新フローがあるか（更新API・Set-Cookie・レスポンス差分）
  - 有効期限や失効が挙動として現れるか（401/再認証/更新要求）
- 何が"推定"できるか（推定の根拠/前提）：
  - トークン設計の意図（寿命・失効・スコープ設計）
- 何は"言えない"か（不足情報・観測限界）：
  - 署名検証の内部詳細（鍵管理、JWK取得、検証ライブラリ）※ログ/設定が必要
  - "なぜ失効しないのか"の内部理由（ブラックリスト方式か、参照方式か等）
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：Accessは短寿命だが、更新で無限に延命できそう → 更新APIの存在と呼ばれ方（自動更新/手動更新）をProxyで確定し、更新前後でトークン（Access/Refresh）がどう変わるか差分を取る
  - パターンB：ログアウトしてもAPIが通ることがある → ログアウト直後に、同一トークンで状態参照APIを叩き、401/403/200の差分を保存する（Cookie削除だけか、サーバ失効かを切り分ける）
  - パターンC：権限変更（ロール/テナント切替）の反映が怪しい → 権限変更の前後で、同一APIの結果差分を取り、トークンが変化する/しない、結果が即時に変わる/遅延するを観測する

## 攻撃者視点での利用（意思決定：優先度・攻め筋・想定パス）
> 具体的手順ではなく「観測された状態が、次の意思決定にどう効くか」を整理する。

- 優先度（まず確定する）
  1) 失効：ログアウト/パスワード変更/権限変更で無効化されるか
  2) 寿命：Accessの短さ、Refreshの長さ、更新の有無
  3) スコープ/テナント：権限境界がトークンに固定されるか、サーバ参照か
  4) 伝播：Gateway/バックエンド/ジョブまで主体がどう運ばれるか
- 状態が意思決定に効く例
  - RefreshがRotationされない：再利用窓が広い可能性 → 失効/検知の観測が優先
  - 権限変更してもトークンが変わらない：権限境界がサーバ参照か、更新が遅延する可能性 → 変更後の差分観測が優先
  - 期限切れで401になる：寿命境界が機能している → 次は“例外経路”で同じ境界が守られるか確認する

## 次に試すこと（仮説A/Bの分岐と検証）
### 仮説A：Accessは短寿命だが、更新で無限に延命できそう
- 次に試すこと
  - 更新APIの存在と呼ばれ方（自動更新/手動更新）をProxyで確定し、更新前後でトークン（Access/Refresh）がどう変わるか差分を取る
- 期待する観測
  - Rotationの有無、古いRefreshの扱い（通る/通らない）を yes/no/unknown で言える

### 仮説B：ログアウトしてもAPIが通ることがある
- 次に試すこと
  - ログアウト直後に、同一トークンで状態参照APIを叩き、401/403/200の差分を保存する（Cookie削除だけか、サーバ失効かを切り分ける）
- 期待する観測
  - “クライアント削除のみ”か“サーバ失効あり”かを説明できる

### 仮説C：権限変更（ロール/テナント切替）の反映が怪しい
- 次に試すこと
  - 権限変更の前後で、同一APIの結果差分を取り、トークンが変化する/しない、結果が即時に変わる/遅延するを観測する
- 期待する観測
  - 権限境界の位置（トークン固定/サーバ参照/キャッシュ）を推定ではなく挙動で絞れる

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
    - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- 取得する証跡（目的ベースで最小限）：
  - Proxyログ（必須）：`Authorization`、Set-Cookie、トークン更新API、401/403/200の差分
  - 必要時：HAR（ブラウザ）、サーバログ（失効・検証エラー）、監査ログ（クラウド/IdP）
  - 差分セット（最小）：ログイン直後、通常操作、更新、ログアウト、権限変更
- 観測の取り方（どの視点で差分を見るか）：
  - トークンの提示点（Authorization/Cookie/ボディ）、種類（Access/Refresh/ID）、変化（ログイン/更新/時間/操作）、失効（ログアウト後、期限切れ）
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/token_design 2>/dev/null
    cd ~/keda_evidence/token_design
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可されたスコープ** のみ
      - 観測は **最小限の差分セット** のみ
      - トークンは秘匿情報。共有・提出・保管はルールに従う。
  - 相関キー（最低限）を作る（後で必ず効く）
    - Host、User、Time、トークン種類（Access/Refresh/ID）、提示点（Authorization/Cookie/ボディ）、変化タイミング（ログイン/更新/時間/操作）、失効状態（有効/失効/不明）、結果（401/403/200）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は"手段"であり"結論"ではない。必ず「何を観測している例か」を添える。

~~~~
# 例：ログイン直後のトークン取得を観測
curl -i https://example.com/login -d "username=test&password=test" -c cookies.txt

# 例：トークンでAPIアクセスを観測
curl -i https://api.example.com/me -H "Authorization: Bearer <token>"
curl -i https://api.example.com/me -b cookies.txt

# 例：トークン更新を観測
curl -i https://api.example.com/refresh -H "Authorization: Bearer <refresh_token>"
~~~~

- この例で観測していること：
  - トークンがどこで提示され、どのAPIに効いているか（提示点の確定）、Access/Refresh相当の更新フローがあるか（更新API・Set-Cookie・レスポンス差分）
- 出力のどこを見るか（注目点）：
  - Authorizationヘッダ、Set-Cookieヘッダ、ステータスコード（200/401/403）、レスポンスボディ（トークン更新時の新トークン）
- この例が使えないケース（前提が崩れるケース）：
  - JS必須/SSO必須の場合、curlだけでは成立しない（ブラウザ+HAR/Proxyで観測へ）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：V2（Authentication）/ V3（Session Management）を中心に、V4（Access Control）/ V13（API）へ接続。トークンは「誰として扱うか」をAPI境界へ運ぶため、寿命・失効・スコープ設計が品質を決める。
  - 該当要件（可能ならID）：V2（Authentication）、V3（Session Management）、V13（API）
  - このファイルの内容が「満たす/破れる」ポイント：
    - 満たす：トークンの設計上の論点（寿命・スコープ・対象サービス）を整理し、以後の検証観点を外さないための基盤。
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：WSTG-ATHN / WSTG-SESS を横断。CookieではなくBearer/Tokenの場合でも、発行→提示→更新→失効を「観測→差分」で確定することが必須。
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：トークン設計の観測と理解
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Vulnerability Analysis（成立条件の切り分け）→ Exploitation（最小再現）→ Reporting（根拠提示）。トークンは推測で断言しやすいので、unknown を許容しつつ証跡で潰す。
  - 前後フェーズとの繋がり（1行）：成立条件の切り分け→最小再現→根拠提示の品質を上げる。
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Valid Accounts / Credential Access / Defense Evasion
  - 攻撃者の目的（この技術が支える意図）：トークンの再利用窓・失効設計・スコープの粗さは、攻撃者の意思決定（何を優先するか）を直接変える。
  - 参照：https://attack.mitre.org/tactics/TA0001/（Initial Access - Valid Accounts）、https://attack.mitre.org/tactics/TA0006/（Credential Access）、https://attack.mitre.org/tactics/TA0005/（Defense Evasion）

## 参考（必要最小限）
- OWASP Application Security Verification Standard: https://github.com/OWASP/ASVS
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- PTES (Penetration Testing Execution Standard): https://pentest-standard.readthedocs.io/
- MITRE ATT&CK: https://attack.mitre.org/
- JWT (JSON Web Token): https://jwt.io/

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`01_topics/02_web/02_authn_00_認証・セッション・トークン.md`
- 関連 topics：`01_topics/02_web/02_authn_02_session_lifecycle（更新_失効_固定化_ローテーション）.md`
- 関連 topics：`01_topics/02_web/04_api_01_権限伝播モデル（フロント_バックエンド_ジョブ）.md`

---

## 深掘りリンク（最大8）
- `01_topics/02_web/02_authn_00_認証・セッション・トークン.md`
- `01_topics/02_web/02_authn_01_cookie属性と境界（Secure_HttpOnly_SameSite_Path_Domain）.md`
- `01_topics/02_web/02_authn_02_session_lifecycle（更新_失効_固定化_ローテーション）.md`
- `01_topics/02_web/02_authn_04_sso_oidc_flow観測（state_nonce_code_PKCE）.md`
- `01_topics/02_web/02_authn_17_refresh_token_rotation_盗用検知（reuse）.md`
- `01_topics/02_web/04_api_00_権限伝播・入力・バックエンド連携.md`
- `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
- `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`

---

<<<END>>>
