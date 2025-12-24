# 02_authn_07_client_storage（localStorage_sessionStorage_memory）.md

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS：V3（Session Management）/ V2（Authentication）/ V13（API）を横断し、「トークン/セッション資産がどこに保存され、どの境界で再利用されるか」を検証対象として固定する。特に“ブラウザ内保存”は、XSS・拡張機能・端末共有・ログ採取など別系統の攻撃面と直結するため、設計の前提を観測で確定する。
- WSTG：Client-side（ブラウザ）由来の攻撃面（XSS等）と、認証/セッション（WSTG-ATHN/SESS）を結合して扱う。トークンの保存先がlocalStorage等なら「XSSが“認証の鍵”になる」ことを前提に優先度を再計算する。
- PTES：Intelligence Gathering（保存先の特定）→ Vulnerability Analysis（露出面と再利用窓）→ Exploitation（最小差分で影響確認）→ Reporting（証跡）へ直結。
- MITRE ATT&CK：Credential Access（Browser Data / Web Tokens）、Valid Accounts、Defense Evasion（セッション再利用）に接続。ここでの目的は“攻撃手順”ではなく「攻撃者が狙う資産がどこにあるか」を確定すること。

## 目的（この技術で到達する状態）
- 認証資産（ID/Access/Refresh、セッションID、免除トークン等）が **ブラウザのどこに存在するか**（Cookie / localStorage / sessionStorage / memory / IndexedDB / Cache 等）を、推測ではなく観測で確定できる。
- “見える/見えない”ではなく、**再利用の窓（いつ・どこで・誰が使えるか）** と **消し方（ログアウト/失効/タブ閉じ/ブラウザ再起動）** を yes/no/unknown で整理できる。
- 02_authn（OIDC/SAML/MFA/Token設計/Session lifecycle）と結合し、「このアプリの主戦場はCookie境界か、クライアント保存か」を決め打ちできる。

## 前提（対象・範囲・想定）
- 対象：ブラウザで動作するWebアプリ（SPA/MPA/BFF有無は問わない）。
- 前段（接続）
  - `01_topics/02_web/02_authn_03_token設計（Bearer_JWT_Refresh_Rotation）.md`（トークン種別の整理）
  - `01_topics/02_web/02_authn_01_cookie属性と境界（Secure_HttpOnly_SameSite_Path_Domain）.md`（Cookie設計の境界）
  - `01_topics/02_web/02_authn_06_mfa_成立点と例外パス（step-up_device_trust）.md`（免除トークンの扱い）
- 制約：本ユニットは「保存先の特定と意味づけ」が主。XSSの詳細攻略や拡張機能の侵害は扱わない（別ユニット）。

## 観測ポイント（何を見ているか：保存先 / 露出面 / 再利用窓）
### 1) まず“資産一覧”を決める（何を探すか）
探す対象は「ログイン状態を作る/維持する/昇格する」もの。
- セッションID（Cookie / ヘッダ / hidden field）
- Access Token（API呼び出しに使う）
- ID Token（ユーザー情報、ログイン表示に使う場合）
- Refresh Token（長期継続・更新に使う）
- MFA免除トークン / 端末信頼トークン（remember device）
- CSRFトークン（認証資産ではないが、設計次第で結合していることがある）

### 2) “どこに保存されているか”を分類する（Cookie vs Storage vs Memory）
- Cookie（HttpOnlyあり/なしで意味が変わる）
  - HttpOnlyあり：JSから読めない（ただし送信はされる）
  - HttpOnlyなし：JSから読める（＝クライアント側露出）
- Web Storage
  - localStorage：永続（ブラウザを閉じても残りやすい）。端末共有・端末侵害・誤ログ採取の影響を受けやすい。
  - sessionStorage：タブ単位（原則タブを閉じると消える）。ただし同一オリジン内での扱いは実装次第。
- Memory（JS変数/アプリ状態）
  - リロードで消えるが、実装によっては“再取得フロー”が強く働き、実質的に長期継続する（silent renew等）。
- IndexedDB / Cache Storage / Service Worker
  - SPAで多い。トークンは置かない設計が推奨されるが、実装上置かれているケースがある。
- URL（クエリ/フラグメント）
  - OIDCの古い/誤ったフローで見えることがある。ログ/Referer/共有で漏れやすい。

### 3) “露出面”を観測する（どこに現れ、どこに残るか）
- ブラウザ開発者ツール
  - Application/Storage：localStorage/sessionStorage/IndexedDB/Cookies
  - Network：Authorizationヘッダ、レスポンスボディ（JSON）、Set-Cookie
- Proxyログ（Burp/Vex等）
  - `Authorization: Bearer ...` が出るか（出るなら“どこでセットされるか”を追う）
  - token endpoint のレスポンスに refresh が含まれるか
- ログアウト・期限切れ・再ログインの挙動
  - “消えるはずの場所が消えない”が最重要の差分

### 4) “再利用窓”をテスト可能な形に落とす（寿命・スコープ・復帰）
観測で yes/no/unknown にする項目（固定テンプレ）
- 永続性：ブラウザ再起動後に残るか（yes/no）
- 共有性：別タブ/別ウィンドウ/別プロファイルで復帰するか（yes/no）
- スコープ：サブドメイン間で共有されるか（Cookie Domain設計と結合して判断）
- ログアウト境界：ログアウト後に資産が消えるか（client側/サーバ側）
- 失効境界：Refresh等が回収されるか（unknownになりやすいので証跡で補強）

### 5) “更新フロー”と結合して観測する（silent renew / refresh rotation）
保存先のリスクは、更新フローで増幅する。
- 更新がどの通信で起きるか（token endpoint / iframe / hidden request 等）
- 更新に必要な資産がどこにあるか（Refreshがブラウザにあるなら、更新=再利用窓が長い）
- ローテーション/失効がある場合、古い資産が使えなくなるか（挙動で推定）

### 6) 証跡（最低限）
- 画面キャプチャ：Applicationタブの保存先（値はマスク）
- Proxyログ：token取得/更新/ログアウトの前後（該当リクエストのみ）
- 差分メモ：
  - ログイン直後 / 一定時間後 / ログアウト後 / ブラウザ再起動後 の保存状態（yes/no/unknown）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える（観測で断定できる）
  - トークン/セッション資産が、Cookie・localStorage・sessionStorage・memory 等のどこにあるか
  - HttpOnlyの有無、Authorizationヘッダの有無（＝API認証の鍵がどこにあるか）
  - ログアウト後に「クライアント側の資産が消える/消えない」
  - ブラウザ再起動で「復帰する/しない」（永続性）
- 推定（追加観測で強くなる）
  - サーバ側失効が効くか（Refresh rotation / revoke の有無）
  - “端末信頼”が複製耐性を持つか（免除トークンの実体に依存）
- 言えない（この段階の限界）
  - 端末が侵害された場合の影響評価（EDR/OS側の論点）
  - XSSが存在するかどうかの断定（別ユニットで検証）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
※ここでは“攻撃手順”ではなく、診断の優先順位付けを行う。
- 状態A：Access/Refresh が localStorage 等に存在（永続）
  - 意味：クライアント側の露出が大きい。XSS/拡張機能/端末共有の影響が直結するため、**XSSの優先度** と **CSP/サニタイズ/依存ライブラリ** の評価優先度が上がる。
  - 次：`02_web` 側の XSS（入力→DOM→実行）ユニットと結合して「攻撃面→資産→到達点」を繋ぐ。
- 状態B：HttpOnly Cookie でのみセッション成立（BFF/サーバ管理）
  - 意味：主戦場はCookie境界（SameSite/Domain/Path）とセッション寿命/失効。XSSの影響は“セッション送信”側に寄るが、トークン窃取よりは軽減されやすい。
  - 次：`02_authn_01` と `02_authn_02` に戻り、境界と失効の unknown を潰す。
- 状態C：memory-only だが、silent renew が強く“実質長期”
  - 意味：保存先だけ見て安全とは言えない。更新フローが“再利用窓”を作る。
  - 次：`02_authn_03`（refresh/rotation）と結合し、更新の成立点・失効境界・再認証要求の有無を観測で固める。

## 次に試すこと（仮説A/Bの分岐と検証）
### 仮説A：localStorage/sessionStorage にトークンがある
- 次に試すこと
  - ログアウト時に storage がクリアされるか（yes/no）
  - 別タブ/ブラウザ再起動後に復帰するか（yes/no）
  - token更新がどの通信で行われるか（token endpoint の有無、更新頻度）
- 期待する到達点
  - “保存先＋再利用窓”を証跡付きで説明できる（設計のリスク判断が可能）

### 仮説B：Cookie中心（HttpOnly）で、JSからは見えない
- 次に試すこと
  - Cookie属性（SameSite/Domain/Path）と、SSO/MFA/Step-upの越境（POST/302）で送信条件が崩れていないかを確認
  - ログアウト後にCookieが削除されるか、サーバ側失効が効くか（unknownを潰す）
- 期待する到達点
  - “クライアント保存は無いが、セッション境界が主戦場”と結論付けできる

### 仮説C：IndexedDB/Service Worker 等に資産がある（想定外）
- 次に試すこと
  - どのキー/どのレコードに置かれているかを“種類だけ”特定（値はマスク）
  - キャッシュクリア/ログアウト/再起動で消えるか（永続性）
- 期待する到達点
  - “想定外の保存先”を観測で示し、設計レビュー/修正提案へ繋げられる

### コマンド/手順例（例示は最小限・意味が主）
~~~~
# 目的：保存先の“存在確認”を最短で行う（値を出力しない運用が基本）
# - ブラウザ開発者ツール（Console）で、キー一覧のみを見る
Object.keys(localStorage)
Object.keys(sessionStorage)
~~~~

## 参考（必要最小限）
- `01_topics/02_web/02_authn_03_token設計（Bearer_JWT_Refresh_Rotation）.md`
- `01_topics/02_web/02_authn_01_cookie属性と境界（Secure_HttpOnly_SameSite_Path_Domain）.md`
- `01_topics/02_web/02_authn_02_session_lifecycle（更新_失効_固定化_ローテーション）.md`
- `01_topics/02_web/02_authn_06_mfa_成立点と例外パス（step-up_device_trust）.md`
- OWASP：JSON Web Token Cheat Sheet / OAuth 2.0 Security Cheat Sheet（設計原則の参照）
- OWASP WSTG：Client-side Testing / Authentication / Session Management（保存先を“検証差分”に落とすための参照）
