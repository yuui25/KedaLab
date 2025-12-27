# 02_authn_07_client_storage（localStorage_sessionStorage_memory）
認証資産（ID/Access/Refresh、セッションID、免除トークン等）が **ブラウザのどこに存在するか**（Cookie / localStorage / sessionStorage / memory / IndexedDB / Cache 等）を、推測ではなく観測で確定する

---

## 目的（この技術で到達する状態）
- ASVS：V3（Session Management）/ V2（Authentication）/ V13（API）を横断し、「トークン/セッション資産がどこに保存され、どの境界で再利用されるか」を検証対象として固定する。特に“ブラウザ内保存”は、XSS・拡張機能・端末共有・ログ採取など別系統の攻撃面と直結するため、設計の前提を観測で確定する。
- WSTG：Client-side（ブラウザ）由来の攻撃面（XSS等）と、認証/セッション（WSTG-ATHN/SESS）を結合して扱う。トークンの保存先がlocalStorage等なら「XSSが“認証の鍵”になる」ことを前提に優先度を再計算する。
- PTES：Intelligence Gathering（保存先の特定）→ Vulnerability Analysis（露出面と再利用窓）→ Exploitation（最小差分で影響確認）→ Reporting（証跡）へ直結。
- MITRE ATT&CK：Credential Access（Browser Data / Web Tokens）、Valid Accounts、Defense Evasion（セッション再利用）に接続。ここでの目的は“攻撃手順”ではなく「攻撃者が狙う資産がどこにあるか」を確定すること。

- 認証資産（ID/Access/Refresh、セッションID、免除トークン等）が **ブラウザのどこに存在するか**（Cookie / localStorage / sessionStorage / memory / IndexedDB / Cache 等）を、推測ではなく観測で確定できる。
- "見える/見えない"ではなく、**再利用の窓（いつ・どこで・誰が使えるか）** と **消し方（ログアウト/失効/タブ閉じ/ブラウザ再起動）** を yes/no/unknown で整理できる。
- 02_authn（OIDC/SAML/MFA/Token設計/Session lifecycle）と結合し、「このアプリの主戦場はCookie境界か、クライアント保存か」を決め打ちできる。

## 用語（最小）
- 境界：責任/権限/到達性が切り替わる地点
- 差分観測：1条件だけ変えて比較する観測
- 成立条件：何が揃うと成立/不成立が決まるか

## 前提（対象・範囲・想定）
- 対象：ブラウザで動作するWebアプリ（SPA/MPA/BFF有無は問わない）。
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - SPA/MPA/BFF有無は問わない。SSO/MFA、CDN/WAFが一般的。
- できること/やらないこと（安全に検証する範囲）：
  - 本ユニットは「保存先の特定と意味づけ」が主。XSSの詳細攻略や拡張機能の侵害は扱わない（別ユニット）。
- 依存する前提知識（必要最小限）：
  - `01_topics/02_web/02_authn_03_token設計（Bearer_JWT_Refresh_Rotation）.md`（トークン種別の整理）
  - `01_topics/02_web/02_authn_01_cookie属性と境界（Secure_HttpOnly_SameSite_Path_Domain）.md`（Cookie設計の境界）
  - `01_topics/02_web/02_authn_06_mfa_成立点と例外パス（step-up_device_trust）.md`（免除トークンの扱い）
  - `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
  - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：
    - 認証資産の保存先（Cookie / localStorage / sessionStorage / memory / IndexedDB / Cache 等）の観測
    - 再利用の窓（いつ・どこで・誰が使えるか）と消し方（ログアウト/失効/タブ閉じ/ブラウザ再起動）の観測
    - 更新フロー（silent renew / refresh rotation）との結合観測
  - 扱わない（別ユニットへ接続）：
    - XSSの詳細攻略 → `01_topics/02_web/05_input_06_xss_01_反射_境界モデル.md`
    - 拡張機能の侵害 → 別ユニット

## 想定時間
- 目安：20〜40分（環境/SSO有無で前後）

## ツール選定の根拠（代替）
- HAR/Proxy：成立点と差分を最小回数で記録できる
- 代替：ブラウザ開発者ツール/サーバログ/設定画面

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
- 何が"確定"できるか：
  - トークン/セッション資産が、Cookie・localStorage・sessionStorage・memory 等のどこにあるか
  - HttpOnlyの有無、Authorizationヘッダの有無（＝API認証の鍵がどこにあるか）
  - ログアウト後に「クライアント側の資産が消える/消えない」
  - ブラウザ再起動で「復帰する/しない」（永続性）
- 何が"推定"できるか（推定の根拠/前提）：
  - サーバ側失効が効くか（Refresh rotation / revoke の有無）
  - "端末信頼"が複製耐性を持つか（免除トークンの実体に依存）
- 何は"言えない"か（不足情報・観測限界）：
  - 端末が侵害された場合の影響評価（EDR/OS側の論点）
  - XSSが存在するかどうかの断定（別ユニットで検証）
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：Access/Refresh が localStorage 等に存在（永続） → クライアント側の露出が大きい。XSS/拡張機能/端末共有の影響が直結するため、XSSの優先度とCSP/サニタイズ/依存ライブラリの評価優先度が上がる
  - パターンB：HttpOnly Cookie でのみセッション成立（BFF/サーバ管理） → 主戦場はCookie境界（SameSite/Domain/Path）とセッション寿命/失効。XSSの影響は"セッション送信"側に寄るが、トークン窃取よりは軽減されやすい
  - パターンC：memory-only だが、silent renew が強く"実質長期" → 保存先だけ見て安全とは言えない。更新フローが"再利用窓"を作る

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

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
    - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- 取得する証跡（目的ベースで最小限）：
  - 画面キャプチャ：Applicationタブの保存先（値はマスク）
  - Proxyログ：token取得/更新/ログアウトの前後（該当リクエストのみ）
  - 差分メモ：ログイン直後 / 一定時間後 / ログアウト後 / ブラウザ再起動後 の保存状態（yes/no/unknown）
- 観測の取り方（どの視点で差分を見るか）：
  - 保存先の分類（Cookie vs Storage vs Memory）、露出面（どこに現れ、どこに残るか）、再利用窓（寿命・スコープ・復帰）、更新フロー（silent renew / refresh rotation）
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/client_storage 2>/dev/null
    cd ~/keda_evidence/client_storage
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可されたスコープ** のみ
      - 観測は **最小限の差分セット** のみ
      - トークン/セッション資産の値自体は秘匿扱い。共有時はマスク。
  - 相関キー（最低限）を作る（後で必ず効く）
    - Host、User、Time、保存先（Cookie/localStorage/sessionStorage/memory/IndexedDB/Cache）、資産種類（セッションID/Access/Refresh/ID/MFA免除/端末信頼）、永続性（yes/no/unknown）、共有性（yes/no/unknown）、ログアウト後の消去（yes/no/unknown）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は"手段"であり"結論"ではない。必ず「何を観測している例か」を添える。

~~~~
# 例：保存先の"存在確認"を最短で行う（値を出力しない運用が基本）
# ブラウザ開発者ツール（Console）で、キー一覧のみを見る
Object.keys(localStorage)
Object.keys(sessionStorage)
~~~~

- この例で観測していること：
  - 認証資産がブラウザのどこに存在するか（Cookie / localStorage / sessionStorage / memory / IndexedDB / Cache 等）の存在確認
- 出力のどこを見るか（注目点）：
  - localStorage/sessionStorageのキー一覧（値は見ない）、Applicationタブの保存先、NetworkタブのAuthorizationヘッダ、Set-Cookieヘッダ
- この例が使えないケース（前提が崩れるケース）：
  - ブラウザ開発者ツールが使えない環境では、Proxyログで観測する

## 観測が失敗した場合
- 変数を1つに絞り、差分が出る条件を再設定する
- HARが取れない場合は、画面遷移とレスポンスのスクショで代替する
- ログ/設定が見られるなら、挙動の根拠として添える

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：V3（Session Management）/ V2（Authentication）/ V13（API）を横断し、「トークン/セッション資産がどこに保存され、どの境界で再利用されるか」を検証対象として固定する。特に"ブラウザ内保存"は、XSS・拡張機能・端末共有・ログ採取など別系統の攻撃面と直結するため、設計の前提を観測で確定する。
  - 該当要件（可能ならID）：V3（Session Management）、V2（Authentication）、V13（API）
  - このファイルの内容が「満たす/破れる」ポイント：
    - 満たす：認証資産の保存先と再利用窓を観測で確定し、以後の検証観点を外さないための基盤。
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：Client-side（ブラウザ）由来の攻撃面（XSS等）と、認証/セッション（WSTG-ATHN/SESS）を結合して扱う。トークンの保存先がlocalStorage等なら「XSSが"認証の鍵"になる」ことを前提に優先度を再計算する。
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：認証資産の保存先と再利用窓の観測と理解
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Intelligence Gathering（保存先の特定）→ Vulnerability Analysis（露出面と再利用窓）→ Exploitation（最小差分で影響確認）→ Reporting（証跡）へ直結。
  - 前後フェーズとの繋がり（1行）：保存先の特定→露出面と再利用窓→最小差分で影響確認→証跡の品質を上げる。
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Credential Access / Valid Accounts / Defense Evasion
  - 攻撃者の目的（この技術が支える意図）：Credential Access（Browser Data / Web Tokens）、Valid Accounts、Defense Evasion（セッション再利用）に接続。ここでの目的は"攻撃手順"ではなく「攻撃者が狙う資産がどこにあるか」を確定すること。
  - 参照：https://attack.mitre.org/tactics/TA0006/（Credential Access）、https://attack.mitre.org/tactics/TA0001/（Initial Access - Valid Accounts）、https://attack.mitre.org/tactics/TA0005/（Defense Evasion）

## 参考（必要最小限）
- OWASP JSON Web Token Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
- OWASP OAuth 2.0 Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Security_Cheat_Sheet.html
- OWASP Application Security Verification Standard: https://github.com/OWASP/ASVS
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- PTES (Penetration Testing Execution Standard): https://pentest-standard.readthedocs.io/
- MITRE ATT&CK: https://attack.mitre.org/

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`01_topics/02_web/02_authn_03_token設計（Bearer_JWT_Refresh_Rotation）.md`
- 関連 topics：`01_topics/02_web/02_authn_01_cookie属性と境界（Secure_HttpOnly_SameSite_Path_Domain）.md`
- 関連 topics：`01_topics/02_web/02_authn_06_mfa_成立点と例外パス（step-up_device_trust）.md`

---

## 深掘りリンク（最大8）
- `01_topics/02_web/02_authn_00_認証・セッション・トークン.md`
- `01_topics/02_web/02_authn_01_cookie属性と境界（Secure_HttpOnly_SameSite_Path_Domain）.md`
- `01_topics/02_web/02_authn_02_session_lifecycle（更新_失効_固定化_ローテーション）.md`
- `01_topics/02_web/02_authn_03_token設計（Bearer_JWT_Refresh_Rotation）.md`
- `01_topics/02_web/02_authn_06_mfa_成立点と例外パス（step-up_device_trust）.md`
- `01_topics/02_web/02_authn_08_device_binding（端末紐付け_IP_UA_fingerprint）.md`
- `01_topics/02_web/05_input_06_xss_01_反射_境界モデル.md`
- `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`

---
