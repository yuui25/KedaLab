# 02_authn_01_cookie属性と境界（Secure_HttpOnly_SameSite_Path_Domain）
Cookie属性を「知っている」ではなく、**境界（いつ/どこへ/誰として送られるか）を観測→差分→結論**で説明する

---

## 目的（この技術で到達する状態）
- Cookie属性を「知っている」ではなく、**境界（いつ/どこへ/誰として送られるか）を観測→差分→結論**で説明できる。
- ブラウザ挙動（自動送信）とサーバ期待（セッション識別）を切り分け、**“送られない理由”を推測せず特定**できる。
- 実務で、Cookie起因の問題（セッション固定化、CSRF成立条件、越境送信、サブドメイン混在など）を、最小の検証で判断できる。

## 用語（最小）
- 境界：責任/権限/到達性が切り替わる地点
- 差分観測：1条件だけ変えて比較する観測
- 成立条件：何が揃うと成立/不成立が決まるか

## 前提（対象・範囲・想定）
- 対象：Webアプリの認証後セッション（Cookieベース）または補助Cookie（CSRF token、Remember-me 等）。
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - CDN/キャッシュ/ドメイン分割があると、同じCookie名でも境界が複雑になる（ケースで明示する）。
- できること/やらないこと（安全に検証する範囲）：
  - Cookie属性は"ブラウザ側の送信条件"を規定する。サーバ側がどう判定したかは別（ログ等で補強）。
- 依存する前提知識（必要最小限）：
  - `01_topics/02_web/02_authn_00_認証・セッション・トークン.md`
  - `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
  - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：
    - Cookie属性（Secure、HttpOnly、SameSite、Domain、Path、Expires/Max-Age、__Host-/__Secure-プレフィックス）の意味と境界
    - Cookieがどの条件で送信されるかの観測と差分検証
    - 実務で、Cookie起因の問題（セッション固定化、CSRF成立条件、越境送信、サブドメイン混在など）の判断
  - 扱わない（別ユニットへ接続）：
    - セッションライフサイクルの詳細 → `01_topics/02_web/02_authn_02_session_lifecycle（更新_失効_固定化_ローテーション）.md`
    - トークン設計の詳細 → `01_topics/02_web/02_authn_03_token設計（Bearer_JWT_Refresh_Rotation）.md`

## 想定時間
- 目安：20〜40分（環境/SSO有無で前後）

## ツール選定の根拠（代替）
- HAR/Proxy：成立点と差分を最小回数で記録できる
- 代替：ブラウザ開発者ツール/サーバログ/設定画面

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### Cookieが関与する「境界」
- 資産境界：セッション（ログイン状態）という資産が、どのCookieで識別されるか
- 信頼境界：同一サイト内の信頼／クロスサイトの不信（SameSiteの境界）
- 権限境界：Cookieが送られた結果、誰の権限で処理されるか（Authn→Authzへ接続）

### まず見るべき通信要素（Set-Cookie と Cookie）
- レスポンス：`Set-Cookie: <name>=<value>; <attributes...>`
- リクエスト：`Cookie: <name>=<value>; ...`
- ここで確定したいこと：
  - Cookieは **いつ発行**されるか（ログイン直後/特定操作/リダイレクト後）
  - Cookieは **どの条件で送信**されるか（同一サイト/サブドメイン/パス/HTTPS 等）
  - Cookieは **どの範囲に効く**か（Domain/Path によるスコープ）

## Cookie属性の意味（意味→判断→次の一手）
> ここでは暗記ではなく「観測された属性が、次の検証判断をどう変えるか」に寄せる。

### Secure
- 意味：HTTPSのときだけ送られる（HTTPでは送られない）
- 判断：
  - HTTPアクセスに対してセッションCookieが送られているなら、Secure不足（または別Cookie）を疑う
  - 逆に送られないなら「HTTP経由の再現ができない」＝攻撃者の手も変わる
- 次の一手：
  - “HTTPで成立しない”を結論にするのではなく、**HTTPS経路での成立条件**（他属性や端末条件）へ移る

### HttpOnly
- 意味：ブラウザのJSから `document.cookie` で参照できない（ただし自動送信はされる）
- 判断：
  - JSから盗めない＝それだけで安全とは言えない（自動送信されるので不正操作は別経路で起き得る）
  - 影響説明では「参照不可」と「操作可能性（送信）」を分ける
- 次の一手：
  - 影響が“情報窃取”から“状態変更（不正操作）”側に寄る可能性を検討（CSRF/SameSiteへ接続）

### SameSite（Lax / Strict / None）
- 意味：クロスサイト文脈でCookieを送るかどうかの境界
- 判断（ざっくりの実務判断）：
  - Strict：原則クロスサイトで送られにくい（CSRF成立しにくい方向）
  - Lax：一部の遷移では送られる可能性がある（“どの操作で送られるか”差分が重要）
  - None：クロスサイトでも送る（通常 Secure が必須）→ CSRF条件が緩くなる方向
- 次の一手：
  - **“どの遷移（GET/POST/iframe/fetch）で送られたか”をProxyで確定**し、成立条件をケースに残す

### Domain
- 意味：どのホスト範囲でCookieを送るか（サブドメインを含むか）
- 判断：
  - 広すぎるDomainは、サブドメイン混在時のリスク（サブドメイン側の弱点で影響が広がる）に繋がる
  - Domain未指定（ホスト限定）なら、サブドメイン跨ぎの影響は限定されやすい
- 次の一手：
  - サブドメインが多い対象では、Domainの広さを「攻撃面（依存）」としてケースに明記し、優先度付けに反映

### Path
- 意味：どのパス配下でCookieを送るか（スコープの境界）
- 判断：
  - Pathが広いほど送信範囲が広い＝影響面が広がりやすい
  - ただし、アプリ設計上“全体で必要”なCookieもあるため、広い=即NGではなく目的と整合を見る
- 次の一手：
  - “本当にその範囲で必要か”を、機能単位の境界（管理画面/一般画面）と合わせて評価する

### Expires / Max-Age（寿命）
- 意味：Cookieの寿命（セッション終了で消えるか、長期保持するか）
- 判断：
  - 長期保持は、端末共有・離席・盗難などのリスク条件で影響が増える
  - “ログアウト”で失効するか（サーバ側）と、寿命（クライアント側）は別物
- 次の一手：
  - ログアウト後の再利用（失効）と、ブラウザ再起動後の残存（寿命）を分けて差分検証する

### __Host- / __Secure-（プレフィックス）
- 意味：ブラウザに追加の制約を課す命名規則（より厳格なスコープを強制）
- 判断：
  - これらが使われている場合、スコープ（Domain/Path/Secure）の設計意図が強い
  - 逆に無い場合、設計の成熟度が低いと決めつけず、他属性との整合を見て評価する
- 次の一手：
  - 使われていないこと自体を問題にするのではなく、境界（送信範囲）が過剰かどうかを差分で確かめる

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が"確定"できるか：
  - Cookieが **どの条件で送られるか**（HTTPS/クロスサイト/サブドメイン/パス）
  - セッション維持が **どのCookieに依存しているか**（識別子の所在）
  - 失効・寿命・スコープが **境界として整合しているか**
- 何が"推定"できるか（推定の根拠/前提）：
  - Cookie属性の設計意図（境界の設計が適切かどうか）
- 何は"言えない"か（不足情報・観測限界）：
  - サーバ側でのセッション失効ロジックの正否（ログ/設定/実装確認が必要）
  - 中間層（CDN/WAF/プロキシ）による書き換えの有無（別観測が必要）
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：Cookieが送られない／挙動が揺れる → Proxyで Set-Cookie と Cookie の両方を保存し、送信される/されない条件を1つずつ変えて差分を見る
  - パターンB：不正操作（状態変更）が疑われる → SameSiteとCSRFトークンの関係を、実リクエスト差分で確認する（送信されるのに拒否される＝別境界）
  - パターンC：サブドメインや複数ホストで挙動が混ざる → Domainのスコープを確定し、サブドメイン一覧（ASM/OSINT結果）と突き合わせて"影響面"を評価する

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
> “攻撃手順”ではなく、次の検証を早く正しく選ぶための判断材料。

- 優先度
  1) **SameSite**：クロスサイトで送られる条件が、状態変更に直結する（差分が強い）
  2) **Domain/Path**：送信範囲が広いほど、依存（サブドメイン/機能）で攻撃面が増える
  3) **Secure**：経路要件（HTTPでは成立しない/する）を早期に確定できる
  4) **HttpOnly**：影響の方向（窃取 vs 不正操作）を分ける判断材料
- 次の仮説の立て方
  - もし「CSRFが成立しない」：SameSiteが境界になっていないか（送信条件の差分）を確定する
  - もし「サブドメインで状態が引き継がれる」：Domainが広い設計かどうかを確認する
  - もし「ログアウト後も操作できる」：寿命ではなくサーバ失効（セッション管理）の問題として切り分ける

## 次に試すこと（仮説A/Bの分岐と検証）
### 仮説A：Cookieが送られない／挙動が揺れる（まず境界を確定したい）
- 次に試すこと
  - Proxyで Set-Cookie と Cookie の両方を保存し、送信される/されない条件を1つずつ変えて差分を見る
- 期待する観測
  - “どの条件で送られないか”を yes/no/unknown で言える

### 仮説B：不正操作（状態変更）が疑われる（影響説明を固めたい）
- 次に試すこと
  - SameSiteとCSRFトークンの関係を、実リクエスト差分で確認する（送信されるのに拒否される＝別境界）
- 期待する観測
  - 送信境界（Cookie）と、拒否境界（サーバ側チェック）を分離して説明できる

### 仮説C：サブドメインや複数ホストで挙動が混ざる（依存を評価したい）
- 次に試すこと
  - Domainのスコープを確定し、サブドメイン一覧（ASM/OSINT結果）と突き合わせて“影響面”を評価する
- 期待する観測
  - “どのホストが同じセッション境界に入るか”を説明できる

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
    - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- 取得する証跡（目的ベースで最小限）：
  - Proxyログ（推奨）、必要時：HAR（ブラウザ）、pcap（HTTP/2/3やTLS切り分け）、サーバログ（認証/セッション）
  - ログイン直後のレスポンスで Set-Cookie を保存
  - 同一機能を、条件を1つだけ変えて呼び出し、Cookie送信の有無を比較する
- 観測の取り方（どの視点で差分を見るか）：
  - 条件差（https/http、同一サイト遷移/クロスサイト遷移、サブドメイン変更、パス変更）を1つずつ変えて差分を見る
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/cookie_attributes 2>/dev/null
    cd ~/keda_evidence/cookie_attributes
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可されたスコープ** のみ
      - 観測は **最小限の差分セット** のみ
      - Cookie値そのものは秘匿情報になり得るため、共有・保存・提出時の扱いはルールに従う
  - 相関キー（最低限）を作る（後で必ず効く）
    - Host、Cookie名、属性（Secure/HttpOnly/SameSite/Domain/Path）、送信条件（HTTPS/クロスサイト/サブドメイン/パス）、送信有無（yes/no/unknown）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は"手段"であり"結論"ではない。必ず「何を観測している例か」を添える。

~~~~
# 例：ログイン直後のレスポンスで Set-Cookie を観測
curl -i -L https://example.com/login -d "username=test&password=test"

# 例：条件を変えてCookie送信の有無を比較
curl -i https://example.com/api/me -H "Cookie: session=..."
curl -i http://example.com/api/me -H "Cookie: session=..."
~~~~

- この例で観測していること：
  - Cookieがどの条件で送られるか（HTTPS/HTTP、クロスサイト/同一サイト、サブドメイン/パス）
- 出力のどこを見るか（注目点）：
  - Set-Cookieヘッダの属性（Secure、HttpOnly、SameSite、Domain、Path、Expires/Max-Age）
  - Cookieヘッダの送信有無（条件差による差分）
- この例が使えないケース（前提が崩れるケース）：
  - JS必須/SSO必須の場合、curlだけでは成立しない（ブラウザ+HAR/Proxyで観測へ）

## 観測が失敗した場合
- 変数を1つに絞り、差分が出る条件を再設定する
- HARが取れない場合は、画面遷移とレスポンスのスクショで代替する
- ログ/設定が見られるなら、挙動の根拠として添える

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：V3（Session Management）を中心に、V2（Authentication）/ V4（Access Control）/ V7（Error Handling & Logging）へ接続する。Cookie属性は「セッションの守り」だけでなく「境界の設計（どこで送られるか）」そのもの。
  - 該当要件（可能ならID）：V3（Session Management）、V2（Authentication）
  - このファイルの内容が「満たす/破れる」ポイント：
    - 満たす：Cookie属性の境界を観測で確定し、以後の検証観点を外さないための基盤。
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：WSTG-SESS（Session Management）/ WSTG-ATHN（Authentication）で、Cookieが"どの条件で送信されるか"を観測し、差分で結論を出すための前提。
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：Cookie送信条件の観測と理解
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Vulnerability Analysis（成立条件の切り分け）→ Exploitation（再現）→ Reporting（根拠提示）の品質を上げる。Cookie属性は"推測"を減らし、通信差分で説明できる。
  - 前後フェーズとの繋がり（1行）：成立条件の切り分け→再現→根拠提示の品質を上げる。
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Credential Access / Collection / Defense Evasion
  - 攻撃者の目的（この技術が支える意図）：Cookie保護が弱いとセッション再利用や不正操作に繋がる。逆に強い場合は攻撃者の次の手が変わる（判断材料）。
  - 参照：https://attack.mitre.org/tactics/TA0006/（Credential Access）、https://attack.mitre.org/tactics/TA0009/（Collection）、https://attack.mitre.org/tactics/TA0005/（Defense Evasion）

## 参考（必要最小限）
- OWASP Application Security Verification Standard: https://github.com/OWASP/ASVS
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- PTES (Penetration Testing Execution Standard): https://pentest-standard.readthedocs.io/
- MITRE ATT&CK: https://attack.mitre.org/

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`01_topics/02_web/02_authn_00_認証・セッション・トークン.md`
- 関連 labs：`04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
- 関連 labs：`04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`

---

## 深掘りリンク（最大8）
- `01_topics/02_web/02_authn_00_認証・セッション・トークン.md`
- `01_topics/02_web/02_authn_02_session_lifecycle（更新_失効_固定化_ローテーション）.md`
- `01_topics/02_web/02_authn_03_token設計（Bearer_JWT_Refresh_Rotation）.md`
- `01_topics/02_web/05_input_07_csrf_01_token（synchronizer_double_submit）.md`
- `01_topics/02_web/05_input_07_csrf_02_samesite（cookie_credential）.md`
- `01_topics/02_web/06_config_01_CORSと信頼境界（Origin_資格情報_プリフライト）.md`
- `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
- `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`

---
