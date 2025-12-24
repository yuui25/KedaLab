# 02_authn_05_sso_saml_flow観測（assertion_audience_recipient）.md

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS：V2（Authentication）/ V3（Session Management）を中心に「外部IdPとの信頼境界」「認証結果（属性/セッション）の受け渡し」「失効/ログアウト境界」を扱う。ASVSはSAML固有の攻撃面を細粒度で網羅しない可能性があるため、SAML Security Cheat Sheet等で補完し、ASVS側は“境界の検証”として落とす。
- WSTG：SAMLは認証（WSTG-ATHN）だけでなく、Identity Management（IdM）として“外部連携の成立点”を観測し、AuthnRequest/Response の検証点（署名/宛先/相関）を差分で確定する。
- PTES：Intelligence Gathering（IdP/SP/ACS/境界特定）→ Vulnerability Analysis（成立点と検証点の切り分け）→ Exploitation（最小差分の再現）→ Reporting（証跡）に直結。
- MITRE ATT&CK：T1606.002（Forge Web Credentials: SAML Tokens）、T1078（Valid Accounts）、T1199（Trusted Relationship）を“目的”として位置づける。SAMLフロー観測は「偽造/再利用の窓」と「信頼境界の固定点」を確定する作業。

## 目的（この技術で到達する状態）
- SAMLの用語暗記ではなく、**どの通信で本人性が成立し、どの境界（資産/信頼/権限）へ伝播するか** を観測で説明できる。
- `SAMLRequest` / `SAMLResponse` を **「存在する/しない」「どこに出る/出ない」** で確定し、次の検証（MFA、属性マッピング、ログアウト境界、クライアント保存）に繋げられる。
- Assertion内の最重要フィールド（Audience/Recipient/InResponseTo/NotOnOrAfter/Issuer/NameID/Attributes/署名位置）を、証跡（HAR/Proxyログ/デコード結果）付きで整理できる。

## 前提（対象・範囲・想定）
- 対象：許可された範囲のWebアプリ（SP: Service Provider）と、連携するIdP（Identity Provider）。
- 想定プロファイル：Browser SSO（Redirect/POST Binding）が主。SP-initiated / IdP-initiated の両方があり得る。
- 依存（観測基盤）
  - `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
  - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- 前段の接続（境界の前提）
  - `01_topics/02_web/02_authn_01_cookie属性と境界（Secure_HttpOnly_SameSite_Path_Domain）.md`
  - `01_topics/02_web/02_authn_02_session_lifecycle（更新_失効_固定化_ローテーション）.md`
  - `01_topics/01_asm-osint/03_http_観測（ヘッダ/挙動）と意味.md`（302/Location/Set-Cookie観測）

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) 入口・越境点・戻り点（境界）を確定する
- 入口（SP側）：ログイン導線（どのURLでSAML誘導が始まるか）
- 越境点（IdP側）：IdPドメインへ遷移する瞬間（302 Location / HTML form post 等）
- 戻り点（SP側）：ACS（Assertion Consumer Service）に到達する瞬間（多くは POST + `SAMLResponse`）
- ここで確定すること
  - SPドメイン / IdPドメイン / ACS URL（callback相当）
  - 「どのレスポンスでSP側セッションCookieが発行されるか」

### 2) AuthnRequest（SAMLRequest）の観測：相関キーと宛先を押さえる
典型：SP→IdPへ 302 で遷移し、URLに `SAMLRequest` と `RelayState` が載る。
観測したい主項目（“ある/ない”をまず確定）
- Request ID（後でResponseの `InResponseTo` と相関する）
- `Destination`（どのIdPエンドポイントへ送る前提か）
- `AssertionConsumerServiceURL` / `ProtocolBinding`（戻り先とBinding）
- `Issuer`（SPの識別子）
- `ForceAuthn` / `IsPassive`（SSO継続の扱いに影響）
- `RequestedAuthnContext`（MFAや強要件と絡む可能性）
- `RelayState`（フロー混線/オープンリダイレクト/状態管理に絡む）

### 3) Response（SAMLResponse）の観測：POST先と“検証すべき境界”を押さえる
典型：IdP→SPのACSへ POST し、form-dataに `SAMLResponse` と `RelayState` が載る。
観測したい主項目
- POST先URL：ACSそのもの（信頼境界の固定点）
- Response側
  - `Destination`（このSPへ送る前提か）
  - `InResponseTo`（AuthnRequestのIDとの相関）
  - `Issuer`（このIdPが発行したと言える根拠）
- Assertion側（認証結果の“中身”）
  - `Subject/NameID`（ユーザー識別子）
  - `SubjectConfirmationData@Recipient`（宛先＝ACS）
  - `SubjectConfirmationData@InResponseTo`（相関）
  - `Conditions@NotBefore` / `NotOnOrAfter`（再利用窓）
  - `AudienceRestriction/Audience`（このSP向けか）
  - `AttributeStatement`（メール/グループ/ロール等。権限伝播の入口）
  - `AuthnStatement`（セッション継続/ログアウト境界に絡む可能性）

### 4) 署名の位置と“何に対する完全性か”を観測する
- 署名対象：Responseが署名されているのか、Assertionが署名されているのか（両方/片方）
- KeyInfo：証明書/鍵がどこに現れるか（ただし信頼はメタデータに依存するため「見えた=信頼」ではない）
- 観測の結論（例）
  - 「Assertion署名あり」→ 少なくとも“中身の改ざん耐性”を意図している
  - 「Responseのみ署名」→ 実装次第で“署名と参照の結び付き”が主戦場になり得る（XSW等の論点）

### 5) セッション橋渡し（IdP→SP→アプリ状態）を確定する
- `SAMLResponse` の受理直後に、SPドメインで **Set-Cookie** が出るか
- SPがアプリ独自セッションへ変換しているか、SAML属性を直接“ログイン済み”判定に使っているか
- Cookie属性（SameSite/Domain/Path）により、SAMLのPOST戻り（クロスサイト）で送信条件が変わっていないか（Cookie境界と結合）

### 6) 観測の最小セット（証跡として残す）
- HAR（ブラウザ）＋ Proxyログ（Location/POST/Set-Cookie）＋ デコードしたXML（マスク済み）
- 証跡メモ（固定）
  - SP/IdP/ACSのURL（ドメイン境界）
  - AuthnRequest ID と Response InResponseTo の相関（yes/no/unknown）
  - Audience / Recipient / Destination の一致有無（yes/no/unknown）
  - 署名の位置（Response/Assertion/両方/なし）
  - 属性（権限伝播に関係しそうなもの：role/group/email など“種類だけ”）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える（観測で断定できる）
  - SAMLが「どのBinding/どの越境点」で動いているか（Redirect/POST、SP-initiated/IdP-initiatedの痕跡）
  - SPのログイン成立点（どのレスポンスでSP側セッションが確定するか）
  - Audience/Recipient/Destination/InResponseTo が存在するか（まずyes/no）
  - 署名が存在するか／どこに掛かっているか（Response/Assertion）
  - Assertionが暗号化されているか（暗号化なら“中身は見えないが、暗号化の有無は観測できる”）
- 推定（追加観測で強くなる）
  - それらが“検証されているか”（改変1点差分で拒否されるか、ログに残るか、unknown を潰せるか）
  - IdP-initiated（unsolicited）を許容するか（相関の有無と挙動で判断）
- 言えない（この段階の限界）
  - SP/IdP内部のメタデータ設定（許可ACS一覧、証明書ローテーション運用、署名検証実装の詳細）
  - “安全/危険”の断定（まず境界と検証点の所在を固め、次で差分検証する）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- 優先度（最初に固める判断材料）
  1) **相関（InResponseTo）と宛先（Recipient/Destination/Audience）の所在**：ここが弱いと「再利用/注入/別SP向けAssertionの受理」に繋がる方向へ広がる。
  2) **署名の位置と検証対象**：署名がある=安全ではない。実装が“どのノードを参照して検証しているか”が主戦場（XSW系の論点に直結）。
  3) **属性が権限へどう伝播するか**：role/group等がそのままアプリ権限に結びつくなら、次は AuthZ（IDOR/BOLA）へ直結する。
  4) **IdP/信頼境界の価値**：IdP側の鍵や信頼が破られると、SAMLトークン偽造（Golden SAML等）が“横展開の入口”になる（攻撃者の狙いが変わる）。
- 具体的な攻め筋の“選び方”（状態で次の手が変わる）
  - 「InResponseToが無い/相関が薄い」：unsolicited response 受理・リプレイ（短時間）を疑う。まずは“拒否されるか”を最小差分で確認。
  - 「Audience/Recipient/Destination があるが検証不明」：改変1点差分で unknown を潰す（失敗する＝検証されている、成功する＝重大な境界欠落）。
  - 「署名があるがResponseのみ」：Assertion参照の扱いにより、XSW系の成立条件が変わる。まず“複数Assertion/複数Signature”の扱いを観測で把握。
  - 「属性が多い（role/group等）」：AuthZや権限伝播の検証を優先し、SAMLは“入口の鍵”として位置づける。

## 次に試すこと（仮説A/Bの分岐と検証）
### 仮説A：SP-initiatedで相関・宛先・署名検証が強い（一般的な堅い実装）
- 次に試すこと
  - SAML属性（role/group/email等）が、アプリ権限にどう結びつくか（AuthZへの接続点）を特定する
  - ログアウト境界（SPログアウト/IdPログアウト/SLO）と、セッション失効（Cookie/サーバ）を観測で分離する
  - `RequestedAuthnContext` がMFA相当の要求に使われているか（次のMFAユニットへ接続）
- 期待する観測
  - “SSOは入口、主戦場は権限とセッション寿命”という結論が証跡付きで言える

### 仮説B：IdP-initiated（unsolicited）や相関が弱く、再利用/注入の窓が疑われる
- 次に試すこと（安全な最小差分）
  - デコードしたSAMLResponseを**オフライン**で確認し、相関/宛先/期限の“存在”をyes/noで固める
  - 影響が許される範囲で、**1点だけ改変**（例：Audience だけ、Recipient だけ）して拒否されるか確認し、unknown を潰す
- 期待する観測
  - “どの検証がサーバで効いているか”が分かり、以降の検証（MFA/属性/セッション）に無駄が出ない

### 仮説C：署名の扱いが曖昧（署名なし受理/署名あるのに改変が通る等）
- 次に試すこと（優先度高）
  - 「署名が無い/弱い/参照がズレている」可能性を、改変の拒否挙動で最小確認する（大量試行しない）
  - 証跡として、受理/拒否のHTTPステータス、エラー画面、ログ（可能なら）を揃える
- 期待する観測
  - “検証点の欠落”を推測ではなく差分で説明できる

### コマンド/リクエスト例（例示は最小限・意味が主）
~~~~
# 目的：SAMLResponse（Base64）をオフラインでデコードして「何が入っているか」を観測する
# - まずは Audience / Recipient / InResponseTo / NotOnOrAfter / 署名位置 を“存在確認”する
python - <<'PY'
import base64, sys
b64 = sys.stdin.read().strip()
xml = base64.b64decode(b64 + '===')  # 端末貼り付け時のパディング崩れに耐える程度
print(xml.decode('utf-8', errors='replace'))
PY
~~~~

## 参考（必要最小限）
- OWASP Cheat Sheet Series：SAML Security Cheat Sheet（InResponseTo/署名検証/XSW等の検証点）
- MITRE ATT&CK：T1606.002 Forge Web Credentials: SAML Tokens / T1078 Valid Accounts / T1199 Trusted Relationship
- OWASP WSTG：Authentication Testing / Identity Management Testing（SAMLを“外部連携の認証境界”として落とす）
- ASVS：SAML固有の粒度が薄い場合があるため、ASVSは“認証/セッション/境界”として適用し、SAMLの検証点はCheat Sheet等で補完する
