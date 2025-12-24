# 05_input_07_csrf_02_samesite（cookie_credential）

## 目的（この技術で到達する状態）
- SameSiteを「付ければCSRF対策」ではなく、以下の“境界”として説明できる
  1) **サイト境界**：same-site / cross-site をブラウザがどう判定し、Cookieを送る/送らないを決める
  2) **資格情報境界**：Cookieが付く条件（SameSite＋Secure＋送信形態（ナビゲーション/サブリクエスト）＋credentials）を整理する
  3) **業務影響境界**：SameSiteで止まるCSRFと止まらないCSRF（特にLax/Top-level navigation/GET状態変更/例外導線）を区別する
- 実務判断として、次を即断できる
  - 重要Cookie（セッション等）を `Lax/Strict/None` のどれに置くべきか（機能要件と衝突する点も含めて）
  - SameSiteだけに依存した設計が危険な理由（“部分防御”であること）を根拠付きで説明できる

---

## 前提（対象・範囲・想定）
- 対象：ブラウザの資格情報（Cookie）が「クロスサイト起点のリクエスト」に自動付与される境界を、Cookie属性（SameSite/Secure/HttpOnly/Domain/Path）と送信条件（credentials）で制御する、セッション等の重要Cookie、CSRF用トークンCookie
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - OWASPはSameSiteを「CSRFを軽減するCookie属性」と位置づけるが、単独で完結する設計ではない（トークン等のサーバ検証が基本）、SameSiteはRFC6265bis（HTTP cookies拡張）で定義され、ブラウザがクロスサイト時にCookieを送るかを制御する、値は `Strict / Lax / None` の3種（ブラウザは設定と文脈により送信可否を変える）、現実のブラウザ挙動として「SameSite未指定は Lax 扱い」が基本（この既定値を前提に"未設定だから安全/危険"を誤判定しない）
- できること/やらないこと（安全に検証する範囲）：
  - できること：サイト境界：same-site / cross-site をブラウザがどう判定し、Cookieを送る/送らないを決める、資格情報境界：Cookieが付く条件（SameSite＋Secure＋送信形態（ナビゲーション/サブリクエスト）＋credentials）を整理する、業務影響境界：SameSiteで止まるCSRFと止まらないCSRF（特にLax/Top-level navigation/GET状態変更/例外導線）を区別する、重要Cookie（セッション等）を `Lax/Strict/None` のどれに置くべきか（機能要件と衝突する点も含めて）、SameSiteだけに依存した設計が危険な理由（"部分防御"であること）を根拠付きで説明できる
  - やらないこと：影響実証は最小限（成立根拠の確定まで）。高負荷/外部到達/大量出力は避ける
- 依存する前提知識（必要最小限）：
  - `01_topics/02_web/05_input_00_入力→実行境界（テンプレ デシリアライズ等）.md`
  - `01_topics/02_web/02_authn_01_cookie属性と境界（Secure_HttpOnly_SameSite_Path_Domain）.md`
  - `01_topics/02_web/05_input_07_csrf_01_token（synchronizer_double_submit）.md`
  - `01_topics/02_web/05_input_07_csrf_03_api（cors_json_csrf）.md`
  - `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
  - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`

## 境界モデル（Cookieが付く/付かないを決める要因）
### 1) 属性境界：SameSiteの意味（設計の言語化）
- Strict
  - 原則：クロスサイト起点ではCookieを送らない（防御強いが、外部からの導線・連携に影響が出やすい）
- Lax
  - 原則：クロスサイトの“多くのケース”でCookie送信を抑えるが、Strictほどではない（要件と両立しやすい）
- None
  - 原則：従来通りクロスサイトでも送る（= CSRF成立条件を残す）
  - 実務上：`SameSite=None` を使うなら `Secure` が必須（ブラウザ要件として扱われる）

### 2) 既定値境界：SameSite未指定の扱い
- 現実のブラウザ挙動として「SameSite未指定は Lax 扱い」が基本（この既定値を前提に“未設定だから安全/危険”を誤判定しない）

### 3) 文脈境界：同じクロスサイトでもCookie送信条件が違う
SameSiteは“クロスサイトかどうか”だけでなく、リクエストがどの文脈で発生したか（ユーザ操作/ナビゲーション/サブリクエスト等）で効き方が変わる。
- ここが、診断と設計で最も誤解が起きる点（「POSTは防げるがGET状態変更は残る」等が典型）

### 4) 資格情報境界：Cookie送信とcredentials
- Cookieはブラウザが“自動付与”する資格情報であり、SameSiteはその自動付与条件を狭める仕組み
- ただし、APIやSPAでは `credentials`（cookieを付けるか）や CORS（資格情報付き許可）が別レイヤとして存在し、SameSiteの外側で“付く/付かない”が揺れる
  - この論点は `05_input_07_csrf_03_api（cors_json_csrf）` と接続する（本ファイルでは「Cookieが付く条件をSameSiteだけで完結させない」ことが主眼）

---

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が"確定"できるか：
  - サイト境界：same-site / cross-site をブラウザがどう判定し、Cookieを送る/送らないを決める、資格情報境界：Cookieが付く条件（SameSite＋Secure＋送信形態（ナビゲーション/サブリクエスト）＋credentials）を整理する、業務影響境界：SameSiteで止まるCSRFと止まらないCSRF（特にLax/Top-level navigation/GET状態変更/例外導線）を区別する、重要Cookie（セッション等）を `Lax/Strict/None` のどれに置くべきか（機能要件と衝突する点も含めて）
- 何が"推定"できるか（推定の根拠/前提）：
  - まず Boolean oracle（クロスサイトでCookieが付く/付かないの差分）で確定する（推奨）
  - 重要Cookieの棚卸し（セッション/リフレッシュ/CSRF用）：`Set-Cookie` で以下を必ず記録する：SameSite（Strict/Lax/None/未指定）、Secure（特に None の場合は必須）、HttpOnly（CSRFではなくXSS面の層だが、Double Submit設計と衝突する）、Domain/Path（送信範囲＝影響範囲。サブドメイン共有は境界が広がる）
  - "未指定＝Lax扱い"の可能性も含め、実ブラウザ挙動（観測）で確定する
- 何は"言えない"か（不足情報・観測限界）：
  - "任意操作が可能"の断定（環境/設定/権限で差が大きい）、"DoSが可能"の断定（性能試験は別枠、契約と安全配慮が必要）
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：SameSiteが"意図通り"に境界を作れている → セッション等の重要Cookieが `Lax` 以上で運用され、クロスサイト起点の状態変更が"Cookie不送信"で拒否される（= CSRFの成立条件が削られている）、ただし、重要操作はトークン等のサーバ検証で最後に閉じる（SameSiteはあくまで外周の層）
  - パターンB：SameSiteが"要件衝突"で None に落ちている（典型） → SSO/外部埋め込み/クロスサイト連携の要件により `SameSite=None` が必要になり、セッションCookieがクロスサイトで送られる、その場合、CSRF成立条件が復活するため、トークン方式（Synchronizer/Double Submit）や重要操作の再認証が必須になる
  - パターンC：SameSiteは付いているが"例外パス/設計不備"でCSRFが残る → Laxでも通る導線（例：トップレベル遷移等）に状態変更が乗っている、GETで状態変更ができる、またはメソッド・経路の例外（旧API、互換エンドポイント）で対策が抜けている、SameSiteに依存しすぎてトークン検証が省略されている（最も危険：ブラウザ差分/例外導線で破綻する）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す"狙い目"：
  - セッション等の重要Cookie、CSRF用トークンCookie、状態変更が起きる操作（メール変更、パスワード変更、2FA有効化、支払先追加、送金、権限付与、外部連携追加、Webhook設定、APIキー再発行）
- 優先度の付け方（時間制約がある場合の順序）：
  - SameSiteは"部分防御"なので、攻撃者は次を探す（= 診断ではここを優先する）：`SameSite=None` のセッションCookieが存在する領域（埋め込み/外部連携の都合で多い）、`Lax/Strict` でも成立する例外導線（文脈差分、旧機能、GET状態変更など）、Cookieが付かなくても成立する設計ミス（トークン未検証、本人性の誤判定）
- 代表的な攻め筋（この観測から自然に繋がるもの）：
  - 攻め筋1：SameSiteが"要件衝突"で None に落ちている → SSO/外部埋め込み/クロスサイト連携の要件により `SameSite=None` が必要になり、セッションCookieがクロスサイトで送られる
  - 攻め筋2：SameSiteは付いているが"例外パス/設計不備"でCSRFが残る → Laxでも通る導線（例：トップレベル遷移等）に状態変更が乗っている、GETで状態変更ができる、またはメソッド・経路の例外（旧API、互換エンドポイント）で対策が抜けている
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）：
  - PortSwiggerもSameSiteはCSRF等への"部分的保護"と整理し、回避可能性を前提に扱っている（= SameSite単独を最終防御にしない）、SameSiteは効果範囲が限定的である点を明示し、重要操作はトークン/再認証/二次確認へ落とす

---

## 観測ポイント（診断で見るべき“最小差分セット”）
### 1) 重要Cookieの棚卸し（セッション/リフレッシュ/CSRF用）
- `Set-Cookie` で以下を必ず記録する
  - SameSite（Strict/Lax/None/未指定）
  - Secure（特に None の場合は必須）
  - HttpOnly（CSRFではなくXSS面の層だが、Double Submit設計と衝突する）
  - Domain/Path（送信範囲＝影響範囲。サブドメイン共有は境界が広がる）
- “未指定＝Lax扱い”の可能性も含め、実ブラウザ挙動（観測）で確定する

### 2) 状態変更エンドポイントの“到達経路”を分類
- どの操作が「トップレベル遷移（リンク）」「サブリクエスト」「AJAX/API」か
- 同一の業務操作が複数経路（旧UI/新UI、v1/v2）で実行できないか

### 3) Cookieが付く/付かないの差分を“根拠”として取る
- 同一操作について
  - 同一サイト起点ではCookieが付く（正常）
  - クロスサイト起点ではCookieが付かない（期待）
  - それでも更新が起きるなら、CSRF防御が破綻（トークン未検証/例外パス）という成立根拠になる
- 重要：ステータスだけで断定しない（反映結果＝状態が変わったかを証拠にする）

---

## 次に試すこと（仮説A/B：条件が違うと次の手が変わる）
### 仮説A：セッションCookieが Lax/Strict で運用されている
- 次の一手
  1) “Laxでも残り得る導線”に状態変更が乗っていないかを点検（GET状態変更、旧エンドポイント、重要操作の例外）
  2) 重要操作にトークン検証があるか確認（SameSiteは外周、最後はサーバ検証）
  3) 同一サイト内でも、サブドメイン共有（Domain広い）で境界が広がっていないかを確認
- 期待する観測
  - 強い：クロスサイトではCookie不送信で拒否＋サーバ側もトークン必須
  - 弱い：Cookieが付かないはずの条件でも処理が通る（トークン不備/例外パス）

### 仮説B：要件により SameSite=None が必要（SSO/埋め込み/外部連携）
- 次の一手
  1) None+Secureが守られているか（Secure欠落は運用崩壊の兆候）
  2) トークン方式（Synchronizer/Double Submit）が全状態変更に適用されているか（抜け探索）
  3) 重要操作は“再認証/二次確認”で閉じているか（トークンだけに寄せない）
- 期待する観測
  - 強い：None運用でもトークン検証が網羅＋重要操作は追加確認
  - 弱い：NoneでCookieがクロスサイト送信され、トークン無し/検証抜けで成立

### 仮説C：SameSite未指定（既定値に依存）または混在している
- 次の一手
  1) 実ブラウザで未指定Cookieが Lax 扱いになっているかを観測で確定
  2) ページ/ドメイン/サブドメインでSameSiteが混在していないか（旧システム・運用UIで多い）
  3) “安全に見えるが、例外パスだけNone/未指定”がないかを重点確認

---

## 手を動かす検証（Labs連動：SameSiteの“効く範囲”を体感で固定）
- 追加候補Lab
  - `04_labs/02_web/05_input/07_csrf_samesite_boundary/`
- 最小構成（現実寄り）
  - 2オリジン（同一サイト / 攻撃者サイト相当）を用意
  - 同一の状態変更を3つ用意（低/中/高）
  - セッションCookieを3パターンで切替（Strict/Lax/None+Secure）
  - 重要操作にはトークン必須の実装も用意し、“SameSiteだけでは足りない”を確認する
- 取得する証跡
  - Set-Cookie（SameSite/Secure/Domain/Path）
  - HAR（同一サイト起点 vs クロスサイト起点でCookieが付く/付かない）
  - 反映結果（DB/APIで状態が変わったか）

---

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は"手段"であり"結論"ではない。必ず「何を観測している例か」を添える。

~~~~
# 観測目的：SameSite属性の付与状況を"証跡として"残す（Set-Cookieの記録）
# 例：レスポンスヘッダに Set-Cookie が複数あり、SameSite が付いている/いないを確認する
# Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax
# Set-Cookie: csrf=...; Secure; SameSite=Strict
# Set-Cookie: legacy=...; SameSite=None; Secure
~~~~

- この例で観測していること：SameSite属性の付与状況、重要Cookieの棚卸し（セッション/リフレッシュ/CSRF用）、Cookie属性（SameSite/Secure/HttpOnly/Domain/Path）と送信条件（credentials）
- 出力のどこを見るか（注目点）：`Set-Cookie` で以下を必ず記録する：SameSite（Strict/Lax/None/未指定）、Secure（特に None の場合は必須）、HttpOnly（CSRFではなくXSS面の層だが、Double Submit設計と衝突する）、Domain/Path（送信範囲＝影響範囲。サブドメイン共有は境界が広がる）
- この例が使えないケース（前提が崩れるケース）：Cookieがそもそも使用されていない場合、または完全に静的なリクエストのみを使用している場合

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：V4 Access Control、V7 Error Handling and Logging
  - 該当要件（可能ならID）：V4.1.1、V4.1.2、V7.4.1
  - このファイルの内容が「満たす/破れる」ポイント：
    - 満たす/破れる点：ブラウザの資格情報（Cookie）が「クロスサイト起点のリクエスト」に自動付与される境界を、Cookie属性（SameSite/Secure/HttpOnly/Domain/Path）と送信条件（credentials）で制御する。SameSiteは"CSRFを減らす層"だが単独では完結しない（重要操作はトークン等のサーバ検証が必要）
- WSTG：
  - 該当カテゴリ/テスト観点：WSTG-SESS-05 Testing for Cross Site Request Forgery
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：
    - CSRFテスト（WSTG-SESS-05）の中で、Cookie属性（SameSite）と「資格情報が付くかどうか」を成立条件として観測し、トークン方式と組み合わせて評価する
- PTES：
  - 該当フェーズ：Vulnerability Analysis、Exploitation、Reporting
  - 前後フェーズとの繋がり（1行）：状態変更面の棚卸し→Cookie属性（SameSite）と送信条件（credentials/CORS）をモデル化→防御層の組合せ（SameSite+Token）を確認し、成立根拠は"クロスサイトでCookieが付く/付かない"の差分と、"付かないはずなのに通る例外パス"の証拠化、SameSiteは効果範囲が限定的である点を明示し、重要操作はトークン/再認証/二次確認へ落とす
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Initial Access / Execution
  - 攻撃者の目的（この技術が支える意図）：ユーザ誘導（リンク/埋め込み）でブラウザにリクエストを起こさせる導線は、攻撃者の初期導線として Drive-by Compromise（T1189）に接続して説明できる（"閲覧を起点に操作を走らせる"）

## 参考（必要最小限）
- OWASP CSRF Prevention Cheat Sheet：SameSiteはCSRF軽減に寄与するが、トークン等の対策と併用する設計が前提
- RFC6265bis（Cookies / SameSite）：SameSite属性の規定（仕様根拠）
- MDN Cookies Guide：SameSite未指定はLax扱い（実装の前提）
- web.dev：SameSite=None は Secure 必須、未指定はLax扱い（ブラウザ現実）

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/05_input_07_csrf_01_token（synchronizer_double_submit）.md`
- `01_topics/02_web/02_authn_01_cookie属性と境界（Secure_HttpOnly_SameSite_Path_Domain）.md`
- `01_topics/02_web/05_input_07_csrf_03_api（cors_json_csrf）.md`

---

## 深掘りリンク（最大8）
- `01_topics/02_web/05_input_00_入力→実行境界（テンプレ デシリアライズ等）.md`
- `01_topics/02_web/05_input_07_csrf_01_token（synchronizer_double_submit）.md`
- `01_topics/02_web/05_input_07_csrf_03_api（cors_json_csrf）.md`
- `01_topics/02_web/02_authn_01_cookie属性と境界（Secure_HttpOnly_SameSite_Path_Domain）.md`
- `01_topics/02_web/06_config_01_CORSと信頼境界（Origin_資格情報_プリフライト）.md`
- `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
- `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
