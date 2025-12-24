## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS
  - 満たす/破れる点：ブラウザの資格情報（Cookie）が「クロスサイト起点のリクエスト」に自動付与される境界を、Cookie属性（SameSite/Secure/HttpOnly/Domain/Path）と送信条件（credentials）で制御する。SameSiteは“CSRFを減らす層”だが単独では完結しない（重要操作はトークン等のサーバ検証が必要）
- WSTG
  - CSRFテスト（WSTG-SESS-05）の中で、Cookie属性（SameSite）と「資格情報が付くかどうか」を成立条件として観測し、トークン方式と組み合わせて評価する
- PTES
  - Vulnerability Analysis：状態変更面の棚卸し→Cookie属性（SameSite）と送信条件（credentials/CORS）をモデル化→防御層の組合せ（SameSite+Token）を確認
  - Exploitation：成立根拠は“クロスサイトでCookieが付く/付かない”の差分と、“付かないはずなのに通る例外パス”の証拠化
  - Reporting：SameSiteは効果範囲が限定的である点を明示し、重要操作はトークン/再認証/二次確認へ落とす
- MITRE ATT&CK
  - 位置づけ：ユーザ誘導（リンク/埋め込み）でブラウザにリクエストを起こさせる導線は、攻撃者の初期導線として Drive-by Compromise（T1189）に接続して説明できる（“閲覧を起点に操作を走らせる”）

---

## タイトル
SameSite（Cookie/Credential）境界モデル：CSRFに効く範囲・効かない範囲

## 目的（この技術で到達する状態）
- SameSiteを「付ければCSRF対策」ではなく、以下の“境界”として説明できる
  1) **サイト境界**：same-site / cross-site をブラウザがどう判定し、Cookieを送る/送らないを決める
  2) **資格情報境界**：Cookieが付く条件（SameSite＋Secure＋送信形態（ナビゲーション/サブリクエスト）＋credentials）を整理する
  3) **業務影響境界**：SameSiteで止まるCSRFと止まらないCSRF（特にLax/Top-level navigation/GET状態変更/例外導線）を区別する
- 実務判断として、次を即断できる
  - 重要Cookie（セッション等）を `Lax/Strict/None` のどれに置くべきか（機能要件と衝突する点も含めて）
  - SameSiteだけに依存した設計が危険な理由（“部分防御”であること）を根拠付きで説明できる

---

## 前提（SameSiteは“部分防御”である）
- OWASPはSameSiteを「CSRFを軽減するCookie属性」と位置づけるが、単独で完結する設計ではない（トークン等のサーバ検証が基本）
- SameSiteはRFC6265bis（HTTP cookies拡張）で定義され、ブラウザがクロスサイト時にCookieを送るかを制御する
- 値は `Strict / Lax / None` の3種（ブラウザは設定と文脈により送信可否を変える）

---

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

## 結果の意味（状態としての判定）
### 状態A：SameSiteが“意図通り”に境界を作れている
- セッション等の重要Cookieが `Lax` 以上で運用され、クロスサイト起点の状態変更が“Cookie不送信”で拒否される（= CSRFの成立条件が削られている）
- ただし、重要操作はトークン等のサーバ検証で最後に閉じる（SameSiteはあくまで外周の層）

### 状態B：SameSiteが“要件衝突”で None に落ちている（典型）
- SSO/外部埋め込み/クロスサイト連携の要件により `SameSite=None` が必要になり、セッションCookieがクロスサイトで送られる
- その場合、CSRF成立条件が復活するため、トークン方式（Synchronizer/Double Submit）や重要操作の再認証が必須になる

### 状態C：SameSiteは付いているが“例外パス/設計不備”でCSRFが残る
- Laxでも通る導線（例：トップレベル遷移等）に状態変更が乗っている
- GETで状態変更ができる、またはメソッド・経路の例外（旧API、互換エンドポイント）で対策が抜けている
- SameSiteに依存しすぎてトークン検証が省略されている（最も危険：ブラウザ差分/例外導線で破綻する）

---

## 攻撃者視点での利用（現実寄り：どこが“残る”か）
- SameSiteは“部分防御”なので、攻撃者は次を探す（= 診断ではここを優先する）
  1) `SameSite=None` のセッションCookieが存在する領域（埋め込み/外部連携の都合で多い）
  2) `Lax/Strict` でも成立する例外導線（文脈差分、旧機能、GET状態変更など）
  3) Cookieが付かなくても成立する設計ミス（トークン未検証、本人性の誤判定）
- PortSwiggerもSameSiteはCSRF等への“部分的保護”と整理し、回避可能性を前提に扱っている（= SameSite単独を最終防御にしない）

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

## コマンド/リクエスト例（例示は最小限：観測の形だけ）
~~~~
# 観測目的：SameSite属性の付与状況を“証跡として”残す（Set-Cookieの記録）
# 例：レスポンスヘッダに Set-Cookie が複数あり、SameSite が付いている/いないを確認する
# Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax
# Set-Cookie: csrf=...; Secure; SameSite=Strict
# Set-Cookie: legacy=...; SameSite=None; Secure
~~~~

---

## 参考（一次情報に近いもの中心）
- OWASP CSRF Prevention Cheat Sheet：SameSiteはCSRF軽減に寄与するが、トークン等の対策と併用する設計が前提
- RFC6265bis（Cookies / SameSite）：SameSite属性の規定（仕様根拠）
- MDN Cookies Guide：SameSite未指定はLax扱い（実装の前提）
- web.dev：SameSite=None は Secure 必須、未指定はLax扱い（ブラウザ現実）
- PortSwigger：SameSiteは部分防御であり、回避・例外を前提に扱う

---

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/05_input_07_csrf_01_token（synchronizer_double_submit）.md`（SameSiteは外周、最後はトークンで閉じる）
- `01_topics/02_web/02_authn_01_cookie属性と境界（Secure_HttpOnly_SameSite_Path_Domain）.md`（Cookie境界の総合）
- `01_topics/02_web/06_config_01_CORSと信頼境界（Origin_資格情報_プリフライト）.md`（credentials/CORSの別レイヤ）

---

## 次（作成候補順）
- `01_topics/02_web/05_input_07_csrf_03_api（cors_json_csrf）.md`
