## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS
  - 満たす/破れる点：APIが「Cookie認証（ブラウザが自動付与）」を採る場合、UI同様にCSRF境界を持つ。CORSは“読み取り制御”であり、CSRF（書き込み/状態変更）対策ではないため、トークン/Fetch Metadata/重要操作の再認証などを含む層で閉じる必要がある
  - 例外設計：SPA/モバイル/外部連携の要件で `SameSite=None` や `credentials` が必要になる局面ほど、CSRFの成立条件が復活しやすい（= APIにこそCSRF設計が要る）
- WSTG
  - CSRF（WSTG-SESS-05）をAPIにも拡張して適用：状態変更APIが(1)トークン等で守られているか、(2)Cookieがクロスサイトで付く条件が残っていないか、(3)例外パス（JSON/アップロード/旧API）に抜けがないかを観測で確定する
- PTES
  - Vulnerability Analysis：API境界（認証方式・CORS・Cookie属性・Fetch Metadata）をモデル化 → Exploitation：成立根拠は「クロスサイトから“送れる形”で状態変更が受理される」差分の証拠化 → Reporting：CORS誤解（“CORS入れてるから安全”）を設計言語に直して是正
- MITRE ATT&CK
  - 位置づけ：Web誘導を起点に被害者ブラウザで操作を走らせる導線は Drive-by Compromise（T1189）と接続して説明可能（= “閲覧/誘導”が入口）

---

## タイトル
API CSRF（CORS / JSON CSRF）境界モデル：送れるのに読めない、を誤解しない

## 目的（この技術で到達する状態）
- 「APIはCORSがあるからCSRF不要」という誤解を排除し、次の境界で判断できる
  1) **送信境界**：攻撃者オリジンから、ブラウザが“状態変更リクエストを送れるか”
  2) **資格情報境界**：その送信にCookie等の資格情報が付くか（SameSite/credentials/ドメイン）
  3) **受理境界**：サーバが受理する条件が何か（CSRFトークン / Fetch Metadata / Origin/Referer 等）
  4) **読取境界**：CORSで“レスポンスが読めるか”は別問題（CSRFは読めなくても成立する）
- 実務で次を即断できる
  - APIの認証方式（Cookie / Bearer）ごとに、CSRF設計が必要な範囲を切り分けられる
  - 「JSONだから安全」「application/jsonだから外部から送れない」といった誤解を、CORS/プリフライト/受理条件の観測で潰せる
  - 防御は CORS ではなく、トークン/Fetch Metadata/重要操作の再認証 で閉じるべきだと説明できる

---

## 前提（最重要の誤解を先に潰す）
### 1) CORSは“CSRF対策ではない”
- PortSwiggerは明示的に「CORSはCSRFの保護ではない」と述べる（CORSは“読み取り”の制御）
- つまり「攻撃者がレスポンスを読めない」だけでは、状態変更（書き込み）は止まらない

### 2) APIのCSRF要否は“認証方式”で決まる
- Cookie（セッション/リフレッシュ）が自動付与される設計は、APIでもCSRF境界を持つ
- Authorization: Bearer をJSが明示付与する設計は、一般にCSRFは成立しにくい（代わりにXSS/トークン窃取が主戦場）
  - ただし「BearerをCookieに入れている」「SameSite=Noneで共有」等をやるとCSRF側へ戻る

---

## 境界モデル（API CSRFの“成立根拠”を構造化）
### 1) 送信境界：攻撃者オリジンから“送れる”形の整理
- ブラウザはクロスサイトでもHTTPリクエスト自体は発生し得る（フォーム送信、タグ、遷移、fetch等）
- CORSは“クロスオリジンでレスポンスをJSが読めるか”を制御する仕組みであり、送信を止めない（= CSRFの本質）

### 2) 資格情報境界：Cookieが付くか（SameSite/credentials）
- Cookieが付くなら、サーバは“本人操作”と誤認し得る（CSRF条件が揃う）
- ここで SameSite（Lax/Strict/None）と、API呼出しでのcredentials（withCredentials/credentials: include）が絡む  
  - CORSプリフライトは資格情報を含まない（仕様上の制約）
  - ただし“実リクエスト”は、許可されれば資格情報付きで送られうる（= 重要なのは実リクエストの受理条件）

### 3) 受理境界：サーバが何で“本人性”を再確立しているか
- トークン（Synchronizer / Double Submit）
- Fetch Metadata（Sec-Fetch-Site等）
  - OWASPはFetch Metadata（Sec-Fetch-*）を「クロスサイト要求を落とす追加の層」として位置づけている
  - MDNもSec-Fetch-SiteをCSRF緩和に使えると説明している
  - 仕様根拠（W3C Fetch Metadata）

### 4) 読取境界：CORS misconfig は“別の破壊”を起こす
- CORSが誤設定（例：Origin反射 + Allow-Credentials）だと、攻撃者はレスポンスを読める＝データ窃取/CSRFトークンの読み取りが可能になり、CSRF防御を迂回しやすくなる
- よって「CSRF（書き込み）」と「CORS（読み取り）」は別問題だが、組み合わさると被害が増幅する

---

## JSON CSRF（“JSONだから安全”が崩れる典型パターン）
> ここは“攻撃手順”ではなく、診断で見るべき成立根拠（受理条件の欠陥）を列挙する

### パターンA：JSON専用のつもりが、別Content-Typeでも受理している
- 例：サーバが Content-Type を厳密に見ずに body をJSONとして解釈する
- 結果：クロスサイトから“送れる形”が増える（フォーム/単純リクエスト文脈でも到達し得る）

### パターンB：メソッド/経路の例外（GETで状態変更、旧API、互換パス）
- “JSON APIだからPOSTだけ”の前提が崩れると、SameSiteやプリフライトの期待が外れる
- 結果：状態変更が意図せず到達可能になる（= CSRF成立根拠）

### パターンC：GraphQL/検索APIで副作用が混じる
- “queryは安全”のつもりでも、mutation相当や状態変更が混ざると境界が崩れる
- 結果：防御（トークン/FETCH metadata）の適用漏れが起きやすい

---

## 観測ポイント（診断で必ず取る“最小差分セット”）
### 1) APIの認証方式を確定（ここが分岐の起点）
- Cookie（session/refresh）が状態変更APIに付いているか
- Authorizationヘッダ主体か（フロントが都度付与か）
- 併用か（“一部だけCookie”が最も事故りやすい）

### 2) 状態変更APIの棚卸し（UIに出ない操作も含む）
- PUT/PATCH/POST/DELETEだけでなく、RPC形式（/action/execute 等）も含める
- “同じ業務操作”が複数APIで実行できないか（旧v1、管理系、バッチ系）

### 3) CSRF対策の種類と適用範囲を確定（抜け探索）
- トークンが必要か（欠落/不一致で拒否されるか）
- Fetch Metadata（Sec-Fetch-Site等）を見て落としているか
- Origin/Referer検証の有無（補助層として評価。ただし単独依存は危険）

### 4) CORS設定を“読取境界”として別枠で評価
- Access-Control-Allow-Origin が反射/過広範になっていないか
- Access-Control-Allow-Credentials が true のとき、許可オリジンが過広範だと危険（読取可能化）
- “CORSが危険＝CSRFが危険”ではないが、CSRFトークンをレスポンスから読めるならCSRFの難易度は急落する

---

## 結果の意味（状態としての判定）
### 状態A：APIでもCSRF境界が閉じている
- Cookie認証APIが、トークン/Fetch Metadata等で状態変更を確実に拒否する
- CORSは必要最小限（許可オリジンが限定、credentials運用が合理的）
- 重要操作は再認証/二次確認など、別境界でも閉じている（CSRFは外周だけでは止まらない）

### 状態B：CSRFが成立し得る（最頻）
- 状態変更APIでトークン検証が抜けている（UIは守っているがAPIが抜ける、など）
- “JSONだから外部から送れない”前提で設計しており、実際は別形で受理している（Content-Type/メソッド/互換パス）
- Fetch Metadata/Origin検証が無く、SameSite=None 等でCookieがクロスサイト送信される条件が残っている

### 状態C：CORS誤設定が重なり、被害が増幅
- CORS misconfig によりレスポンスが読める → CSRFトークンやユーザ情報の読み取りが可能になり、CSRF防御の迂回が容易になる

---

## 攻撃者視点での利用（“攻撃より”だが、作り方ではなく優先度を固定）
- まず見る：Cookie認証の状態変更API（特に `SameSite=None` を要求する要件がある領域）
- 次に見る：CORSで credentials を許容しているAPI（反射/過広範なら“読取”まで可能）
- 最後に見る：トークンがあるのに、トークンを返すAPIがCORSで読める（= 防御層を自分で開けている）

---

## 次に試すこと（仮説A/B：条件で手が変わる）
### 仮説A：APIがCookie認証（セッション）で動いている
- 次の一手
  1) 状態変更APIにCSRF対策があるか（トークン/Fetch Metadata）を横断で確認
  2) “UIは守ってるがAPIが抜ける”を優先的に疑う（実務で多い）
  3) SameSite/Domain/Pathの境界が広すぎないか（サブドメイン共有は事故要因）

### 仮説B：APIがBearer（Authorization）主体で動いている
- 次の一手
  1) 本当にCookieで権限が付いていないか（混在していないか）を確認
  2) CSRFではなく、XSS/トークン保管（localStorage等）側の境界（別ファイル）へ寄せる

### 仮説C：CORSが緩い/不明
- 次の一手
  1) “読めるか”の評価を分離して実施（CORSはCSRF防御ではない）
  2) credentials=true の許可オリジンが限定されているか、反射していないかを確認
  3) 読めるなら、CSRFトークン/ユーザ情報/APIキーなどの露出面（影響）を再評価する

---

## 防御設計（実務で効く順：API向けに再整理）
1) 状態変更は必ず“サーバで”本人性を再確立
- CSRFトークン（Synchronizer/Double Submit）をAPIにも適用（例外を作らない）
- Fetch Metadata（Sec-Fetch-Site など）で cross-site を早期遮断する層を追加

2) Cookie設計を見直す（CSRFの成立条件を減らす）
- SameSiteを適切に（要件でNoneが必要なら、その分トークン/再認証を強化）
- Domain/Pathを狭め、サブドメイン共有を最小化

3) CORSは“最小許可”で運用（読取境界の防御）
- 許可オリジンを限定し、安易なOrigin反射をしない
- credentials を許可するなら、オリジンの許可条件を厳密に（読取可能化は影響が大きい）

---

## 手を動かす検証（Labs連動：API CSRFの事故を再現できる形に）
- 追加候補Lab
  - `04_labs/02_web/05_input/07_csrf_api_cors_json_boundary/`
- 最小構成（現実寄り）
  - Cookie認証API（状態変更）＋ Bearer認証API（比較用）
  - CORS：安全設定（限定オリジン）／危険設定（反射 + credentials）を切替
  - CSRF防御：トークン無し→トークン有り→Fetch Metadata追加、の順で差分を取る
- 取得する証跡
  - Set-Cookie、CORSヘッダ一式、Sec-Fetch-* の到達、反映結果（状態変化）

---

## コマンド/例（例示は最小限：観測の形だけ）
~~~~
# 観測目的：CORSは“送信を止めない”ので、状態変更が受理される条件（トークン/Fetch Metadata）を確認する
# 1) 状態変更APIに、CSRFトークンが必須か（欠落/不一致で拒否されるか）
# 2) リクエストに Sec-Fetch-Site 等が来ているか、サーバが cross-site を拒否しているか
# 3) CORSヘッダが credentials を許可していないか（読取境界の評価）
~~~~

---

## 参考（一次情報に近いもの中心）
- OWASP WSTG：Testing for CSRF（WSTG-SESS-05）
- OWASP CSRF Prevention Cheat Sheet（Fetch Metadata含む）
- MDN：CSRF（Sec-Fetch-Siteによる緩和の説明）
- W3C：Fetch Metadata Request Headers（仕様根拠）
- MDN：CORS（プリフライトとcredentialsの原則）
- PortSwigger：CORSはCSRF防御ではない（明示）
- PortSwigger Lab：Origin反射などのCORS誤設定例（影響理解の補助）

---

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/06_config_01_CORSと信頼境界（Origin_資格情報_プリフライト）.md`
- `01_topics/02_web/05_input_07_csrf_01_token（synchronizer_double_submit）.md`
- `01_topics/02_web/05_input_07_csrf_02_samesite（cookie_credential）.md`

---

## 次（作成候補順）
- `01_topics/02_web/05_input_08_xxe_01_parser（doctype_entity）.md`
