## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS
  - 破れる：ブラウザ境界（SOP/CORS/CSP）を「サーバ側の防御」と誤認し、(1) CORS誤設定で“読める境界”が崩れる、(2) CSPが緩く“実行境界”が崩れる、(3) SOPの前提（origin/site/opaque origin）を取り違えて“越境が起きる設計”になる。結果として、XSS/データ窃取/セッション悪用/テナント混線の成立条件が揃う。
  - 満たす：SOPを“既定の読み取り境界”として前提化し、CORSは“例外（必要最小限の読める越境）”として仕様化、CSPは“実行と外部接続の最終ゲート”として設計・監視（report-only→強制）する。特に CORS の Vary / キャッシュ混線、CSP の nonce/hash/strict-dynamic、connect-src の外部接続境界を「観測→判断→次の一手」で回せる状態にする。
- WSTG
  - 観点：クライアント側制御（SOP/CORS/CSP）を、(1) ブラウザが拒否しているだけか、(2) サーバが許可しているか、(3) 中継点（CDN/Proxy）が混線させるか、の3層で観測する。単なる“CORSエラーが出た/出ない”ではなく、プリフライト・資格情報・Vary・エラー差分・CSP違反レポートまで含めて成立条件を確定する。
- PTES
  - 位置づけ：情報収集〜脆弱性分析（境界モデル化）→検証（安全な範囲での成立根拠）→侵害評価（影響半径）→報告（設計要件と監視要件）。前後フェーズとの繋がり：`06_config_01_CORS...` や `05_input_06_xss...` で見える兆候を、本ファイルの「境界（SOP/CORS/CSP）」で統一して説明可能にする。
- MITRE ATT&CK
  - 初期侵入/実行：Webの脆弱性悪用（公開アプリ経由）に接続し得る（条件付き）。
  - 目的：Collection（ブラウザ経由のデータ取得）、Credential Access（トークン/セッション奪取）、Defense Evasion（CSP回避・検知回避）、Impact（誤配布・誤誘導）に接続し得る。
  - 注意：ATT&CKの断定は「何が読めた/何が実行できた/どこへ送れた」が観測で揃ってから行う。

---

## タイトル
ブラウザセキュリティ境界（SOP / CORS / CSP）：“読める・実行できる・送れる”の境界を、観測で確定し設計へ落とす

---

## 目的（このファイルで到達する状態）
- SOP / CORS / CSP を「用語」ではなく、**実務の境界モデル**として扱える。
  1) “同一生成元（origin）/同一サイト（site）/不透明生成元（opaque origin）”を区別して説明できる  
  2) CORS を「越境読み取りの例外」として、プリフライト/資格情報/Vary/キャッシュ混線まで含めて成立条件を観測で確定できる  
  3) CSP を「実行境界（script）」「外部接続境界（connect）」として分解し、report-only→強制の運用設計に落とせる  
  4) 影響半径（誰のデータが、どの経路で、どこへ出るか）を境界で説明できる  
  5) 次の一手を A/B 分岐で選べる（CORS誤設定なのか、XSS/CSP問題なのか、SOPの例外経路なのか）

---

## 扱う範囲（本ファイルの守備範囲）
- 扱う：ブラウザが持つ“境界”を3つに分けて統一して扱う
  - SOP：既定の読み取り境界（DOM / Storage / XHR/fetch の“読める”）
  - CORS：SOPの例外としての越境読み取り許可（サーバが“読める”を明示する）
  - CSP：コンテンツ実行・ロード・外部接続の最終ゲート（“実行できる/送れる”）
- 扱わない（接続先へ）
  - CORSの運用・設定詳細（ヘッダ設計の深掘り）：`06_config_01_CORSと信頼境界（Origin_資格情報_プリフライト）.md`
  - CSPの実務設計（nonce/strict-dynamic/report-only運用などの深掘り）：（今後の分割ファイル候補。作成時は深掘りリンク枠へ追加）
  - XSSの成立モデル・分類（反射/格納/DOM）：`05_input_06_xss_0x_*.md`
  - CSRF（CORSと混同しやすい“書ける境界”）：`05_input_07_csrf_0x_*.md`

---

## 前提：ブラウザ境界は「読める」「実行できる」「送れる」を分離すると崩れにくい
### 1) 3つの動詞で整理する（実務で誤解が減る）
- 読める（Read）
  - DOM参照、XHR/fetchでレスポンス本文/ヘッダを読む、Storage参照 など
- 実行できる（Execute）
  - script 実行、イベントハンドラ、eval系、WASM、動的 import など
- 送れる（Send）
  - fetch/XHRで送信、フォーム送信、画像/リンクでの発火、Beacon、WebSocket など

SOP/CORS は主に「読める」を規定し、CSP は「実行できる」「送れる」を強く規定する。
この対応関係を崩すと、調査・報告で混線しやすい。

### 2) “origin” と “site” は別物（SameSite Cookie とCORS/SOPの誤配線を防ぐ）
- origin（同一生成元）：概ね scheme + host + port の組
- site（同一サイト）：概ね eTLD+1（+ 近年は schemeful site の概念が絡む）
- 重要：CookieのSameSiteは「site」を中心に語られ、SOP/CORSは「origin」を中心に語られる。
  - “SameSite=Lax だから安全” と “CORSが厳しいから安全” は、守っている境界が別である。

---

## 定義：SOP / CORS / CSP を“判定可能”な形に落とす
### SOP（Same-Origin Policy）
- 定義（判定に必要な最小形）：
  - ブラウザが、**異なる origin のリソースに対して「読み取り」や一部の操作を制限**する既定ポリシー。
- 実務の要点：
  - SOPは「サーバを守る」のではなく、**ブラウザ内の別オリジンが“読めない”ようにする**ための制御。
  - 書ける（送れる）操作は多くが許される（例：フォーム送信、画像読み込み）ため、SOPだけでCSRF等は止まらない。

### CORS（Cross-Origin Resource Sharing）
- 定義（判定に必要な最小形）：
  - サーバがレスポンスヘッダで **“このoriginは読んでよい”** を明示し、ブラウザがSOPの例外として読み取りを許可する仕組み。
- 実務の要点：
  - 重要なのは「許可するorigin」「資格情報（cookie等）を許可するか」「プリフライトで何を許可するか」「Vary/キャッシュ混線」。
  - “CORSがある＝サーバ側アクセス制御”ではない（CORSはブラウザの読み取り制御であり、サーバの認可ではない）。

### CSP（Content Security Policy）
- 定義（判定に必要な最小形）：
  - サーバがレスポンスヘッダで **“どこから読み込む/何を実行する/どこへ接続する”** を宣言し、ブラウザが実行・ロード・接続を拒否できる仕組み。
- 実務の要点：
  - CSPは “XSSが起きた後の被害半径” を縮めることが多い（XSSを完全に無にする魔法ではない）。
  - report-only を使うと、強制せずに違反収集できる（運用の起点）。

---

## 境界モデル：資産境界 / 信頼境界 / 権限境界で “どこが壊れると実害か” を固定する
### 資産境界（どこまでが対象か）
- ブラウザ内資産（クライアント側）
  - DOM、Cookie、Storage、Service Worker、Cache Storage、JSメモリ上のトークン
- サーバ側資産
  - APIレスポンス（個人情報/機微情報）、セッション、管理機能、テナント資産
- 中継点（CDN/Proxy）
  - CORSレスポンスのキャッシュ、ヘッダ正規化、エラー生成、圧縮変換

### 信頼境界（どこから先が第三者か）
- 別origin（例：`app.example.com` と `evil.example.net`）
- サブドメイン間（同一siteでもoriginが違うケース）
- サードパーティ（分析SDK、タグ、CDN、IdP、決済、チャット）
- iframe/ポップアップ/リダイレクトを跨ぐ連携（postMessage等）

### 権限境界（どこで権限が切り替わる/伝播するか）
- 認証済み（cookie/トークン）と未認証の境界
- テナント（org/tenant）境界
- 一般ユーザと管理者境界
- “ブラウザで読める”が崩れると、サーバ側の認可が正しくても **閲覧境界が崩れる**（CORS系事故の本質）
- “ブラウザで実行できる”が崩れると、権限境界を横断して **操作・窃取が可能**（XSS/CSP系事故の本質）

---

## SOPを深掘り：どの操作が “同一origin” を要求するか（観測に落とす）
### 1) DOMアクセスの境界（Window/Documentの読み取り）
- 代表的な状態
  - 同一origin：親子フレーム間でDOM参照が可能（原則）
  - 異なるorigin：DOM参照は原則不可（例外は限定的）
- 実務の観測ポイント
  - iframeを跨ぐUI連携がある場合：postMessageの使用有無、targetOrigin指定、受信側のorigin検証
  - “サブドメインなら同じ”という誤解がないか（originは別）

### 2) Storageの境界（cookie/localStorage/sessionStorage/indexedDB など）
- cookie：送信は“スコープ（Domain/Path/SameSite等）”で決まる。読み取りはJSならHttpOnly等で制限。
- localStorage/sessionStorage：原則 origin スコープ（越境して読めない）
- 実務の観測ポイント
  - 認証トークンが localStorage 等に置かれていると、XSS成立時の被害半径が増える（`02_authn_07_client_storage...` と接続）
  - “SameSiteで守っているつもり”が、SPAのトークン保管やCORS設計と整合しているか

### 3) ネットワーク読み取りの境界（XHR/fetch）
- SOPにより、別originへのリクエストは送れても **レスポンスをJSが読めない** のが既定。
- ただし、サーバがCORSで許可した場合は読める（例外がCORS）。

---

## CORSを深掘り：SOP例外の“成立条件”を4点セットで確定する
> ここが薄いと、診断結果が「CORSが弱いっぽい」で終わる。

### 1) 何が許可されているか（許可の種類）
- 読める（Read）許可
  - どの origin からのJSがレスポンス本文/特定ヘッダを読めるか
- 資格情報（Credential）許可
  - cookie 等を含めたリクエストが許されるか（ブラウザ側オプション + サーバ側宣言）
- メソッド/ヘッダ許可（Preflight）
  - 非単純リクエストの前にプリフライトで許可が必要になる

### 2) “反射”か “固定”か（Access-Control-Allow-Origin の性質）
- 反射：リクエストの Origin をそのまま返す実装は、許可範囲が過大になりやすい
- 固定：許可originを厳密に固定できる（ただし運用が難しい）
- 実務の観測ポイント
  - 許可originの決定ロジックが「部分一致」「サフィックス一致」「正規表現」等になっていないか（例：`*.example.com` のつもりが `example.com.evil.tld` を通す）

### 3) Preflight の成立条件（“CORSエラー”の原因を切り分ける）
- 典型
  - Method / Headers / Content-Type によりプリフライトが発生
  - サーバが OPTIONS を正しく処理できない（WAF/Proxyで潰れる等）
- 実務の観測ポイント
  - “本番では失敗するが検証環境では成功する”は、中継点の挙動差が疑わしい（Proxy/WAF/ALB）

### 4) Vary とキャッシュ混線（CORSはキャッシュと相性が悪い）
- 原則：Origin に応じてレスポンスが変わるなら `Vary: Origin` が必要
- これが無いと、CDN/共有キャッシュが **別origin向けの許可レスポンスを再利用**し、越境が拡大する可能性がある
- 実務の接続
  - `05_input_19_cache_poisoning_*` の観点（キー不一致/誤配布）が CORS に直結する

---

## CSPを深掘り：実行境界（script）と外部接続境界（connect）を分けて観測する
### 1) script境界：XSSの“成立後”に何が止まるか
- CSPが効くと止まり得るもの（例）
  - インラインscriptの実行（nonce/hashが無い場合）
  - 未許可オリジンからのscript読み込み
  - eval系（unsafe-evalが無い場合）
- CSPが効いても止まらない/別途設計が要るもの
  - DOM汚染そのもの（サーバ側入力処理は別）
  - “許可済みの場所”へのデータ送信（connect-srcが緩い場合）
  - 既存の許可ドメイン（広すぎるCDN/タグ）経由の迂回（設計問題）

### 2) connect境界：データが“どこへ送れるか”
- connect-src は fetch/XHR/WebSocket/EventSource などの送信先を縛る（= exfilの最後の門）
- form-action / img-src / media-src / frame-src など、送信・埋め込み経路は複数あるため、1ディレクティブで全ては止まらない
- 実務の観測ポイント
  - “XSSはあるが外へ出せない”か、“XSSがあれば即データが出る”かの分岐は、connect-src 等の制約で決まる

### 3) report-only：運用で失敗しないための入口
- report-only は、強制せずに違反を収集できる
- 実務の要点
  - “いきなり強制”は誤検知・業務影響を起こしやすい  
  - report-only → 違反収集 → 許可範囲の整理 → 強制、の順が現実的

---

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
> SOP/CORS/CSPは「ブラウザが拒否しているのか」「サーバが許可しているのか」を切り分ける。

### 1) ブラウザ観測（DevToolsで“拒否理由”を取る）
- Console
  - CORSエラー（プリフライト失敗、Allow-Origin不一致、Credentials不整合 など）
  - CSP違反（blocked by CSP、violated directive など）
- Network
  - preflight（OPTIONS）が出ているか
  - レスポンスヘッダ（Access-Control-* / Content-Security-Policy / Report-Only）を確認
- Application
  - Storageのスコープ（どのoriginに何が保存されているか）
  - Service Worker の支配範囲（意図しないオフラインキャッシュ/改変が無いか）

### 2) サーバ観測（レスポンスヘッダの“事実”を取る）
- CORS：Access-Control-Allow-Origin / -Credentials / -Methods / -Headers / -Expose-Headers
- CSP：Content-Security-Policy / Content-Security-Policy-Report-Only（report-to/report-uri含む）
- 重要：ヘッダは中継点で付与・上書きされる場合があるため、「エッジ経由」と「可能ならオリジン直」を比較する

### 3) 中継点観測（キャッシュ/変換が境界を壊す）
- CDN/Proxy が
  - CORSレスポンスをキャッシュしていないか（Vary欠落）
  - OPTIONS をブロック/変換していないか
  - エラー生成時にヘッダを付与していないか（“アプリは正しいのに壊れる”経路）
- ここが疑わしい場合、`06_config_*`（設定運用境界）へ接続して評価する

---

## 結果の意味（その出力が示す状態：何が言える/言えない）
### 状態A：ブラウザが拒否している（サーバは許可していない）
- 言える：CORSは“緩んでいない”可能性が高い（ただしサーバ間通信や非ブラウザ経路は別）
- 言えない：サーバ側が安全（認可が安全）とは限らない（CORSは認可ではない）

### 状態B：特定originで読める（CORSで例外が成立）
- 言える：そのorigin上のJSが、レスポンスを読める（=読み取り境界が崩れている可能性）
- 追加で必要：資格情報あり/なしの区別、影響半径（どのAPI/データが対象か）、Vary/キャッシュ混線の有無

### 状態C：CSPが緩い（実行/送信の制約が弱い）
- 言える：XSS成立時の被害半径が大きい可能性（実行できる・送れる）
- 言えない：XSSが存在する断定（CSPは入口ではなくゲートである）

### 状態D：CSPが強い（nonce/hash中心で、connectも絞られている）
- 言える：XSSがあっても実行/送信が制限される可能性（ただし“許可済みの経路”次第）
- 追加で必要：report-only運用・例外（特定ページだけ緩い等）の有無、サードパーティ許可の範囲

---

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
> 目的は“何が狙える環境か”の判定。手順の列挙ではなく、判断軸を固定する。

### 1) CORS誤設定が示す“狙い目”
- 狙い：別origin（攻撃者支配）から **被害者の認証済みコンテンツを読める** 条件が揃うと、データ取得が成立し得る
- 優先度が上がる条件
  - 読める対象が機微（個人情報/権限情報/テナント情報）
  - 資格情報付きで読める（cookieセッション等）
  - Vary欠落/キャッシュ混線で“読める範囲”が拡大し得る

### 2) CSPの弱さが示す“狙い目”
- 狙い：XSSが成立した場合に、実行と送信が止まらない（=被害が伸びる）
- 優先度が上がる条件
  - unsafe-inline / unsafe-eval / wide allowlist（広すぎるCDN/タグ）
  - connect-src が広い（任意外部へ送れる）
  - report-only のまま（強制されていない）

### 3) SOP例外経路（連携）に潜む“狙い目”
- 狙い：postMessage/iframe連携/リダイレクト/サブドメイン分離の誤設計で、境界を越えて情報が渡る
- 優先度が上がる条件
  - サブドメインにユーザ生成コンテンツ（UGC）がある（同一siteだが別originという設計が壊れやすい）
  - 受信側が origin 検証をしていない postMessage
  - ログイン/決済/管理導線に iframe/ポップアップ連携が絡む

---

## 次に試すこと（仮説A/Bで分岐：条件が違うと次の手が変わる）
### 仮説A：問題の中心は CORS（“読める越境”が成立している）
- 判断条件（観測で確定する）
  - 特定originで Access-Control-Allow-Origin が許可され、ブラウザでレスポンス本文が読める
  - 資格情報（cookie等）を伴う読み取りが成立する/しないが判別できる
- 次の一手
  - 読める対象（API/画面）を “資産境界（機微/テナント/権限）” で棚卸しする
  - Vary/キャッシュ混線の兆候を取り、影響半径（他originへ拡大する可能性）を評価する
  - 対策要件を「許可originの固定」「資格情報の扱い」「Vary/キャッシュ設計」「プリフライト運用」で提示する

### 仮説B：問題の中心は CSP（“実行/送信”の制約が弱い）
- 判断条件（観測で確定する）
  - CSPが無い/弱い/例外が広い（unsafe-*、広域ドメイン許可、connect-srcが広い）
  - report-only の違反が多いのに強制へ進めていない
- 次の一手
  - XSS系トピック（`05_input_06_xss_*`）の観測に戻り、入口（注入点）を探す
  - “成立した場合の被害半径”として、connect-src とデータ所在（cookie/storage/API）を結びつける
  - 対策要件を「nonce/hash中心」「strict-dynamic」「外部依存の棚卸し」「report-only運用」で提示する

### 仮説C：問題の中心は SOP例外（連携/埋め込み/サブドメイン分離の誤設計）
- 判断条件（観測で確定する）
  - postMessage の targetOrigin が緩い/受信側のorigin検証が無い
  - iframe/ポップアップ連携で機微情報が渡っている
  - サブドメインにUCG/広告/外部JSを寄せている（分離前提が崩れる）
- 次の一手
  - 連携の設計意図（どこが信頼境界か）を整理し、許可するoriginを最小化する
  - 必要に応じて、CSPの frame-ancestors / connect-src 等で“許可された連携だけを残す”方向に落とす

---

## 04_labs（SOP/CORS/CSP を“観測→解釈→利用”で回すための検証設計）
- 追加候補Lab（例）
  - `04_labs/02_web/07_browser_security_01_sop_cross_origin_dom_and_postmessage/`
  - `04_labs/02_web/07_browser_security_02_cors_preflight_credentials_vary_cache/`
  - `04_labs/02_web/07_browser_security_03_csp_report_only_to_enforce_nonce_connect_src/`
- Lab設計要件（手順書ではなく設計）
  - 2つのorigin（app / attacker）を用意し、DOM・fetch・iframe・postMessage を最小構成で比較できる
  - CORSは
    - 許可originの固定/反射の差
    - credentials on/off
    - preflight 成功/失敗
    - Varyあり/なし（キャッシュ混線）
    を切り替えられる
  - CSPは
    - report-only / enforce
    - nonce/hash/unsafe-* の差
    - connect-src の差（送信先制御）
    を切り替えられる
  - 観測点
    - ブラウザ：Console/Network/Application（違反理由・プリフライト・保存場所）
    - サーバ：受信Origin/OPTIONS処理/レスポンスヘッダ
    - 中継点（任意）：キャッシュログ/ヘッダ付与/正規化ログ
  - 成功条件
    - “読める・実行できる・送れる”の境界が、設定差分でどう変わるか説明できる

---

## コマンド/例（例示は最小限：観測と判断を優先）
~~~~
# 目的：
# - CORS：プリフライト（OPTIONS）と本リクエストの両方を観測し、「何が許可されているか」を確定する
# - CSP：Consoleの違反理由と、Response Headerのポリシーを対応付ける
# - SOP：同一origin/別originで “読める/読めない” の差分を、最小のHTML+JSで再現する

# 注意：
# - CORSは「サーバの認可」ではない。CORSが厳しくてもAPIが安全とは言えない。
# - 逆にCORSが緩いと、ブラウザ経由の読み取り境界が崩れ、影響半径が拡大し得る（資格情報・Vary・キャッシュ混線を必ず確認）。
~~~~

---

## 深掘りリンク（最大8）
- `06_config_01_CORSと信頼境界（Origin_資格情報_プリフライト）.md`
- `06_config_03_セキュリティヘッダ（CSP_HSTS_Frame_Referrer）.md`
- `05_input_06_xss_01_反射_境界モデル.md`
- `05_input_06_xss_02_格納_境界モデル.md`
- `05_input_06_xss_03_DOM_境界モデル.md`
- `05_input_07_csrf_01_token（synchronizer_double_submit）.md`
- `05_input_07_csrf_03_api（cors_json_csrf）.md`
- `05_input_19_cache_poisoning_02_unkeyed（headers_params）.md`
