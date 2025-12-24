# 07_browser_security_境界（SOP_CORS_CSP）
ブラウザセキュリティ境界（SOP / CORS / CSP）："読める・実行できる・送れる"の境界を、観測で確定し設計へ落とす

---

## 目的（この技術で到達する状態）
- SOP / CORS / CSP を「用語」ではなく、**実務の境界モデル**として扱える。
  1) "同一生成元（origin）/同一サイト（site）/不透明生成元（opaque origin）"を区別して説明できる  
  2) CORS を「越境読み取りの例外」として、プリフライト/資格情報/Vary/キャッシュ混線まで含めて成立条件を観測で確定できる  
  3) CSP を「実行境界（script）」「外部接続境界（connect）」として分解し、report-only→強制の運用設計に落とせる  
  4) 影響半径（誰のデータが、どの経路で、どこへ出るか）を境界で説明できる  
  5) 次の一手を A/B 分岐で選べる（CORS誤設定なのか、XSS/CSP問題なのか、SOPの例外経路なのか）

## 前提（対象・範囲・想定）
- 対象：許可範囲のWeb/API/関連サブドメイン/クラウド露出面。
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - CDN → WAF → Reverse Proxy（Nginx/Envoy等）→ App（Spring/Node/Rails等）
  - ブラウザが持つ"境界"を3つに分けて統一して扱う：SOP（既定の読み取り境界（DOM / Storage / XHR/fetch の"読める"））、CORS（SOPの例外としての越境読み取り許可（サーバが"読める"を明示する））、CSP（コンテンツ実行・ロード・外部接続の最終ゲート（"実行できる/送れる"））
- できること/やらないこと（安全に検証する範囲）：
  - やる：クライアント側制御（SOP/CORS/CSP）を、(1) ブラウザが拒否しているだけか、(2) サーバが許可しているか、(3) 中継点（CDN/Proxy）が混線させるか、の3層で観測する。単なる"CORSエラーが出た/出ない"ではなく、プリフライト・資格情報・Vary・エラー差分・CSP違反レポートまで含めて成立条件を確定する
  - やらないこと：CORSの運用・設定詳細（ヘッダ設計の深掘り）、CSPの実務設計（nonce/strict-dynamic/report-only運用などの深掘り）、XSSの成立モデル・分類（反射/格納/DOM）、CSRF（CORSと混同しやすい"書ける境界"）は別ユニットへ接続
- 依存する前提知識（必要最小限）：
  - `01_topics/02_web/06_config_00_設定・運用境界（CORS ヘッダ Secrets）.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：
    - ブラウザが持つ"境界"を3つに分けて統一して扱う：SOP（既定の読み取り境界（DOM / Storage / XHR/fetch の"読める"））、CORS（SOPの例外としての越境読み取り許可（サーバが"読める"を明示する））、CSP（コンテンツ実行・ロード・外部接続の最終ゲート（"実行できる/送れる"））
  - 扱わない（別ユニットへ接続）：
    - CORSの運用・設定詳細（ヘッダ設計の深掘り） → `06_config_01_CORSと信頼境界（Origin_資格情報_プリフライト）.md`
    - CSPの実務設計（nonce/strict-dynamic/report-only運用などの深掘り） → `06_config_04_csp_実務設計（report-only_違反収集）.md`
    - XSSの成立モデル・分類（反射/格納/DOM） → `05_input_06_xss_0x_*.md`
    - CSRF（CORSと混同しやすい"書ける境界"） → `05_input_07_csrf_0x_*.md`

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
- 観測対象（プロトコル/データ構造/やり取りの単位）：
  - ブラウザ観測（DevToolsで"拒否理由"を取る）：Console（CORSエラー（プリフライト失敗、Allow-Origin不一致、Credentials不整合 など）、CSP違反（blocked by CSP、violated directive など））、Network（preflight（OPTIONS）が出ているか、レスポンスヘッダ（Access-Control-* / Content-Security-Policy / Report-Only）を確認）、Application（Storageのスコープ（どのoriginに何が保存されているか）、Service Worker の支配範囲（意図しないオフラインキャッシュ/改変が無いか））
  - サーバ観測（レスポンスヘッダの"事実"を取る）：CORS（Access-Control-Allow-Origin / -Credentials / -Methods / -Headers / -Expose-Headers）、CSP（Content-Security-Policy / Content-Security-Policy-Report-Only（report-to/report-uri含む））、重要（ヘッダは中継点で付与・上書きされる場合があるため、「エッジ経由」と「可能ならオリジン直」を比較する）
  - 中継点観測（キャッシュ/変換が境界を壊す）：CDN/Proxy が CORSレスポンスをキャッシュしていないか（Vary欠落）、OPTIONS をブロック/変換していないか、エラー生成時にヘッダを付与していないか（"アプリは正しいのに壊れる"経路）
- 境界の観点：
  - 資産境界（管理主体・委託先・対象範囲の線引き）：ブラウザ内資産（クライアント側：DOM、Cookie、Storage、Service Worker、Cache Storage、JSメモリ上のトークン）、サーバ側資産（APIレスポンス（個人情報/機微情報）、セッション、管理機能、テナント資産）、中継点（CDN/Proxy：CORSレスポンスのキャッシュ、ヘッダ正規化、エラー生成、圧縮変換）
  - 信頼境界（外部連携・第三者・越境ポイント）：別origin（例：`app.example.com` と `evil.example.net`）、サブドメイン間（同一siteでもoriginが違うケース）、サードパーティ（分析SDK、タグ、CDN、IdP、決済、チャット）、iframe/ポップアップ/リダイレクトを跨ぐ連携（postMessage等）
  - 権限境界（権限の切替/伝播/委任）：認証済み（cookie/トークン）と未認証の境界、テナント（org/tenant）境界、一般ユーザと管理者境界、"ブラウザで読める"が崩れると、サーバ側の認可が正しくても **閲覧境界が崩れる**（CORS系事故の本質）、"ブラウザで実行できる"が崩れると、権限境界を横断して **操作・窃取が可能**（XSS/CSP系事故の本質）
- 重要なフィールド/差分/状態（「ここが変わると意味が変わる」点）：
  - 3つの動詞で整理する（実務で誤解が減る）：読める（Read：DOM参照、XHR/fetchでレスポンス本文/ヘッダを読む、Storage参照 など）、実行できる（Execute：script 実行、イベントハンドラ、eval系、WASM、動的 import など）、送れる（Send：fetch/XHRで送信、フォーム送信、画像/リンクでの発火、Beacon、WebSocket など）
  - "origin" と "site" は別物（SameSite Cookie とCORS/SOPの誤配線を防ぐ）：origin（同一生成元：概ね scheme + host + port の組）、site（同一サイト：概ね eTLD+1（+ 近年は schemeful site の概念が絡む））

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が"確定"できるか：
  - 状態A：ブラウザが拒否している（サーバは許可していない） → CORSは"緩んでいない"可能性が高い（ただしサーバ間通信や非ブラウザ経路は別）
  - 状態B：特定originで読める（CORSで例外が成立） → そのorigin上のJSが、レスポンスを読める（=読み取り境界が崩れている可能性）
  - 状態C：CSPが緩い（実行/送信の制約が弱い） → XSS成立時の被害半径が大きい可能性（実行できる・送れる）
  - 状態D：CSPが強い（nonce/hash中心で、connectも絞られている） → XSSがあっても実行/送信が制限される可能性（ただし"許可済みの経路"次第）
- 何が"推定"できるか（推定の根拠/前提）：
  - 資格情報あり/なしの区別、影響半径（どのAPI/データが対象か）、Vary/キャッシュ混線の有無
  - report-only運用・例外（特定ページだけ緩い等）の有無、サードパーティ許可の範囲
- 何は"言えない"か（不足情報・観測限界）：
  - サーバ側が安全（認可が安全）とは限らない（CORSは認可ではない）
  - XSSが存在する断定（CSPは入口ではなくゲートである）
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：ブラウザが拒否している（サーバは許可していない） → CORSは"緩んでいない"可能性が高い（ただしサーバ間通信や非ブラウザ経路は別）
  - パターンB：特定originで読める（CORSで例外が成立） → そのorigin上のJSが、レスポンスを読める（=読み取り境界が崩れている可能性）
  - パターンC：CSPが緩い（実行/送信の制約が弱い） → XSS成立時の被害半径が大きい可能性（実行できる・送れる）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す"狙い目"：
  - CORS誤設定が示す"狙い目"：別origin（攻撃者支配）から **被害者の認証済みコンテンツを読める** 条件が揃うと、データ取得が成立し得る
  - CSPの弱さが示す"狙い目"：XSSが成立した場合に、実行と送信が止まらない（=被害が伸びる）
  - SOP例外経路（連携）に潜む"狙い目"：postMessage/iframe連携/リダイレクト/サブドメイン分離の誤設計で、境界を越えて情報が渡る
- 優先度の付け方（時間制約がある場合の順序）：
  1) 読める対象が機微（個人情報/権限情報/テナント情報） → 最優先で重大
  2) 資格情報付きで読める（cookieセッション等） → 信頼境界が崩れる可能性
  3) Vary欠落/キャッシュ混線で"読める範囲"が拡大し得る → 影響半径が拡大
  4) unsafe-inline / unsafe-eval / wide allowlist（広すぎるCDN/タグ） → 実行境界が崩れる可能性
  5) connect-src が広い（任意外部へ送れる） → 送信境界が崩れる可能性
- 代表的な攻め筋（この観測から自然に繋がるもの）：
  - 攻め筋1：CORS誤設定が示す"狙い目" → 読める対象（API/画面）を "資産境界（機微/テナント/権限）" で棚卸しする。Vary/キャッシュ混線の兆候を取り、影響半径（他originへ拡大する可能性）を評価する。対策要件を「許可originの固定」「資格情報の扱い」「Vary/キャッシュ設計」「プリフライト運用」で提示する
  - 攻め筋2：CSPの弱さが示す"狙い目" → XSS系トピック（`05_input_06_xss_*`）の観測に戻り、入口（注入点）を探す。"成立した場合の被害半径"として、connect-src とデータ所在（cookie/storage/API）を結びつける。対策要件を「nonce/hash中心」「strict-dynamic」「外部依存の棚卸し」「report-only運用」で提示する
  - 攻め筋3：SOP例外経路（連携/埋め込み/サブドメイン分離の誤設計） → 連携の設計意図（どこが信頼境界か）を整理し、許可するoriginを最小化する。必要に応じて、CSPの frame-ancestors / connect-src 等で"許可された連携だけを残す"方向に落とす
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）：
  - サブドメインにユーザ生成コンテンツ（UGC）がある（同一siteだが別originという設計が壊れやすい）
  - 受信側が origin 検証をしていない postMessage
  - ログイン/決済/管理導線に iframe/ポップアップ連携が絡む

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：問題の中心は CORS（"読める越境"が成立している）
  - 成立条件：
    - 特定originで Access-Control-Allow-Origin が許可され、ブラウザでレスポンス本文が読める
    - 資格情報（cookie等）を伴う読み取りが成立する/しないが判別できる
  - 次の検証：
    - 読める対象（API/画面）を "資産境界（機微/テナント/権限）" で棚卸しする
    - Vary/キャッシュ混線の兆候を取り、影響半径（他originへ拡大する可能性）を評価する
    - 対策要件を「許可originの固定」「資格情報の扱い」「Vary/キャッシュ設計」「プリフライト運用」で提示する
  - 期待する観測（成功/失敗時に何が見えるか）：
    - 成功：特定originで Access-Control-Allow-Origin が許可され、ブラウザでレスポンス本文が読める
    - 失敗：CORSが適切に設定されている
- 仮説B：問題の中心は CSP（"実行/送信"の制約が弱い）
  - 成立条件：
    - CSPが無い/弱い/例外が広い（unsafe-*、広域ドメイン許可、connect-srcが広い）
    - report-only の違反が多いのに強制へ進めていない
  - 次の検証：
    - XSS系トピック（`05_input_06_xss_*`）の観測に戻り、入口（注入点）を探す
    - "成立した場合の被害半径"として、connect-src とデータ所在（cookie/storage/API）を結びつける
    - 対策要件を「nonce/hash中心」「strict-dynamic」「外部依存の棚卸し」「report-only運用」で提示する
  - 期待する観測：
    - 成功：CSPが無い/弱い/例外が広い（unsafe-*、広域ドメイン許可、connect-srcが広い）
    - 失敗：CSPが適切に設定されている
- 仮説C：問題の中心は SOP例外（連携/埋め込み/サブドメイン分離の誤設計）
  - 成立条件：
    - postMessage の targetOrigin が緩い/受信側のorigin検証が無い
    - iframe/ポップアップ連携で機微情報が渡っている
    - サブドメインにUCG/広告/外部JSを寄せている（分離前提が崩れる）
  - 次の検証：
    - 連携の設計意図（どこが信頼境界か）を整理し、許可するoriginを最小化する
    - 必要に応じて、CSPの frame-ancestors / connect-src 等で"許可された連携だけを残す"方向に落とす
  - 期待する観測：
    - 成功：postMessage の targetOrigin が緩い/受信側のorigin検証が無い
    - 失敗：SOP例外（連携/埋め込み/サブドメイン分離）が適切に設計されている

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/02_web/07_browser_security_01_sop_cross_origin_dom_and_postmessage/`（追加候補）
    - `04_labs/02_web/07_browser_security_02_cors_preflight_credentials_vary_cache/`（追加候補）
    - `04_labs/02_web/07_browser_security_03_csp_report_only_to_enforce_nonce_connect_src/`（追加候補）
- 取得する証跡（目的ベースで最小限）：
  - ブラウザ観測（DevToolsで"拒否理由"を取る）：Console（CORSエラー、CSP違反）、Network（preflight（OPTIONS）、レスポンスヘッダ）、Application（Storageのスコープ、Service Worker の支配範囲）
  - サーバ観測（レスポンスヘッダの"事実"を取る）：CORS（Access-Control-Allow-Origin / -Credentials / -Methods / -Headers / -Expose-Headers）、CSP（Content-Security-Policy / Content-Security-Policy-Report-Only）
  - 中継点観測（キャッシュ/変換が境界を壊す）：CDN/Proxy が CORSレスポンスをキャッシュしていないか（Vary欠落）、OPTIONS をブロック/変換していないか、エラー生成時にヘッダを付与していないか
- 観測の取り方（どの視点で差分を見るか）：
  - 視点1：ブラウザ観測（DevToolsで"拒否理由"を取る）
  - 視点2：サーバ観測（レスポンスヘッダの"事実"を取る）
  - 視点3：中継点観測（キャッシュ/変換が境界を壊す）
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/browser_security 2>/dev/null
    cd ~/keda_evidence/browser_security
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可されたスコープ** のみ
      - 観測は **代表点の抽出** のみ（単なる"CORSエラーが出た/出ない"ではなく、プリフライト・資格情報・Vary・エラー差分・CSP違反レポートまで含めて成立条件を確定する）
      - クライアント側制御（SOP/CORS/CSP）を、(1) ブラウザが拒否しているだけか、(2) サーバが許可しているか、(3) 中継点（CDN/Proxy）が混線させるか、の3層で観測する
  - 相関キー（最低限）を作る（後で必ず効く）
    - Host、User、Time、Origin、Destination、CORSエラー（プリフライト失敗、Allow-Origin不一致、Credentials不整合）、CSP違反（blocked by CSP、violated directive）、preflight（OPTIONS）、レスポンスヘッダ（Access-Control-* / Content-Security-Policy / Report-Only）、Storageのスコープ、Service Worker の支配範囲、Vary欠落、OPTIONS をブロック/変換

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は"手段"であり"結論"ではない。必ず「何を観測している例か」を添える。

~~~~
# 目的：
# - CORS：プリフライト（OPTIONS）と本リクエストの両方を観測し、「何が許可されているか」を確定する
# - CSP：Consoleの違反理由と、Response Headerのポリシーを対応付ける
# - SOP：同一origin/別originで "読める/読めない" の差分を、最小のHTML+JSで再現する

# 注意：
# - CORSは「サーバの認可」ではない。CORSが厳しくてもAPIが安全とは言えない。
# - 逆にCORSが緩いと、ブラウザ経由の読み取り境界が崩れ、影響半径が拡大し得る（資格情報・Vary・キャッシュ混線を必ず確認）。
~~~~

- この例で観測していること：
  - CORS（プリフライト（OPTIONS）と本リクエストの両方を観測し、「何が許可されているか」を確定する）、CSP（Consoleの違反理由と、Response Headerのポリシーを対応付ける）、SOP（同一origin/別originで "読める/読めない" の差分を、最小のHTML+JSで再現する）
- 出力のどこを見るか（注目点）：
  - プリフライト（OPTIONS）、本リクエスト、Consoleの違反理由、Response Headerのポリシー、同一origin/別originで "読める/読めない" の差分
- この例が使えないケース（前提が崩れるケース）：
  - ブラウザを使用しない場合、観測できない

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：設定・運用、クライアント側制御
  - 該当要件（可能ならID）：ブラウザ境界（SOP/CORS/CSP）を「サーバ側の防御」と誤認し、(1) CORS誤設定で"読める境界"が崩れる、(2) CSPが緩く"実行境界"が崩れる、(3) SOPの前提（origin/site/opaque origin）を取り違えて"越境が起きる設計"になる。結果として、XSS/データ窃取/セッション悪用/テナント混線の成立条件が揃う。
  - このファイルの内容が「満たす/破れる」ポイント：
    - 破れる：ブラウザ境界（SOP/CORS/CSP）を「サーバ側の防御」と誤認し、(1) CORS誤設定で"読める境界"が崩れる、(2) CSPが緩く"実行境界"が崩れる、(3) SOPの前提（origin/site/opaque origin）を取り違えて"越境が起きる設計"になる。結果として、XSS/データ窃取/セッション悪用/テナント混線の成立条件が揃う。
    - 満たす：SOPを"既定の読み取り境界"として前提化し、CORSは"例外（必要最小限の読める越境）"として仕様化、CSPは"実行と外部接続の最終ゲート"として設計・監視（report-only→強制）する。特に CORS の Vary / キャッシュ混線、CSP の nonce/hash/strict-dynamic、connect-src の外部接続境界を「観測→判断→次の一手」で回せる状態にする。
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：Configuration/Deployment、Client-Side Testing
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：クライアント側制御（SOP/CORS/CSP）を、(1) ブラウザが拒否しているだけか、(2) サーバが許可しているか、(3) 中継点（CDN/Proxy）が混線させるか、の3層で観測する。単なる"CORSエラーが出た/出ない"ではなく、プリフライト・資格情報・Vary・エラー差分・CSP違反レポートまで含めて成立条件を確定する。
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：情報収集、脆弱性分析、侵害評価
  - 前後フェーズとの繋がり（1行）：情報収集〜脆弱性分析（境界モデル化）→検証（安全な範囲での成立根拠）→侵害評価（影響半径）→報告（設計要件と監視要件）。前後フェーズとの繋がり：`06_config_01_CORS...` や `05_input_06_xss...` で見える兆候を、本ファイルの「境界（SOP/CORS/CSP）」で統一して説明可能にする。
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：初期侵入/実行：Webの脆弱性悪用（公開アプリ経由）
  - 攻撃者の目的（この技術が支える意図）：Collection（ブラウザ経由のデータ取得）、Credential Access（トークン/セッション奪取）、Defense Evasion（CSP回避・検知回避）、Impact（誤配布・誤誘導）に接続し得る。ATT&CKの断定は「何が読めた/何が実行できた/どこへ送れた」が観測で揃ってから行う。
  - 参照：https://attack.mitre.org/tactics/TA0001/（Initial Access）

## 参考（必要最小限）
- 親：`01_topics/02_web/06_config_00_設定・運用境界（CORS ヘッダ Secrets）.md`
- SOP/CORS/CSPの定義：
  - SOP（Same-Origin Policy）：ブラウザが、**異なる origin のリソースに対して「読み取り」や一部の操作を制限**する既定ポリシー。SOPは「サーバを守る」のではなく、**ブラウザ内の別オリジンが"読めない"ようにする**ための制御。書ける（送れる）操作は多くが許される（例：フォーム送信、画像読み込み）ため、SOPだけでCSRF等は止まらない。
  - CORS（Cross-Origin Resource Sharing）：サーバがレスポンスヘッダで **"このoriginは読んでよい"** を明示し、ブラウザがSOPの例外として読み取りを許可する仕組み。重要なのは「許可するorigin」「資格情報（cookie等）を許可するか」「プリフライトで何を許可するか」「Vary/キャッシュ混線」。"CORSがある＝サーバ側アクセス制御"ではない（CORSはブラウザの読み取り制御であり、サーバの認可ではない）。
  - CSP（Content Security Policy）：サーバがレスポンスヘッダで **"どこから読み込む/何を実行する/どこへ接続する"** を宣言し、ブラウザが実行・ロード・接続を拒否できる仕組み。CSPは "XSSが起きた後の被害半径" を縮めることが多い（XSSを完全に無にする魔法ではない）。report-only を使うと、強制せずに違反収集できる（運用の起点）。

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`06_config_01_CORSと信頼境界（Origin_資格情報_プリフライト）.md`
- 関連 topics：`06_config_03_security_headers（CSP_HSTS_XFO等）.md`
- 関連 topics：`06_config_04_csp_実務設計（report-only_違反収集）.md`

---

## 深掘りリンク（最大8）
- `06_config_01_CORSと信頼境界（Origin_資格情報_プリフライト）.md`
- `06_config_03_security_headers（CSP_HSTS_XFO等）.md`
- `06_config_04_csp_実務設計（report-only_違反収集）.md`
- `05_input_06_xss_01_反射_境界モデル.md`
- `05_input_06_xss_02_格納_境界モデル.md`
- `05_input_06_xss_03_DOM_境界モデル.md`
- `05_input_07_csrf_01_token（synchronizer_double_submit）.md`
- `05_input_19_cache_poisoning_02_unkeyed（headers_params）.md`

---
