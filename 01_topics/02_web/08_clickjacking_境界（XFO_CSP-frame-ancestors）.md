# 08_clickjacking_境界（XFO_CSP-frame-ancestors）
"読める/送れる"ではなく「ユーザのクリックを踏ませる」で境界が崩れる領域

## 目的（この技術で到達する状態）
- クリックジャッキングを「CSRFの亜種」や「古い脆弱性」ではなく、**UI Redressing（ユーザ操作の代理実行）**として境界モデル化できる。
- XFO（`X-Frame-Options`）と CSP（`frame-ancestors`）を、互換性・例外設計・適用漏れ（経路/ページ/エッジ）まで含めて観測し、**成立/不成立を言語化**できる。
- "埋め込み（iframe）を要する正当な要件"がある場合でも、例外を安全に作る設計（専用ページ・機能縮退・許可親最小化・監視）へ落とせる。
- 次の一手を分岐できる：
  - A：フレーム不可 → 別経路（XSS/CSRF/認可）へ
  - B：フレーム可だが重要操作は守られている → 再認証/確認設計の評価へ
  - C：フレーム可 + 重要操作が完遂 → 高影響として報告・設計是正へ
  - D：埋め込み例外が広い → 例外境界の縮退・分離へ

## 前提（対象・範囲・想定）
- 対象：WebアプリケーションのHTMLレスポンス（特に重要操作・設定・管理・承認・OAuth同意画面）
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - CDN/WAF経由とオリジン直でヘッダの差分が生じ得る
  - SPA/ルーティングで複数経路が存在し得る
  - エラーページ・旧UI・リダイレクトチェーンで適用漏れが起きやすい
- できること/やらないこと（安全に検証する範囲）：
  - できる：許可されたスコープ内での観測（DevTools/プロキシ/簡易PoC）
  - やらない：実際の攻撃実行、許可されていない対象への検証
- 依存する前提知識（必要最小限）：
  - HTTPレスポンスヘッダの基本
  - iframe/フレーミングの仕組み
  - 同一オリジンポリシー（SOP）の基本
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：
    - Clickjacking / UI Redressing の成立条件
    - フレーミング制御：`X-Frame-Options` と `Content-Security-Policy: frame-ancestors`
    - 例外（埋め込み要件）を安全に扱う設計
    - 観測（DevTools/プロキシ/簡易PoC）と判断（状態分類）
  - 扱わない（別ユニットへ接続）：
    - CSRF（トークン/SameSite等）の詳細 → `05_input_07_csrf_*`
    - XSSの入口（注入点探索） → `05_input_06_xss_*`
    - セキュリティヘッダ総合（CSP/HSTS等） → `06_config_03_セキュリティヘッダ（CSP_HSTS_Frame_Referrer）.md`
    - 重要操作の再認証（step-up） → `02_authn_16_step-up_再認証境界（重要操作_再確認）.md`
    - 重要操作（承認/送金/権限）の境界 → `03_authz_06_privileged_action_重要操作（承認_送金_権限）.md`

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
- 観測対象（プロトコル/データ構造/やり取りの単位）：
  - HTTPレスポンスヘッダ：`X-Frame-Options`、`Content-Security-Policy`（特に`frame-ancestors`ディレクティブ）
  - 実際のiframe埋め込み時の挙動（表示される/拒否される/一部だけ表示される）
  - リダイレクトチェーン全体でのヘッダの有無（中間レスポンスと最終HTML）
  - サーバ側ログ：`Sec-Fetch-Dest: iframe`、`Sec-Fetch-Site: cross-site`、`Referer`
- 境界の観点：
  - 資産境界（管理主体・委託先・対象範囲の線引き）：
    - どのページ/経路でヘッダが適用されているか（適用漏れの有無）
    - エラーページ・旧UI・特定パスでの例外
  - 信頼境界（外部連携・第三者・越境ポイント）：
    - 埋め込み例外の許可親（`frame-ancestors`のallowlist）
    - 外部SaaS・サブドメイン・委託先への許可範囲
  - 権限境界（権限の切替/伝播/委任）：
    - 重要操作がクリックだけで完遂するか（再認証/確認/手入力の有無）
    - 埋め込み専用ページと本体UIの分離
- 重要なフィールド/差分/状態（「ここが変わると意味が変わる」点）：
  - `X-Frame-Options: DENY` vs `SAMEORIGIN` vs 欠落
  - `frame-ancestors 'none'` vs `'self'` vs 特定のallowlist vs 欠落
  - ヘッダの併用（XFO + CSP）と矛盾（二重ヘッダ・経路による不一致）
  - 重要操作のUI到達性（モーダル/確認/二要素/再認証の有無）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が"確定"できるか：
  - フレーミング可否（XFO/CSPの有無と値）
  - 重要操作がクリックだけで完遂するか（再認証/確認/手入力の有無）
  - 適用漏れの有無（エラーページ・旧UI・特定パス・リダイレクトチェーン）
- 何が"推定"できるか（推定の根拠/前提）：
  - クリックジャッキングの成立可能性（フレーミング可 + 重要操作がクリックのみで完遂）
  - 例外設計の安全性（埋め込み専用ページの分離・機能縮退・許可親の最小化）
  - 攻撃の検知可能性（`Sec-Fetch-Dest: iframe`等のログと重要操作ログの相関）
- 何は"言えない"か（不足情報・観測限界）：
  - 実際の攻撃成功の有無（観測だけでは確定できない）
  - ユーザの操作誘導の難易度（UI要素の位置の安定性・文脈の自然さ）
  - フレームバスティング等のクライアント側対策の有効性（サーバ側観測だけでは不十分）
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：フレーム不可（XFO/CSPで拒否される）
    - 正常：clickjackingの主要経路は抑止されている可能性が高い
  - パターンB：フレーム可だが重要操作は再認証/手入力/確認で止まる
    - 境界がズレている：フレーミング制御は不足だが、影響は限定される可能性
  - パターンC：フレーム可 + 重要操作がクリックのみで完遂（高影響）
    - 異常：クリックジャッキングが実害に繋がる成立条件が揃っている
  - パターンD：埋め込み例外が広い（allowlistが広すぎる/外部SaaSやサブドメインを広範に許可）
    - 境界がズレている：例外が境界を壊している可能性（"親"が乗っ取られたら成立）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す"狙い目"：
  - クリックだけで完遂する重要操作（追加の再認証/二要素/手入力確認がない）
  - UI要素の位置が安定している操作（オーバーレイで合わせやすい）
  - "被害者が押しても不自然でない文脈"に置ける操作（景品/アンケート/動画再生など）
  - 具体例：
    - アカウント設定：メールアドレス変更、パスワード変更開始、2FA無効化、回復コード再発行
    - 権限/IAM/管理：管理者追加、ロール付与、APIキー発行、Webhook追加、外部連携（Slack/Jira/IdP）追加
    - 金銭/承認：支払い手段追加、送金/振込、承認フローの承認ボタン押下、請求先変更
    - 共有/公開："社外共有ON"、公開リンク生成、アクセス権を"公開"へ変更
    - OAuth/SSO同意："許可（Allow）"の押下（IdP/RP間の画面で発生しやすい）
- 優先度の付け方（時間制約がある場合の順序）：
  1. 高影響操作ページ（アカウント設定・権限管理・支払い・連携・承認・OAuth同意画面）のフレーミング可否を確認
  2. 適用漏れ（エラーページ・旧UI・特定パス・リダイレクトチェーン）を確認
  3. 重要操作がクリックだけで完遂するかを確認（再認証/確認/手入力の有無）
  4. 埋め込み例外の許可親を確認（allowlistが広すぎないか）
- 代表的な攻め筋（この観測から自然に繋がるもの）：
  - 攻め筋1：フレーミング可能な重要操作ページを特定し、透明iframe + ダミーUIでクリック誘導
    - 成立条件：フレーミング可 + 重要操作がクリックのみで完遂 + UI要素の位置が安定
  - 攻め筋2：適用漏れ（エラーページ・旧UI・特定パス）を利用してバイパス
    - 成立条件：主要ページは防御されているが、例外ページでヘッダが抜けている
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）：
  - CDN/WAF経由とオリジン直でヘッダの差分がある場合：オリジン直を優先的に確認
  - SPA/ルーティングで複数経路が存在する場合：全ての経路でヘッダの有無を確認
  - 埋め込み例外が広い場合：許可親が乗っ取られた場合の影響を評価

## 次に試すこと（仮説A/Bの分岐と検証）
> ここが最重要。条件が違うと次の手が変わる形で書く。

- 仮説A：フレーム不可（XFO/CSPで拒否される）
  - 成立条件：主要ページで`X-Frame-Options: DENY`または`frame-ancestors 'none'`が適用されている
  - 次の検証：
    - "例外ページ"だけ抜けていないか（エラー/旧UI/特定パス）を最低限確認
    - リダイレクトチェーン全体でヘッダが適用されているか確認
  - 期待する観測（成功/失敗時に何が見えるか）：
    - 成功：全ての経路でフレーミングが拒否される
    - 失敗：一部の経路でヘッダが抜けている（適用漏れ）
- 仮説B：フレーム可だが重要操作は再認証/手入力/確認で止まる
  - 成立条件：フレーミング制御は不足だが、重要操作に再認証/確認/手入力が入っている
  - 次の検証：
    - どの操作が「クリックだけで完遂」かを棚卸しし、重要操作だけでも`frame-ancestors 'none'`に寄せられるか検討
    - 再認証が"例外パス"でバイパスできないか（古い画面/モバイル専用等）を確認
  - 期待する観測：
    - 成功：重要操作は再認証/確認で止まり、影響は限定される
    - 失敗：例外パスで再認証がバイパスできる
- 仮説C：フレーム可 + 重要操作がクリックのみで完遂（高影響）
  - 成立条件：フレーミング可 + 重要操作がクリックのみで完遂 + UI要素の位置が安定
  - 次の検証（報告/対策要件）：
    - 原則 deny（`frame-ancestors 'none'` / `XFO: DENY`）を適用し、例外が必要なら専用ページ化で縮退
    - 重要操作には step-up を追加（万一の残存リスク低減）
    - 監視（重要操作ログ + sec-fetch 兆候）を合わせて提案
  - 期待する観測：
    - 成功：PoCでクリック誘導が成立することを示せる
    - 失敗：実際には再認証/確認で止まる（影響が限定される）
- 仮説D：埋め込み例外が広い（allowlistが広すぎる/外部SaaSやサブドメインを広範に許可）
  - 成立条件：`frame-ancestors`のallowlistが広すぎる、または外部SaaS/サブドメインを広範に許可している
  - 次の検証：
    - allowlist を「管理主体が強い親」に限定
    - 埋め込み対象の機能を縮退し、本体UIを埋め込ませない
    - 親子通信（postMessage）を使うなら origin 検証と最小権限で設計し直す
  - 期待する観測：
    - 成功：許可親が限定され、機能が縮退されている
    - 失敗：許可親が広すぎる、または本体UIが埋め込まれている

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/02_web/08_clickjacking_01_xfo_vs_frame_ancestors_matrix/`（候補）
    - `04_labs/02_web/08_clickjacking_02_exception_design_embed_only_pages/`（候補）
- 取得する証跡（目的ベースで最小限）：
  - HTTPレスポンスヘッダ（XFO/CSPの有無と値）
  - 実際のiframe埋め込み時の挙動（画面キャプチャ）
  - サーバ側ログ（`Sec-Fetch-Dest: iframe`、`Sec-Fetch-Site: cross-site`、`Referer`）
  - 重要操作ログ（誰が何を変更したか）
- 観測の取り方（どの視点で差分を見るか）：
  - DevTools Networkでレスポンスヘッダを確認
  - 実際に iframe で埋め込んだときの挙動（表示される/拒否される/一部だけ表示される）
  - エッジ（CDN/WAF）経由とオリジン直（可能なら）で差分がないか
  - リダイレクトチェーン全体でヘッダの有無を確認（中間レスポンスと最終HTML）
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/clickjacking 2>/dev/null
    cd ~/keda_evidence/clickjacking
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可されたスコープ** のみ
      - 観測は **代表点の抽出** のみ（全ページを網羅しない）
      - PoCは **最小限**（攻撃手順の提供ではなく、ヘッダ不備と影響の成立を示す）
  - 相関キー（最低限）を作る（後で必ず効く）
    - Host（対象ドメイン）
    - Path（対象パス）
    - Time（観測時刻）
    - X-Frame-Options（ヘッダの値）
    - Content-Security-Policy（ヘッダの値、特に`frame-ancestors`）
    - Iframe-Result（埋め込み時の挙動：表示/拒否/一部表示）
    - Sec-Fetch-Dest（サーバ側ログ）
    - Sec-Fetch-Site（サーバ側ログ）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は"手段"であり"結論"ではない。必ず「何を観測している例か」を添える。

~~~~
<!-- 最小PoC：対象ページがiframeに入るか確認するだけ -->
<!doctype html>
<html>
  <head><meta charset="utf-8"><title>frame test</title></head>
  <body>
    <h1>Frame Test (Authorized Only)</h1>
    <iframe src="https://target.example.com/settings" style="width:1200px;height:800px;border:1px solid #ccc"></iframe>
  </body>
</html>
~~~~

- この例で観測していること：
  - 対象ページがiframeに埋め込めるか（フレーミング可否）
  - 実際のiframe表示時の挙動（表示される/拒否される/一部だけ表示される）
- 出力のどこを見るか（注目点）：
  - ブラウザのiframe内での表示結果（完全に表示されるか、拒否されるか、一部だけ表示されるか）
  - DevTools Networkでレスポンスヘッダ（`X-Frame-Options`、`Content-Security-Policy`）を確認
- この例が使えないケース（前提が崩れるケース）：
  - 許可されていないスコープへの検証（倫理・法的問題）
  - 実際の攻撃実行（目的は観測であり、攻撃ではない）
  - 影響評価が必要な場合のみ、クリック誘導の概念検証を追加（透明iframe + ダミーUI）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：UI Redressing（Clickjacking）
  - 該当要件（可能ならID）：UI Redressing対策
  - このファイルの内容が「満たす/破れる」ポイント：
    - 破れる：UI Redressing（Clickjacking）を「CSRFがあるから大丈夫」「重要操作はPOSTだから大丈夫」と誤認し、**"ユーザ操作を代理実行させる経路"**を放置する。特に、(1) 管理/権限/決済など高影響操作がフレーム内で実行可能、(2) XFO/CSP frame-ancestors の適用がページ/経路/エラーページで抜ける、(3) "埋め込み用途"の例外が広すぎて境界が崩れる、で事故が起きる。
    - 満たす：**「フレームに入れてよいページ」と「絶対に入れてはならないページ」を分離**し、原則 deny（`frame-ancestors 'none'` / `X-Frame-Options: DENY`）をデフォルトにする。例外（埋め込み）を許す場合は、専用画面化・機能縮退・トークン分離・許可親の最小化・監視（違反/異常）を設計要件化する。
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：クリックジャッキング（UI Redressing）
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：
    - クリックジャッキングは「読み取り」ではなく **"ユーザのクリックを被害者セッションで踏ませる"**攻撃。確認は (1) フレーミング可否（XFO / frame-ancestors）、(2) 高影響操作のUI到達性（モーダル/確認/二要素/再認証の有無）、(3) 例外パス（サブドメイン/古い画面/エラー/リダイレクト）を、PoCフレームで観測して成立条件を固める。
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Vulnerability Analysis、Exploitation、Reporting
  - 前後フェーズとの繋がり（1行）：
    - Vulnerability Analysisで「UI操作が攻撃面になる高影響機能」を抽出し、Exploitationは**最小PoC**（自前HTMLでのiframe）で成立根拠を示す。Reportingは「ヘッダの設計要件」「例外の許容範囲」「運用/監視（逸脱検知）」まで落とす。
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：User Execution（T1204）、Phishing（T1566）
  - 攻撃者の目的（この技術が支える意図）：
    - ユーザ操作の誘導（ソーシャル/誘導）を起点に、権限操作・設定変更・連携追加・送金/承認等のImpactに繋がり得る。
    - 注意：ATT&CKへの接続は、(a) フレーム可能、(b) ユーザ操作で高影響操作が完遂、(c) 追加の再認証/確認で止まらない、の観測が揃ってから断定する。
  - 参照：https://attack.mitre.org/tactics/TA0001/（Initial Access）、https://attack.mitre.org/tactics/TA0040/（Impact）

## 参考（必要最小限）
- MDN: X-Frame-Options - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
- MDN: Content-Security-Policy: frame-ancestors - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors
- OWASP: Clickjacking Defense Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html
- RFC 7034: HTTP Header Field X-Frame-Options - https://tools.ietf.org/html/rfc7034
- W3C: Content Security Policy Level 3 - https://www.w3.org/TR/CSP3/#directive-frame-ancestors

## リポジトリ内リンク（最大3つまで）
- 関連 topics：
  - `01_topics/02_web/06_config_03_セキュリティヘッダ（CSP_HSTS_Frame_Referrer）.md`（セキュリティヘッダ総合）
  - `01_topics/02_web/03_authz_06_privileged_action_重要操作（承認_送金_権限）.md`（重要操作の境界）
  - `01_topics/02_web/02_authn_16_step-up_再認証境界（重要操作_再確認）.md`（再認証の境界）
- 関連 playbooks：
  - （該当するplaybookがあれば記載）
- 関連 labs / cases：
  - `04_labs/02_web/08_clickjacking_01_xfo_vs_frame_ancestors_matrix/`（候補）
  - `04_labs/02_web/08_clickjacking_02_exception_design_embed_only_pages/`（候補）

---

## 深掘りリンク（最大8）
- `01_topics/02_web/07_browser_security_境界（SOP_CORS_CSP）.md`
- `01_topics/02_web/06_config_03_セキュリティヘッダ（CSP_HSTS_Frame_Referrer）.md`
- `01_topics/02_web/05_input_07_csrf_01_token（synchronizer_double_submit）.md`
- `01_topics/02_web/05_input_07_csrf_02_samesite（cookie_credential）.md`
- `01_topics/02_web/03_authz_06_privileged_action_重要操作（承認_送金_権限）.md`
- `01_topics/02_web/02_authn_16_step-up_再認証境界（重要操作_再確認）.md`
- `01_topics/02_web/02_authn_01_cookie属性と境界（Secure_HttpOnly_SameSite_Path_Domain）.md`
- `01_topics/02_web/04_api_04_webhook_受信側の信頼境界（署名_再送）.md`
