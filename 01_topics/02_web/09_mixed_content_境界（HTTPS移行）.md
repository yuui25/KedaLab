# 09_mixed_content_境界（HTTPS移行）
HTTPSページ内の"HTTP残存"が、実行・表示・外部接続の境界を壊す条件を観測で確定する

---

## 目的（この技術で到達する状態）
- Mixed Content を「警告が出る/出ない」の話ではなく、**境界（資産/信頼/権限）**として説明できる。
- Mixed Content の種類（active/passive、ws、CSS、iframe等）を"影響の強さ"で分類できる。
- ブラウザが **ブロックするのか/読み込むのか** を、ページ単位・経路単位で観測し状態化できる。
- HTTPS移行の設計（参照統一、HSTS、CSP upgrade/ブロック、外部依存棚卸し）を、優先度と分岐で提示できる。
- 攻撃者視点で「何が起きるなら危険か（成立条件）」を、過不足なく示せる。
- 次の一手を A/B 分岐で固定できる（"機能破壊の修正"か、"真正性崩れの是正"か、"例外隔離"か）。

## 前提（対象・範囲・想定）
- 対象：HTTPSページ内のHTTP参照（HTML/JS/CSS/API/WebSocket/iframe等）
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - CDN/WAF/Proxy等の中継点が関与する場合、URL書き換えや設定の差分が生じ得る
  - 部分移行（一部パス/サブドメインだけ未移行）の状態
  - 外部依存（CDN/タグ/解析SDK/広告）がhttps対応不完全な状態
- できること/やらないこと（安全に検証する範囲）：
  - できる：許可されたスコープ内での観測（DevTools/プロキシ/ログ）、自環境での検証
  - やらない：実際の攻撃実行、許可されていない対象への検証、本番環境での意図的な改ざん
- 依存する前提知識（必要最小限）：
  - HTTP/HTTPSの基本、TLS/証明書の基本
  - ブラウザのMixed Contentポリシー（ブロック/警告/読み込み）
  - HSTS、CSPの基本
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：
    - Mixed Content の定義と分類（active/passive、外部接続、WebSocket、iframe等）
    - HTTPS移行時に残りやすい経路（HTML/JS/CSS/テンプレ/設定/外部依存/旧UI）
    - 観測ポイント（DevTools/プロキシ/ログ）と結果の意味（状態分類）
    - 是正の方針（参照統一、段階導入、HSTS/CSP、例外設計）
  - 扱わない（別ユニットへ接続）：
    - TLS/証明書/CT等の深掘り → `01_topics/01_asm-osint/02_tls_証明書・CT・外部依存推定.md`
    - CSP全体設計 → `01_topics/02_web/06_config_03_セキュリティヘッダ（CSP_HSTS_Frame_Referrer）.md`
    - ブラウザ境界の総合 → `01_topics/02_web/07_browser_security_境界（SOP_CORS_CSP）.md`
    - XSSの入口と成立 → `01_topics/02_web/05_input_06_xss_0x_*.md`

---


## 観測ポイント（何を見ているか：プロトコル/データ/境界）
- 観測対象（プロトコル/データ構造/やり取りの単位）：
  - HTTPレスポンス（HTML/JS/CSS/画像/フォント/API/WebSocket）
  - ブラウザのConsole/Network/Securityパネル（Mixed Content警告/ブロック理由/対象URL）
  - サーバ/エッジのヘッダ（HSTS、CSP upgrade/ブロック）
  - HAR（対象URL・起点・成否の再現性のある記録）
- 境界の観点：
  - 資産境界（管理主体・委託先・対象範囲の線引き）：
    - 影響対象：HTML（起点）、JS/CSS/画像/フォント、API（JSON等）、WebSocket、埋め込み（iframe）
    - 残存しやすい経路：HTMLテンプレの絶対URL、JS内のエンドポイント文字列、CSS（背景画像/フォント/外部import）、外部依存（CDN/タグ/解析SDK/広告）、リダイレクト/ロードバランサ設定の"取り残し"
  - 信頼境界（外部連携・第三者・越境ポイント）：
    - HTTPS（信頼）に対し、HTTP（非信頼）が混入することで「経路上の第三者」が介在可能になる
    - 外部依存（CDN/タグ/解析SDK）が "https対応不完全" だと残存しやすい
    - 中継点（CDN/WAF/Proxy）の関与（URL書き換え、環境差）
  - 権限境界（権限の切替/伝播/委任）：
    - 被害者のセッションで実行・操作が起きる可能性（特に実行系）
    - API接続がHTTPだと、操作/応答の真正性が崩れ、誤操作・誤状態が起き得る
- 重要なフィールド/差分/状態（「ここが変わると意味が変わる」点）：
  - リソース種別：Active Mixed Content（script/iframe/object/ws） vs Passive/Display Mixed Content（画像/CSS/フォント）
  - ブロック状態：ブロックされる vs 読み込まれる vs HTTPSへ自動アップグレードされる
  - 起点（Initiator）：HTML/JS/CSSのどれが起点か
  - 取得の成否：blocked / redirected / 200
  - 最終URL：http→httpsの置換が起きているか

---

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が"確定"できるか：
  - どのリソース種別がHTTP参照か（script/iframe/ws/画像/CSS等）
  - ブラウザがブロックするか/読み込むか/HTTPSへ自動アップグレードするか
  - 起点（Initiator）がHTML/JS/CSSのどれか
  - HSTS/CSP upgrade/ブロックの有無
- 何が"推定"できるか（推定の根拠/前提）：
  - 実行境界が崩れる可能性（active mixed content が成立する場合）
    - "HTTPSで守られているはずのページ"に、経路上の第三者が介入できる前提が揃う
    - そのリソースが "権限のある操作" に到達できるページで起きているか
  - 誤誘導/追跡が成立する可能性（display mixed content が残る場合）
    - 画像やCSS等でも、外部へリクエストが飛ぶ（追跡）、表示が変わる（誤誘導）前提になり得る
  - 外部接続境界が崩れる可能性（http API / ws が残る場合）
    - 操作イベント・通知・リアルタイム更新が盗聴/改ざんされ得る
- 何は"言えない"か（不足情報・観測限界）：
  - 実際の攻撃成功の有無（観測だけでは確定できない）
  - 例外クライアント（組み込みWebView/古い環境）での成立可能性（対象範囲を境界として明記する必要がある）
  - 環境差による壊れやすさ（https側が存在しない/証明書が不正/ホスト名が違う等）
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：ブラウザがブロックしている（機能障害として出る）
    - 異常：直接の改ざんリスクは"当該ブラウザでは"顕在化しにくいが、**移行品質の失敗**（本番で機能が壊れる）として重大になり得る
  - パターンB：読み込まれている（警告止まり/例外成立）
    - 異常：表示系なら追跡/誤誘導の前提、実行系なら改ざんで実行境界が壊れ得る
  - パターンC：HTTPSへ自動アップグレードされて成立している（移行の段階措置）
    - 境界がズレている："参照文字列がhttpのまま"でも、運用として成立する場合があるが、環境差により壊れる可能性がある

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す"狙い目"：
  - Active Mixed Content（実行・操作に直結しやすい）
    - 典型：`<script src="http://...">`、`<iframe src="http://...">`、`<object/data>`, `ws://` 接続 等
    - 一部クライアント/条件で通る場合 → **改ざんで実行境界が崩れる**ため、影響が重い
  - Passive/Display Mixed Content（表示・追跡・誤誘導に寄りやすい）
    - 典型：画像、アイコン、CSS背景画像、フォント等（HTTP参照）
    - 追跡（リクエストが外へ飛ぶ）や、表示改ざん（誤誘導）の前提になり得る
  - Mixed WebSocket（wssページから ws://）
    - 典型：通知・チャット・リアルタイム更新が ws:// で残る
    - 通信内容が盗聴/改ざんされ得る（特に操作イベントやトークン）
- 優先度の付け方（時間制約がある場合の順序）：
  1. Active Mixed Content（script/iframe/ws）が読み込まれているかを確認
  2. 発生ページの権限境界を評価（ログイン後、管理、決済、テナント操作 など）
  3. 外部依存（CDN/タグ/解析SDK/広告）の残存を確認
  4. 例外経路（管理画面・旧UI・メールリンク到達・エラーHTML）の残存を確認
- 代表的な攻め筋（この観測から自然に繋がるもの）：
  - 攻め筋1：実行境界が崩れる（active mixed content が成立する場合）
    - 成立条件：HTTP参照のscript/iframe/ws等が実際に読み込まれている + 権限のある操作に到達できるページ
    - 結果：ページ内での任意実行・操作・外部送信が成立し得る
  - 攻め筋2：誤誘導/追跡が成立する（display mixed content が残る場合）
    - 成立条件：画像やCSS等のHTTP参照が読み込まれている + ログイン後/管理画面/決済画面等の高権限ページ
    - 結果：外部へリクエストが飛ぶ（追跡）、表示が変わる（誤誘導）
  - 攻め筋3：外部接続境界が崩れる（http API / ws が残る場合）
    - 成立条件：API/WebSocketがHTTPで接続されている
    - 結果：操作イベント・通知・リアルタイム更新が盗聴/改ざんされ得る（特にトークン/ID/状態更新が混ざると影響が増える）
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）：
  - CDN/WAF/Proxy等の中継点が関与する場合：URL書き換えや設定の差分を確認
  - 部分移行（一部パス/サブドメインだけ未移行）の場合：例外経路を優先的に確認
  - 外部依存がhttps対応不完全な場合：その依存は必須か（削除/置換/自社ホスト化が可能か）を判断

---

## 次に試すこと（仮説A/Bの分岐と検証）
> ここが最重要。条件が違うと次の手が変わる形で書く。

- 仮説A：ブラウザがブロックしている（機能障害として出る）
  - 成立条件：Console/Networkに "blocked:mixed-content" 等の拒否理由が出る、該当リソースが pending / canceled / blocked になる
  - 次の検証（優先：移行品質の是正）：
    1) 対象URLとInitiatorを確定（HTML/JS/CSSのどこが起点か）
    2) 修正方針を決める（https固定、相対URL化、設定値の置換、依存の差し替え）
    3) "例外経路だけ残る"を潰すため、同一機能の別到達（旧UI、メールリンク、エラーHTML）も確認する
    4) 再発防止：CIでの静的検出（http参照検出）や、監視（Consoleエラー/フロント計測）を設計要件に含める
  - 期待する観測（成功/失敗時に何が見えるか）：
    - 成功：対象URLとInitiatorが確定し、修正方針が決まる
    - 失敗：例外経路で残存が発見される、または例外クライアント（組み込みWebView/古い環境）で成立する可能性がある
- 仮説B：読み込まれている（警告止まり/例外成立）
  - 成立条件：NetworkでHTTPリソースが200で取得できている（または中継で見える）、Securityパネルで "insecure content" 等が表示される
  - 次の検証（優先：影響半径の確定→是正）：
    1) リソース種別ごとに影響を分ける（script/iframe/ws は高、画像等は状況依存）
    2) 発生ページの権限境界を評価（ログイン後、管理、決済、テナント操作 など）
    3) 外部依存なら「管理主体」と「置換可能性」を決め、最終的に https へ統一する
    4) 最後の門として、HSTS/CSP（upgrade/ブロック）で"残存"を抑え込む（ただし段階導入）
  - 期待する観測：
    - 成功：リソース種別ごとの影響が分かり、発生ページの権限境界が評価される
    - 失敗：影響半径が広すぎる、または外部依存の置換が困難
- 仮説C：HTTPSへ自動アップグレードされて成立している（移行の段階措置）
  - 成立条件：ブラウザまたはCSP（upgrade系）で、http参照がhttpsへ置換されて取得できている
  - 次の検証（優先：恒久化）：
    1) 参照文字列（http）が残っている箇所を除去（相対/https固定）
    2) アップグレードに依存していた外部ドメイン（https対応が不完全）を棚卸しして置換/自社ホスト化を検討
    3) 移行計画として、report（観測）→強制（ブロック）の順で運用へ落とす
  - 期待する観測：
    - 成功：参照文字列がhttps固定/相対化され、外部ドメインの棚卸しが完了する
    - 失敗：https側が存在しない/証明書が不正/ホスト名が違う等で、環境差により壊れる可能性がある

---

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/02_web/09_mixed_content_01_active_vs_display_blocking/`（候補）
    - `04_labs/02_web/09_mixed_content_02_ws_to_wss_migration_boundary/`（候補）
    - `04_labs/02_web/09_mixed_content_03_hsts_csp_upgrade_enforce_rollout/`（候補）
- 取得する証跡（目的ベースで最小限）：
  - ブラウザのConsole/Network/Securityパネル（Mixed Content警告/ブロック理由/対象URL）
  - HAR（対象URL・起点・成否の再現性のある記録）
  - サーバログ（http側への到達）
  - 必要ならpcap（盗聴の事実は"自環境"でのみ検証）
- 観測の取り方（どの視点で差分を見るか）：
  - ブラウザ観測（最優先：拒否理由と対象資産を取る）
    - Console：Mixed Content の警告/ブロック理由（どのURLが対象か）
    - Network：対象リクエストのスキーム（http/ws）と Initiator（HTML/JS/CSSのどれが起点か）、取得の成否（blocked / redirected / 200）と最終URL（http→httpsの置換が起きているか）
    - Security（可能なら）：ページが "secure" でも "insecure requests" が混在していないか
  - サーバ/エッジ観測（ヘッダと移行施策の有無）
    - HSTS（Strict-Transport-Security）が出ているか（ドメイン/サブドメイン適用の方針が見える）
    - CSPで upgrade/ブロックの方針があるか（存在するなら段階導入中の可能性）
  - 中継点（CDN/WAF/Proxy）の関与
    - HTMLはhttpsだが、裏のAPI/WSがhttpに落ちる（別ホスト、別LB、別設定）
    - 中継でURL書き換えをしている（環境差が出やすい）
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/mixed_content 2>/dev/null
    cd ~/keda_evidence/mixed_content
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可されたスコープ** のみ
      - 観測は **代表点の抽出** のみ（全ページを網羅しない）
      - 盗聴の事実は **自環境でのみ検証**（pcap等）
  - 相関キー（最低限）を作る（後で必ず効く）
    - Host（対象ドメイン）
    - Path（対象パス）
    - Time（観測時刻）
    - Resource-Type（リソース種別：script/iframe/ws/画像/CSS等）
    - Scheme（スキーム：http/ws）
    - Initiator（起点：HTML/JS/CSS）
    - Status（取得の成否：blocked/redirected/200）
    - Final-URL（最終URL：http→httpsの置換が起きているか）
    - HSTS（Strict-Transport-Securityの有無）
    - CSP（upgrade/ブロックの有無）

---

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は"手段"であり"結論"ではない。必ず「何を観測している例か」を添える。

~~~~
# 記録の基本：
# - ブラウザ（Console/Network/Security）で「どのURLが混在し、ブロック/成功のどちらか」を確定する
# - Initiator で起点（HTML/JS/CSS）を特定し、修正箇所の優先度を付ける
# - エッジ/オリジンでHSTS/CSP等の移行施策が統一されているかを確認する（経路差分が残存の原因になりやすい）
~~~~

- この例で観測していること：
  - どのURLがHTTP参照で混在しているか（対象URLの特定）
  - ブラウザがブロックするか/読み込むか/HTTPSへ自動アップグレードするか（成立状態の確定）
  - 起点（Initiator）がHTML/JS/CSSのどれか（修正箇所の優先度付け）
  - HSTS/CSP等の移行施策が統一されているか（経路差分の確認）
- 出力のどこを見るか（注目点）：
  - Console：Mixed Content の警告/ブロック理由
  - Network：対象リクエストのスキーム（http/ws）、Initiator、取得の成否（blocked / redirected / 200）、最終URL
  - Security：ページが "secure" でも "insecure requests" が混在していないか
  - サーバ/エッジのヘッダ：HSTS、CSP upgrade/ブロック
- この例が使えないケース（前提が崩れるケース）：
  - 許可されていないスコープへの検証（倫理・法的問題）
  - 実際の攻撃実行（目的は観測であり、攻撃ではない）
  - 本番環境での意図的な改ざん（検証環境でのみ実施）

---

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：HTTPS移行、Mixed Content対策
  - 該当要件（可能ならID）：HTTPS移行、Mixed Content対策
  - このファイルの内容が「満たす/破れる」ポイント：
    - 破れる：HTTPS化（TLS終端）により"安全になった"と誤認し、**HTTPSページ内にHTTP（/ ws / 旧CDN）参照が残る**ことで、(1) ブラウザでブロックされ機能が壊れる、(2) 一部クライアントで読み込みが成立し通信の真正性が崩れる、(3) 例外経路（管理画面・旧UI・メールリンク到達・エラーHTML）だけ取り残される、などの状態になる。結果として、実行境界（スクリプト）・表示境界（CSS/画像）・外部接続境界（API/WebSocket）が壊れ、盗聴/改ざん/誤誘導/セッション悪用の前提が揃い得る。
    - 満たす：HTTPS移行は「証明書が出た」で完了ではなく、**Mixed Content を"境界違反"としてゼロ化**する。方針は (a) 参照のHTTPS化（相対URL化・https固定）、(b) 例外が必要なら専用経路へ隔離、(c) 監視（ブラウザ警告/ログ/レポート）で逸脱を検知、(d) HSTS と CSP（upgrade/ブロック）で最後の門を閉じる、までを要件化する。
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：Mixed Content（HTTPS移行品質）
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：
    - Mixed Content は「脆弱性」だけでなく **移行/運用の品質**として出る。テストは (1) どのリソース種別がHTTP参照か、(2) ブラウザがブロックするか/読み込むか、(3) 読み込まれる場合の影響（改ざん・追跡・実行）と範囲、(4) 修正案（参照統一/HSTS/CSP/依存整理）までを、観測→意味→次の一手で固定する。
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Recon、Vulnerability Analysis、Exploitation、Reporting
  - 前後フェーズとの繋がり（1行）：
    - Recon（TLS終端/サブドメイン/外部依存）と、Vulnerability Analysis（境界崩れ）を繋ぐ"移行品質の評価点"。Exploitationは原則として「成立条件の提示」と「影響半径の根拠」まで（過剰な手順化は不要）。Reportingでは、HTTP残存の棚卸し、段階的是正（report→強制）、ロールバック可能な移行計画まで落とす。
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Initial Access（T1204）、Collection（T1005）、Credential Access（T1552）、Impact（T1499）
  - 攻撃者の目的（この技術が支える意図）：
    - 条件付きで、初期侵入（公開アプリ経由）や実行（外部スクリプト改ざん）に接続し得る。
    - Collection（盗聴/追跡）、Credential Access（セッション/トークン周辺の前提崩れ）、Impact（誤誘導・機能破壊）へ繋がり得るが、断定は「どのリソースが読み込まれ、どのクライアントで成立し、何が改ざん可能か」が観測で揃ってから行う。
  - 参照：https://attack.mitre.org/tactics/TA0001/（Initial Access）、https://attack.mitre.org/tactics/TA0009/（Collection）、https://attack.mitre.org/tactics/TA0006/（Credential Access）、https://attack.mitre.org/tactics/TA0040/（Impact）

## 参考（必要最小限）
- MDN: Mixed Content - https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content
- W3C: Mixed Content - https://www.w3.org/TR/mixed-content/
- OWASP: Transport Layer Protection Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html
- Google: Mixed Content - https://developers.google.com/web/fundamentals/security/prevent-mixed-content/what-is-mixed-content

## リポジトリ内リンク（最大3つまで）
- 関連 topics：
  - `01_topics/02_web/06_config_03_セキュリティヘッダ（CSP_HSTS_Frame_Referrer）.md`（セキュリティヘッダ総合）
  - `01_topics/02_web/07_browser_security_境界（SOP_CORS_CSP）.md`（ブラウザ境界の総合）
  - `01_topics/01_asm-osint/02_tls_証明書・CT・外部依存推定.md`（TLS/証明書の深掘り）
- 関連 playbooks：
  - （該当するplaybookがあれば記載）
- 関連 labs / cases：
  - `04_labs/02_web/09_mixed_content_01_active_vs_display_blocking/`（候補）
  - `04_labs/02_web/09_mixed_content_02_ws_to_wss_migration_boundary/`（候補）
  - `04_labs/02_web/09_mixed_content_03_hsts_csp_upgrade_enforce_rollout/`（候補）

---

## 深掘りリンク（最大8）
- `01_topics/02_web/07_browser_security_境界（SOP_CORS_CSP）.md`
- `01_topics/02_web/06_config_03_セキュリティヘッダ（CSP_HSTS_Frame_Referrer）.md`
- `01_topics/01_asm-osint/02_tls_証明書・CT・外部依存推定.md`
- `01_topics/01_asm-osint/21_third-party_外部依存（タグ_分析SDK）洗い出し.md`
- `01_topics/02_web/02_authn_01_cookie属性と境界（Secure_HttpOnly_SameSite_Path_Domain）.md`
- `01_topics/02_web/05_input_06_xss_01_反射_境界モデル.md`
- `01_topics/02_web/04_api_00_権限伝播・入力・バックエンド連携.md`
- `01_topics/02_web/06_config_00_設定・運用境界（CORS ヘッダ Secrets）.md`
