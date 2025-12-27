# 21_third-party_外部依存（タグ_分析SDK）洗い出し
Third-party 外部依存（タグ/分析SDK）洗い出し
“信頼境界（trust boundary）：どの第三者ドメインへ通信・データ送信しているかを特定できる”

## 目的（この技術で到達する状態）
Webサイト/アプリが依存している third-party（タグ、分析SDK、広告、チャット、A/Bテスト、CDN、決済、Captcha 等）を ASM/OSINT の範囲で洗い出し、次を「証跡つき」「優先度つき」で確定できる状態にする。
- 信頼境界（trust boundary）：どの第三者ドメインへ通信・データ送信しているかを特定できる
- 攻撃面（入口）：第三者スクリプト/iframe/タグ経由で追加される面（endpoint/連携URL/コールバック）を抽出できる
- データ境界：PII/セッション/識別子が “どこへ流れ得るか” を推定し、後工程（02_web/認証、03_http、05_cloud）へ渡せる
- “重要依存” と “周辺依存” を分離し、レビュー・監視・優先度（P0/P1/P2）を付けられる

## 前提（対象・範囲・想定）
- 対象：Webサイト/アプリが依存している third-party（タグ、分析SDK、広告、チャット、A/Bテスト、CDN、決済、Captcha 等）。原則は OSINT：HTML/JS/CSS、sourcemap（14）、ネットワーク観測の最小範囲、公開ドキュメントから把握する
- 想定する環境：
  - third-party は正当な運用も多い（分析/計測/UX改善）。リスク評価は “データ/権限/重要導線への近さ” で行う
  - 依存は頻繁に変わる（タグ更新・新サービス導入）。証跡（観測時点）を必ず残す
- できること/やらないこと（安全に検証する範囲）：
  - できる：原則は OSINT：HTML/JS/CSS、sourcemap（14）、ネットワーク観測の最小範囲、公開ドキュメントから把握する。“利用の把握” が目的
  - やらない：本ファイルは “利用の把握” が目的であり、第三者サービスへの不正アクセスや、悪用手順の具体化は扱わない
- 依存する前提知識（必要最小限）：
  - `01_topics/01_asm-osint/14_js_sourcemap_公開物から攻撃面抽出（endpoint_key）.md`
  - `01_topics/01_asm-osint/03_http_観測（ヘッダ・挙動）と意味.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：Third-party 外部依存（タグ/分析SDK）洗い出し、信頼境界・攻撃面・データ境界の特定
  - 扱わない（別ユニットへ接続）
    - Sourcemap → `14_js_sourcemap_公開物から攻撃面抽出（endpoint_key）.md`
    - HTTP観測 → `03_http_観測（ヘッダ/挙動）と意味.md`
    - API仕様 → `01_topics/01_asm-osint/15_api_spec_公開（OpenAPI_GraphQLスキーマ）から面抽出.md`
    - Storage → `01_topics/01_asm-osint/18_storage_discovery（S3_GCS_AzureBlob）境界推定.md`

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
- 観測対象（プロトコル/データ構造/やり取りの単位）
  - 入口（依存の出どころ）を分解する
    - HTML：script/link/iframe/img/beacon、meta（verification系）
    - JS：動的ロード（createElement, import(), eval相当、tag manager）
    - Tag Manager：GTM等（tagの集合体。背後が見えないので別扱い）
    - CSP（Content-Security-Policy）：許可先のドメイン群（実際の通信先の上限として有用）
    - DNS/TLS：CDN/計測ドメインの推定（CNAMEや証明書SANがヒントになる）
    - 公開ドキュメント：プライバシーポリシー/クッキーポリシー/利用規約にベンダ一覧が載ることがある
  - 何を “third-party 依存” として記録するか
    - ドメイン依存：`*.example-cdn.com` など外部ホスト
    - スクリプト依存：外部JS（analytics.js等）
    - iframe依存：埋め込み（captcha、決済、チャット）
    - SDK依存：npm等の依存（フロントビルドに入り込む）
    - Webhook/Callback依存：決済/認証/通知で “外部から呼ばれる入口” が増える
  - データ境界（何が送られ得るか）を推定する
    - OSINT段階では “断定” せず、送信可能性を分類する。
    - 送信され得るデータ：識別子（cookie、localStorage、device id、広告ID）、セッション（JWT、session id（設計ミスで送られるケース））、PII（メール、電話、住所、氏名（フォーム連携・計測））、行動ログ（URL、リファラ、クリック、入力イベント）
    - 観測シグナル：URLクエリに PII らしき値、送信先が “フォーム/CRM/サポート” 系（データが濃い傾向）、Tag Manager 経由で多岐（未知が増える）
- 境界の観点
  - 資産境界（管理主体・委託先・対象範囲の線引き）：third-party は正当な運用も多い（分析/計測/UX改善）。リスク評価は “データ/権限/重要導線への近さ” で行う
  - 信頼境界（外部連携・第三者・越境ポイント）：重要導線への近さ（login/reset/billing/support などのページで動くか）、実行権限（JS（同一オリジンで実行）/ iframe（隔離）/ サーバサイド送信（見えにくい））、サプライチェーン観点（依存ライブラリ/外部スクリプトの改ざん耐性（SRI、固定バージョン、署名等の有無））、運用境界（委託先が多いほど、漏えい/障害/改ざんの影響が大きくなる）
  - 権限境界（権限の切替/伝播/委任）：認証/セッションの機微情報が第三者に露出しない設計が必要
- 重要なフィールド/差分/状態（「ここが変わると意味が変わる」点）
  - dep_key_boundary（後工程に渡す正規化キー）
    - dep_key_boundary = <site_or_app> + <third_party_domain> + <integration_type> + <data_class> + <route_criticality> + <confidence>
  - integration_type（例）
    - script | iframe | tag_manager | sdk | webhook | cdn | api
  - data_class（例：OSINT推定）
    - pii_possible | session_possible | behavior_only | unknown
  - route_criticality（例）
    - auth | billing | support | general | unknown

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が“確定”できるか
  - third-party の “存在” と “統合形態”（script/iframe/SDK等）
  - 信頼境界の広さ（外部送信先/実行主体の増加）
  - 重要導線（auth/billing/support）に third-party が絡んでいるかの示唆
- 何が“推定”できるか（推定の根拠/前提）
  - 実際に送信されたデータの内容（完全には断定できない。実測が必要）
- 何は“言えない”か（不足情報・観測限界）
  - 実際に送信されたデータの内容（完全には断定できない。実測が必要）
  - その third-party 自体の脆弱性有無（別の調査軸）
  - 改ざんの実発生（監視/整合チェックが必要）
- よくある状態パターン（正常/異常/境界がズレている等）
  - パターンA：依存が多すぎて把握できない（ノイズが多い）
  - パターンB：重要導線で外部JSが実行される（P0候補）
  - パターンC：iframe主体で隔離されている（影響は限定的に見える）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す“狙い目”（診断上の優先度付けとして使う）
  - P0（最優先でレビュー/監視すべき）：認証/決済/サポート等の重要導線で、外部scriptが実行される（JS権限が強い）、Tag Manager が導入されており、背後の依存が不透明（未知が大きい）、送信先が “フォーム/CRM/サポート” 系で、PIIが濃い導線に近い
  - P1（優先的に面へ投入）：CDN/計測が多く、CSP許可先が広い（外部送信面が広い）、iframe型でも、決済/認証連携がある（コールバック/リダイレクト面が増える）
  - P2（整理・棚卸し）：静的配信のみ（フォントCDN等）で、重要導線と遠い、依存はあるが、隔離（iframe）で影響が限定的なもの
- 優先度の付け方（時間制約がある場合の順序）
  - P0（最優先でレビュー/監視すべき）→ P1（優先的に面へ投入）→ P2（整理・棚卸し）の順
- 代表的な攻め筋（この観測から自然に繋がるもの）
  - 攻め筋1：14_js_sourcemap：JSの動的ロード/依存先ドメイン抽出の裏取り
  - 攻め筋2：03_http_観測：CSP/ヘッダ/リダイレクト、重要導線での外部送信の存在確認（低アクティブ）
  - 攻め筋3：15_api_spec：webhook/callback の仕様露出があれば面抽出へ
  - 攻め筋4：18_storage_discovery：外部依存がストレージ配布/ログ保管に繋がる場合がある
  - 攻め筋5：19_email_infra：外部通知/フォーム運用がメール送信SaaSに繋がる可能性
  - 攻め筋6：02_web（後続）：認証導線での外部JSはセッション/トークン取り扱いの検証優先度を上げる
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）
  - 依存が多すぎて把握できない（ノイズが多い） → “重要導線のページ” に絞って抽出（auth/billing/support）、Tag Manager を別枠化（GTM等は “依存の母体” として扱い、背後は追加観測タスクにする）、ドメインを “ベンダ単位” に正規化（サブドメイン乱立を束ねる）

## 次に試すこと（仮説A/Bの分岐と検証）
> ここが最重要。条件が違うと次の手が変わる形で書く。

- 仮説A：依存が多すぎて把握できない（ノイズが多い）
  - 次の検証：
    - “重要導線のページ” に絞って抽出（auth/billing/support）
    - Tag Manager を別枠化（GTM等は “依存の母体” として扱い、背後は追加観測タスクにする）
    - ドメインを “ベンダ単位” に正規化（サブドメイン乱立を束ねる）
  - 期待する観測（成功/失敗時に何が見えるか）：
    - 依存の整理と、優先度付けの改善
- 仮説B：重要導線で外部JSが実行される（P0候補）
  - 次の検証：
    - （OSINTの安全域）依存の形（script/iframe）と CSP 許可先をセットで記録し、信頼境界の根拠にする。SRI（Subresource Integrity）の有無、バージョン固定の有無を観測（改ざん耐性の示唆）。“どのイベントで送信されそうか”（フォーム送信/ページ遷移）をコード断片から推定して data_class を上げる
    - （後工程への受け渡し）02_web の認証/セッション観測で、トークンが URL/JS に露出しない設計かを重点チェックにする。23_vdp_scope を想定し、観測は最小（既存ページ閲覧＋ヘッダ/静的解析）で留める
  - 期待する観測：
    - 依存の形とCSP許可先の記録、SRI/バージョン固定の有無、送信イベントの推定、認証/セッション観測の結果
- 仮説C：iframe主体で隔離されている（影響は限定的に見える）
  - 次の検証：
    - iframe の src ドメインと、リダイレクト/コールバック先（自ドメイン側の入口）が増えていないかを確認
    - 15_api_spec / 03_http に繋いで “外部→自ドメイン” の入口（webhook/callback）を整理
  - 期待する観測：
    - iframe の src ドメインとリダイレクト/コールバック先の確認、webhook/callback の整理

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/01_local/01_attack-box_作業端末設計.md`（結果の保存・差分管理）
    - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`（現状確認の最小証跡）
- 取得する証跡（目的ベースで最小限）
  - dep_key_boundary（後工程に渡す正規化キー）
    - dep_key_boundary = <site_or_app> + <third_party_domain> + <integration_type> + <data_class> + <route_criticality> + <confidence>
  - 記録の最小フィールド（推奨）
    - source_locator: 観測元（URL、HTML/JSの箇所、sourcemap、CSP等）
    - third_party_domain: ドメイン
    - artifact_type: script/iframe/sdk/tag_manager/cdn 等
    - observed_signal: 何で分かったか（タグ、CSP、URL、ライブラリ名）
    - data_class: 上記分類
    - route_criticality: 重要導線との関係
    - confidence: high/mid/low
    - action_priority: P0/P1/P2
- 観測の取り方（どの視点で差分を見るか）
  - 原則は OSINT：HTML/JS/CSS、sourcemap（14）、ネットワーク観測の最小範囲、公開ドキュメントから把握する
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/thirdparty_21 2>/dev/null
    cd ~/keda_evidence/thirdparty_21
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可されたスコープ** のみ（契約範囲/社内許可範囲/自前検証環境）
      - 観測は **代表点の抽出** のみ（原則は OSINT：HTML/JS/CSS、sourcemap（14）、ネットワーク観測の最小範囲、公開ドキュメントから把握する）
      - 観測視点（端末/経路/ネットワーク）を記録
  - 相関キー（最低限）を作る（後で必ず効く）
    - SiteOrApp：site_or_app
    - ThirdPartyDomain：third_party_domain
    - IntegrationType：integration_type（script/iframe/tag_manager/sdk/webhook/cdn/api）
    - DataClass：data_class（pii_possible/session_possible/behavior_only/unknown）
    - RouteCriticality：route_criticality（auth/billing/support/general/unknown）
    - Confidence：confidence（high/mid/low）
    - ActionPriority：action_priority（P0/P1/P2）
    - Timestamp：観測日時（JSTで秒まで）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は“手段”であり“結論”ではない。必ず「何を観測している例か」を添える。

~~~~
# 最小の観測例（HTML/JS/CSPから依存を拾う：例示のみ）

## 出力例（最小）
- `gtm`/`analytics` の外部ドメイン

# HTMLで第三者script/iframeを拾う（例：タグを眺める）

## 出力例（最小）
- `gtm`/`analytics` の外部ドメイン
# <script src="https://third.example/sdk.js"></script>

## 出力例（最小）
- `gtm`/`analytics` の外部ドメイン
# <iframe src="https://pay.example/checkout"></iframe>

## 出力例（最小）
- `gtm`/`analytics` の外部ドメイン

# CSPで許可先を拾う（例：script-src/connect-src）

## 出力例（最小）
- `gtm`/`analytics` の外部ドメイン
# Content-Security-Policy: script-src 'self' https://*.third.example; connect-src 'self' https://api.third.example

## 出力例（最小）
- `gtm`/`analytics` の外部ドメイン
~~~~

- この例で観測していること：
  - 原則は OSINT：HTML/JS/CSS、sourcemap（14）、ネットワーク観測の最小範囲、公開ドキュメントから把握する
- 出力のどこを見るか（注目点）：
  - HTML：script/link/iframe/img/beacon、meta（verification系）
  - JS：動的ロード（createElement, import(), eval相当、tag manager）
  - CSP：許可先のドメイン群（実際の通信先の上限として有用）
- この例が使えないケース（前提が崩れるケース）：
  - Tag Manager が導入されており、背後の依存が不透明（未知が大きい） → Tag Manager を別枠化（GTM等は “依存の母体” として扱い、背後は追加観測タスクにする）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：V14（設定）：CSP、外部依存管理、秘密情報の取り扱い、ログ/送信の設計に直結。V1（アーキ/要件）：信頼境界（第三者）を定義し、脅威モデリングの入力にする。V2/V3（支える前提）：認証/セッションの機微情報が第三者に露出しない設計が必要
  - 該当要件（可能ならID）：外部依存・設定・通信・境界（ASM/OSINTは“前提の崩れ”を潰す役）
  - このファイルの内容が「満たす/破れる」ポイント：
    - 破れる：CSP、外部依存管理、秘密情報の取り扱い、ログ/送信の設計を確定できないと、以降の検証で“対象外”や“前提違い”を起こし、検証精度が落ちる。
    - 満たす：外部依存・設定・通信・境界（ASM/OSINTは“前提の崩れ”を潰す役）を把握し、以降の検証（認証/認可/API/運用）を「前提崩れ」なく進める土台を作る。
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：INFO：公開情報（HTML/JS/CSP）から外部依存と攻撃面を収集。CLNT（クライアント側）：第三者JS/SDKはクライアント側の攻撃面とデータ境界を増やす
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：WSTG各観点へ入る前の“入口確定”として接続
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Intelligence Gathering → Threat Modeling：第三者依存を洗い出し、重要導線での優先度を決める
  - 前後フェーズとの繋がり（1行）：Webサイト/アプリが依存している third-party（タグ、分析SDK、広告、チャット、A/Bテスト、CDN、決済、Captcha 等）を ASM/OSINT の範囲で洗い出し、信頼境界・攻撃面・データ境界を抽出する
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Reconnaissance：公開情報から外部依存・技術境界を収集。Supply Chain（支える前提）：外部依存はサプライチェーン観点のリスク入力となる
  - 攻撃者の目的（この技術が支える意図）：Reconnaissance / Discovery として、攻め筋の確率を上げるための境界特定・依存推定。
  - 参照：https://attack.mitre.org/tactics/TA0043/

## 参考（必要最小限）
- OWASP ASVS
  https://github.com/OWASP/ASVS
- OWASP WSTG
  https://owasp.org/www-project-web-security-testing-guide/
- PTES
  https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：Reconnaissance
  https://attack.mitre.org/tactics/TA0043/
- Content Security Policy（CSP）と third-party 許可先の読み方
- Subresource Integrity（SRI）と外部スクリプト改ざん耐性の概念

## リポジトリ内リンク（最大3つまで）
- 関連 topics：
  - `01_topics/01_asm-osint/14_js_sourcemap_公開物から攻撃面抽出（endpoint_key）.md`
  - `01_topics/01_asm-osint/03_http_観測（ヘッダ/挙動）と意味.md`
- 関連 labs / cases：
  - `04_labs/01_local/01_attack-box_作業端末設計.md`

---

## 深掘りリンク（最大8）
- `01_topics/01_asm-osint/15_api_spec_公開（OpenAPI_GraphQLスキーマ）から面抽出.md`
- `01_topics/01_asm-osint/18_storage_discovery（S3_GCS_AzureBlob）境界推定.md`
- `01_topics/01_asm-osint/19_email_infra（SPF_DKIM_DMARC）と攻撃面.md`
- `01_topics/01_asm-osint/22_mobile_assets_アプリ由来攻撃面（deep-link_API）.md`
- `01_topics/02_web/01_web_00_recon_入口・境界・攻め筋の確定.md`
- `01_topics/01_asm-osint/23_vdp_scope_制約下での低アクティブ観測設計.md`
- `02_playbooks/01_asm_passive-recon_資産境界→優先度付け.md`
- `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`

---
