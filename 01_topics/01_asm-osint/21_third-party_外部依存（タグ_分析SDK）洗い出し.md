# third-party_外部依存（タグ_分析SDK）洗い出し

## 目的（この技術で到達する状態）
Webサイト/アプリが依存している third-party（タグ、分析SDK、広告、チャット、A/Bテスト、CDN、決済、Captcha 等）を ASM/OSINT の範囲で洗い出し、次を「証跡つき」「優先度つき」で確定できる状態にする。
- 信頼境界（trust boundary）：どの第三者ドメインへ通信・データ送信しているかを特定できる
- 攻撃面（入口）：第三者スクリプト/iframe/タグ経由で追加される面（endpoint/連携URL/コールバック）を抽出できる
- データ境界：PII/セッション/識別子が “どこへ流れ得るか” を推定し、後工程（02_web/認証、03_http、05_cloud）へ渡せる
- “重要依存” と “周辺依存” を分離し、レビュー・監視・優先度（P0/P1/P2）を付けられる

## 前提（対象・範囲・想定）
- 原則は OSINT：HTML/JS/CSS、sourcemap（14）、ネットワーク観測の最小範囲、公開ドキュメントから把握する
- 本ファイルは “利用の把握” が目的であり、第三者サービスへの不正アクセスや、悪用手順の具体化は扱わない
- third-party は正当な運用も多い（分析/計測/UX改善）。リスク評価は “データ/権限/重要導線への近さ” で行う
- 依存は頻繁に変わる（タグ更新・新サービス導入）。証跡（観測時点）を必ず残す

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) 入口（依存の出どころ）を分解する
- HTML：script/link/iframe/img/beacon、meta（verification系）
- JS：動的ロード（createElement, import(), eval相当、tag manager）
- Tag Manager：GTM等（tagの集合体。背後が見えないので別扱い）
- CSP（Content-Security-Policy）：許可先のドメイン群（実際の通信先の上限として有用）
- DNS/TLS：CDN/計測ドメインの推定（CNAMEや証明書SANがヒントになる）
- 公開ドキュメント：プライバシーポリシー/クッキーポリシー/利用規約にベンダ一覧が載ることがある

### 2) 何を “third-party 依存” として記録するか
- ドメイン依存：`*.example-cdn.com` など外部ホスト
- スクリプト依存：外部JS（analytics.js等）
- iframe依存：埋め込み（captcha、決済、チャット）
- SDK依存：npm等の依存（フロントビルドに入り込む）
- Webhook/Callback依存：決済/認証/通知で “外部から呼ばれる入口” が増える

### 3) データ境界（何が送られ得るか）を推定する
OSINT段階では “断定” せず、送信可能性を分類する。
- 送信され得るデータ
  - 識別子：cookie、localStorage、device id、広告ID
  - セッション：JWT、session id（設計ミスで送られるケース）
  - PII：メール、電話、住所、氏名（フォーム連携・計測）
  - 行動ログ：URL、リファラ、クリック、入力イベント
- 観測シグナル
  - URLクエリに PII らしき値
  - 送信先が “フォーム/CRM/サポート” 系（データが濃い傾向）
  - Tag Manager 経由で多岐（未知が増える）

### 4) 信頼境界（trust boundary）の読み方
- 重要導線への近さ：login/reset/billing/support などのページで動くか
- 実行権限：JS（同一オリジンで実行）/ iframe（隔離）/ サーバサイド送信（見えにくい）
- サプライチェーン観点：依存ライブラリ/外部スクリプトの改ざん耐性（SRI、固定バージョン、署名等の有無）
- 運用境界：委託先が多いほど、漏えい/障害/改ざんの影響が大きくなる

### 5) dep_key_boundary（後工程に渡す正規化キー）
- dep_key_boundary（推奨）
  - dep_key_boundary = <site_or_app> + <third_party_domain> + <integration_type> + <data_class> + <route_criticality> + <confidence>
- integration_type（例）
  - script | iframe | tag_manager | sdk | webhook | cdn | api
- data_class（例：OSINT推定）
  - pii_possible | session_possible | behavior_only | unknown
- route_criticality（例）
  - auth | billing | support | general | unknown

記録の最小フィールド（推奨）
- source_locator: 観測元（URL、HTML/JSの箇所、sourcemap、CSP等）
- third_party_domain: ドメイン
- artifact_type: script/iframe/sdk/tag_manager/cdn 等
- observed_signal: 何で分かったか（タグ、CSP、URL、ライブラリ名）
- data_class: 上記分類
- route_criticality: 重要導線との関係
- confidence: high/mid/low
- action_priority: P0/P1/P2

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える（OSINTで確定できる）
  - third-party の “存在” と “統合形態”（script/iframe/SDK等）
  - 信頼境界の広さ（外部送信先/実行主体の増加）
  - 重要導線（auth/billing/support）に third-party が絡んでいるかの示唆
- 言えない（この段階では確定しない）
  - 実際に送信されたデータの内容（完全には断定できない。実測が必要）
  - その third-party 自体の脆弱性有無（別の調査軸）
  - 改ざんの実発生（監視/整合チェックが必要）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
※“やり方”ではなく、ASMとしての優先度設計。
### 優先度（P0/P1/P2）
- P0（最優先でレビュー/監視すべき）
  - 認証/決済/サポート等の重要導線で、外部scriptが実行される（JS権限が強い）
  - Tag Manager が導入されており、背後の依存が不透明（未知が大きい）
  - 送信先が “フォーム/CRM/サポート” 系で、PIIが濃い導線に近い
- P1（優先的に面へ投入）
  - CDN/計測が多く、CSP許可先が広い（外部送信面が広い）
  - iframe型でも、決済/認証連携がある（コールバック/リダイレクト面が増える）
- P2（整理・棚卸し）
  - 静的配信のみ（フォントCDN等）で、重要導線と遠い
  - 依存はあるが、隔離（iframe）で影響が限定的なもの

### 後続トピックへの接続（地続き）
- 14_js_sourcemap：JSの動的ロード/依存先ドメイン抽出の裏取り
- 03_http_観測：CSP/ヘッダ/リダイレクト、重要導線での外部送信の存在確認（低アクティブ）
- 15_api_spec：webhook/callback の仕様露出があれば面抽出へ
- 18_storage_discovery：外部依存がストレージ配布/ログ保管に繋がる場合がある
- 19_email_infra：外部通知/フォーム運用がメール送信SaaSに繋がる可能性
- 02_web（後続）：認証導線での外部JSはセッション/トークン取り扱いの検証優先度を上げる

## 次に試すこと（仮説A/Bの分岐と検証）
### 仮説A：依存が多すぎて把握できない（ノイズが多い）
- 次の一手
  - “重要導線のページ” に絞って抽出（auth/billing/support）
  - Tag Manager を別枠化（GTM等は “依存の母体” として扱い、背後は追加観測タスクにする）
  - ドメインを “ベンダ単位” に正規化（サブドメイン乱立を束ねる）

### 仮説B：重要導線で外部JSが実行される（P0候補）
- 次の一手（OSINTの安全域）
  - 依存の形（script/iframe）と CSP 許可先をセットで記録し、信頼境界の根拠にする
  - SRI（Subresource Integrity）の有無、バージョン固定の有無を観測（改ざん耐性の示唆）
  - “どのイベントで送信されそうか”（フォーム送信/ページ遷移）をコード断片から推定して data_class を上げる
- 次の一手（後工程への受け渡し）
  - 02_web の認証/セッション観測で、トークンが URL/JS に露出しない設計かを重点チェックにする
  - 23_vdp_scope を想定し、観測は最小（既存ページ閲覧＋ヘッダ/静的解析）で留める

### 仮説C：iframe主体で隔離されている（影響は限定的に見える）
- 次の一手
  - iframe の src ドメインと、リダイレクト/コールバック先（自ドメイン側の入口）が増えていないかを確認
  - 15_api_spec / 03_http に繋いで “外部→自ドメイン” の入口（webhook/callback）を整理

#### 最小の観測例（HTML/JS/CSPから依存を拾う：例示のみ）
~~~~
# HTMLで第三者script/iframeを拾う（例：タグを眺める）
<script src="https://third.example/sdk.js"></script>
<iframe src="https://pay.example/checkout"></iframe>

# CSPで許可先を拾う（例：script-src/connect-src）
Content-Security-Policy: script-src 'self' https://*.third.example; connect-src 'self' https://api.third.example
~~~~

## 不明点（ここが決まると精度が上がる：回答は短くてOK）
- 対象は「Webのみ」で固定するか（モバイルSDKは22に寄せる前提で書いている）
- 23_vdp_scope を想定し、HTTP観測は「ページ閲覧＋静的解析のみ」で固定するか（Network観測まで許容するか）
- “重要導線” の定義を固定するか（auth/billing/support/recruit を既定セットにするか）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回）
- ASVS：
  - V14（設定）：CSP、外部依存管理、秘密情報の取り扱い、ログ/送信の設計に直結
  - V1（アーキ/要件）：信頼境界（第三者）を定義し、脅威モデリングの入力にする
  - V2/V3（支える前提）：認証/セッションの機微情報が第三者に露出しない設計が必要
- WSTG：
  - INFO：公開情報（HTML/JS/CSP）から外部依存と攻撃面を収集
  - CLNT（クライアント側）：第三者JS/SDKはクライアント側の攻撃面とデータ境界を増やす
- PTES：
  - Intelligence Gathering → Threat Modeling：第三者依存を洗い出し、重要導線での優先度を決める
- MITRE ATT&CK：
  - Reconnaissance：公開情報から外部依存・技術境界を収集
  - Supply Chain（支える前提）：外部依存はサプライチェーン観点のリスク入力となる

## 参考（必要最小限）
- Content Security Policy（CSP）と third-party 許可先の読み方
- Subresource Integrity（SRI）と外部スクリプト改ざん耐性の概念
- Tag Manager（GTM等）運用が信頼境界を広げるという観点