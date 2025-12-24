# mobile_assets_アプリ由来攻撃面（deep-link_API）

## 目的（この技術で到達する状態）
モバイルアプリ（iOS/Android）の公開情報（ストア情報、アプリ配布物、公開設定断片）から、deep link / API / 環境差分（prod/stg/dev）を ASM/OSINT の範囲で抽出し、次を「証跡つき」「優先度つき」で確定できる状態にする。
- mobile_key_endpoint として、アプリ由来の API host / path / scheme / deep link を正規化して整理できる
- Web側から見えない攻撃面（モバイル専用API、旧API、staging環境、固定クライアントID等）を補完できる
- 認証/SSO（02_web/02_authn）やクラウド露出（18_storage_discovery）に繋がる境界情報（issuer、redirect、bucket名等）を回収できる
- 低アクティブで再現可能な観測（静的解析中心）を設計できる

## 前提（対象・範囲・想定）
- 原則は OSINT：ストア/公開ドキュメント/公開配布物（apk等）/既に取得可能なアプリ資産の静的解析
- “解析対象の取得” は合法・許可された範囲に限定する（VDP/契約/端末ポリシーに従う）
- 本ファイルは「攻撃面の抽出・境界推定」まで。実運用アカウントを使った不正ログインや、深い動的検証は別工程
- モバイル資産は更新頻度が高い。バージョン（ver/build）を必ず証跡化する

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) 入口（OSINTで得られる情報源）
- ストア情報（App Store / Google Play）
  - 対象アプリの公式名、開発者名、サポートURL、プライバシーポリシーURL
  - ドメイン（公式/関連）棚卸しへの接続（20_brand_assets）
- 公開配布物
  - Android：APK（公式配布、公開ミラー等）※取得の正当性が前提
  - iOS：IPAは取得制約が多い。OSINTではストアメタ情報と公開設定断片が中心になりやすい
- 公開リポジトリ/ドキュメント
  - SDK公開、設定例、既知の deep link 仕様、APIドキュメント等（16/15へ接続）

### 2) deep link（入口面）を抽出する
モバイルは “URL以外の入口” を持つ。Webのendpoint_keyとは別軸で整理する。
- custom scheme：`myapp://` のような独自スキーム
- universal link / app link：`https://` だがアプリにハンドオフされる
- intent/route：画面遷移ルート（内部パス）と、外部から渡されるパラメータ

観測したいもの（例）
- 対応するホスト/パス（どのURLがアプリに入るか）
- パラメータ（token/code/state/redirect など機微値が乗り得る）
- “外部から呼べる範囲” と “認証前後で挙動が変わる範囲” の示唆

### 3) API endpoint（通信先）を抽出する
- ベースURL（api.example.com、stg-api.example.com など）
- GraphQL/Swagger の痕跡（/graphql、openapi.json など）
- バージョン/環境切り替え（v1/v2、prod/stg/dev）
- pinning / 証明書検証の示唆（OSINT段階では “強度” を断定しない）

### 4) モバイル由来で出やすい “境界断片”
- OAuth/OIDC/SSO 断片
  - issuer、client_id、redirect_uri、scopes、PKCEの示唆（02_authnへ接続）
- クラウド/ストレージ断片
  - bucket名、配布URL、Signed URL の痕跡（18へ接続）
- 計測/外部依存
  - SDKの送信先（analytics、crash report、A/Bテスト等）（21へ接続）
- feature flag / config
  - リモート設定URL、環境スイッチ、社内向けフラグ（stg/dev面の示唆）

### 5) mobile_key_endpoint（後工程に渡す正規化キー）
- mobile_key_endpoint（推奨）
  - mobile_key_endpoint = <platform>(ios|android) + <app_id_or_package> + <entry_type>(deeplink|api) + <normalized_target> + <environment_hint> + <confidence>
- normalized_target（例）
  - deeplink: scheme://host/path（パラメータは signature 化）
  - api: https://host/basepath（バージョン正規化）

記録の最小フィールド（推奨）
- source_locator: 取得元（ストアURL/解析対象ファイル/バージョン）
- app_identity: bundle_id / package_name / version(build)
- entry: deeplink or api
- extracted_value: URL/scheme/host/path
- parameters_hint: token/code/state/redirect 等の有無（断片でも）
- environment_hint: prod/stg/dev/unknown
- confidence: high/mid/low
- action_priority: P0/P1/P2

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える（OSINTで確定できる）
  - モバイル由来の入口（deep link）と、通信先（API host/パス）の候補
  - Webでは見えない環境差分（stg/dev）や、専用APIの存在の示唆
  - SSO/クラウド/外部依存に繋がる境界断片（issuer/bucket/SDK送信先）の示唆
- 言えない（この段階では確定しない）
  - 実際に到達可能か（ネットワーク制御・認証・WAF）
  - deep link の挙動（認証前後の遷移、パラメータの扱い）※動的検証が必要
  - 抜け道や脆弱性の確定（別工程：認証/認可/入力検証）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
※“手口”ではなく、ASMとしての優先度設計。
### 優先度（P0/P1/P2）
- P0（最優先で後工程に渡す）
  - stg/dev らしき API host（本番より弱い制御の可能性）
  - deep link に `token/code/state/redirect` 等が絡む示唆（認証導線・回復導線の可能性）
  - モバイル専用の管理/サポート導線（reset/support/billing など）に近いルート
- P1（優先的に面へ投入）
  - APIベースURLが複数（環境/地域/ブランド）で分岐している
  - GraphQL/Swagger の痕跡（面抽出しやすい。15へ接続）
  - bucket/ストレージURLが見える（18へ接続）
- P2（整理・相関用）
  - 外部計測SDKの送信先（21へ接続し、信頼境界として整理）
  - 一般的な静的資産配布のみ

### 後続トピックへの接続（地続き）
- 15_api_spec：モバイルから見える openapi/graphql の入口があれば面抽出を強化
- 03_http：抽出した host/path を低アクティブに到達性確認し、境界（401/403/404/302）を取る
- 02_authn（SSO/OIDC）：issuer/client_id/redirect_uri を観測点に追加（モバイル固有のクライアント差分）
- 18_storage_discovery：bucket/署名URLの痕跡をストレージ境界に統合
- 21_third-party：モバイルSDKの送信先を trust boundary として統合（ただし詳細は21/22で分業）

## 次に試すこと（仮説A/Bの分岐と検証）
### 仮説A：モバイルから “stg/dev面” が出た（P0）
- 次の一手（OSINTの安全域）
  - 抽出値の “複数ソース一致” を取る（設定ファイル/文字列/ドキュメント）
  - environment_hint（stg/dev）を付与し、03_http の観測対象へ渡す（到達性の薄い確認）
  - 16_github / 17_ci-cd に戻り、同じホスト名が設定断片やログに出るか相関する
- 次の一手（後工程への受け渡し）
  - 認証方式（JWT/OIDC等）の示唆があれば 02_authn の観測点に追加する

### 仮説B：deep link は見えるが、API面が見えにくい
- 次の一手
  - deep link を “導線” として分類（auth/support/billing/general）し、重要導線優先で後工程へ渡す
  - deep link が https 系なら、対応するWebページの存在を 03_http で確認（アプリ/ブラウザ分岐の境界）
  - 14_sourcemap で Web側の同名ルートがあるか照合し、片側だけの面を特定する

### 仮説C：情報が少ない（ストア情報のみ）
- 次の一手
  - サポートURL/プライバシーポリシーURL から公式ドメイン棚卸し（20へ接続）
  - 21_third-party として、公開ページ上の計測/SDK導入を先に押さえる
  - “不足” を境界情報として残し、許可がある場合にのみ動的解析/実機観測へ（別工程）

#### 最小の観測例（deep link / API の整理：例示のみ）
~~~~
# deeplink（例）
myapp://auth/callback?code=<...>&state=<...>
https://app.example.com/open?screen=reset

# api（例）
https://api.example.com/v1/
https://stg-api.example.com/graphql
~~~~

## 不明点（ここが決まると精度が上がる：回答は短くてOK）
- 解析対象は「Android APKのみ」で進める前提で良いか（iOSはストアメタ中心でよいか）
- VDP/契約上、アプリ配布物の取得・静的解析が許可されるケースを想定してよいか
- 03_http での到達性確認は “最小限（1回程度）” を許容するか（OSINTのみ固定か）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回）
- ASVS：
  - V13（API）：モバイル専用APIや環境差分はAPIセキュリティ検証の入口となる
  - V2（認証の支える前提）：モバイル固有クライアント（OIDC設定/redirect）で認証境界が変わり得る
  - V14（設定）：アプリ内設定/feature flag/環境切替の露出は設定リスクに直結
- WSTG：
  - INFO：公開情報（ストア/配布物/ドキュメント）から攻撃面（deep link/API）を収集・整理
  - APIT（支える前提）：抽出したAPI面を後続で認証/認可/入力として検証する
- PTES：
  - Intelligence Gathering → Threat Modeling：モバイル由来の面を統合し、優先度（P0/P1/P2）を決める
- MITRE ATT&CK：
  - Reconnaissance：公開情報からモバイル資産と依存・エンドポイントを収集
  - Collection（支える前提）：アプリ導線は情報収集経路になり得るため、境界情報として重要

## 参考（必要最小限）
- deep link（custom scheme / universal link / app link）の概念
- モバイルアプリから抽出しがちな設定断片（API host, OIDC, analytics, feature flags）
- “環境差分（stg/dev）” が攻撃面を増やすという整理