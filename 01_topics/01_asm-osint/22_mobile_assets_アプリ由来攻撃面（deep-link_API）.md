# 22_mobile_assets_アプリ由来攻撃面（deep-link_API）
Mobile Assets アプリ由来攻撃面（deep-link/API）
“deep link / API / 環境差分（prod/stg/dev）を ASM/OSINT の範囲で抽出し、Web側から見えない攻撃面を補完できる”

## 目的（この技術で到達する状態）
モバイルアプリ（iOS/Android）の公開情報（ストア情報、アプリ配布物、公開設定断片）から、deep link / API / 環境差分（prod/stg/dev）を ASM/OSINT の範囲で抽出し、次を「証跡つき」「優先度つき」で確定できる状態にする。
- mobile_key_endpoint として、アプリ由来の API host / path / scheme / deep link を正規化して整理できる
- Web側から見えない攻撃面（モバイル専用API、旧API、staging環境、固定クライアントID等）を補完できる
- 認証/SSO（02_web/02_authn）やクラウド露出（18_storage_discovery）に繋がる境界情報（issuer、redirect、bucket名等）を回収できる
- 低アクティブで再現可能な観測（静的解析中心）を設計できる

## 前提（対象・範囲・想定）
- 対象：モバイルアプリ（iOS/Android）の公開情報（ストア情報、アプリ配布物、公開設定断片）。原則は OSINT：ストア/公開ドキュメント/公開配布物（apk等）/既に取得可能なアプリ資産の静的解析
- 想定する環境：
  - モバイル資産は更新頻度が高い。バージョン（ver/build）を必ず証跡化する
  - “解析対象の取得” は合法・許可された範囲に限定する（VDP/契約/端末ポリシーに従う）
- できること/やらないこと（安全に検証する範囲）：
  - できる：原則は OSINT：ストア/公開ドキュメント/公開配布物（apk等）/既に取得可能なアプリ資産の静的解析。“攻撃面の抽出・境界推定” まで
  - やらない：本ファイルは「攻撃面の抽出・境界推定」まで。実運用アカウントを使った不正ログインや、深い動的検証は別工程
- 依存する前提知識（必要最小限）：
  - `01_topics/01_asm-osint/14_js_sourcemap_公開物から攻撃面抽出（endpoint_key）.md`
  - `01_topics/01_asm-osint/15_api_spec_公開（OpenAPI_GraphQLスキーマ）から面抽出.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：Mobile Assets アプリ由来攻撃面（deep-link/API）、環境差分の抽出、境界情報の回収
  - 扱わない（別ユニットへ接続）
    - Sourcemap → `14_js_sourcemap_公開物から攻撃面抽出（endpoint_key）.md`
    - API仕様 → `15_api_spec_公開（OpenAPI_GraphQLスキーマ）から面抽出.md`
    - 認証/SSO → `01_topics/02_web/02_authn_認証境界（SSO_OIDC_SAML_パスワード）.md`
    - Storage → `01_topics/01_asm-osint/18_storage_discovery（S3_GCS_AzureBlob）境界推定.md`

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
- 観測対象（プロトコル/データ構造/やり取りの単位）
  - 入口（OSINTで得られる情報源）
    - ストア情報（App Store / Google Play）：対象アプリの公式名、開発者名、サポートURL、プライバシーポリシーURL、ドメイン（公式/関連）棚卸しへの接続（20_brand_assets）
    - 公開配布物：Android：APK（公式配布、公開ミラー等）※取得の正当性が前提、iOS：IPAは取得制約が多い。OSINTではストアメタ情報と公開設定断片が中心になりやすい
    - 公開リポジトリ/ドキュメント：SDK公開、設定例、既知の deep link 仕様、APIドキュメント等（16/15へ接続）
  - deep link（入口面）を抽出する
    - モバイルは “URL以外の入口” を持つ。Webのendpoint_keyとは別軸で整理する。
    - custom scheme：`myapp://` のような独自スキーム
    - universal link / app link：`https://` だがアプリにハンドオフされる
    - intent/route：画面遷移ルート（内部パス）と、外部から渡されるパラメータ
    - 観測したいもの（例）：対応するホスト/パス（どのURLがアプリに入るか）、パラメータ（token/code/state/redirect など機微値が乗り得る）、“外部から呼べる範囲” と “認証前後で挙動が変わる範囲” の示唆
  - API endpoint（通信先）を抽出する
    - ベースURL（api.example.com、stg-api.example.com など）
    - GraphQL/Swagger の痕跡（/graphql、openapi.json など）
    - バージョン/環境切り替え（v1/v2、prod/stg/dev）
    - pinning / 証明書検証の示唆（OSINT段階では “強度” を断定しない）
  - モバイル由来で出やすい “境界断片”
    - OAuth/OIDC/SSO 断片：issuer、client_id、redirect_uri、scopes、PKCEの示唆（02_authnへ接続）
    - クラウド/ストレージ断片：bucket名、配布URL、Signed URL の痕跡（18へ接続）
    - 計測/外部依存：SDKの送信先（analytics、crash report、A/Bテスト等）（21へ接続）
    - feature flag / config：リモート設定URL、環境スイッチ、社内向けフラグ（stg/dev面の示唆）
- 境界の観点
  - 資産境界（管理主体・委託先・対象範囲の線引き）：モバイル資産は更新頻度が高い。バージョン（ver/build）を必ず証跡化する
  - 信頼境界（外部連携・第三者・越境ポイント）：計測/外部依存（SDKの送信先（analytics、crash report、A/Bテスト等））から信頼境界を推定できる
  - 権限境界（権限の切替/伝播/委任）：OAuth/OIDC/SSO 断片（issuer、client_id、redirect_uri、scopes、PKCEの示唆）から権限境界を推定できる
- 重要なフィールド/差分/状態（「ここが変わると意味が変わる」点）
  - mobile_key_endpoint（後工程に渡す正規化キー）
    - mobile_key_endpoint = <platform>(ios|android) + <app_id_or_package> + <entry_type>(deeplink|api) + <normalized_target> + <environment_hint> + <confidence>
  - normalized_target（例）
    - deeplink: scheme://host/path（パラメータは signature 化）
    - api: https://host/basepath（バージョン正規化）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が“確定”できるか
  - モバイル由来の入口（deep link）と、通信先（API host/パス）の候補
  - Webでは見えない環境差分（stg/dev）や、専用APIの存在の示唆
  - SSO/クラウド/外部依存に繋がる境界断片（issuer/bucket/SDK送信先）の示唆
- 何が“推定”できるか（推定の根拠/前提）
  - 実際に到達可能か（ネットワーク制御・認証・WAF）
- 何は“言えない”か（不足情報・観測限界）
  - 実際に到達可能か（ネットワーク制御・認証・WAF）
  - deep link の挙動（認証前後の遷移、パラメータの扱い）※動的検証が必要
  - 抜け道や脆弱性の確定（別工程：認証/認可/入力検証）
- よくある状態パターン（正常/異常/境界がズレている等）
  - パターンA：モバイルから “stg/dev面” が出た（P0）
  - パターンB：deep link は見えるが、API面が見えにくい
  - パターンC：情報が少ない（ストア情報のみ）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す“狙い目”（診断上の優先度付けとして使う）
  - P0（最優先で後工程に渡す）：stg/dev らしき API host（本番より弱い制御の可能性）、deep link に `token/code/state/redirect` 等が絡む示唆（認証導線・回復導線の可能性）、モバイル専用の管理/サポート導線（reset/support/billing など）に近いルート
  - P1（優先的に面へ投入）：APIベースURLが複数（環境/地域/ブランド）で分岐している、GraphQL/Swagger の痕跡（面抽出しやすい。15へ接続）、bucket/ストレージURLが見える（18へ接続）
  - P2（整理・相関用）：外部計測SDKの送信先（21へ接続し、信頼境界として整理）、一般的な静的資産配布のみ
- 優先度の付け方（時間制約がある場合の順序）
  - P0（最優先で後工程に渡す）→ P1（優先的に面へ投入）→ P2（整理・相関用）の順
- 代表的な攻め筋（この観測から自然に繋がるもの）
  - 攻め筋1：15_api_spec：モバイルから見える openapi/graphql の入口があれば面抽出を強化
  - 攻め筋2：03_http：抽出した host/path を低アクティブに到達性確認し、境界（401/403/404/302）を取る
  - 攻め筋3：02_authn（SSO/OIDC）：issuer/client_id/redirect_uri を観測点に追加（モバイル固有のクライアント差分）
  - 攻め筋4：18_storage_discovery：bucket/署名URLの痕跡をストレージ境界に統合
  - 攻め筋5：21_third-party：モバイルSDKの送信先を trust boundary として統合（ただし詳細は21/22で分業）
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）
  - 情報が少ない（ストア情報のみ） → サポートURL/プライバシーポリシーURL から公式ドメイン棚卸し（20へ接続）、21_third-party として、公開ページ上の計測/SDK導入を先に押さえる

## 次に試すこと（仮説A/Bの分岐と検証）
> ここが最重要。条件が違うと次の手が変わる形で書く。

- 仮説A：モバイルから “stg/dev面” が出た（P0）
  - 次の検証：
    - （OSINTの安全域）抽出値の “複数ソース一致” を取る（設定ファイル/文字列/ドキュメント）。environment_hint（stg/dev）を付与し、03_http の観測対象へ渡す（到達性の薄い確認）。16_github / 17_ci-cd に戻り、同じホスト名が設定断片やログに出るか相関する
    - （後工程への受け渡し）認証方式（JWT/OIDC等）の示唆があれば 02_authn の観測点に追加する
  - 期待する観測（成功/失敗時に何が見えるか）：
    - 抽出値の複数ソース一致、environment_hint、設定断片やログとの相関、認証方式の示唆
- 仮説B：deep link は見えるが、API面が見えにくい
  - 次の検証：
    - deep link を “導線” として分類（auth/support/billing/general）し、重要導線優先で後工程へ渡す
    - deep link が https 系なら、対応するWebページの存在を 03_http で確認（アプリ/ブラウザ分岐の境界）
    - 14_sourcemap で Web側の同名ルートがあるか照合し、片側だけの面を特定する
  - 期待する観測：
    - deep link の導線分類、対応するWebページの存在確認、Web側の同名ルートの照合
- 仮説C：情報が少ない（ストア情報のみ）
  - 次の検証：
    - サポートURL/プライバシーポリシーURL から公式ドメイン棚卸し（20へ接続）
    - 21_third-party として、公開ページ上の計測/SDK導入を先に押さえる
    - “不足” を境界情報として残し、許可がある場合にのみ動的解析/実機観測へ（別工程）
  - 期待する観測：
    - 公式ドメイン棚卸し、公開ページ上の計測/SDK導入、境界情報としての記録

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/01_local/01_attack-box_作業端末設計.md`（結果の保存・差分管理）
    - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`（現状確認の最小証跡）
- 取得する証跡（目的ベースで最小限）
  - mobile_key_endpoint（後工程に渡す正規化キー）
    - mobile_key_endpoint = <platform>(ios|android) + <app_id_or_package> + <entry_type>(deeplink|api) + <normalized_target> + <environment_hint> + <confidence>
  - 記録の最小フィールド（推奨）
    - source_locator: 取得元（ストアURL/解析対象ファイル/バージョン）
    - app_identity: bundle_id / package_name / version(build)
    - entry: deeplink or api
    - extracted_value: URL/scheme/host/path
    - parameters_hint: token/code/state/redirect 等の有無（断片でも）
    - environment_hint: prod/stg/dev/unknown
    - confidence: high/mid/low
    - action_priority: P0/P1/P2
- 観測の取り方（どの視点で差分を見るか）
  - 原則は OSINT：ストア/公開ドキュメント/公開配布物（apk等）/既に取得可能なアプリ資産の静的解析
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/mobile_22 2>/dev/null
    cd ~/keda_evidence/mobile_22
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可されたスコープ** のみ（契約範囲/社内許可範囲/自前検証環境）
      - 観測は **代表点の抽出** のみ（原則は OSINT：ストア/公開ドキュメント/公開配布物（apk等）/既に取得可能なアプリ資産の静的解析）
      - 観測視点（端末/経路/ネットワーク）を記録
  - 相関キー（最低限）を作る（後で必ず効く）
    - Platform：platform（ios/android）
    - AppIdOrPackage：app_id_or_package
    - EntryType：entry_type（deeplink/api）
    - NormalizedTarget：normalized_target（scheme://host/path または https://host/basepath）
    - EnvironmentHint：environment_hint（prod/stg/dev/unknown）
    - Confidence：confidence（high/mid/low）
    - ActionPriority：action_priority（P0/P1/P2）
    - Timestamp：観測日時（JSTで秒まで）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は“手段”であり“結論”ではない。必ず「何を観測している例か」を添える。

~~~~
# 最小の観測例（deep link / API の整理：例示のみ）

# deeplink（例）
# myapp://auth/callback?code=<...>&state=<...>
# https://app.example.com/open?screen=reset

# api（例）
# https://api.example.com/v1/
# https://stg-api.example.com/graphql
~~~~

- この例で観測していること：
  - 原則は OSINT：ストア/公開ドキュメント/公開配布物（apk等）/既に取得可能なアプリ資産の静的解析
- 出力のどこを見るか（注目点）：
  - deeplink：custom scheme（`myapp://` のような独自スキーム）、universal link / app link（`https://` だがアプリにハンドオフされる）、intent/route（画面遷移ルート（内部パス）と、外部から渡されるパラメータ）
  - api：ベースURL（api.example.com、stg-api.example.com など）、GraphQL/Swagger の痕跡（/graphql、openapi.json など）、バージョン/環境切り替え（v1/v2、prod/stg/dev）
- この例が使えないケース（前提が崩れるケース）：
  - “解析対象の取得” は合法・許可された範囲に限定する（VDP/契約/端末ポリシーに従う）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：V13（API）：モバイル専用APIや環境差分はAPIセキュリティ検証の入口となる。V2（認証の支える前提）：モバイル固有クライアント（OIDC設定/redirect）で認証境界が変わり得る。V14（設定）：アプリ内設定/feature flag/環境切替の露出は設定リスクに直結
  - 該当要件（可能ならID）：外部依存・設定・通信・境界（ASM/OSINTは“前提の崩れ”を潰す役）
  - このファイルの内容が「満たす/破れる」ポイント：
    - 破れる：モバイル専用APIや環境差分を確定できないと、以降の検証で“対象外”や“前提違い”を起こし、検証精度が落ちる。
    - 満たす：外部依存・設定・通信・境界（ASM/OSINTは“前提の崩れ”を潰す役）を把握し、以降の検証（認証/認可/API/運用）を「前提崩れ」なく進める土台を作る。
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：INFO：公開情報（ストア/配布物/ドキュメント）から攻撃面（deep link/API）を収集・整理。APIT（支える前提）：抽出したAPI面を後続で認証/認可/入力として検証する
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：WSTG各観点へ入る前の“入口確定”として接続
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Intelligence Gathering → Threat Modeling：モバイル由来の面を統合し、優先度（P0/P1/P2）を決める
  - 前後フェーズとの繋がり（1行）：モバイルアプリ（iOS/Android）の公開情報（ストア情報、アプリ配布物、公開設定断片）から、deep link / API / 環境差分（prod/stg/dev）を ASM/OSINT の範囲で抽出し、攻撃面と境界情報を抽出する
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Reconnaissance：公開情報からモバイル資産と依存・エンドポイントを収集。Collection（支える前提）：アプリ導線は情報収集経路になり得るため、境界情報として重要
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
- deep link（custom scheme / universal link / app link）の概念
- モバイルアプリから抽出しがちな設定断片（API host, OIDC, analytics, feature flags）

## リポジトリ内リンク（最大3つまで）
- 関連 topics：
  - `01_topics/01_asm-osint/14_js_sourcemap_公開物から攻撃面抽出（endpoint_key）.md`
  - `01_topics/01_asm-osint/15_api_spec_公開（OpenAPI_GraphQLスキーマ）から面抽出.md`
- 関連 labs / cases：
  - `04_labs/01_local/01_attack-box_作業端末設計.md`

---

## 深掘りリンク（最大8）
- `01_topics/01_asm-osint/03_http_観測（ヘッダ/挙動）と意味.md`
- `01_topics/01_asm-osint/18_storage_discovery（S3_GCS_AzureBlob）境界推定.md`
- `01_topics/01_asm-osint/21_third-party_外部依存（タグ_分析SDK）洗い出し.md`
- `01_topics/02_web/02_authn_認証境界（SSO_OIDC_SAML_パスワード）.md`
- `01_topics/01_asm-osint/20_brand_assets_関連ドメイン推定（typo_lookalike）.md`
- `01_topics/01_asm-osint/16_github_code-search_漏えい（key_token_endpoint）.md`
- `02_playbooks/01_asm_passive-recon_資産境界→優先度付け.md`
- `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`

---
