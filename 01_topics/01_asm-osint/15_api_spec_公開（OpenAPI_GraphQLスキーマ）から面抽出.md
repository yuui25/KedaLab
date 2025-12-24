# 15_api_spec_公開（OpenAPI_GraphQLスキーマ）から面抽出
API仕様公開（OpenAPI/GraphQLスキーマ）から攻撃面抽出（endpoint_key_schema）
“エンドポイント/操作の一覧を機械的に漏れなく抽出し、検証対象の最小集合（優先度付き）を作る”

## 目的（この技術で到達する状態）
公開されている API 仕様（OpenAPI/Swagger, GraphQL schema/introspection, ドキュメント）から、次の状態に到達する。
- エンドポイント/操作の一覧を「機械的に漏れなく」抽出し、検証対象の最小集合（優先度付き）を作る
- 資産境界（どのホスト/ベースURLが対象か）・信頼境界（外部連携/第三者URL）・権限境界（どこで認証/認可が切り替わるか）を、仕様から先にモデル化する
- “endpoint_key_schema” として、後工程（02_web の入口確定、04_api の権限伝播検証）に渡せる形で正規化する

## 前提（対象・範囲・想定）
- 対象：OpenAPI/Swagger の JSON/YAML（openapi.json / swagger.json 等）、Swagger UI / Redoc / API Portal の HTML、GraphQL の schema 表示、または introspection で取得できるスキーマ
- 想定する環境：
  - 「仕様が公開されている」ことは、到達性や権限を保証しない（仕様は古い/部分的/環境差分があり得る）
  - 許可された範囲で実施する（顧客環境/VDP/社内検証など）
- できること/やらないこと（安全に検証する範囲）：
  - できる：仕様の取得と解析、エンドポイント/操作の抽出、優先度付け
  - やらない：ゴールは“攻撃”ではなく、攻撃面を確定して「次の検証」を選べる状態（意思決定）にすること
- 依存する前提知識（必要最小限）：
  - `01_topics/01_asm-osint/03_http_観測（ヘッダ・挙動）と意味.md`
  - `01_topics/01_asm-osint/14_js_sourcemap_公開物から攻撃面抽出（endpoint_key）.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：API仕様公開（OpenAPI/GraphQLスキーマ）から攻撃面抽出（endpoint_key_schema）、境界のモデル化
  - 扱わない（別ユニットへ接続）
    - HTTP観測 → `03_http_観測（ヘッダ/挙動）と意味.md`
    - Sourcemap → `14_js_sourcemap_公開物から攻撃面抽出（endpoint_key）.md`
    - Web深掘り → `01_topics/02_web/01_web_00_recon_入口・境界・攻め筋の確定.md`

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
- 観測対象（プロトコル/データ構造/やり取りの単位）
  - 仕様の所在（入口）を観測する
    - どこに仕様が置かれているか（URL・ホスト・パス）
    - 取得の難易度：未認証で取れる / 認証が必要 / 社内IP限定 / 参照元制限（CORS等）
    - キャッシュ/配布境界：CDN配下か、別ドメイン（docs.example / api.example）に分離か
    - よくある探索対象（例）：
      - `/openapi.json`, `/openapi.yaml`, `/swagger.json`, `/swagger/v1/swagger.json`, `/api-docs`, `/v2/api-docs`, `/swagger-ui`, `/redoc`, `/graphql` (GraphQL endpoint), `/graphiql` (GUI)
  - OpenAPI（Swagger）で見るべきデータ構造
    - 資産境界：`servers`（v3）/ `host`+`basePath`（v2）、`schemes`
    - 操作（面）：
      - `paths` → method（GET/POST/…）→ operation
      - `operationId` / `tags`（機能単位のクラスタリング）
      - `parameters` / `requestBody` / `responses`（入出力とエラー条件）
    - 権限境界：
      - `securitySchemes`（API Key / OAuth2 / JWT Bearer など）
      - operation 毎の `security`（この操作が要求する認証/スコープ）
    - 信頼境界：
      - 外部URLの記載（webhook / callback / externalDocs / examples 内の URL）
      - “x-” 拡張（例：`x-internal`, `x-admin-only` 等）がある場合は要注意（内部面の露出示唆）
  - GraphQL で見るべき観測対象
    - エンドポイント位置：`/graphql` など（HTTP）
    - スキーマの可視性：
      - introspection 有効（= 仕様が機械的に取れる）
      - introspection 無効でも、エラー応答/ドキュメント/クライアントコード（前ファイル14のsourcemap）から面が復元できる場合がある
    - 操作（面）：
      - Query / Mutation / Subscription のフィールド一覧
      - 引数（ID/検索条件/ページング/ソート）＝「入力面」の主要部分
      - 型（User, Order, Payment など）＝「データ境界」の主要部分
    - 権限境界の示唆：
      - directive（例：`@auth`, `@requiresRole` 等）や説明文
      - “管理者専用”を示す命名（admin*, internal*, staff*）
- 境界の観点
  - 資産境界（管理主体・委託先・対象範囲の線引き）：`servers`（v3）/ `host`+`basePath`（v2）、`schemes` から対象ホストやベースパスが分かり、資産境界の取りこぼしを減らせる
  - 信頼境界（外部連携・第三者・越境ポイント）：外部URLの記載（webhook / callback / externalDocs / examples 内の URL）から信頼境界を推定できる
  - 権限境界（権限の切替/伝播/委任）：`securitySchemes`（API Key / OAuth2 / JWT Bearer など）と operation 毎の `security`（この操作が要求する認証/スコープ）から権限境界の「仮説」が作れる（この操作は認証必須/スコープ必須 など）
- 重要なフィールド/差分/状態（「ここが変わると意味が変わる」点）
  - 仕様の所在（URL・ホスト・パス）
  - 取得の難易度（未認証で取れる / 認証が必要 / 社内IP限定 / 参照元制限）
  - introspection 有効/無効（GraphQL）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が“確定”できるか
  - “存在し得る面”の候補が、機械的に一覧化できる（漏れにくい）
  - 操作単位で、入力（パラメータ/ボディ）と出力（レスポンス）を推定できる
  - 権限境界の「仮説」が作れる（この操作は認証必須/スコープ必須 など）
  - 対象ホストやベースパスが分かり、資産境界の取りこぼしを減らせる
- 何が“推定”できるか（推定の根拠/前提）
  - 到達性（WAF/認証前段/ネットワークACL）や、実装の実際（仕様未反映の裏口/隠しAPI）
- 何は“言えない”か（不足情報・観測限界）
  - 到達性（WAF/認証前段/ネットワークACL）や、実装の実際（仕様未反映の裏口/隠しAPI）
  - 認可の正しさ（“要求している”と“正しく検証している”は別）
  - 実データの有無（本番/ステージング差分、ダミー運用）
- よくある状態パターン（正常/異常/境界がズレている等）
  - パターンA：仕様が未認証で取得できる（= 仕様露出が攻撃面そのもの）
  - パターンB：仕様は認証が必要/見えない（= 別経路で面を復元する必要がある）
  - パターンC：introspection 有効（GraphQL）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す“狙い目”（診断上の優先度付けとして使う）
  - 権限が絡む操作：ユーザ管理、権限変更、請求/決済、設定、招待、エクスポート
  - “IDを引数に取る”操作：`/users/{id}`、GraphQL の `user(id: ...)`（IDOR/BOLAの主戦場）
  - “検索/フィルタ/クエリ”が豊富：列挙・情報漏えい・DoS（複雑クエリ）の入口
  - “ファイル/URL/HTML”を扱う：SSRF/XSS/アップロード起点の可能性
  - “例外系が仕様にある”：404/403/409/5xx の使い分けがある操作は実装が複雑な傾向
- 優先度の付け方（時間制約がある場合の順序）
  - 権限が絡む操作、IDを引数に取る操作、検索/フィルタ/クエリが豊富な操作、ファイル/URL/HTMLを扱う操作、例外系が仕様にある操作を優先
- 代表的な攻め筋（この観測から自然に繋がるもの）
  - 攻め筋1：仕様が未認証で取得できる → 仕様ファイルを証跡として保存し、`servers/basePath` を起点に、実際の到達性（200/401/403/404）を薄く確認し、面の生存確認をする
  - 攻め筋2：仕様は認証が必要/見えない → Swagger UI だけ見える場合は UI が参照している JSON/YAML の実体URLを特定、GraphQL endpoint はあるが introspection 無効の場合はクライアント（sourcemap/JS）・エラー応答・ドキュメントから field を推定して辞書化
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）
  - 社内限定/別ドメイン → 01_asm-osint の DNS/TLS/HTTP 観測で資産境界を広げ、到達条件（IP制限/認証）を確定

## 次に試すこと（仮説A/Bの分岐と検証）
> ここが最重要。条件が違うと次の手が変わる形で書く。

- 仮説A：仕様が未認証で取得できる（= 仕様露出が攻撃面そのもの）
  - 次の検証：
    - 仕様ファイルを証跡として保存（ダウンロード日時・URL・ハッシュ）
    - `servers/basePath` を起点に、実際の到達性（200/401/403/404）を薄く確認し、面の生存確認をする
    - 認証必須と書かれている操作について、未認証時の挙動（401/403/302など）を確認し、境界の切り替え点を特定する
  - 期待する観測（成功/失敗時に何が見えるか）：
    - 優先度付きの endpoint_key_schema 一覧（最小検証セット）
- 仮説B：仕様は認証が必要/見えない（= 別経路で面を復元する必要がある）
  - 次の検証：
    - B1：Swagger UI だけ見える → UI が参照している JSON/YAML の実体URLを特定（Networkタブ/参照URL）
    - B2：GraphQL endpoint はあるが introspection 無効 → クライアント（sourcemap/JS）・エラー応答・ドキュメントから field を推定して辞書化
    - B3：社内限定/別ドメイン → 01_asm-osint の DNS/TLS/HTTP 観測で資産境界を広げ、到達条件（IP制限/認証）を確定
  - 期待する観測：
    - “仕様が見えない”こと自体を境界情報として記録（どの条件で見えるか）し、次工程の前提にする

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/01_local/01_attack-box_作業端末設計.md`（結果の保存・差分管理）
    - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`（現状確認の最小証跡）
- 取得する証跡（目的ベースで最小限）
  - 仕様ファイル（ダウンロード日時・URL・ハッシュ）
  - `endpoint_key_schema` 一覧（優先度付き）
  - 正規化キー：
    - REST/OpenAPI：`endpoint_key_schema = <host_group> + <method> + <normalized_path> + <auth_requirement> + <input_schema_signature>`
    - GraphQL：`endpoint_key_schema = <endpoint_url> + <op_type(Query/Mutation)> + <field_name> + <arg_signature> + <auth_hint>`
- 観測の取り方（どの視点で差分を見るか）
  - 仕様の所在（URL・ホスト・パス）、取得の難易度、エンドポイント/操作の抽出、優先度付け
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/apispec_15 2>/dev/null
    cd ~/keda_evidence/apispec_15
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可されたスコープ** のみ（契約範囲/社内許可範囲/自前検証環境）
      - 観測は **代表点の抽出** のみ（仕様の取得と解析、エンドポイント/操作の抽出、優先度付け）
      - 観測視点（端末/経路/ネットワーク）を記録
  - 相関キー（最低限）を作る（後で必ず効く）
    - SpecUrl：仕様のURL
    - SpecType：仕様タイプ（OpenAPI/GraphQL）
    - EndpointKey：endpoint_key_schema（正規化キー）
    - Method：HTTPメソッド（GET/POST等）
    - Path：パス（正規化）
    - AuthRequirement：認証要件（API Key/OAuth2/JWT Bearer等）
    - Priority：優先度（高/中/低）
    - Timestamp：観測日時（JSTで秒まで）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は“手段”であり“結論”ではない。必ず「何を観測している例か」を添える。

~~~~
# OpenAPI JSON 取得（例）
curl -sS https://target.example/openapi.json -o openapi.json

# paths の列挙（例）
jq -r '.paths | keys[]' openapi.json | sort -u

# GraphQL の最小確認例（introspection が許可されているかの観測）
curl -sS https://target.example/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{queryType{name} mutationType{name}}}"}'
~~~~

- この例で観測していること：
  - 仕様の所在（URL・ホスト・パス）、取得の難易度、エンドポイント/操作の抽出
- 出力のどこを見るか（注目点）：
  - OpenAPI JSON：`servers`（v3）/ `host`+`basePath`（v2）、`paths`、`securitySchemes`、外部URLの記載
  - GraphQL：introspection 有効/無効、Query / Mutation / Subscription のフィールド一覧
- この例が使えないケース（前提が崩れるケース）：
  - 仕様は認証が必要/見えない → Swagger UI だけ見える場合は UI が参照している JSON/YAML の実体URLを特定、GraphQL endpoint はあるが introspection 無効の場合はクライアント（sourcemap/JS）・エラー応答・ドキュメントから field を推定して辞書化

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：V1（設計/脅威モデリングの前提）/ V4（アクセス制御）/ V5（入力検証）/ V13（APIセキュリティ）/ V14（設定）
  - 該当要件（可能ならID）：外部依存・設定・通信・境界（ASM/OSINTは“前提の崩れ”を潰す役）
  - このファイルの内容が「満たす/破れる」ポイント：
    - 破れる：エンドポイント/操作の一覧を「機械的に漏れなく」抽出できないと、以降の検証で“対象外”や“前提違い”を起こし、検証精度が落ちる。
    - 満たす：外部依存・設定・通信・境界（ASM/OSINTは“前提の崩れ”を潰す役）を把握し、以降の検証（認証/認可/API/運用）を「前提崩れ」なく進める土台を作る。
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：INFO（公開情報の収集）/ APIT（APIのテスト設計：認証・認可・入力・エラーハンドリング）
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：WSTG各観点へ入る前の“入口確定”として接続
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Intelligence Gathering → Threat Modeling → Vulnerability Analysis（APIの攻撃面を「仕様」から確定して次フェーズへ渡す）
  - 前後フェーズとの繋がり（1行）：エンドポイント/操作の一覧を「機械的に漏れなく」抽出し、検証対象の最小集合（優先度付き）を作る
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Reconnaissance（公開情報から技術/面を確定し、優先度付けに利用）
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
- OpenAPI Specification（v3）  
  https://spec.openapis.org/oas/v3.0.3
- GraphQL Specification / Introspection  
  https://graphql.org/learn/introspection/

## リポジトリ内リンク（最大3つまで）
- 関連 topics：
  - `01_topics/01_asm-osint/03_http_観測（ヘッダ/挙動）と意味.md`
  - `01_topics/01_asm-osint/14_js_sourcemap_公開物から攻撃面抽出（endpoint_key）.md`
- 関連 labs / cases：
  - `04_labs/01_local/01_attack-box_作業端末設計.md`

---

## 深掘りリンク（最大8）
- `01_topics/02_web/01_web_00_recon_入口・境界・攻め筋の確定.md`
- `01_topics/02_web/05_api_権限伝播→検証観点チェック.md`
- `02_playbooks/01_asm_passive-recon_資産境界→優先度付け.md`
- `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- `01_topics/01_asm-osint/06_subdomain_列挙（passive_active_辞書_優先度）.md`
- `01_topics/01_asm-osint/12_waf-cdn_挙動観測（ブロック_チャレンジ_例外）.md`
- `01_topics/01_asm-osint/16_github_code-search_漏えい（key_token_endpoint）.md`
- `01_topics/04_saas/00_index.md`

---
