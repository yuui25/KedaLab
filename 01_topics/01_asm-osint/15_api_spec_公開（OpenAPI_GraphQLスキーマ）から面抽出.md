# API仕様公開（OpenAPI/GraphQLスキーマ）から攻撃面抽出（endpoint_key_schema）

## ガイドライン対応
- ASVS：V1（設計/脅威モデリングの前提）/ V4（アクセス制御）/ V5（入力検証）/ V13（APIセキュリティ）/ V14（設定）
- WSTG：INFO（公開情報の収集）/ APIT（APIのテスト設計：認証・認可・入力・エラーハンドリング）
- PTES：Intelligence Gathering → Threat Modeling → Vulnerability Analysis（APIの攻撃面を「仕様」から確定して次フェーズへ渡す）
- MITRE ATT&CK：Reconnaissance（公開情報から技術/面を確定し、優先度付けに利用）

## 目的（この技術で到達する状態）
公開されている API 仕様（OpenAPI/Swagger, GraphQL schema/introspection, ドキュメント）から、次の状態に到達する。
- エンドポイント/操作の一覧を「機械的に漏れなく」抽出し、検証対象の最小集合（優先度付き）を作る
- 資産境界（どのホスト/ベースURLが対象か）・信頼境界（外部連携/第三者URL）・権限境界（どこで認証/認可が切り替わるか）を、仕様から先にモデル化する
- “endpoint_key_schema” として、後工程（02_web の入口確定、04_api の権限伝播検証）に渡せる形で正規化する

## 前提（対象・範囲・想定）
- 許可された範囲で実施する（顧客環境/VDP/社内検証など）
- 「仕様が公開されている」ことは、到達性や権限を保証しない（仕様は古い/部分的/環境差分があり得る）
- 対象は以下のいずれか（複数併用を前提）
  - OpenAPI/Swagger の JSON/YAML（openapi.json / swagger.json 等）
  - Swagger UI / Redoc / API Portal の HTML
  - GraphQL の schema 表示、または introspection で取得できるスキーマ
- ゴールは“攻撃”ではなく、攻撃面を確定して「次の検証」を選べる状態（意思決定）にすること

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) 仕様の所在（入口）を観測する
- どこに仕様が置かれているか（URL・ホスト・パス）
- 取得の難易度：未認証で取れる / 認証が必要 / 社内IP限定 / 参照元制限（CORS等）
- キャッシュ/配布境界：CDN配下か、別ドメイン（docs.example / api.example）に分離か

よくある探索対象（例）
~~~~
/openapi.json
/openapi.yaml
/swagger.json
/swagger/v1/swagger.json
/api-docs
/v2/api-docs
/swagger-ui
/redoc
/graphql (GraphQL endpoint)
/graphiql (GUI)
~~~~

### 2) OpenAPI（Swagger）で見るべきデータ構造
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

### 3) GraphQL で見るべき観測対象
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

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言えること（仕様から確定できる状態）
  - “存在し得る面”の候補が、機械的に一覧化できる（漏れにくい）
  - 操作単位で、入力（パラメータ/ボディ）と出力（レスポンス）を推定できる
  - 権限境界の「仮説」が作れる（この操作は認証必須/スコープ必須 など）
  - 対象ホストやベースパスが分かり、資産境界の取りこぼしを減らせる
- 言えないこと（仕様だけでは確定できない）
  - 到達性（WAF/認証前段/ネットワークACL）や、実装の実際（仕様未反映の裏口/隠しAPI）
  - 認可の正しさ（“要求している”と“正しく検証している”は別）
  - 実データの有無（本番/ステージング差分、ダミー運用）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
ここでの「攻撃者視点」は、診断上の優先度付けに使う。

### 優先度の付け方（仕様由来のシグナル）
- 権限が絡む操作：ユーザ管理、権限変更、請求/決済、設定、招待、エクスポート
- “IDを引数に取る”操作：`/users/{id}`、GraphQL の `user(id: ...)`（IDOR/BOLAの主戦場）
- “検索/フィルタ/クエリ”が豊富：列挙・情報漏えい・DoS（複雑クエリ）の入口
- “ファイル/URL/HTML”を扱う：SSRF/XSS/アップロード起点の可能性
- “例外系が仕様にある”：404/403/409/5xx の使い分けがある操作は実装が複雑な傾向

### endpoint_key_schema（後工程に渡す正規化キー）
- REST/OpenAPI：
  - `endpoint_key_schema = <host_group> + <method> + <normalized_path> + <auth_requirement> + <input_schema_signature>`
- GraphQL：
  - `endpoint_key_schema = <endpoint_url> + <op_type(Query/Mutation)> + <field_name> + <arg_signature> + <auth_hint>`

正規化の例
~~~~
GET /v1/users/{userId}        -> GET /v1/users/:id
GET /v1/users/{id}            -> GET /v1/users/:id （同一扱い）
Mutation updateUser(id, ...)  -> Mutation updateUser(id, <fields...>)
~~~~

## 次に試すこと（仮説A/Bの分岐と検証）
### 仮説A：仕様が未認証で取得できる（= 仕様露出が攻撃面そのもの）
- 次の一手（検証）
  - 仕様ファイルを証跡として保存（ダウンロード日時・URL・ハッシュ）
  - `servers/basePath` を起点に、実際の到達性（200/401/403/404）を薄く確認し、面の生存確認をする
  - 認証必須と書かれている操作について、未認証時の挙動（401/403/302など）を確認し、境界の切り替え点を特定する
- 期待する成果物
  - 優先度付きの endpoint_key_schema 一覧（最小検証セット）

最小コマンド例（取得/抽出の例）
~~~~
# OpenAPI JSON 取得（例）
curl -sS https://target.example/openapi.json -o openapi.json

# paths の列挙（例）
jq -r '.paths | keys[]' openapi.json | sort -u
~~~~

### 仮説B：仕様は認証が必要/見えない（= 別経路で面を復元する必要がある）
- 次の一手（分岐）
  - B1：Swagger UI だけ見える → UI が参照している JSON/YAML の実体URLを特定（Networkタブ/参照URL）
  - B2：GraphQL endpoint はあるが introspection 無効 → クライアント（sourcemap/JS）・エラー応答・ドキュメントから field を推定して辞書化
  - B3：社内限定/別ドメイン → 01_asm-osint の DNS/TLS/HTTP 観測で資産境界を広げ、到達条件（IP制限/認証）を確定
- 期待する成果物
  - “仕様が見えない”こと自体を境界情報として記録（どの条件で見えるか）し、次工程の前提にする

GraphQL の最小確認例（introspection が許可されているかの観測）
~~~~
curl -sS https://target.example/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{queryType{name} mutationType{name}}}"}'
~~~~

## 参考（必要最小限）
- OpenAPI Specification（v3）
- Swagger / Swagger UI（仕様表示と取得の仕組み）
- GraphQL Specification / Introspection
- OWASP API Security Top 10（優先度付けの観点整理）