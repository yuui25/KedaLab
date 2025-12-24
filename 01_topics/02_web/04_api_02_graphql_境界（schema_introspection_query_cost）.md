## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - この技術で満たす/破れる点：APIアクセス制御（認証・認可の強制点がresolver/fieldに分散）、最小開示（schema/field-level）、入力の信頼境界（variables/ID/tenant）、濫用耐性（レート・コスト制限）、監査（operation/field/decision/trace）
  - 支える前提：GraphQLは「単一エンドポイントに機能が集約」「取得フィールドがクライアント主導」「ネストで爆発」する。従来の“エンドポイント単位の境界”が破綻しやすく、schema露出・introspection・クエリコストを設計として制御しないと、漏えいとDoSが同時に起きる。
- WSTG：
  - 該当テスト観点：Authorization Testing（GraphQL入口のIDOR/越境、field-level）、API Testing（GraphQL：introspection、operationName、persisted query、complexity/depth、エラー差分）
  - どの観測に対応するか：同一 endpoint（/graphql）で「operation差分」「フィールド差分」「ネスト差分」「変数差分」を取り、(1)schema露出、(2)introspectionの可否と範囲、(3)コスト制御の有無（depth/complexity/timeout/rate）を確定する
- PTES：
  - 該当フェーズ：Information Gathering（schema/operationの把握、入口列挙）、Vulnerability Analysis（境界と防御の欠落特定）、Exploitation（最小差分で確定：2ユーザ/2テナント、低負荷でのコスト境界観測）
  - 前後フェーズとの繋がり（1行）：AuthZ（03_authz_07）で扱ったfield-level認可を前提に、API設計としての「schema露出」「introspection運用」「query cost（濫用耐性）」を詰め、以降のREST filters / webhook / idempotency / async job に“境界の作り方”として接続する
- MITRE ATT&CK：
  - 戦術：Discovery / Collection / Impact
  - 目的：schema/operationの発見（Discovery）→機微フィールド収集（Collection）→高負荷クエリで可用性低下（Impact）。GraphQLは1リクエストで多目的に進むため、境界設計の欠落が攻撃の“加速器”になる。

## タイトル
graphql_境界（schema_introspection_query_cost）

## 目的（この技術で到達する状態）
- GraphQLの“攻撃面”を、(1)schema公開面（型・フィールド・操作）、(2)introspectionの運用境界、(3)クエリコスト境界（depth/complexity/timeout/rate）、(4)persisted query/allowlist境界、(5)エラー・監査境界、に分解して評価できる
- ペネトレ実務として「負荷をかけずに」境界の有無（守りの有無）を証跡で確定し、設計是正に落とし込める
- GraphQLがあるだけで危険という誤解を避け、危険なのは「無制限な探索（schema/introspection）」「無制限な要求（cost制御無し）」「入口一貫性の欠如（AuthZ drift）」である、と具体化できる

## 前提（対象・範囲・想定）
- 対象：GraphQL API（典型：POST /graphql、場合によりGET、Persisted Query / APQ、Gateway/Federation、BFF）
- 混在前提（現実運用に寄せる）
  - 本番：introspection OFF か “ロール限定” のいずれか（運用事情で例外あり）
  - 開発/ステージング：Playground/Explorerが有効で、誤公開が起きやすい
  - 監視：WAF/Rate limit はあるが、GraphQLの“コスト”を理解しない設定が多い
- 検証の安全な範囲（ペネトレ）
  - DoSを狙う実行はしない。代わりに「低負荷でコスト境界が働くか」を観測する（深いネストを1段ずつ増やす等の差分観測）
  - schema/operationの把握は、(a)introspection、(b)フロントJS/SDK、(c)エラー、(d)ドキュメント/メタAPI の順で、最小の侵襲で進める

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) GraphQLの入口を固定する（単一endpointでも“入口は複数”）
- 入口の種類（運用でよく混在）
  - /graphql（本体）
  - /graphql/batch（バッチ、複数operationまとめ）
  - /api/graphql（別パス）
  - Playground/Explorer（/graphiql, /playground, /graphql/console 等）
  - Persisted Query endpoint（同じ/別）
  - Federation gateway（/graphql がgatewayで、背後にsubgraphがある）
- 観測で確定したい点
  - 本番に explorer が露出していないか（露出してもAuthN必須か）
  - 同一ホストに “internal/graphql” のような例外入口が無いか（管理・社内想定の誤公開）

### 2) schema公開面：GraphQLは“メニューが攻撃面”になりやすい
- schemaに含まれる危険要素（優先度順）
  - 管理系Mutation/Query（admin*, internal*, audit*, export*, reset*, grant*）
  - 機微フィールド（PII、認証補助情報、請求、権限、監査詳細）
  - “横断検索”の入口（search, nodes, connections）＝越境混入の温床
  - Deprecatedフィールド（古い実装はAuthZ driftを起こしやすい：v1/v2問題に似る）
- 観測の作法
  - schemaを取れたら「操作（root fields）」をまず棚卸しし、次に “機微フィールドの所在（型のどこにあるか）” を地図化する
  - schemaが取れない場合でも、フロントJS/SDK（型定義、operationName、persisted query ID）から「実運用の操作集合」を復元する

### 3) introspection：ON/OFFではなく「どの範囲で、誰に」までが境界
introspectionは“便利な機能”だが、運用境界が無いとDiscoveryが無制限になる。
- 運用パターン（現実的）
  - パターンA：本番OFF（最も単純）
  - パターンB：本番ONだがAuthN必須＋管理者/開発者ロール限定（運用事情で多い）
  - パターンC：本番ONで公開（危険、ただし存在する）
- OFFでも危険が残る点（よくある誤解）
  - フロントがoperationや型の断片を持っている（JS/モバイルに残る）
  - エラーが型名/フィールド名を漏らす（04_api_09にも接続）
- 観測で確定したい点（証跡化）
  - introspectionが拒否されるときの挙動（明示拒否/汎用エラー/部分成功）
  - ロール差分（一般ユーザと管理者で範囲が違うか）
  - ステージング/サブドメインでONのまま公開されていないか（“本番OFF”でも事故る）

### 4) query_cost：GraphQL特有の濫用耐性（DoSは“サイズ”ではなく“計算量”）
GraphQLの負荷は「レスポンスサイズ」より「resolver実行回数・DBクエリ・外部呼び出し」で増える。
- コスト爆発の典型要因
  - 深いネスト（depth）
  - 接続（connection）での大量ノード取得（first/limit）
  - N+1（各ノードで追加DB）
  - 高コストフィールド（集計、検索、PDF生成、外部API参照）
  - エラーハンドリング（失敗時にも重い処理が走る）
- 代表的な防御（実運用で併用される）
  - Depth limit（最大ネスト深さ）
  - Complexity limit（フィールドに重み、合計上限）
  - Query timeout / resolver timeout（時間上限）
  - Rate limit（IP/ユーザ/トークン単位）
  - Pagination強制（connectionのfirst上限）
  - フィールド別のコスト制限（高コストフィールドは別権限・別レート）
  - バッチ/キャッシュ/DataLoader（N+1緩和：ただしtenantキー混入に注意＝03_authz_07）
- 観測で確定したい点（“低負荷で”境界を測る）
  - depthを1段ずつ増やしたときに、ある段で明確に拒否されるか（境界の存在）
  - first/limitを上げたときに、上限が強制されるか（強制の位置：UI/サーバ/DB）
  - 高コストっぽいフィールド（search/export/aggregate）に別レートや権限があるか
  - 失敗時に“コスト拒否のエラー”が返るか（汎用500になっていないか＝04_api_09）

### 5) persisted query / allowlist：本番運用の現実的な強化策（Discoveryと濫用を同時に抑える）
- 実運用の狙い
  - クエリ本文を自由に送れない（allowlist）→探索・濫用が減る
  - operationName/IDベースで監査が安定する
- ただし残るリスク（ここを見落とさない）
  - allowlistに “危険操作” が入っていれば意味がない（AuthZ/ガードが本体）
  - variables次第で越境・漏洩が起きる（IDOR/tenant/filters）
  - persisted queryのIDが推測可能・列挙可能だと探索が戻る
- 観測で確定したい点
  - 本番で「任意query本文」が拒否されるか（persisted専用か）
  - operationNameが監査・レート制御の単位になっているか（操作別に制限が違うか）

### 6) エラーと部分成功：境界の不備は“エラー差分”として現れる（04_api_09へ接続）
- GraphQLの特徴
  - 一部フィールドが失敗しても、他は返る（partial response）
- 典型の情報漏洩
  - 存在/権限/型/フィールド名が errors に出る
  - “コスト拒否”が内部実装名（complexityルール、stack）を漏らす
- 観測で確定したい点
  - エラーが一貫しているか（拒否時に同じエラーモデル）
  - 403相当をGraphQLでどう表現しているか（errors/path/extensions）
  - trace id が付くか（監査・調査に重要）

### 7) GraphQLの境界はAuthZと不可分（03_authz_07と地続き）
- よくある事故（設計としての境界欠落）
  - schemaにはあるが “UIで使ってないから大丈夫” → 直接呼ばれる（入口集約ゆえに現実的）
  - introspection OFF でも、operationはフロントに残る → 実行できる
  - cost制御があっても、AuthZが弱いと「重い漏洩（大量取得）」に直結
- したがって、この章の結論
  - schema/introspection/cost は “Discoverability と Abusability” を下げる
  - “漏れない/越境しない”は AuthZ（field/resolver/tenant）で担保する（07）

### 8) graphql_schema_introspection_cost_key_boundary（正規化キー：後続へ渡す）
- 推奨キー：graphql_schema_introspection_cost_key_boundary
  - graphql_schema_introspection_cost_key_boundary =
    <schema_discovery>(introspection|front_artifacts|errors|docs|mixed|unknown)
    + <introspection_policy>(off|authn_required|role_limited|public|unknown)
    + <explorer_exposure>(none|public|authn_only|unknown)
    + <persisted_query>(required|optional|none|unknown)
    + <cost_controls>(depth|complexity|timeout|rate|pagination_cap|mixed|none|unknown)
    + <cost_enforcement_point>(gateway|app|subgraph|waf_only|mixed|unknown)
    + <error_model_consistency>(consistent|leaky|unknown)
    + <audit_strength>(strong|partial|weak|unknown)
    + <confidence>
- 記録の最小フィールド（推奨）
  - endpoint/host、explorer有無
  - introspectionの可否と条件（ロール差分）
  - persisted queryの要否
  - depth/limitの境界の有無（低負荷の差分観測）
  - エラー表現（errors/path/extensions、trace id）
  - evidence（HAR、レスポンス差分、UI露出、JS断片）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える（確定できる）：
  - schema discovery がどの経路で可能か（introspection/JS/エラー）
  - introspectionが誰にどこまで開いているか（運用境界）
  - cost制御（depth/complexity/timeout/rate/pagination cap）が存在し、どの層で強制されるか
  - persisted query/allowlist が運用されているか（探索抑制）
  - エラーと監査が“境界の証跡”として整っているか（trace id、操作単位のログ）
- 推定（根拠付きで言える）：
  - introspectionが公開で、cost制御が無い場合、Discovery→Collection→Impact（濫用/DoS）が現実的
  - persisted queryが必須でも、variablesの境界（AuthZ/filters）が弱いと漏洩は起きる
  - cost制御がWAFのみの場合、GraphQL特有の計算量を捉えきれず抜けやすい
- 言えない（この段階では断定しない）：
  - 実際にサービス停止できるか（DoSは実行しない）。ただし境界の欠落は“重大リスク”として示せる。

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- 優先度（P0/P1/P2）
  - P0：
    - introspectionが公開、またはexplorerが無認証で露出
    - cost制御が見当たらず、深さ/取得件数が無制限（低負荷観測で境界が出ない）
    - persisted queryなしで任意query本文が実行可能、かつ監査が弱い（追跡困難）
    - エラーが型/内部名/stackを漏らす（探索が加速）
  - P1：
    - introspectionは制限されるが、JS/エラーから操作が復元できる（現実的な探索が可能）
    - cost制御があるが一貫しない（入口/operationにより抜ける）
    - persisted queryはあるが、operation IDが列挙可能・推測可能な兆候
  - P2：
    - 運用境界は強いが、監査・レート設計が弱く回帰/誤設定リスクが残る
- “成立条件”としての整理（技術者が直すべき対象）
  - introspectionは本番OFF、またはAuthN必須＋ロール限定＋監査（運用要件でONなら境界を明文化）
  - explorer（graphiql/playground）は本番非公開、または強いAuthN＋IP制限＋短時間セッション
  - cost制御は depth/complexity/timeout/pagination cap をサーバ側で強制し、WAF任せにしない
  - persisted query/allowlist を導入し、操作別にレート・コスト・権限を設計する
  - エラーモデルを統一し、trace id と operationName を監査・検知の軸にする（04_api_09へ）

## 次に試すこと（仮説A/Bの分岐と検証：低負荷で境界を確定）
- 仮説A：introspection が公開/過剰に広い
  - 次の検証（差分）：
    - 未認証/一般ユーザ/管理ロールで、introspection可否と返る範囲が変わるかを比較
  - 判断：
    - 公開/広い：P0（Discoveryが無制限）
- 仮説B：cost制御が無い、または弱い
  - 次の検証（差分）：
    - ネスト深さを段階的に増やす、取得件数（first/limit）を段階的に増やす
    - ある境界で明確に拒否されるか、または静かに処理されるかを見る
  - 判断：
    - 境界が出ない：P0〜P1（監査・運用次第で深刻）
- 仮説C：persisted query/allowlist が無い（探索が容易）
  - 次の検証（差分）：
    - 任意query本文が通るか、persisted IDのみ許容か、operationName単位で拒否があるかを見る
  - 判断：
    - 任意queryが通る：P1（他要素と組み合わさるとP0）
- 仮説D：エラーが探索オラクルになる
  - 次の検証（差分）：
    - 存在しないフィールド/型/operationName を与えたとき、内部情報が出るかを観測（最小限）
  - 判断：
    - 型名/stack/内部ホストが出る：P0〜P1（探索加速）

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/` ）：
  - `04_labs/02_web/04_api/02_graphql_schema_introspection_cost/`
    - 構成案（現実運用の再現）
      - 環境：prod/stg を想定（stg誤公開を再現）
      - introspection：OFF / AuthN必須 / ロール限定 / 公開 を切替
      - explorer：公開/非公開を切替
      - persisted query：required/optional/none を切替（APQ含む）
      - cost制御：depth/complexity/timeout/pagination cap/rate を切替
      - ログ：operationName、cost計算値、deny理由、trace_id、actor/tenant を必ず出す
      - “高コストフィールド”：search/aggregate/export を用意し、別レート/別権限の設計を比較
- 取得する証跡（深掘り向け：HTTP＋周辺ログ）
  - HTTP：同一operationの差分（深さ/件数/フィールド）と、その時のエラーモデル
  - レスポンス：errors.path / extensions、trace id
  - ログ：cost計算、timeout、rate、operation allow/deny、actor/tenant
  - 監査：操作別の回数、拒否の統計（濫用検知）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
# 典型のGraphQLリクエスト（擬似）
POST /graphql
{
  "operationName": "GetUser",
  "query": "query GetUser($id: ID!){ user(id:$id){ id name } }",
  "variables": { "id": "U123" }
}

# 観測の差分（擬似）
- 同じoperationで、フィールドを増やす（field差分）
- ネストを1段ずつ深くする（depth差分）
- first/limitを段階的に上げる（pagination cap差分）
- 任意query本文が拒否され、persisted IDのみ許可されるか（allowlist差分）

# 見るべき結果（擬似）
- どこで拒否されるか（境界の存在）
- エラーが一貫するか（漏えいの有無）
- trace id / operationName が残るか（監査可能性）
~~~~
- この例で観測していること：
  - GraphQLの“探索可能性（schema/introspection）”と“濫用耐性（cost制御）”が、サーバ側で強制されているか
- 出力のどこを見るか（注目点）：
  - introspection_policy、cost_controls、cost_enforcement_point、persisted_query、error_model_consistency、audit_strength
- この例が使えないケース（前提が崩れるケース）：
  - query本文が完全に隠される（persisted only）場合：operationName/ID と variables の境界（AuthZ/filters）に観測を寄せる

## 参考（必要最小限）
- OWASP ASVS（Authorization、API濫用耐性、監査）
- OWASP WSTG（API/Authorization Testing：GraphQL特有の入口・フィールド差分観測）
- PTES（低負荷で境界を確定し、設計是正へ落とす）
- MITRE ATT&CK（Discovery/Collection/Impact：探索と濫用を境界で抑える）

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/03_authz_07_graphql_authz（field_level）.md`
- `01_topics/02_web/03_authz_03_multi-tenant_分離（org_id_tenant_id）.md`
- `01_topics/02_web/04_api_09_error_model_情報漏えい（例外_スタック）.md`

## 次（04_api_03 以降）に進む前に確認したいこと（必要なら回答）
- 04_api_03（REST filters）では、GraphQLの「variablesによるfilters」と同型の事故（越境混入、並び替えでの推測、ページング差分）をREST側に写像して書く（地続きで理解できるようにする）
