## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - この技術で満たす/破れる点：アクセス制御（一覧/検索は越境混入の最頻出）、最小開示（返却列/サマリの設計）、入力検証（filter/sort/pageの信頼境界）、濫用耐性（ページング上限・検索負荷・レート）、監査（検索条件と結果範囲の追跡）
  - 支える前提：RESTの一覧/検索は「業務で最も使われる」＝「最も攻撃に使われる」。IDORは詳細参照だけではなく、検索・ソート・ページングの“条件の穴”で静かに成立する。
- WSTG：
  - 該当テスト観点：Authorization Testing（IDOR/BOLA、マルチテナント分離）、API Testing（検索条件、ページング、並び替え、エラー差分）、Business Logic（検索で見えてはいけない状態/属性）
  - どの観測に対応するか：同一一覧APIで「filter差分」「sort差分」「paging差分」「列（fields）差分」を取り、(1)越境混入、(2)推測/列挙のオラクル、(3)過剰返却、(4)負荷境界欠落、を確定する
- PTES：
  - 該当フェーズ：Information Gathering（一覧/検索エンドポイント列挙、パラメータ体系の把握）、Vulnerability Analysis（境界の欠落：tenant/権限/状態/上限）、Exploitation（最小差分検証：2ユーザ/2テナント、低負荷での列挙可能性確認）
  - 前後フェーズとの繋がり（1行）：AuthZ（03）で定義した“境界モデル（tenant/role/state）”を、API設計（REST filters）として「検索条件に埋め込むのではなくサーバが強制する」形に落とし込み、以降のwebhook/async/export/error/versioningの“例外パス”でも同様に崩れないよう接続する
- MITRE ATT&CK：
  - 戦術：Discovery / Collection / Impact
  - 目的：検索条件とソートを利用して対象の存在・関係・件数を推測（Discovery）、大量に収集（Collection）、負荷を上げて可用性へ影響（Impact）。検索は“静かな列挙”の主戦場。

## タイトル
rest_filters_検索・ソート・ページング境界

## 目的（この技術で到達する状態）
- RESTの一覧/検索APIを、(1)テナント境界（03）、(2)認可条件（RBAC/ABAC：04）、(3)状態（10）、(4)最小開示（列/フィールド）、(5)濫用耐性（上限・コスト）、(6)観測オラクル（エラー差分/件数差分）、の観点でモデル化し、短時間で“越境混入/静かな漏洩”を確定できる
- 「フィルタは自由に見せても良い」という誤解を避け、危険なのは“クライアントが境界条件を指定できる/外せる”こと、と設計に落とせる
- ペンテスターとして、低侵襲（少数リクエスト）で「境界の欠落」を証跡化し、修正方針（サーバ強制、allowlist、上限、監査）まで提示できる

## 前提（対象・範囲・想定）
- 対象：一覧/検索API（例：/users, /projects, /orders, /invoices, /tickets など）
- 想定される検索実装（現実運用の混在）
  - DBのWHERE（SQL/ORM）
  - NoSQLクエリ（Mongo等）
  - 検索基盤（Elasticsearch/OpenSearch等）
  - キャッシュ＋バックエンド検索（BFF/集約）
- フィルタ/ソート/ページングの表現は多様（混在前提）
  - filter：query string（?status=...&org_id=...）、JSON body、RSQL、OData風、独自DSL
  - sort：?sort=created_at,-id など
  - paging：offset/limit、page/per_page、cursor（after/before）、keyset（since_id）
- 検証の安全な範囲（ペネトレ）
  - 大量列挙はしない。代わりに「件数」「次ページトークン」「ソート差分」「存在の匂い」で列挙可能性を示す
  - 2ユーザ×2テナントで差分観測（同一条件で結果が混ざるか）を優先する

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) 検索APIは“認可の入口”であり、境界条件はサーバが付与するべき
- 正しい方向（設計原則）
  - tenant_id / owner_id / permitted_scope はクライアント入力ではなく、サーバのコンテキストから強制付与する
  - クライアントは「絞り込み希望」を出せるが、“境界の下限”は外せない
- 危険な兆候（実務で頻出）
  - ?tenant_id= をクライアントが指定でき、しかも検証が弱い（03）
  - filter DSLで “tenant条件を上書き/無効化” できる（例：or/neq/null条件で逃げる）
  - “検索は全体インデックス”で、結果の後段（詳細）だけで認可している（一覧で漏れる）

観測で確定したい点：
- サーバが強制している境界条件が何か（tenant/role/state）
- それがクライアント入力で外せる/上書ける余地があるか

### 2) filter の境界：どの属性で絞れるか、どの属性は絞れてはいけないか
- filterの分類（実務的）
  - 公開フィルタ：仕様として誰でも使う（status、category、created_at範囲等）
  - センシティブフィルタ：使えると探索が加速（email、phone、external_id、internal_flag）
  - 境界フィルタ：tenant_id、org_id、owner_id、role、visibility、state（ここをクライアントに渡すと危険）
- 典型事故パターン
  - “境界フィルタ”が外部入力で指定可能（tenant越境の入口）
  - “センシティブフィルタ”で存在確認オラクル（メールが登録済みか等）
  - 状態（draft/approved）をフィルタで覗ける（10）＋返却列が過剰（PII）
- 観測の作法（差分で確定）
  - 同一APIで、境界系パラメータ（org_id等）を変えて結果が変わるか
  - “存在しない値” と “存在するが見えない値” の応答差（件数・エラー・時間）を比較し、オラクル有無を判断
  - filterのエラーがDSL内部情報を漏らさないか（04_api_09へ）

### 3) sort の境界：ソートは“推測”と“漏洩の補助線”になりやすい
ソートは見落とされがちだが、探索を加速する。
- 典型の危険
  - sortに内部カラム（is_admin、deleted_at、risk_score、balance 等）が指定できる
  - sortに関連テーブル/ネスト属性が指定でき、越境混入や負荷増大が起きる
  - sortのデフォルトが “新規順” で、漏れがあると直近データが取り放題
- 観測で確定したい点
  - sortに指定可能なフィールドが allowlist か（未知のsort指定が通るなら危険）
  - sort指定のエラーが内部カラム名を漏らさないか
  - sort変更で「見えるデータの集合」が変化しないか（本来、境界が強ければ順序が変わるだけ）

### 4) paging の境界：列挙可能性と負荷の両方を決める
#### 4.1 offset/limit（古典）
- 危険
  - limitが無制限、または過大（大量取得）
  - offsetが深いほど重い（負荷/DoSの入口）
  - “件数 total” が常に返り、存在/規模のメタ情報が漏れる（仕様判断）
- 観測で確定したい点
  - limit上限（cap）がサーバで強制されるか
  - totalを返す/返さないの方針（返すなら権限・スコープ別で妥当か）

#### 4.2 cursor/keyset（現実運用で多い）
- 強み
  - 深いoffsetより性能が良い
- ただし危険
  - cursorが推測可能（base64でも中身が連番/時刻だと推測材料）
  - cursorがテナント/検索条件に束縛されていない（別条件で再利用できる＝越境混入）
  - cursorが “存在のオラクル” を提供する（無効cursorの応答差）
- 観測で確定したい点
  - cursorが「検索条件＋スコープ」にバインドされているか（別ユーザ/別tenantで使えないか）
  - cursorのエラーが内部実装を漏らさないか
  - after/beforeの境界で “重複/欠落” がないか（実運用の整合性）

### 5) fields/expand/include の境界：最小開示（field-level）がRESTにもある
RESTでも「返却列を増やすパラメータ」がよく存在する。
- 例：?fields=..., ?include=..., ?expand=..., ?with=...
- 危険
  - “一覧”なのに詳細相当の機微フィールドが取れる
  - expandで関連オブジェクト（他人/他tenant）へ到達（AuthZの入口増殖）
- 観測で確定したい点
  - fieldsが allowlist か、権限別に返却が変わるか
  - expandが nested AuthZ を強制しているか（03_authz_07の考え方をRESTに移植）

### 6) 検索は越境混入（03）の最頻出：特に“横断検索”と“全文検索”
- 典型事故
  - tenant条件の付与漏れ（index全体に検索がかかる）
  - キャッシュがtenantキーを持たず混入（GraphQLのloader問題と同型）
  - “検索結果の一覧だけ見える” → 詳細は拒否、しかし一覧で十分漏れる（氏名/件名/金額など）
- 観測で確定したい点
  - 同一検索語でテナントA/Bの結果が混ざらないか（差分観測）
  - 返るサマリ（title/subject）に機微が含まれないか（最小開示）

### 7) エラー差分とレスポンス形状：検索はオラクルになりやすい（04_api_09へ接続）
- 代表的オラクル
  - total件数の差
  - 次ページトークン有無の差
  - 200だが空配列 vs 403/404（存在と権限の判別）
  - レスポンス時間差（存在する時だけ重い）
- 観測で確定したい点
  - “存在するが見えない”を、攻撃者に区別させない設計になっているか（必要なら曖昧化）
  - 例外メッセージに内部実装（DSL、SQL、index）が漏れていないか

### 8) 濫用耐性：検索は“コスト制御”が必要（GraphQL query_costと同型）
- 実運用で効く防御
  - filter/sort allowlist（未定義は拒否）
  - limit cap（サーバ強制）
  - 高コスト操作（全文検索、広範囲期間、ワイルドカード）に別レート/別権限
  - time range の上限（例：created_atは最大90日）
  - index設計（運用だが境界に直結）
- 観測で確定したい点（低負荷で）
  - “危険フィルタ”が拒否されるか（ワイルドカード、巨大範囲）
  - rate limit が検索に効いているか（他APIより厳しいか）
  - timeout時のエラーが情報漏えいしていないか（04_api_09）

### 9) rest_filters_key_boundary（正規化キー：後続へ渡す）
- 推奨キー：rest_filters_key_boundary
  - rest_filters_key_boundary =
    <filter_style>(query_params|json_body|dsl|mixed|unknown)
    + <tenant_scope_enforcement>(server_forced|client_influenced|weak|unknown)
    + <filter_allowlist>(yes/no/unknown)
    + <sort_allowlist>(yes/no/unknown)
    + <paging_style>(offset|cursor|mixed|unknown)
    + <limit_cap>(strong|weak|none|unknown)
    + <cursor_binding>(bound|unbound|unknown)
    + <fields_expand_controls>(strong|weak|none|unknown)
    + <oracle_risk>(high|medium|low|unknown)
    + <abuse_controls>(rate|timeout|range_cap|mixed|none|unknown)
    + <error_model_consistency>(consistent|leaky|unknown)
    + <audit_strength>(strong|partial|weak|unknown)
    + <confidence>
- 記録の最小フィールド（推奨）
  - endpoint、主要パラメータ一覧（filter/sort/page/fields）
  - tenant/ownerの強制有無（差分観測）
  - limit上限とcursor束縛（差分観測）
  - オラクル候補（total/next token/時間差/エラー差分）
  - evidence（HAR、レスポンス差分、エラー断片）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える（確定できる）：
  - 検索条件の中で、境界条件（tenant/role/state）がサーバ強制か、クライアント影響か
  - filter/sort/paging/fields の allowlist と上限があるか
  - cursorが検索条件とスコープに束縛されているか（再利用で越境しないか）
  - 一覧/検索が越境混入や過剰開示の入口になっていないか
  - オラクル（件数/トークン/エラー差分）として利用できる余地があるか
- 推定（根拠付きで言える）：
  - allowlist無し＋limit cap無し＋横断検索あり は、情報漏えいと濫用の両面で高リスク
  - cursor束縛が弱い場合、ページングトークンが“横断のパス”になり得る
- 言えない（この段階では断定しない）：
  - 大規模データでの実際の負荷限界（DoSは実行しない）。ただし“上限設計不在”は重大リスクとして示せる。

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- 優先度（P0/P1/P2）
  - P0：
    - tenant/owner条件がクライアント入力で上書きでき、越境混入が発生
    - limit cap無しで大量取得が可能（Collectionに直結）
    - expand/include で他人/他tenantの関連情報へ到達（入口増殖）
    - cursorが別ユーザ/別tenantで再利用できる（束縛欠落）
  - P1：
    - sortで内部属性や機微が推測できる（探索加速）
    - total/next_token/エラー差分が存在オラクルになる
    - 高コスト検索にコスト制御が弱い（濫用耐性不足）
  - P2：
    - 設計は堅牢だが、監査（検索条件ログ）が弱く調査が難しい
- “成立条件”としての整理（技術者が直すべき対象）
  - tenant/owner/state等の境界条件はサーバが強制付与し、クライアント指定を信頼しない
  - filter/sort/fields/expand は allowlist 化し、未定義は拒否（または安全に無視）
  - pagingはcap必須、cursorは検索条件＋スコープにバインドし、再利用を防ぐ
  - オラクル（件数/トークン/エラー差分）を仕様として制御し、必要なら曖昧化
  - 検索は高コストなので、レート・範囲上限・タイムアウトを操作単位で設計する

## 次に試すこと（仮説A/Bの分岐と検証：低侵襲で差分確定）
- 仮説A：tenant越境混入（server-forcedではない）
  - 次の検証（差分）：
    - 同一検索語/同一条件で、tenantA/tenantB の結果差分を比較（混入兆候）
    - org_id/tenant_id等の境界パラメータを変えたときに結果が変わるか（上書き兆候）
  - 判断：
    - 混入/上書き：P0
- 仮説B：limit capが無い
  - 次の検証：
    - limitを段階的に増やし、ある境界で強制されるか/拒否されるかを見る（低負荷）
  - 判断：
    - 境界無し：P0〜P1
- 仮説C：cursor束縛が弱い
  - 次の検証：
    - cursorを条件違い・ユーザ違いで使ったときの挙動差分（拒否/無視/成立）を観測
  - 判断：
    - 再利用成立：P0
- 仮説D：fields/expandで過剰開示
  - 次の検証：
    - fields/expandを追加した時に、一覧が詳細相当にならないか（機微フィールドが出ないか）
  - 判断：
    - 機微が増える：P1〜P0（内容次第）
- 仮説E：オラクル（存在判定）が強い
  - 次の検証：
    - “存在しない値” と “存在するが見えない値” の応答差（total/next/error/time）を比較
  - 判断：
    - 明確に区別できる：P1（攻撃の加速器）

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/` ）：
  - `04_labs/02_web/04_api/03_rest_filters_sort_paging_boundary/`
    - 構成案（現実運用の再現）
      - テナント2つ、ロール複数（viewer/editor/admin）
      - 一覧API：filter（status/date/owner/tenant）、sort（created_at/amount/internal_flag）、paging（offset/cursor）を併設
      - fields/expand：include=owner, expand=details などを用意
      - 防御切替：tenant強制ON/OFF、allowlist ON/OFF、limit cap ON/OFF、cursor binding ON/OFF
      - ログ：検索条件、強制付与した境界条件、結果件数、trace_id、deny理由
- 取得する証跡（深掘り向け：HTTP＋周辺ログ）
  - HTTP：filter/sort/page/fields の差分リクエスト（少数）
  - レスポンス：itemsの一部、total/next_token、エラー形状、時間差（必要最小限）
  - ログ：tenant強制付与の有無、where条件（抽象化）、rate/timeout
  - 監査：誰がどの条件で検索したか（調査可能性）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
# filter / sort / paging（擬似）
GET /api/orders?status=paid&sort=-created_at&limit=50&offset=0

# cursor paging（擬似）
GET /api/orders?status=paid&sort=-created_at&limit=50&after=CURSOR_TOKEN

# fields / expand（擬似）
GET /api/orders?status=paid&fields=id,amount,customer_email&expand=customer

# 観測すること（擬似）
- tenant/owner条件がクライアント入力で上書きできないか
- limit cap がサーバで強制されるか
- cursor が検索条件/スコープにバインドされているか
- fields/expand で一覧が過剰開示にならないか
~~~~
- この例で観測していること：
  - REST一覧/検索の境界（強制条件・上限・最小開示・オラクル）を、低侵襲の差分で確定する
- 出力のどこを見るか（注目点）：
  - tenant_scope_enforcement、limit_cap、cursor_binding、fields_expand_controls、oracle_risk、error_model_consistency
- この例が使えないケース（前提が崩れるケース）：
  - 検索がPOST bodyのDSLの場合：同じ観測軸（allowlist/境界強制/上限/オラクル）をbodyパラメータに写像する

## 参考（必要最小限）
- OWASP ASVS（認可、最小開示、API濫用耐性、監査）
- OWASP WSTG（Authorization / API Testing：一覧・検索・ページングの境界）
- PTES（差分観測で越境混入と列挙可能性を確定）
- MITRE ATT&CK（Discovery/Collection：検索は静かな列挙）

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/03_authz_03_multi-tenant_分離（org_id_tenant_id）.md`
- `01_topics/02_web/03_authz_02_idor_典型パターン（一覧_検索_参照キー）.md`
- `01_topics/02_web/04_api_09_error_model_情報漏えい（例外_スタック）.md`

## 次（04_api_04 以降）に進む前に確認したいこと（必要なら回答）
- 次のWebhook（04/05）では、REST filtersで出た「クライアント入力を信頼しない」「再送/重複/欠落の扱い」を、署名・idempotency・到達性（SSRF）に写像して同じ軸で扱う
