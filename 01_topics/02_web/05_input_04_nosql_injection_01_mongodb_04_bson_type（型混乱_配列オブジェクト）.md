# 05_input_04_nosql_injection_01_mongodb_04_bson_type（型混乱_配列オブジェクト）

## 目的（この技術で到達する状態）
- MongoDB（BSON）特有の「型の自由度」を悪用した **型混乱（Type Confusion）** を、Operator Injection（$ne等）とは別枠で整理できる。
- 具体的に次ができる状態になる。
  1) 入力点で “型” を変えるだけで結果が変わるか（成立根拠）を観測で確定できる  
  2) “配列/オブジェクト/null” が混入する設計上の原因（復元・バリデーション・merge）を特定できる  
  3) 影響を「認証（照合）」「検索（フィルタ）」「認可（tenant/owner条件）」に分解して評価できる  
  4) 修正を「禁止ワード」ではなく **API境界の型拘束（DTO/Schema）＋クエリ生成の設計** へ落とせる

## 前提（対象・範囲・想定）
- 対象：MongoDB を利用するWeb/APIで、検索・ログイン・一覧・管理UI等の条件が入力由来になっている箇所、JSON（application/json）、form-urlencoded、query string（ネスト復元あり）のいずれも対象
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - 本ファイルの焦点："$演算子" を直接使わなくても、入力が **配列/オブジェクト** になっただけでクエリ解釈が変わる・バリデーションがすり抜ける・mergeが崩れる、という境界破壊を扱う
  - 位置づけ：Operator Injection（`$ne/$gt/$regex`）が「演算子語彙の混入」なら、BSON型混乱は「型（データ構造）の混入」で、入力→クエリの境界を破る
- できること/やらないこと（安全に検証する範囲）：
  - できること：入力が "値" を超えて "Mongoクエリ構造（演算子）" を形成できる（境界破壊）、その成立経路（JSON直渡し / ネスト復元 / filter JSONパース / マージ処理）がどれか、差分（oracle）がどこに出るか（件数/長さ/エラー/時間）と再現性、認可境界（tenant/org/owner 条件）に接続し得る入口か（設計上の危険性）
  - やらないこと：DB種類の断定（互換実装・抽象化がある）、"データが全て抜ける" の断定（権限・投影・API制限・監査で変わる）、"高負荷攻撃が可能" の断定（負荷検証は契約と安全配慮が必要）
- 依存する前提知識（必要最小限）：
  - `01_topics/02_web/05_input_00_入力→実行境界（テンプレ デシリアライズ等）.md`
  - `01_topics/02_web/05_input_04_nosql_injection_01_mongodb_01_operator（$ne_$gt_$regex）.md`
  - `01_topics/02_web/03_authz_00_認可（IDOR BOLA BFLA）境界モデル化.md`
  - `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
  - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`

## 境界モデル：どこで“型”が変わるか（入力→復元→検証→クエリ生成）

### 1) 型混乱の本質は「アプリはstring想定、実際はBSONで多型」
- 多くの実装は “このフィールドは文字列” の前提で作る
- しかし、APIはJSON等で **object/array/null/bool/number** を自然に受理できる
- 境界破壊の形
  - 入力が string ではなく object/array になった瞬間、以後の処理（検証・正規化・クエリ生成）が想定外分岐へ入る

### 2) 型が変わる典型ポイント（黒箱でも当てられる）
- (A) JSONをそのまま扱う（application/json）
  - 受けた型がそのままメモリ上のオブジェクトになる
- (B) form/query のネスト復元（`a[b]=x` → `{a:{b:"x"}}`）
  - 文字列のつもりが、いつの間にかobject/arrayになり得る
- (C) “汎用filter” のパース（`filter=`にJSON文字列）
  - JSONパースが入ると型が自由になる
- (D) 既定条件とユーザ条件の merge（浅い/深いマージ）
  - 型が違う値（string vs object）が混ざると、上書き・空配列・null混入など“意図しない確定条件”を作る

### 3) 観測指標（oracle）を固定する：エラーではなく“結果差分”
- Boolean oracle（主証拠）
  - 件数、レスポンス長、ページ数、表示要素数、特定要素の有無
- Error oracle（補助）
  - 型不一致・キャスト失敗が返るなら「内部実装（期待型）」の補助証拠になるが、主証拠はBooleanに寄せる
- Time oracle（原則補助）
  - 型混乱自体は時間差分より結果差分が主。遅延を狙う検証は避ける

## MongoDB/BSONの“型差分”が問題になる代表パターン（差分＝成立根拠）

> ここでは「どう悪用するか」ではなく、「どの差分が出たら、どの設計境界が壊れていると言えるか」を固定する。

### パターン1：照合（login/本人確認）で型が揺れる
- 状況
  - username/email/userId などの照合値を string 前提で扱う設計
- 型混乱の論点
  - 入力が array/object/null になったときに、検証が落ちるべきなのに“通る/別分岐へ行く”
- 観測で言えること（成立根拠）
  - 同じフィールドに対して型だけ変えてレスポンスが変わるなら、API境界の型拘束が崩れている
- 次の一手（評価の方向）
  - 認証そのものの成立可否より先に、「照合入力が多型で受理される」点を根本原因として固定する

### パターン2：検索/フィルタで “配列” が想定外の意味を持つ
- 状況
  - `status`, `tags`, `category` などを単一値で受けるつもりが、配列として入る
- 型混乱の論点
  - アプリ側が「単一値」想定で組んだクエリが、配列やnullの混入で“条件が弱くなる/強くなる/無効化される”
- 観測で言えること
  - “単一入力”と“配列入力”で件数が大きく変わるのに、仕様としてその説明がない場合、型混乱の疑いが濃い
- 注意（仕様との切り分け）
  - “複数選択検索”は仕様として存在し得る  
    → 仕様なら、上限・認可条件同居・入力正規化（配列要素型）まで設計されているかを確認する

### パターン3：ObjectId（またはUUID等）キャスト境界の不整合
- 状況
  - DB側は `_id: ObjectId` なのに、APIは文字列で受ける
- 典型リスク
  - ある経路では ObjectId にキャストするが、別経路では文字列のまま検索する（実装分岐）
  - キャスト失敗が例外差分（oracle）になり、さらに“fallback”があると条件が崩れる
- 観測で言えること
  - 同じID入力でもエンドポイントやモードによって挙動が揺れるなら、型変換の一貫性がない（設計不備）
- 次の一手
  - “キャストは常にサーバで統一” と “受理型を固定（string→ObjectIdへ正規化）” を修正方針として提示する

### パターン4：既定条件（tenant/owner）とユーザ条件の merge で型が衝突する
- 状況
  - `base = { tenant_id: currentTenant }` と `userFilter` を混ぜる
- 型混乱の論点
  - `tenant_id` を string のつもりでも、ユーザが object/array/null を混ぜられると、上書き・無効化・条件の別解釈が起き得る
- 観測で言えること
  - 認可境界に関わるキーが"ユーザ入力と同じ階層で受理される"設計自体が危険（BOLA接続）
- 次の一手
  - 既定条件は固定、ユーザ条件は安全DSLから生成しAND結合（入力オブジェクトを直接mergeしない）へ落とす

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が"確定"できるか：
  - 入力が "値" を超えて "Mongoクエリ構造（演算子）" を形成できる（境界破壊）、その成立経路（JSON直渡し / ネスト復元 / filter JSONパース / マージ処理）がどれか、差分（oracle）がどこに出るか（件数/長さ/エラー/時間）と再現性、認可境界（tenant/org/owner 条件）に接続し得る入口か（設計上の危険性）
- 何が"推定"できるか（推定の根拠/前提）：
  - まず Boolean oracle（件数/長さ）で確定する（推奨）
  - エラーが見えるなら、型不一致・キャスト失敗が返る場合は「DB到達」の補助証拠に使う（主証拠はBoolean）
  - 時間差分は最後（短時間・少回数で、他指標と組み合わせる）
- 何は"言えない"か（不足情報・観測限界）：
  - DB種類の断定（互換実装・抽象化がある）、"データが全て抜ける" の断定（権限・投影・API制限・監査で変わる）、"高負荷攻撃が可能" の断定（負荷検証は契約と安全配慮が必要）
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：照合（login/本人確認）で型が揺れる → 入力が array/object/null になったときに、検証が落ちるべきなのに"通る/別分岐へ行く"
  - パターンB：検索/フィルタで "配列" が想定外の意味を持つ → アプリ側が「単一値」想定で組んだクエリが、配列やnullの混入で"条件が弱くなる/強くなる/無効化される"
  - パターンC：ObjectId（またはUUID等）キャスト境界の不整合 → ある経路では ObjectId にキャストするが、別経路では文字列のまま検索する（実装分岐）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す"狙い目"：
  - ログイン/本人確認に近い照合、"一致判定"が型で崩れると、認証・アカウント列挙の問題へ繋がる、検索API（q/filter/where）、"柔軟検索"を謳うほど、filter JSON を受けてマージしがち、管理画面の一覧・エクスポート、条件が複雑で、サーバ側も動的にマージしがち（越境混入が起きやすい）
- 優先度の付け方（時間制約がある場合の順序）：
  - まず "同じフィールド"に対し、入力形式だけ変えて "条件解釈が変わる" かを差分で見る、これが見えれば「エスケープ不足」ではなく「構造注入」であることを説明できる
- 代表的な攻め筋（この観測から自然に繋がるもの）：
  - 攻め筋1：型拘束がなく、object/array/null が受理されている → 同一フィールドに対し、型だけ変えたときにレスポンス（件数/長さ/表示）が安定して変わる
  - 攻め筋2：filterパース/merge が原因で型衝突が起きている → 単純パラメータでは差分が出ないが、advanced filter で差分が出る
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）：
  - 型混乱は "値のエスケープ" では防げない、防御は **ステージの許可集合（allowlist）** と **サーバ側生成（入力を構造にしない）** が本体

## 根本原因の分類（報告にそのまま使える形）

### 原因A：API境界での型拘束がない（スキーマ/DTO不在）
- 症状
  - 想定外の型（object/array/null）が受理される
- 修正
  - JSON Schema / DTO / バリデータで型を固定し、object/arrayを拒否する（許すなら仕様として明示し要素型も固定）

### 原因B：ネスト復元・型変換ミドルウェアの設定が危険
- 症状
  - query/form から object/array が作られる
- 修正
  - ネスト復元の深さ制限、配列受理の明示、未定義キーの拒否（strict）

### 原因C：汎用filterのJSONパース＋直渡し（またはdeep merge）
- 症状
  - ユーザ入力がクエリ構造・型を自由に持つ
- 修正
  - アプリ独自DSL（field/op/value）へ落とし、サーバ側でクエリ生成（受理語彙と型をallowlist化）

### 原因D：ID（ObjectId等）キャストの一貫性欠如
- 症状
  - エンドポイントによりキャスト/非キャストが混在
- 修正
  - 入口で正規化（常に同じ型へ）し、DBアクセス層で統一

## 次に試すこと（仮説A/B/C：最小差分で確定）
※ここは「検証の進め方（観測設計）」であり、悪用の手順ではない。

### 仮説A：型拘束がなく、object/array/null が受理されている
- 条件（観測）
  - 同一フィールドに対し、型だけ変えたときにレスポンス（件数/長さ/表示）が安定して変わる
- 次の一手
  - 差分指標を固定（件数/長さ）し、入力点（body/query/form）を確定して横展開（同種パラメータを洗う）
  - 仕様として複数選択があるかを切り分け（仕様なら要素型・上限・認可同居まで設計されているかを見る）

### 仮説B：filterパース/merge が原因で型衝突が起きている
- 条件（観測）
  - 単純パラメータでは差分が出ないが、advanced filter で差分が出る
- 次の一手
  - “どのキー”がfilter内で受理されるかを差分で特定し、allowlist不在・deep merge を根本原因として固定する
  - 認可キー（tenant/org/owner）がfilterと同列に扱われていないかを確認（BOLA接続）

### 仮説C：ObjectIdキャスト境界が揺れている
- 条件（観測）
  - ある経路は400、ある経路は200など、同じID入力で挙動が揺れる
- 次の一手
  - 入口（DTO）での型正規化の有無、DBアクセス層の統一性を指摘し、修正方針を“設計”として提示する

## 防御設計（実装・運用の両面で“境界”を閉じる）

### 1) 型拘束をAPI境界で強制（最優先）
- “このフィールドはstring” をコードで保証する（DTO/JSON Schema）
- object/array/null を拒否（許すなら仕様として、要素型・最大要素数・最大ネスト深さを固定）

### 2) 受理語彙をallowlist化（スキーマレスDBの自由度をアプリで抑える）
- filter/where/pipeline をそのまま受けない
- field/op/value などの安全DSLに限定し、サーバ側でクエリ生成
- 未知キーは拒否（strip unknown に頼り切らない）

### 3) 既定条件（tenant/owner）とユーザ条件を“同階層mergeしない”
- base条件は固定、ユーザ条件は安全に生成したものだけAND結合
- deep merge を避け、境界条件が上書きされない設計にする

### 4) ID型（ObjectId等）の正規化を統一
- 入口で正規化（文字列→ObjectId）
- 失敗時は一貫して400（エラーモデル統一）
- DBアクセス層で統一（エンドポイント別の例外実装をなくす）

### 5) 監査・検知（型逸脱の観測）
- ログ（機微はマスク）
  - trace_id、パラメータ名、受理した型（string/object/array/null）、失敗理由分類
- アラート候補
  - 特定入力点でobject/array/nullの出現が増える
  - 400増加（キャスト失敗）と200の揺れが同一IP/UA/アカウントで相関

## 手を動かす検証（Labs連動：型境界の再現）
- 目的：Operator Injectionと切り分けて、BSON型混乱だけで差分が出る設計を再現する
- 最小構成（推奨）
  - (1) 安全：DTOで型拘束（stringのみ）、未知キー拒否
  - (2) 脆弱：body/queryをそのままfind条件へ利用（型混入）
  - (3) 脆弱：filter JSONパース＋deep merge（型衝突）
  - (4) ID境界：ObjectIdキャストあり/なしの差分（実装分岐の危険性）
- 証跡
  - HAR：baseline / 型変化（差分true/false）
  - サーバログ：trace_id、受理型、生成クエリの要約（キーのみ、値はマスク）
  - DBログ（Labsのみ）：実行クエリの型（ObjectIdか文字列か等）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は"手段"であり"結論"ではない。必ず「何を観測している例か」を添える。

~~~~
# 危険：受理型を固定していない（object/arrayがそのまま通る）
const username = req.body.username
db.users.find({ username: username })

# 安全：入口で型拘束（stringのみ）
assert(typeof req.body.username === "string")
db.users.find({ username: req.body.username })
~~~~

- この例で観測していること：受理型の固定、型拘束の有無、object/arrayの混入可能性
- 出力のどこを見るか（注目点）：型検証の有無、エラーハンドリング、クエリの生成方法
- この例が使えないケース（前提が崩れるケース）：ORMが自動的に型検証を行っている場合、または完全に静的なクエリのみを使用している場合

~~~~
# 危険：filterパース＋deep merge（型衝突・上書きが起きる）
base = { tenant_id: t }
user = JSON.parse(req.query.filter)
query = deepMerge(base, user)

# 安全：base固定、ユーザ条件は安全DSLから生成してAND結合
query = { $and: [ base, safeUserCondition ] }
~~~~

- この例で観測していること：filterパースの処理、deep mergeの危険性、権限条件の固定性
- 出力のどこを見るか（注目点）：マージ処理の方法、AND結合の有無、権限条件の固定性
- この例が使えないケース（前提が崩れるケース）：権限条件が固定されていない場合、または完全に静的なクエリのみを使用している場合

~~~~
# 危険：IDキャストが経路で揺れる（ある経路はObjectId、別経路は文字列）
findById(id)  # 実装によりキャスト有無が混在

# 安全：入口で必ず正規化してからDBアクセス層へ渡す（失敗は一貫して400）
id = normalizeObjectId(req.params.id)
findById(id)
~~~~

- この例で観測していること：IDキャストの一貫性、型正規化の有無、エラーハンドリング
- 出力のどこを見るか（注目点）：キャスト処理の方法、エラーハンドリング、型正規化の有無
- この例が使えないケース（前提が崩れるケース）：IDが常に同じ型で扱われている場合、または完全に静的なクエリのみを使用している場合

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：V5 Validation, Sanitization and Encoding、V7 Error Handling and Logging
  - 該当要件（可能ならID）：V5.3.1、V5.3.2、V7.4.1
  - このファイルの内容が「満たす/破れる」ポイント：
    - 入力→実行境界：入力が「値（scalar）」ではなく「BSON型（object/array/null/bool/number）」としてDBクエリに到達し、条件解釈が変わらない設計か
    - 型・スキーマ：API境界で型拘束（DTO/JSON Schema）を強制し、スキーマレスDBの"自由度"をアプリ側で閉じているか
    - 認可境界：tenant/org/owner 条件と同列にユーザ入力をマージしていないか（型混乱で条件が崩れる）
    - 例外/エラー：キャスト失敗・型不一致・配列処理の例外を統一し、差分（oracle）を潰せているか
    - 監査：型逸脱（string想定にobject/arrayが来る、nullが多い等）をログ相関し、探索兆候を検知できるか
- WSTG：
  - 該当カテゴリ/テスト観点：WSTG-INPV-05 SQL Injection、WSTG-ERRH-01 Error Handling
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：
    - Injection（入力→実行）として、SQLiの"型キャスト境界"に相当する観点をNoSQLへ移植（型変化で挙動が変わるか）
    - テストはエラー誘発より **Boolean oracle（件数/長さ/表示要素）** を主証拠に、型変化（string→array/object/null等）で差分を取る
- PTES：
  - 該当フェーズ：Vulnerability Analysis、Exploitation、Reporting
  - 前後フェーズとの繋がり（1行）：入力点→型変換/バリデーション→クエリ生成点（find/aggregate）→差分観測で成立根拠を確定し、影響実証は最小限（認証/検索/越境混入の成立の有無）。DoSや大量抽出は避ける、根本原因を「API境界の型拘束欠如」「型変換の不整合（string/ObjectId）」「merge設計」「スキーマレス運用」に分解して提示
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：TA0001 Initial Access（公開アプリ入口）/ TA0009 Collection（検索APIからの収集）/ TA0005 Defense Evasion（エラー統一下でブラインド化）
  - 攻撃者の目的（この技術が支える意図）：T1190 Exploit Public-Facing Application（NoSQLi/型混乱は入口になり得る）

## 参考（必要最小限）
- MongoDB Documentation: https://docs.mongodb.com/
- MongoDB BSON Types: https://docs.mongodb.com/manual/reference/bson-types/
- OWASP NoSQL Injection: https://owasp.org/www-community/attacks/NoSQL_Injection
- OWASP Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/05_input_04_nosql_injection_01_mongodb_01_operator（$ne_$gt_$regex）.md`
- `01_topics/02_web/04_api_03_rest_filters_検索・ソート・ページング境界.md`
- `01_topics/02_web/03_authz_00_認可（IDOR BOLA BFLA）境界モデル化.md`

---

## 深掘りリンク（最大8）
- `01_topics/02_web/05_input_00_入力→実行境界（テンプレ デシリアライズ等）.md`
- `01_topics/02_web/05_input_04_nosql_injection_01_mongodb_01_operator（$ne_$gt_$regex）.md`
- `01_topics/02_web/05_input_04_nosql_injection_01_mongodb_02_where_eval（$where_js）.md`
- `01_topics/02_web/05_input_04_nosql_injection_01_mongodb_03_aggregation（pipeline_$lookup）.md`
- `01_topics/02_web/03_authz_00_認可（IDOR BOLA BFLA）境界モデル化.md`
- `01_topics/02_web/04_api_03_rest_filters_検索・ソート・ページング境界.md`
- `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
- `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
