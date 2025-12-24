## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）

- ASVS：
  - 該当領域/章：入力検証（Injection）、アクセス制御（認可/テナント分離）、エラー処理/ロギング、可用性（リソース制御）
  - このファイルの内容が「満たす/破れる」ポイント：
    - ユーザ入力が Query DSL（JSON構造）として **bool / filter / script** を形成できると、値のエスケープでは防げない「入力→実行境界」破壊になる
    - 認可条件（tenant/org/owner）を query と同階層で合成すると、境界条件が“揺れる/上書きされる”設計になりやすい
    - script（Painless等）を入力由来で組み立てると、実行境界（コード評価）とDoS境界（高コスト計算）が同時に崩れる
    - 防御は「安全DSL→サーバ側生成」「フィールド/演算子 allowlist」「固定の認可filter強制」「高コスト機能の無効化/制限（search.allow_expensive_queries 等）」に落ちる
- WSTG：
  - 該当カテゴリ/テスト観点：Injection（検索/フィルタ入力が実行計画に変換される点）、Authorization（テナント分離が検索で崩れないか）、Error Handling（oracle化）
  - 対応の書き方：エラーより **Boolean oracle（件数/長さ/要素数）** と **構造差分（bool構造の揺れ）** を主証拠にする
- PTES：
  - 該当フェーズ：Vulnerability Analysis → Exploitation（影響実証は最小限）→ Reporting（根本原因を設計へ落とす）
  - 前後フェーズとの繋がり（1行）：
    - 前：APIの検索・絞り込み（filters/paging）観測で入口を確定 → 本：DSL生成点の境界破壊 → 後：認可（BOLA/BFLA）と可用性（DoS）へ影響を分解して報告
- MITRE ATT&CK：
  - 該当戦術：TA0001 Initial Access / TA0009 Collection / TA0005 Defense Evasion（エラー統一でブラインド化）
  - 攻撃者の目的：検索機能を“横断収集・越境混入・高コスト実行”の足場にする（T1190 など）

---

## タイトル
NoSQL Injection（Elasticsearch）：Query DSL（bool / filter / script）入力→実行境界

## 目的（この技術で到達する状態）
- Elasticsearch を使うWeb/APIで、ユーザ入力が「検索語」ではなく **Query DSL（JSON構造）** として解釈されているかを判定できる。
- 特に bool / filter / script 周りについて、次を自走でできる状態になる。
  - DSL生成点（JSONパース/merge/テンプレ/ORM相当）を同定し、入力→実行境界の成立根拠（差分）を取れる
  - 認可filter（tenant/org/owner）の適用位置が正しいか（揺れないか）を、構造と結果差分で確定できる
  - script（Painless等）を「必要機能」と「危険境界（コード評価・高コスト）」に分離し、設計レビューと検証優先度を付けられる
  - 修正提案を、エスケープではなく **サーバ側DSL生成 + allowlist + 高コスト制限** に落とせる

## 前提（対象・範囲・想定）
- 対象：
  - 検索、一覧フィルタ、監査ログ検索、管理画面の詳細検索、レポート/エクスポートの絞り込み（保存検索＝second-orderも含む）
- 想定する環境：
  - アプリ（API）→ Elasticsearch クラスタ（同VPC/同NW・または外部SaaS）
  - 単一テナント/マルチテナント（同一indexにtenant_idを持つ、または index/alias分離）
  - Kibana 等が背後にある可能性（運用要件が設定に影響）
- できること/やらないこと（安全に検証する範囲）：
  - 低侵襲な差分観測（件数/長さ/構造差分）で境界を確定する
  - 高負荷を発生させる検証（DoS相当）や大量抽出は避け、設計上の制約欠如として評価する
- 依存する前提知識（必要最小限）：
  - Query（スコアリング）と Filter（フィルタコンテキスト）の違い
  - bool（must/should/filter/must_not）による合成構造
  - script（Painless）を使う場面と、許可/制限の考え方

## 観測ポイント（何を見ているか：プロトコル/データ/境界）

- 観測対象（プロトコル/データ構造/やり取りの単位）：
  - Web/APIの入力（q/filter/query/payload）→ サーバ側で組み立てられる ES検索リクエスト（_search JSON）
  - 応答：hits.total / 件数 / レスポンス長 / facet/aggregationの出現 / エラー分類 / took（時間）
- 境界の観点：
  - 資産境界（管理主体・対象範囲）：
    - ESクラスタ、index/alias、ログindex、顧客データindex、分析用index（横断の可否が影響）
  - 信頼境界（外部連携・第三者・越境ポイント）：
    - アプリ→ES間（同NWでも“別コンポーネント”であり、入力を構造に変える境界）
    - Kibana/Watcher/Alerting などの運用機能が、設定（script/expensive query）に影響する
  - 権限境界（権限の切替/伝播/委任）：
    - アプリ側の認可（tenant/org/role）と、ES側の権限制御（index権限、DLS/FLS、aliasフィルタ）の二重構造
    - 「固定のtenant filter」が検索構造のどこで強制されるか（ここが最重要）
- 重要なフィールド/差分/状態（ここが変わると意味が変わる）：
  - bool の階層：filter と must の混在、should の有無、minimum_should_match の有無
  - filter の位置：ユーザ入力と同階層で合成されていないか（merge上書き）
  - script の有無：script/query/script_score/runtime_fields 等の“高コスト/コード評価”要素が入力によりONになるか
  - 例外モデル：パースエラーやscriptエラーがそのまま返るか（oracle化）

## 結果の意味（その出力が示す状態：何が言える/言えない）

- 何が“確定”できるか：
  - 入力が「値」ではなく「DSL構造」として解釈されている兆候（構造差分→結果差分の再現性）
  - 認可条件（tenant/org/owner）が “固定で強制されている” か、“検索構造の一部として揺れている” か
  - script系が入力で到達可能か（コード評価境界が入力→実行として開いているか）
- 何が“推定”できるか（推定の根拠/前提）：
  - ES側設定（高コスト拒否、スクリプト許可）が効いている可能性（拒否エラー/挙動の一貫性から推定）
  - ESのどのクエリ種別（query_string/simple_query_string/DSL）が使われているか（差分とエラー形状から推定）
- 何は“言えない”か（不足情報・観測限界）：
  - “越境データが確実に漏えいした”の断定（返却フィールド、マスキング、DLS/FLS、アプリ側整形で変わる）
  - “DoS可能”の断定（性能試験の枠が必要。ここでは制約欠如の指摘に留める）
- よくある状態パターン：
  - パターンA（安全寄り）：ユーザ入力はキーワード/選択肢のみ、サーバが固定テンプレでDSL生成。tenant filterは常に bool.filter で強制
  - パターンB（危険）：filter/query を JSON として受け、サーバがdeep mergeしてESへ直渡し。固定条件が上書き/揺れる余地がある
  - パターンC（危険＋高影響）：script（inline）を入力由来で組み立て、さらに expensive query 制限/タイムアウトが弱い

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）

- この状態が示す“狙い目”：
  - 管理画面の詳細検索、監査ログ検索、分析ダッシュボード、レポート/エクスポート（DSL直結が多い）
  - “保存検索/共有フィルタ”がある機能（second-order：保存時は無害でも実行時に境界破壊）
- 優先度の付け方（時間制約がある場合の順序）：
  1) tenant/org/owner の固定条件がどこで強制されているか（認可境界の崩れが最優先）
  2) 入力がDSL構造（JSON）として通るか（直受け/mergeの有無）
  3) script/runtime_fields 等の高影響要素が入力で到達可能か（コード評価・高コスト）
- 代表的な攻め筋（この観測から自然に繋がるもの）：
  - 攻め筋1：固定認可filterの適用範囲・適用位置の揺れ（越境混入の成立根拠を差分で取る）
  - 攻め筋2：高コスト検索（expensive query）を許す設計か（制約欠如として評価）
- 「見える/見えない」による戦略変更：
  - ESがアプリ内に隠蔽されていても、APIがDSLを受けるなら同じ（境界は“入力→実行”）
  - Kibana運用要件がある場合、設定を強く締めると運用が壊れることがあるため、修正提案は「アプリ側でDSLを狭める」寄りに置く

## 次に試すこと（仮説A/Bの分岐と検証）
> ここが最重要。条件が違うと次の手が変わる形で書く。

- 仮説A：アプリがユーザ入力をDSL（JSON）として受理し、bool構造に混入できる（直受け/merge）
  - 次の検証：
    - 同一入力点で、入力“の型/構造”だけを変えたときに結果差分（件数/長さ/要素）が安定して出るかを確認
    - advanced search / filter / report definition の入口で差分が強く出るかを優先
  - 期待する観測（成功/失敗時に何が見えるか）：
    - 成功：検索結果の面積が入力構造に応じて揺れる（Boolean oracleで再現性が取れる）
    - 失敗：400等で拒否され、かつエラーが統一されていれば“入口で型拘束されている”可能性が高い

- 仮説B：固定のtenant/org/owner 条件が query と同階層で合成され、適用が揺れる（認可filter設計不備）
  - 次の検証：
    - テナント/権限/ロール切替（正当な条件変化）に対して、検索結果の変化が“仕様通り”かを見る
    - 特に「固定条件が filter コンテキストで強制されている」かを、レスポンス差分と（可能なら）監査ログ/サーバログで確認
  - 期待する観測：
    - 成功（不備がある）：本来変わらないはずの検索範囲が入力/モードで揺れる（固定条件の適用位置が不安定）
    - 失敗（健全）：固定条件が常に同じ形で適用され、入力は query 部分に閉じ込められている

- 仮説C：script（Painless等）・runtime_fields など高影響要素が入力経由で到達可能（コード評価/高コスト）
  - 次の検証：
    - 入力/モードで script要素がONになる経路が存在するか（UIの“計算フィールド/並び替え/カスタム式”等）
    - 拒否・許可の挙動が設定により変化するか（ただし負荷をかけない範囲で観測）
  - 期待する観測：
    - 成功：script関連のエラー/拒否/実行の差分が出る（＝入力→実行境界が開いている可能性）
    - 失敗：scriptがそもそも入力から到達不能、または stored script のみなどで制限されている

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/` ）：
  - `04_labs/03_targets/02_api_targets_検証用API選定.md`（検索APIを持つミニアプリ or 自作）
  - `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`（HAR/HTTPログで差分観測）
- 参照ファイル：
  - `01_topics/02_web/04_api_03_rest_filters_検索・ソート・ページング境界.md`
  - `01_topics/02_web/03_authz_00_認可（IDOR BOLA BFLA）境界モデル化.md`
- 取得する証跡（目的ベースで最小限）：
  - HAR（baselineと差分）、レスポンスの件数/長さ、ステータス、エラー種別
  - サーバログ（trace_id、検索モード、生成したDSLの“ステージ種別/キー”のみ要約：値はマスク）
  - ES側（Labsのみ）：slowlog / audit log（可能なら）、検索のtookと拒否理由
- 観測の取り方（どの視点で差分を見るか）：
  - 「入力が“値”として扱われる」場合：入力の文字列を変えても構造は変わらず、件数変化は限定的
  - 「入力が“構造”として扱われる」場合：入力の型/構造で件数・ネスト・付随情報が不自然に変わる
  - 認可境界：テナント切替・権限切替で“変わるべき範囲だけ”変わるかを主観ではなく差分指標で取る

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は“手段”であり“結論”ではない。必ず「何を観測している例か」を添える。

~~~~
# 例：bool の filter と must を分離して“固定条件（認可）”と“ユーザ検索”を別レイヤに置く（設計例）
POST /<index>/_search
{
  "query": {
    "bool": {
      "filter": [
        { "term": { "tenant_id": "<currentTenant>" } }
      ],
      "must": [
        { "match": { "message": "<userKeyword>" } }
      ]
    }
  }
}
~~~~
- この例で観測していること：
  - tenant_id が filter（固定条件）で強制され、ユーザ入力は must（検索）に閉じている
- 出力のどこを見るか（注目点）：
  - 件数（hits.total）、結果の変化が“tenant切替に連動しているか”
- この例が使えないケース（前提が崩れるケース）：
  - tenant分離が index/alias 単位で行われている場合（filterではなくindex選択が境界）

~~~~
# 例：script を“入力で自由に書かせない”前提で、サーバが固定の stored script を呼ぶ（設計例）
# ※具体のスクリプト内容ではなく、入力→実行の境界を閉じる発想だけを示す
{
  "query": {
    "script": {
      "script": {
        "id": "fixed_scoring_rule_v1",
        "params": { "p1": "<validatedParam>" }
      }
    }
  }
}
~~~~
- この例で観測していること：
  - scriptの“本文”を入力にしない（入力はparamsのみ、かつ型拘束）
- 出力のどこを見るか（注目点）：
  - 失敗時のエラーが統一されるか（oracle化しないか）
- この例が使えないケース：
  - そもそも script が不要な検索（原則は使わない方が安全・運用も簡単）

## 参考（必要最小限）
- Elastic Docs：Query DSL（全体）  
  - https://www.elastic.co/docs/explore-analyze/query-filter/languages/querydsl
- Elastic Docs：bool query（must/should/filter/must_not と filter context）  
  - https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-bool-query
- Elastic Docs：Scripting and security（script.allowed_types 等）  
  - https://www.elastic.co/docs/explore-analyze/scripting/modules-scripting-security
- Elastic Docs：search.allow_expensive_queries（高コスト検索の抑制に関わる）  
  - https://www.elastic.co/docs/reference/elasticsearch/configuration-reference/search-settings
- Elastic Docs：Runtime fields（expensive query扱いの例）  
  - https://www.elastic.co/docs/manage-data/data-store/mapping/runtime-fields

## リポジトリ内リンク（最大3つまで）
- 関連 topics：
  - `01_topics/02_web/05_input_04_nosql_injection_02_elasticsearch_01_query_string（lucene_querystring）.md`
  - `01_topics/02_web/03_authz_00_認可（IDOR BOLA BFLA）境界モデル化.md`
- 関連 playbooks：
  - `02_playbooks/05_api_権限伝播→検証観点チェック.md`

---

## 次（作成候補順）
- `01_topics/02_web/05_input_04_nosql_injection_02_elasticsearch_03_painless（script_injection）.md`
