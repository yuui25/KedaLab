## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）

- ASVS
  - 入力→実行境界：ユーザ入力が **スクリプト本文（code）** として評価される経路が存在しないか（最優先で排除）
  - 設計：スクリプトが必要な場合でも、入力は **パラメータ（data）** のみに閉じ、本文は固定（stored script/固定テンプレ）にする
  - 可用性：スクリプトは高コスト化しやすく、DoS境界（timeout/expensive query制限/レート制限）と一体で評価する
  - 例外/エラー：コンパイルエラー・ランタイムエラー・セキュリティ例外を外部へ詳細に返さない（oracle化防止）
  - 監査：script使用（inline/stored）、拒否理由、異常頻度を trace_id で相関し検知できるか
- WSTG
  - Injection testing の中でも「コード評価」系（SQLiの動的SQLより危険側）
  - エラー差分（compile/runtime）とBoolean差分（件数/長さ/並び順）を、低侵襲に再現できる形で証拠化する
- PTES
  - Vulnerability Analysis：入口（sort/score/script/runtime field）→生成点→入力がscript本文に入る条件を同定
  - Exploitation：影響実証は最小限（成立根拠の確定まで）。高負荷検証・大量抽出は避ける
  - Reporting：根本原因を「inline script採用」「本文組立」「stored script不使用」「設定不備」「監査不足」に分解して提示
- MITRE ATT&CK
  - TA0001 Initial Access / TA0009 Collection / TA0005 Defense Evasion（エラー統一下でブラインド化）
  - 入口：T1190（公開アプリ）での入力→実行境界破壊として位置づける

---

## タイトル
NoSQL Injection（Elasticsearch）：Painless script_injection（入力→コード評価境界）

## 目的（この技術で到達する状態）
- Elasticsearch の Painless スクリプト（script query / script_score / runtime fields 等）について、
  1) スクリプトが使われる入口（UI/API）と生成点（サーバ側の組立）を特定できる  
  2) 入力が “パラメータ（data）” ではなく “本文（code）” に入っているかを、差分観測で確定できる  
  3) 影響を「認可境界」「情報露出（エラーモデル）」「可用性（高コスト）」に分解して評価できる  
  4) 修正を「サニタイズ」ではなく **stored script化 + allowlist + 高コスト制限** に落とせる  
  状態になる。

## 前提（対象・範囲・想定）
- 対象
  - 管理画面の詳細検索、監査ログ検索、分析ダッシュボード、ランキング/スコアリング、柔軟な並び替え、計算フィールド
  - “条件式” “計算式” “カスタム式” “スクリプト” の文言がUIやAPIに存在する箇所
- 想定アーキテクチャ
  - アプリ（API）→ ES（_search）  
  - ES側で inline script を許可/不許可にできる（運用要件で揺れがち）
- 本ファイルの焦点
  - Painless の **script_injection（本文の注入）** を、入力→実行境界としてモデル化する
- 非スコープ（別ファイル）
  - Query DSL（bool/filter）全体：前ファイル
  - mustache template / stored search template：別ファイル（template）で扱う

## 概念整理：Painlessは「機能」だが、境界としては“コード実行”
- Painless は ES のスクリプト言語で、以下で利用される
  - script query（条件をコードで判定）
  - script_score（スコア計算をコードで実行）
  - runtime fields（検索時にフィールドを計算）
  - aggregation 内の script 等
- セキュリティ上の境界
  - 入力が「値」なら data
  - 入力が「スクリプト本文」なら code（＝入力→実行境界が開いている）
- 結論
  - “スクリプトを使う”こと自体が直ちに脆弱性ではない  
  - しかし **本文が入力由来** になった瞬間、Injectionとして扱う（最優先で潰す）

## 観測ポイント（入力→生成→実行→反応）

### 1) 入口（input surface）の同定：どこでscriptに触れられるか
- 典型入口（優先度高）
  - `sort=` の高度指定（カスタム順）
  - `score=` / `rank=` / `boost=` のようなパラメータ（スコアリング）
  - `fields=` / `computed=` / `runtime=` のような計算フィールド指定
  - advanced search で “式” を受け取る（文字列）
  - saved search / report definition（保存した条件が後で実行＝second-order）
- 入口同定の判断
  - UI上に式がなくても、APIに hidden/advanced なパラメータがあることがある  
    → Burp等で“未使用パラメータ”の有無を確認し、サーバで受理されるかを差分で見る

### 2) 生成点（sink）の分類：本文固定か、本文組立か
- 安全側（望ましい）
  - 本文：固定（stored script / 固定テンプレ）  
  - 入力：paramsのみ（型拘束・上限あり）
- 危険側（脆弱になりやすい）
  - 本文：入力文字列を連結/テンプレ埋め込み/条件分岐で生成
  - “式”のつもりが、実際にはコード断片として本文に混ざる
- 黒箱での推定
  - エラーの粒度（compile/runtime）が入力に依存して揺れる  
  - 入力文字列の形で「コンパイル失敗/実行失敗/成功」の切替が起きる  
  → これが再現するなら、本文が入力に影響されている疑いが強い（ただし断定は避け、観測根拠を積む）

### 3) oracle（差分指標）を固定する：安全に“成立根拠”を取る
- Boolean oracle（主証拠）
  - 件数、レスポンス長、並び順の変化（ランキング/ソートが絡む場合）、特定ドキュメントの出現
- Error oracle（補助）
  - compile error / runtime error の差分（ただし外部へ詳細を返す時点で情報漏えいの問題も同時に指摘）
- Time oracle（補助、DoS配慮）
  - scriptは計算量で遅延が出やすいが、負荷試験に近づく  
    → “制約欠如（timeout/expensive query制限不在）”として評価し、長い遅延検証は避ける

## 影響の分解（実務報告でブレないための枠）

### 影響1：入力→実行（コード評価）境界の破壊
- 本文が入力由来なら、Injectionとして重大
- ただし “RCE” を短絡的に言わない  
  - ES/Painlessはサンドボックス/設定/バージョンで変わる  
  - 本ファイルでは「入力がコードとして評価される」という境界破壊を確定し、設計として潰す方針に落とす

### 影響2：認可境界（tenant/org/owner）との衝突
- scriptは条件判定に使えるため、固定の認可filterと同居すると設計が複雑化する
- あるべき設計
  - 認可条件は bool.filter 等で常に強制し、scriptは“補助”に閉じる  
  - scriptで認可を実装しない（レビュー不能・監査困難）

### 影響3：情報露出（エラーと実装の露出）
- compile/runtimeエラーが外部へ詳細に出ると
  - フィールド名、型、スクリプト断片、内部構造、index名等が漏れることがある
- これは “script_injectionの発見” とは別に、error model不備として報告できる

### 影響4：可用性（高コスト評価・expensive query）
- scriptは高コストになりやすい
- 評価の姿勢（PTES）
  - 実際に負荷をかけるより、制約の欠如（timeout/上限/設定）を設計問題として提示する

## 成立しやすい根本原因（実装パターン→原因へ落とす）

### 原因A：ユーザ入力を “式” として受け、本文に埋め込む（inline script組立）
- 症状
  - 入力が少し変わるだけで compile/runtime エラーが揺れる
- 修正
  - “式”を廃止し、選択式（allowlist）＋ params のみにする
  - どうしても式が必要なら、サーバ側DSLに落として生成（スクリプト本文を入力にしない）

### 原因B：stored script を使わず、inline script を採用している
- 症状
  - 本文がリクエストごとに送られる（入力の影響が入りやすい）
- 修正
  - 本文は stored script（id参照）に固定、入力は params のみ
  - バージョン管理（idにv1/v2）を導入し、移行を安全に行う

### 原因C：高コスト制限・監査が不十分（運用設計不備）
- 症状
  - scriptを含む検索が無制限に実行できる
- 修正
  - クエリ上限（長さ/頻度）、timeout、expensive query制御、rate limit、監査ログ相関

### 原因D：認可条件の適用がscript側に寄っている（設計アンチパターン）
- 症状
  - tenant分離やアクセス制御がscriptに依存している
- 修正
  - 認可は filter レイヤで固定、scriptは補助に限定（可能なら撤去）

## 次に試すこと（仮説A/B/C：低侵襲で確定）

### 仮説A：スクリプト本文が入力に影響されている（script_injection）
- 条件（観測）
  - 入力の形で compile/runtime エラー差分、または並び順/件数の差分が再現性を持って出る
- 次の一手
  - 入口（どのパラメータ/モードでscriptがONになるか）を確定
  - “paramsだけの入力”として扱われているか、“本文に混ざっている”かを、エラー形状と結果差分で切り分ける
  - 影響実証は最小限（成立根拠の確定まで）に留める

### 仮説B：スクリプトは使われるが、本文は固定でparamsのみ（設計として許容される可能性）
- 条件（観測）
  - 入力を変えてもエラー差分が出ず、パラメータとしてのみ反映される挙動
- 次の一手
  - params の型拘束・上限・allowlist（どのパラメータが許可されるか）を確認
  - DoS境界（timeout/頻度制限）の有無を確認し、設計を補強する観点で報告する

### 仮説C：scriptは拒否されている（設定で抑止）
- 条件（観測）
  - script関連が一貫して拒否される（ただしエラー詳細が漏れる場合は別問題）
- 次の一手
  - “拒否されること”を肯定材料にしつつ、拒否エラーがoracleになっていないか（情報漏えい）を確認
  - アプリ側でそもそも入口を持たない設計へ寄せる提案を行う

## 防御設計（修正を“実装＋運用”へ落とす）

### 1) 本文固定（stored script）＋ paramsのみ（最優先）
- 本文はES側に保存し、アプリは script id を指定するだけにする
- 入力は params として渡し、型拘束（number/string/bool）と上限（範囲/長さ）を設ける

### 2) 入口を選択式（allowlist）にする
- UI/APIで「式を自由入力」させない
- 例：並び替えは “createdAt/score/name” のような選択肢、計算フィールドは固定メニュー化

### 3) 認可条件は filter レイヤで固定
- tenant/org/owner は bool.filter 等で常に適用
- scriptで認可を表現しない（レビュー不能・テスト困難）

### 4) 高コスト制限（DoS境界）
- timeout、結果上限、rate limit、expensive query制御（設定/運用）
- 監査：script使用の頻度、拒否、遅延（took/slowlog）を相関しアラート

### 5) エラーモデル統一（oracle化防止）
- compile/runtimeエラーを外部へ詳細に返さない
- 外部：統一エラー（400/422など）＋trace_id
- 内部ログ：詳細（ただし機微はマスク）、原因分類、ユーザ/リクエスト相関

## 手を動かす検証（Labs連動：安全に“境界”を再現）
- 目的：scriptが “paramsのみ” か “本文に混ざる” かを、同じAPIで比較できるようにする
- 最小構成（推奨）
  - (1) 安全：stored script + paramsのみ + 認可filter強制
  - (2) 危険：inline script本文を文字列連結で生成（悪い例として比較）
  - (3) 運用境界：expensive query制限あり/なし、timeoutあり/なし（差分）
- 証跡
  - HAR：baseline / 差分（並び順/件数） / 差分（エラー）
  - サーバログ：trace_id、スクリプト利用の有無（id/inline）、params（マスク）、実行時間
  - ES側（Labsのみ）：slowlog、scriptの拒否/許可、took、拒否理由

## コマンド/リクエスト例（例示は最小限：発想の固定）
> 具体の悪用payloadは示さない。設計の違い（本文固定 vs 本文入力）だけを示す。

~~~~
# 安全設計例：本文は stored script（id参照）、入力は params のみ
{
  "query": {
    "script_score": {
      "query": { "match_all": {} },
      "script": {
        "id": "fixed_score_v1",
        "params": { "p1": "<validated_number>" }
      }
    }
  }
}
~~~~
- 観測していること：
  - 本文が固定で、入力はparams（data）に閉じる
- どこを見るか：
  - エラーが統一されているか、paramsの型逸脱が400で落ちるか、tookが上限内か

~~~~
# 危険設計の説明（例示は概念のみ）
# 「ユーザ入力を script.source に連結する」実装は、入力→実行境界が開くため禁止
~~~~

## 参考（必要最小限）
- Elastic Docs：Scripting and security（許可/制限の考え方）  
  - https://www.elastic.co/docs/explore-analyze/scripting/modules-scripting-security
- Elastic Docs：script query / script_score（利用箇所の理解）  
  - https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-script-query
  - https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-script-score-query
- Elastic Docs：search settings（expensive query制御など）  
  - https://www.elastic.co/docs/reference/elasticsearch/configuration-reference/search-settings
- Elastic Docs：Slow log（高コスト検知）  
  - https://www.elastic.co/docs/reference/elasticsearch/index-settings/slow-log

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/05_input_04_nosql_injection_02_elasticsearch_02_dsl（bool_filter_script）.md`
- `01_topics/02_web/03_authz_00_認可（IDOR BOLA BFLA）境界モデル化.md`
- `01_topics/02_web/04_api_09_error_model_情報漏えい（例外_スタック）.md`

---

## 次（作成候補順）
- `01_topics/02_web/05_input_04_nosql_injection_02_elasticsearch_04_template（mustache_stored_template）.md`
