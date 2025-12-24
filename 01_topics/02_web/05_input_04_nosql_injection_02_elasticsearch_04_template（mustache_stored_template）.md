## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）

- ASVS
  - 入力→実行境界：ユーザ入力が「検索パラメータ」ではなく **テンプレ（Mustache）展開後のQuery DSL構造** に影響しない設計か
  - 設計：テンプレ（stored search template）を使う場合でも、入力は **params（data）** に限定し、テンプレ本文（code）に混ぜない
  - 認可境界：tenant/org/owner の固定条件をテンプレ内で“入力と同列に合成”していないか（上書き・揺らぎ・適用範囲漏れ）
  - 例外/エラー：テンプレ展開エラー・パースエラーを外部へ詳細に返さない（oracle化防止）
  - 可用性：テンプレが“表現力”を持つため、複雑度（条件分岐/配列展開）と検索の高コスト要素（wildcard/script/runtime等）を制限する
  - 監査：template id / params 形状 / 実行時間 / ヒット数 を相関し、探索・濫用を検知できるか
- WSTG
  - Injection：テンプレ展開は「入力→実行計画生成」の代表例（SQLiの動的SQL生成に近い）
  - テスト方針：エラーより **Boolean oracle（件数/長さ/フィールド出現）** と **“テンプレ分岐の差分”** で成立根拠を取る
  - Second-order：保存検索/共有検索条件で “保存時は無害、実行時に展開される” を重視
- PTES
  - Vulnerability Analysis：入口（search/report/saved view）→ テンプレ利用（_search/template or stored script）→ params の受理範囲 → 認可条件の適用位置 を特定
  - Exploitation：影響実証は最小限（越境混入や情報露出の根拠まで）。高負荷・大量抽出は避ける
  - Reporting：根本原因を「テンプレ本文の設計」「paramsの型拘束不足」「認可条件の混在」「監査不足」「高コスト制限不在」に分解して提示
- MITRE ATT&CK
  - TA0001 Initial Access（公開アプリ入口）/ TA0009 Collection（検索で横断収集）/ TA0005 Defense Evasion（エラー統一下でブラインド化）
  - 代表：T1190 Exploit Public-Facing Application（検索入力→実行計画生成の悪用）

---

## タイトル
NoSQL Injection（Elasticsearch）：Mustache / stored template（_search/template）入力→実行境界

## 目的（この技術で到達する状態）
- Elasticsearch の Search Template（Mustache、stored template）を「便利機能」ではなく **入力→実行境界（テンプレ展開→Query DSL生成）** として扱い、
  1) テンプレが使われている入口（UI/API）を同定できる  
  2) 入力が params（data）に閉じているか、テンプレ本文（code）に混入しているかを、差分観測で確定できる  
  3) 認可境界（tenant/org/owner）をテンプレ内で安全に固定できているかを検証できる  
  4) second-order（保存検索/共有検索条件）まで含めて、設計・運用の修正案を提示できる  
  状態になる。

## 前提（対象・範囲・想定）
- 対象
  - 検索窓（サイト内検索）、監査ログ検索、管理UIの詳細検索、レポート/エクスポート、保存検索（saved search）、共有フィルタ
  - “テンプレ/クエリ定義/検索条件テンプレ” 等の文言がある機能
- 想定アーキテクチャ
  - アプリ（API）→ ES（_search または _search/template）
  - テンプレは
    - アプリ内（サーバ側文字列テンプレ）で展開してESへ送る、または
    - ESの stored template（_scripts）として保持し、id参照で呼ぶ
- 本ファイルの焦点
  - Mustache（テンプレ）＋ params の境界、stored template の運用とsecond-orderの危険性
- 非スコープ（別ファイル）
  - query_string（Lucene Query String）
  - DSL（bool/filter/script）全般
  - painless（script本文注入）

## 概念整理：Search Template は “サーバで動く動的クエリ生成”
- “入力が文字列として安全” であっても、テンプレが
  - 条件分岐（if）
  - 配列展開（terms相当の組立）
  - 部分テンプレ（include的な再利用）
  を持つと、結果として **Query DSLの構造** が入力で変わり得る
- セキュリティ上の論点は2つに分かれる
  - 論点A（code vs data）：入力がテンプレ本文（code）へ混ざるか
  - 論点B（構造生成）：入力が分岐/展開を通じて Query DSL の形（must/filter/should等）を変えるか
- 結論（実務）
  - “テンプレを使うこと”自体は直ちに脆弱性ではない  
  - しかし **paramsの設計と認可条件の固定方法** を誤ると、越境混入や探索容易化、second-orderの温床になる

## 境界モデル（入力→テンプレ→DSL→認可→結果）

### 1) 入口（input surface）：テンプレが効いている場所を特定する
- 典型入口（優先度高）
  - 保存検索（saved view / saved filter）：保存時に params を格納し、実行時にテンプレに流す
  - レポート/エクスポート：UIで条件を作り、テンプレでDSL化して実行
  - 管理画面の詳細検索：項目選択・複数条件・期間指定など、テンプレ化されやすい
- 入口確定の観測
  - “同じ検索でも”実行時にサーバ側で構造が変わる（例：入力が空なら条件を省く等）
  - 実行ログ（アプリログ/監査ログ）に template id が出る場合がある（出るならそれ自体は情報露出にもなるので扱い注意）

### 2) テンプレ実行点（sink）の2系統：アプリ内テンプレ vs ES stored template
- 系統A：アプリ内テンプレ（サーバ側でMustache等を展開し、ESへ _search）
  - メリット：ES側機能に依存しない
  - リスク：テンプレ本文がアプリコードにあり、入力混入（連結/部分テンプレ）を起こしやすい
- 系統B：ES stored template（_search/template、_scripts に保存）
  - メリット：テンプレ本文を固定化しやすい（id参照）
  - リスク：テンプレの更新・権限管理が運用課題。second-orderで “古いテンプレ” が残ることがある

### 3) 認可境界（tenant/org/owner）との結合点：テンプレ内に混ぜると事故る
- アンチパターン
  - tenant条件を “入力と同じレイヤ” の must/should に混ぜ、分岐で省略される/上書きされる余地がある
  - tenant条件を params として受け取り、クライアント入力に依存させる
- 望ましい設計
  - tenant/org/owner は **常に固定で付与**（bool.filter 等）
  - テンプレ分岐で “消えない” 場所に置く（テンプレの分岐対象にしない）
  - 可能ならテンプレ外（アプリ共通部品）で強制し、テンプレは“検索条件の補助”に限定

## oracle（成立根拠）の取り方：テンプレは“エラーより差分”
- Boolean oracle（主）
  - 件数、レスポンス長、ページ数、集計値の有無、特定フィールド出現（source filteringの有無）
- Error oracle（補助）
  - テンプレ展開エラー、パースエラーが返る場合
  - ただし外部へ詳細を返す時点で error model不備（情報露出）として独立に指摘する
- Time oracle（補助、DoS配慮）
  - 分岐や展開でクエリが肥大化して遅くなることがある  
  - しかし負荷試験に近づくため、長い遅延検証は避け、「上限制約の欠如」を設計問題として提示する

## 典型的なリスクシナリオ（差分＝成立根拠として扱う枠）

### シナリオ1：params が “data” ではなく “code（テンプレ本文/断片）” に混ざる
- 起き方（原因）
  - テンプレ本文に入力を連結している
  - 部分テンプレや文字列生成で、入力が構文要素に影響する
- 観測で言えること（成立根拠）
  - 入力の形で “テンプレ展開エラー/パースエラー” が再現性を持って揺れる
  - あるいは、入力の記号により結果構造が不自然に変化する
- 重要
  - Mustache自体は“ロジックレス”でも、テンプレ内にJSON構文がある以上、**入力が構文に混ざれば壊れる**
- 修正の方向
  - テンプレ本文は固定、入力は params のみ（型拘束）  
  - “文字列としてのエスケープ”ではなく、そもそも構文要素に混ぜない

### シナリオ2：分岐・配列展開で Query DSL の形が入力で変わる（構造生成リスク）
- 起き方（原因）
  - 入力が空なら $match を省く、複数条件なら should を増やす、など
  - “柔軟性”が仕様として増えすぎ、実質的にクエリ設計をユーザへ委譲している
- 観測で言えること
  - 入力の有無/配列長/モードで、件数・集計・ネストが安定して変化する
- 修正の方向
  - 受理する条件の種類・数・配列長を制限（上限、allowlist）
  - 生成されるDSLの形を固定テンプレで制約（must/should/filterの位置を固定）

### シナリオ3：second-order（保存検索/共有条件）で“実行時”に境界が開く
- 起き方（原因）
  - 保存時のバリデーションが浅い、またはテンプレ変更後に古いデータが想定外の分岐へ入る
  - “共有検索条件”が他ユーザ/他テナントに配布される（越境の拡散点）
- 観測で言えること
  - 直接の検索リクエストではなく「保存→実行」の経路でのみ差分が出る（これ自体が second-order の根拠）
- 修正の方向
  - 保存時・実行時の二重バリデーション（同じスキーマで）
  - テンプレのバージョニング（idにv1/v2）と、保存データに template_version を持たせる
  - 共有条件は tenant境界を越えない設計（owner/tenantの付与と強制）

### シナリオ4：認可条件の混在（tenant filterがテンプレ分岐で消える/揺れる）
- 起き方（原因）
  - tenant条件をテンプレ内の if 条件に入れている
  - tenant条件を params として受けている
- 観測で言えること
  - tenant切替・権限切替で“変わるべき範囲以上”に検索面積が揺れる（越境混入リスク）
- 修正の方向
  - tenant/org/owner はテンプレ外（共通部品）で強制、またはテンプレ内でも分岐させない固定位置へ

## 次に試すこと（仮説A/B/C：安全に確定）

### 仮説A：テンプレ本文（code）に入力が混入している（最重）
- 条件（観測）
  - 入力の記号や形で展開/パースエラーが揺れる、または結果構造が不自然に変化する
- 次の一手
  - 入口（どのパラメータ/保存項目）がテンプレに流れるかを確定
  - “paramsとしての反映”か“本文への混入”かを、差分（エラー形状・結果差分）の再現性で切り分け
  - レポートでは「本文混入の設計」が根本原因であり、エスケープでの対処にしない

### 仮説B：入力はparamsのみだが、分岐/展開でDSL構造が過剰に変わる（設計過多）
- 条件（観測）
  - 入力の有無/配列長/モードで、must/should/filter相当の結果が広がりすぎる
- 次の一手
  - “許可する柔軟性”を仕様として明確化し、上限（条件数・配列長・文字数）とallowlistを設計へ落とす
  - 監査ログで “高コスト傾向” を検知できるか（took/slowlog/ヒット数）を確認

### 仮説C：second-order（保存→実行）にだけ問題がある
- 条件（観測）
  - 直接検索では問題が出ず、保存済み条件を実行したときだけ差分が出る
- 次の一手
  - 保存時バリデーションと実行時バリデーションの差分（実装分岐）を原因として切り出す
  - テンプレ変更（バージョン差分）との組み合わせを疑い、template_version管理を修正案に含める

## 防御設計（修正を“設計＋運用”へ落とす）

### 1) code と data を分離（最優先）
- テンプレ本文（code）は固定（stored template / アプリ内固定テンプレ）
- 入力は params（data）のみ。params は
  - 型拘束（string/number/bool/array of string 等）
  - 上限（文字数、配列長、ネスト深さ）
  - allowlist（許可フィールド、許可演算子、許可ソートキー）
  を必須とする

### 2) 認可条件（tenant/org/owner）は“テンプレ分岐”にしない
- tenant条件は常に bool.filter 等で強制（テンプレ内でも固定位置、できればテンプレ外で共通付与）
- tenant値はクライアント入力から受けない（サーバで決定）
- 返却フィールドも縮退（source filtering / view model）

### 3) second-order対策（保存検索/共有条件）
- 保存時と実行時で同じスキーマ検証を適用（実行時の再検証を省略しない）
- テンプレのバージョニング（id: search_v1 / search_v2）
- 保存データに template_version を持ち、互換性を破る変更時は移行/拒否を明示
- 共有条件は owner/tenant を必ず持ち、共有範囲（同一tenant内等）を強制

### 4) DoS境界（複雑度・高コスト要素の制限）
- 入力上限（クエリ長、条件数、terms数、期間幅）
- 検索上限（timeout、結果上限、rate limit）
- 高コスト要素（wildcard/script/runtime等）をテンプレ内で固定し、入力でON/OFFさせない
- 監査：template id、実行時間、ヒット数、拒否理由を相関し検知

### 5) エラーモデル統一（oracle化防止）
- 外部：統一エラー（400/422など）＋ trace_id のみ
- 内部：テンプレ展開エラー、パースエラー、検証エラーを分類し、原因特定できるログ（ただし入力はマスク）

## 手を動かす検証（Labs連動：テンプレ境界を再現）
- 目的：テンプレを使う検索を、(1)安全設計 と (2)危険設計 で比較し、差分観測で成立根拠を取れるようにする
- 最小構成（推奨）
  - (1) 安全：stored template（本文固定）＋ params型拘束＋ tenant filter固定
  - (2) 危険：テンプレ本文に入力を連結（悪い例）
  - (3) second-order：保存検索（保存→実行）で同じ検証を当て、保存時のみ検証する悪い例を比較
  - (4) 運用境界：テンプレv1→v2変更と、保存データのtemplate_version未管理の悪い例
- 証跡
  - HAR：baseline / 差分（件数/長さ） / 差分（エラー）
  - サーバログ：trace_id、template id/version、params形状（型・配列長のみ）、検証結果、実行時間
  - ES側（Labsのみ）：slowlog、拒否/許可、took、テンプレ呼び出し痕跡

## 例（最小限：設計の違いを固定する）
~~~~
# 安全：stored template（id参照）＋ params（data）のみ
POST /<index>/_search/template
{
  "id": "search_v1",
  "params": {
    "keyword": "<validated_string>",
    "filters": ["<allowed_field_1>", "<allowed_field_2>"],
    "size": 50
  }
}
~~~~
- 観測していること：
  - 本文（code）が固定で、入力はparams（data）に閉じる
  - paramsの型逸脱が400で落ちるか（型拘束）
  - tenant条件が“入力に依存せず”常に適用されるか（認可境界）

~~~~
# 危険（概念）：テンプレ本文（JSON構文）にユーザ入力を連結する設計は、code/data境界が壊れるため禁止
# ※悪用payloadは提示しない
~~~~

## 参考（必要最小限）
- Elastic Docs：Search templates（Mustache / _search/template）  
  - https://www.elastic.co/guide/en/elasticsearch/reference/current/search-template.html
- Elastic Docs：Stored scripts（_scripts）  
  - https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-scripting-using.html
- Elastic Docs：Query DSL bool（filterの位置づけ確認）  
  - https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-bool-query
- Elastic Docs：Search settings（timeout / expensive query 等）  
  - https://www.elastic.co/docs/reference/elasticsearch/configuration-reference/search-settings

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/05_input_04_nosql_injection_02_elasticsearch_02_dsl（bool_filter_script）.md`
- `01_topics/02_web/03_authz_00_認可（IDOR BOLA BFLA）境界モデル化.md`
- `01_topics/02_web/04_api_03_rest_filters_検索・ソート・ページング境界.md`

---

## 次（作成候補順）
- `01_topics/02_web/05_input_04_nosql_injection_03_neo4j_cypher_01_query（cypher_injection）.md`
