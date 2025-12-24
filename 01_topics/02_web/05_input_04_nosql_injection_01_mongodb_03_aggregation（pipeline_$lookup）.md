## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）

- ASVS
  - 入力→実行境界：ユーザ入力が「集約パイプライン（aggregation pipeline）」の **ステージ構造** を形成できていないか（SQLiの“動的SQL”相当）
  - 認可境界：tenant/org/owner 条件が `$match` 以外の経路（$lookup / $facet / $unionWith 等）で迂回されない設計になっているか
  - 型・語彙制約：フィールド名、演算子、ステージ種別を allowlist で拘束できているか（ブラックリスト依存は崩れる）
  - DoS境界：$lookup / $group / $sort / $facet / allowDiskUse による計算量増大を、上限（limit/timeout/maxTimeMS）と設計で抑えられているか
  - 監査：危険ステージ（$lookup/$function/$where相当/正規表現/広範囲$match）の出現をログ相関で検知できるか
- WSTG
  - Injection testing として、SQLi同様に「入力点→sink（パイプライン生成点）→差分観測→成立根拠」を取る
  - エラー誘発より、**Boolean oracle（件数/長さ）** と **構造差分** を主証拠にする（Mongoは“構文エラー”が表に出ないことが多い）
- PTES
  - Vulnerability Analysis：filter/aggregate/advanced search の入口を同定→パイプライン生成点（直渡し/マージ/テンプレ）を特定→$lookup を“成立根拠”として境界破壊を確定
  - Exploitation：影響実証は必要最小限（越境混入/他コレクション参照の成立を示す。高負荷や大量抽出は避ける）
  - Reporting：根本原因を「パイプライン直受け」「ステージallowlist不在」「権限条件の付与位置誤り」「計算量制限不在」に分解して提示
- MITRE ATT&CK
  - TA0001 Initial Access（公開アプリ入口）/ TA0009 Collection（集約で横断収集）/ TA0005 Defense Evasion（エラー統一下でブラインド化）
  - 代表：T1190 Exploit Public-Facing Application（NoSQLiも入口）

# NoSQL Injection（MongoDB）：aggregation（pipeline_$lookup）

## 目的（この技術で到達する状態）
- MongoDB の aggregation pipeline を「入力→実行境界」の中でも **動的クエリ生成（SQLiの動的SQL相当）** として整理し、
  1) パイプライン（ステージ配列）を入力が形成できる入口（成立条件）を特定できる  
  2) `$lookup`（他コレクション結合）を使って **“権限条件の適用範囲”が崩れる** 典型を、差分観測で確定できる  
  3) 影響を「越境混入（BOLA/BFLA接続）」と「DoS（計算量境界）」に分解し、過剰に煽らず実務的に評価できる  
  4) 修正を “入力禁止” ではなく、**安全DSL→サーバ側でパイプライン生成** と **ステージallowlist/上限設計** に落とせる  
  状態になる。

## 前提（対象・範囲・想定）
- 対象
  - 検索・一覧・分析（ダッシュボード）・レポート・エクスポート・監査ログ閲覧等で aggregation を用いるWeb/API
  - “柔軟検索” “集計” “絞り込み + join” がある機能（UI都合で pipeline を使いがち）
- 成立しやすい設計
  - `pipeline`（配列JSON）をクライアントから受け、サーバでほぼそのまま `aggregate()` に渡している
  - “汎用フィルタ”として JSON を受け、既定条件と **deep merge** している（ステージ混入）
  - GraphQL/REST で “fields/expand/include” を受け、裏で `$lookup` を組立している（識別子・参照先が入力由来）
- 本ファイルの焦点
  - `$lookup` を中心に、**他コレクション参照（横断）** と **権限条件の適用漏れ** を境界として扱う
- 非スコープ（ただし関連として言及する）
  - `$where`（JS評価）は別ファイル
  - BSON型混乱は別ファイル

## 概念整理：aggregation pipeline は “クエリ” ではなく “実行計画” に近い
- find（通常クエリ）
  - 条件（$match相当）と投影（projection）が中心
- aggregation pipeline
  - ステージ（$match/$project/$group/$sort/$facet/$lookup/...）の **配列** で処理を定義する
  - したがって、入力が pipeline 構造を作れると「条件だけでなく処理自体」を組み替えられる
- セキュリティ上の帰結
  - “値のエスケープ”では防げない
  - 防御は **ステージの許可集合（allowlist）** と **サーバ側生成（入力を構造にしない）** が本体

## 観測ポイント（入力→パイプライン→実行→反応）

### 1) 最重要の境界：入力が「配列（pipeline）」として解釈されているか
- 典型入口
  - body JSON（application/json）
  - `pipeline=` の JSON 文字列（query string）
  - advanced filter / report definition などの“定義”を保存して実行
- 観測の狙い
  - 同一エンドポイントで「入力の形」だけ変えて、結果（件数/長さ/構造）が変わるかを取る
- 判断（次の一手）
  - pipeline を受理する入口が確定したら、以後はその入口に固定して横展開（似たエンドポイントを洗う）

### 2) `$lookup` を“成立根拠”として使う（なぜ$lookupが強いか）
- `$lookup` は **別コレクションのデータを結合**するステージ
- 実務で起きる問題の型
  - 型A：参照先（from）が入力に影響される（コレクション横断の境界破壊）
  - 型B：結合条件（localField/foreignField または pipeline）が入力に影響される（意図しない関連付け）
  - 型C：権限条件（tenant/owner）を主コレクションにしか付けていない（結合先が無防備）
- 重要
  - “他人データが見える”の断定ではなく、**権限条件が適用される範囲が崩れる設計** を証拠化する

### 3) oracle（差分指標）を固定する：Mongoはエラーより結果差分
- Boolean oracle（主証拠）
  - 件数、レスポンス長、配列要素数、ページ数、特定フィールドの出現（join結果の有無）
- Error oracle（補助）
  - 無効なステージ、型不一致、フィールド未存在など（ただし本来はエラー統一されるべき）
- Time oracle（補助、DoS配慮）
  - $lookup / $group / $sort は負荷差分が出るが、性能試験に近づく  
    → 短時間・少回数・上限確認（maxTimeMS等）を中心に、過度な遅延検証は避ける

### 4) 認可境界（tenant/org/owner）との結合点：$lookupで“境界が二重になる”
- よくある設計
  - 主コレクション：`tenant_id = currentTenant` を必ず $match する
  - 参照先コレクション：同じく tenant_id がある（または owner_id がある）
- 典型的な落とし穴
  - 主コレクション側の $match は堅いが、$lookup で結合した参照先に **tenant条件が付かない**
  - あるいは参照先が “共有マスタ” 扱いで、想定以上の情報が混ざる
- 観測の要点（実務）
  - “joinした配列の中身”が増減する差分を、tenant切替や対象ユーザ切替など **正当な境界変化** に合わせて観測し、設計上の漏れを示す

## 成立しやすい根本原因（実装パターンを原因へ落とす）

### 原因1：pipeline直受け（クライアント定義をそのまま実行）
- 典型：分析/レポート/検索保存で「定義をJSONで持つ」設計
- 問題
  - 入力が“処理”を定義できる（SQLiの動的SQLと同じ）
- 防御設計
  - クライアントは “意図（指示）” だけ送る（例：groupBy=status, period=day）
  - サーバ側で固定テンプレから pipeline を生成する（ステージを入力にさせない）

### 原因2：ステージallowlist不在（危険ステージが混ざる）
- `$lookup` 自体が危険というより、「何が許されるか」が不明確で混入できる点が問題
- 防御設計
  - 受理するステージ（例：$match/$project/$sort/$limit など）を明示
  - $lookup を許すなら、参照先コレクションと結合キーを固定（入力で変えない）

### 原因3：権限条件の付与位置が誤っている（適用範囲が狭い）
- 例
  - 主コレクションのみに tenant $match
  - 参照先は $lookup で無条件結合
- 防御設計
  - 主・参照先の両方に “権限条件” を適用する（設計として）
  - 参照先が共有マスタなら「混ぜてよい最小情報」を投影（$project）で縮退

### 原因4：計算量境界が未定義（DoS・コスト増大が起きる）
- $lookup は cardinality が増えると急に重くなる
- 防御設計
  - limit/skipの上限、索引設計、maxTimeMS、allowDiskUseの取り扱い、結果サイズ上限
  - “ユーザ入力でパイプラインが肥大化しない”よう、DSLで表現力を制限

## 結果の意味（何が言える/言えない）

### 言える（確定できる）
- 入力が pipeline 構造（ステージ配列）として解釈され、クエリ/処理の境界が破れている可能性が高い
- `$lookup` により参照先コレクションが処理に組み込まれ、権限条件の適用範囲が設計上複雑化している
- oracle（件数/長さ/フィールド出現/時間）として何が再現性のある根拠か
- 根本原因の候補（直受け・allowlist不在・付与位置誤り・上限不在）を、観測から説明できる

### 断定しない（追加根拠が必要）
- “参照先の機微データが漏れる”の断定（投影/マスキング/権限で変わる）
- “DoSが可能”の断定（性能試験は別枠、契約と安全配慮が必要）
- DBが必ずMongoである断定（互換/抽象化がある）

## 攻撃者視点での利用（意思決定：優先度・攻め筋）
※悪用手順ではなく、優先度付けとして整理。

- 優先度が上がる入口
  - “分析/レポート/エクスポート”系（pipelineを使いがち）
  - “高度な検索” “保存検索” “共有フィルタ” （定義を保存→後で実行＝second-order温床）
  - “expand/include/with=xxx” のように関連情報を返すAPI（裏で$lookupが入りやすい）
- まず疑う設計問題
  - pipelineをクライアントに定義させていないか
  - $lookup が入力やモードでON/OFFされる実装分岐がないか
  - tenant/owner 条件が join先にも適用されているか

## 次に試すこと（仮説A/B/C：最小差分で確定）

### 仮説A：pipeline直受け（ステージ混入）が可能
- 条件（観測）
  - pipeline風の入力で、結果構造（配列/ネスト/フィールド出現）が安定して変化する
- 次の一手
  - 入力形式（JSON body / query JSON）を確定し固定
  - “どのステージが受理されるか”を差分で切り分け、allowlist不在を原因として固める

### 仮説B：$lookup の参照先・結合条件が入力に影響される
- 条件（観測）
  - 関連データ（ネスト配列等）が入力によって増減する
- 次の一手
  - 参照先コレクションが固定か（入力で変わらないか）
  - 参照先にも tenant/owner 条件が適用されているか（適用漏れなら設計原因として確定）

### 仮説C：計算量境界が未定義（DoSリスク）
- 条件（観測）
  - limit/offsetの増加や結合条件でレスポンス時間・タイムアウトが顕著に揺れる
- 次の一手
  - 上限（pageSize最大、maxTimeMS、結果サイズ上限）の有無を確認し、欠如を原因として報告
  - DoS検証は“成立根拠”より“設計不備の指摘”を優先（過負荷試験を避ける）

## 防御設計（修正を“設計”として提示する）

### 1) サーバ側生成（入力をパイプライン構造にしない）
- クライアントは “意図” を送る（例：groupBy, sortKey, period, filters）
- サーバは固定テンプレから pipeline を生成（受理するステージは固定 or allowlist）

### 2) ステージallowlist / 参照先固定（$lookupを許すなら）
- $lookup を許す場合でも
  - 参照先コレクション（from）を固定
  - 結合キー（local/foreign）を固定
  - 参照先への権限条件（tenant/owner）と投影（必要最小限）を必ず適用
- 入力は “on/off” や “選択肢” に落とす（入力値を from/field 名にしない）

### 3) 計算量境界（DoS対策）
- limit/pageSize上限、結果サイズ上限、maxTimeMS、allowDiskUseの扱いを明示
- 索引前提のパターンのみ許可（自由な正規表現や無制限joinを許さない）
- 監査：$lookup/$facet/$group などの高コストステージの頻度監視

### 4) 認可境界（BOLA接続）を設計で閉じる
- “主コレクションでのtenant match”だけで安心しない
- join先にも必ず境界条件を適用し、投影で情報を縮退
- 可能なら join 自体をサーバ側の権限制御層でラップ（共通部品化）する

## 手を動かす検証（Labs連動：安全に差分を再現）
- 目的：pipeline直受け/allowlist/権限条件付与位置/計算量上限の差分を、同じ画面・同じAPIで比較できるようにする
- 最小構成（推奨）
  - (1) 安全：DSL→サーバ生成（$lookup固定・参照先にtenant付与）
  - (2) 脆弱：pipeline直受け（ステージ混入）
  - (3) 脆弱：主のみtenant付与、$lookup先は無条件（適用範囲漏れ）
  - (4) 性能境界：limit上限あり/なし（maxTimeMSあり/なし）を比較
- 証跡
  - HAR：baseline / 差分（関連配列の増減） / 差分（時間）
  - サーバログ：trace_id、受理したDSL/入力要約、生成したステージ種別（機微はマスク）、実行時間
  - DBログ（Labsのみ）：実際に $lookup が実行された痕跡

## 例（最小限：設計の違いを理解するための形）
~~~~
# 危険：クライアントのpipelineをほぼそのまま実行（構造注入の余地）
pipeline = JSON.parse(req.query.pipeline)
db.collection.aggregate(pipeline)

# 安全：クライアントは“意図”のみ、サーバが固定テンプレから生成（allowlist）
- allowedGroupToggle = ["status", "day", "owner"]
- allowedSortKey     = ["createdAt", "score"]
- filters はフィールド/演算子/型のallowlistで拘束
pipeline = buildPipelineFromIntent(intent)   # ステージを入力にしない
db.collection.aggregate(pipeline, { maxTimeMS: ... })
~~~~

~~~~
# 危険：主にtenant条件があっても、$lookup先が無条件（適用範囲漏れ）
[ { $match: { tenant_id: t } },
  { $lookup: { from: "other", localField: "x", foreignField: "y", as: "joined" } } ]

# 安全：join先にも境界条件と投影を適用（設計として）
- $lookup を許すなら “from/keys” は固定
- join先は tenant/owner 条件を必ず適用
- joined は必要最小限のフィールドだけ返す
~~~~

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/03_authz_00_認可（IDOR BOLA BFLA）境界モデル化.md`
- `01_topics/02_web/04_api_03_rest_filters_検索・ソート・ページング境界.md`
- `01_topics/02_web/05_input_04_nosql_injection_01_mongodb_01_operator（$ne_$gt_$regex）.md`

## 次（作成候補順）
- `01_topics/02_web/05_input_04_nosql_injection_01_mongodb_04_bson_type（型混乱_配列オブジェクト）.md`
