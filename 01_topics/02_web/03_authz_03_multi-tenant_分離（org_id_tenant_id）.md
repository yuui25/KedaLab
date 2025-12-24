## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - この技術で満たす/破れる点：マルチテナント分離（論理/物理）、テナント境界の一貫性（全エンドポイント・全データストア）、テナント選択の信頼境界（URL/ヘッダ/クレーム/セッション）、検索/キャッシュ/非同期処理での越境防止、監査（tenantを含む相関）
  - 支える前提：IDOR（02）が“同一テナント内”で止まっても、テナント越境が成立するとImpactが最大化（法務・信用・契約上の重大事故）
- WSTG：
  - 該当テスト観点：Authorization Testing（Multi-tenant isolation、IDOR/BOLAの越境版）、Business Logic（テナント切替/招待/共有）、API Testing（tenantスコープ）
  - どの観測に対応するか：tenantの決定点（resolver）と、各入口（list/search/get/download/admin/webhook/job）でのスコープ強制をHTTP差分で体系化する
- PTES：
  - 該当フェーズ：Information Gathering（テナントモデル把握：切替・識別子・境界）、Vulnerability Analysis（越境成立条件の特定）、Exploitation（許可範囲での最小差分検証）
  - 前後フェーズとの繋がり（1行）：02で抽出した参照キーと入口を、tenant軸（org_id/tenant_id）で再マッピングし、「テナント決定→スコープ強制→例外パス」を確定して04〜10へ分岐する
- MITRE ATT&CK：
  - 戦術：Discovery / Collection / Privilege Escalation / Impact
  - 目的：tenant境界の決定点や例外パスを突いて越境アクセス（他社データ閲覧・操作）を成立させる（※手順ではなく成立条件の判断）

## タイトル
multi-tenant_分離（org_id_tenant_id）

## 目的（この技術で到達する状態）
- マルチテナント分離を「DBが同じ/違う」ではなく、(1)テナント決定点（どのtenantとして処理するか）、(2)スコープ強制点（どこでtenant条件を必ず付けるか）、(3)例外パス（検索/キャッシュ/非同期/ファイル/管理UI等）で分解し、短時間で越境リスクを特定できる
- 02（IDOR）を“越境版”として拡張し、同じ入口（一覧/検索/参照/派生）をtenant軸で再評価できる
- 修正指示を「tenant_idをWHEREに付けろ」で終わらせず、設計として「信頼できるtenantの決め方」「強制の実装位置」「例外パスの封じ方」まで落とし込める
- 後続（04 RBAC/ABAC、06 重要操作、08 ファイル、09 管理UI、10 状態遷移）へ、テナント境界が絡む論点（admin権限、共有、署名URL、状態公開）を明確に接続できる

## 前提（対象・範囲・想定）
- 対象：B2B SaaS / 組織（org）単位 / tenant単位の分離があるWeb/API
- 用語整理（このファイル内で固定）
  - tenant：分離単位（顧客会社、組織、プロジェクト空間など）
  - tenant_id / org_id：tenantを識別するキー（名称は実装により異なる。ここでは混在前提）
  - actor：操作主体（user/service account）
  - scope：actorがアクセス可能なtenant集合 + tenant内のオブジェクト集合
- 想定するテナント方式（混在もある）
  - 論理分離：同一DB/同一テーブルで tenant_id を列に持つ
  - スキーマ分離：tenantごとにschema
  - DB分離：tenantごとにDB
  - 物理分離：専用クラスタ/専用環境
- 検証の安全な範囲（実務的）
  - 2ユーザ×2テナント（可能なら3）で、差分観測を最小回数で行う
  - “越境の成立条件”を確定するために、入口別に代表エンドポイントを固定して観測する
  - 重要操作（削除/権限/送金等）は、可能なら確認画面・dry-run相当までで証跡化する（06へ接続）

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) マルチテナント分離の中核は「tenantの決定点（Tenant Resolver）」である
テナント越境は、多くの場合「tenantをどう決めるか」「その決定がどこで強制されるか」が崩れて起きる。
- Tenant Resolver の典型入力（どれが“真”かを見極める）
  - サブドメイン：{tenant}.example.com
  - パス：/t/{tenant_id}/...
  - ヘッダ：X-Org-Id / X-Tenant-Id（危険になりやすい：信頼境界が曖昧）
  - セッション：ログイン時に選択したtenantがサーバセッションに保存
  - トークンクレーム：JWTのtenant_id/org_id、または許可tenant一覧
  - 共有リンク：share_idからtenantを逆引き（公開/共有設計に絡む）
- 観測で確定したい点
  - tenantは「ユーザ入力」から直接採用されていないか（URL/ヘッダの値を無検証で採用）
  - tenantは「サーバ側で確定」されているか（セッション/クレーム/DB参照で整合）
  - tenant切替（スイッチ）がある場合、切替時の再認証/再承認があるか（設計次第）

### 2) スコープ強制点（Enforcement Layer）を固定し、入口不一致を潰す
- 代表的な強制方式（設計の違い＝抜け方の違い）
  - handler/controller 都度チェック：実装漏れが例外パス化しやすい
  - service/policy 統一（Policy Engine含む）：呼び出し忘れ、例外APIで抜けやすい
  - DBクエリで強制（常にWHERE tenant_id）：検索/集計/別ストアで抜けやすい
  - DB側機能（RLS等）で強制：アプリ層の漏れに強いが設定ミスが致命的
- 観測で確定したい点
  - 入口（list/search/get/download/admin/webhook/job）ごとに強制方式が混在していないか
  - “tenant条件”が要求パラメータ依存になっていないか（org_idを送れば見える、等）

### 3) 越境の典型パターン（02の越境版）
#### 3.1 複合キー片落ち（org_id無視 / tenant_id無視）
- 症状
  - /org/{org_id}/items/{id} のはずが、実体は {id} だけで参照できる
  - org_idを変えても同じ結果になる（tenant resolverが効いていない兆候）
- 原因モデル（推定）
  - DBクエリが `WHERE id = ?` で tenant条件が無い
  - org_idはUI/ルーティングの装飾で、認可に使われていない

#### 3.2 テナント切替の“状態”が壊れる（セッション/クレーム/キャッシュ）
- 症状
  - 切替後も一部APIが旧tenantで動く、または逆（混在）
  - UI表示とAPI結果のtenantが一致しない
- 原因モデル（推定）
  - サーバセッションのtenant更新が一部ミドルウェアに反映されない
  - キャッシュキーに tenant が入っていない（最頻出の重大原因）
  - 非同期ジョブ/イベントに tenant コンテキストが渡っていない（3.6へ）

#### 3.3 検索/集計が越境する（全体インデックス問題）
- 症状
  - searchが他tenantのレコードを返す（一覧は守るのに検索だけ漏れる）
  - レポート/集計が他tenant混入（数字が合わない）
- 原因モデル（推定）
  - 検索基盤（ES等）側にtenantフィルタが入っていない/必須化されていない
  - “管理者向け検索”が一般ユーザへ露出（09へ接続）

#### 3.4 共有リンク/招待リンクがtenant境界を迂回する（仕様境界の誤用）
- 症状
  - share_id / invite_token が tenantスコープを超えて機能する（設計意図と乖離）
- 原因モデル（推定）
  - shareの権限・期限・対象オブジェクト束縛が弱い
  - 招待受諾で、既存セッションのtenantが想定外に切替/付与される（権限付与が過剰）

#### 3.5 ファイル/署名URLが越境する（08へ直結）
- 症状
  - file_id / signed_url で他tenantの添付が取れる
- 原因モデル（推定）
  - アプリは本文をtenantスコープするが、ストレージキー/署名対象がtenantを含まない
  - 署名URLのスコープが広い（バケット/プレフィックスが共通）

#### 3.6 非同期（ジョブ/キュー/Webhook/メール）が越境する（実務で事故が多い）
- 症状
  - 他tenant宛に通知/請求/レポートが送られる
  - Webhookが別tenantのイベントを配送する
- 原因モデル（推定）
  - メッセージに tenant_id が含まれない、または消費側で無視
  - “グローバルジョブ”が誤って複数tenantのデータを横断

### 4) 入口マトリクス（ペネトレ/TLPTでの優先度付け）
テナント越境は「高Impact×例外パス」で起きる。入口を固定して高優先度から観測する。
- 優先入口（上から）
  1. 検索/レポート/エクスポート（大量漏洩）
  2. ファイルDL/署名URL（添付の抜け道）
  3. 管理UI/管理API（横展開の加速）
  4. 詳細参照（get）
  5. 一覧（list）
  6. 非同期（Webhook/ジョブ/メール）
- 観測の作法
  - 同じ操作を「tenant A」「tenant B」で比較し、結果にtenant混入が無いかを差分で見る
  - テナント切替があるなら、切替前後で“同じAPI”を観測し、混在が無いかを見る

### 5) “テナントを信頼しない”設計の判断軸（修正指示の骨格）
- 原則
  - tenantはクライアントから“指定させない”方向に寄せる（指定させるなら署名/検証/allowlistが必要）
  - tenantコンテキストはサーバ側で確定し、全クエリ/全ストア/全キャッシュに一貫して適用する
- 実装方向（代表）
  - middleware で tenant を確定し、以降の処理で必ず参照する（全入口）
  - DBクエリに tenant 条件を“必ず”含める（ORMのスコープ/自動付与）
  - キャッシュキーに tenant を含める（レスポンス/権限キャッシュ含む）
  - 検索/分析基盤でも tenant フィルタを必須化（クエリテンプレ）
  - 非同期メッセージに tenant_id を含め、消費側で検証する（コンテキストの明示）

### 6) multi_tenant_key_boundary（正規化キー：後続へ渡す）
- 推奨キー：multi_tenant_key_boundary
  - multi_tenant_key_boundary = <tenant_model>(logical|schema|db|dedicated|unknown) + <tenant_resolver>(subdomain|path|header|session|token_claim|share_invite|mixed|unknown) + <scope_axis>(tenant_id|org_id|workspace_id|project_id|unknown) + <enforcement_layer>(handler|service_policy|db_query|db_rls|mixed|unknown) + <high_risk_entrypoints>(search|export|file|admin|webhook|job|mixed|unknown) + <cache_tenant_keyed>(yes/no/unknown) + <evidence_level>(http_only|http+logs|unknown) + <confidence>
- 記録の最小フィールド（推奨）
  - tenant_resolver_inputs（どれで決まるか）
  - tenant_switch_mechanism（ある/ない、入口）
  - endpoints（代表3〜8本：search/export/file/admin/get/list）
  - 期待される分離と観測差分（tenant A/B）
  - evidence（HAR、レスポンス差分、ヘッダ/クレーム断片、ログ断片）
  - action_priority（P0/P1/P2）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える（確定できる）：
  - tenantの決定点（subdomain/path/header/session/token等）と、その信頼境界がどこにあるか
  - 入口ごとにtenantスコープが一貫して強制されているか（検索/ファイル/管理/非同期含む）
  - テナント越境の兆候が「複合キー片落ち」「検索基盤」「キャッシュ」「非同期」など、どの原因モデルに近いか
- 推定（根拠付きで言える）：
  - enforcement_layer が混在している場合、例外入口で越境が起きやすい（修正は統一・必須化へ）
  - 検索/キャッシュ/非同期のいずれかが弱い場合、UI上の見え方と無関係に越境事故が起き得る
- 言えない（この段階では断定しない）：
  - 最大漏洩量（実行による大量取得は許可・影響評価が必要）
  - 契約上の“分離要件”の厳密度（SLA/法務要件は別途確認が必要）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- 優先度（P0/P1/P2）
  - P0：
    - 他tenantのデータ参照/ダウンロード/検索が成立する（越境確定）
    - tenant resolver がクライアント入力（ヘッダ/パス等）を無検証で採用している兆候
    - キャッシュ/検索/ファイル/管理UIなど高Impact入口で越境兆候（横展開が容易）
  - P1：
    - 直接越境は未確定だが、入口差分（検索だけ怪しい、ファイルだけ怪しい、切替後混在）がある
    - 監査ログに tenant が入っておらず、侵害時に追跡できない（運用リスク）
  - P2：
    - 分離は堅牢だが、共有/招待など仕様境界が曖昧で誤設定事故が起きやすい
- “成立条件”としての整理（技術者が直すべき対象）
  - tenantをサーバ側で確定し、全入口・全ストア（検索/キャッシュ/非同期/ストレージ）へ一貫適用する
  - tenant条件を「要求パラメータに依存」させない（org_idを送れば見える、を排除）
  - キャッシュキー/検索クエリ/ジョブメッセージに tenant を必須化する
  - 監査ログに tenant を含め、越境の検知・追跡を可能にする

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：複合キー片落ち（org_id/tenant_idが無視される）
  - 次の検証（最小差分）：
    - 複合形式の代表APIで、tenant情報が“参照に効いている”兆候（レスポンス差分/拒否）があるかを見る
  - 判断：
    - 片落ち兆候：P0（02の越境版として確定）
- 仮説B：検索/集計が越境する（全体インデックス）
  - 次の検証：
    - search/export/report の代表APIを固定し、tenant A/Bで混入が無いかを差分で見る
  - 判断：
    - 混入兆候：P0〜P1（高Impact入口。修正は検索基盤の必須フィルタ）
- 仮説C：キャッシュ/切替状態が混在する
  - 次の検証：
    - tenant切替前後で同一APIを観測し、結果がtenantに追随するか（混在しないか）を見る
  - 判断：
    - 混在：P1（事故リスク高。キャッシュキー/コンテキスト伝播の見直し）
- 仮説D：ファイル/署名URLが越境する
  - 次の検証：
    - 添付DL/署名URLを入口として、tenant境界が適用されている兆候を確認（08へ直行）
  - 判断：
    - 越境兆候：P0
- 仮説E：非同期（Webhook/ジョブ/メール）が越境する
  - 次の検証：
    - 通知/配送/ジョブ実行のログや宛先の設計（tenantの相関）を確認（HTTPだけで難しい場合は設計/設定断片を証跡に）
  - 判断：
    - tenant相関が取れない：P1（事故が起きても追えない）

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/` ）：
  - `04_labs/02_web/03_authz/03_multi_tenant_isolation_org_tenant/`
    - 構成案：
      - 2テナント×複数ユーザ、tenant resolver を切替（subdomain/path/header/session/token_claim）
      - 入口：list/search/get/export/file/download/admin/webhook/job を用意
      - 意図的に例外パスを作る（searchだけtenantフィルタ漏れ、cacheキー漏れ、fileキー漏れ、jobコンテキスト漏れ）
      - 監査ログ：actor, tenant, object, endpoint, decision を必ず出す
- 取得する証跡（深掘り向け：HTTP＋周辺ログ）
  - HTTP：HAR（search/export/file/admin/get/list）＋tenant切替の手順ログ
  - ヘッダ/クレーム：tenantを示す要素（subdomain/path/header/claims）の断片
  - ログ：tenant確定値、policy判定点、キャッシュヒットキー、検索クエリのtenant条件（取れる場合）
  - 監査：tenantを含むアクセスログ（後追い可能性）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
# 代表入口（擬似）
GET  /t/{tenant_id}/items/search?q=...     # 検索（越境が起きやすい）
GET  /t/{tenant_id}/items/{id}            # 参照（複合キー片落ちを観測）
GET  /t/{tenant_id}/export/items.csv      # エクスポート（大量漏洩の入口）
GET  /files/{file_id}/download            # ファイル（本文は守るが添付が抜けやすい）
GET  /admin/search?q=...                  # 管理系（露出すると横展開）

# 観測すること（擬似）
- tenant_resolver が何を根拠に tenant を確定しているか
- search/export/file/admin など高Impact入口で tenant フィルタが必須化されているか
- tenant切替前後で結果が混在しないか（キャッシュ/状態）
~~~~
- この例で観測していること：
  - tenant境界が「全入口・全ストア」に一貫して適用されているか
- 出力のどこを見るか（注目点）：
  - tenantの決定点、入口差分（特にsearch/export/file/admin）、切替後混在、エラーの一貫性、監査ログのtenant相関
- この例が使えないケース（前提が崩れるケース）：
  - テナントが“見た目だけ”で実体が別環境（専用環境）になっており、HTTP上で比較できない（→設計/構成証跡で分離方式を確定し、例外入口の有無を重点確認する）

## 参考（必要最小限）
- OWASP ASVS（Authorization / Multi-tenant分離 / 監査）
- OWASP WSTG（Authorization Testing：越境、IDOR/BOLA）
- PTES（情報収集→境界モデル化→差分観測で確定）
- MITRE ATT&CK（Discovery/Collection：越境の成立条件を見つける）

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/03_authz_02_idor_典型パターン（一覧_検索_参照キー）.md`
- `01_topics/02_web/03_authz_08_file_access_ダウンロード認可（署名URL）.md`
- `01_topics/02_web/03_authz_09_admin_console_運用UIの境界.md`

## 次（04以降）に進む前に確認したいこと（必要なら回答）
- 04 rbac_abac：
  - ロールは「tenant内ロール（org admin等）」中心か、「システム全体ロール（super admin等）」もあるか
  - ルール評価がアプリ内実装か、policy engine（OPA等）に外出ししているか（無くても“判定点”として書ける）
- 08 file access：
  - アプリ経由DL中心か、S3/GCS等の署名URL中心か（両方でも可）
- 09 admin console：
  - 管理UIが同一IdP/同一ドメインか、別サブドメイン/別IdPか（境界の切り方が変わる）
- 10 object state：
  - 公開/非公開（draft/published）や承認フローが強いプロダクトか（強いならstate×tenant×roleを主軸にする）
