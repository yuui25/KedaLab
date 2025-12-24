## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - この技術で満たす/破れる点：アクセス制御（生成物の参照/共有/期限）、最小開示（PII・機微列の制御）、入力検証（エクスポート条件・テンプレ）、出力エンコーディング（CSV Injection等）、機密データ保護（保存先・暗号化・署名URL）、監査（誰が何を出したか）、可用性（巨大生成・ワーカー枯渇）
  - 支える前提：エクスポートは「一覧/検索（03）」と「非同期（07）」の出口であり、実装の例外パスが最も多い。生成物は“ファイル/URL/キャッシュ”として残るため、漏えいは長期化しやすい。
- WSTG：
  - 該当テスト観点：Authorization Testing（生成物IDOR、共有境界）、API Testing（エクスポート条件、署名URL、期限、キャッシュ）、Business Logic（フィルタ/状態/権限の反映）、Input/Output Handling（CSV Injection、PDF生成のテンプレ境界）、Error Handling（エラー差分/情報漏えい）
  - どの観測に対応するか：エクスポートの“入口（条件）→生成（ジョブ）→出口（ファイル参照）”を分解し、(1)越境混入、(2)生成物参照のIDOR、(3)署名URLの束縛/期限、(4)出力安全性（CSV/PDF）、(5)ログ/監査、を低侵襲で確定する
- PTES：
  - 該当フェーズ：Information Gathering（エクスポート機能/URL/ジョブ/保存先/共有手段の列挙）、Vulnerability Analysis（IDOR/越境混入/署名URL不備/CSV Injection/テンプレ境界）、Exploitation（少数差分で成立条件確定：2ユーザ/2テナント、生成物の参照と内容差分で証跡化）
  - 前後フェーズとの繋がり（1行）：REST filters（03）で集めた“検索境界”、Async Job（07）で整理した“権限再評価”、Idempotency（06）の“一回性”が、エクスポートでは生成物（artifact）として集約される。ここが崩れると大量漏えい（Collection）に直結する
- MITRE ATT&CK：
  - 戦術：Collection / Exfiltration / Impact
  - 目的：エクスポート機能で大量取得（Collection）、生成物URLや添付で持ち出し（Exfiltration）、巨大生成・無限再生成でワーカー枯渇（Impact）。

## タイトル
file_export_エクスポート境界（CSV_PDF）

## 目的（この技術で到達する状態）
- CSV/PDF等のエクスポートを「最大の漏えい出口」として扱い、(1)生成対象範囲の境界（tenant/role/state/filters）、(2)生成物参照の境界（IDOR/共有/期限/署名）、(3)データ最小化（列/マスキング/集計化）、(4)出力安全性（CSV Injection/テンプレ注入/HTML→PDF）、(5)保存と配布（S3/署名URL/メール添付）、(6)非同期・再生成・キャッシュ混線、(7)監査と濫用耐性、をモデル化してペンテスターが低侵襲で確定できる
- “検索APIは堅牢でも、エクスポートは穴”という現実を前提に、入口→出口までの差分観測で越境混入/IDORを短時間で証跡化できる
- 開発側に「何をどう直すべきか（実装/設定/運用）」を、具体的な制御点（署名URL束縛、期限、server-forced scoping、列allowlist、CSVエスケープ等）で提示できる

## 前提（対象・範囲・想定）
- 対象：CSV/PDF/Excel/ZIP 等の出力
  - 入口：export作成（UI/API）
  - 生成：非同期ジョブ（07）での生成が多い
  - 出口：ダウンロードURL、メール添付、ストレージ（S3等）への保存、管理画面閲覧
- 典型の現実構成
  - export request（条件・列・期間）→ job_id → artifact_id → download_url（署名URL）
  - 生成物は一時保存（期限付き）だが、ログ/添付で長期化することがある
- 重要前提
  - エクスポートは“データの再構成”であり、一覧APIとは別クエリ/別権限で実装されがち（＝穴）
  - 非同期は“時間差”があるため、権限変更/状態変更後に生成が走る（07の再評価が必須）

## 観測ポイント（何を見ているか：データ/境界/運用）
### 1) 入口（export request）の境界：誰が何を出せるか
- 観測で確定したい点
  - export作成権限（一般/管理/運用）
  - 条件（filters）がどの程度自由か（03と同型：期間、status、owner、org）
  - 列指定（fields/columns）があるか（最小開示の入口）
  - “テンプレ”や“カスタムクエリ”が許されるか（危険度が上がる）
- 典型事故（実務）
  - UIは制限しているがAPIは自由（hidden parameter / body改変）
  - 列指定で機微列（email、phone、token、internal_flag）を追加できる
  - 期間が無制限で全件取得できる（Collection直結）

### 2) 生成（ジョブ）での権限再評価：時間差で崩れないか（07接続）
- 観測で確定したい点
  - enqueue後にロール剥奪/退会した場合、生成が止まるか
  - enqueue後に対象データの可視範囲が変わった場合、古い前提で生成しないか
  - 生成時のeffective_identity（誰の権限）が起動者に沿っているか

### 3) 出口（artifact参照）の境界：生成物は最頻出IDOR
- 生成物参照のパターン
  - GET /exports/{export_id}/download
  - GET /files/{artifact_id}
  - 署名URL（queryにsignature/expires）
- 観測で確定したい点（最優先）
  - export_id/artifact_id が別ユーザ/別テナントで参照できないか（IDOR）
  - 404/403の返し方が一貫しているか（オラクル抑制）
  - “共有リンク”がある場合、共有範囲と失効が制御されているか

### 4) 署名URL（Signed URL）の束縛：誰に・何に・いつまで有効か
署名URLは便利だが、束縛が弱いと“URLを知っている人が全員アクセス可能”になる。
- 実務での束縛要件（推奨）
  - 有効期限（短い：分〜時間）
  - 対象リソース固定（path/object keyを固定）
  - HTTPメソッド固定（GETだけ等）
  - できれば主体束縛（少なくともテナント束縛、理想はユーザ束縛）
  - 失効（revoke）手段がある（URL漏えい時に止められる）
- 観測で確定したい点
  - expiresが短いか、更新/再発行の挙動
  - URLの使い回しが可能か（再生成しても同URLにならないか）
  - 参照時にアプリが再チェックしているか（単にS3直リンクだけになっていないか）

### 5) キャッシュ/混線：生成物が他テナントと混ざる現実事故
- 現実の混線要因
  - キャッシュキーにtenantが入っていない（CDN/アプリキャッシュ）
  - 生成物の保存キー（object key）が予測可能/衝突（tenantを含まない）
  - “同じ条件”のエクスポートを共有化してしまい、テナントが混ざる
- 観測で確定したい点
  - 生成物URL/ファイル名にtenantや一意IDが含まれるか（推測材料にもなるのでバランス）
  - 同条件でも別テナントで同一artifactが返らないか（混線の差分観測）

### 6) データ最小化：列allowlist・マスキング・集計化
- 実務で必要な制御
  - “出してよい列”のallowlist（役割別）
  - PIIはマスキング/匿名化（必要性がなければ出さない）
  - 詳細ではなく集計で足りるなら集計（最小開示）
  - 行数上限（巨大漏えい抑制）
- 観測で確定したい点
  - 出力に機微列が含まれていないか（UI制限だけでなくAPI改変で確認）
  - ロール差分（viewer vs admin）で列が変わるか

### 7) CSV特有：CSV Injection（式注入）とエスケープ
CSVは「Excel等で開く」ことが多く、セル先頭が `= + - @` 等だと式として評価され得る。
- 実務リスク
  - 攻撃者が入力欄（氏名、会社名、住所等）に式を入れ、運用者がCSVを開くと危険
- 防御（実務推奨）
  - 先頭文字が危険なら `'` 付与や安全なエスケープ
  - 出力時のサニタイズを“列単位”で実施
  - “ダウンロード前警告”だけに頼らない
- 観測で確定したい点（低侵襲）
  - ユーザ入力がCSVに反映される列があるか
  - 反映される場合、危険先頭文字が中和されているか

### 8) PDF特有：テンプレ境界（HTML→PDF）と内部参照
PDF生成はHTMLテンプレ→レンダリングが多く、テンプレ注入/内部参照（SSRF）やパス参照が絡むことがある。
- 実務で起きる問題
  - テンプレ内で外部URLを読み込む（画像/フォント）→ SSRF/情報漏えいの導線
  - HTMLにユーザ入力を埋め込み、意図しないタグ/参照を許す（ただし実害は生成器次第）
- 防御（実務）
  - 生成器の外部通信を禁止/制限（05のegress制御と同型）
  - テンプレに入れる値はエスケープ、許可タグを限定
- 観測で確定したい点
  - PDF生成が外部通信を行うか（ネットワーク/ログの兆候）
  - ユーザ入力がテンプレに入る箇所があり、参照が許されるか

### 9) 監査・可用性：誰が何をいつ出したか、濫用できないか
- 監査の最小フィールド（推奨）
  - actor_id、tenant_id、export_id/job_id/artifact_id、条件（期間/フィルタ概要）、列セット、行数、生成開始/完了、ダウンロード実行者、download回数
- 濫用耐性（実務）
  - 行数/期間/列の上限
  - 同時実行上限、キュー優先度、キャンセル
  - 失敗時のbounded retry、DLQ
- 観測で確定したい点
  - 上限がサーバ強制か（UIだけではないか）
  - 監査が拒否も含めて残るか

### 10) file_export_boundary_key（正規化キー：後続へ渡す）
- 推奨キー：file_export_boundary_key
  - file_export_boundary_key =
    <request_scope_enforcement>(server_forced|client_influenced|weak|unknown)
    + <job_reauthz>(strict|partial|none|unknown)
    + <artifact_access_control>(strong|weak|none|unknown)
    + <signed_url_binding>(resource_only|tenant_bound|user_bound|none|unknown)
    + <signed_url_ttl>(short|medium|long|unknown)
    + <cache_isolation>(strong|weak|unknown)
    + <data_minimization>(allowlist+mask|partial|none|unknown)
    + <csv_injection_controls>(yes/no/unknown)
    + <pdf_template_controls>(strong|partial|none|unknown)
    + <abuse_controls>(caps+rate+queue|partial|none|unknown)
    + <audit_strength>(strong|partial|weak|unknown)
    + <confidence>
- 記録の最小フィールド（推奨）
  - export作成条件（filters/columns/period）
  - job_id/artifact_id と参照URL
  - 別ユーザ/別テナント参照差分（IDOR有無）
  - 署名URLの期限・束縛（挙動根拠）
  - 出力の機微列/マスキングの有無
  - 上限（行数/期間）と監査

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える（確定できる）：
  - 生成範囲（filters/columns）がサーバで強制され、越境混入が起きないか
  - 生成物参照がIDOR/越境になっていないか（最重要）
  - 署名URLの束縛・期限・失効が実務的に安全か
  - CSV/PDF特有の出力リスク（CSV Injection、テンプレ境界）が抑えられているか
  - 濫用耐性（巨大生成/再生成/並列）と監査が整備されているか
- 推定（根拠付きで言える）：
  - 署名URLが長寿命・束縛弱い場合、URL漏えいで長期漏えいになりやすい
  - export条件が自由・上限無しの場合、バグバウンティでも“低工数大量漏えい”に直結
- 言えない（この段階では断定しない）：
  - 保存先（S3等）の設定詳細。だが、URL形状と期限挙動から安全性を評価できる。

## 確認（最大限詳しく：どうやって“確定”したと言えるか）
エクスポートは「入口→生成→出口」の3点セットで確認する。特に出口（artifact参照）の越境は、少数リクエストで確定でき、ペネトレ報告に強い。

### 1) 確認の基本原則（安全・再現性・低侵襲）
- 原則1：2ユーザ×（可能なら）2テナントで差分を取る
  - A（作成者）/B（非作成者）、T1/T2で “参照できる/できない” を確定する
- 原則2：大量生成は不要。少量データで境界を示す
  - “行数1〜数行でも越境が成立”すれば十分（実害の拡大は避ける）
- 原則3：同じ条件をUIとAPIで比較する
  - UI制限を、API改変で突破できないかを確認（列追加/期間拡大）
- 原則4：相関キーを固定し控える
  - export_id/job_id/artifact_id、download_url、expires、trace_id
- 原則5：証跡は「生成物そのもの」ではなく「参照可否」と「含まれる範囲（最小サンプル）」で取る
  - 生成物を丸ごと保存/共有せず、機微は最小限マスクして証跡化（実務配慮）

### 2) 確認ステップ（入口→生成→出口：A→B→Cで確定度を上げる）
#### ステップA：入口（export作成）の仕様と上限を確定
- 観測するもの
  - export作成API/UI：条件（filters）、列（columns/fields）、期間（date range）、フォーマット（csv/pdf）
  - “テスト生成/プレビュー”があるか（副作用が軽い経路）
- 確認できたと言う条件（証拠）
  - export_id（またはjob_id）が取得でき、条件が監査/UIで追える

#### ステップB：生成（ジョブ）の挙動を確定（07の再評価の有無）
- 観測するもの
  - 状態遷移：queued→running→completed/failed
  - enqueue後の権限/状態変更に追従するか（可能ならテスト環境）
- 確認できたと言う条件（証拠）
  - 失効/剥奪後に拒否/停止する（堅牢） or 完遂する（再評価欠落疑い）

#### ステップC：出口（artifact参照）のIDOR/越境を確定（最優先）
- 差分観測（強力で低侵襲）
  - Aが生成した export_id/artifact_id をBで参照
  - T1で生成したものをT2で参照（可能なら）
  - 参照APIが無ければ、download_url（署名URL）をBで開けるか
- 確認できたと言う条件（証拠）
  - 参照成功：IDOR/越境（P0）
  - 参照失敗（403/404）かつ一貫：堅牢
  - 403と404が条件で揺れるなら、存在オラクルの可能性（P1）

#### ステップD：署名URLの束縛と期限を確定（URL漏えい耐性）
- 差分観測
  - URLを別セッション/別ユーザで使用しても同様にDLできるか（束縛の有無）
  - expires経過後に使えるか（TTL）
  - 生成物を削除/失効した後にURLが生きるか（revoke）
- 確認できたと言う条件（証拠）
  - TTLが短く、削除/失効で即無効化（堅牢）
  - TTL長い/失効不可/主体束縛無し（漏えい耐性弱：P1〜P0）

#### ステップE：内容の境界（越境混入・列過剰・マスキング）を確定
- 差分観測（少量でよい）
  - viewerとadminで列が違うか（ロール差分）
  - 列指定（fields）をAPI改変して機微列が出るか
  - フィルタ（期間/状態）を逸脱させてもサーバで制限されるか（03/03_authz_10接続）
- 確認できたと言う条件（証拠）
  - 禁止されるべき列/範囲が出る（P0/P1）
  - サーバで拒否/マスクされる（堅牢）

#### ステップF：CSV/PDF特有リスクを確定（出力安全性）
- CSV Injection
  - ユーザ入力が出力に含まれる列があるかを確認
  - 危険先頭文字が中和されているか（先頭に ' 等）
- PDFテンプレ境界
  - 外部参照が起きない設計か（ログ/設定/挙動）
  - ユーザ入力がテンプレに入る場合、過剰なHTML/参照が許されないか
- 確認できたと言う条件（証拠）
  - 中和されていない（P1）
  - 参照/外部通信の兆候（設計上リスク：P1〜P0）

### 3) “確認できた”と言うための最低限の証跡セット（報告に耐える）
- HTTP/UI証跡（HAR推奨）
  - export作成（条件付き）→ job_id/export_id の取得
  - 状態参照（completed）→ artifact参照URLの取得
  - Bユーザ/別テナントでの参照試行（成功/失敗）
- 生成物の証跡（最小限）
  - 先頭数行/メタ（列名、サンプル1行）だけをマスクして保存
- 署名URLの証跡（必要最小限）
  - expires値、期限後の挙動、失効後の挙動
- 監査証跡（取れるなら強い）
  - actor/tenant/export_id/条件/ダウンロード者 が記録されていること

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- 優先度（P0/P1/P2）
  - P0：
    - artifact参照がIDOR/越境（別ユーザ/別テナントでDL可能）
    - export条件の逸脱で他テナント/他人のデータが混入
    - 署名URLが長寿命かつ失効不可で、漏えい時に止められない
  - P1：
    - 列指定で機微列を追加できる（UI制限のみ）
    - CSV Injection対策が無い（運用者端末リスク）
    - 生成が無制限で濫用可能（大量生成・費用/可用性）
  - P2：
    - 境界は堅牢だが監査/レート/上限が弱い（運用リスク）
- “成立条件”としての整理（技術者が直すべき対象）
  - 生成範囲はサーバ強制（tenant/role/state/期間/列 allowlist）
  - 生成物参照は強制AuthZ（起動者/テナント束縛）＋署名URLは短TTL・失効可能
  - キャッシュ/保存キーはテナント分離（混線防止）
  - CSVは式注入を中和、PDFは外部参照を抑止（egress制御）
  - 上限（行数/期間/同時）と監査（作成/ダウンロード）を必須化

## 次に試すこと（仮説A/Bの分岐と検証：低侵襲で確定）
- 仮説A：artifact参照がIDOR
  - 検証：
    - Aのartifact_idをBで参照（成功/失敗）
  - 判断：
    - 成功：P0
- 仮説B：署名URLの束縛が弱い
  - 検証：
    - 別セッションでDL、期限後DL、失効後DL
  - 判断：
    - 可能：P1〜P0
- 仮説C：列/期間/フィルタが自由すぎる
  - 検証：
    - UIとAPI改変差分、上限の有無
  - 判断：
    - 逸脱可能：P1（越境混入が出ればP0）
- 仮説D：CSV Injectionが残っている
  - 検証：
    - ユーザ入力が出る列で中和の有無
  - 判断：
    - 無し：P1

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/` ）：
  - `04_labs/02_web/04_api/08_file_export_boundary_csv_pdf/`
    - 構成案（現実運用の再現）
      - export作成（filters/columns/period）→ async job → artifact生成 → signed URL
      - テナント2つ、ロール差分、状態遷移（draft/approved）
      - 防御切替：
        - server-forced scoping ON/OFF
        - artifact AuthZ ON/OFF（IDOR再現）
        - signed URL TTL（短/長）＆失効機構 ON/OFF
        - cache key に tenant 含む/含まない
        - CSV Injection 中和 ON/OFF
        - PDF外部参照禁止（egress制御）ON/OFF
        - 上限（行数/期間/同時）ON/OFF
      - 監査：作成/ダウンロード/失敗理由/列セットを記録
- 取得する証跡（深掘り向け：HTTP＋ログ）
  - HTTP：作成→状態→参照のHAR、別ユーザ参照差分
  - URL：署名URLのexpires/再発行/失効
  - 内容：列名＋サンプル1行（マスク）
  - ログ：actor/tenant/export_id/artifact_id/download_by/row_count

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
# export作成（擬似）
POST /api/exports
Body:
  { "type": "invoices", "format": "csv", "columns": ["id","amount","customer_email"], "period": { "from":"2025-01-01", "to":"2025-01-31" } }

# 状態参照（擬似）
GET /api/exports/{export_id}

# ダウンロード（擬似）
GET /api/exports/{export_id}/download
# または署名URLを取得して直接GET

# 観測すること（擬似）
- 別ユーザ/別テナントで download できないか（IDOR）
- columns を改変して機微列が出ないか（最小開示）
- 署名URLが短TTLで失効できるか
~~~~
- この例で観測していること：
  - 生成物（artifact）の参照境界が強制され、漏えい出口になっていないか
- 出力のどこを見るか（注目点）：
  - artifact_access_control、signed_url_binding、signed_url_ttl、data_minimization、cache_isolation、csv_injection_controls、abuse_controls
- この例が使えないケース（前提が崩れるケース）：
  - エクスポートが同期で即レスポンスの場合でも、出口（ファイル参照/添付/ログ）境界は同じ軸で評価する

## 参考（必要最小限）
- OWASP ASVS（アクセス制御、最小開示、出力安全性、監査）
- OWASP WSTG（AuthZ、Business Logic、Output Handling）
- PTES（差分観測で越境/IDORを確定）
- MITRE ATT&CK（Collection/Exfiltration：エクスポートの悪用）

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/04_api_07_async_job_権限伝播（キュー_ワーカー）.md`
- `01_topics/02_web/03_authz_02_idor_典型パターン（一覧_検索_参照キー）.md`
- `01_topics/02_web/04_api_05_webhook_ssrf_送信側の到達性境界.md`

## 次（04_api_09 以降）に進む前に確認したいこと（必要なら回答）
- 04_api_09（error_model）では、API/ジョブ/エクスポート全体に共通する“例外パスが漏えい/オラクルになる問題”を、スタック・例外分類・trace_id・ユーザ向けメッセージの一貫性まで含めて最大限深掘りする
