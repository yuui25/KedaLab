## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - この技術で満たす/破れる点：アクセス制御の一貫性（版間で認可がズレない）、入力検証（古い版の緩いバリデーションが残存しない）、エラーモデルの一貫性（09）、機密情報保護（旧版の過剰レスポンス/フィールド）、監査（版別の利用状況・デプリケーション）、可用性（旧版維持による攻撃面拡大）
  - 支える前提：versioningは“互換性のための残存”であり、攻撃者にとっては“古い脆い面”を探すための地図になる。v2で修正したつもりでも、v1が残っていれば脆弱性は残る。
- WSTG：
  - 該当テスト観点：API Testing（version指定方法、互換性、古い版の発見）、Authorization Testing（版間差分でBOLA/BFLAが復活していないか）、Input Validation（旧版の緩いパース/型）、Error Handling（09：旧版のスタック漏えい）、Business Logic（版間で状態遷移/制約が異ならないか）
  - どの観測に対応するか：同一機能をv1/v2で“差分観測”し、(1)認可・境界のズレ、(2)フィールド/レスポンスの過剰開示、(3)バリデーションの緩さ、(4)エラーモデルの漏えい、(5)ルーティング/フォールバックの誤実装、(6)デプリケーション運用、を低侵襲で確定する
- PTES：
  - 該当フェーズ：Information Gathering（バージョン面の列挙、ドキュメント/SDK/旧URL）、Vulnerability Analysis（版間差分、旧版残存リスク）、Exploitation（最小差分で成立条件を確定：同一リクエストを版だけ変えて比較し、認可/漏えい/挙動差を証拠化）
  - 前後フェーズとの繋がり（1行）：GraphQL（02）は単一エンドポイントでもschema versionがあり、REST filters（03）・Webhook（04/05）・Idempotency（06）・Async（07）・Export（08）・Error model（09）は版間でズレると脆弱性が復活する。10は“残存面の管理”として全体に接続する
- MITRE ATT&CK：
  - 戦術：Discovery / Initial Access / Persistence
  - 目的：旧版エンドポイントやフォールバック挙動の探索（Discovery）、緩い旧版でBOLA/BFLAや入力汚染を成立（Initial Access）、デプリケーションされない旧版を長期に悪用（Persistence）。

## タイトル
versioning_互換性と境界（v1_v2）

## 目的（この技術で到達する状態）
- API versioning を「互換性のための仕組み」ではなく「攻撃面管理・残存面管理の仕組み」として扱い、版間で起きる典型事故（認可ズレ、フィールド漏えい、緩い入力、エラーモデル漏えい、フォールバック誤実装、計測不足）をモデル化し、ペネトレで差分観測により低侵襲で確定できる
- 開発/運用側に、(1)版の定義と適用点、(2)後方互換の範囲、(3)デプリケーションと計測、(4)古い版の強制停止と移行、(5)SDK/クライアント更新戦略、を具体的な実務として落とし込める
- “v2で直したのにv1が残っていた”を確実に防ぐための、テスト観点・監査観点・移行観点を揃える

## 前提（対象・範囲・想定）
- 対象：REST/GraphQL/gRPC/WebSocket/SSE など全API（ただし本ファイルは主にHTTP API）
- versioningの現実的な表現（混在しやすい）
  - URL：/api/v1/... /api/v2/...
  - Header：Accept: application/vnd.xxx.v2+json / X-API-Version: 2
  - Query：?version=1
  - GraphQL：schema evolution（deprecated field）、operationごとに差が残る
- “残存面”が生まれる理由
  - モバイル/IoT/外部顧客の更新が遅い
  - SDKが古い
  - パートナー連携の改修コスト
  - 監査/法対応で過去互換が必要
- ペネトレの重要姿勢
  - “新しい版しか見ない”は危険。旧版こそ優先的に見る（攻撃者の合理性）
  - 版の違いは“差分観測”で立証する（同一リクエストで版だけ変える）

## 観測ポイント（何を見ているか：版の定義・適用・残存）
### 1) 版の定義：何が“互換性”で、何が“破壊的変更”か
- 実務での最小定義（例）
  - “同じ操作”の意味（セマンティクス）が変わるなら破壊的変更
  - フィールド削除/型変更/権限制約変更は破壊的変更になりやすい
  - エラー形式変更（09）はクライアント影響が大きい
- 観測で確定したい点
  - v1/v2で同名endpointが実際に存在するか
  - 何が変わったのか（認可/入力/出力/状態/エラー）

### 2) 版の適用点（routing）：どこでv1/v2が切り替わるか
- 危険なパターン（実務頻出）
  - 版指定が無い場合に“デフォルトでv1へフォールバック”
  - 不正な版指定で“黙ってv1へ落ちる”
  - プロキシ/CDNでパス正規化され、/v2 が /v1 にマップされる
- 観測で確定したい点
  - 版指定無しでどこに行くか（default）
  - 不正な版指定（v999）でどうなるか（rejectかfallbackか）
  - 版指定がキャッシュキーに含まれているか（混線）

### 3) 認可（AuthZ）の版間差分：v2で修正したBOLA/BFLAがv1で復活しやすい
- 典型事故
  - v2はtenant/ownerチェックを追加、v1は未実装
  - v2はRBACを強化、v1はロール判定が緩い
- 観測で確定したい点（差分観測の中心）
  - 同一ユーザで v1は成功、v2は403（またはその逆）
  - 同一IDで v1/v2の403/404が揺れ、存在オラクルが成立（09接続）

### 4) 入力検証の版間差分：旧版は“パースが緩い”が最も多い
- 典型事故（実務）
  - v1は型が曖昧（string/objectどちらでも通る）
  - v1は未知フィールドを許容し、mass-assignment的な挙動を誘発
  - v1はフィルタ（03）が無制限
- 観測で確定したい点
  - 同じ不正入力がv1で通り、v2で拒否されるか
  - v1だけ“謎のフィールド”が効いていないか（hidden parameter）

### 5) 出力（レスポンス）の版間差分：旧版に“過剰なフィールド”が残りやすい
- 典型事故
  - v2でPII/内部フラグを削ったがv1に残る
  - v2でマスキングしたがv1は生値
- 観測で確定したい点
  - v1だけ余計なフィールド（is_admin, internal_notes, email等）が出る
  - v1だけ関連オブジェクトが過剰展開（N+1的な過剰開示）

### 6) エラーモデル（09）の版間差分：旧版にスタック漏えいが残る
- 典型事故
  - v2は統一エンベロープ、v1はフレームワーク既定のHTMLエラー/スタック
- 観測で確定したい点
  - v1だけ 500に内部詳細
  - v1だけ 403/404差分が強い（存在オラクル）

### 7) 非同期/エクスポート/署名URLの版間差分：旧版が“出口”として残る
- 典型事故
  - v2はartifact参照にAuthZ追加、v1は直リンク
  - v2は署名URL短TTL、v1は長寿命
- 観測で確定したい点
  - export/download/job/result の参照がv1で緩くないか（07/08接続）
  - 署名URLの束縛/期限がv1で弱くないか

### 8) キャッシュ混線：Vary/キャッシュキーにversionが入らず、v1/v2が混ざる
- 実務で起きる
  - Acceptヘッダでversionを切るのにCDNがVaryを見ない
  - /api を同一キャッシュに載せてしまい、古いレスポンスが混入
- 観測で確定したい点
  - Varyヘッダの有無（Accept/Versionヘッダを使う場合）
  - v1/v2でレスポンスが混ざる兆候（フィールドが揺れる、古い形式が返る）

### 9) デプリケーション運用：旧版を“終わらせる仕組み”があるか
- 実務で必要
  - Deprecation告知（レスポンスヘッダ、ドキュメント）
  - Sunset日付（期限の明示）
  - 版別の利用計測（どのクライアントがv1を叩いているか）
  - 強制移行（段階的に拒否、影響範囲の把握）
- 観測で確定したい点
  - 旧版に deprecation/sunset シグナルがあるか
  - 旧版が無期限で残っていないか（攻撃面の固定化）

### 10) versioning_boundary_key（正規化キー：後続へ渡す）
- 推奨キー：versioning_boundary_key
  - versioning_boundary_key =
    <version_mechanism>(url|header|query|mixed|unknown)
    + <default_behavior>(reject_without_version|default_latest|fallback_old|unknown)
    + <invalid_version_behavior>(reject|fallback|unknown)
    + <authz_parity>(strong_parity|minor_drift|major_drift|unknown)
    + <input_validation_parity>(strong|drift|unknown)
    + <output_minimization_parity>(strong|drift|unknown)
    + <error_model_parity>(strong|drift|unknown)
    + <async_export_parity>(strong|drift|unknown)
    + <cache_isolation>(strong|weak|unknown)
    + <deprecation_ops>(strong|partial|none|unknown)
    + <confidence>
- 記録の最小フィールド（推奨）
  - v1/v2の入口（URL/ヘッダ）の特定
  - 版指定無し/不正指定の挙動
  - 同一操作の差分（認可・入力・出力・エラー）
  - 旧版の利用状況（観測できる範囲：ログ/メトリクスがあれば）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える（確定できる）：
  - 版指定の仕組みとフォールバック挙動（残存面の入口）が安全か
  - v1/v2で境界（認可・入力・出力・エラー）が同等か、どこでズレるか
  - 旧版が“出口（非同期/エクスポート）”として緩く残っていないか
  - キャッシュ混線の兆候があるか
  - デプリケーション運用が攻撃面縮小に寄与しているか
- 推定（根拠付きで言える）：
  - major_drift がある場合、攻撃者は旧版を優先利用してBOLA/BFLAや漏えいを狙う
  - fallback_old がある場合、版指定を誤らせる/改ざんする攻撃で旧版へ誘導できる
- 言えない（この段階では断定しない）：
  - 旧版を残すビジネス都合の妥当性。ただし“残すなら守る/終わらせる”の必要条件は提示できる。

## 確認（最大限詳しく：どうやって“確定”したと言えるか）
versioningの確認は「版の入口を見つける → フォールバックを確認する → 同一操作の差分を取る → 残存面（出口）を確認する」の順で行う。全て差分観測で低侵襲に立証できる。

### 1) 確認の基本原則（再現性・低侵襲・証拠の強さ）
- 原則1：同じリクエストを“版だけ”変えて比較する
  - 変えるのは /v1 と /v2、またはヘッダのversionだけ
- 原則2：比較項目を固定する
  - status、レスポンスフィールド集合、エラー形式、ヘッダ、処理時間
- 原則3：比較は3点セットで偶然を潰す
  - 正常系（200）、境界系（403/404/409）、不正入力（400/422）
- 原則4：旧版探索は“受動情報”から始める
  - ドキュメント/SDK/モバイルアプリ/ログ/JS/旧URLの痕跡
- 原則5：出口（export/job/download）は旧版の“穴”になりやすいので必ず見る

### 2) ステップA：版の入口（version mechanism）を確定
- 観測方法（低侵襲）
  - ルーティング：/api/v1/… /api/v2/… の存在
  - ヘッダ：AcceptやX-API-Versionの有無
  - クエリ：?version=1 の有無
- 確認できたと言う条件（証拠）
  - “同一機能”に対し、版の指定方法が最低1つ観測できる
  - 版を変えるとレスポンスに差分が出る（何らかの変化が見える）

### 3) ステップB：デフォルト挙動と不正版の挙動を確定（残存面の入口）
- テスト観測（最小）
  - 版指定無し（/api/resource または versionヘッダ無し）
  - 不正版指定（v999、X-API-Version: 999）
- 確認できたと言う条件（証拠）
  - 版指定無しでどこへ行くかが分かる（reject/latest/fallback_old）
  - 不正版がrejectされるか、fallbackするかが分かる
- 危険判定の根拠
  - fallback_old なら、攻撃者は“版指定を壊す/消す”ことで旧版へ誘導できる

### 4) ステップC：同一操作の差分観測（認可・入力・出力・エラー）で“ズレ”を確定
#### 4.1 認可差分（最優先）
- 手順（差分の立証）
  - 同一ユーザで、同一対象IDに対し v1 と v2 を叩く
  - あるいは同一対象IDで、権限だけ変えて v1/v2 を比較する
- 確認できたと言う条件（証拠）
  - v1で成功、v2で403（または逆）＝authz_parity drift
  - 403/404の揺れ＝存在オラクル復活（09接続）

#### 4.2 入力検証差分
- 手順
  - 同じ“不正入力”（型違い、未知フィールド、境界値）を v1/v2 で投げる
- 確認できたと言う条件（証拠）
  - v1は通る/別挙動、v2は拒否＝input_validation drift
  - v1だけ未知フィールドが効く＝hidden parameterの可能性

#### 4.3 出力差分（過剰開示）
- 手順
  - 同じGETを v1/v2 で比較し、フィールド集合を差分抽出
- 確認できたと言う条件（証拠）
  - v1だけPII/内部フラグ/関連オブジェクトが多い＝output drift

#### 4.4 エラーモデル差分（09）
- 手順
  - 同じ例外を v1/v2 で誘発し、レスポンス形式と漏えいを比較
- 確認できたと言う条件（証拠）
  - v1だけスタック/SQL/内部情報＝error_model drift（P0）

### 5) ステップD：残存面（出口）の差分観測（07/08の“穴”）
- 対象（優先）
  - export/download/job/result などの生成物参照
- 手順
  - v1/v2で同じexportを作り、artifact参照のAuthZ・署名URLの束縛/TTLを比較
- 確認できたと言う条件（証拠）
  - v1の方が参照が緩い、TTLが長い、失効できない、などが確定できる

### 6) ステップE：キャッシュ混線の確認（Vary/キー）
- 手順（低侵襲）
  - versionを切るヘッダ/パスで、レスポンスが混ざる兆候を観測
  - Acceptで切るなら Vary: Accept が出ているかを確認
- 確認できたと言う条件（証拠）
  - Vary不足や混線の兆候（フィールドが揺れる、旧形式が返る）

### 7) “確認できた”と言うための最低限の証跡セット（報告に耐える）
- 版入口の証跡
  - v1/v2のリクエスト例（URLまたはヘッダ差分）
- フォールバックの証跡
  - 版指定無し/不正指定の結果（statusと挙動）
- 差分観測の証跡（最重要）
  - 認可差分：同一対象IDで v1/v2 の結果を並べる
  - 出力差分：v1/v2のレスポンスフィールド差分（必要最小限の抜粋）
  - エラー差分：同じ不正入力で v1だけ漏えい（または形式違い）
- 出口差分（あれば強い）
  - export/download のv1/v2差（参照可否、署名URL TTL、失効挙動）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- 優先度（P0/P1/P2）
  - P0：
    - v1でBOLA/BFLAが成立し、v2では防げている（修正漏れ＝残存）
    - v1で内部情報漏えい（スタック/SQL/クラウド識別子）
    - v1の出口（export/job/download）がIDOR/長寿命URL
    - version指定の誤りで旧版へフォールバック（誘導可能）
  - P1：
    - v1で入力検証が緩く、未知フィールドが通る
    - キャッシュ混線で旧形式が混入（セキュリティ境界の不確定化）
    - deprecation/sunsetが無く旧版が無期限
  - P2：
    - 境界は概ね同等だが、計測/運用が弱い（移行できず攻撃面が縮まらない）
- “成立条件”としての整理（技術者が直すべき対象）
  - 版指定無し/不正指定はreject（fallback_old禁止）
  - 版間でAuthZ/入力/出力/エラーのパリティを保つ（共通コンポーネント化）
  - 旧版の出口（export/job/download）を優先的に是正
  - AcceptヘッダversionならVaryを正しく設定し、キャッシュ混線を防ぐ
  - デプリケーション（Sunset）と利用計測を必須化し、旧版を終わらせる

## 次に試すこと（仮説A/Bの分岐と検証：低侵襲で確定）
- 仮説A：旧版がフォールバックで残っている
  - 検証：
    - 版指定無し/不正指定で挙動確認
  - 判断：
    - fallback_old：P0/P1
- 仮説B：v1に認可ズレがある
  - 検証：
    - 同一対象IDで v1/v2 を比較（権限差分）
  - 判断：
    - v1だけ成功：P0
- 仮説C：v1に漏えいが残る
  - 検証：
    - 同じ不正入力でv1のエラー応答を確認
  - 判断：
    - スタック等：P0

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/` ）：
  - `04_labs/02_web/04_api/10_versioning_boundary_v1_v2/`
    - 構成案（現実運用の再現）
      - v1/v2を並存（AuthZ/validation/output/errorを切替可能）
      - フォールバック挙動（reject vs fallback_old）を切替
      - Accept header version + CDN cache（Vary有無）を再現
      - export/job/download をv1/v2で差を付ける（穴の再現）
      - 監査：version、client_id、trace_id、endpoint を記録し利用計測
- 取得する証跡
  - v1/v2差分（HTTP）
  - フォールバック挙動（HTTP）
  - 出口差分（export/job/download）
  - cache混線（必要ならヘッダ）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
# URL version（擬似）
GET /api/v1/resources/123
GET /api/v2/resources/123

# Header version（擬似）
GET /api/resources/123
Accept: application/vnd.example.v1+json

GET /api/resources/123
Accept: application/vnd.example.v2+json

# 不正版（擬似）
GET /api/resources/123
X-API-Version: 999
~~~~
- この例で観測していること：
  - “版だけ変えた差分”が境界のズレ（残存脆弱性）を生むか
- 出力のどこを見るか（注目点）：
  - default_behavior、invalid_version_behavior、authz_parity、error_model_parity、async_export_parity、cache_isolation
- この例が使えないケース（前提が崩れるケース）：
  - 版が表に出ていなくても、内部で互換モード（feature flag）やdeprecated fieldが存在するため、同様に“差分観測”で実質版を特定する

## 参考（必要最小限）
- OWASP ASVS（認可一貫性、情報漏えい、監査）
- OWASP WSTG（API/Authorization/Error Handling）
- PTES（差分観測で旧版残存を確定）
- MITRE ATT&CK（Discovery：旧版探索）

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/04_api_09_error_model_情報漏えい（例外_スタック）.md`
- `01_topics/02_web/04_api_08_file_export_エクスポート境界（CSV_PDF）.md`
- `01_topics/02_web/03_authz_02_idor_典型パターン（一覧_検索_参照キー）.md`

## 次（04_api_11 以降）に進む前に確認したいこと（必要なら回答）
- 04_api_11（gRPC）では、HTTP/2・メタデータ・サービス定義・リトライ/タイムアウト・ゲートウェイ（grpc-web）など“現実運用の落とし穴”を、認証/認可境界と合わせて最大限詳しく扱う
