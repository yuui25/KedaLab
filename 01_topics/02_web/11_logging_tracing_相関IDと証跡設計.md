# 11_logging_tracing_相関IDと証跡設計
「どの層で何が起きたか」を"同じID"で追い、監査可能な証跡として残すための設計単位

## 目的（この技術で到達する状態）
- Webアプリ（Browser→BFF→API→DB→Job/Queue→外部SaaS）を跨ぐ処理を、**相関IDで1本の線として追える**状態にする。
- 「ログを出す」ではなく、境界として以下を説明できる：
  - 観測対象（何を見ているか：プロトコル/データ/境界）
  - 観測結果の意味（何が言える/言えない、前提条件）
  - 仮説A/B（相関できない原因が"伝播欠落"か"記録欠落"か"改ざん/欠損"か）
  - 次の一手（実装/運用/監視/検証の優先度）
- 証跡設計として、改ざん耐性・最小化・アクセス制御・保持・検索性を、実務要件に落とせる。

## 前提（対象・範囲・想定）
- 対象：Webアプリケーションのログ/トレース（Browser→BFF→API→DB→Job/Queue→外部SaaS）
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - マイクロサービスアーキテクチャ、非同期処理（Queue/Job）、分散トレーシング
  - CDN/WAF/LB/Ingress等のエッジ、BFF、API Gateway、各マイクロサービス
- できること/やらないこと（安全に検証する範囲）：
  - できる：許可されたスコープ内での観測（ログ/トレースの確認）、相関IDの伝播確認
  - やらない：実際のログ改ざん・機微情報の漏えい、許可されていない対象への検証
- 依存する前提知識（必要最小限）：
  - HTTP/HTTPSの基本、分散トレーシングの基本概念、ログの基本構造
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：
    - 相関ID（Request-ID / Trace-ID / Span-ID）設計と伝播（同期/非同期）
    - 分散トレーシング（traceparent / tracestate / B3 等）の"境界での扱い"
    - 監査ログ（誰が/どこで/何を/どれに/許可or拒否）設計
    - ログの機微保護（トークン/個人情報/秘密情報）とログ注入対策
    - 証跡の完全性（改ざん耐性、WORM、時刻同期、チェーン・オブ・カストディの前提）
  - 扱わない（別ユニットへ接続）：
    - 個別のWAF/SIEM/APM製品の選定・操作手順（本リポジトリの方針上、製品紹介で終えない）
    - 低レベルのOS/基盤ログ設計（必要なら 08_blue-dfir へ接続）

---


## 相関ID設計（Request-ID と Trace-ID を“役割”で分ける）
### 1) 最小セット（まずこれが揃わないと運用が崩れる）
- request_id：1つのHTTPリクエスト（Hop単位）を識別
- trace_id：ユーザ操作から連なる一連の処理（複数Hop/複数リクエスト）を束ねる
- span_id：trace内の区間（各HopやDB呼び出し等）を識別

実務では「request_idだけ」だと、リダイレクト/並列API/再試行で追えなくなるため、trace_id（分散トレーシング）の導入価値が高い。

### 2) 発行責任（誰がIDを発行するか）
- 原則
  - trace_id：入口（Ingress/Gateway または BFF）で発行し、下流へ伝播
  - request_id：各Hopで新規発行してもよいが、trace_idにぶら下げて紐付ける
- 例外（既存運用）
  - クライアントの `X-Request-ID` を採用する運用はあるが、信頼境界が崩れやすい
  - 対応方針は「採用するならサーバ側で正規化し、内部IDを別名で必ず付与する」

### 3) 伝播の規約（ヘッダ/メタデータ）
- HTTP（同期）
  - W3C Trace Context：`traceparent` / `tracestate`
  - 互換枠：`X-Request-ID`（内部用）、`X-Correlation-ID`（運用用）
- WebSocket / SSE
  - 接続確立時のHTTP handshakeで trace_id を決定し、その後のメッセージに “connection_id + trace_id” を紐付ける
- Queue/Job（非同期）
  - メッセージ属性（headers/properties）に `trace_id`, `parent_span_id`, `request_id`, `message_id`, `job_id` を持たせる
  - “再試行”や“DLQ”でも trace_id が維持される設計にする（運用上の追跡に直結）

---

## 監査ログ（Audit）設計：相関IDだけでは足りない“誰が何をしたか”
### 1) 監査ログの目的を固定する（一般ログと分ける）
- 一般ログ（運用/デバッグ）：障害調査、性能、エラーの原因
- 監査ログ（証跡/否認防止）：重要操作の説明責任（誰が/いつ/どこで/何を/どれに/許可or拒否）

監査ログは「量」より「意味」が重要。重要操作の判定点に近いところ（Policy/Service層）で記録する。

### 2) 監査ログの最小フィールド（実務で揉めないための固定）
- 相関
  - trace_id / request_id / span_id
- 主体と境界
  - actor_type（user/service/job）
  - actor_id（user_id / client_id / service_account）
  - on_behalf_of（代理実行なら依頼者）
  - tenant_id / org_id（マルチテナントは必須）
  - session_id（あれば）/ device_id（あれば）/ auth_context（amr/acr/auth_time 等）
- 操作と対象
  - action（例：grant_role / disable_mfa / create_webhook / approve_payment）
  - object_type / object_id（例：invoice:123 / project:abc）
  - decision（allow/deny）と reason（ポリシー名・ルールID・評価結果の要約）
- ネットワーク/クライアント
  - source_ip（信頼できる境界で確定）、user_agent、origin/referer（取得できる範囲）
- 結果
  - status（HTTPステータス/業務結果）、error_code、latency_ms

---

## 機微情報の取り扱い（ログが情報漏えいにならない設計）
### 1) “ログに入れてはいけないもの”を先に決める
- 認証秘密
  - パスワード、MFAシード/回復コード、秘密鍵、セッション秘密、CSRF秘密
- トークン類
  - Authorizationヘッダの生値、Refresh token、ID token/Access tokenの完全値（原則）
- 個人情報/機微データ
  - 必要最小限を超えるPII（住所、氏名、電話など）
  - 決済情報（PAN等）

### 2) それでも必要な場合の“代替”を用意する
- トークンはハッシュ（先頭数文字＋hash）やJTI（識別子）をログ化し、完全値は残さない
- メール等は正規化（例：ドメインは残すがローカル部はマスク）など、用途に応じて段階を定義
- リクエストボディは原則ログ化せず、必要時はサンプリング＋フィールド単位マスキング

---

## ログ注入・ログ偽装の境界（証跡を壊す攻撃を前提にする）
- 文字列に改行や制御文字が混ざると、構造ログが壊れ「別イベント」に見える（監査が崩れる）
- 対応の方向性
  - 構造ログ（JSON等）で出し、入力値はエスケープ/正規化して格納する
  - ヘッダ/クエリ/フォーム入力の “そのまま出力” を避ける（特にUser-Agent/Referer/Origin/filename）
  - 監査ログでは、ユーザ入力を直接フィールドに置かず、別フィールドに隔離して長さ制限・正規化する

（接続先：`05_input_20_crlf_injection_*` と合わせて、ログ破壊を“攻撃者視点で利用”に繋げる）

---

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
- 観測対象（プロトコル/データ構造/やり取りの単位）：
  - 相関ID：request_id（1つのHTTPリクエスト/Hop単位）、trace_id（ユーザ操作から連なる一連の処理/複数Hop/複数リクエスト）、span_id（trace内の区間/各HopやDB呼び出し等）
  - 分散トレーシング：W3C Trace Context（`traceparent` / `tracestate`）、互換枠（`X-Request-ID`、`X-Correlation-ID`）
  - 監査ログ：相関（trace_id / request_id / span_id）、主体と境界（actor_type / actor_id / on_behalf_of / tenant_id / org_id / session_id / device_id / auth_context）、操作と対象（action / object_type / object_id / decision / reason）、ネットワーク/クライアント（source_ip / user_agent / origin / referer）、結果（status / error_code / latency_ms）
  - ログの機微保護：認証秘密（パスワード、MFAシード/回復コード、秘密鍵、セッション秘密、CSRF秘密）、トークン類（Authorizationヘッダの生値、Refresh token、ID token/Access tokenの完全値）、個人情報/機微データ（PII、決済情報）
- 境界の観点：
  - 資産境界（管理主体・委託先・対象範囲の線引き）：
    - ブラウザ（RUM/エラー/操作イベント）、CDN/WAF、LB/Ingress、BFF、API、DB、キャッシュ、ジョブ/キュー、外部SaaS（Webhook/IdP）
    - レスポンスヘッダで request_id / trace_id を返しているか（問い合わせ・運用に直結）
    - フロント計測（エラー/操作イベント）が trace_id と結び付くか
  - 信頼境界（外部連携・第三者・越境ポイント）：
    - クライアントが送ってくる `X-Request-ID` / `traceparent` は"自己申告"になり得る
    - 内部（Gateway/Ingress）が発行するIDは、内部境界の担保（注入不可）とセットで信頼できる
    - 入口で受けた `X-Request-ID` 等を"そのまま信じていないか"（自己申告の混入）
    - 受け取った traceparent を引き継ぐか、別IDへ置換するか（置換するなら対応関係がログで残るか）
  - 権限境界（権限の切替/伝播/委任）：
    - principal（ユーザ/サービス/ジョブ）と、tenant（組織）と、actor（代理実行/On-behalf-of）を分離して記録しないと否認が成立する
    - 認可判定点（policy/guard）での decision を残さないと、成功/失敗の意味が曖昧になる
    - 認可判定点で decision が trace_id と一緒に記録されるか
- 重要なフィールド/差分/状態（「ここが変わると意味が変わる」点）：
  - 相関の連続性：同期（HTTP）では、Hopが増えるたびに「IDが欠落・置換・分岐」しやすい、非同期（Queue/Job）では、さらに「時間の断絶」が入り、親リクエストとの紐付けが消えやすい
  - 証跡の完全性：改ざんされにくい（Write Once / 署名 / 集約）、欠損しにくい（バッファ/再送/バックプレッシャ）、時刻が揃う（NTP/UTC/単調増加）、検索できる（正規化された構造ログ）
  - 重要イベントの観測：認証（login success/failure、MFA challenge/verify、recovery、logout、token refresh/revoke）、認可（deny のログ（理由付き）が残るか）、高影響操作（権限付与、設定変更、連携追加、支払い/承認、データエクスポート）、異常（rate-limit、CSRF、入力検証失敗、WAFブロック、予期せぬリダイレクト/エラー連鎖）
  - ログ注入・ログ偽装：文字列に改行や制御文字が混ざると、構造ログが壊れ「別イベント」に見える（監査が崩れる）

---

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が"確定"できるか：
  - 相関IDが全Hopに一貫しているか（追跡可能）
  - どのHopで欠落するか（伝播欠落の特定）
  - IDがHopごとに置換され対応関係があるか（相関断絶の有無）
  - クライアント自己申告IDを信じているか（信頼境界の崩壊の有無）
  - 監査ログが不足しているか（相関はあるが"誰が何をしたか"が言えない）
- 何が"推定"できるか（推定の根拠/前提）：
  - "ユーザ操作→下流処理→ジョブ"まで追えるため、検知・調査・報告が強い
  - マイクロサービス/非同期で原因究明が崩れる典型。境界は"伝播点"にある
  - "置換自体"はあり得るが、対応表（旧→新）がないと証跡が繋がらない
  - 攻撃者がIDを偽装し、追跡を混乱させたり、他者の事象に見せかける余地がある
  - トレースがあっても否認に弱い。運用監査・事故対応で困る
- 何は"言えない"か（不足情報・観測限界）：
  - 実際の攻撃成功の有無（観測だけでは確定できない）
  - ログ改ざんの有無（改ざん耐性の設計次第）
  - 機微情報の漏えいの有無（ログの機微保護の設計次第）
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：相関IDが全Hopに一貫している（追跡可能）
    - 正常："ユーザ操作→下流処理→ジョブ"まで追えるため、検知・調査・報告が強い
  - パターンB：入口はあるが下流で欠落する（伝播欠落）
    - 異常：マイクロサービス/非同期で原因究明が崩れる典型。境界は"伝播点"にある
  - パターンC：IDがHopごとに置換され対応関係がない（相関断絶）
    - 境界がズレている："置換自体"はあり得るが、対応表（旧→新）がないと証跡が繋がらない
  - パターンD：クライアント自己申告IDを信じている（信頼境界の崩壊）
    - 異常：攻撃者がIDを偽装し、追跡を混乱させたり、他者の事象に見せかける余地がある
  - パターンE：監査ログが不足（相関はあるが"誰が何をしたか"が言えない）
    - 境界がズレている：トレースがあっても否認に弱い。運用監査・事故対応で困る

---

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す"狙い目"：
  - 追跡不能化：相関IDが欠落/分断していると、攻撃の連鎖（入口→権限→影響）が繋がらず、封じ込めが遅れる
  - ノイズ埋め（大量リクエストで調査不能化）：構造化されていないログ、相関キーが弱いログは検索・集計が破綻しやすい
  - ログ偽装/注入：改行や制御文字でログを壊せると、監査や検知ロジックが誤作動する（証跡の信頼性が崩れる）
  - 機微混入の悪用：ログにトークンや個人情報が混ざると、ログ閲覧権限が事実上の"特権"になり、横展開や情報漏えいの二次被害になる
- 優先度の付け方（時間制約がある場合の順序）：
  1. 相関IDの伝播確認（Browser→Edge→BFF→API→Job）
  2. 監査ログの有無と内容（action/object/decision/reason）
  3. ログ注入・ログ偽装の対策（構造ログ、エスケープ/正規化）
  4. 機微情報の取り扱い（マスキング/最小化）
- 代表的な攻め筋（この観測から自然に繋がるもの）：
  - 攻め筋1：追跡不能化
    - 成立条件：相関IDが欠落/分断している
    - 結果：攻撃の連鎖（入口→権限→影響）が繋がらず、封じ込めが遅れる
  - 攻め筋2：ノイズ埋め（大量リクエストで調査不能化）
    - 成立条件：構造化されていないログ、相関キーが弱いログ
    - 結果：検索・集計が破綻しやすい
  - 攻め筋3：ログ偽装/注入
    - 成立条件：改行や制御文字でログを壊せる
    - 結果：監査や検知ロジックが誤作動する（証跡の信頼性が崩れる）
  - 攻め筋4：機微混入の悪用
    - 成立条件：ログにトークンや個人情報が混ざる
    - 結果：ログ閲覧権限が事実上の"特権"になり、横展開や情報漏えいの二次被害になる
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）：
  - マイクロサービス/非同期環境では、相関IDの伝播が崩れやすいため、伝播点を優先的に確認
  - クライアント自己申告IDを信じている場合、入口で正規化（内部ID付与）が必要
  - 監査ログが不足している場合、重要操作の判定点で監査ログを追加する必要がある

---

## 次に試すこと（仮説A/Bの分岐と検証）
> ここが最重要。条件が違うと次の手が変わる形で書く。

- 仮説A：相関IDの"伝播"が問題（欠落/置換/非同期で消える）
  - 成立条件：入口はあるが下流で欠落する、またはIDがHopごとに置換され対応関係がない
  - 次の検証：
    1) 入口で trace_id を発行しているか（Edge/BFF）
    2) HTTPヘッダ（traceparent等）が下流へ渡っているか（Hopごとに観測）
    3) Queue/Jobのメタデータに trace_id が積まれているか（投入/実行の双方）
    4) 置換があるなら、parent/linked をログに残す設計へ是正
  - 期待する観測（成功/失敗時に何が見えるか）：
    - 成功：相関IDが全Hopに一貫している（追跡可能）
    - 失敗：どのHopで欠落するかを特定し、ヘッダ/メタデータの規約とミドルウェア実装を是正する（優先度高）
- 仮説B：記録の"意味"が問題（誰が/何を/許可or拒否が残らない）
  - 成立条件：監査ログが不足（相関はあるが"誰が何をしたか"が言えない）
  - 次の検証：
    1) 重要操作の一覧を作り、監査ログを「判定点」で出す（UI層ではなくService/Policy寄り）
    2) principal/tenant/action/object/decision/reason を最小セットとして固定
    3) deny（拒否）も必ず残す（攻撃・誤設定の検知に直結）
    4) 監査ログの保持・改ざん耐性・アクセス制御を運用要件に落とす
  - 期待する観測：
    - 成功：監査ログの意味（action/object/decision）が十分か、機微が混入していないか、へ評価を進める
    - 失敗：トレースがあっても否認に弱い。運用監査・事故対応で困る
- 仮説C：証跡の"完全性"が問題（欠損/時刻ずれ/改ざん余地）
  - 成立条件：ログが揃っても、改ざん・欠損・時刻ずれ・注入で証拠として崩れる
  - 次の検証：
    1) 時刻同期（NTP/UTC）とタイムスタンプ形式を統一
    2) 集約先を一元化し、書き込み権限と閲覧権限を分離
    3) 欠損検知（配送失敗、遅延、バッファ溢れ）をメトリクス化
    4) WORM/署名/改ざん検知など、証跡としての要件を明文化
  - 期待する観測：
    - 成功：改ざんされにくい（Write Once / 署名 / 集約）、欠損しにくい（バッファ/再送/バックプレッシャ）、時刻が揃う（NTP/UTC/単調増加）、検索できる（正規化された構造ログ）
    - 失敗：ログ配送の欠損（バッファあふれ、ネットワーク断）を検知できない、時刻が揃っていない（サービス間で秒単位のズレがあると相関が崩れる）

---

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/02_web/11_logging_tracing_01_request_trace_propagation_hops/`（候補）
    - `04_labs/02_web/11_logging_tracing_02_async_job_context_linking/`（候補）
    - `04_labs/02_web/11_logging_tracing_03_audit_log_minset_and_redaction/`（候補）
- 取得する証跡（目的ベースで最小限）：
  - HTTPヘッダ（traceparent / tracestate / X-Request-ID / X-Correlation-ID）
  - メッセージ属性（Queue/Jobのheaders/properties：trace_id / parent_span_id / request_id / message_id / job_id）
  - 構造ログ（JSON等：trace_id / request_id / span_id / principal / tenant / action / object / decision / reason）
  - 監査ログ（principal / tenant / action / object / decision / reason / request_id）
- 観測の取り方（どの視点で差分を見るか）：
  - Hop別に見る（Browser→Edge→BFF→API→Job）
    - Browser：レスポンスヘッダで request_id / trace_id を返しているか、フロント計測（エラー/操作イベント）が trace_id と結び付くか
    - Edge（CDN/WAF/LB/Ingress）：入口で trace_id を発行しているか、下流へ伝播しているか、入口で受けた `X-Request-ID` 等を"そのまま信じていないか"
    - BFF/API：受け取った traceparent を引き継ぐか、別IDへ置換するか、認可判定点で decision が trace_id と一緒に記録されるか
    - Job/Queue：メッセージに trace_id が積まれ、ワーカーがそれを採用してログ/監査に残すか
  - 重要イベントの観測：認証（login success/failure、MFA challenge/verify、recovery、logout、token refresh/revoke）、認可（deny のログ（理由付き）が残るか）、高影響操作（権限付与、設定変更、連携追加、支払い/承認、データエクスポート）、異常（rate-limit、CSRF、入力検証失敗、WAFブロック、予期せぬリダイレクト/エラー連鎖）
  - 証跡の完全性：ログ配送の欠損（バッファあふれ、ネットワーク断）を検知できるか、時刻が揃っているか、アクセス制御（誰がログを見られるか）と改ざん防止（WORM/権限分離）の前提があるか
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/logging_tracing 2>/dev/null
    cd ~/keda_evidence/logging_tracing
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可されたスコープ** のみ
      - 観測は **代表点の抽出** のみ（全サービスを網羅しない）
      - ログの機微保護は **読み取りのみ**（改ざんは行わない）
  - 相関キー（最低限）を作る（後で必ず効く）
    - Host（対象ドメイン）
    - Path（対象パス）
    - Time（観測時刻）
    - Trace-ID（ユーザ操作から連なる一連の処理）
    - Request-ID（1つのHTTPリクエスト/Hop単位）
    - Span-ID（trace内の区間）
    - Principal（ユーザ/サービス/ジョブ）
    - Tenant（組織）
    - Action（操作）
    - Object（対象）
    - Decision（許可/拒否）
    - Reason（ポリシー/理由）

---

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は"手段"であり"結論"ではない。必ず「何を観測している例か」を添える。

~~~~
# 目標：
# - 1つのユーザ操作が、複数サービス/ジョブに跨っても trace_id で追える
# - 重要操作は、auditログで actor/tenant/action/object/decision が追える
# - ログに token/PII を混入させず、注入で壊れない（構造ログ＋正規化）

# 推奨の"ログ1行に必ず入れる"最小セット（例）
# - ts, level, service, env
# - trace_id, span_id, request_id
# - principal(user/service/job), tenant_id
# - http.method, http.path, http.status, latency_ms
# - decision(allow/deny) は重要操作/認可判定点で必ず
~~~~

- この例で観測していること：
  - 1つのユーザ操作が、複数サービス/ジョブに跨っても trace_id で追える
  - 重要操作は、auditログで actor/tenant/action/object/decision が追える
  - ログに token/PII を混入させず、注入で壊れない（構造ログ＋正規化）
- 出力のどこを見るか（注目点）：
  - HTTPヘッダ：traceparent / tracestate / X-Request-ID / X-Correlation-ID
  - 構造ログ：trace_id / request_id / span_id / principal / tenant / action / object / decision / reason
  - 監査ログ：principal / tenant / action / object / decision / reason / request_id
  - ログの機微保護：認証秘密、トークン類、個人情報/機微データが混入していないか
- この例が使えないケース（前提が崩れるケース）：
  - 許可されていないスコープへの検証（倫理・法的問題）
  - 実際のログ改ざん・機微情報の漏えい（目的は観測であり、攻撃ではない）
  - 個別のWAF/SIEM/APM製品の選定・操作手順（本リポジトリの方針上、製品紹介で終えない）

---

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：ログ/監査、相関ID、証跡設計
  - 該当要件（可能ならID）：ログ/監査、相関ID、証跡設計
  - このファイルの内容が「満たす/破れる」ポイント：
    - 破れる：認証・認可・入力防御が一定でも、ログが「追えない」「改ざんされる」「機微が漏れる」「相関できない」状態だと、(1) 侵害の検知・封じ込め・原因究明ができない、(2) 重要操作の証跡が残らず否認に弱い、(3) ログ自体が情報漏えい（トークン/個人情報）になる、(4) ログ注入（改行/CRLF）で監査が崩れる、が現実に起きる。結果として"安全に運用できる境界"が成立しない。
    - 満たす：相関ID（request/trace）と、主体（principal）・テナント（tenant）・操作（action）・対象（object）・判断（decision）を最小セットとして一貫記録し、改ざん耐性（WORM/署名/集中管理）と機微保護（マスキング/最小化）を設計要件化する。さらに、同期（API）だけでなく非同期（ジョブ/キュー）まで"同じ相関"で追えるようにする。
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：ログ/監査、相関ID、証跡設計
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：
    - 脆弱性の有無だけでなく、検証で得られた事象を「再現・説明・証跡化」できるかが品質になる。テストは (1) 相関IDが各Hopに伝播するか、(2) 認証/認可の判定点がログ化されるか、(3) 異常（失敗/拒否/レート制限/CSRF等）が可観測か、(4) ログ注入や機微混入が起きないか、を観測で確定する。
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Recon、Exploitation、Reporting
  - 前後フェーズとの繋がり（1行）：
    - Recon〜Exploitationの"結果"を、Reportingで説得力ある根拠に変えるための基盤。攻撃成立の証跡（リクエスト/レスポンス/相関ID/監査ログ）を揃え、同時に運用是正（検知・追跡・封じ込め）へ繋げる。特にマイクロサービス/非同期では、相関ID設計がないと「どこで何が起きたか」が崩れて評価が曖昧になる。
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Defense Evasion（T1562）、Collection（T1005）
  - 攻撃者の目的（この技術が支える意図）：
    - 攻撃者は痕跡を残さない/分断する方向に動く（例：ログ無効化・ログ改ざん・相関不能化・大量ノイズ）。防御側は相関IDと監査ログで「行為の連鎖（Discovery→Credential→Lateral/Impact）」を繋ぐ。
    - 本ファイルはATT&CKの網羅ではなく、(a) 攻撃者が"隠す/分断する"対象としてログが狙われる、(b) 相関設計があると検知・追跡の目的に直接効く、という接続を明示する。
  - 参照：https://attack.mitre.org/tactics/TA0005/（Defense Evasion）、https://attack.mitre.org/tactics/TA0009/（Collection）

## 参考（必要最小限）
- W3C Trace Context - https://www.w3.org/TR/trace-context/
- OpenTelemetry - https://opentelemetry.io/
- OWASP: Logging Cheat Sheet - https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- NIST: Guide to Computer Security Log Management - https://csrc.nist.gov/publications/detail/sp/800-92/final

## リポジトリ内リンク（最大3つまで）
- 関連 topics：
  - `01_topics/02_web/10_authn_to_authz_接続（claims_権限伝播）.md`（権限伝播）
  - `01_topics/02_web/04_api_01_権限伝播モデル（フロント_バックエンド_ジョブ）.md`（API連携の詳細）
  - `01_topics/02_web/03_authz_06_privileged_action_重要操作（承認_送金_権限）.md`（重要操作の境界）
- 関連 playbooks：
  - （該当するplaybookがあれば記載）
- 関連 labs / cases：
  - `04_labs/02_web/11_logging_tracing_01_request_trace_propagation_hops/`（候補）
  - `04_labs/02_web/11_logging_tracing_02_async_job_context_linking/`（候補）
  - `04_labs/02_web/11_logging_tracing_03_audit_log_minset_and_redaction/`（候補）

---

## 深掘りリンク（最大8）
- `01_topics/02_web/10_authn_to_authz_接続（claims_権限伝播）.md`
- `01_topics/02_web/04_api_01_権限伝播モデル（フロント_バックエンド_ジョブ）.md`
- `01_topics/02_web/04_api_09_error_model_情報漏えい（例外_スタック）.md`
- `01_topics/02_web/05_input_20_crlf_injection_01_response_splitting（header_body）.md`
- `01_topics/02_web/05_input_20_crlf_injection_02_downstream（proxy_log_cache）.md`
- `01_topics/02_web/06_config_02_Secrets管理と漏えい経路（JS_ログ_設定_クラウド）.md`
- `01_topics/02_web/02_authn_02_session_lifecycle（更新_失効_固定化_ローテーション）.md`
- `01_topics/02_web/03_authz_06_privileged_action_重要操作（承認_送金_権限）.md`
