## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - この技術で満たす/破れる点：認証（ハンドシェイク時/再接続/トークン更新）、認可（チャネル/トピック/ルーム/購読単位）、セッション管理（長時間接続の失効反映、同時接続数）、入力検証（メッセージスキーマ、巨大payload）、出力制御（他人データ混入防止）、監査（接続/購読/送信の相関）、可用性（接続保持・ブロードキャスト濫用）
  - 支える前提：WebSocket/SSEは“1回認証して長く流す”構造のため、HTTPの前提（リクエスト毎の認証/認可）からズレる。ズレた分がIDOR（購読）・越境混入・失効未反映・再接続穴として現れる。
- WSTG：
  - 該当テスト観点：Authorization Testing（チャネル/トピック単位の境界、購読IDOR）、Session Management（長時間接続、失効/再認証、同時接続）、API Testing（WebSocket/SSEの認証方式、再接続、CORS/Origin）、Input Validation（メッセージの型/サイズ）、Error Handling（エラー差分オラクル）
  - どの観測に対応するか：入口（handshake/subscribe）→継続（push）→再接続（reconnect）→解除（unsubscribe/close）を分解し、(1)認証の運搬、(2)認可の判定点、(3)購読/ルームのIDOR、(4)テナント分離、(5)失効反映、(6)再接続穴、(7)濫用耐性、を差分観測で確定する
- PTES：
  - 該当フェーズ：Information Gathering（WS/SSEの入口URL、プロトコル、トピック/イベント名、再接続仕様）、Vulnerability Analysis（購読境界・失効反映・混線・オラクル）、Exploitation（低侵襲：2ユーザ差分で購読越境/混入を最小件数で証跡化）
  - 前後フェーズとの繋がり（1行）：AuthN（セッション/更新）、AuthZ（IDOR/マルチテナント）、Async（07：イベント配信）、Error model（09）、Versioning（10）、gRPC（11）と同様に“別経路/長時間”で境界が崩れる。12はリアルタイム系の総仕上げとして扱う
- MITRE ATT&CK：
  - 戦術：Collection / Exfiltration / Impact / Discovery
  - 目的：購読越境で継続収集（Collection）、イベントに含まれる機微の取得（Exfiltration）、接続/購読濫用で枯渇（Impact）、イベント名/トピック推定（Discovery）。

## タイトル
websocket_sse_認証・認可境界

## 目的（この技術で到達する状態）
- WebSocket/SSE を「リアルタイム機能」ではなく「長時間接続の認証/認可境界」としてモデル化し、典型事故（購読IDOR、ルーム越境、失効未反映、再接続穴、Origin誤信頼、イベント混線、濫用）を実務ペネトレで差分観測により“確定”できる
- 入口（handshake）だけでなく、継続（push）、再接続、購読変更、切断後の挙動まで含めて評価し、エンジニアが修正できる具体策（サーバ強制scoping、subscribe権限チェック、token更新・再認証、同時接続制御、backpressure/レート、監査）を提示できる
- “HTTPは堅牢でもWS/SSEが穴”を防ぐための共通観測テンプレを持つ

## 前提（対象・範囲・想定）
- 対象
  - WebSocket：双方向（client→server、server→client）
  - SSE：単方向（server→client、HTTPで接続保持）
- 現実の構成例
  - 認証：Cookie（セッション）/Bearer（クエリorヘッダ）/サブプロトコル/初回メッセージでtoken送信
  - 認可：subscribe時にtopic/room/channel を指定（JSONメッセージ）し、以降pushされる
  - 再接続：自動再接続（指数バックオフ）やLast-Event-ID（SSE）
- ペネトレ安全配慮
  - 長時間接続・大量購読は可用性に影響するため、少数トピック・短時間で確認する
  - “取得したイベント内容”は最小限のマスクで証跡化する（08と同型）

## 観測ポイント（何を見ているか：入口→継続→再接続→解除）
### 1) 入口（handshake / connect）での認証：どこにtokenが載るか
- WebSocket handshakeの観測点
  - URL（wss://.../ws）
  - Header（Cookie、Authorization、Sec-WebSocket-Protocol、Origin）
  - クエリ（?token=...）※漏えいリスク高（ログ/Referer）
- SSEの観測点
  - GET /events などのエンドポイント
  - Header（Authorization、Cookie）、Last-Event-ID
- 確定したい点
  - 認証無しで接続できないか
  - tokenがURLに出ていないか（運用上の漏えい）
  - Originを誤って信頼し、CSWSH（Cross-Site WebSocket Hijacking）的に成立しないか

### 2) 認可の単位：接続単位か、購読（subscribe）単位か
- 典型設計
  - 接続確立＝ユーザ確定、購読要求でtopic/roomを指定
- 危険
  - “接続は認証済み”という理由で、subscribe時の権限チェックが抜ける
- 確定したい点
  - subscribeメッセージが存在するか（イベント名/トピック指定）
  - topic/roomを変えた時にサーバがAuthZチェックするか

### 3) 購読IDOR（最重要）：topic/room/channel_id を推測・改変できるか
- 典型IDORパターン
  - `roomId: 123` / `channel: "org_1"` / `projectId: ...`
  - 予測可能な連番・短いID・slug
- 確定したい点
  - Aが購読できるroomをBが購読できないこと（2ユーザ差分）
  - roomIdを変えても同じ挙動（拒否）になること（存在オラクル抑制）

### 4) マルチテナント分離（03接続）：tenantをクライアント指定していないか
- 危険
  - subscribe payloadに tenant_id があり、その値を信頼
  - `x-tenant-id` をフロントが付け、サーバがそれを信頼
- 確定したい点
  - tenantはサーバ強制（token/セッション由来）で決まり、payloadのtenant指定は無効か

### 5) 継続配信（push）中の境界：失効・権限変更が反映されるか
- 典型事故（実務）
  - トークン失効/ログアウト/権限剥奪後も、既存接続が生き続ける
  - 重要操作（step-up）後にのみ配信すべきイベントが、常時配信される
- 確定したい点
  - ログアウト後に接続が切断されるか（またはイベントが止まるか）
  - 権限変更後に購読が無効化されるか（再評価）
  - token更新（refresh/再認証）が必要な設計か

### 6) 再接続（reconnect）：自動再接続が“穴”になっていないか
- 危険
  - 再接続時に認証が省略される（クライアント状態に依存）
  - SSEのLast-Event-IDで、他人のイベントを再取得できる
- 確定したい点
  - 再接続でも同等の認証/認可が必ず実施されるか
  - Last-Event-ID がユーザ/テナントに束縛されているか（IDORにならないか）

### 7) Origin/CORS/CSRF系：WebSocketは“CORSで守られない”前提
- 実務注意
  - WebSocketはCORSとは別の話で、Originチェックはサーバ実装に依存
  - Cookie認証のWSは、CSWSHのリスクが上がる
- 確定したい点
  - Originが適切に検証されているか（許可リスト）
  - Cookie認証の場合、追加のCSRF相当防御（トークン、同一サイト制約）をどうしているか

### 8) メッセージスキーマと入力検証：任意イベント送信・巨大payload
- 危険
  - client→server メッセージで、イベント名やactionが自由に指定できる
  - “管理者用イベント”がクライアントから送れる
  - 巨大payloadでDoS
- 確定したい点
  - 許可されるaction/eventがサーバでallowlistされているか
  - サイズ/レート/バックプレッシャがあるか

### 9) 混線（cross-talk）：他ユーザのイベントが混ざる（キャッシュ/ルーティング/ルーム管理）
- 実務で起きる
  - 接続のユーザ紐付けがバグる、または共有オブジェクトに混ざる
  - pub/sub基盤（Redis等）のチャンネル名が衝突し、tenantが混ざる
- 確定したい点
  - Bが何もしなくてもAのイベントが届く（最悪）
  - 特定条件（同じroom名など）で混線する

### 10) 監査（Observability）：何が起きたか追えるか
- 実務で必要な最小ログ
  - connect/disconnect、actor_id、tenant_id、ip、user-agent
  - subscribe/unsubscribe（topic/room）、結果（allowed/denied）
  - 送信イベント数（レート/濫用検知）
  - trace_id 相当（接続ID・サブスクID）
- 確定したい点
  - 拒否も含めてログが残るか（濫用/探索が見えるか）

### 11) realtime_authz_boundary_key（正規化キー：後続へ渡す）
- 推奨キー：realtime_authz_boundary_key
  - realtime_authz_boundary_key =
    <transport>(websocket|sse|mixed|unknown)
    + <auth_carrier>(cookie|bearer_header|bearer_query|subprotocol|first_message|mixed|unknown)
    + <authz_unit>(connection_only|subscribe_level|message_level|mixed|unknown)
    + <subscription_idor_risk>(none|room_idor|topic_idor|last_event_id_idor|multi|unknown)
    + <tenant_enforcement>(server_forced|client_influenced|weak|unknown)
    + <revocation_handling>(strict_disconnect|stop_events|none|unknown)
    + <reconnect_hardening>(strong|partial|weak|unknown)
    + <origin_hardening>(strong|partial|none|na|unknown)
    + <rate_backpressure>(strong|partial|none|unknown)
    + <audit_strength>(strong|partial|weak|unknown)
    + <confidence>
- 記録の最小フィールド（推奨）
  - connect URL、認証の載り方（ヘッダ/クエリ/初回メッセージ）
  - subscribe payload（topic/roomのキー名）
  - A/Bユーザでの購読差分（成功/拒否）
  - ログアウト/失効後の挙動（接続維持/切断/停止）
  - 再接続時の挙動、Last-Event-IDの束縛
  - レート/サイズ制限の兆候

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える（確定できる）：
  - 認証がどこで成立し、どの経路で漏えいし得るか（query token等）
  - 認可が接続単位/購読単位/メッセージ単位のどこで強制されているか
  - 購読IDOR（room/topic/Last-Event-ID）が成立するか
  - テナント分離がサーバ強制か、クライアント指定で崩れるか
  - 失効・権限変更が既存接続に反映されるか（長時間境界）
  - Originチェック/CSWSH耐性、濫用耐性（レート/バックプレッシャ）
- 推定（根拠付きで言える）：
  - subscribe_levelのAuthZが弱い場合、IDORと組み合わさって継続的なデータ収集が成立しやすい
  - revocation_handlingがnoneの場合、アカウント停止後も情報が流れ続ける可能性が高い
- 言えない（この段階では断定しない）：
  - pub/sub内部実装の健全性（Redis等）を完全には断定できないが、混線の有無は外形で評価できる

## 確認（最大限詳しく：どうやって“確定”したと言えるか）
リアルタイム系は「接続が確立した」だけでは確認にならない。connect→subscribe→受信→再接続→失効反映→解除の一連を、2ユーザ差分で“最小イベント”を使って確定する。以下は、実務で再現性が高い手順に落とす。

### 1) 確認の基本原則（再現性・低侵襲・証拠の強さ）
- 原則1：変数は1つずつ変える（同じ接続・同じsubscribeで、roomIdだけ変える等）
- 原則2：2ユーザ（A/B）を必ず用意し、Aの正当購読とBの不正購読を並べる
- 原則3：イベント内容は最小限の証跡にする（タイトル/件数/メタだけ、機微はマスク）
- 原則4：接続時間を短くし、購読数も最小にする（DoS回避）
- 原則5：SSE/WSそれぞれで、入口と再接続仕様が違うので混ぜずに観測する
- 原則6：確認は“差分証拠”で表現する
  - 例：同一subscribe payloadで、主体だけ変えて成功/拒否が分かれる
  - 例：同一主体で、roomIdだけ変えると、同一の拒否になる（存在オラクルがない）

### 2) ステップA：入口（connect）の確定（認証の載り方を固定）
#### A-1 WebSocket
- 観測
  - handshake request：URL、Cookie/Authorization、Origin、Sec-WebSocket-Protocol
- 最小テスト（順序固定）
  - A1：認証無しで接続 → 期待：拒否（401/403相当 or 即close）
  - A2：不正tokenで接続 → 期待：同様に拒否（詳細差分が出すぎない）
  - A3：有効tokenで接続 → 期待：接続確立（101 Switching Protocols）
- 確認できたと言う条件（証拠）
  - 認証の載り方（cookie/bearer/query/subprotocol/first_message）が確定し、無し/不正/有効で挙動が一貫

#### A-2 SSE
- 観測
  - GET /events のヘッダ（Authorization/Cookie）、レスポンス（text/event-stream）
- 最小テスト
  - token無し/不正/有効の3点で、接続が確立/拒否されることを確認
- 確認できたと言う条件（証拠）
  - SSE接続の認証が毎回強制される（接続だけ通る、が無い）

### 3) ステップB：subscribeモデルの確定（認可単位の特定）
- 目的：AuthZが“接続だけ”なのか、“購読ごと”なのかを確定
- 観測
  - 接続後に送るメッセージの型（例：{"type":"subscribe","topic":"..."}）
  - サーバからのack（success/error）
- 最小テスト
  - B1：subscribe無しで何も流れないか（流れるなら暗黙購読＝注意）
  - B2：subscribeを送ると流れるか（ack/エラーが返るか）
- 確認できたと言う条件（証拠）
  - subscribe payloadのキー名（roomId/topic/channel）が確定し、ackで成功/失敗が観測できる

### 4) ステップC：購読IDORの確定（最重要：2ユーザ差分）
- 目的：room/topic を改変したときに越境購読が成立するかを確定
- 手順（再現性が高い）
  - C1（基準）：Aが正当なroomId=RAを購読し、イベントが届くことを確認
  - C2（攻撃）：BがroomId=RAを購読できるか試す（主体だけ変更）
  - C3（存在オラクル）：Bが存在しないっぽいroomId=RZを購読した時の挙動と比較する
- 確認できたと言う条件（証拠）
  - P0（越境成立）：BでRA購読が成功し、A向けイベントが届く
  - P1（存在オラクル）：RAは“permission denied”、RZは“not found”等で差分が出る
  - 堅牢：RAもRZも同等に拒否され、イベントも届かない（オラクル抑制）

### 5) ステップD：テナント分離の確定（03接続：client指定の無効化）
- 目的：tenant_id をpayload/ヘッダで指定しても結果が変わらない（サーバ強制）ことを確定
- 手順
  - D1：Aで正当購読（tenantはtoken由来）
  - D2：Aがpayloadに別tenant_idを入れてsubscribe（もしキーが存在するなら）
  - D3：結果が変わるか確認
- 確認できたと言う条件（証拠）
  - tenant_idを変えても購読結果/受信内容が変わらない（サーバ強制）
  - tenant_idで変わるなら client-influenced（危険）

### 6) ステップE：失効・ログアウト反映の確定（長時間境界の核心）
- 目的：“接続が生き続ける問題”を確定する
- 手順（副作用を抑える）
  - E1：Aで接続し、イベントが届く状態を作る（短時間）
  - E2：同一ブラウザ/別タブ等でログアウト、またはトークン失効相当を行う
  - E3：その後もイベントが届くか、サーバが切断するかを観測
- 確認できたと言う条件（証拠）
  - strict_disconnect：一定時間内に切断される／以降イベントが止まる（堅牢）
  - none：ログアウト後も流れ続ける（P1〜P0：機微度次第）
- 追加で強い確認（可能なら）
  - ロール剥奪後に購読が止まるか（再評価の有無）

### 7) ステップF：再接続とLast-Event-ID（SSE）の束縛確定
#### F-1 WebSocket再接続
- 手順
  - F1：接続→切断→自動再接続の挙動を観測
  - F2：再接続時に認証が再送されるか（token無しで再接続が成立しないか）
- 確認できたと言う条件（証拠）
  - 再接続でも認証/認可が必ず走る（token無し再接続が不可）

#### F-2 SSE Last-Event-ID
- 手順
  - F3：Last-Event-ID を変えたリクエストを試す（存在する/しないID想定）
  - F4：他ユーザのイベントを再取得できないか（束縛の確認）
- 確認できたと言う条件（証拠）
  - Last-Event-ID が主体/テナントに束縛され、任意IDで過去イベントが引けない

### 8) ステップG：Origin/CSWSH耐性の確定（Cookie認証で最重要）
- 目的：第三者サイトからWS接続を張れてしまうリスクを評価
- 手順（低侵襲）
  - G1：Originが許可リストで検証されているかを確認（拒否/accept）
  - G2：Cookie認証の場合、Originが無制限なら危険
- 確認できたと言う条件（証拠）
  - Originが適切に制限され、想定外Originで接続/購読できない

### 9) ステップH：濫用耐性（レート/バックプレッシャ/サイズ）を“安全に”確定
- 目的：DoSを起こさずに、制御が存在することだけを確認
- 手順
  - H1：購読を短時間に2〜3回繰り返し、429/拒否/遅延が出るか観測
  - H2：payloadサイズ境界を1回だけ越えて拒否されるか観測
- 確認できたと言う条件（証拠）
  - 制御が見える（拒否・切断・エラー分類が適切）
  - 何も制御が見えない場合は“none”として記録（ただし本番で深追いしない）

### 10) “確認できた”と言うための最低限の証跡セット（報告に耐える）
- 接続証跡（3点）
  - token無し / 不正 / 有効 の接続結果（WS: 101 or close、SSE: 200 stream or 401等）
- subscribe証跡（2ユーザ差分）
  - Aの正当購読（成功・イベント受信）
  - Bの同一room/topic購読（成功ならP0、拒否ならその証拠）
- オラクル証跡（あれば強い）
  - “存在するroom”と“存在しないroom”で拒否が揺れる差分
- 失効反映証跡（長時間境界）
  - ログアウト/失効後に切断されるか・イベントが止まるか
- 再接続証跡
  - 再接続時の認証/購読が再評価されること
- 監査/相関（可能なら）
  - 接続ID/サブスクID/trace_id

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- 優先度（P0/P1/P2）
  - P0：
    - BがAのroom/topicを購読できる（購読IDOR）
    - tenant_id をpayloadで変えて越境できる
    - 管理者向けイベント/アクションをclient→serverで送れる
  - P1：
    - 存在オラクル（room存在でエラー差分）
    - ログアウト後もイベントが流れる（機微イベントならP0）
    - Origin無制限（Cookie認証WS）でCSWSH成立余地
    - Last-Event-IDで過去イベントが推測可能
  - P2：
    - 境界は堅牢だがレート/監査が弱い（濫用検知が困難）
- “成立条件”としての整理（技術者が直すべき対象）
  - subscribe/room/topic は必ずサーバ側でAuthZ（接続だけで信頼しない）
  - tenant/主体はサーバ強制（token/セッション）で決定し、client指定を無効化
  - 失効/ログアウトで接続を切る or 以降配信停止（再評価）
  - 再接続時も再認証・再認可（Last-Event-IDも主体束縛）
  - Cookie認証WSはOriginチェック＋追加防御（SameSite、トークン等）
  - レート/バックプレッシャ/サイズ制限と監査を設計に入れる

## 次に試すこと（仮説A/Bの分岐と検証：低侵襲で確定）
- 仮説A：購読IDORがある
  - 検証：
    - Aのroom/topicをBでsubscribe（主体だけ変更）
  - 判断：
    - 受信できる：P0
- 仮説B：失効が反映されない
  - 検証：
    - ログアウト後も受信が続くか
  - 判断：
    - 続く：P1〜P0
- 仮説C：Originチェックが弱い（Cookie WS）
  - 検証：
    - 想定外Originで接続できるか（安全な範囲で）
  - 判断：
    - できる：P1（環境/影響次第で上がる）

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/` ）：
  - `04_labs/02_web/04_api/12_websocket_sse_authz_boundary/`
    - 構成案（現実運用の再現）
      - WebSocket：connect→subscribe→push→unsubscribe
      - SSE：connect（Last-Event-ID対応）→push
      - テナント2つ、ユーザA/B
      - 脆弱切替：
        - subscribe認可ON/OFF（IDOR再現）
        - tenant client指定信頼ON/OFF
        - logout失効反映ON/OFF
        - OriginチェックON/OFF（Cookie認証）
        - Last-Event-ID束縛ON/OFF
        - レート/サイズ制限ON/OFF
      - 監査：connect/subscribe/deny/close を相関キーで記録
- 取得する証跡
  - handshake（WS）/HTTP（SSE）のリクエスト・レスポンス
  - subscribe payload と ack
  - 受信イベントの最小抜粋（マスク）
  - ログアウト/失効後の挙動
  - 再接続の挙動

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
# WebSocket：接続後にsubscribe（擬似メッセージ）
{"type":"subscribe","roomId":"123"}

# SSE：接続（擬似）
GET /events
Accept: text/event-stream
Authorization: Bearer <TOKEN>

# SSE：Last-Event-ID（擬似）
Last-Event-ID: 9999
~~~~
- この例で観測していること：
  - 購読単位のAuthZが存在し、room/topic改変で越境できないか
- 出力のどこを見るか（注目点）：
  - authz_unit、subscription_idor_risk、revocation_handling、reconnect_hardening、origin_hardening、tenant_enforcement
- この例が使えないケース（前提が崩れるケース）：
  - subscribeモデルが無い場合でも、接続URLのパスやクエリでチャネル指定する設計がある。そこで同様に“チャネルID改変”の差分観測を行う

## 参考（必要最小限）
- OWASP ASVS（セッション・認可・監査）
- OWASP WSTG（Authorization/Session）
- PTES（差分観測）
- MITRE ATT&CK（Collection/Impact：リアルタイム濫用）

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/03_authz_02_idor_典型パターン（一覧_検索_参照キー）.md`
- `01_topics/02_web/04_api_07_async_job_権限伝播（キュー_ワーカー）.md`
- `01_topics/02_web/04_api_09_error_model_情報漏えい（例外_スタック）.md`

## 次（次トピック）に進む前に確認したいこと（必要なら回答）
- 次に進む際、04_api配下は一通り揃ったため、運用上は「04_api_00_index.md（入口）」に各ファイルの“使いどころ（どの場面で参照するか）”を追記しておくと、実務で迷子になりにくい
