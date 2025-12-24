## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - この技術で満たす/破れる点：認証（トークン/セッション相当）、認可（メソッド単位・テナント分離）、入力検証（protobufの型/制約・巨大メッセージ）、エラーモデル（10/09と同様に情報漏えい抑制）、通信保護（mTLS/証明書検証/ALPN）、監査（trace_id・呼出し主体・メソッド・結果）
  - 支える前提：gRPCはHTTP/2上で動く“RPC”であり、RESTの前提（URL/verb/ステータスコード、WAF/ログ/認可ミドルウェア）がそのまま通用しない。認可境界は「メソッド」「メタデータ」「Gateway/Proxy」「Interceptor」に散り、ズレるとBOLA/BFLAが復活する。
- WSTG：
  - 該当テスト観点：Authorization Testing（メソッド単位の認可、tenant/roleの強制）、API Testing（gRPC/Transcoding/Grpc-web）、Input Validation（protobufの境界値、ストリーミング）、Error Handling（gRPC status/detailsの漏えい）、Transport（mTLS/証明書/HTTP/2）
  - どの観測に対応するか：gRPCの入口（port/ALPN/Reflection）→呼出し（grpcurl等）→メタデータ（Authorization等）→認可判定（Interceptor/サービス内）→Gateway（REST変換）→ログ/監査、を分解し差分観測で確定する
- PTES：
  - 該当フェーズ：Information Gathering（gRPCサービス/メソッド列挙、proto入手、Reflection有無、Gatewayの有無、内部向けポート発見）、Vulnerability Analysis（認可欠落・ヘッダ/メタデータ信頼・Gatewayズレ・ストリーミング境界）、Exploitation（最小差分：同一メソッドを主体/テナント/権限/入力だけ変えて比較し証跡化）
  - 前後フェーズとの繋がり（1行）：versioning（10）で“旧経路”が残るのと同様、gRPCはGateway/Grpc-web/内部LBなど複数経路が生まれやすい。REST側で直した認可がgRPC直叩きで復活する、または逆、が典型なので04_apiの総仕上げとして扱う
- MITRE ATT&CK：
  - 戦術：Discovery / Privilege Escalation / Collection / Lateral Movement
  - 目的：Reflection/サービス列挙で面を増やす（Discovery）、メソッド認可欠落で高権限操作（Privilege Escalation）、バッチ系RPCで大量取得（Collection）、内部向けgRPCを足掛かりに横展開（Lateral Movement：環境次第）。

## タイトル
grpc_メタデータと認可境界

## 目的（この技術で到達する状態）
- gRPCにおける「認証情報（メタデータ）」「認可判定点（Interceptor / Service / Gateway）」「テナント分離」「内部/外部経路のズレ」を、実務ペネトレで短時間に“確定”できる観測設計を持つ
- REST/GraphQLと同等レベルで、gRPC特有の落とし穴（Reflection、Transcoding、Grpc-web、HTTP/2 proxy、metadata信頼、streaming境界）を整理し、BOLA/BFLAや情報漏えいの成立条件を差分証跡で示せる
- エンジニアが「どこで何を強制するか（Gateway/Interceptor/Service/Envoy）」を具体的に実装へ落とせる（“何を見れば良いか”ではなく“何を直すか”まで）

## 前提（対象・範囲・想定）
- gRPCの現実構成（よくある）
  - 外部：Grpc-web（ブラウザ）→ Envoy/Ingress → gRPC Service
  - 外部：REST（JSON）→ gRPC Transcoding（Gateway）→ gRPC Service
  - 内部：Service-to-Service（mTLS + SPIFFE等）で直叩き
- 入口が増える理由
  - 同一機能が「REST」「Gateway→gRPC」「gRPC直」「Grpc-web」で提供される
  - 認可実装が経路ごとに分散し、差分が生まれる（versioningの“残存面”と同型）
- gRPCの重要要素
  - HTTP/2（ALPN、擬似ヘッダ、ストリーム、HPACK）
  - metadata（HTTPヘッダに近いが、仕様/慣習が異なる）
  - status code（HTTPではなくgRPC status：OK/UNAUTHENTICATED/PERMISSION_DENIED 等）
  - proto（メソッド/型が“攻撃面”の一覧になる）
- ペネトレ上の安全配慮
  - ストリーミングRPCは高負荷になりやすい（少数メッセージ・短時間で確認）
  - message size/デッドライン/リトライが絡むため、過剰リクエストは避ける

## 観測ポイント（何を見ているか：gRPCの境界分解）
### 1) 経路の分解：同じ機能の“入口”が複数あるか（最初に確定）
- 入口パターン
  - gRPC直（通常は 443/8443/50051 等）
  - gRPC-Gateway（REST JSONをHTTP/1.1で受けて内部でgRPCへ）
  - Grpc-web（ブラウザ→envoyで変換）
- 観測で確定したい点
  - 外部からgRPC直が到達できるか
  - “RESTで直した認可”がgRPC直でも効いているか（ズレの有無）
  - 逆に、gRPC側だけ強くてREST側が弱い、がないか

### 2) 認証情報の運搬：metadataに何が入るか（Authorization / Cookie相当）
- よくある認証の運び方
  - `authorization: Bearer <JWT>`（最頻）
  - `x-api-key: ...`（サービス間/外部連携）
  - mTLSクライアント証明書（主体の強固定）
  - 独自ヘッダ（`x-user-id` 等）※危険：信頼境界が崩れやすい
- gRPC metadataの注意点（実務）
  - “-bin” suffix（バイナリ値）や、プロキシで落ちるヘッダがある
  - LB/Proxyがヘッダを付与・上書きする構成がある（envoy/nginx/ingress）
- 観測で確定したい点
  - token無し/不正token/期限切れtoken の挙動が一貫しているか（UNAUTHENTICATED）
  - どのヘッダが“信頼されている”か（危険な `x-user-*` の有無）

### 3) 認可判定点（AuthZ）：Interceptor / Service / Gateway のどこで判定しているか
- 典型の判定点
  - Gateway（HTTP層）で認可し、gRPC Serviceは信頼する（危険：gRPC直でバイパス）
  - gRPC Interceptorで一律に認証/認可（比較的安全）
  - 各Service/Method内で個別に認可（実装漏れが出やすい）
- 観測で確定したい点
  - “gRPC直叩き”で、Gatewayの制限を迂回できないか（最重要）
  - メソッドごとの認可が揃っているか（あるメソッドだけ抜けるのが典型）

### 4) テナント分離（03_multi-tenant接続）：metadata/リクエストにtenant_idがあると危険
- 危険パターン（実務頻出）
  - クライアントが `tenant_id` を送る → サーバがその値を信頼してDBを切る
  - `x-tenant-id` をプロキシが付ける前提だが、外部からも付けられる
- 観測で確定したい点
  - tenantはサーバ強制（tokenのclaim/証明書/サーバサイドセッション）で決まるか
  - リクエストボディ/metadataのtenant指定が効かない（上書きされる）か

### 5) Reflection / proto入手：攻撃面を“一覧化”できるか
- Reflectionが有効だと
  - サービス名/メソッド名/型が列挙でき、未公開メソッド（Admin系）も露出し得る
- ただし“無効なら安全”ではない
  - SDK/モバイル/フロントにprotoが同梱されていることが多い
- 観測で確定したい点
  - Reflection有無（外部から列挙できるか）
  - “内部用メソッド”が外部到達経路に出ていないか

### 6) gRPC status / error details：情報漏えいとオラクル（09接続）
- 漏えいしやすい要素
  - `grpc-status-details-bin` に詳細（スタック/内部理由）が入る
  - “NOT_FOUND vs PERMISSION_DENIED” の揺れで存在オラクル
- 観測で確定したい点
  - 同一IDで権限だけ変えた際に、statusが揺れて存在推定できないか
  - detailsに内部例外名/SQL/内部ホストが出ないか

### 7) Streaming（server/client/bidi）：認可の“継続性”とDoS耐性
- 典型事故
  - 接続確立時だけ認証し、途中のメッセージで権限境界が崩れる（状態遷移/step-up無視）
  - 無制限streamでリソース枯渇（Impact）
- 観測で確定したい点
  - streaming開始後に主体/権限が変わるケース（失効など）に追従するか
  - message size/レート制限/デッドラインが安全か

### 8) Gateway/Transcodingのズレ：RESTとgRPCで“同一操作”の意味が変わる
- 典型事故
  - RESTではフィルタ/列が制限されるが、gRPC直だと自由（03/08と接続）
  - RESTではRBACが効くが、gRPC直だとメソッド側が抜ける
- 観測で確定したい点
  - 同一操作をRESTとgRPCで呼び、結果範囲・認可・エラーを比較（差分観測）

### 9) grpc_authz_metadata_key（正規化キー：後続へ渡す）
- 推奨キー：grpc_authz_metadata_key
  - grpc_authz_metadata_key =
    <exposed_entrypoints>(grpc_direct|gateway|grpc_web|mixed|unknown)
    + <auth_carrier>(bearer|mtls|apikey|custom_header|mixed|unknown)
    + <authz_enforcement_point>(gateway_only|interceptor|service_method|mixed|unknown)
    + <tenant_enforcement>(server_forced|client_influenced|weak|unknown)
    + <reflection_exposure>(on|off|unknown)
    + <status_oracle_risk>(none|exists_oracle|tenant_oracle|state_oracle|multi|unknown)
    + <error_detail_exposure>(none|low|medium|high|unknown)
    + <streaming_controls>(strong|partial|none|na|unknown)
    + <audit_observability>(strong|partial|weak|unknown)
    + <confidence>
- 記録の最小フィールド（推奨）
  - 到達した入口（grpc direct/gateway/grpc-web）
  - サービス/メソッド名（分かる範囲）
  - 認証の運搬（authorization等）
  - 403/404相当（PERMISSION_DENIED/NOT_FOUND等）の差分
  - details-binの有無と内容（機微はマスク）
  - tenant/role差分の観測結果

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える（確定できる）：
  - gRPCの入口がどこまで外部到達可能で、Gatewayの制御を迂回できるか
  - 認証がmetadata/mTLSで運ばれ、どの層で認可されているか（判定点）
  - メソッド単位で認可が揃っているか、抜けがあるか
  - status/詳細の揺れでオラクルが成立していないか（09）
  - Reflection/プロト露出により攻撃面が増えていないか
- 推定（根拠付きで言える）：
  - Gatewayだけで認可している兆候がある場合、gRPC直でBFLA/BOLAが復活しやすい
  - NOT_FOUNDとPERMISSION_DENIEDが揺れる場合、存在列挙が可能になりやすい
- 言えない（この段階では断定しない）：
  - 内部サービス間のmTLS/ID連携の完全性（外部から見えない場合）。ただし外部到達経路がある時点で境界設計の妥当性は評価できる。

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- 優先度（P0/P1/P2）
  - P0：
    - Gatewayでは制限される操作が、gRPC直で成立（認可判定点ズレ＝BFLA/BOLA）
    - admin/内部メソッドが外部から呼べる（Reflection/proto経由で発見）
    - grpc-status-details-bin 等で内部情報（スタック/SQL/内部URL/秘密）が露出
    - テナント分離がmetadata/リクエスト値を信頼して崩れる
  - P1：
    - statusの揺れで存在/テナント/状態オラクルが成立
    - streamingが無制限/制御弱で可用性に影響
    - 旧版経路（10）や別入口（grpc-web）だけ対策が遅れている
  - P2：
    - 主要境界は堅牢だが監査/相関（trace_id等）が弱く、運用上の検知が困難
- “成立条件”としての整理（技術者が直すべき対象）
  - 認可はGatewayだけに置かず、必ずgRPC側（Interceptor/Service）で強制（直叩き耐性）
  - テナント/主体はサーバ強制（token claim / mTLS identity）で決め、クライアント指定を信頼しない
  - Reflectionは外部では無効、または強い認証の内側に限定
  - error detailsは外部に過剰に出さず、trace_idで内部ログに誘導
  - streamingはレート/サイズ/期限/切断の制御を設計に組み込む

## 確認（最大限詳しく：どうやって“確定”したと言えるか）
gRPCの確認は「入口の特定 → サービス/メソッドの特定 → 認証の運び方の確定 → 認可判定点の推定 → 差分観測で立証 → 二次面（Gateway/Reflection/Streaming/Error details）の確認」の順で行う。重要なのは“同一メソッドで、変数を1つだけ変える”差分観測で確定すること。

### 1) 確認の基本原則（再現性・低侵襲・証拠の強さ）
- 原則1：まず入口を固定する（grpc direct / gateway / grpc-web を分けて観測）
  - 同じ機能でも入口が変わると認可が変わり得るため、混ぜない
- 原則2：比較項目を固定する
  - gRPC status（UNAUTHENTICATED / PERMISSION_DENIED / NOT_FOUND / INVALID_ARGUMENT 等）
  - responseの有無、エラーdetailsの有無（grpc-status-details-bin 等）
  - 返却データ範囲（件数/フィールド）
- 原則3：差分観測は“変数を1つだけ”変える
  - 主体（token A/B）、対象（idだけ変更）、テナント（可能なら）、入力型（invalid vs valid）
- 原則4：証跡は“呼出しの再現性”を優先
  - service/method名、endpoint、metadata、status、trace_id を残す
- 原則5：ストリーミングは最小回数・短時間で（DoSを避ける）

### 2) ステップA：gRPC入口の特定（到達性の確定）
- 目的：外部からgRPC直が到達できるか、Gateway経由しか無いかを確定
- 観測方法（低侵襲）
  - 接続確認：対象ホストに対して gRPCらしさ（HTTP/2, ALPN, server header等）を確認
  - 既存のRESTがあるなら、内部でgRPCを使う痕跡（レスポンスヘッダ/エラー/挙動）も手掛かり
- 確認できたと言う条件（証拠）
  - grpc direct（例：443でHTTP/2 + gRPC）に到達し、gRPC呼出しが成立する
  - または、grpc directは不可でGateway/Grpc-webのみが入口であることが観測できる

### 3) ステップB：サービス/メソッドの特定（Reflection / proto / 受動情報）
- 目的：テスト対象を“メソッド名”として固定し、差分観測できる状態にする
- 代表的な確定経路（現実的）
  - Reflectionが有効：サービス一覧とメソッド一覧を列挙できる
  - Reflection無効：protoがクライアント（モバイル/フロント/SDK）に同梱されていることが多い
  - ドキュメント/SDK：メソッド名が露出している場合がある
- 確認できたと言う条件（証拠）
  - 少なくとも1つ、実際に呼び出せる service/method を特定できた（例：HealthCheck 等でも可）
  - 本命は業務メソッド（一覧/検索/更新/管理）を1〜3本固定する

### 4) ステップC：認証の運び方（metadata/mTLS）の確定
- 目的：どの情報が認証に使われるかを確定し、以降の差分観測の基準にする
- 最小の確認セット（順序が重要）
  - C1：認証情報無しで呼ぶ → 期待：UNAUTHENTICATED（または同等）
  - C2：不正な認証情報で呼ぶ → 期待：UNAUTHENTICATED（詳細差分が出すぎない）
  - C3：有効tokenで呼ぶ → 期待：OK か、認可不足なら PERMISSION_DENIED
- 確認できたと言う条件（証拠）
  - token無し/不正token/有効tokenで、statusが一貫して分類される
  - “x-user-id 等の独自ヘッダ”だけで通らない（通るならP0級の疑い）

### 5) ステップD：認可判定点の推定（Gateway only を炙り出す）
- 目的：認可がGatewayに寄っていないか（gRPC直でバイパスできないか）を確定
- 立証の基本：同じ操作を「Gateway経由」と「gRPC直」で比較する
  - D1：REST（Gateway）で403になる操作を確認（同期で拒否される対象を選ぶ）
  - D2：同じ主体/同じ対象で、gRPC直で同等メソッドを呼ぶ
- 確認できたと言う条件（証拠）
  - RESTでは拒否、gRPC直では成功 → 認可判定点ズレ（Gateway onlyの疑いが強い）
  - 両方拒否 → gRPC側でも認可が効いている（堅牢側の証拠）
- 注意：本当に同一操作か
  - メソッドが異なる場合（RESTは集約API、gRPCは低レベルAPI）に差分が出るのは自然なので、対象メソッドの意味（セマンティクス）を揃える

### 6) ステップE：メソッド単位の認可欠落（BOLA/BFLA）の確定
- 目的：特定メソッドだけ認可が抜ける典型を確定する
- 差分観測の設計（強い）
  - E1：読み取り（Get/List）と更新（Update/Delete/Admin）を少なくとも1本ずつテストする
  - E2：同一対象IDで、主体だけ変える（Aは所有者、Bは非所有者）
  - E3：同じメソッドで id を変える（存在するID/存在しないID/他テナントID）
- 確認できたと言う条件（証拠）
  - Bが本来アクセスできない対象IDを、gRPCで取得/更新できる（P0）
  - あるメソッドだけ権限チェックが無い（ListはOKだが AdminUpdate は誰でもOK 等）

### 7) ステップF：テナント分離の確定（metadata/ボディのtenant指定が効かないことを示す）
- 目的：tenantがサーバ強制かどうかを確定する（03と同型）
- 差分観測
  - F1：tokenのtenantと異なるtenant_idをmetadata/ボディに入れてみる
  - F2：結果が変わるか（変わるなら危険）
- 確認できたと言う条件（証拠）
  - tenant_idを入れても無視される（サーバ強制）＝堅牢
  - tenant_idで結果が変わる＝client-influenced（P0/P1）

### 8) ステップG：Reflection/未公開メソッドの露出の確定
- 目的：攻撃面拡大を確定し、優先度を付ける
- 差分観測
  - G1：Reflection有効なら一覧を取得（外部から見えるかが核心）
  - G2：Admin系/Debug系メソッドがあるか
  - G3：呼べるか（認証/認可で止まるか）
- 確認できたと言う条件（証拠）
  - “存在する”だけでも攻撃面（探索コスト低下）
  - “呼べる”なら直ちにP0

### 9) ステップH：エラーdetailsとオラクルの確定（09接続）
- 目的：内部情報漏えい、存在/状態オラクルを確定
- 差分観測（最低限）
  - H1：存在するID（権限無し） → PERMISSION_DENIED
  - H2：存在しないID → NOT_FOUND
  - この差で存在オラクル成立（列挙可能）
- details漏えいの確認
  - INVALID_ARGUMENTを誘発（型違い/必須欠落）し、details-bin/メッセージに内部情報が無いか確認
- 確認できたと言う条件（証拠）
  - statusの揺れ（NOT_FOUND vs PERMISSION_DENIED）を同一メソッドで再現できる
  - detailsにスタック/SQL/内部パスが含まれる（P0）

### 10) ステップI：Streamingの境界（継続認可・制限）の確定
- 目的：長時間接続で境界が崩れないか、DoS耐性を確認
- 差分観測（安全第一）
  - I1：短時間で開始→即切断、を基本にする
  - I2：失効/権限変更が可能な環境なら、開始後に失効させて挙動を見る
  - I3：message size上限（小さい境界値）を1回だけ試し、拒否されるかを見る
- 確認できたと言う条件（証拠）
  - 失効後に継続できない（堅牢）／継続できる（設計要確認）
  - サイズ/レート/期限の制御が見える（拒否/切断/エラー分類）

### 11) “確認できた”と言うための最低限の証跡セット（報告に耐える）
- 入口証跡
  - grpc direct/gateway/grpc-web の到達可否（どれが外部露出か）
- メソッド証跡
  - service/method 名、呼出しに使ったmetadata（機微はマスク）
- 認証証跡（3点）
  - token無し / 不正token / 有効token の status比較
- 認可証跡（最重要）
  - 同一対象IDで、主体だけ変えた差分（成功/拒否）
  - Gateway経由 vs gRPC直 の差分（迂回成立の有無）
- 漏えい/オラクル証跡
  - status揺れ（NOT_FOUND vs PERMISSION_DENIED）
  - details-binの有無と、含まれる内部情報の有無（抜粋・マスク）
- 監査/相関（取れるなら強い）
  - trace_id（外部返却）と内部ログの相関が可能な設計であること

## 次に試すこと（仮説A/Bの分岐と検証：低侵襲で確定）
- 仮説A：Gatewayでしか認可していない（gRPC直で迂回）
  - 検証：
    - RESTで403の操作を、gRPC直で同等メソッド呼出し
  - 判断：
    - 成功：P0
- 仮説B：特定メソッドだけ認可欠落
  - 検証：
    - Read系/Write系を各1本、主体差分で確認
  - 判断：
    - Bで成功：P0
- 仮説C：tenantがclient指定で変わる
  - 検証：
    - tenant_idをmetadata/ボディに入れて挙動比較
  - 判断：
    - 変わる：P0/P1
- 仮説D：details漏えい・statusオラクル
  - 検証：
    - NOT_FOUND/PERMISSION_DENIEDの揺れ、details-bin内容確認
  - 判断：
    - 揺れ/漏えい：P1〜P0

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/` ）：
  - `04_labs/02_web/04_api/11_grpc_metadata_authz_boundary/`
    - 構成案（現実運用の再現）
      - 入口：grpc direct + gateway + grpc-web を用意（ズレを再現しやすい）
      - 認証：Bearer JWT（tenant/role claim）＋ mTLS（任意）
      - 認可の配置を切替：gateway_only / interceptor / method_only
      - Reflection：ON/OFF切替（外部露出/内部限定の差）
      - エラー詳細：details-bin 露出ON/OFF
      - streaming：bidiを1本（制御ON/OFF）
      - 監査：trace_id、actor_id、tenant_id、method、decision を記録
- 取得する証跡（深掘り向け）
  - grpcurl等の呼出しログ（method、metadata、status）
  - gateway経由RESTとgRPC直の差分
  - details-binの中身（機微はマスク）
  - 監査ログの相関（trace_id）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
# サービス列挙（Reflectionが有効な場合）
grpcurl -plaintext <host>:<port> list

# メソッド列挙
grpcurl -plaintext <host>:<port> list <package.Service>

# 認証付き呼出し（Bearer）
grpcurl -H "authorization: Bearer <TOKEN>" -d '{"id":"123"}' <host>:<port> <package.Service/Method>

# エラー差分（存在オラクル例）
# ID_EXISTS（権限無し） -> PERMISSION_DENIED
# ID_NOTFOUND -> NOT_FOUND
~~~~
- この例で観測していること：
  - gRPCの“メソッド単位”で認証/認可が成立し、Gatewayの制御を迂回できないか
- 出力のどこを見るか（注目点）：
  - authz_enforcement_point、status_oracle_risk、error_detail_exposure、tenant_enforcement、reflection_exposure
- この例が使えないケース（前提が崩れるケース）：
  - Reflectionが無効でも、protoがクライアントに存在することが多い。proto/SDK由来でメソッドを固定し同様に差分観測する

## 参考（必要最小限）
- OWASP ASVS（認証・認可・ログ/監査・情報漏えい）
- OWASP WSTG（API/Authorization/Error Handling）
- PTES（差分観測で確定）
- MITRE ATT&CK（Discovery/Privilege Escalation：RPC面の悪用）

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/04_api_10_versioning_互換性と境界（v1_v2）.md`
- `01_topics/02_web/04_api_09_error_model_情報漏えい（例外_スタック）.md`
- `01_topics/02_web/03_authz_03_multi-tenant_分離（org_id_tenant_id）.md`

## 次（04_api_12 以降）に進む前に確認したいこと（必要なら回答）
- 04_api_12（websocket_sse）では、長時間接続・再接続・トークン更新・サブスク範囲・メッセージ単位認可・購読IDORなど、現実運用で破綻しやすい境界を、同じ粒度で最大限深掘りする
