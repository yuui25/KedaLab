## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - この技術で満たす/破れる点：信頼境界（第三者からの入力の真正性）、認証・認可（イベント発生源の確認、テナント束縛）、入力検証（payload/headers）、再送・重複耐性（idempotency）、監査（イベント受領と処理結果）、可用性（濫用・再送スパム）
  - 支える前提：Webhook受信は「外部から内部処理（状態遷移・課金・権限変更）」へ直結しやすい。署名検証と再送（replay/重複）耐性が弱いと、偽装イベント・二重実行・不正状態遷移が現実的に成立する。
- WSTG：
  - 該当テスト観点：API Testing（署名検証、ヘッダ、時刻、再送）、Authorization Testing（テナント束縛：どの顧客のイベントか）、Business Logic（状態遷移・二重実行）、Error Handling（エラー差分による情報漏えい）
  - どの観測に対応するか：Webhookの「真正性（署名/mTLS）」「再送（timestamp/nonce/event_id）」「処理の副作用（状態遷移/課金）」を、低侵襲の差分（正/不正/重複/期限切れ）で確定する
- PTES：
  - 該当フェーズ：Information Gathering（受信エンドポイント/ヘッダ仕様/署名方式の把握）、Vulnerability Analysis（署名未検証/不備、replay、idempotency欠如、tenant混線）、Exploitation（最小差分での成立条件確定：副作用を最小化）
  - 前後フェーズとの繋がり（1行）：REST filtersの「クライアント入力を信頼しない」「上限/監査」を、Webhookでは「送信者の真正性」「再送・重複・順序」を軸に具体化し、次の05（送信側SSRF）と06（idempotency）へ地続きで接続する
- MITRE ATT&CK：
  - 戦術：Initial Access / Persistence / Impact / Defense Evasion
  - 目的：偽装Webhookで状態遷移や権限操作を誘発（Impact）、再送で二重実行（Impact）、監査を回避する入力形状（Defense Evasion）。Webhookは“境界の内側”に影響を与える入口。

## タイトル
webhook_受信側の信頼境界（署名_再送）

## 目的（この技術で到達する状態）
- Webhook受信を「外部入力→内部副作用」へ繋がる信頼境界としてモデル化し、(1)真正性（署名/mTLS）、(2)テナント束縛、(3)再送・重複耐性（replay/idempotency）、(4)順序/欠落の扱い、(5)エラーと監査、(6)濫用耐性、を観測・判断・是正提案まで落とし込める
- ペネトレとして、DoSや本番破壊を避けつつ「署名検証の有無」「replay耐性の有無」「二重実行の影響」を少数の差分リクエストで証跡化できる
- エンジニアが“何を実装/設定すべきか”を、署名仕様・時刻検証・イベントID・処理の非同期化・監査設計として具体化できる

## 前提（対象・範囲・想定）
- 対象：第三者サービス（決済、IDaaS、SaaS、Git、監視、配送等）から受信するWebhook
- 典型アーキテクチャ（現実的）
  - インターネット到達可能なWebhook endpoint（/webhooks/provider）
  - 受信→検証→キュー投入→ワーカー処理（非同期）で副作用を実行（推奨）
  - 署名方式：HMAC（多い）、公開鍵署名（JWS等）、mTLS（少数だが強い）
  - 再送：プロバイダ側が失敗時に再送（at-least-once delivery）
- 前提の重要点
  - “再送は正常”であり、重複を前提に設計しないと業務が壊れる
  - “送信元IP固定”は現実に崩れやすい（CDN/クラウド変更）ため、署名検証が本体
- 検証の安全な範囲（ペネトレ）
  - 副作用が発生するイベント（課金、権限付与、取消）はテスト環境/テストテナントで行う
  - 本番では、署名検証の“拒否挙動”と監査（受領ログ）中心に観測する

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) Webhook受信の責務分離：受信（verify）と処理（apply）を分ける
- 強い設計（推奨）
  - 受信層：署名/時刻/重複チェックを行い、即200/202で返しキューへ
  - 処理層：内部認可（テナント束縛/状態遷移）と副作用を実行
- 危険な設計
  - 受信ハンドラが同期でDB更新・課金等を実行（遅延→再送→二重実行）
  - 署名検証前に処理を開始（TOCTOU）
- 観測で確定したい点
  - 応答が早いか（非同期化の兆候）
  - 受信時点で検証に失敗した場合の応答（明確に拒否するか）

### 2) 真正性（authenticity）：署名検証は“正しく・完全に・恒常的に”行う
#### 2.1 HMAC署名（Stripe/GitHubなどに多い）
- 検証の必須要件（成立条件として）
  - 署名対象が “生のHTTPボディ（raw body）” に対して計算されている（JSONを再シリアライズすると破綻）
  - secretがテナント/エンドポイントに紐づく（共通secretは事故りやすい）
  - 比較は定数時間（timing回避は実務では“できれば”だが、まずは検証の有無が本体）
- 典型の検証ミス（現実頻出）
  - signatureヘッダを見ているだけで検証していない（ログ目的）
  - JSONパース後の文字列で署名を計算してしまい、検証が常に失敗→例外パスで通す
  - secretが環境/顧客で使い回し
- 観測で確定したい点（低侵襲）
  - signature欠落/改変で拒否されるか
  - content-typeや改行差分で挙動が変わらないか（raw body扱いの兆候）

#### 2.2 公開鍵署名（JWS等）
- 強い点
  - 送信者が鍵ローテーションしても追従しやすい（JWKSなど）
- 注意点（運用）
  - 鍵取得（JWKS）をSSRF的に使わせない（“鍵URLを入力”させない）
  - kid/alg混乱、許可アルゴリズムの固定
- 観測で確定したい点
  - algが固定されているか、署名無し/noneの受理が無いか
  - 鍵ローテーション時の挙動（失敗時は拒否が基本）

#### 2.3 mTLS（相互TLS）
- 強い点
  - 送信元の証明書で真正性を強く担保
- 現実的な落とし穴
  - mTLSは“経路の認証”であり、payloadの再送/順序/重複は別問題
- 観測で確定したい点
  - mTLSがある場合でも、replay/idempotencyが実装されているか

### 3) テナント束縛（03）：Webhookは“どの顧客のイベントか”が最大の境界
- 典型のマッピング
  - provider_account_id（Stripe account 等）→ tenant_id
  - event内のcustomer_id/subscription_id → tenantのリソース
- 危険な兆候（現実頻出）
  - tenant_idをクエリやヘッダで受け取り、それを信頼して処理（client-influenced）
  - 1つのendpointで全テナントを受け、ルーティングが曖昧（誤紐付け）
- 観測で確定したい点
  - tenantの同定が “署名で守られたpayloadの識別子” から行われるか
  - tenant同定に失敗した場合の挙動（拒否・隔離・監査）

### 4) 再送（replay）と重複：Webhookは“少なくとも一回届く”前提
#### 4.1 replay対策（時間・一意性）
- 実運用の推奨（あなたの指示に沿う）
  - timestamp検証（受信時刻と許容ウィンドウ）
  - nonce/event_id の一意性検証（重複拒否）
  - idempotency（副作用を一度だけ適用）
- 注意点
  - timestampだけでは不十分（ウィンドウ内で再送される）
  - nonceだけでも不十分（永続保存/TTLが必要、競合もある）
- 観測で確定したい点（低侵襲）
  - 同一イベント（同一id）を再送すると、二度目が拒否/無害化されるか
  - timestampが古い/未来のとき拒否されるか（許容幅があるか）

#### 4.2 重複処理が引き起こす事故（06/10と接続）
- 代表例（Impactが大きい）
  - 二重課金、二重払い戻し
  - ロック解除の重複（影響小に見えるが監査が壊れる）
  - 状態遷移の二重実行（approvedが二回走る等）
- 観測で確定したい点
  - “二回目が同じ結果で終わる” か（idempotent）
  - “二回目が例外で落ちる” 場合、プロバイダが再送を続けて更に事故が増える

### 5) 順序（ordering）と欠落（loss）：現実は並び替わる、欠ける
- 典型現象
  - A→Bの順で送られたが、受信はB→A
  - 一部が遅延して後から届く
  - 一部が失敗して再送される
- 防御（設計）
  - イベントの“最終状態”を参照して適用（source of truthに照会）する戦略
  - 状態遷移を単純な増分ではなく、整合が取れる形にする（10）
- 観測で確定したい点
  - 受信側が順序前提で壊れないか（古いイベントで巻き戻らないか）
  - “イベント欠落”を検知できるか（監査・メトリクス）

### 6) エラーと応答：Webhookは応答コードが再送挙動を決める
- 現実的な推奨
  - 検証失敗（署名不正/期限外/重複）は 4xx で明確に拒否（再送不要）
  - 一時障害は 5xx で再送を許す（ただし重複耐性が前提）
  - 受信後の処理は非同期化し、受信は200/202で早く返す（再送抑制）
- 危険な兆候
  - 例外で常に500（署名不正でも500）→プロバイダが再送し続ける
  - エラー本文に内部情報（stack/secret取り扱い）を出す（04_api_09へ）
- 観測で確定したい点
  - 署名不正・重複・期限外が明確に区別されるか（監査上も重要）
  - trace_id が返る/ログに残るか

### 7) 監査（監視/調査）：受信は“証跡”がないと守れない
- 監査の最小フィールド（推奨）
  - provider、endpoint、received_at、event_id/nonce、timestamp、signature_valid（yes/no）
  - tenant_id（マッピング結果）、decision（accept/reject）、reject_reason
  - processing_status（queued/processed/failed）、attempt_count（再送回数）
  - trace_id/request_id（相関）
- 観測で確定したい点
  - 受信ログが必ず残るか（拒否も残るか）
  - “同一event_idの再送”を追えるか（重複検知の裏付け）

### 8) 濫用耐性：Webhookは“外部からの連打”が現実に起きる
- 現実的な対策（運用）
  - providerごとのレート制御（IPだけに依存しない）
  - 署名検証を先に行い、重い処理は後段（キュー）に逃がす
  - エンドポイントを推測されにくい形（ただし秘密URLだけに依存しない）
- 観測で確定したい点
  - 署名不正の大量入力で内部処理が重くならないか（検証コストも含む）
  - レート制御の有無（429等）

### 9) webhook_receiver_trust_boundary_key（正規化キー：後続へ渡す）
- 推奨キー：webhook_receiver_trust_boundary_key
  - webhook_receiver_trust_boundary_key =
    <authenticity>(hmac|public_key|mtls|none|mixed|unknown)
    + <signature_enforcement>(strict|partial|none|unknown)
    + <tenant_binding>(strong|weak|client_influenced|unknown)
    + <replay_controls>(timestamp|nonce|event_id|mixed|none|unknown)
    + <idempotency>(strong|partial|none|unknown)
    + <ordering_strategy>(robust|assumes_order|unknown)
    + <processing_model>(async_queue|sync|mixed|unknown)
    + <response_policy>(4xx_on_invalid|500_leaky|unknown)
    + <abuse_controls>(rate|waf|none|unknown)
    + <audit_strength>(strong|partial|weak|unknown)
    + <confidence>
- 記録の最小フィールド（推奨）
  - endpoint、provider、署名ヘッダ仕様（存在/形式）
  - 署名欠落/改変/期限外/重複の挙動差分
  - tenantマッピング根拠（payloadの何を使うか）
  - 応答コード方針（再送に影響）
  - evidence（HAR差分、ログ断片、監査記録）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える（確定できる）：
  - 署名/真正性が“必須”として強制されているか（欠落/改変で拒否されるか）
  - replay（再送/重複）に対して、無害化（idempotency）できる設計か
  - テナント束縛が強いか（client_influencedが残っていないか）
  - 応答コードとエラーモデルが再送挙動を悪化させないか
  - 監査（拒否含む）が整備され、調査可能か
- 推定（根拠付きで言える）：
  - 署名検証が弱い場合、偽装イベントによる状態操作が現実的
  - idempotency/重複耐性が弱い場合、プロバイダ再送が事故を増幅する
- 言えない（この段階では断定しない）：
  - プロバイダの正確な再送アルゴリズム（実装差）。ただし受信側は“少なくとも一回”で設計すべき、という結論は変わらない。

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- 優先度（P0/P1/P2）
  - P0：
    - signature欠落/改変でも受理（署名未検証/例外パス）
    - tenant束縛がクライアント指定で、他テナントへ副作用が届く（03崩壊）
    - 同一event_id再送で副作用が二重実行（課金/権限/状態遷移）
    - 署名不正でも500を返し再送嵐を誘発（可用性・事故増幅）
  - P1：
    - timestampはあるがnonce/event_id重複検知が無い（ウィンドウ内replay）
    - エラーがオラクル/情報漏えい（04_api_09）
    - 受信が同期処理で遅い（再送が起きやすい）
  - P2：
    - 設計は堅牢だが監査が弱く、調査・否認防止が困難
- “成立条件”としての整理（技術者が直すべき対象）
  - 署名検証は raw body で厳密に行い、失敗は4xxで拒否
  - tenant同定は署名で保護されたpayloadの識別子から行い、外部入力のtenant指定を信頼しない
  - replay対策（timestamp+nonce/event_id）＋idempotencyで“再送前提”にする
  - 受信は非同期化し、処理失敗で再送が増殖しないよう設計する
  - 監査（受領/拒否/処理）を必須化し、trace_idで相関可能にする

## 次に試すこと（仮説A/Bの分岐と検証：低侵襲で成立条件を確定）
- 仮説A：署名検証が無い/弱い
  - 次の検証（差分）：
    - signatureヘッダ欠落/改変での応答差分（拒否か、受理か）
  - 判断：
    - 受理：P0
- 仮説B：replay/重複が無害化されていない
  - 次の検証（差分）：
    - 同一event_idを少数回再送し、二回目の扱い（拒否/無害化/二重実行）を観測
  - 判断：
    - 二重実行：P0
- 仮説C：timestamp検証が無い/緩い
  - 次の検証：
    - 古い/未来のtimestamp相当の差分（許容幅の有無）を観測
  - 判断：
    - 無制限受理：P1（replay耐性弱）
- 仮説D：tenant束縛が弱い
  - 次の検証：
    - tenant同定に外部入力（query/header）が使われていないか、挙動差分で推定
  - 判断：
    - client_influenced：P0

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/` ）：
  - `04_labs/02_web/04_api/04_webhook_receiver_trust_boundary/`
    - 構成案（現実運用の再現）
      - provider模擬：署名付き送信、再送、順序入替、遅延を再現
      - 署名：HMAC/公開鍵/mTLSを切替
      - replay：timestamp窓、event_id重複検知（DB/Redis）を切替
      - 処理：同期/非同期（キュー）を切替、idempotency有無を比較
      - 監査：受領・拒否・処理の各ログを必須化（trace_id）
- 取得する証跡（深掘り向け：HTTP＋周辺ログ）
  - HTTP：署名欠落/改変/重複/期限外の応答差分
  - ログ：signature_valid、reject_reason、event_id、tenant_id、attempt_count、trace_id
  - 処理ログ：副作用が一回だけ適用されたこと（idempotencyの裏付け）
  - メトリクス：再送回数、拒否率（運用価値）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
# Webhook受信（擬似）
POST /webhooks/providerX
Headers:
  X-Signature: ...
  X-Timestamp: ...
Body:
  { "id": "evt_123", "account": "acct_789", "type": "payment.succeeded", ... }

# 観測の差分（擬似）
- X-Signature を欠落させる / 改変する
- 同一 id（evt_123）を再送する（少数回）
- timestamp を古くする/未来にする（許容窓があるか）

# 見るべき結果（擬似）
- 署名不正は4xxで拒否されるか（再送させない）
- 重複は無害化されるか（副作用が二度起きない）
- tenant同定がpayload由来で強制されるか
~~~~
- この例で観測していること：
  - Webhook受信の信頼境界（真正性＋replay/重複耐性＋tenant束縛）が成立しているか
- 出力のどこを見るか（注目点）：
  - signature_enforcement、replay_controls、idempotency、tenant_binding、processing_model、response_policy、audit_strength
- この例が使えないケース（前提が崩れるケース）：
  - 受信がAPI Gateway等で吸収される場合：ゲートウェイ側の検証（署名/レート）とアプリ側の重複耐性が二重で必要、という軸で整理する

## 参考（必要最小限）
- OWASP ASVS（外部入力の信頼境界、監査、濫用耐性）
- OWASP WSTG（API Testing：署名/再送/認可）
- PTES（低侵襲差分で成立条件を確定）
- MITRE ATT&CK（Impact：偽装イベント/二重実行）

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/04_api_06_idempotency_レースと二重実行境界.md`
- `01_topics/02_web/03_authz_10_object_state_状態遷移と権限（draft_approved）.md`
- `01_topics/02_web/04_api_09_error_model_情報漏えい（例外_スタック）.md`

## 次（04_api_05 以降）に進む前に確認したいこと（必要なら回答）
- 04_api_05（Webhook送信側SSRF）では、「送信先がユーザ入力になる」ことで到達性境界が崩れる点を、allowlist/正規化/リダイレクト/DNS/メタデータ/プロキシ設定まで含めて最大限深掘りする
