# Slack トークン境界（xox_署名検証）

## ガイドライン対応
- ASVS：V2（認証）、V3（セッション）、V4（アクセス制御）、V6（暗号）、V7（エラー/ログ）、V9（通信）
  - このファイルでは「トークン（bearer）/署名（HMAC）/同意（OAuth）/監査ログ」を“権限境界・信頼境界”として扱い、漏えい・誤検証・過剰権限を検出/防止する観点に接続する
- WSTG：認証（WSTG-ATHN）、認可（WSTG-ATHZ）、設定・運用（WSTG-CONF）、ビジネスロジック（WSTG-BUSL）
  - 直接のWebアプリ脆弱性というより「外部IdP/外部SaaS連携の境界設計・検証」として、署名検証/トークン運用/同意/ログを観測対象にする
- PTES：Intelligence Gathering → Threat Modeling → Vulnerability Analysis → Exploitation → Post-Exploitation → Reporting
  - Slack連携は「入口（外部到達）→資格（token）→権限（scope/installation）→永続（refresh/再発行）→痕跡（audit）」が一本の導線になる
- MITRE ATT&CK：Credential Access / Discovery / Lateral Movement / Command and Control / Exfiltration
  - Slackは“業務SaaS”として、トークン奪取・不正アプリ同意・監査回避が横展開や情報収集に直結する

## 目的（この技術で到達する状態）
- Slack連携における「トークン境界（xox*等）」と「リクエスト真正性境界（署名検証）」を、観測→解釈→意思決定の単位に落とす。
- 具体的には次を判断できる状態になる：
  - どの“トークン”が、どの“主体/設置点/権限”を代表しているか（権限境界）
  - 外部から到達するWebhook/Events/Commandsが「Slackからの正当な要求」かを、どこで・何で担保するか（信頼境界）
  - 事故（漏えい/誤設定/実装不備）が起きた時に、被害範囲と打ち手（失効・再発行・制限・監査）を即断できる

## 前提（対象・範囲・想定）
- 対象
  - Slack App（OAuthでインストールされるアプリ）、Slack Events API / Slash Commands / Shortcuts / Interactivity など「Slack→自社/自前サーバ」へ届く経路
  - Socket Mode（WebSocketで受ける）も含める（到達性境界が変わるため）
- 範囲（このファイルで扱う境界）
  - 権限境界：token種別、scope、installation（どのorg/workspace/userに紐付くか）、token rotation/失効
  - 信頼境界：Signing Secret（HMAC署名）、タイムスタンプ、mTLS（利用時）
  - 資産境界：Slackワークスペース/Enterprise Grid/アプリ設定（配布/インストール）/監査ログ
- 想定読者・状況
  - ペンテスター/診断員が「Slack連携があるWeb/API」を見たときに、実装の安全性・運用の安全性・痕跡性を短時間で判定する
  - Blue/運用側が「何をログで追うべきか」「失効・再発行・制限の優先度」を整理する

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) トークンの“種類”と“代表主体”（権限境界の中心）
Slackは用途ごとに複数のトークン体系を持つ。観測では「prefix（見た目）」ではなく、必ず“用途/主体/設置点”まで落とす。

- Bot token（例：`xoxb-...`）
  - 何を代表：アプリのボットユーザ（workspace内でのアプリ主体）
  - どこに置かれる：サーバ側（API呼び出しでBearerとして使用）
- User token（例：`xoxp-...`）
  - 何を代表：Slackユーザの権限（ユーザの可視性/操作主体）
  - どこに置かれる：原則サーバ側。クライアント露出は重大事故
- App-level token（例：`xapp-...`）
  - 何を代表：アプリ“全体”を代表（Socket Mode等で使用）
  - どこに置かれる：Socket Modeを動かすサーバ/ワーカー（漏えいは“受信口”の乗っ取りに近い）
- Refresh token / Token rotation（例：`xoxe-...`など）
  - 何を代表：アクセストークン更新の権限（長期的な永続に直結）
  - どこに置かれる：サーバ側の秘匿ストア（DB/Secrets Manager等）
- Workflow token（例：`xwfp-...`）
  - 何を代表：ワークフロー実行の一時権限（短命だが“借用された可視性”があり得る）
  - どこに置かれる：ワークフロー/関数実行環境（ログ漏えいに注意）
- Configuration token 等（“アプリ設定用”）
  - 何を代表：アプリ作成・設定操作（運用者の権限）
  - どこに置かれる：CI/CDや管理者端末に置かれがち（漏えい＝供給網に近い事故）

観測で見るデータ例（ログ/設定/コード）：
- Authorizationヘッダ（`Authorization: Bearer ...`）でtokenを渡しているか
- tokenがPOST bodyに混在していないか（ログに残りやすい）
- tokenがフロント（JS/localStorage）に出ていないか（重大）
- tokenがCIログ/エラー/監査ログに平文で出ていないか

### 2) Scope（最小権限）と Installation（どこに入ったか）
Slackの権限はscopeで決まる。さらに「同じアプリが複数workspace/orgにインストール」され得るため、installation境界（team_id/enterprise_id等）で“どの環境の権限か”が分岐する。

観測ポイント：
- アプリの設定（OAuth & Permissions）
  - 付与scope（bot/userそれぞれ）
  - “不要scope”の有無（過剰権限）
- Events API payloadの `authorizations` / `team_id` / `enterprise_id` など（受信側が複数インストールを扱う前提か）
- 監査ログ（Enterprise GridならAudit Logs API/管理画面）で
  - アプリインストール/権限変更/トークン失効のイベントが追えるか

### 3) Slack→自社のHTTP到達（信頼境界）：署名検証の実装点
Slackは、Events/Commands/Shortcuts等で `X-Slack-Signature` と `X-Slack-Request-Timestamp` を付与し、Signing SecretでHMAC署名する。受信側は「生body」を使って署名を計算し一致確認する。タイムスタンプはリプレイ耐性（一定時間窓）に使う。

観測ポイント（HTTP）：
- 受信エンドポイント（例：`/slack/events` `/slack/commands` `/slack/actions` 等）
- 受信時に以下を見ているか
  - `X-Slack-Signature`（署名）
  - `X-Slack-Request-Timestamp`（リプレイ耐性）
  - 生のrequest body（JSONにパースする前のraw bytes）
- 署名比較が“定数時間比較”になっているか（タイミング差の抑制）
- URL verification（初回のchallenge）時も署名検証の流れに乗せているか（Events APIの所有確認）

### 4) Socket Mode（到達性境界の変形）
Socket Modeは公開HTTP受信口を不要にし、WebSocketでSlackからイベントを受ける。ここでは“署名検証”の代わりに「app-level token（xapp-）の秘匿」と「接続境界（どこでSocketを終端するか）」が主要論点になる。

観測ポイント：
- app-level token（`xapp-`）が環境変数/Secretsで管理されているか
- 受信処理がワーカー/常駐プロセスで動き、ログにpayloadやtokenを落としていないか

## 結果の意味（その出力が示す状態：何が言える/言えない）
### 署名検証が“正しく”できている状態とは
- 言えること（満たしている性質）
  - そのHTTPリクエストが「Slackが送った」ことを、Signing Secretに基づき検証できる
  - リクエストボディ改ざん（途中改ざん/代理送信）の検知ができる
  - タイムスタンプ窓で、一定のリプレイを弾ける
- 言えないこと（誤解しがちな点）
  - “Slackの中の誰が操作したか”は署名だけでは保証しない（ユーザの意図/権限は別問題）
  - “正しいワークスペース/組織向けのイベントか”は、payload内のteam_id/enterprise_idやinstallation管理で別途判定が必要
  - “アプリが過剰権限を持つかどうか”は署名検証とは無関係（scope設計の問題）

### トークン管理が“境界として健全”な状態とは
- Bot/User/App-level/Refresh等が用途ごとに分離され、最小権限のscopeが付いている
- tokenがサーバ側の安全な保管にあり、ログ/クライアント/リポジトリに露出していない
- 失効（auth.revoke等）/再発行/制限（IP制限など）/監査（Audit Logs）が運用で回る

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
Slack連携は、攻撃者にとって「業務SaaSの資格（token）を取れば、外部から“正規の業務経路”で横展開できる」面がある。よって、以下の条件が揃うほど優先度が上がる。

優先度が上がる観測結果（例）：
- 受信口が公開されている（Events/Commands/ActionsのRequest URL）＋ 署名検証が曖昧
- tokenが長期有効（非rotation）で、scopeが強い（投稿/ファイル/ユーザ情報/管理系）
- tokenがフロント/ログ/CIに露出する経路がある（例：フロントにbot token、サーバログにAuthorization、エラーにtoken）
- 複数workspace/orgにインストールされ、installation境界が曖昧（別テナントのイベント混入、誤ルーティング）

攻撃者の典型目的（防御側の判断軸）：
- Credential Access：token/refresh_token/signing secretの奪取（設定/ログ/環境変数/CI経路）
- Discovery：Slack内の会話/メンバー/チャンネルの探索（scope次第）
- Lateral Movement：Slack経由でリンク配布、ワークフロー、通知連携など（業務フローに刺さる）
- Exfiltration：Slack経由の情報持ち出し（ファイル/メッセージ/外部転送）

ここでの意思決定：
- “まず守るべき境界”は、（1）Signing Secretの検証点、（2）tokenの保管点、（3）scopeとinstallationの分離
- 診断では「署名検証がない/弱い」より「tokenが漏れている/過剰権限」の方が致命になりやすい（復旧コスト・横展開速度が高い）

## 次に試すこと（仮説A/Bの分岐と検証）
### 仮説A：Request URL（HTTP受信）型で、署名検証が実装されている/されていない
目的：受信口が“Slack以外から叩ける状態”になっていないか（信頼境界の破断）を、観測で確定する。

- A1（期待）：署名検証が必須で、失敗時は非200（または処理しない）
  - 確認観点
    - `X-Slack-Signature` / `X-Slack-Request-Timestamp` がない要求を拒否するか
    - timestampが古い/未来の要求を拒否するか（リプレイ耐性）
    - bodyをパースした後の文字列ではなく、生bodyで計算しているか（改行/エンコード差分でズレる）
    - 署名比較が安全な比較関数になっているか
  - 次の一手
    - 署名検証がライブラリ任せなら、フレームワークの“raw body取得方法”とミドルウェア順序をコードレビュー
    - 監査ログに「署名検証失敗」が残るか（運用検知）

- A2（危険）：署名検証が任意/未実装、または“tokenフィールド”だけ見ている
  - 意味
    - 外部からの偽装リクエストで、Slackイベント処理系（通知・連携・更新）が誤作動し得る
  - 次の一手（防御/改善）
    - 署名検証を必須化（Signing SecretでHMAC）
    - challenge（url_verification）を含めて、最初に署名検証→OKならchallenge返却へ統一
    - mTLS採用も検討（終端がLBの場合の設計含む）

署名検証ロジック（実装の“観測点”を固定するための擬似コード）：
~~~~
入力：
- signing_secret（アプリごとの秘密）
- headers: X-Slack-Signature, X-Slack-Request-Timestamp
- raw_body（JSONやフォームに変換する前の生バイト列）

手順：
1) timestamp を取り出し、現在時刻との差が閾値（例：5分）以内か確認
2) base_string = "v0:" + timestamp + ":" + raw_body_as_text
3) my_sig = "v0=" + HMAC_SHA256(signing_secret, base_string).hex
4) 定数時間比較で my_sig と X-Slack-Signature を比較
5) 一致したら処理、違えば拒否（処理しない）
~~~~

### 仮説B：Socket Mode でHTTP受信口がなく、app-level tokenが境界
目的：外部到達性は下がるが、`xapp-`漏えいが“受信口そのものの乗っ取り”に近いことを理解し、保護状況を確定する。

- B1（期待）：`xapp-`がSecrets管理され、ログに出ず、最小権限で運用
  - 確認観点
    - `SLACK_APP_TOKEN` がSecrets Manager等にあり、CI/ログに出ていない
    - ワーカー/常駐プロセスがクラッシュ時にpayload/tokenをダンプしない
  - 次の一手
    - 監査ログで、アプリ設定変更/トークン再発行を追える体制（誰がいつ再発行したか）

- B2（危険）：`xapp-`が平文で配布、または開発者PC/リポジトリに残っている
  - 意味
    - 攻撃者がSocket接続を確立できれば、イベント受信・操作の起点になり得る
  - 次の一手（防御/改善）
    - 即時再発行（漏えい時のローテーション手順を確立）
    - 配布経路の遮断（CIのマスキング、ログの禁止、Secret scanning）

### 仮説C：Token rotation/Refresh token を使っており、永続性の境界がある
目的：短命アクセストークン + refresh token による設計で、漏えい時の被害と復旧をコントロールできているかを確定する。

- C1（期待）：refresh tokenを安全保管し、期限前に更新し、使い回し検知の前提がある
  - 確認観点
    - refresh tokenはDB/Secretsにあり、アクセス制御/監査がある
    - refresh tokenは“使い捨て”で更新後に置換される運用になっている
    - 失効（auth.revoke等）・再発行の運用手順がある
  - 次の一手
    - “更新失敗時”のフェイルセーフ（APIが止まる/権限が落ちる）を設計

- C2（危険）：refresh tokenをログ/設定ファイルに置き、更新処理が雑
  - 意味
    - 1回の漏えいで長期支配（永続）が成立しやすい
  - 次の一手
    - refresh tokenの保管と監査を最優先で改善（漏えい面積を減らす）

## 参考（必要最小限）
- Verifying requests from Slack（署名検証：X-Slack-Signature / timestamp / 生body / HMAC）  
  https://docs.slack.dev/authentication/verifying-requests-from-slack/  
  https://api.slack.com/docs/verifying-requests-from-slack
- Token rotation（refresh token / expires_in / 2 active token limit 等）  
  https://docs.slack.dev/authentication/using-token-rotation/
- Token types（xoxb/xoxp/xapp/xwfp などの概念整理）  
  https://api.slack.com/concepts/token-types
- Events API：Request URLのURL verification（challenge）  
  https://api.slack.com/events/url_verification  
  https://docs.slack.dev/apis/events-api/using-http-request-urls/
- Socket Mode（xapp- と connections:write）  
  https://docs.slack.dev/apis/events-api/using-socket-mode  
- Audit Logs（Enterprise組織での監査：auditlogs:read 等）  
  https://docs.slack.dev/admins/audit-logs-api  
  https://api.slack.com/admins/audit-logs
- OAuth運用と安全（token保護、IP制限、incoming webhookの性質など）  
  https://docs.slack.dev/authentication/installing-with-oauth  
  https://api.slack.com/docs/oauth-safety
