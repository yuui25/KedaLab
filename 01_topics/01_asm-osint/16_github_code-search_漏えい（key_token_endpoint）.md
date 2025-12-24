# github_code-search_漏えい（key_token_endpoint）

## 目的（この技術で到達する状態）
GitHub 上に露出している「鍵・トークン・内部エンドポイント・設定断片」を、ASM/OSINTの範囲で漏れなく収集し、次工程（HTTP観測/サブドメイン列挙/クラウド露出推定/認証・認可検証）へ渡せる状態にする。
- key_token_endpoint を「証跡つき」「優先度つき」「境界（資産/信頼/権限）つき」で整理できる
- “実害の可能性が高い漏えい” と “攻撃面の推定に効く断片” を分離し、対応を迷わない
- 「検証せずに（使わずに）危険度を判定する」ための判断軸を持つ（OSINTの安全域）

## 前提（対象・範囲・想定）
- 対象は原則「公開情報」：Public repo / Public gists / Public issues・PR・discussions / 公開されている Actions ログやリリース成果物（公開設定のもの）
- Private/Org 内部は、許可・権限がある場合のみ（本ファイルでは “探し方の設計” を中心にし、侵入的な行為は扱わない）
- 目的は「漏えいの有無と攻撃面の確定」であり、見つけた認証情報を“利用してログイン確認する”ことは原則しない（必要なら合意の上で別工程）
- 検索は “広く浅く” から入り、確度が高い箇所だけ “狭く深く” に寄せる（ノイズ制御が品質）

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) 資産境界：どこまでが「対象のGitHub露出」か
- 公式Org / 公式ユーザ / 関連会社 / 旧Org / 子会社 / OSSプロジェクト（プロダクト別）を区別する
- fork / mirror / 個人アカウント（従業員）を「対象外」にしないが、優先度と扱いを分ける（誤検知・責任境界の差）
- “検索対象面” を分解する（コードだけでなくテキスト面がある）
  - repo（default branch / tag / release）
  - commit（過去に存在した秘匿情報）
  - issue / PR / discussion（貼り付け・ログ添付・設定共有）
  - wiki（運用手順の断片）
  - gist（個人運用の断片）
  - Actions（ログ・artifact・環境変数露出の断片）※公開設定のもの

### 2) データ境界：何が出たら「key/token/endpoint」か
- key（長期秘密）：秘密鍵、サービスアカウント鍵、クラウド鍵、署名鍵、SSH鍵、PGP鍵、暗号鍵素材（base64等）
- token（短期〜中期）：API token、Personal access token、CI token、Webhook secret、JWT（署名済み）、セッショントークン断片
- endpoint（攻撃面）：内部API URL、管理画面URL、staging/dev URL、GraphQL endpoint、Swagger/OpenAPI URL、webhook URL、storage URL
- config（境界の断片）：.env、config.yml、terraform state断片、kubeconfig断片、DB接続文字列、OIDC/SAML設定断片（issuer/client_id/redirect_uri 等）

### 3) 権限境界：それは「どの権限で効く情報」か
key/token/endpoint を見つけたら、必ず “権限境界ラベル” を付ける。
- 影響範囲：個人（dev）/ チーム / 本番 / 顧客環境
- 権限種別：読み取り / 書き込み / 管理者 / 認証回避（署名鍵など）
- 期限：短期（CI一時トークン）/ 中期（PAT）/ 長期（鍵）
- 露出の場所：現行コード / 過去コミット / issue添付 / Actionsログ など（回収難易度が変わる）

### 4) 収集の単位（key_token_endpoint の正規化）
漏えい断片は「後工程で使える形」に正規化して記録する。

- key_token_endpoint レコード（推奨フィールド）
  - source_type: repo | commit | issue_pr | discussion | wiki | gist | actions_log | release_asset
  - source_locator: org/repo + path + ref（branch/tag/commit）+ 行番号 or URL
  - artifact_type: key | token | endpoint | config
  - artifact_fingerprint: 先頭/末尾数文字 + ハッシュ（全文は保存しない方針も可）
  - asset_boundary: 対象Org/プロダクト/環境（prod/stg/dev）
  - trust_boundary: third-party（SaaS/クラウド/外部API）有無
  - privilege_boundary: 想定権限（read/write/admin）
  - confidence: high | mid | low（形式一致・文脈一致・実在性）
  - action_priority: P0（即時ローテ）/P1（緊急確認）/P2（攻撃面へ投入）

#### 最小の検索クエリ例（“広く浅く”）
※クエリは最小限の例。対象名（Org/ドメイン/プロダクト名）を差し替えて使う。
~~~~
# 入口：.env / config / secret 断片
org:<ORG> (filename:.env OR filename:config.yml OR filename:settings.py) (SECRET OR TOKEN OR KEY)

# 入口：URL（endpoint断片）
org:<ORG> ("https://" OR "http://") (staging OR dev OR admin OR internal)

# 入口：クラウド/ストレージの断片（境界推定へ接続）
org:<ORG> (s3.amazonaws.com OR ".blob.core.windows.net" OR "storage.googleapis.com")

# 入口：Swagger / OpenAPI / GraphQL（面抽出へ接続）
org:<ORG> (openapi OR swagger OR "swagger.json" OR "openapi.json" OR graphql OR graphiql)
~~~~

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える（状態としての結論）
  - 「本来は秘匿されるべきもの」が公開面に存在する、または過去に存在した可能性が高い
  - endpoint が見つかった場合、ASMでの“攻撃面（入口候補）”が増える（特に stg/dev/admin は優先度が上がる）
  - config 断片が見つかった場合、資産境界（どのクラウド/どのIdP/どの外部SaaSか）と信頼境界（第三者依存）が具体化する
- 言えない（この段階で確定しない）
  - その鍵/トークンが現在も有効か（有効性確認は別工程・合意が必要）
  - その endpoint が到達可能か（WAF/ネットワーク/認証で遮断される可能性）
  - それが本当に対象組織の管理下か（fork・個人repo・サンプルコードの可能性）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
### 優先度の決め方（P0/P1/P2）
- P0（即時対応レベル）
  - 長期秘密（秘密鍵・署名鍵・クラウド鍵素材）の疑いが強い
  - 本番系の管理権限に繋がり得る設定（IdP設定、Webhook secret、CIの固定token 等）
- P1（緊急確認レベル）
  - token らしき形式一致＋文脈一致（例：READMEに貼り付け、ログに出力）
  - “管理画面/内部API/ステージング” の endpoint が明確（面が増える）
- P2（攻撃面投入レベル）
  - endpoint/設定断片のみ（直接の認証材料ではないが、後工程の探索精度が上がる）
  - 旧コミットにのみ存在し、現行では削除済み（ただし履歴から回収され得る）

### 攻め筋の作り方（OSINT→次工程への橋渡し）
- endpoint が出た → 01_asm-osint/03_http 観測へ投入（到達性・認証境界の薄い確認）
- OpenAPI/Swagger/GraphQL が出た → 15_api_spec の “面抽出（endpoint_key_schema）” に接続
- storage URL が出た → 18_storage_discovery（境界推定）へ接続
- IdP/OIDC/SAMLの断片が出た → 02_web の認証/SSO観測（state/nonce/redirect_uri等）に接続
- “ログの貼り付け” が出た → 17_ci-cd_artifact（公開ログ/成果物）で再現性ある観測に拡張

## 次に試すこと（仮説A/Bの分岐と検証）
### 仮説A：秘匿情報（key/token）の可能性が高い（P0/P1）
- 次の一手（OSINTの安全域）
  - 収集は「証跡化」まで：URL/コミット/行番号/スクショ/ハッシュ（全文を横流ししない）
  - “形式一致” と “文脈一致” を切り分けて confidence を付ける（高/中/低）
  - 関係者へ連絡する前提で「最小の再現メモ」を作る（どこに、何が、どの権限に効きそうか）
- 次の一手（合意がある場合のみ）
  - 失効/ローテーション方針（鍵の再発行、トークン無効化、権限最小化、過去コミットの扱い）
  - 影響確認は“ログ確認”を優先し、実トークン利用の検証は最終手段にする

### 仮説B：endpoint/config 断片が中心（P2が多い）
- 次の一手
  - endpoint を “環境別（prod/stg/dev）” にタグ付けし、HTTP観測へ投入して境界（401/403/404/302）を取る
  - 依存先（SaaS/クラウド）を trust_boundary として整理し、後続（18/21/23）へ渡す
  - “同じ断片が複数箇所に出る” 場合は優先度を上げる（運用上の恒常露出の疑い）

### 仮説C：見つからない（ノイズは多いが確証がない）
- 次の一手
  - 対象境界の見直し（旧Org名、旧プロダクト名、関連会社、OSS名、ドメイン別名）
  - “コード検索だけ”に寄っていないかを見直す（issue/PR/discussions/gist/actions を追加）
  - 14_sourcemap や 15_api_spec で得た endpoint_key/schema を検索クエリにフィードバックし、ピンポイント探索へ寄せる

### 不明点（ここが決まると精度が上がる：回答は短くてOK）
- GitHub の対象は「Publicのみ」で進める前提で良いか（Org内部/GHEまで含めるか）
- 対象Org/プロダクト名（検索の起点文字列）は、あなた側で毎回与える運用か（固定の一覧があるか）
- “証跡の保存方針” はどちらか：全文保存OK / マスキング＋ハッシュのみ（推奨）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回）
- ASVS：
  - V14（設定）：秘密情報の管理、設定の露出、セキュアなデプロイ運用に直結
  - V13（API）：APIキー/トークン/エンドポイント露出が API セキュリティ全般の前提を破る
  - V1（アーキ/要件）：信頼境界・外部依存の把握（脅威モデリングの入力）
- WSTG：
  - INFO：公開情報（コード/ドキュメント/ログ）からの攻撃面・環境差分・認証材料の収集
  - CRYP/CONF（該当が薄い場合でも“秘匿情報が公開される”前提を支える）：鍵・トークン露出の発見は後続検証の安全設計に必要
- PTES：
  - Intelligence Gathering → Threat Modeling：公開情報から資産境界・信頼境界・権限境界を具体化し、検証優先度を決める
- MITRE ATT&CK：
  - Reconnaissance：公開情報の収集（組織/技術/エンドポイント/クラウド依存）
  - Resource Development / Credential Access（支える前提として）：認証材料・アクセス手掛かりの獲得に繋がる断片の発見

## 参考（必要最小限）
- GitHub 検索（code/commits/issues/PR/discussions/gists）の公式仕様とクエリ演算子
- secret scanning / gitleaks / trufflehog 等（組織内での防御的スキャンとして）
- OWASP（API Security / Secrets Management / Logging）関連のガイダンス