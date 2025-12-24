# ci-cd_artifact_公開物（ログ_ビルド成果物）

## 目的（この技術で到達する状態）
CI/CD の公開物（ビルドログ、テストログ、成果物アーティファクト、リリース添付、パッケージ、コンテナイメージ等）を、ASM/OSINTの範囲で観測し、以下を「証跡つき」「優先度つき」で抽出できる状態にする。
- 漏えい（key/token/credential/内部URL/設定断片）の発見と、影響範囲（本番/開発/顧客環境）の推定
- 攻撃面（endpoint/管理画面/内部API/ストレージ/IdP/第三者SaaS）の拡張
- “CI/CD由来” の境界情報（信頼境界・権限境界・ビルド経路）を、後工程（HTTP観測、クラウド露出、SSO観測）へ渡す
- 低アクティブで再現可能な観測設計（ログ閲覧/メタデータ収集中心、実行や負荷をかけない）

## 前提（対象・範囲・想定）
- 対象は「公開設定により閲覧可能なCI/CD情報」に限定する（Public repoのActionsログ、公開Artifacts、公開Pages、公開Package、公開Release等）
- 自分でジョブを実行・再実行しない（ワークフロー起動＝アクティブ行為。原則、既存の公開物のみ観測）
- 目的は “攻撃” ではなく “面と漏えいの確定” であり、見つけた認証情報の利用（ログイン/アクセス確認）は別工程・合意が必要
- CI/CD製品は特定しない（GitHub Actions / GitLab CI / Jenkins / CircleCI / Azure DevOps / Bitbucket Pipelines 等に共通する観測軸で整理）

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) 公開面の分類（どこから漏れるか）
- ログ：ビルド/テスト/デプロイログ、デバッグ出力、スタックトレース、コマンド実行ログ
- 成果物（Artifacts）：ビルド出力（zip/tar）、テストレポート（JUnit/HTML）、Coverage、SBOM、静的解析結果（SARIF）
- リリース：Release 添付ファイル、changelog、署名ファイル、古いバイナリ
- パッケージ/イメージ：GitHub Packages / npm/pypi/nuget 等、コンテナレジストリ（public image）
- 公開サイト：Docs/Artifacts viewer/Pages（CI生成の静的サイト、レポート公開）
- キャッシュ/一時物：一部CIのキャッシュが外部参照可能なケース（設定次第）

### 2) 漏えいの観測対象（artifact由来の “key_token_endpoint”）
- key/token：API token、PAT、クラウド鍵素材、Webhook secret、署名鍵、SSH鍵、JWT、セッション断片
- endpoint：内部API URL、管理画面URL、stg/dev URL、Swagger/OpenAPI、GraphQL endpoint、Webhook URL、ストレージURL
- config：.env、設定yaml、terraform断片、kubeconfig、DB接続文字列、OIDC/SAML設定断片（issuer/client_id/redirect_uri 等）
- ビルド情報：環境名（prod/stg/dev）、クラスタ名、リージョン、アカウントID、サブスクリプションID、プロジェクトID
- 依存情報：private registry、社内パッケージ名、SaaS連携（Slack/Datadog/Sentry等）の識別子

### 3) 境界の読み方（CI/CD特有の “権限境界/信頼境界”）
- 権限境界（CIの実行主体）
  - どのIdentityでデプロイしているか（Service Principal / IAM Role / Workload Identity / OIDC Federated）
  - read-only か write/admin か（push/ deploy/ infra変更）
  - “fork PR” と “main branch” で権限が変わるか（CIの典型境界）
- 信頼境界（外部依存）
  - third-party action / runner / marketplace 依存の有無
  - 外部SaaSへの送信先（ログ転送、テスト結果アップロード）
- 資産境界（どこにデプロイされるか）
  - 対象環境（prod/stg/dev）と対象ドメイン（api/admin/docs）
  - リージョン/アカウント/テナント（クラウド境界）

### 4) artifact_key（後工程に渡す正規化キー）
公開物は「同一性」と「追跡可能性」で管理する。

- artifact_key（推奨）
  - artifact_key = <platform> + <org/repo(or project)> + <run_id(or pipeline_id)> + <artifact_type> + <artifact_name> + <created_at>
- 付随ラベル（必須）
  - source_locator: URL（閲覧可能な公開URL）
  - artifact_risk: leak_key | token_key | endpoint_key | config_key | info_only
  - environment_hint: prod | stg | dev | unknown
  - privilege_hint: read | write | admin | unknown
  - confidence: high | mid | low
  - action_priority: P0/P1/P2

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える（この観測で確定できる）
  - 公開面に「本来非公開であるべき運用情報」が露出している可能性（ログ/成果物/公開レポート）
  - CI/CD 経路から見える資産境界（どの環境へ、どのクラウド/どのテナントへ）が推定できる
  - endpoint/config が見つかれば、ASMでの面（攻撃面の入口候補）が拡張される
- 言えない（この段階では確定しない）
  - トークン/鍵が現在も有効か（有効性確認は合意の上で別工程）
  - endpoint の到達性（ネットワーク/認証/WAFで遮断され得る）
  - 露出が偶発か恒常か（複数run・複数artifactで再現するか観測が必要）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
### 優先度（P0/P1/P2）
- P0（即時対応レベル）
  - 長期秘密（秘密鍵/署名鍵/クラウド鍵素材）らしきものがログ/成果物に含まれる
  - 本番デプロイに関与する認証材料（OIDC連携設定の秘密、固定トークン、Webhook secret等）の露出が濃厚
- P1（緊急確認レベル）
  - 管理画面/内部API/stg-dev の endpoint が具体的に露出
  - クラウド境界情報（アカウントID、バケット名、プロジェクトID等）が揃い、面の探索精度が上がる
- P2（攻撃面投入レベル）
  - ビルド情報/依存情報/第三者SaaSの断片（直接の認証材料ではないが、攻め筋の確度が上がる）

### 典型的な“漏えいパターン”（CI/CDで起きやすい）
- デバッグログに環境変数やヘッダをそのまま出力（Authorization、Cookie、API_KEY 等）
- テスト失敗時に設定ファイルや接続先を含むスタックトレースが露出
- 成果物に .env / config / kubeconfig / terraform state などが混入
- レポートHTML（Coverage/テスト）に内部URL・社内ホスト名・Sentry DSN等が埋め込まれる
- 公開コンテナイメージに設定や秘密が焼き込まれる（レイヤに残る）

## 次に試すこと（仮説A/Bの分岐と検証）
### 仮説A：ログ/成果物に secret（key/token）が含まれる可能性が高い
- 次の一手（OSINTの安全域）
  - 証跡化：URL、run/pipeline識別子、該当箇所（行番号相当）、タイムスタンプ、ハッシュ
  - 全文を保持しない運用（推奨）：マスキング＋fingerprint（先頭/末尾数文字）＋ハッシュで記録
  - 同種の露出が “複数runで再現するか” を観測（恒常運用ミスか、単発事故か）
- 次の一手（合意がある場合のみ）
  - ローテ/無効化/履歴削除方針（公開ログは回収不能前提で、まず失効・権限最小化へ）
  - 影響確認はログ・監査証跡（誰が使ったか）を優先し、実トークン利用の検証は最終手段

### 仮説B：endpoint/config 断片が中心（攻撃面拡張が主目的）
- 次の一手
  - endpoint を “環境別（prod/stg/dev）” にタグ付けし、01_asm-osint/03_http 観測へ投入（到達性と認証境界を薄く取る）
  - クラウド境界（バケット/レジストリ/プロジェクト）を 18_storage_discovery に接続
  - IdP断片（issuer/redirect_uri 等）を 02_web のSSO観測に接続

### 仮説C：公開物が見つからない／閲覧できない（境界情報としての価値）
- 次の一手
  - “公開されていない” を境界情報として記録（artifact露出は低い＝別経路へ）
  - GitHub 検索（16）に戻り、issue/PR/discussions/commit など “テキスト面” でログ貼り付けを探索
  - 14_sourcemap / 15_api_spec の結果（endpoint_key/schema）をクエリにフィードバックしてピンポイント探索へ

#### 最小の観測例（公開物の同定・証跡化）
~~~~
# 例：公開レポート/ArtifactsのURLを見つけた場合の“証跡化”観点
- URL
- 作成日時（表示される範囲）
- サイズ（過大ダウンロードを避ける）
- 種別（log / report / zip / container / package）
- 含まれる断片（endpoint/config/secret のどれか）
~~~~

## 不明点（ここが決まると精度が上がる：回答は短くてOK）
- 対象は「PublicのCI公開物のみ」で固定するか（許可があるならOrg内部/GHEも観測対象にするか）
- “ダウンロード許容” の上限（例：数MBまで、またはメタデータのみ）を運用で決めるか
- 対象の主CIはどれか（GitHub Actions中心 / GitLab CI中心 / 混在）※書き方の比重が変わる

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回）
- ASVS：
  - V14（設定）：ビルド/デプロイ設定、秘密情報管理、ログ出力設計が直結
  - V1（アーキ/要件）：信頼境界（第三者SaaS/CI依存）と資産境界（環境/クラウド）を明確化
  - V13（API）：公開物からAPI endpoint/認証情報が漏れるとAPI防御の前提が崩れる
- WSTG：
  - INFO：公開情報（ログ/成果物/レポート）から攻撃面・環境差分・認証材料の収集
  - CONF/CRYP（支える前提）：秘密情報をログ/成果物に出さない、保存しない、露出しない
- PTES：
  - Intelligence Gathering → Threat Modeling：CI/CD公開物から“現実のデプロイ経路”と“境界”を確定し、検証優先度を決める
- MITRE ATT&CK：
  - Reconnaissance：公開情報（技術スタック/環境/エンドポイント/クラウド依存）の収集
  - Credential Access（支える前提）：ログ・成果物から認証材料が得られる可能性があるため、検知/対策観点も含めて整理

## 参考（必要最小限）
- CI/CD各製品の “Artifacts/Logs/Packages/Pages” 公開設定の公式ドキュメント
- ソフトウェアサプライチェーン（SLSA、SBOM、署名）の基礎（公開物の意味づけ）
- secret scanning / gitleaks / trufflehog 等（防御的な再発防止の観点）