# 17_ci-cd_artifact_公開物（ログ_ビルド成果物）
CI/CD Artifact 公開物（ログ/ビルド成果物）
“漏えい（key/token/credential/内部URL/設定断片）の発見と、影響範囲（本番/開発/顧客環境）の推定”

## 目的（この技術で到達する状態）
CI/CD の公開物（ビルドログ、テストログ、成果物アーティファクト、リリース添付、パッケージ、コンテナイメージ等）を、ASM/OSINTの範囲で観測し、以下を「証跡つき」「優先度つき」で抽出できる状態にする。
- 漏えい（key/token/credential/内部URL/設定断片）の発見と、影響範囲（本番/開発/顧客環境）の推定
- 攻撃面（endpoint/管理画面/内部API/ストレージ/IdP/第三者SaaS）の拡張
- “CI/CD由来” の境界情報（信頼境界・権限境界・ビルド経路）を、後工程（HTTP観測、クラウド露出、SSO観測）へ渡す
- 低アクティブで再現可能な観測設計（ログ閲覧/メタデータ収集中心、実行や負荷をかけない）

## 前提（対象・範囲・想定）
- 対象：Public repoのActionsログ、公開Artifacts、公開Pages、公開Package、公開Release等（公開設定により閲覧可能なCI/CD情報）に限定する。Private/Org 内部は、許可・権限がある場合のみ
- 想定する環境：
  - CI/CD製品は特定しない（GitHub Actions / GitLab CI / Jenkins / CircleCI / Azure DevOps / Bitbucket Pipelines 等に共通する観測軸で整理）
  - 自分でジョブを実行・再実行しない（ワークフロー起動＝アクティブ行為。原則、既存の公開物のみ観測）
- できること/やらないこと（安全に検証する範囲）：
  - できる：公開設定により閲覧可能なCI/CD情報の観測、漏えい（key/token/credential/内部URL/設定断片）の発見、攻撃面の拡張
  - やらない：自分でジョブを実行・再実行しない（ワークフロー起動＝アクティブ行為。原則、既存の公開物のみ観測）。目的は “攻撃” ではなく “面と漏えいの確定” であり、見つけた認証情報の利用（ログイン/アクセス確認）は別工程・合意が必要
- 依存する前提知識（必要最小限）：
  - `01_topics/01_asm-osint/16_github_code-search_漏えい（key_token_endpoint）.md`
  - `01_topics/01_asm-osint/14_js_sourcemap_公開物から攻撃面抽出（endpoint_key）.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：CI/CD Artifact 公開物（ログ/ビルド成果物）から漏えいと攻撃面の抽出、境界情報の特定
  - 扱わない（別ユニットへ接続）
    - GitHub検索 → `16_github_code-search_漏えい（key_token_endpoint）.md`
    - Sourcemap → `14_js_sourcemap_公開物から攻撃面抽出（endpoint_key）.md`
    - Secrets管理 → `01_topics/02_web/06_config_02_Secrets管理と漏えい経路（JS_ログ_設定_クラウド）.md`

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
- 観測対象（プロトコル/データ構造/やり取りの単位）
  - 公開面の分類（どこから漏れるか）
    - ログ：ビルド/テスト/デプロイログ、デバッグ出力、スタックトレース、コマンド実行ログ
    - 成果物（Artifacts）：ビルド出力（zip/tar）、テストレポート（JUnit/HTML）、Coverage、SBOM、静的解析結果（SARIF）
    - リリース：Release 添付ファイル、changelog、署名ファイル、古いバイナリ
    - パッケージ/イメージ：GitHub Packages / npm/pypi/nuget 等、コンテナレジストリ（public image）
    - 公開サイト：Docs/Artifacts viewer/Pages（CI生成の静的サイト、レポート公開）
    - キャッシュ/一時物：一部CIのキャッシュが外部参照可能なケース（設定次第）
  - 漏えいの観測対象（artifact由来の “key_token_endpoint”）
    - key/token：API token、PAT、クラウド鍵素材、Webhook secret、署名鍵、SSH鍵、JWT、セッション断片
    - endpoint：内部API URL、管理画面URL、stg/dev URL、Swagger/OpenAPI、GraphQL endpoint、Webhook URL、ストレージURL
    - config：.env、設定yaml、terraform断片、kubeconfig、DB接続文字列、OIDC/SAML設定断片（issuer/client_id/redirect_uri 等）
    - ビルド情報：環境名（prod/stg/dev）、クラスタ名、リージョン、アカウントID、サブスクリプションID、プロジェクトID
    - 依存情報：private registry、社内パッケージ名、SaaS連携（Slack/Datadog/Sentry等）の識別子
  - 境界の読み方（CI/CD特有の “権限境界/信頼境界”）
    - 権限境界（CIの実行主体）：どのIdentityでデプロイしているか（Service Principal / IAM Role / Workload Identity / OIDC Federated）、read-only か write/admin か（push/ deploy/ infra変更）、“fork PR” と “main branch” で権限が変わるか（CIの典型境界）
    - 信頼境界（外部依存）：third-party action / runner / marketplace 依存の有無、外部SaaSへの送信先（ログ転送、テスト結果アップロード）
    - 資産境界（どこにデプロイされるか）：対象環境（prod/stg/dev）と対象ドメイン（api/admin/docs）、リージョン/アカウント/テナント（クラウド境界）
- 境界の観点
  - 資産境界（管理主体・委託先・対象範囲の線引き）：対象環境（prod/stg/dev）と対象ドメイン（api/admin/docs）、リージョン/アカウント/テナント（クラウド境界）
  - 信頼境界（外部連携・第三者・越境ポイント）：third-party action / runner / marketplace 依存の有無、外部SaaSへの送信先（ログ転送、テスト結果アップロード）
  - 権限境界（権限の切替/伝播/委任）：どのIdentityでデプロイしているか（Service Principal / IAM Role / Workload Identity / OIDC Federated）、read-only か write/admin か（push/ deploy/ infra変更）、“fork PR” と “main branch” で権限が変わるか（CIの典型境界）
- 重要なフィールド/差分/状態（「ここが変わると意味が変わる」点）
  - artifact_key（後工程に渡す正規化キー）
    - artifact_key = <platform> + <org/repo(or project)> + <run_id(or pipeline_id)> + <artifact_type> + <artifact_name> + <created_at>
  - 付随ラベル（必須）
    - source_locator: URL（閲覧可能な公開URL）
    - artifact_risk: leak_key | token_key | endpoint_key | config_key | info_only
    - environment_hint: prod | stg | dev | unknown
    - privilege_hint: read | write | admin | unknown
    - confidence: high | mid | low
    - action_priority: P0/P1/P2

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が“確定”できるか
  - 公開面に「本来非公開であるべき運用情報」が露出している可能性（ログ/成果物/公開レポート）
  - CI/CD 経路から見える資産境界（どの環境へ、どのクラウド/どのテナントへ）が推定できる
  - endpoint/config が見つかれば、ASMでの面（攻撃面の入口候補）が拡張される
- 何が“推定”できるか（推定の根拠/前提）
  - トークン/鍵が現在も有効か（有効性確認は合意の上で別工程）
- 何は“言えない”か（不足情報・観測限界）
  - トークン/鍵が現在も有効か（有効性確認は合意の上で別工程）
  - endpoint の到達性（ネットワーク/認証/WAFで遮断され得る）
  - 露出が偶発か恒常か（複数run・複数artifactで再現するか観測が必要）
- よくある状態パターン（正常/異常/境界がズレている等）
  - パターンA：ログ/成果物に secret（key/token）が含まれる可能性が高い
  - パターンB：endpoint/config 断片が中心（攻撃面拡張が主目的）
  - パターンC：公開物が見つからない／閲覧できない（境界情報としての価値）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す“狙い目”（診断上の優先度付けとして使う）
  - P0（即時対応レベル）：長期秘密（秘密鍵/署名鍵/クラウド鍵素材）らしきものがログ/成果物に含まれる、本番デプロイに関与する認証材料（OIDC連携設定の秘密、固定トークン、Webhook secret等）の露出が濃厚
  - P1（緊急確認レベル）：管理画面/内部API/stg-dev の endpoint が具体的に露出、クラウド境界情報（アカウントID、バケット名、プロジェクトID等）が揃い、面の探索精度が上がる
  - P2（攻撃面投入レベル）：ビルド情報/依存情報/第三者SaaSの断片（直接の認証材料ではないが、攻め筋の確度が上がる）
- 優先度の付け方（時間制約がある場合の順序）
  - P0（即時対応レベル）→ P1（緊急確認レベル）→ P2（攻撃面投入レベル）の順
- 代表的な攻め筋（この観測から自然に繋がるもの）
  - 攻め筋1：ログ/成果物に secret（key/token）が含まれる可能性が高い → 証跡化（URL、run/pipeline識別子、該当箇所、タイムスタンプ、ハッシュ）、全文を保持しない運用（推奨：マスキング＋fingerprint＋ハッシュで記録）、同種の露出が “複数runで再現するか” を観測（恒常運用ミスか、単発事故か）
  - 攻め筋2：endpoint/config 断片が中心（攻撃面拡張が主目的） → endpoint を “環境別（prod/stg/dev）” にタグ付けし、01_asm-osint/03_http 観測へ投入（到達性と認証境界を薄く取る）、クラウド境界（バケット/レジストリ/プロジェクト）を 18_storage_discovery に接続、IdP断片（issuer/redirect_uri 等）を 02_web のSSO観測に接続
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）
  - 公開物が見つからない／閲覧できない（境界情報としての価値） → “公開されていない” を境界情報として記録（artifact露出は低い＝別経路へ）、GitHub 検索（16）に戻り、issue/PR/discussions/commit など “テキスト面” でログ貼り付けを探索

## 次に試すこと（仮説A/Bの分岐と検証）
> ここが最重要。条件が違うと次の手が変わる形で書く。

- 仮説A：ログ/成果物に secret（key/token）が含まれる可能性が高い
  - 次の検証：
    - （OSINTの安全域）証跡化：URL、run/pipeline識別子、該当箇所（行番号相当）、タイムスタンプ、ハッシュ。全文を保持しない運用（推奨）：マスキング＋fingerprint（先頭/末尾数文字）＋ハッシュで記録。同種の露出が “複数runで再現するか” を観測（恒常運用ミスか、単発事故か）
    - （合意がある場合のみ）ローテ/無効化/履歴削除方針（公開ログは回収不能前提で、まず失効・権限最小化へ）、影響確認はログ・監査証跡（誰が使ったか）を優先し、実トークン利用の検証は最終手段
  - 期待する観測（成功/失敗時に何が見えるか）：
    - 証跡化された漏えい情報と、最小の再現メモ
- 仮説B：endpoint/config 断片が中心（攻撃面拡張が主目的）
  - 次の検証：
    - endpoint を “環境別（prod/stg/dev）” にタグ付けし、01_asm-osint/03_http 観測へ投入（到達性と認証境界を薄く取る）
    - クラウド境界（バケット/レジストリ/プロジェクト）を 18_storage_discovery に接続
    - IdP断片（issuer/redirect_uri 等）を 02_web のSSO観測に接続
  - 期待する観測：
    - endpoint/config 断片の整理と、HTTP観測への投入
- 仮説C：公開物が見つからない／閲覧できない（境界情報としての価値）
  - 次の検証：
    - “公開されていない” を境界情報として記録（artifact露出は低い＝別経路へ）
    - GitHub 検索（16）に戻り、issue/PR/discussions/commit など “テキスト面” でログ貼り付けを探索
    - 14_sourcemap / 15_api_spec の結果（endpoint_key/schema）をクエリにフィードバックしてピンポイント探索へ
  - 期待する観測：
    - 境界情報としての記録と、別経路での探索

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/01_local/01_attack-box_作業端末設計.md`（結果の保存・差分管理）
    - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`（現状確認の最小証跡）
- 取得する証跡（目的ベースで最小限）
  - artifact_key（後工程に渡す正規化キー）
    - artifact_key = <platform> + <org/repo(or project)> + <run_id(or pipeline_id)> + <artifact_type> + <artifact_name> + <created_at>
  - 付随ラベル（必須）
    - source_locator, artifact_risk, environment_hint, privilege_hint, confidence, action_priority
  - 証跡化された漏えい情報（URL、run/pipeline識別子、該当箇所、タイムスタンプ、ハッシュ）
- 観測の取り方（どの視点で差分を見るか）
  - 公開設定により閲覧可能なCI/CD情報の観測、漏えい（key/token/credential/内部URL/設定断片）の発見、攻撃面の拡張
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/cicd_17 2>/dev/null
    cd ~/keda_evidence/cicd_17
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可されたスコープ** のみ（契約範囲/社内許可範囲/自前検証環境）
      - 観測は **代表点の抽出** のみ（公開設定により閲覧可能なCI/CD情報の観測、漏えいと攻撃面の抽出）
      - 観測視点（端末/経路/ネットワーク）を記録
  - 相関キー（最低限）を作る（後で必ず効く）
    - Platform：CI/CDプラットフォーム（GitHub Actions/GitLab CI/Jenkins等）
    - OrgRepo：org/repo(or project)
    - RunId：run_id(or pipeline_id)
    - ArtifactType：artifact_type（log/artifact/release/package/image）
    - ArtifactName：artifact_name
    - CreatedAt：created_at
    - ArtifactRisk：artifact_risk（leak_key/token_key/endpoint_key/config_key/info_only）
    - EnvironmentHint：environment_hint（prod/stg/dev/unknown）
    - PrivilegeHint：privilege_hint（read/write/admin/unknown）
    - Confidence：confidence（high/mid/low）
    - ActionPriority：action_priority（P0/P1/P2）
    - Timestamp：観測日時（JSTで秒まで）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は“手段”であり“結論”ではない。必ず「何を観測している例か」を添える。

~~~~
# 例：公開レポート/ArtifactsのURLを見つけた場合の“証跡化”観点

## 出力例（最小）
- `BUILD_URL` / `ENV` の残存が手がかり
# - URL

## 出力例（最小）
- `BUILD_URL` / `ENV` の残存が手がかり
# - 作成日時（表示される範囲）

## 出力例（最小）
- `BUILD_URL` / `ENV` の残存が手がかり
# - サイズ（過大ダウンロードを避ける）

## 出力例（最小）
- `BUILD_URL` / `ENV` の残存が手がかり
# - 種別（log / report / zip / container / package）

## 出力例（最小）
- `BUILD_URL` / `ENV` の残存が手がかり
# - 含まれる断片（endpoint/config/secret のどれか）

## 出力例（最小）
- `BUILD_URL` / `ENV` の残存が手がかり
~~~~

- この例で観測していること：
  - 公開設定により閲覧可能なCI/CD情報の観測、漏えい（key/token/credential/内部URL/設定断片）の発見、攻撃面の拡張
- 出力のどこを見るか（注目点）：
  - URL、作成日時、サイズ、種別、含まれる断片（endpoint/config/secret のどれか）
- この例が使えないケース（前提が崩れるケース）：
  - Private/Org 内部は、許可・権限がある場合のみ（本ファイルでは “探し方の設計” を中心にし、侵入的な行為は扱わない）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：V14（設定）：ビルド/デプロイ設定、秘密情報管理、ログ出力設計が直結。V1（アーキ/要件）：信頼境界（第三者SaaS/CI依存）と資産境界（環境/クラウド）を明確化。V13（API）：公開物からAPI endpoint/認証情報が漏れるとAPI防御の前提が崩れる
  - 該当要件（可能ならID）：外部依存・設定・通信・境界（ASM/OSINTは“前提の崩れ”を潰す役）
  - このファイルの内容が「満たす/破れる」ポイント：
    - 破れる：ビルド/デプロイ設定、秘密情報管理、ログ出力設計を確定できないと、以降の検証で“対象外”や“前提違い”を起こし、検証精度が落ちる。
    - 満たす：外部依存・設定・通信・境界（ASM/OSINTは“前提の崩れ”を潰す役）を把握し、以降の検証（認証/認可/API/運用）を「前提崩れ」なく進める土台を作る。
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：INFO：公開情報（ログ/成果物/レポート）から攻撃面・環境差分・認証材料の収集。CONF/CRYP（支える前提）：秘密情報をログ/成果物に出さない、保存しない、露出しない
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：WSTG各観点へ入る前の“入口確定”として接続
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Intelligence Gathering → Threat Modeling：CI/CD公開物から“現実のデプロイ経路”と“境界”を確定し、検証優先度を決める
  - 前後フェーズとの繋がり（1行）：CI/CD の公開物（ビルドログ、テストログ、成果物アーティファクト、リリース添付、パッケージ、コンテナイメージ等）を、ASM/OSINTの範囲で観測し、漏えいと攻撃面を抽出する
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Reconnaissance：公開情報（技術スタック/環境/エンドポイント/クラウド依存）の収集。Credential Access（支える前提）：ログ・成果物から認証材料が得られる可能性があるため、検知/対策観点も含めて整理
  - 攻撃者の目的（この技術が支える意図）：Reconnaissance / Discovery として、攻め筋の確率を上げるための境界特定・依存推定。
  - 参照：https://attack.mitre.org/tactics/TA0043/

## 参考（必要最小限）
- OWASP ASVS
  https://github.com/OWASP/ASVS
- OWASP WSTG
  https://owasp.org/www-project-web-security-testing-guide/
- PTES
  https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：Reconnaissance
  https://attack.mitre.org/tactics/TA0043/
- CI/CD各製品の “Artifacts/Logs/Packages/Pages” 公開設定の公式ドキュメント
- ソフトウェアサプライチェーン（SLSA、SBOM、署名）の基礎（公開物の意味づけ）

## リポジトリ内リンク（最大3つまで）
- 関連 topics：
  - `01_topics/01_asm-osint/16_github_code-search_漏えい（key_token_endpoint）.md`
  - `01_topics/01_asm-osint/14_js_sourcemap_公開物から攻撃面抽出（endpoint_key）.md`
- 関連 labs / cases：
  - `04_labs/01_local/01_attack-box_作業端末設計.md`

---

## 深掘りリンク（最大8）
- `01_topics/01_asm-osint/18_storage_discovery（S3_GCS_AzureBlob）境界推定.md`
- `01_topics/01_asm-osint/03_http_観測（ヘッダ/挙動）と意味.md`
- `01_topics/02_web/01_web_00_recon_入口・境界・攻め筋の確定.md`
- `01_topics/02_web/06_config_02_Secrets管理と漏えい経路（JS_ログ_設定_クラウド）.md`
- `02_playbooks/01_asm_passive-recon_資産境界→優先度付け.md`
- `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- `01_topics/01_asm-osint/15_api_spec_公開（OpenAPI_GraphQLスキーマ）から面抽出.md`
- `01_topics/04_saas/00_index.md`

---
