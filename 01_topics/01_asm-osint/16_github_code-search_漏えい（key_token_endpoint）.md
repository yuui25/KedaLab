# 16_github_code-search_漏えい（key_token_endpoint）
GitHub Code Search 漏えい（key/token/endpoint）
“鍵・トークン・内部エンドポイント・設定断片”を漏れなく収集し、次工程へ渡せる状態にする

## 目的（この技術で到達する状態）
GitHub 上に露出している「鍵・トークン・内部エンドポイント・設定断片」を、ASM/OSINTの範囲で漏れなく収集し、次工程（HTTP観測/サブドメイン列挙/クラウド露出推定/認証・認可検証）へ渡せる状態にする。
- key_token_endpoint を「証跡つき」「優先度つき」「境界（資産/信頼/権限）つき」で整理できる
- “実害の可能性が高い漏えい” と “攻撃面の推定に効く断片” を分離し、対応を迷わない
- 「検証せずに（使わずに）危険度を判定する」ための判断軸を持つ（OSINTの安全域）

## 前提（対象・範囲・想定）
- 対象：Public repo / Public gists / Public issues・PR・discussions / 公開されている Actions ログやリリース成果物（公開設定のもの）。Private/Org 内部は、許可・権限がある場合のみ（本ファイルでは “探し方の設計” を中心にし、侵入的な行為は扱わない）
- 想定する環境：
  - 検索は “広く浅く” から入り、確度が高い箇所だけ “狭く深く” に寄せる（ノイズ制御が品質）
  - 目的は「漏えいの有無と攻撃面の確定」であり、見つけた認証情報を“利用してログイン確認する”ことは原則しない（必要なら合意の上で別工程）
- できること/やらないこと（安全に検証する範囲）：
  - できる：公開情報の収集、漏えいの有無と攻撃面の確定、優先度付け
  - やらない：見つけた認証情報を“利用してログイン確認する”ことは原則しない（必要なら合意の上で別工程）。侵入的な行為は扱わない。
- 依存する前提知識（必要最小限）：
  - `01_topics/01_asm-osint/14_js_sourcemap_公開物から攻撃面抽出（endpoint_key）.md`
  - `01_topics/01_asm-osint/15_api_spec_公開（OpenAPI_GraphQLスキーマ）から面抽出.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：GitHub Code Search 漏えい（key/token/endpoint）、優先度付け、境界の特定
  - 扱わない（別ユニットへ接続）
    - Sourcemap → `14_js_sourcemap_公開物から攻撃面抽出（endpoint_key）.md`
    - API仕様 → `15_api_spec_公開（OpenAPI_GraphQLスキーマ）から面抽出.md`
    - Secrets管理 → `01_topics/02_web/06_config_02_Secrets管理と漏えい経路（JS_ログ_設定_クラウド）.md`

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
- 観測対象（プロトコル/データ構造/やり取りの単位）
  - 資産境界：どこまでが「対象のGitHub露出」か
    - 公式Org / 公式ユーザ / 関連会社 / 旧Org / 子会社 / OSSプロジェクト（プロダクト別）を区別する
    - fork / mirror / 個人アカウント（従業員）を「対象外」にしないが、優先度と扱いを分ける（誤検知・責任境界の差）
    - “検索対象面” を分解する（コードだけでなくテキスト面がある）
      - repo（default branch / tag / release）
      - commit（過去に存在した秘匿情報）
      - issue / PR / discussion（貼り付け・ログ添付・設定共有）
      - wiki（運用手順の断片）
      - gist（個人運用の断片）
      - Actions（ログ・artifact・環境変数露出の断片）※公開設定のもの
  - データ境界：何が出たら「key/token/endpoint」か
    - key（長期秘密）：秘密鍵、サービスアカウント鍵、クラウド鍵、署名鍵、SSH鍵、PGP鍵、暗号鍵素材（base64等）
    - token（短期〜中期）：API token、Personal access token、CI token、Webhook secret、JWT（署名済み）、セッショントークン断片
    - endpoint（攻撃面）：内部API URL、管理画面URL、staging/dev URL、GraphQL endpoint、Swagger/OpenAPI URL、webhook URL、storage URL
    - config（境界の断片）：.env、config.yml、terraform state断片、kubeconfig断片、DB接続文字列、OIDC/SAML設定断片（issuer/client_id/redirect_uri 等）
  - 権限境界：それは「どの権限で効く情報」か
    - key/token/endpoint を見つけたら、必ず “権限境界ラベル” を付ける。
    - 影響範囲：個人（dev）/ チーム / 本番 / 顧客環境
    - 権限種別：読み取り / 書き込み / 管理者 / 認証回避（署名鍵など）
    - 期限：短期（CI一時トークン）/ 中期（PAT）/ 長期（鍵）
    - 露出の場所：現行コード / 過去コミット / issue添付 / Actionsログ など（回収難易度が変わる）
  - 収集の単位（key_token_endpoint の正規化）
    - 漏えい断片は「後工程で使える形」に正規化して記録する。
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
- 境界の観点
  - 資産境界（管理主体・委託先・対象範囲の線引き）：公式Org / 公式ユーザ / 関連会社 / 旧Org / 子会社 / OSSプロジェクト（プロダクト別）を区別する。fork / mirror / 個人アカウント（従業員）を「対象外」にしないが、優先度と扱いを分ける（誤検知・責任境界の差）
  - 信頼境界（外部連携・第三者・越境ポイント）：third-party（SaaS/クラウド/外部API）有無を trust_boundary として整理し、後続（18/21/23）へ渡す
  - 権限境界（権限の切替/伝播/委任）：影響範囲（個人（dev）/ チーム / 本番 / 顧客環境）、権限種別（読み取り / 書き込み / 管理者 / 認証回避）、期限（短期/中期/長期）を privilege_boundary として整理する
- 重要なフィールド/差分/状態（「ここが変わると意味が変わる」点）
  - source_type（repo/commit/issue_pr/discussion/wiki/gist/actions_log/release_asset）
  - artifact_type（key/token/endpoint/config）
  - confidence（high/mid/low）
  - action_priority（P0/P1/P2）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が“確定”できるか
  - 「本来は秘匿されるべきもの」が公開面に存在する、または過去に存在した可能性が高い
  - endpoint が見つかった場合、ASMでの“攻撃面（入口候補）”が増える（特に stg/dev/admin は優先度が上がる）
  - config 断片が見つかった場合、資産境界（どのクラウド/どのIdP/どの外部SaaSか）と信頼境界（第三者依存）が具体化する
- 何が“推定”できるか（推定の根拠/前提）
  - その鍵/トークンが現在も有効か（有効性確認は別工程・合意が必要）
- 何は“言えない”か（不足情報・観測限界）
  - その鍵/トークンが現在も有効か（有効性確認は別工程・合意が必要）
  - その endpoint が到達可能か（WAF/ネットワーク/認証で遮断される可能性）
  - それが本当に対象組織の管理下か（fork・個人repo・サンプルコードの可能性）
- よくある状態パターン（正常/異常/境界がズレている等）
  - パターンA：秘匿情報（key/token）の可能性が高い（P0/P1）
  - パターンB：endpoint/config 断片が中心（P2が多い）
  - パターンC：見つからない（ノイズは多いが確証がない）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す“狙い目”（診断上の優先度付けとして使う）
  - P0（即時対応レベル）：長期秘密（秘密鍵・署名鍵・クラウド鍵素材）の疑いが強い、本番系の管理権限に繋がり得る設定（IdP設定、Webhook secret、CIの固定token 等）
  - P1（緊急確認レベル）：token らしき形式一致＋文脈一致（例：READMEに貼り付け、ログに出力）、“管理画面/内部API/ステージング” の endpoint が明確（面が増える）
  - P2（攻撃面投入レベル）：endpoint/設定断片のみ（直接の認証材料ではないが、後工程の探索精度が上がる）、旧コミットにのみ存在し、現行では削除済み（ただし履歴から回収され得る）
- 優先度の付け方（時間制約がある場合の順序）
  - P0（即時対応レベル）→ P1（緊急確認レベル）→ P2（攻撃面投入レベル）の順
- 代表的な攻め筋（この観測から自然に繋がるもの）
  - 攻め筋1：endpoint が出た → 01_asm-osint/03_http 観測へ投入（到達性・認証境界の薄い確認）
  - 攻め筋2：OpenAPI/Swagger/GraphQL が出た → 15_api_spec の “面抽出（endpoint_key_schema）” に接続
  - 攻め筋3：storage URL が出た → 18_storage_discovery（境界推定）へ接続
  - 攻め筋4：IdP/OIDC/SAMLの断片が出た → 02_web の認証/SSO観測（state/nonce/redirect_uri等）に接続
  - 攻め筋5：“ログの貼り付け” が出た → 17_ci-cd_artifact（公開ログ/成果物）で再現性ある観測に拡張
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）
  - 見つからない（ノイズは多いが確証がない） → 対象境界の見直し（旧Org名、旧プロダクト名、関連会社、OSS名、ドメイン別名）、“コード検索だけ”に寄っていないかを見直す（issue/PR/discussions/gist/actions を追加）

## 次に試すこと（仮説A/Bの分岐と検証）
> ここが最重要。条件が違うと次の手が変わる形で書く。

- 仮説A：秘匿情報（key/token）の可能性が高い（P0/P1）
  - 次の検証：
    - 収集は「証跡化」まで：URL/コミット/行番号/スクショ/ハッシュ（全文を横流ししない）
    - “形式一致” と “文脈一致” を切り分けて confidence を付ける（高/中/低）
    - 関係者へ連絡する前提で「最小の再現メモ」を作る（どこに、何が、どの権限に効きそうか）
    - （合意がある場合のみ）失効/ローテーション方針（鍵の再発行、トークン無効化、権限最小化、過去コミットの扱い）、影響確認は“ログ確認”を優先し、実トークン利用の検証は最終手段にする
  - 期待する観測（成功/失敗時に何が見えるか）：
    - 証跡化された漏えい情報と、最小の再現メモ
- 仮説B：endpoint/config 断片が中心（P2が多い）
  - 次の検証：
    - endpoint を “環境別（prod/stg/dev）” にタグ付けし、HTTP観測へ投入して境界（401/403/404/302）を取る
    - 依存先（SaaS/クラウド）を trust_boundary として整理し、後続（18/21/23）へ渡す
    - “同じ断片が複数箇所に出る” 場合は優先度を上げる（運用上の恒常露出の疑い）
  - 期待する観測：
    - endpoint/config 断片の整理と、HTTP観測への投入
- 仮説C：見つからない（ノイズは多いが確証がない）
  - 次の検証：
    - 対象境界の見直し（旧Org名、旧プロダクト名、関連会社、OSS名、ドメイン別名）
    - “コード検索だけ”に寄っていないかを見直す（issue/PR/discussions/gist/actions を追加）
    - 14_sourcemap や 15_api_spec で得た endpoint_key/schema を検索クエリにフィードバックし、ピンポイント探索へ寄せる
  - 期待する観測：
    - 対象境界の見直しと、検索クエリの改善

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/01_local/01_attack-box_作業端末設計.md`（結果の保存・差分管理）
    - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`（現状確認の最小証跡）
- 取得する証跡（目的ベースで最小限）
  - key_token_endpoint レコード（推奨フィールド）
    - source_type, source_locator, artifact_type, artifact_fingerprint, asset_boundary, trust_boundary, privilege_boundary, confidence, action_priority
  - 証跡化された漏えい情報（URL/コミット/行番号/スクショ/ハッシュ）
  - 最小の再現メモ（どこに、何が、どの権限に効きそうか）
- 観測の取り方（どの視点で差分を見るか）
  - 検索は “広く浅く” から入り、確度が高い箇所だけ “狭く深く” に寄せる（ノイズ制御が品質）
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/github_16 2>/dev/null
    cd ~/keda_evidence/github_16
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可されたスコープ** のみ（契約範囲/社内許可範囲/自前検証環境）
      - 観測は **代表点の抽出** のみ（公開情報の収集、漏えいの有無と攻撃面の確定、優先度付け）
      - 観測視点（端末/経路/ネットワーク）を記録
  - 相関キー（最低限）を作る（後で必ず効く）
    - SourceType：source_type（repo/commit/issue_pr/discussion/wiki/gist/actions_log/release_asset）
    - SourceLocator：source_locator（org/repo + path + ref + 行番号 or URL）
    - ArtifactType：artifact_type（key/token/endpoint/config）
    - ArtifactFingerprint：artifact_fingerprint（先頭/末尾数文字 + ハッシュ）
    - AssetBoundary：asset_boundary（対象Org/プロダクト/環境）
    - TrustBoundary：trust_boundary（third-party有無）
    - PrivilegeBoundary：privilege_boundary（想定権限）
    - Confidence：confidence（high/mid/low）
    - ActionPriority：action_priority（P0/P1/P2）
    - Timestamp：観測日時（JSTで秒まで）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は“手段”であり“結論”ではない。必ず「何を観測している例か」を添える。

~~~~
# 最小の検索クエリ例（“広く浅く”）

## 出力例（最小）
- `<TOKEN>` のプレフィックス/命名規則を抽出
# ※クエリは最小限の例。対象名（Org/ドメイン/プロダクト名）を差し替えて使う。

## 出力例（最小）
- `<TOKEN>` のプレフィックス/命名規則を抽出

# 入口：.env / config / secret 断片

## 出力例（最小）
- `<TOKEN>` のプレフィックス/命名規則を抽出
org:<ORG> (filename:.env OR filename:config.yml OR filename:settings.py) (SECRET OR TOKEN OR KEY)

# 入口：URL（endpoint断片）

## 出力例（最小）
- `<TOKEN>` のプレフィックス/命名規則を抽出
org:<ORG> ("https://" OR "http://") (staging OR dev OR admin OR internal)

# 入口：クラウド/ストレージの断片（境界推定へ接続）

## 出力例（最小）
- `<TOKEN>` のプレフィックス/命名規則を抽出
org:<ORG> (s3.amazonaws.com OR ".blob.core.windows.net" OR "storage.googleapis.com")

# 入口：Swagger / OpenAPI / GraphQL（面抽出へ接続）

## 出力例（最小）
- `<TOKEN>` のプレフィックス/命名規則を抽出
org:<ORG> (openapi OR swagger OR "swagger.json" OR "openapi.json" OR graphql OR graphiql)
~~~~

- この例で観測していること：
  - 公開情報の収集、漏えいの有無と攻撃面の確定、優先度付け
- 出力のどこを見るか（注目点）：
  - 検索結果から key/token/endpoint/config を抽出し、key_token_endpoint レコードとして整理する
- この例が使えないケース（前提が崩れるケース）：
  - Private/Org 内部は、許可・権限がある場合のみ（本ファイルでは “探し方の設計” を中心にし、侵入的な行為は扱わない）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：V14（設定）：秘密情報の管理、設定の露出、セキュアなデプロイ運用に直結。V13（API）：APIキー/トークン/エンドポイント露出が API セキュリティ全般の前提を破る。V1（アーキ/要件）：信頼境界・外部依存の把握（脅威モデリングの入力）
  - 該当要件（可能ならID）：外部依存・設定・通信・境界（ASM/OSINTは“前提の崩れ”を潰す役）
  - このファイルの内容が「満たす/破れる」ポイント：
    - 破れる：秘密情報の管理、設定の露出、セキュアなデプロイ運用を確定できないと、以降の検証で“対象外”や“前提違い”を起こし、検証精度が落ちる。
    - 満たす：外部依存・設定・通信・境界（ASM/OSINTは“前提の崩れ”を潰す役）を把握し、以降の検証（認証/認可/API/運用）を「前提崩れ」なく進める土台を作る。
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：INFO：公開情報（コード/ドキュメント/ログ）からの攻撃面・環境差分・認証材料の収集。CRYP/CONF（該当が薄い場合でも“秘匿情報が公開される”前提を支える）：鍵・トークン露出の発見は後続検証の安全設計に必要
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：WSTG各観点へ入る前の“入口確定”として接続
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Intelligence Gathering → Threat Modeling：公開情報から資産境界・信頼境界・権限境界を具体化し、検証優先度を決める
  - 前後フェーズとの繋がり（1行）：GitHub 上に露出している「鍵・トークン・内部エンドポイント・設定断片」を、ASM/OSINTの範囲で漏れなく収集し、次工程へ渡せる状態にする
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Reconnaissance：公開情報の収集（組織/技術/エンドポイント/クラウド依存）。Resource Development / Credential Access（支える前提として）：認証材料・アクセス手掛かりの獲得に繋がる断片の発見
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
- GitHub 検索（code/commits/issues/PR/discussions/gists）の公式仕様とクエリ演算子
  https://docs.github.com/en/search-github/searching-on-github
- secret scanning / gitleaks / trufflehog 等（組織内での防御的スキャンとして）

## リポジトリ内リンク（最大3つまで）
- 関連 topics：
  - `01_topics/01_asm-osint/14_js_sourcemap_公開物から攻撃面抽出（endpoint_key）.md`
  - `01_topics/01_asm-osint/15_api_spec_公開（OpenAPI_GraphQLスキーマ）から面抽出.md`
- 関連 labs / cases：
  - `04_labs/01_local/01_attack-box_作業端末設計.md`

---

## 深掘りリンク（最大8）
- `01_topics/01_asm-osint/03_http_観測（ヘッダ/挙動）と意味.md`
- `01_topics/01_asm-osint/18_storage_discovery（S3_GCS_AzureBlob）境界推定.md`
- `01_topics/02_web/01_web_00_recon_入口・境界・攻め筋の確定.md`
- `01_topics/02_web/06_config_02_Secrets管理と漏えい経路（JS_ログ_設定_クラウド）.md`
- `02_playbooks/01_asm_passive-recon_資産境界→優先度付け.md`
- `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- `01_topics/01_asm-osint/17_ci-cd_artifact_公開物（ログ_ビルド成果物）.md`
- `01_topics/04_saas/00_index.md`

---
