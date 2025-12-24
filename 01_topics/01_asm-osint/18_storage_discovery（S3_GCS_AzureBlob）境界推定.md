# 18_storage_discovery（S3_GCS_AzureBlob）境界推定
Storage Discovery（S3/GCS/AzureBlob）境界推定
“storage（バケット/アカウント/コンテナ）に関する資産境界・信頼境界・攻撃面（endpoint）の拡張”

## 目的（この技術で到達する状態）
クラウドストレージ（AWS S3 / Google Cloud Storage / Azure Blob Storage）の「露出面」を ASM/OSINT の範囲で観測し、次を「証跡つき」「優先度つき」で確定できる状態にする。
- storage（バケット/アカウント/コンテナ）に関する資産境界：どの名前・どのドメイン・どの環境（prod/stg/dev）に紐づくか
- 信頼境界：CDN/WAF/アプリ本体とストレージの関係、第三者（外注/分析基盤/マーケSaaS）経由の保管有無
- 攻撃面（endpoint）の拡張：アップロード/配布/静的資産/ログ置き場等の“入口候補”を増やす
- 「公開/非公開」「誤設定の疑い」「単なる参照」を切り分け、次工程（HTTP観測・JS/CIログ・API仕様）へ渡す

## 前提（対象・範囲・想定）
- 対象：クラウドストレージ（AWS S3 / Google Cloud Storage / Azure Blob Storage）の露出面。原則は OSINT（公開情報の観測）で完結させる
- 想定する環境：
  - “推測で名前を総当たり” するような行為は避ける（低アクティブ設計に反する）
  - 例外として、許可がある場合のみ「すでに観測できたURL/名前」に対して最小の到達性確認（HEAD/GETの軽量）を分岐として扱う
- できること/やらないこと（安全に検証する範囲）：
  - できる：OSINT（公開情報の観測）で完結させる。例外として、許可がある場合のみ「すでに観測できたURL/名前」に対して最小の到達性確認（HEAD/GETの軽量）を分岐として扱う
  - やらない：“推測で名前を総当たり” するような行為は避ける（低アクティブ設計に反する）。目的は “侵入” ではなく、境界と面の確定（意思決定）である
- 依存する前提知識（必要最小限）：
  - `01_topics/01_asm-osint/17_ci-cd_artifact_公開物（ログ_ビルド成果物）.md`
  - `01_topics/01_asm-osint/16_github_code-search_漏えい（key_token_endpoint）.md`
  - `01_topics/01_asm-osint/03_http_観測（ヘッダ・挙動）と意味.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：Storage Discovery（S3/GCS/AzureBlob）境界推定、資産境界・信頼境界・攻撃面の拡張
  - 扱わない（別ユニットへ接続）
    - CI/CD公開物 → `17_ci-cd_artifact_公開物（ログ_ビルド成果物）.md`
    - GitHub検索 → `16_github_code-search_漏えい（key_token_endpoint）.md`
    - HTTP観測 → `03_http_観測（ヘッダ/挙動）と意味.md`

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
- 観測対象（プロトコル/データ構造/やり取りの単位）
  - 入口（ストレージ参照の出どころ）を固定する
    - ストレージ名は「推測」ではなく、まず既存の公開面から回収する。
    - Web資産：HTML/JS/CSS、sourcemap、画像URL、ダウンロードリンク
    - API資産：OpenAPI/Swagger、GraphQL、レスポンス内の署名URL/配布URL
    - CI/CD公開物：ログ/成果物/レポート（17_ci-cd_artifact）
    - GitHub公開情報：config/.env/README/issue/PR（16_github_code-search）
    - DNS/TLS：SAN、CNAME、証明書CT、CDN配下の配布ドメイン（01_dns/02_tls/03_http）
    - メール/文書：請求書・採用資料・ヘルプ記事のダウンロード（19_email_infraにも接続）
  - URLパターンから “どのクラウドか” を即判定する
    - AWS S3（よく出る形）：
      - virtual-hosted style：`https://<bucket>.s3.amazonaws.com/<key>`, `https://<bucket>.s3.<region>.amazonaws.com/<key>`
      - path style（古い/互換）：`https://s3.amazonaws.com/<bucket>/<key>`, `https://s3.<region>.amazonaws.com/<bucket>/<key>`
    - GCS（Google Cloud Storage）：
      - `https://storage.googleapis.com/<bucket>/<object>`, `https://<bucket>.storage.googleapis.com/<object>`
      - 署名URL（Signed URL）として長いクエリ付きで出ることが多い
    - Azure Blob Storage：
      - `https://<account>.blob.core.windows.net/<container>/<blob>`
      - 環境差分（政府/中国/独自ドメイン）で末尾が変わる可能性はあるが、まずは blob.core.windows.net を入口にする
  - “境界推定” のために見るべき属性
    - 資産境界（Asset boundary）：名前（bucket / account / container）、環境ヒント（prod/stg/dev/test、リージョン、テナントID、プロジェクトID）、配布経路（直リンクか、CDN（CloudFront等）経由か、アプリ経由の署名URLか）
    - 信頼境界（Trust boundary）：third-party の痕跡（分析/広告/チャット/フォーム等の外部SaaSが “保管先” を持っていないか）、アップロード主体（ユーザアップロード（危険）/運用アップロード（静的）/CI生成物（レポート））
    - 権限境界（Privilege boundary）：公開読み取り（Public read）に見えるか、“AccessDenied/403” なのか “NoSuchBucket/404” なのか（※許可がある範囲の観測でのみ扱う）、署名URL（期限付き）なのか（= 恒久公開ではないが、漏えい経路として重要）
- 境界の観点
  - 資産境界（管理主体・委託先・対象範囲の線引き）：名前（bucket / account / container）、環境ヒント（prod/stg/dev/test、リージョン、テナントID、プロジェクトID）、配布経路（直リンクか、CDN（CloudFront等）経由か、アプリ経由の署名URLか）
  - 信頼境界（外部連携・第三者・越境ポイント）：third-party の痕跡（分析/広告/チャット/フォーム等の外部SaaSが “保管先” を持っていないか）、アップロード主体（ユーザアップロード（危険）/運用アップロード（静的）/CI生成物（レポート））
  - 権限境界（権限の切替/伝播/委任）：公開読み取り（Public read）に見えるか、“AccessDenied/403” なのか “NoSuchBucket/404” なのか（※許可がある範囲の観測でのみ扱う）、署名URL（期限付き）なのか（= 恒久公開ではないが、漏えい経路として重要）
- 重要なフィールド/差分/状態（「ここが変わると意味が変わる」点）
  - storage_key_boundary（後工程に渡す正規化キー）
    - storage_key_boundary = <cloud>(aws|gcp|azure) + <bucket_or_account> + <container_optional> + <environment_hint> + <access_hint>
  - access_hint（OSINTで付けるラベル）
    - public_suspected | private_suspected | signed_url_seen | cdn_fronted | unknown

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が“確定”できるか
  - “どのストレージ識別子が使われているか” と “どの面から参照されているか” が確定する
  - 配布経路（直リンク/署名URL/CDN/アプリ経由）から、信頼境界とリスク種別を分類できる
  - 環境名が混ざれば、境界（prod/stg/dev）取り違えの可能性を提示できる
- 何が“推定”できるか（推定の根拠/前提）
  - バケット/コンテナの存在・公開設定の真偽（アクティブ確認が必要な場合がある）
- 何は“言えない”か（不足情報・観測限界）
  - バケット/コンテナの存在・公開設定の真偽（アクティブ確認が必要な場合がある）
  - 読み取り/書き込みの実可否（権限検証は別工程・合意が必要）
  - “推測名” の妥当性（本ファイルでは総当たりをしないため）
- よくある状態パターン（正常/異常/境界がズレている等）
  - パターンA：観測した storage URL が “公開読み取りの疑い” を含む（P0/P1）
  - パターンB：署名URLのみが見える（= ストレージは非公開だが“発行API”が面）
  - パターンC：参照はあるが、ストレージ識別子が不明（CDN/独自ドメインで隠れている）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す“狙い目”（診断上の優先度付けとして使う）
  - P0（即時確認レベル）：ユーザアップロード起点の可能性（/upload/、profile画像、添付ファイル）＋ 直リンク配布、CI生成物/ログ/バックアップっぽいパス（report、backup、db、dump、logs 等）の参照が見える、“本番らしさ” が強い識別子（prod、corp、customer、billing等）と結びつく
  - P1（優先的に面へ投入）：署名URLが頻出（期限付きでも、漏えい経路・権限設計のヒント）、CDN前段あり（storage単独では叩けないが、配布ドメインが攻撃面として残る）、stg/dev が露出（本番より弱い制御である可能性）
  - P2（情報整備）：静的資産（css/js/image）のみで、配布は通常運用の範囲、参照はあるが環境/用途が不明（後続で裏取り）
- 優先度の付け方（時間制約がある場合の順序）
  - P0（即時確認レベル）→ P1（優先的に面へ投入）→ P2（情報整備）の順
- 代表的な攻め筋（この観測から自然に繋がるもの）
  - 攻め筋1：直リンク配布 → 03_http 観測で境界（キャッシュ/ヘッダ/認証有無）の把握へ
  - 攻め筋2：署名URL → “誰が発行しているか”（API/バックエンド）を 15_api_spec / 02_web へ接続
  - 攻め筋3：バケット名/アカウント名の命名規則 → 05_cloud 露出面推定（CDN/WAF/Storage）に統合
  - 攻め筋4：storage URL が GitHub/CI にも現れる → 16/17 と相関し、恒常露出かを判定
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）
  - 参照はあるが、ストレージ識別子が不明（CDN/独自ドメインで隠れている） → DNS/TLS（CNAME、証明書SAN、CT）から “配布ドメイン→実体” の手がかりを集める

## 次に試すこと（仮説A/Bの分岐と検証）
> ここが最重要。条件が違うと次の手が変わる形で書く。

- 仮説A：観測した storage URL が “公開読み取りの疑い” を含む（P0/P1）
  - 次の検証：
    - （OSINTの安全域）同一識別子（bucket/account/container）が複数ソースに出るか（JS、API、CI、ドキュメント）を確認し、confidence を上げる。参照パスの用途を分類（static / user_upload / report / backup / log）。“発行主体” を推定：署名URLならAPI側、直リンクならフロント/静的配布側
    - （許可がある場合のみ：最小アクティブ）既に観測できたURLに対して、軽量に到達性を確認（HEAD/GET最小、過大DLを避ける）。返り値（200/403/404/リダイレクト）を “境界の事実” として記録し、公開/非公開の判定に使う
  - 期待する観測（成功/失敗時に何が見えるか）：
    - 同一識別子が複数ソースに出るか、参照パスの用途分類、“発行主体” の推定、到達性確認の結果
- 仮説B：署名URLのみが見える（= ストレージは非公開だが“発行API”が面）
  - 次の検証：
    - 署名URLの発行元になっている機能を探す（ダウンロードAPI、添付取得API）
    - 15_api_spec の面抽出へ接続し、署名URL発行に関与する endpoint_key_schema を優先度上げ
    - 02_web（認証/セッション）観測へ接続し、誰の権限で何が発行できる設計かを仮説化
  - 期待する観測：
    - 署名URLの発行元機能、endpoint_key_schema、認証/セッション観測の結果
- 仮説C：参照はあるが、ストレージ識別子が不明（CDN/独自ドメインで隠れている）
  - 次の検証：
    - DNS/TLS（CNAME、証明書SAN、CT）から “配布ドメイン→実体” の手がかりを集める
    - 03_http 観測で CDN/WAF の前段を判定し、背後のオリジン推定を 05_cloud へ統合
    - 16_github / 17_ci-cd に戻って config 断片（origin、bucket、account名）を追加探索
  - 期待する観測：
    - 配布ドメイン→実体の手がかり、CDN/WAFの前段判定、config断片の探索結果

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/01_local/01_attack-box_作業端末設計.md`（結果の保存・差分管理）
    - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`（現状確認の最小証跡）
- 取得する証跡（目的ベースで最小限）
  - storage_key_boundary（後工程に渡す正規化キー）
    - storage_key_boundary = <cloud>(aws|gcp|azure) + <bucket_or_account> + <container_optional> + <environment_hint> + <access_hint>
  - 記録の最小フィールド（推奨）
    - source_locator: 観測元URL（JS/HTML/API/ログ等）
    - storage_locator: ストレージURL（観測できた形のまま）
    - parsed_identity: bucket/account/container（抽出した識別子）
    - environment_hint: prod/stg/dev/unknown
    - confidence: high/mid/low（形式一致・文脈一致・複数箇所一致）
    - action_priority: P0/P1/P2
- 観測の取り方（どの視点で差分を見るか）
  - OSINT（公開情報の観測）で完結させる。例外として、許可がある場合のみ「すでに観測できたURL/名前」に対して最小の到達性確認（HEAD/GETの軽量）を分岐として扱う
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/storage_18 2>/dev/null
    cd ~/keda_evidence/storage_18
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可されたスコープ** のみ（契約範囲/社内許可範囲/自前検証環境）
      - 観測は **代表点の抽出** のみ（OSINT（公開情報の観測）で完結させる）
      - 観測視点（端末/経路/ネットワーク）を記録
  - 相関キー（最低限）を作る（後で必ず効く）
    - Cloud：クラウド（aws/gcp/azure）
    - BucketOrAccount：bucket_or_account
    - Container：container（オプション）
    - EnvironmentHint：environment_hint（prod/stg/dev/unknown）
    - AccessHint：access_hint（public_suspected/private_suspected/signed_url_seen/cdn_fronted/unknown）
    - SourceLocator：source_locator（観測元URL）
    - StorageLocator：storage_locator（ストレージURL）
    - ParsedIdentity：parsed_identity（bucket/account/container）
    - Confidence：confidence（high/mid/low）
    - ActionPriority：action_priority（P0/P1/P2）
    - Timestamp：観測日時（JSTで秒まで）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は“手段”であり“結論”ではない。必ず「何を観測している例か」を添える。

~~~~
# 最小の記録例（HTTP観測の扱い）
# - URL（観測済みのもののみ）
# - 時刻
# - ステータス（例：200 / 403 / 404）
# - 応答ヘッダの特徴（Server, x-amz-*, x-goog-*, x-ms-* など）
# - サイズ（過大DL回避のため）
~~~~

- この例で観測していること：
  - OSINT（公開情報の観測）で完結させる。例外として、許可がある場合のみ「すでに観測できたURL/名前」に対して最小の到達性確認（HEAD/GETの軽量）を分岐として扱う
- 出力のどこを見るか（注目点）：
  - URL、時刻、ステータス（200/403/404）、応答ヘッダの特徴（Server, x-amz-*, x-goog-*, x-ms-* など）、サイズ（過大DL回避のため）
- この例が使えないケース（前提が崩れるケース）：
  - “推測で名前を総当たり” するような行為は避ける（低アクティブ設計に反する）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：V14（設定）：クラウドストレージの公開設定、アクセス制御、ログ/成果物保管の設計が直結。V13（API）：署名URL発行やアップロードAPIは APIセキュリティの主戦場（認証/認可/入力）。V1（アーキ/要件）：資産境界・信頼境界（CDN/第三者SaaS）を定義する入力になる
  - 該当要件（可能ならID）：外部依存・設定・通信・境界（ASM/OSINTは“前提の崩れ”を潰す役）
  - このファイルの内容が「満たす/破れる」ポイント：
    - 破れる：クラウドストレージの公開設定、アクセス制御、ログ/成果物保管の設計を確定できないと、以降の検証で“対象外”や“前提違い”を起こし、検証精度が落ちる。
    - 満たす：外部依存・設定・通信・境界（ASM/OSINTは“前提の崩れ”を潰す役）を把握し、以降の検証（認証/認可/API/運用）を「前提崩れ」なく進める土台を作る。
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：INFO：公開情報（URL/JS/ドキュメント/ログ）から外部資産と攻撃面を確定する。APIT（支える前提）：署名URL発行/アップロード/ダウンロードのAPI設計を後続で検証する前提整理
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：WSTG各観点へ入る前の“入口確定”として接続
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Intelligence Gathering → Threat Modeling：ストレージ境界を確定し、優先度（P0/P1/P2）を決めて次工程へ渡す
  - 前後フェーズとの繋がり（1行）：クラウドストレージ（AWS S3 / Google Cloud Storage / Azure Blob Storage）の「露出面」を ASM/OSINT の範囲で観測し、資産境界・信頼境界・攻撃面を抽出する
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Reconnaissance：公開情報からクラウド依存と資産境界を収集。Collection（支える前提）：誤公開や配布面は情報収集経路になり得るため、防御観点の重要入力
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
- 各クラウドのストレージURL形式（S3/GCS/Azure Blob）
- 署名URL（Signed URL / SAS）と期限・権限モデルの概念

## リポジトリ内リンク（最大3つまで）
- 関連 topics：
  - `01_topics/01_asm-osint/17_ci-cd_artifact_公開物（ログ_ビルド成果物）.md`
  - `01_topics/01_asm-osint/03_http_観測（ヘッダ/挙動）と意味.md`
- 関連 labs / cases：
  - `04_labs/01_local/01_attack-box_作業端末設計.md`

---

## 深掘りリンク（最大8）
- `01_topics/01_asm-osint/16_github_code-search_漏えい（key_token_endpoint）.md`
- `01_topics/01_asm-osint/15_api_spec_公開（OpenAPI_GraphQLスキーマ）から面抽出.md`
- `01_topics/01_asm-osint/05_cloud_露出面（CDN_WAF_Storage等）推定.md`
- `01_topics/02_web/01_web_00_recon_入口・境界・攻め筋の確定.md`
- `02_playbooks/01_asm_passive-recon_資産境界→優先度付け.md`
- `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- `01_topics/01_asm-osint/19_email_infra（SPF_DKIM_DMARC）と攻撃面.md`
- `01_topics/01_asm-osint/01_dns_委譲・境界・解釈.md`

---
