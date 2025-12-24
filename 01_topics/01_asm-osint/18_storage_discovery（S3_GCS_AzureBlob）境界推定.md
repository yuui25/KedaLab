# storage_discovery（S3_GCS_AzureBlob）境界推定

## 目的（この技術で到達する状態）
クラウドストレージ（AWS S3 / Google Cloud Storage / Azure Blob Storage）の「露出面」を ASM/OSINT の範囲で観測し、次を「証跡つき」「優先度つき」で確定できる状態にする。
- storage（バケット/アカウント/コンテナ）に関する資産境界：どの名前・どのドメイン・どの環境（prod/stg/dev）に紐づくか
- 信頼境界：CDN/WAF/アプリ本体とストレージの関係、第三者（外注/分析基盤/マーケSaaS）経由の保管有無
- 攻撃面（endpoint）の拡張：アップロード/配布/静的資産/ログ置き場等の“入口候補”を増やす
- 「公開/非公開」「誤設定の疑い」「単なる参照」を切り分け、次工程（HTTP観測・JS/CIログ・API仕様）へ渡す

## 前提（対象・範囲・想定）
- 原則は OSINT（公開情報の観測）で完結させる
- “推測で名前を総当たり” するような行為は避ける（低アクティブ設計に反する）
- 例外として、許可がある場合のみ「すでに観測できたURL/名前」に対して最小の到達性確認（HEAD/GETの軽量）を分岐として扱う
- 目的は “侵入” ではなく、境界と面の確定（意思決定）である

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) 入口（ストレージ参照の出どころ）を固定する
ストレージ名は「推測」ではなく、まず既存の公開面から回収する。
- Web資産：HTML/JS/CSS、sourcemap、画像URL、ダウンロードリンク
- API資産：OpenAPI/Swagger、GraphQL、レスポンス内の署名URL/配布URL
- CI/CD公開物：ログ/成果物/レポート（17_ci-cd_artifact）
- GitHub公開情報：config/.env/README/issue/PR（16_github_code-search）
- DNS/TLS：SAN、CNAME、証明書CT、CDN配下の配布ドメイン（01_dns/02_tls/03_http）
- メール/文書：請求書・採用資料・ヘルプ記事のダウンロード（19_email_infraにも接続）

### 2) URLパターンから “どのクラウドか” を即判定する
#### AWS S3（よく出る形）
- virtual-hosted style
  - https://<bucket>.s3.amazonaws.com/<key>
  - https://<bucket>.s3.<region>.amazonaws.com/<key>
- path style（古い/互換）
  - https://s3.amazonaws.com/<bucket>/<key>
  - https://s3.<region>.amazonaws.com/<bucket>/<key>

#### GCS（Google Cloud Storage）
- https://storage.googleapis.com/<bucket>/<object>
- https://<bucket>.storage.googleapis.com/<object>
- 署名URL（Signed URL）として長いクエリ付きで出ることが多い

#### Azure Blob Storage
- https://<account>.blob.core.windows.net/<container>/<blob>
- 環境差分（政府/中国/独自ドメイン）で末尾が変わる可能性はあるが、まずは blob.core.windows.net を入口にする

### 3) “境界推定” のために見るべき属性
- 資産境界（Asset boundary）
  - 名前：bucket / account / container（命名規則、プロダクト名、環境名）
  - 環境ヒント：prod/stg/dev/test、リージョン、テナントID、プロジェクトID
  - 配布経路：直リンクか、CDN（CloudFront等）経由か、アプリ経由の署名URLか
- 信頼境界（Trust boundary）
  - third-party の痕跡：分析/広告/チャット/フォーム等の外部SaaSが “保管先” を持っていないか
  - アップロード主体：ユーザアップロード（危険）/運用アップロード（静的）/CI生成物（レポート）
- 権限境界（Privilege boundary）
  - 公開読み取り（Public read）に見えるか
  - “AccessDenied/403” なのか “NoSuchBucket/404” なのか（※許可がある範囲の観測でのみ扱う）
  - 署名URL（期限付き）なのか（= 恒久公開ではないが、漏えい経路として重要）

### 4) storage_key_boundary（後工程に渡す正規化キー）
- storage_key_boundary（推奨）
  - storage_key_boundary = <cloud>(aws|gcp|azure) + <bucket_or_account> + <container_optional> + <environment_hint> + <access_hint>
- access_hint（OSINTで付けるラベル）
  - public_suspected | private_suspected | signed_url_seen | cdn_fronted | unknown

記録の最小フィールド（推奨）
- source_locator: 観測元URL（JS/HTML/API/ログ等）
- storage_locator: ストレージURL（観測できた形のまま）
- parsed_identity: bucket/account/container（抽出した識別子）
- environment_hint: prod/stg/dev/unknown
- confidence: high/mid/low（形式一致・文脈一致・複数箇所一致）
- action_priority: P0/P1/P2（後述）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える（OSINTで確定できる）
  - “どのストレージ識別子が使われているか” と “どの面から参照されているか” が確定する
  - 配布経路（直リンク/署名URL/CDN/アプリ経由）から、信頼境界とリスク種別を分類できる
  - 環境名が混ざれば、境界（prod/stg/dev）取り違えの可能性を提示できる
- 言えない（この段階では確定しない）
  - バケット/コンテナの存在・公開設定の真偽（アクティブ確認が必要な場合がある）
  - 読み取り/書き込みの実可否（権限検証は別工程・合意が必要）
  - “推測名” の妥当性（本ファイルでは総当たりをしないため）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
### 優先度（P0/P1/P2）
- P0（即時確認レベル）
  - ユーザアップロード起点の可能性（/upload/、profile画像、添付ファイル）＋ 直リンク配布
  - CI生成物/ログ/バックアップっぽいパス（report、backup、db、dump、logs 等）の参照が見える
  - “本番らしさ” が強い識別子（prod、corp、customer、billing等）と結びつく
- P1（優先的に面へ投入）
  - 署名URLが頻出（期限付きでも、漏えい経路・権限設計のヒント）
  - CDN前段あり（storage単独では叩けないが、配布ドメインが攻撃面として残る）
  - stg/dev が露出（本番より弱い制御である可能性）
- P2（情報整備）
  - 静的資産（css/js/image）のみで、配布は通常運用の範囲
  - 参照はあるが環境/用途が不明（後続で裏取り）

### 代表的な“攻め筋”への接続（行為ではなく設計）
- 直リンク配布 → 03_http 観測で境界（キャッシュ/ヘッダ/認証有無）の把握へ
- 署名URL → “誰が発行しているか”（API/バックエンド）を 15_api_spec / 02_web へ接続
- バケット名/アカウント名の命名規則 → 05_cloud 露出面推定（CDN/WAF/Storage）に統合
- storage URL が GitHub/CI にも現れる → 16/17 と相関し、恒常露出かを判定

## 次に試すこと（仮説A/Bの分岐と検証）
### 仮説A：観測した storage URL が “公開読み取りの疑い” を含む（P0/P1）
- 次の一手（OSINTの安全域）
  - 同一識別子（bucket/account/container）が複数ソースに出るか（JS、API、CI、ドキュメント）を確認し、confidence を上げる
  - 参照パスの用途を分類（static / user_upload / report / backup / log）
  - “発行主体” を推定：署名URLならAPI側、直リンクならフロント/静的配布側
- 次の一手（許可がある場合のみ：最小アクティブ）
  - 既に観測できたURLに対して、軽量に到達性を確認（HEAD/GET最小、過大DLを避ける）
  - 返り値（200/403/404/リダイレクト）を “境界の事実” として記録し、公開/非公開の判定に使う

最小の記録例（HTTP観測の扱い）
~~~~
- URL（観測済みのもののみ）
- 時刻
- ステータス（例：200 / 403 / 404）
- 応答ヘッダの特徴（Server, x-amz-*, x-goog-*, x-ms-* など）
- サイズ（過大DL回避のため）
~~~~

### 仮説B：署名URLのみが見える（= ストレージは非公開だが“発行API”が面）
- 次の一手
  - 署名URLの発行元になっている機能を探す（ダウンロードAPI、添付取得API）
  - 15_api_spec の面抽出へ接続し、署名URL発行に関与する endpoint_key_schema を優先度上げ
  - 02_web（認証/セッション）観測へ接続し、誰の権限で何が発行できる設計かを仮説化

### 仮説C：参照はあるが、ストレージ識別子が不明（CDN/独自ドメインで隠れている）
- 次の一手
  - DNS/TLS（CNAME、証明書SAN、CT）から “配布ドメイン→実体” の手がかりを集める
  - 03_http 観測で CDN/WAF の前段を判定し、背後のオリジン推定を 05_cloud へ統合
  - 16_github / 17_ci-cd に戻って config 断片（origin、bucket、account名）を追加探索

## 不明点（ここが決まると精度が上がる：回答は短くてOK）
- “最小アクティブ確認（HEAD/GET）” は、許可がある案件では実施前提にするか（OSINTのみ固定か）
- 対象環境のラベル（prod/stg/dev）の命名規則が既にあるか（例：prd, production, stage 等）
- ストレージの主要用途はどれに寄るか（static配布 / ユーザアップロード / レポート保管 / バックアップ）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回）
- ASVS：
  - V14（設定）：クラウドストレージの公開設定、アクセス制御、ログ/成果物保管の設計が直結
  - V13（API）：署名URL発行やアップロードAPIは APIセキュリティの主戦場（認証/認可/入力）
  - V1（アーキ/要件）：資産境界・信頼境界（CDN/第三者SaaS）を定義する入力になる
- WSTG：
  - INFO：公開情報（URL/JS/ドキュメント/ログ）から外部資産と攻撃面を確定する
  - APIT（支える前提）：署名URL発行/アップロード/ダウンロードのAPI設計を後続で検証する前提整理
- PTES：
  - Intelligence Gathering → Threat Modeling：ストレージ境界を確定し、優先度（P0/P1/P2）を決めて次工程へ渡す
- MITRE ATT&CK：
  - Reconnaissance：公開情報からクラウド依存と資産境界を収集
  - Collection（支える前提）：誤公開や配布面は情報収集経路になり得るため、防御観点の重要入力

## 参考（必要最小限）
- 各クラウドのストレージURL形式（S3/GCS/Azure Blob）
- 署名URL（Signed URL / SAS）と期限・権限モデルの概念
- クラウド設定ミス（Public read、誤ったCORS、意図しない配布）の一般的な注意点