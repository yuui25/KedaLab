<<<BEGIN>>>
# Web/NWペネトレーション技術深化プロジェクト 統合指示プロンプト（ASM/OSINT・Labs・Cases対応）

## 0. 本プロンプトの目的
本プロンプトは、Web/NWペネトレーション（Web:NW=5:5）に必要な技術を、ASM/OSINT・SaaSを含めて「実務で使えるレベル」まで深掘りし、GitHubリポジトリとして継続的に構築するための統合指示である。  
ツールの表面的な説明（例：コマンド例だけ、機能紹介だけ）は禁止し、必ず「意味→判断→次の一手」まで落とし込む。

## 1. プロジェクト名
keda-lab

## 2. 最重要方針（必ず守る：技術最大化のための詳細）

### 2.1 「技術を高める」とは何か（定義）
以下を“読んで分かる”ではなく“自分で回せる”状態にすることを指す。
- 観測対象を言語化できる（何を見ているか：プロトコル/データ/境界）
- 観測結果の意味を説明できる（何が言える/言えない、前提条件）
- 仮説を立てられる（この状態なら攻め筋A、違うならB）
- 次の一手を選べる（優先度・分岐・検証の順序）
- 検証の安全な範囲を理解している（検証環境、影響の制御）

### 2.2 本プロジェクトが「絶対に避ける」こと（禁止事項）
- ツール紹介・コマンド紹介で終える（例：「digでAが取れます」だけで終わる）
- 一般論でページを埋める（“重要です”“気をつけましょう”だけの文章）
- 事例の要約で終える（ニュースまとめ化の禁止：技術ユニットに結びつける）
- 「落とし穴」章の追加（ファクトチェックできないため）
- 報告テンプレの肥大化（報告は“ガイドライン程度”に留める）
- ガイドラインの“貼り付け”のみ（どこに当たるかの列挙で終わらせない）

### 2.3 各ファイルに求める「深掘り最低ライン」（品質ゲート）
01_topics の各ファイルは、最低でも以下を満たすまで出力しない。
- 「観測ポイント」：観測対象・境界（資産/信頼/権限）が明確
- 「結果の意味」：出力の意味を“状態”として説明（例：委譲、外部依存、権限境界、到達性 等）
- 「攻撃者視点での利用」：その状態が意思決定にどう効くか（優先度/攻め筋/想定パス）
- 「次に試すこと」：仮説A/Bの分岐がある（条件が違うと次の手が変わる）
- 「ガイドライン対応」：ASVS/WSTG/PTES/ATT&CKを“毎回”記載し、関連が薄い場合は「どの前提を支えるか」を明記

### 2.4 重点配分（Web/NW=5:5＋ASM/OSINT＋SaaS）
- WebとNWを同格に扱う（Webだけに偏らない）
- ASM/OSINTは必須（入口の精度が技術力の上限を決めるため）
- SaaSは必須領域として含めるが、特別扱いしない（現代の攻撃面の一部として組み込む）
- どの領域でも「境界（Boundary）」で統一する  
  - 資産境界：どこまでが対象/管理主体か  
  - 信頼境界：どこから先が第三者/外部連携か  
  - 権限境界：どこで権限が切り替わる/伝播するか  

### 2.5 ガイドラインを「確実に使える」状態にするルール
各ファイルで必ず4規格を扱う（毎回）。
- ASVS：該当する管理策を“この技術で満たす/破れる点”として書く（単なる参照列挙禁止）
- WSTG：該当テスト観点を“どの観測・検証に対応するか”で書く（項目名貼り付け禁止）
- PTES：どのフェーズの技術かを明示し、前後フェーズとどう繋がるか1行で示す
- ATT&CK：戦術（必要なら技術）として位置づけ、攻撃者の目的（Discovery/Credential/Lateral等）と結びつける  
※関連が薄い場合は「この技術が支える前提（例：情報収集、境界特定、到達性推定）」として接続を書く。

### 2.6 「手を動かす」を前提にする（Labsとの連動が必須）
- 深掘りは、可能な限り 04_labs の検証環境で“観測→解釈→利用”を再現して理解する
- topics には「検証の観測点（何をログ/pcap/harで取るか）」を含める
- labs は「手順書」ではなく「設計（境界・到達性・観測点・巻き戻し）」として書く
- クラウド（AWS/Azure）やVMは制約なく活用し、検証の巻き戻し（snapshot/reset）を必須要素にする

### 2.7 実世界事例（Cases）は“技術ユニットの教材”にする
- 03_cases はフォルダ分割しない（追加しても迷わない）
- 事例は要約で終えず、必ず以下を含める  
  - 公表情報の事実（確定範囲）  
  - 技術的論点（攻撃面/成立条件/境界）  
  - 自リポジトリ内リンク（関連topics/playbooks/labs）  
  - ガイドライン対応（ASVS/WSTG/PTES/ATT&CK）  
- 事例の位置づけは「この技術が現実でどう使われるか/どこが破られるか」を示すものとする

### 2.8 出力密度（過不足を防ぐ）
- “少なすぎる”を避ける（実務で判断できない情報量は禁止）
- “多すぎる”も避ける（読者が迷う補足の過剰投入は禁止）
- 原則は「判断に直結する情報を優先」  
  - 仕様の丸写し、用語解説の長文化、網羅目的の列挙は後回し

### 2.9 アシスタントの自己検証（送信前チェック）
出力前に必ず以下を確認し、満たさない場合は書き直す。
- コマンド紹介で終わっていないか（意味/判断/次の手があるか）
- 境界（資産/信頼/権限）が明確か
- 仮説A/Bの分岐があるか
- ASVS/WSTG/PTES/ATT&CKの4つが“毎回”書かれているか
- 「落とし穴」章が入っていないか
- 報告テンプレが肥大化していないか（ガイドライン程度か）
- 内側コードが `~~~~` 〜 `~~~~` になっているか（```禁止）

### 2.10 拡張性（肥大化防止と実務比較のための分割ルール）
- 本リポジトリは「深掘りが進むほど論点が増える」前提で設計する。  
  ただし、1ファイルに確認事項を詰め込み過ぎると、比較・再現・参照が破綻するため、次のルールで拡張する。

#### 2.10.1 総合インデックス（親ファイル）を維持する
- 01_topics の“主要ファイル”は、原則 **総合インデックス（入口）** として維持する。  
  例：`01_topics/02_web/02_authn_認証・セッション・トークン.md` は、認証領域の入口（観測設計・境界モデル・最小差分セット）に徹し、チェックリスト化して肥大化させない。

#### 2.10.2 追加の深掘りは「論点別の分割ファイル」で行う
- 深掘りが必要になった論点は、同一フォルダ内に **論点別の分割ファイル**として追加する（フォルダの新設で迷子を作らない）。  
- 分割ファイルでも必ず、以下を揃えて“実務で回せる単位”にする（2.3の品質ゲートに準拠）。
  - 観測ポイント / 結果の意味 / 攻撃者視点での利用 / 次に試すこと（仮説A/B）/ 手を動かす検証 / ガイドライン対応

#### 2.10.3 親ファイル末尾に「深掘りリンク枠」を常設する
- 親ファイル（総合インデックス）の末尾に「深掘り（必要時に追加するファイル）」を置き、作成済み分割ファイルへのリンクを列挙する。  
- 上限：原則8件まで（過剰列挙で読者が迷うのを防ぐ）。必要なら整理して差し替える。

#### 2.10.4 命名規則（迷いを増やさない）
- 分割ファイルは、親ファイル名を起点に、連番と論点名を付ける（例：`02_authn_01_...`）。  
- ファイル名には「/」を含めない（フォルダ区切りは `/`、ファイル名内の区切りは `_` を使用）。

例（認証領域：既定の拡張形）
- `01_topics/02_web/02_authn_01_cookie属性と境界（Domain Path SameSite Secure HttpOnly）.md`
- `01_topics/02_web/02_authn_02_token設計（Bearer JWT refresh rotation）.md`
- `01_topics/02_web/02_authn_03_sso_oidc_flow観測（state nonce code PKCE）.md`
- `01_topics/02_web/02_authn_04_sso_saml_flow観測（assertion audience recipient）.md`
- `01_topics/02_web/02_authn_05_mfa_成立点と例外パス（step-up device trust）.md`
- `01_topics/02_web/02_authn_06_session_lifecycle（idle absolute logout revocation）.md`
- `01_topics/02_web/02_authn_07_client_storage（localStorage sessionStorage memory）.md`
- `01_topics/02_web/02_authn_08_device_binding（端末紐付け IP UA fingerprint）.md`

#### 2.10.5 認証以外の領域にも同ルールを適用する
- ASM/OSINT、Web、Network、SaaS、Playbooks、Labs でも、親ファイルを総合インデックスとして維持し、増える論点は分割ファイルで拡張する。  
  例：DNS/TLS/HTTP、API、認可、NW列挙、AD、SaaS連携などは、必要になった論点から分割する。  
- ただし、`03_cases` は本方針の対象外（元ルール通り「1事例=1ファイル」で積み増す）。

## 3. 出力ルール（厳守）
- 出力する成果物は Markdown（.md）。
- 1ファイル=1テーマ（スキルユニット）で完結させる。
- ツール/コマンドは「例」として最小限に留め、出力の意味・判断・次の手を中心に書く。
- ファイル冒頭に「ガイドライン対応（ASVS/WSTG/PTES/ATT&CK）」を必ず設置する。
- 見出し・区切りは日本語で直感的に分かる言葉を使う（What/So whatは禁止）。
- 内側のコード例は `~~~~` 〜 `~~~~` を使う（絶対に ``` は使わない）。

## 4. リポジトリ構成（確定）
以下の構成を前提に、以降のファイル生成・追記・改訂を行う。

~~~~
repo-root/
│  README.md
│
├─01_topics
│  ├─01_asm-osint
│  │      00_index.md
│  │      01_dns_委譲・境界・解釈.md
│  │      02_tls_証明書・CT・外部依存推定.md
│  │      03_http_観測（ヘッダ・挙動）と意味.md
│  │      04_js_フロント由来の攻撃面抽出.md
│  │      05_cloud_露出面（CDN_WAF_Storage等）推定.md
│  │      06_subdomain_列挙（passive_active_辞書_優先度）.md
│  │      07_whois_rdap_所有者・関連企業推定（組織境界）.md
│  │      08_asn_bgp_ネットワーク境界（AS_プレフィックス_関連性）.md
│  │      09_passive-dns_履歴と再利用（過去資産の掘り起こし）.md
│  │      10_ctlog_証明書拡張観測（SAN_ワイルドカード_中間CA）.md
│  │      11_cohosting_同居推定（共有IP_VHost_CDN収束）.md
│  │      12_waf-cdn_挙動観測（ブロック_チャレンジ_例外）.md
│  │      13_http2_h3_観測（ALPN_Alt-Svc_到達性）.md
│  │      14_js_sourcemap_公開物から攻撃面抽出（endpoint_key）.md
│  │      15_api_spec_公開（OpenAPI_GraphQLスキーマ）から面抽出.md
│  │      16_github_code-search_漏えい（key_token_endpoint）.md
│  │      17_ci-cd_artifact_公開物（ログ_ビルド成果物）.md
│  │      18_storage_discovery（S3_GCS_AzureBlob）境界推定.md
│  │      19_email_infra（SPF_DKIM_DMARC）と攻撃面.md
│  │      20_brand_assets_関連ドメイン推定（typo_lookalike）.md
│  │      21_third-party_外部依存（タグ_分析SDK）洗い出し.md
│  │      22_mobile_assets_アプリ由来攻撃面（deep-link_API）.md
│  │      23_vdp_scope_制約下での低アクティブ観測設計.md
│  │      24_subdomain_takeover_成立条件推定（DNS_CNAME_プロバイダ）.md
│  │      25_dnssec_観測と意味（委譲_検証_誤設定）.md
│  │
│  ├─02_web
│  │      00_index.md
│  │      01_web_00_recon_入口・境界・攻め筋の確定.md
│  │      02_authn_00_認証・セッション・トークン.md
│  │      02_authn_01_cookie属性と境界（Secure_HttpOnly_SameSite_Path_Domain）.md
│  │      02_authn_02_session_lifecycle（更新_失効_固定化_ローテーション）.md
│  │      02_authn_03_token設計（Bearer_JWT_Refresh_Rotation）.md
│  │      02_authn_04_sso_oidc_flow観測（state_nonce_code_PKCE）.md
│  │      02_authn_05_sso_saml_flow観測（assertion_audience_recipient）.md
│  │      02_authn_06_mfa_成立点と例外パス（step-up_device_trust）.md
│  │      02_authn_07_client_storage（localStorage_sessionStorage_memory）.md
│  │      02_authn_08_device_binding（端末紐付け_IP_UA_fingerprint）.md
│  │      02_authn_09_password_policy（強度_漏えい照合_禁止語）.md
│  │      02_authn_10_password_reset_回復経路（token_失効_多要素）.md
│  │      02_authn_11_account_recovery_本人確認（サポート代行_回復コード）.md
│  │      02_authn_12_bruteforce_rate-limit_lockout（例外パス）.md
│  │      02_authn_13_login_csrf_認証CSRFとstate設計.md
│  │      02_authn_14_logout_設計（RP_IdP_フロントチャネル）.md
│  │      02_authn_15_session_concurrency（多端末_同時ログイン制御）.md
│  │      02_authn_16_step-up_再認証境界（重要操作_再確認）.md
│  │      02_authn_17_refresh_token_rotation_盗用検知（reuse）.md
│  │      02_authn_18_token_binding（DPoP_mTLS）観測.md
│  │      02_authn_19_webauthn_passkeys_登録・回復境界.md
│  │      02_authn_20_magic-link_メールリンク認証の成立条件.md
│  │      03_authz_00_認可（IDOR BOLA BFLA）境界モデル化.md
│  │      03_authz_01_境界モデル（オブジェクト_ロール_テナント）.md
│  │      03_authz_02_idor_典型パターン（一覧_検索_参照キー）.md
│  │      03_authz_03_multi-tenant_分離（org_id_tenant_id）.md
│  │      03_authz_04_rbac_abac_判定点（policy_engine）.md
│  │      03_authz_05_mass-assignment_モデル結合境界.md
│  │      03_authz_06_privileged_action_重要操作（承認_送金_権限）.md
│  │      03_authz_07_graphql_authz（field_level）.md
│  │      03_authz_08_file_access_ダウンロード認可（署名URL）.md
│  │      03_authz_09_admin_console_運用UIの境界.md
│  │      03_authz_10_object_state_状態遷移と権限（draft_approved）.md
│  │      04_api_00_権限伝播・入力・バックエンド連携.md
│  │      04_api_01_権限伝播モデル（フロント_バックエンド_ジョブ）.md
│  │      04_api_02_graphql_境界（schema_introspection_query_cost）.md
│  │      04_api_03_rest_filters_検索・ソート・ページング境界.md
│  │      04_api_04_webhook_受信側の信頼境界（署名_再送）.md
│  │      04_api_05_webhook_ssrf_送信側の到達性境界.md
│  │      04_api_06_idempotency_レースと二重実行境界.md
│  │      04_api_07_async_job_権限伝播（キュー_ワーカー）.md
│  │      04_api_08_file_export_エクスポート境界（CSV_PDF）.md
│  │      04_api_09_error_model_情報漏えい（例外_スタック）.md
│  │      04_api_10_versioning_互換性と境界（v1_v2）.md
│  │      04_api_11_grpc_メタデータと認可境界.md
│  │      04_api_12_websocket_sse_認証・認可境界.md
│  │      05_input_00_入力→実行境界（テンプレ デシリアライズ等）.md
│  │      05_input_01_入力→実行境界（テンプレート注入_SSTI）.md
│  │      05_input_02_入力→実行境界（デシリアライズ_型混乱_ガジェット前提）.md
│  │      06_config_00_設定・運用境界（CORS ヘッダ Secrets）.md
│  │      06_config_01_CORSと信頼境界（Origin_資格情報_プリフライト）.md
│  │      06_config_02_Secrets管理と漏えい経路（JS_ログ_設定_クラウド）.md
│  │      06_config_03_セキュリティヘッダ（CSP_HSTS_Frame_Referrer）.md
│  │      README.md
│  │
│  ├─03_network
│  │      00_index.md
│  │      01_enum_到達性→サービス→認証→権限推定.md
│  │      02_post_侵入後の前提（権限 経路 横展開の入口）.md
│  │      03_creds_認証情報の所在と扱い（攻撃 検知の両面）.md
│  │      04_ad_ドメイン環境の基礎（ペンテスト視点の地図）.md
│  │
│  └─04_saas
│          00_index.md
│          01_idp_連携（SAML OIDC OAuth）と信頼境界.md
│          02_saas_共有・外部連携・監査ログの勘所.md
│
├─02_playbooks
│      00_index.md
│      01_asm_passive-recon_資産境界→優先度付け.md
│      02_web_recon_入口→境界→検証方針.md
│      03_authn_観測ポイント（SSO_MFA前提）.md
│      04_authz_境界モデル→検証観点チェック.md
│      05_api_権限伝播→検証観点チェック.md
│      06_network_enum_to_post_列挙→侵入後の導線.md
│
├─03_cases
│      00_index.md
│      01_case-template.md
│
├─04_labs
│  │  00_index.md
│  │
│  ├─01_local
│  │      00_index.md
│  │      01_attack-box_作業端末設計.md
│  │      02_proxy_計測・改変ポイント設計.md
│  │      03_capture_証跡取得（pcap_harl_log）.md
│  │
│  ├─02_virtualization
│  │      00_index.md
│  │      01_virtualbox_基盤.md
│  │      02_vmware_基盤.md
│  │      03_networking_nat_hostonly_bridge.md
│  │
│  ├─03_targets
│  │      00_index.md
│  │      01_web_targets_検証用アプリ選定.md
│  │      02_api_targets_検証用API選定.md
│  │      03_ad_lab_検証用ドメイン構成.md
│  │
│  ├─04_cloud
│  │      00_index.md
│  │      01_aws_lab_構成と検証観点.md
│  │      02_azure_lab_構成と検証観点.md
│  │      03_logging_クラウド監査ログの取り方.md
│  │
│  └─05_automation
│          02_snapshots_reset_検証の巻き戻し.md
│
└─99_templates
        00_project-prompt.md
        01_topic-template.md
        02_playbook-template.md
        03_case-template.md
~~~~

※上記ツリーは「最低限の基準構成」として維持する。  
※今後の拡張（分割ファイル追加）は、原則として同一フォルダ配下にファイルを追加する形で行い、迷子を増やすフォルダ新設は行わない（03_casesを除く）。

## 5. テンプレ（必須見出し：日本語）
以降、01_topics の各ファイルは必ず次の見出しを採用する（順序固定）。

- 目的（この技術で到達する状態）
- 前提（対象・範囲・想定）
- 観測ポイント（何を見ているか：プロトコル/データ/境界）
- 結果の意味（その出力が示す状態：何が言える/言えない）
- 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- 次に試すこと（仮説A/Bの分岐と検証）
- ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回）
- 参考（必要最小限）

※「よくある落とし穴」は章として作らない。

## 6. ガイドライン対応（毎回必須：書き方）
各ファイルに必ず以下のブロックを置く。該当が薄い場合も「接続の仕方」を明記する。

~~~~
## ガイドライン対応
- ASVS：章/要件（可能ならID）を列挙（このファイルの内容がどの管理策に対応するか）
- WSTG：該当カテゴリ/テスト観点を列挙（該当が薄い場合は「この技術が支える前提」を記載）
- PTES：該当フェーズ（Pre-engagement / Intelligence Gathering / Threat Modeling / Vulnerability Analysis / Exploitation / Post-Exploitation / Reporting のいずれか）
- MITRE ATT&CK：戦術（必要に応じて技術）として位置づけ
~~~~

## 7. 03_cases の作り方（迷わない運用）
- 1事例=1ファイル。フォルダ分割しない。
- 命名規則は「検索しやすさ」を優先（例：CVE-YYYY-xxxx_短い識別子.md / CYYYY-MM_社名_事件名.md など）。
- 事例はニュース要約ではなく、必ず以下を含める：
  - 公表情報の事実（確定範囲）
  - 技術的な論点（攻撃面/成立条件/境界）
  - 自リポジトリ内リンク（関連topics/playbooks/labsへの参照）
  - ガイドライン対応（ASVS/WSTG/PTES/ATT&CK）

## 8. 04_labs の作り方（技術を上げるための環境構築）
- 検証環境は「作る過程が学習」になるように、構成理由・境界・到達性・観測点を必ず書く。
- VM / AWS / Azure は制約なく活用し、検証を回すための「巻き戻し（snapshot/reset）」を前提化する。
- labsは「手順書」ではなく「技術の理解が進む設計書」として書く。

## 9. 作業の進め方（実行指示）
以降の会話では、あなた（アシスタント）は次を順守する。

1) ユーザーが作りたいファイル（パス/ファイル名）を指定したら、そのファイルを生成する。  
2) 指定がない場合は、次の優先順で提案し、1つずつ作る：  
   - 99_templates（topic/playbook/case）→ 04_labs → 01_topics（ASM→Web→NW→SaaS）→ 03_cases → 02_playbooks  
3) 生成する本文は必ず「日本語見出しテンプレ」に従う。  
4) 各ファイルで「ガイドライン対応」を必ず記載する。  
5) ツール/コマンドは最小限の例示に留め、出力の意味と攻撃者視点の意思決定を中心に書く。  
6) 余計な一般論・過剰な補足で読み手を迷わせない。  

## 10. 最初に作るべきファイル（推奨の開始順）
次の順で作ると品質が揃い、以降の深掘りが加速する。

1) 99_templates/01_topic-template.md  
2) 99_templates/02_playbook-template.md  
3) 99_templates/03_case-template.md  
4) 04_labs/00_index.md（検証環境の全体像と狙い）  
5) 01_topics/01_asm-osint/01_dns_委譲・境界・解釈.md（“観測→解釈→利用”の基準品質確立）

## 11. 今後作成予定ファイル候補（タイトル一覧：ぶれ防止）
※この一覧は「候補バックログ」。以降の提案・生成は原則ここから選び、命名規則（2.10.4）に従う。
※“厳選（約30）/推奨（80+）/最大（200）”の粒度を想定し、必要に応じて増減・整理する（重複・陳腐化は随時差し替え）。

### 01_topics/03_network（追加候補）
- 01_topics/03_network/05_scanning_到達性把握（nmap_masscan）.md
- 01_topics/03_network/06_service_fingerprint（banner_tls_alpn）.md
- 01_topics/03_network/07_pivot_tunneling（ssh_socks_chisel）.md
- 01_topics/03_network/08_firewall_waf_検知と回避の境界（観測中心）.md
- 01_topics/03_network/09_smb_enum_共有・権限・匿名（null_session）.md
- 01_topics/03_network/10_ntlm_relay_成立条件（SMB署名_LLMNR）.md
- 01_topics/03_network/11_ldap_enum_ディレクトリ境界（匿名_bind）.md
- 01_topics/03_network/12_kerberos_asrep_kerberoast_成立条件.md
- 01_topics/03_network/13_adcs_証明書サービス悪用の境界.md
- 01_topics/03_network/14_delegation（unconstrained_constrained_RBCD）.md
- 01_topics/03_network/15_acl_abuse（AD権限グラフ）.md
- 01_topics/03_network/16_gpo_永続化と権限境界.md
- 01_topics/03_network/17_laps_ローカル管理者パスワード境界.md
- 01_topics/03_network/18_winrm_psremoting_到達性と権限.md
- 01_topics/03_network/19_rdp_設定と認証（NLA）.md
- 01_topics/03_network/20_mssql_横展開（xp_cmdshell_linkedserver）.md
- 01_topics/03_network/21_nfs_共有とroot_squash境界.md
- 01_topics/03_network/22_snmp_情報収集（community_v3）.md
- 01_topics/03_network/23_dns_internal_委譲とゾーン転送（AXFR）.md
- 01_topics/03_network/24_linux_priv-esc_入口（sudo_capabilities）.md
- 01_topics/03_network/25_windows_priv-esc_入口（サービス権限_UAC）.md
- 01_topics/03_network/26_credential_dumping_所在（LSA_DPAPI）.md
- 01_topics/03_network/27_persistence_永続化（schtasks_services_wmi）.md
- 01_topics/03_network/28_exfiltration_持ち出し経路（DNS_HTTP_SMB）.md

### 01_topics/04_saas（追加候補）
- 01_topics/04_saas/03_m365_権限境界（アプリ登録_Consent）.md
- 01_topics/04_saas/04_azuread_条件付きアクセス（CA）と例外パス.md
- 01_topics/04_saas/05_okta_サインオンポリシーとトークン境界.md
- 01_topics/04_saas/06_google_workspace_oauth_スコープ境界.md
- 01_topics/04_saas/07_github_組織権限境界（PAT_App_Actions）.md
- 01_topics/04_saas/08_slack_トークン境界（xox_署名検証）.md
- 01_topics/04_saas/09_atlassian_外部連携と権限境界.md
- 01_topics/04_saas/10_saas_oauth_consent_phishing_成立条件.md
- 01_topics/04_saas/11_scim_jit_provisioning_境界（権限初期値）.md
- 01_topics/04_saas/12_audit_logs_取得と相関（誰が何をいつ）.md
- 01_topics/04_saas/13_shadow_it_発見（DNS_CASB_ログ）.md
- 01_topics/04_saas/14_sso_bypass_パス（ローカルログイン残存）.md
- 01_topics/04_saas/15_token_lifetime_更新と失効（SaaS側）.md

### 02_playbooks（追加候補）
- 02_playbooks/07_input_to_rce_入力→実行の導線（最小差分）.md
- 02_playbooks/08_xss_to_account_takeover_クッキー/トークン窃取の導線.md
- 02_playbooks/09_ssrf_to_cloud_metadata_メタデータ到達性→権限推定.md
- 02_playbooks/10_idor_harvest_横取り→エクスポート→到達点固定.md
- 02_playbooks/11_webhook_abuse_署名/再送/到達性の導線.md
- 02_playbooks/12_graphql_abuse_過剰取得→認可欠落の導線.md
- 02_playbooks/13_ad_enum_to_da_列挙→資格→権限の導線.md
- 02_playbooks/14_saas_oauth_同意→横展開→永続化の導線.md

### 04_labs（追加候補）
- 04_labs/01_local/04_browser_profiles_差分観測（cookie_storage）.md
- 04_labs/01_local/05_mitm_tls_観測（証明書_ピンニング）.md
- 04_labs/01_local/06_burp_project_証跡設計（整理_タグ付け）.md
- 04_labs/01_local/07_replay_差分再現（再送_並列）.md
- 04_labs/02_virtualization/04_kali_vm_拡張（tools_snapshots）.md
- 04_labs/02_virtualization/05_windows_vm_検証基盤（edge_ie_mode）.md
- 04_labs/03_targets/04_intentionally_vuln_apps_導入（DVWA_JuiceShop）.md
- 04_labs/03_targets/05_graphql_targets_検証環境（vuln_graphql）.md
- 04_labs/03_targets/06_ssrf_targets_検証環境（webhook_metadata）.md
- 04_labs/03_targets/07_xss_targets_検証環境（CSP差分）.md
- 04_labs/03_targets/08_deser_targets_検証環境（Java_PHP）.md
- 04_labs/04_cloud/04_aws_metadata_到達性ラボ（IMDSv1_v2）.md
- 04_labs/04_cloud/05_azure_msi_到達性ラボ（IMDS）.md
- 04_labs/04_cloud/06_cloudtrail_sentinel_相関ラボ.md
- 04_labs/05_automation/03_replay_har_to_tests_自動再現.md
- 04_labs/05_automation/04_log_correlation_自動相関（trace_id）.md

### 03_cases（追加候補：命名例）
- 03_cases/C2023-xx_外部IdP設定不備_SSOバイパス.md
- 03_cases/C2024-xx_API認可欠落_BOLAによるPII漏えい.md
- 03_cases/C2024-xx_Webhook_SSFR_クラウドメタデータ到達.md
- 03_cases/C2025-xx_RefreshToken再利用_セッション乗っ取り.md
- 03_cases/C2025-xx_SaaS_OAuth同意_永続化.md

<<<END>>>
