# 00_index（ASM / OSINT の入口）
このフォルダは、許可されたスコープ内で外形情報を集め「どこまでが自社資産で、どこからが外部依存か」を観測で確定し、Web/NW/SaaS 以降の検証へ渡すための前段ユニット群です。テンプレ依存の詳細は不要なように、ChatGPT が読めば各ファイルの狙いが一目で分かるようにまとめています。

## 目的（ここで到達する状態）
- 資産境界・信頼境界・権限境界を、DNS/TLS/HTTP/JS/外部依存などの外形から説明できる。
- 「どこが自社運用で、どこが委託/外部依存か」を根拠付きで示し、深掘り優先度を付けられる。
- 次の検証（Web認証/認可/API/ネットワーク/SaaS）に持ち込む仮説A/Bと観測点を用意する。
- 低アクティブを前提（許可範囲・代表点のみ、総当たりや大量スキャンはしない）。

## ガイドライン位置づけ
- ASVS：外部依存・設定・境界の把握で「前提崩れ」を防ぐ（後段AuthN/AuthZ/APIの前提を固める）。
- WSTG：Information Gathering を中核に、以降のテストカテゴリ（Auth/AccessControl/API/Config）へ入口と仮説を供給。
- PTES：Intelligence Gathering / Threat Modeling から Vulnerability Analysis へ繋げるための素材化。
- MITRE ATT&CK：Reconnaissance / Discovery。入口と境界を最小コストで確定し、攻め筋を決める。

## 主なアウトプット
- 観測メモ：資産/信頼/権限の境界メモ（根拠付き）。
- 入口一覧：代表ドメイン/ホスト/HTTP入口とその根拠（到達性/挙動/証明書等）。
- 外部依存一覧：委譲先・終端・外部連携（CDN/WAF/SaaS/Storage等）。
- 次の検証方針：仮説A/Bと観測点（Web/NW/SaaS プレイブックへの接続）。

## 各ファイルの概要
- 01_dns_委譲・境界・解釈：NS/SOA/委譲経路とCNAME/CAA/TXTから管轄・外部依存を読む。
- 02_tls_証明書・CT・外部依存推定：証明書/CTから終端・SAN・Issuerを観測し依存や残骸を推定。
- 03_http_観測（ヘッダ・挙動）と意味：未ログインHTTPのヘッダ/リダイレクト/CORSから入口と保護層を読む。
- 04_js_フロント由来の攻撃面抽出：JSビルド成果物からAPI/境界変数/外部依存/環境差分を抽出。
- 05_cloud_露出面（CDN_WAF_Storage等）推定：CDN/WAF/Storage 等の外部構成要素を境界として特定。
- 06_subdomain_列挙（passive_active_辞書_優先度）：受動→解決→HTTP疎通で入口候補を優先付け。
- 07_whois_rdap_所有者・関連企業推定（組織境界）：WHOIS/RDAPで所有者・関連組織・管轄を読む。
- 08_asn_bgp_ネットワーク境界（AS_プレフィックス_関連性）：AS/プレフィックスからネットワーク外形と関連性を作る。
- 09_passive-dns_履歴と再利用（過去資産の掘り起こし）：過去FQDN履歴を正規化し現状確認へ回す。
- 10_ctlog_証明書拡張観測（SAN_ワイルドカード_中間CA）：CTログからSAN候補を生成し現状DNS/HTTPへ接続。
- 11_cohosting_同居推定（共有IP_VHost_CDN収束）：同一IPのFQDN束をまとめ、HTTP/TLS差分で束を評価。
- 12_waf-cdn_挙動観測（ブロック_チャレンジ_例外）：代表パスでブロック/チャレンジ/例外の型を観測しクラスタ化。
- 13_http2_h3_観測（ALPN_Alt-Svc_到達性）：ALPN/Alt-Svc/HTTP3到達性を代表点で確認。
- 14_js_sourcemap_公開物から攻撃面抽出（endpoint_key）：sourceMap公開有無と情報量を確認しAPI/Key断片を抽出。
- 15_api_spec_公開（OpenAPI_GraphQLスキーマ）から面抽出：公開スキーマからエンドポイント面を最小限抽出。
- 16_github_code-search_漏えい（key_token_endpoint）：GitHub Code Searchで鍵/トークン/エンドポイント断片を探す。
- 17_ci-cd_artifact_公開物（ログ_ビルド成果物）：公開CI/CD成果物からログ/設定断片を拾う際の証跡化。
- 18_storage_discovery（S3_GCS_AzureBlob）境界推定：S3/GCS/Blobの挙動で公開/制限/依存を推定。
- 19_email_infra（SPF_DKIM_DMARC）と攻撃面：メール系DNS（MX/SPF/DKIM/DMARC/MTA-STS）から攻撃面を読む。
- 20_brand_assets_関連ドメイン推定（typo_lookalike）：ブランド変形ドメインの生成と低アクティブ観測。
- 21_third-party_外部依存（タグ_分析SDK）洗い出し：HTML/JS/CSPから第三者タグ/SDK/連携先を抽出。
- 22_mobile_assets_アプリ由来攻撃面（deep-link_API）：モバイルアプリの deeplink / API パスを整理。
- 23_vdp_scope_制約下での低アクティブ観測設計：VDP等での低アクティブ観測ルールの作り方。
- 24_subdomain_takeover_成立条件推定（DNS_CNAME_プロバイダ）：CNAME/プロバイダ残骸からサブドメインテイクオーバー成立可否を読む。
- 25_dnssec_観測と意味（委譲_検証_誤設定）：DS/DNSKEY/RRSIGでDNSSECの有無・誤設定を観測。

## 接続先（次の検証へ）
- Web 側の詳細：`01_topics/02_web/01_web_recon_入口・境界・攻め筋確定.md`
- ネットワーク側：`01_topics/03_network/01_enum_到達性→サービス→認証→権限推定.md`
- SaaS/IdP 側：`01_topics/04_saas/01_idp_連携（SAML OIDC OAuth）と信頼境界.md`
- ローカル証跡取得：`04_labs/01_local/02_proxy_計測・改変ポイント設計.md`, `04_labs/01_local/03_capture_証跡取得（pcap_har_log）.md`
