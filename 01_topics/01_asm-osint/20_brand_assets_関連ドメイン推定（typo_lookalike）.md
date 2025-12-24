# 20_brand_assets_関連ドメイン推定（typo_lookalike）
Brand Assets 関連ドメイン推定（typo/lookalike）
“類似ドメイン群（候補）を、生成根拠（どの変形ルールか）つきで整理できる”

## 目的（この技術で到達する状態）
ブランド起点（社名・プロダクト名・主要ドメイン）で、typo / lookalike（類似）ドメインを OSINT で洗い出し、次を「証跡つき」「優先度つき」で確定できる状態にする。
- 類似ドメイン群（候補）を、生成根拠（どの変形ルールか）つきで整理できる
- “攻撃面” として重要な導線（ログイン、決済、サポート、採用、パスワードリセット、メール送信）に紐づけて優先度付けできる
- 19_email_infra（SPF/DKIM/DMARC）と接続し、「本体が強くても周辺ドメインが弱い」リスクを説明できる
- 23_vdp_scope（制約下）に耐える「低アクティブな観測設計」（アクセス最小・証跡中心）を構成できる

## 前提（対象・範囲・想定）
- 対象：ブランド起点（社名・プロダクト名・主要ドメイン）で、typo / lookalike（類似）ドメイン。原則は OSINT（公開情報の観測）で完結する
- 想定する環境：
  - 類似ドメインは “正当利用” も混在する（代理店・販売店・コミュニティ・旧ブランド等）。誤検知を前提に confidence を付ける
  - VDP/契約の制約を尊重し、アクセスは最小限（できればDNS/CT/公開情報中心）。ログイン試行や大量アクセスは行わない
- できること/やらないこと（安全に検証する範囲）：
  - できる：OSINT（公開情報の観測）で完結する。類似ドメイン群（候補）を、生成根拠（どの変形ルールか）つきで整理できる
  - やらない：目的は “登録/悪用” ではなく、防御・監視・リスク評価のための ASM/OSINT である。本ファイルは「候補の推定」と「観測・分類・優先度付け」まで（フィッシング実行や登録手順などの具体化には踏み込まない）。ログイン試行や大量アクセスは行わない
- 依存する前提知識（必要最小限）：
  - `01_topics/01_asm-osint/19_email_infra（SPF_DKIM_DMARC）と攻撃面.md`
  - `01_topics/01_asm-osint/01_dns_委譲・境界・解釈.md`
  - `01_topics/01_asm-osint/02_tls_証明書・CT・外部依存推定.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：Brand Assets 関連ドメイン推定（typo/lookalike）、類似ドメイン群の整理、優先度付け
  - 扱わない（別ユニットへ接続）
    - Email Infra → `19_email_infra（SPF_DKIM_DMARC）と攻撃面.md`
    - DNS観測 → `01_dns_委譲・境界・解釈.md`
    - TLS観測 → `02_tls_証明書・CT・外部依存推定.md`
    - Subdomain Takeover → `01_topics/01_asm-osint/24_subdomain_takeover_成立条件推定（DNS_CNAME_プロバイダ）.md`

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
- 観測対象（プロトコル/データ構造/やり取りの単位）
  - 生成（候補づくり）の単位：どの“似せ方”か
    - 候補は「変形ルール」ごとに生成し、根拠を残す（後で説明できる形にする）。
    - typo-squatting：文字の打ち間違い（脱落・重複・隣接キー・入替）
    - combo-squatting：単語の付け足し（login / secure / support / help / verify / billing 等）
    - TLD/ccTLD差分：.com/.net/.org/国別など（ブランドの展開地域に影響）
    - subdomain混同：`brand-login.example` のように “ブランドっぽい” 文字列をドメイン本体に置く
    - homograph/IDN：見た目が似た文字（国際化ドメイン）。OSINTでは “存在有無の把握” に留める
  - 観測の入口（低アクティブで確度を上げる順）
    - DNS：A/AAAA/CNAME/NS/MX/TXT（特にMX・DMARCの有無は「メール悪用耐性」の示唆）
    - TLS/CT：証明書の発行履歴（同一運用者・同一CDN/WAF・同一証明書運用の痕跡）
    - HTTP（最小）：トップページの到達性、リダイレクト、HSTS等の基本だけ（深追いしない）
    - 共有インフラの痕跡：CDN/WAF、ホスティング、ネームサーバ、リダイレクト先
    - 公開情報：検索エンジン、SNS、公式ドキュメント（正当ドメインの棚卸しにもなる）
  - “攻撃面” への紐づけ（ブランドリスクを攻撃面として扱う）
    - 類似ドメインの価値は「どの導線を偽装できるか」で決まる。
    - 認証導線：login / sso / oauth / reset / MFA / verify
    - 金銭導線：billing / invoice / payment
    - サポート導線：support / help / ticket
    - 採用導線：careers / recruit（情報収集・なりすましに繋がりやすい）
    - 通知導線：mail/notify/bounce に似せる（19_email_infra とセットで評価）
- 境界の観点
  - 資産境界（管理主体・委託先・対象範囲の線引き）：類似ドメインは “正当利用” も混在する（代理店・販売店・コミュニティ・旧ブランド等）。誤検知を前提に confidence を付ける
  - 信頼境界（外部連携・第三者・越境ポイント）：共有インフラの痕跡（CDN/WAF、ホスティング、ネームサーバ、リダイレクト先）から信頼境界を推定できる
  - 権限境界（権限の切替/伝播/委任）：認証導線（login / sso / oauth / reset / MFA / verify）はブランド攻撃面に直結（通知/回復も含む）
- 重要なフィールド/差分/状態（「ここが変わると意味が変わる」点）
  - brand_key_domain（後工程に渡す正規化キー）
    - brand_key_domain = <brand_root_domain> + <candidate_domain> + <variant_type> + <risk_route> + <infra_hint> + <confidence>
  - variant_type（例）
    - typo | combo | tld_variant | subdomain_confusion | idn_homograph | legacy_brand
  - risk_route（例）
    - auth | billing | support | recruit | notify | unknown
  - infra_hint（例）
    - same_cdn_suspected | same_ns_suspected | mx_present | dmarc_missing | redirects_to_official | unknown

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が“確定”できるか
  - 類似ドメイン候補の集合と、その根拠（変形ルール）・観測シグナル（DNS/CT等）
  - “危険になりやすい導線” に寄った候補（auth/billing/support等）を、優先度つきで提示できる
  - メール関連（MX/DMARC等）の薄い観測から「メール悪用耐性の低さ」を示唆できる（ただし断定はしない）
- 何が“推定”できるか（推定の根拠/前提）
  - 実際にフィッシング等に使われているか（コンテンツ精査や被害確認が必要）
- 何は“言えない”か（不足情報・観測限界）
  - 実際にフィッシング等に使われているか（コンテンツ精査や被害確認が必要）
  - 誰が運用者か（WHOIS非公開・代理登録等で不明なことが多い）
  - 公式の関連ドメインか否か（正当利用もあるため、確証は別工程）
- よくある状態パターン（正常/異常/境界がズレている等）
  - パターンA：候補が多すぎる（ノイズで意思決定できない）
  - パターンB：高リスク候補が出た（P0/P1）
  - パターンC：候補が少ない/見つからない（でも不安がある）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す“狙い目”（診断上の優先度付けとして使う）
  - P0（即時に注意喚起・監視すべき）：auth/billing/support の語を含む combo 系で、到達性があり（HTTP応答あり）かつ “公式へリダイレクトしない”、MX が存在し、DMARC が見当たらない/弱い示唆（なりすまし耐性が弱い可能性）、証明書が発行されており（CTで確認）、運用が継続していそう（短期の遊びでない）
  - P1（優先監視・棚卸し対象）：ブランド名＋一般語（app / cloud / portal / account 等）の combo、TLD差分で、対象の展開地域・顧客層と一致、インフラが “公式と似ている” 可能性（同一CDN/同一NSなどの痕跡）
  - P2（情報整備・誤検知除外も含む）：明確に無関係そうなもの、または公式が既に保有していそうな守りのドメイン、到達性が無い/痕跡が薄い（ただし継続観測候補には残す）
- 優先度の付け方（時間制約がある場合の順序）
  - P0（即時に注意喚起・監視すべき）→ P1（優先監視・棚卸し対象）→ P2（情報整備・誤検知除外も含む）の順
- 代表的な攻め筋（この観測から自然に繋がるもの）
  - 攻め筋1：19_email_infra：本体DMARCが強くても、類似ドメイン側の弱さが “ブランド攻撃面” を作る
  - 攻め筋2：01_dns/02_tls/03_http：類似ドメインの背後インフラ推定（CDN/ホスティング/境界）
  - 攻め筋3：24_subdomain_takeover：類似ドメイン“そのもの”ではなく、公式サブドメイン側のCNAME運用も並行で見る（別軸）
  - 攻め筋4：23_vdp_scope：制約下では「候補列挙＋最小観測＋証跡化」を標準手順にする
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）
  - 候補が少ない/見つからない（でも不安がある） → 生成の起点語を見直す（旧ブランド名、略称、プロダクト名、部署名、キャンペーン名）、公式が保有する “正当関連ドメイン” の棚卸しを先にやる（誤検知を減らす）

## 次に試すこと（仮説A/Bの分岐と検証）
> ここが最重要。条件が違うと次の手が変わる形で書く。

- 仮説A：候補が多すぎる（ノイズで意思決定できない）
  - 次の検証：
    - combo語彙を “導線に直結する語” に絞る（auth/billing/support/recruit など）
    - 地域/TLDは事業実態に合わせて縮める（対象市場に無いccTLDは優先度を下げる）
    - “観測シグナルが2つ以上一致” を high にする（例：CTで証明書＋DNSでMX など）
  - 期待する観測（成功/失敗時に何が見えるか）：
    - 候補の絞り込みと、優先度付けの改善
- 仮説B：高リスク候補が出た（P0/P1）
  - 次の検証：
    - （OSINTの安全域）DNS（MX/TXT）とCT（証明書発行の継続性）で、運用の実在性を裏取り。HTTPは最小限：到達性、リダイレクト先、基本ヘッダ程度に留める（過度に踏み込まない）。19_email_infra の観測項目（SPF/DKIM/DMARC）を候補ドメインにも適用し、なりすまし耐性を比較する
    - （合意がある場合のみ）監視・連絡・テイクダウン等の対応方針（運用側タスク）へ繋ぐための「証跡パック」を整える。VDPの場合は scope と禁止行為を再確認し、報告形に落とす（23へ接続）
  - 期待する観測：
    - 運用の実在性の裏取り、なりすまし耐性の比較、証跡パックの整備
- 仮説C：候補が少ない/見つからない（でも不安がある）
  - 次の検証：
    - 生成の起点語を見直す（旧ブランド名、略称、プロダクト名、部署名、キャンペーン名）
    - 公式が保有する “正当関連ドメイン” の棚卸しを先にやる（誤検知を減らす）
    - 16_github / 17_ci-cd / 14_sourcemap から出る語彙（プロダクト内部呼称）を起点語に追加する
  - 期待する観測：
    - 生成の起点語の見直し、正当関連ドメインの棚卸し、起点語の追加

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/01_local/01_attack-box_作業端末設計.md`（結果の保存・差分管理）
    - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`（現状確認の最小証跡）
- 取得する証跡（目的ベースで最小限）
  - brand_key_domain（後工程に渡す正規化キー）
    - brand_key_domain = <brand_root_domain> + <candidate_domain> + <variant_type> + <risk_route> + <infra_hint> + <confidence>
  - 記録の最小フィールド（推奨）
    - source_locator: どう見つけたか（生成ルール / CT / DNS / 公開情報）
    - candidate_domain: 候補
    - variant_type: 上記分類
    - observed_signals: DNS/TLS/HTTP最小の観測結果（短く）
    - risk_route: 想定導線
    - confidence: high/mid/low
    - action_priority: P0/P1/P2
- 観測の取り方（どの視点で差分を見るか）
  - OSINT（公開情報の観測）で完結する。類似ドメイン群（候補）を、生成根拠（どの変形ルールか）つきで整理できる
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/brand_20 2>/dev/null
    cd ~/keda_evidence/brand_20
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象ドメインは **許可されたスコープ** のみ（契約範囲/社内許可範囲/自前検証環境）
      - 観測は **代表点の抽出** のみ（OSINT（公開情報の観測）で完結する）
      - 観測視点（端末/経路/ネットワーク）を記録
  - 相関キー（最低限）を作る（後で必ず効く）
    - BrandRootDomain：brand_root_domain
    - CandidateDomain：candidate_domain
    - VariantType：variant_type（typo/combo/tld_variant/subdomain_confusion/idn_homograph/legacy_brand）
    - RiskRoute：risk_route（auth/billing/support/recruit/notify/unknown）
    - InfraHint：infra_hint（same_cdn_suspected/same_ns_suspected/mx_present/dmarc_missing/redirects_to_official/unknown）
    - Confidence：confidence（high/mid/low）
    - ActionPriority：action_priority（P0/P1/P2）
    - Timestamp：観測日時（JSTで秒まで）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は“手段”であり“結論”ではない。必ず「何を観測している例か」を添える。

~~~~
# 最小の作業例（候補生成と観測の枠組み：例示のみ）

# 候補生成（例：変形ルールをラベル化して残す）
# - typo: example -> exmaple / examlpe / exampel
# - combo: example + login / support / billing
# - tld: example.{com,net,org,co,jp}

# 観測（例：DNS中心で低アクティブ）
# - MX/TXT の有無（メール悪用耐性の示唆）
# - NS（運用者/ホスティングのヒント）
# - CTで証明書発行があるか（運用の実在性）
~~~~

- この例で観測していること：
  - OSINT（公開情報の観測）で完結する。類似ドメイン群（候補）を、生成根拠（どの変形ルールか）つきで整理できる
- 出力のどこを見るか（注目点）：
  - 候補生成：変形ルール（typo/combo/tld_variant/subdomain_confusion/idn_homograph/legacy_brand）
  - 観測：MX/TXT の有無（メール悪用耐性の示唆）、NS（運用者/ホスティングのヒント）、CTで証明書発行があるか（運用の実在性）
- この例が使えないケース（前提が崩れるケース）：
  - ログイン試行や大量アクセスは行わない（VDP/契約の制約を尊重し、アクセスは最小限（できればDNS/CT/公開情報中心））

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：V14（設定）：ドメイン運用・DNS・外部公開の統制不備はブランドリスクと情報漏えいの入口になる。V1（アーキ/要件）：資産境界（公式/非公式）と信頼境界（委託先/関連会社）を定義する入力。V2（認証の支える前提）：認証導線はブランド攻撃面に直結（通知/回復も含む）
  - 該当要件（可能ならID）：外部依存・設定・通信・境界（ASM/OSINTは“前提の崩れ”を潰す役）
  - このファイルの内容が「満たす/破れる」ポイント：
    - 破れる：ドメイン運用・DNS・外部公開の統制不備を確定できないと、以降の検証で“対象外”や“前提違い”を起こし、検証精度が落ちる。
    - 満たす：外部依存・設定・通信・境界（ASM/OSINTは“前提の崩れ”を潰す役）を把握し、以降の検証（認証/認可/API/運用）を「前提崩れ」なく進める土台を作る。
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：INFO：公開情報（DNS/CT/HTTP最小）から関連資産と攻撃面を収集・整理。CLNT/IDNT（支える前提）：ユーザが接触する導線（ログイン/サポート）の偽装リスクは重要な前提情報
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：WSTG各観点へ入る前の“入口確定”として接続
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Intelligence Gathering：ブランド資産を境界として整理し、優先度（P0/P1/P2）を決めて後続へ渡す。Threat Modeling：導線（auth/billing/support）ごとに想定リスクを整理し、制約下の観測設計に落とす
  - 前後フェーズとの繋がり（1行）：ブランド起点（社名・プロダクト名・主要ドメイン）で、typo / lookalike（類似）ドメインを OSINT で洗い出し、類似ドメイン群（候補）を、生成根拠（どの変形ルールか）つきで整理できる
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Reconnaissance：公開情報から組織の外部露出（関連ドメイン）を収集。Resource Development（支える前提）：周辺ドメインの存在は攻撃準備に利用され得るため、監視・統制の入力になる
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
- typo-squatting / combo-squatting / homograph（IDN）の概念
- Certificate Transparency（証明書発行履歴を使った公開情報観測）

## リポジトリ内リンク（最大3つまで）
- 関連 topics：
  - `01_topics/01_asm-osint/19_email_infra（SPF_DKIM_DMARC）と攻撃面.md`
  - `01_topics/01_asm-osint/01_dns_委譲・境界・解釈.md`
- 関連 labs / cases：
  - `04_labs/01_local/01_attack-box_作業端末設計.md`

---

## 深掘りリンク（最大8）
- `01_topics/01_asm-osint/02_tls_証明書・CT・外部依存推定.md`
- `01_topics/01_asm-osint/03_http_観測（ヘッダ/挙動）と意味.md`
- `01_topics/01_asm-osint/24_subdomain_takeover_成立条件推定（DNS_CNAME_プロバイダ）.md`
- `01_topics/01_asm-osint/23_vdp_scope_制約下での低アクティブ観測設計.md`
- `01_topics/01_asm-osint/16_github_code-search_漏えい（key_token_endpoint）.md`
- `01_topics/01_asm-osint/17_ci-cd_artifact_公開物（ログ_ビルド成果物）.md`
- `02_playbooks/01_asm_passive-recon_資産境界→優先度付け.md`
- `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`

---
