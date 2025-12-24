# brand_assets_関連ドメイン推定（typo_lookalike）

## 目的（この技術で到達する状態）
ブランド起点（社名・プロダクト名・主要ドメイン）で、typo / lookalike（類似）ドメインを OSINT で洗い出し、次を「証跡つき」「優先度つき」で確定できる状態にする。
- 類似ドメイン群（候補）を、生成根拠（どの変形ルールか）つきで整理できる
- “攻撃面” として重要な導線（ログイン、決済、サポート、採用、パスワードリセット、メール送信）に紐づけて優先度付けできる
- 19_email_infra（SPF/DKIM/DMARC）と接続し、「本体が強くても周辺ドメインが弱い」リスクを説明できる
- 23_vdp_scope（制約下）に耐える「低アクティブな観測設計」（アクセス最小・証跡中心）を構成できる

## 前提（対象・範囲・想定）
- 目的は “登録/悪用” ではなく、防御・監視・リスク評価のための ASM/OSINT である
- 本ファイルは「候補の推定」と「観測・分類・優先度付け」まで（フィッシング実行や登録手順などの具体化には踏み込まない）
- 類似ドメインは “正当利用” も混在する（代理店・販売店・コミュニティ・旧ブランド等）。誤検知を前提に confidence を付ける
- VDP/契約の制約を尊重し、アクセスは最小限（できればDNS/CT/公開情報中心）。ログイン試行や大量アクセスは行わない

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) 生成（候補づくり）の単位：どの“似せ方”か
候補は「変形ルール」ごとに生成し、根拠を残す（後で説明できる形にする）。
- typo-squatting：文字の打ち間違い（脱落・重複・隣接キー・入替）
- combo-squatting：単語の付け足し（login / secure / support / help / verify / billing 等）
- TLD/ccTLD差分：.com/.net/.org/国別など（ブランドの展開地域に影響）
- subdomain混同：`brand-login.example` のように “ブランドっぽい” 文字列をドメイン本体に置く
- homograph/IDN：見た目が似た文字（国際化ドメイン）。OSINTでは “存在有無の把握” に留める

### 2) 観測の入口（低アクティブで確度を上げる順）
- DNS：A/AAAA/CNAME/NS/MX/TXT（特にMX・DMARCの有無は「メール悪用耐性」の示唆）
- TLS/CT：証明書の発行履歴（同一運用者・同一CDN/WAF・同一証明書運用の痕跡）
- HTTP（最小）：トップページの到達性、リダイレクト、HSTS等の基本だけ（深追いしない）
- 共有インフラの痕跡：CDN/WAF、ホスティング、ネームサーバ、リダイレクト先
- 公開情報：検索エンジン、SNS、公式ドキュメント（正当ドメインの棚卸しにもなる）

### 3) “攻撃面” への紐づけ（ブランドリスクを攻撃面として扱う）
類似ドメインの価値は「どの導線を偽装できるか」で決まる。
- 認証導線：login / sso / oauth / reset / MFA / verify
- 金銭導線：billing / invoice / payment
- サポート導線：support / help / ticket
- 採用導線：careers / recruit（情報収集・なりすましに繋がりやすい）
- 通知導線：mail/notify/bounce に似せる（19_email_infra とセットで評価）

### 4) brand_key_domain（後工程に渡す正規化キー）
- brand_key_domain（推奨）
  - brand_key_domain = <brand_root_domain> + <candidate_domain> + <variant_type> + <risk_route> + <infra_hint> + <confidence>
- variant_type（例）
  - typo | combo | tld_variant | subdomain_confusion | idn_homograph | legacy_brand
- risk_route（例）
  - auth | billing | support | recruit | notify | unknown
- infra_hint（例）
  - same_cdn_suspected | same_ns_suspected | mx_present | dmarc_missing | redirects_to_official | unknown

記録の最小フィールド（推奨）
- source_locator: どう見つけたか（生成ルール / CT / DNS / 公開情報）
- candidate_domain: 候補
- variant_type: 上記分類
- observed_signals: DNS/TLS/HTTP最小の観測結果（短く）
- risk_route: 想定導線
- confidence: high/mid/low
- action_priority: P0/P1/P2

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える（OSINTで確定できる）
  - 類似ドメイン候補の集合と、その根拠（変形ルール）・観測シグナル（DNS/CT等）
  - “危険になりやすい導線” に寄った候補（auth/billing/support等）を、優先度つきで提示できる
  - メール関連（MX/DMARC等）の薄い観測から「メール悪用耐性の低さ」を示唆できる（ただし断定はしない）
- 言えない（この段階では確定しない）
  - 実際にフィッシング等に使われているか（コンテンツ精査や被害確認が必要）
  - 誰が運用者か（WHOIS非公開・代理登録等で不明なことが多い）
  - 公式の関連ドメインか否か（正当利用もあるため、確証は別工程）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
※ここは“攻撃のやり方”ではなく、ASMとしての優先度設計に使う。
### 優先度（P0/P1/P2）
- P0（即時に注意喚起・監視すべき）
  - auth/billing/support の語を含む combo 系で、到達性があり（HTTP応答あり）かつ “公式へリダイレクトしない”
  - MX が存在し、DMARC が見当たらない/弱い示唆（なりすまし耐性が弱い可能性）
  - 証明書が発行されており（CTで確認）、運用が継続していそう（短期の遊びでない）
- P1（優先監視・棚卸し対象）
  - ブランド名＋一般語（app / cloud / portal / account 等）の combo
  - TLD差分で、対象の展開地域・顧客層と一致
  - インフラが “公式と似ている” 可能性（同一CDN/同一NSなどの痕跡）
- P2（情報整備・誤検知除外も含む）
  - 明確に無関係そうなもの、または公式が既に保有していそうな守りのドメイン
  - 到達性が無い/痕跡が薄い（ただし継続観測候補には残す）

### 次の仮説（周辺トピックへの接続）
- 19_email_infra：本体DMARCが強くても、類似ドメイン側の弱さが “ブランド攻撃面” を作る
- 01_dns/02_tls/03_http：類似ドメインの背後インフラ推定（CDN/ホスティング/境界）
- 24_subdomain_takeover：類似ドメイン“そのもの”ではなく、公式サブドメイン側のCNAME運用も並行で見る（別軸）
- 23_vdp_scope：制約下では「候補列挙＋最小観測＋証跡化」を標準手順にする

## 次に試すこと（仮説A/Bの分岐と検証）
### 仮説A：候補が多すぎる（ノイズで意思決定できない）
- 次の一手
  - combo語彙を “導線に直結する語” に絞る（auth/billing/support/recruit など）
  - 地域/TLDは事業実態に合わせて縮める（対象市場に無いccTLDは優先度を下げる）
  - “観測シグナルが2つ以上一致” を high にする（例：CTで証明書＋DNSでMX など）

### 仮説B：高リスク候補が出た（P0/P1）
- 次の一手（OSINTの安全域）
  - DNS（MX/TXT）とCT（証明書発行の継続性）で、運用の実在性を裏取り
  - HTTPは最小限：到達性、リダイレクト先、基本ヘッダ程度に留める（過度に踏み込まない）
  - 19_email_infra の観測項目（SPF/DKIM/DMARC）を候補ドメインにも適用し、なりすまし耐性を比較する
- 次の一手（合意がある場合のみ）
  - 監視・連絡・テイクダウン等の対応方針（運用側タスク）へ繋ぐための「証跡パック」を整える
  - VDPの場合は scope と禁止行為を再確認し、報告形に落とす（23へ接続）

### 仮説C：候補が少ない/見つからない（でも不安がある）
- 次の一手
  - 生成の起点語を見直す（旧ブランド名、略称、プロダクト名、部署名、キャンペーン名）
  - 公式が保有する “正当関連ドメイン” の棚卸しを先にやる（誤検知を減らす）
  - 16_github / 17_ci-cd / 14_sourcemap から出る語彙（プロダクト内部呼称）を起点語に追加する

#### 最小の作業例（候補生成と観測の枠組み：例示のみ）
~~~~
# 候補生成（例：変形ルールをラベル化して残す）
- typo: example -> exmaple / examlpe / exampel
- combo: example + login / support / billing
- tld: example.{com,net,org,co,jp}

# 観測（例：DNS中心で低アクティブ）
- MX/TXT の有無（メール悪用耐性の示唆）
- NS（運用者/ホスティングのヒント）
- CTで証明書発行があるか（運用の実在性）
~~~~

## 不明点（ここが決まると精度が上がる：回答は短くてOK）
- “公式に含める正当ドメイン” の一覧があるか（あるなら誤検知除外が速い）
- 対象市場（国/地域）として優先すべき ccTLD があるか（例：.jp を優先する等）
- 23_vdp_scope を想定し、HTTP観測は「DNS/CTのみ」で固定するか（最小HTTPは許容するか）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回）
- ASVS：
  - V14（設定）：ドメイン運用・DNS・外部公開の統制不備はブランドリスクと情報漏えいの入口になる
  - V1（アーキ/要件）：資産境界（公式/非公式）と信頼境界（委託先/関連会社）を定義する入力
  - V2（認証の支える前提）：認証導線はブランド攻撃面に直結（通知/回復も含む）
- WSTG：
  - INFO：公開情報（DNS/CT/HTTP最小）から関連資産と攻撃面を収集・整理
  - CLNT/IDNT（支える前提）：ユーザが接触する導線（ログイン/サポート）の偽装リスクは重要な前提情報
- PTES：
  - Intelligence Gathering：ブランド資産を境界として整理し、優先度（P0/P1/P2）を決めて後続へ渡す
  - Threat Modeling：導線（auth/billing/support）ごとに想定リスクを整理し、制約下の観測設計に落とす
- MITRE ATT&CK：
  - Reconnaissance：公開情報から組織の外部露出（関連ドメイン）を収集
  - Resource Development（支える前提）：周辺ドメインの存在は攻撃準備に利用され得るため、監視・統制の入力になる

## 参考（必要最小限）
- typo-squatting / combo-squatting / homograph（IDN）の概念
- Certificate Transparency（証明書発行履歴を使った公開情報観測）
- DMARC/SPF/DKIM（類似ドメイン側の“メール悪用耐性”比較に使う）