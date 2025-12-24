# 25_dnssec_観測と意味（委譲_検証_誤設定）
DNSSEC 観測と意味（委譲/検証/誤設定）
“DNSSEC 成熟度（有効/無効/破綻の疑い）を整理できる”

## 目的（この技術で到達する状態）
DNSSEC を ASM/OSINT の範囲で観測し、委譲（DS）〜検証（DNSKEY/RRSIG）〜誤設定（bogus/破綻）までを「証跡つき」「優先度つき」で説明できる状態にする。
- dnssec_key_posture として、対象ドメインの DNSSEC 成熟度（有効/無効/破綻の疑い）を整理できる
- “DNSの信頼境界” を言語化できる（DNS改ざん・キャッシュ汚染等への耐性の前提）
- 誤設定がある場合、可用性リスク（名前解決不能）や境界破綻の兆候を、低アクティブで提示できる
- 01_dns（委譲の解釈）、02_tls（証明書/CT）、20_brand_assets（関連ドメイン）に接続し、全体のASM設計に統合できる

## 前提（対象・範囲・想定）
- 対象：DNSSEC を ASM/OSINT の範囲で観測する。原則は OSINT：DNSクエリと公開情報のみ（状態変更なし、負荷は軽い）
- 想定する環境：
  - DNSSEC は「有効＝万能」ではない（DNSの完全性を強化するが、運用ミスで可用性を落とす）
  - 企業ドメインはサブドメイン委任が多い。親と子で DNSSEC 状態が異なる前提で観測する
- できること/やらないこと（安全に検証する範囲）：
  - できる：原則は OSINT：DNSクエリと公開情報のみ（状態変更なし、負荷は軽い）。DNSSEC 成熟度（有効/無効/破綻の疑い）を整理できる
  - やらない：本ファイルでは “DNSSECの実装” ではなく “観測と意味づけ（判断）” を主に扱う
- 依存する前提知識（必要最小限）：
  - `01_topics/01_asm-osint/01_dns_委譲・境界・解釈.md`
  - `01_topics/01_asm-osint/02_tls_証明書・CT・外部依存推定.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：DNSSEC 観測と意味（委譲/検証/誤設定）、成熟度の整理、可用性リスクの提示
  - 扱わない（別ユニットへ接続）
    - DNS観測 → `01_dns_委譲・境界・解釈.md`
    - TLS観測 → `02_tls_証明書・CT・外部依存推定.md`
    - ブランド資産 → `01_topics/01_asm-osint/20_brand_assets_関連ドメイン推定（typo_lookalike）.md`

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
- 観測対象（プロトコル/データ構造/やり取りの単位）
  - DNSSEC を “委譲チェーン” として見る
    - DNSSEC は「親ゾーンが子ゾーンを信頼してよい」という鎖（chain of trust）。
    - 親（example.com の親＝.com）が DS を持つ → 子ゾーンの DNSKEY と一致 → 署名（RRSIG）が検証できる
    - どこかで鎖が切れると、検証リゾルバは bogus（不正）として扱い、名前解決が失敗し得る
    - 観測の要点（OSINTで見る範囲）：
      - DS レコードの有無（親側の委譲があるか）
      - DNSKEY の有無（子側が鍵を公開しているか）
      - RRSIG の有無（署名付き応答が返るか）
      - 検証結果（ADフラグなど）や、検証失敗の兆候（SERVFAIL等）
  - “有効/無効/破綻” を分ける観測シグナル
    - 無効（unsigned）：DS が無い（親が委譲していない）、DNSKEY/RRSIG が返らない
    - 有効（signed & validating）：DS がある（親に登録されている）、DNSKEY/RRSIG が返る、検証済みの兆候（検証リゾルバで AD フラグなどが立つ）
    - 破綻の疑い（bogus / misconfig）：DS はあるが DNSKEY が合わない/署名が壊れている、検証リゾルバ経由で SERVFAIL が出る（検証失敗の可能性）、一部のリゾルバだけ解決できない（利用者影響の兆候）
    - ※OSINTでは「兆候」として扱い、断定は運用側確認へ繋ぐ。
  - “誤設定” が起きやすいポイント（意味づけ）
    - DNSSEC運用の事故は、信頼の鎖の更新で起きやすい。
    - 鍵ロールオーバ（KSK/ZSK更新）で DS 更新が追従しない
    - ゾーン移行（DNSプロバイダ変更）で DS/DNSKEY が不整合
    - 署名期限切れ（RRSIG expiration）で検証失敗
    - 委譲先（サブドメイン）で DNSSEC 状態が親と不一致（運用境界のズレ）
    - ASMとしては「攻撃」より「可用性＋境界健全性」の観点が強い。
- 境界の観点
  - 資産境界（管理主体・委託先・対象範囲の線引き）：企業ドメインはサブドメイン委任が多い。親と子で DNSSEC 状態が異なる前提で観測する
  - 信頼境界（外部連携・第三者・越境ポイント）：DNSSEC は「有効＝万能」ではない（DNSの完全性を強化するが、運用ミスで可用性を落とす）
  - 権限境界（権限の切替/伝播/委任）：認証・回復導線はDNSの健全性が前提（名前解決不能＝利用不能）
- 重要なフィールド/差分/状態（「ここが変わると意味が変わる」点）
  - dnssec_key_posture（後工程に渡す正規化キー）
    - dnssec_key_posture = <domain> + <ds_present> + <dnskey_present> + <rrsig_present> + <validation_hint> + <misconfig_hint> + <confidence>
  - validation_hint（例）
    - ad_set | validates | unknown
  - misconfig_hint（例）
    - servfail_on_validating_resolver | ds_dnskey_mismatch_suspected | rrsig_expired_suspected | none | unknown

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が“確定”できるか
  - DNSSEC が “設定されている/いない” の大枠（DS/DNSKEY/RRSIG の有無）
  - 検証失敗を示唆する兆候（SERVFAIL等）が見えるかどうか
  - サブドメイン委任がある場合、どこで状態が変わるか（運用境界の示唆）
- 何が“推定”できるか（推定の根拠/前提）
  - 検証失敗の原因の断定（ロールオーバ失敗、移行事故等）
- 何は“言えない”か（不足情報・観測限界）
  - 検証失敗の原因の断定（ロールオーバ失敗、移行事故等）
  - 影響範囲（どの利用者/リゾルバで発生するか）※追加観測が必要
  - 攻撃の有無（DNSSECは攻撃検知ではなく改ざん耐性の仕組み）
- よくある状態パターン（正常/異常/境界がズレている等）
  - パターンA：DNSSECが無効（DSなし）で、特に問題兆候はない
  - パターンB：DNSSECが有効（DS/DNSKEY/RRSIGあり）で、検証も良さそう
  - パターンC：DNSSEC破綻の疑い（SERVFAIL等）がある（P0/P1）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す“狙い目”（診断上の優先度付けとして使う）
  - P0（即時に運用確認が必要）：DNSSEC破綻の疑いが強い（検証リゾルバでSERVFAIL、DSありなのに検証不能など）、重要導線（auth/billing/support等）のドメインで、名前解決不安定の兆候（可用性に直結）
  - P1（優先的に棚卸し/成熟度評価）：DNSSECは有効だが、委譲やサブドメインが多く、運用境界が複雑（移行/更新の事故リスク）、関連ドメイン（20_brand_assets）でDNSSEC状態がバラバラ（周辺弱点の示唆）
  - P2（情報整備）：DNSSEC未導入（必ずしも脆弱性ではないが、境界強化の余地として記録）、小規模/非重要ドメイン（影響が限定）
- 優先度の付け方（時間制約がある場合の順序）
  - P0（即時に運用確認が必要）→ P1（優先的に棚卸し/成熟度評価）→ P2（情報整備）の順
- 代表的な攻め筋（この観測から自然に繋がるもの）
  - 攻め筋1：01_dns：委譲の境界（NS/サブドメイン委任）と合わせて “どこで運用が分かれているか” を説明する
  - 攻め筋2：02_tls：DNSが破綻するとTLS/HTTPS以前に到達できない（可用性/信頼の前提）
  - 攻め筋3：20_brand_assets：類似ドメイン群の成熟度差（DNSSEC/DMARC等）を周辺リスクとして比較する
  - 攻め筋4：23_vdp_scope：P0兆候が出たら深追いせず、証跡＋運用確認（またはVDP報告）へ
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）
  - DNSSEC破綻の疑い（SERVFAIL等）がある（P0/P1） → どの条件で発生するかを “最小” で切り分ける（例：検証リゾルバAでは失敗、Bでは成功）

## 次に試すこと（仮説A/Bの分岐と検証）
> ここが最重要。条件が違うと次の手が変わる形で書く。

- 仮説A：DNSSECが無効（DSなし）で、特に問題兆候はない
  - 次の検証：
    - “未導入” を dnssec_key_posture として記録（P2）
    - 他の境界（TLS/HTTP/メール）と合わせて、優先度が上がる要因があるかを見る（単体では致命でないことが多い）
    - 関連ドメイン（20）も同様に観測し、統制の一貫性を評価する
  - 期待する観測（成功/失敗時に何が見えるか）：
    - “未導入” の記録、他の境界との相関、関連ドメインの観測結果
- 仮説B：DNSSECが有効（DS/DNSKEY/RRSIGあり）で、検証も良さそう
  - 次の検証：
    - “有効” を posture として記録（P2〜P1）
    - サブドメイン委任が多い場合は、重要サブドメインだけ追加観測（低アクティブで点検）
    - 移行/更新時の事故が起きやすい点を運用リスクとしてメモ（攻撃面ではなく運用境界）
  - 期待する観測：
    - “有効” の記録、重要サブドメインの追加観測、運用リスクのメモ
- 仮説C：DNSSEC破綻の疑い（SERVFAIL等）がある（P0/P1）
  - 次の検証：
    - （OSINTの安全域）どの条件で発生するかを “最小” で切り分ける（例：検証リゾルバAでは失敗、Bでは成功）。DS/DNSKEY/RRSIGの有無を証跡化し、“鎖が切れている可能性” を説明できる形にする。影響が大きい導線（auth/support等）なら深追いせず、運用/VDPへ報告・確認へ
    - （運用側への依頼）鍵更新/プロバイダ移行/署名期限の状況を運用側で確認してもらう（こちらで状態変更しない）
  - 期待する観測：
    - 条件の切り分け、証跡化、運用側への依頼

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/01_local/01_attack-box_作業端末設計.md`（結果の保存・差分管理）
    - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`（現状確認の最小証跡）
- 取得する証跡（目的ベースで最小限）
  - dnssec_key_posture（後工程に渡す正規化キー）
    - dnssec_key_posture = <domain> + <ds_present> + <dnskey_present> + <rrsig_present> + <validation_hint> + <misconfig_hint> + <confidence>
  - 記録の最小フィールド（推奨）
    - source_locator: 取得日時（JST）＋問い合わせ先（どのリゾルバ/ツールか）
    - domain: 対象
    - ds: 有無/要点
    - dnskey: 有無/要点
    - rrsig: 有無/要点
    - validation_hint: 検証済み兆候
    - misconfig_hint: 誤設定兆候
    - confidence: high/mid/low
    - action_priority: P0/P1/P2
- 観測の取り方（どの視点で差分を見るか）
  - 原則は OSINT：DNSクエリと公開情報のみ（状態変更なし、負荷は軽い）
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/dnssec_25 2>/dev/null
    cd ~/keda_evidence/dnssec_25
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象ドメインは **許可されたスコープ** のみ（契約範囲/社内許可範囲/自前検証環境）
      - 観測は **代表点の抽出** のみ（原則は OSINT：DNSクエリと公開情報のみ（状態変更なし、負荷は軽い））
      - 観測視点（端末/経路/ネットワーク）を記録
  - 相関キー（最低限）を作る（後で必ず効く）
    - Domain：domain
    - DSPresent：ds_present（yes/no/unknown）
    - DNSKEYPresent：dnskey_present（yes/no/unknown）
    - RRSIGPresent：rrsig_present（yes/no/unknown）
    - ValidationHint：validation_hint（ad_set/validates/unknown）
    - MisconfigHint：misconfig_hint（servfail_on_validating_resolver/ds_dnskey_mismatch_suspected/rrsig_expired_suspected/none/unknown）
    - Confidence：confidence（high/mid/low）
    - ActionPriority：action_priority（P0/P1/P2）
    - Timestamp：観測日時（JSTで秒まで）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は“手段”であり“結論”ではない。必ず「何を観測している例か」を添える。

~~~~
# 最小の観測例（DNSSEC関連の問合せ：例示のみ）

# DS（親側委譲の有無を見る）
dig +dnssec +short DS example.com

# DNSKEY（子側の鍵）
dig +dnssec +short DNSKEY example.com

# 署名付き応答（A等にRRSIGが付くか）
dig +dnssec example.com A

# 検証を意識（ADフラグ等は環境依存）
# 例：検証するリゾルバ（手元/公共）を使う場合は「どのリゾルバで見たか」を証跡に残す
~~~~

- この例で観測していること：
  - 原則は OSINT：DNSクエリと公開情報のみ（状態変更なし、負荷は軽い）
- 出力のどこを見るか（注目点）：
  - DS：親側委譲の有無（親（example.com の親＝.com）が DS を持つ）
  - DNSKEY：子側の鍵（子ゾーンの DNSKEY と一致）
  - RRSIG：署名付き応答（署名（RRSIG）が検証できる）
  - 検証結果：ADフラグなど、検証失敗の兆候（SERVFAIL等）
- この例が使えないケース（前提が崩れるケース）：
  - 検証失敗の原因の断定（ロールオーバ失敗、移行事故等）は運用側情報が必要な場合がある

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：V14（設定）：DNS運用（委譲・署名・更新）の誤設定は可用性と信頼境界に直結する。V1（アーキ/要件）：資産境界（DNS委譲/プロバイダ）を定義し、運用変更のリスクを管理する。V2（支える前提）：認証・回復導線はDNSの健全性が前提（名前解決不能＝利用不能）
  - 該当要件（可能ならID）：外部依存・設定・通信・境界（ASM/OSINTは“前提の崩れ”を潰す役）
  - このファイルの内容が「満たす/破れる」ポイント：
    - 破れる：DNS運用（委譲・署名・更新）の誤設定を確定できないと、以降の検証で“対象外”や“前提違い”を起こし、検証精度が落ちる。
    - 満たす：外部依存・設定・通信・境界（ASM/OSINTは“前提の崩れ”を潰す役）を把握し、以降の検証（認証/認可/API/運用）を「前提崩れ」なく進める土台を作る。
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：INFO：公開情報（DNS）から境界（委譲・署名）を収集し、意味づけする。CONF（支える前提）：設定ミス（DNSSEC破綻）は重大インシデントにつながり得るため、早期発見が重要
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：WSTG各観点へ入る前の“入口確定”として接続
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Intelligence Gathering：DNSSEC状態を収集し、境界健全性として評価する。Threat Modeling（支える前提）：DNS改ざん耐性と運用事故リスクを、全体の前提として組み込む
  - 前後フェーズとの繋がり（1行）：DNSSEC を ASM/OSINT の範囲で観測し、委譲（DS）〜検証（DNSKEY/RRSIG）〜誤設定（bogus/破綻）までを「証跡つき」「優先度つき」で説明できる
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Reconnaissance：DNS公開情報から運用境界を把握。Impact（支える前提）：DNS破綻は可用性に影響し得るため、リスク評価の入力として扱う
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
- DNSSEC（DS/DNSKEY/RRSIG）の役割と “委譲チェーン” の概念
- 検証失敗（bogus）と SERVFAIL の関係（断定はせず、兆候として扱う）

## リポジトリ内リンク（最大3つまで）
- 関連 topics：
  - `01_topics/01_asm-osint/01_dns_委譲・境界・解釈.md`
  - `01_topics/01_asm-osint/02_tls_証明書・CT・外部依存推定.md`
- 関連 labs / cases：
  - `04_labs/01_local/01_attack-box_作業端末設計.md`

---

## 深掘りリンク（最大8）
- `01_topics/01_asm-osint/20_brand_assets_関連ドメイン推定（typo_lookalike）.md`
- `01_topics/01_asm-osint/23_vdp_scope_制約下での低アクティブ観測設計.md`
- `01_topics/01_asm-osint/03_http_観測（ヘッダ/挙動）と意味.md`
- `01_topics/01_asm-osint/19_email_infra（SPF_DKIM_DMARC）と攻撃面.md`
- `02_playbooks/01_asm_passive-recon_資産境界→優先度付け.md`
- `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- `01_topics/01_asm-osint/24_subdomain_takeover_成立条件推定（DNS_CNAME_プロバイダ）.md`
- `01_topics/01_asm-osint/06_subdomain_列挙（passive_active_辞書_優先度）.md`

---
