# 24_subdomain_takeover_成立条件推定（DNS_CNAME_プロバイダ）
Subdomain Takeover 成立条件推定（DNS/CNAME/プロバイダ）
“成立条件（未割当・解除済み・参照先不整合）を説明できる”

## 目的（この技術で到達する状態）
サブドメインの “subdomain takeover（奪取）” について、ASM/OSINT の範囲で「成立条件」を推定し、次を「証跡つき」「優先度つき」で確定できる状態にする。
- DNS（CNAME/A/ALIAS 等）とプロバイダ特性から、奪取リスクのある候補を漏れなく洗い出す
- “実際に奪取する” ことなく、成立条件（未割当・解除済み・参照先不整合）を説明できる
- 影響（ブランド/認証導線/配布面）と優先度（P0/P1/P2）を付け、運用側に渡せる
- 23_vdp_scope（制約下）に沿った、低アクティブ観測・中断条件・許可依頼ポイントを持てる

## 前提（対象・範囲・想定）
- 対象：サブドメインの “subdomain takeover（奪取）” について、ASM/OSINT の範囲で「成立条件」を推定する。原則は OSINT：DNS/TLS/HTTP の最小観測（既知ホストのみ、過度な探索なし）
- 想定する環境：
  - 誤検知があり得るため、confidence を必ず付ける（DNSだけで断定しない）
  - 目的は “奪取の実行” ではなく、奪取が成立し得る「条件の推定」と「防止/是正の意思決定」
- できること/やらないこと（安全に検証する範囲）：
  - できる：原則は OSINT：DNS/TLS/HTTP の最小観測（既知ホストのみ、過度な探索なし）。成立条件（未割当・解除済み・参照先不整合）を説明できる
  - やらない：実際の “リソース登録/紐付け/乗っ取り確認” は状態変更に該当し得るため、原則行わない（必要なら合意・許可が前提）
- 依存する前提知識（必要最小限）：
  - `01_topics/01_asm-osint/01_dns_委譲・境界・解釈.md`
  - `01_topics/01_asm-osint/02_tls_証明書・CT・外部依存推定.md`
  - `01_topics/01_asm-osint/03_http_観測（ヘッダ・挙動）と意味.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：Subdomain Takeover 成立条件推定（DNS/CNAME/プロバイダ）、成立条件の説明、優先度付け
  - 扱わない（別ユニットへ接続）
    - DNS観測 → `01_dns_委譲・境界・解釈.md`
    - TLS観測 → `02_tls_証明書・CT・外部依存推定.md`
    - HTTP観測 → `03_http_観測（ヘッダ/挙動）と意味.md`
    - VDP Scope → `01_topics/01_asm-osint/23_vdp_scope_制約下での低アクティブ観測設計.md`

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
- 観測対象（プロトコル/データ構造/やり取りの単位）
  - DNSの入口：どのレコードで “外部ホスティング” に委譲しているか
    - 奪取リスクは「外部の名前空間」へ委譲しているときに出やすい。
    - CNAME：`sub.example.com -> target.provider.net`
    - ALIAS/ANAME（実装依存）：ルートドメイン相当で CNAME 的に外部へ向ける
    - A/AAAA：直接IPでも、クラウド/ホスティングIPで “解約後に再割当” の性質がある場合は注意（ただしCNAMEほど典型ではない）
    - NS（サブドメイン委任）：`dev.example.com` 自体が別のDNSに委任されている場合、境界がさらに広い
  - “成立条件” の分解（奪取リスクを条件論で扱う）
    - subdomain takeover の成立は、概ね次の積み上げで推定できる。
    - 条件A：サブドメインが外部プロバイダのリソース（ホスティング/アプリ/ストレージ/CDN）に向いている
    - 条件B：参照先のリソースが “存在しない/解除済み/未割当” に見える（オーナ不在の示唆）
    - 条件C：そのプロバイダが “先着登録で同名を取れる” 性質を持つ（一般論としてのリスク）
    - 条件D：サブドメインが重要導線（auth/billing/support/download 等）に近い（影響が大きい）
    - ※OSINTでは A/B/D の観測で優先度を作り、C はプロバイダ一般特性として “推定” に留める。
  - DNS観測で見るべきシグナル（低アクティブ）
    - CNAME の “末尾ドメイン” からプロバイダを推定（例：特定のPaaS/ホスティング/CDNの命名）
    - CNAME チェーンの途中で NXDOMAIN / SERVFAIL が出ないか（不整合の示唆）
    - TTL が極端に短い/長い（運用の癖。短い＝頻繁に切替、長い＝放置の可能性）
    - 同一プロバイダへ向くサブドメインが多数あるか（面の広さ、運用一括の可能性）
  - HTTP/TLS観測で “オーナ不在” を示唆するシグナル（断定しない）
    - DNSだけだと「単にメンテ中」もあるため、最小のHTTP/TLS観測で confidence を上げる。
    - HTTP：プロバイダ特有のエラーページ/ホスト未登録を示す文言/404の出方（スクショ/本文要約で証跡化）
    - TLS：証明書が不在、またはプロバイダ共通証明書のみ（SNI/host紐付けができていない示唆）
    - リダイレクト：公式へ戻らず、プロバイダ側の汎用ページに落ちる（不整合の示唆）
    - ※ここでも “攻撃の検証” はせず、「観測できた事実」と「推定」を分離する。
- 境界の観点
  - 資産境界（管理主体・委託先・対象範囲の線引き）：サブドメインが外部プロバイダのリソース（ホスティング/アプリ/ストレージ/CDN）に向いている
  - 信頼境界（外部連携・第三者・越境ポイント）：そのプロバイダが “先着登録で同名を取れる” 性質を持つ（一般論としてのリスク）
  - 権限境界（権限の切替/伝播/委任）：サブドメインが重要導線（auth/billing/support/download 等）に近い（影響が大きい）
- 重要なフィールド/差分/状態（「ここが変わると意味が変わる」点）
  - takeover_key_condition（後工程に渡す正規化キー）
    - takeover_key_condition = <subdomain> + <dns_target> + <provider_hint> + <orphan_signal> + <critical_route> + <confidence>
  - provider_hint（例）
    - paas_hosting | cdn | storage | pages | unknown
  - orphan_signal（例：OSINTでの示唆）
    - dns_broken | http_unclaimed_suspected | tls_unbound_suspected | unknown
  - critical_route（例）
    - auth | billing | support | download | general | unknown

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が“確定”できるか
  - 外部プロバイダへの委譲の有無（CNAME等）と、プロバイダ推定（provider_hint）
  - “不整合/オーナ不在を示唆するシグナル” の有無（orphan_signal）
  - 重要導線との近さ（critical_route）と、優先度（P0/P1/P2）
- 何が“推定”できるか（推定の根拠/前提）
  - 実際に奪取が可能かの最終確証（状態変更を伴う検証が必要になり得る）
- 何は“言えない”か（不足情報・観測限界）
  - 実際に奪取が可能かの最終確証（状態変更を伴う検証が必要になり得る）
  - 参照先が一時障害か、解除済みかの断定（運用側情報が必要な場合がある）
  - 影響の確定（本番導線か、内部用途か）※追加の境界情報が必要
- よくある状態パターン（正常/異常/境界がズレている等）
  - パターンA：外部委譲＋オーナ不在の示唆が強い（P0）
  - パターンB：外部委譲はあるが、オーナ不在か不明（P1）
  - パターンC：誤検知の可能性が高い（運用中に見える）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す“狙い目”（診断上の優先度付けとして使う）
  - P0（即時是正候補）：orphan_signal が強い（DNS不整合＋HTTPで未登録示唆 等）かつ、critical_route が auth/billing/support/download に近い、サブドメインが公式ブランドに近い命名（login, account, pay, support 等）で、第三者誘導の影響が大きい
  - P1（優先的に運用確認）：orphan_signal は中程度だが、外部委譲が明確で、同一プロバイダへ複数委譲（面が広い）、stg/dev っぽい命名だが、外部公開されている（境界管理の問題の示唆）
  - P2（整理・棚卸し）：外部委譲はあるが、HTTP/TLSで正当な運用が示唆される（誤検知の可能性）、内部用途が強く、外部から到達しない（ただしDNSは公開なので運用是正候補には残す）
- 優先度の付け方（時間制約がある場合の順序）
  - P0（即時是正候補）→ P1（優先的に運用確認）→ P2（整理・棚卸し）の順
- 代表的な攻め筋（この観測から自然に繋がるもの）
  - 攻め筋1：01_dns：委譲・境界の解釈（CNAME/NSの意味づけ）
  - 攻め筋2：02_tls：証明書/SAN/CTから、運用実体（正当ホスト紐付け）を補助観測
  - 攻め筋3：03_http：低アクティブでの到達性・境界（401/403/404/302）の観測
  - 攻め筋4：20_brand_assets：ブランド導線に近いサブドメインほど影響が大きい（優先度に直結）
  - 攻め筋5：23_vdp_scope：P0兆候時は深追いせず、証跡＋許可依頼へ
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）
  - 誤検知の可能性が高い（運用中に見える） → 低優先度（P2）として棚卸しに残し、定期確認（変更監視）対象に回す

## 次に試すこと（仮説A/Bの分岐と検証）
> ここが最重要。条件が違うと次の手が変わる形で書く。

- 仮説A：外部委譲＋オーナ不在の示唆が強い（P0）
  - 次の検証：
    - （OSINTの安全域）証跡を整える：DNS応答、HTTPステータス/ヘッダ、エラーページの要約（全文貼付は避ける）、日時。影響推定：そのサブドメインがどの導線に使われていそうか（auth/billing/support 等）を周辺情報から整理。同一パターンの横展開：同一プロバイダへの委譲が他にもあるか（面の把握）
    - （許可がある場合のみ）“確定に必要な最小追加確認” を明文化して、運用/VDPへ許可依頼（こちらで状態変更をしない前提で）
  - 期待する観測（成功/失敗時に何が見えるか）：
    - 証跡の整備、影響推定、同一パターンの横展開、許可依頼の明文化
- 仮説B：外部委譲はあるが、オーナ不在か不明（P1）
  - 次の検証：
    - TLS/HTTPの最小観測で confidence を上げる（ただし回数・負荷を増やさない）
    - 16/17（GitHub/CI）で該当ホスト名が設定断片として出るかを相関し、正当運用の可能性を評価
    - 18（storage）や 21（third-party）で、同じプロバイダが別面でも使われていないかを確認（運用一括の示唆）
  - 期待する観測：
    - TLS/HTTPの最小観測結果、設定断片との相関、別面での使用確認
- 仮説C：誤検知の可能性が高い（運用中に見える）
  - 次の検証：
    - 低優先度（P2）として棚卸しに残し、定期確認（変更監視）対象に回す
    - “DNS上の外部委譲を減らす/正当リソースに紐付ける” など、是正方針としてまとめる
  - 期待する観測：
    - 棚卸しへの追加、是正方針のまとめ

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/01_local/01_attack-box_作業端末設計.md`（結果の保存・差分管理）
    - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`（現状確認の最小証跡）
- 取得する証跡（目的ベースで最小限）
  - takeover_key_condition（後工程に渡す正規化キー）
    - takeover_key_condition = <subdomain> + <dns_target> + <provider_hint> + <orphan_signal> + <critical_route> + <confidence>
  - 記録の最小フィールド（推奨）
    - source_locator: 取得日時（JST）＋DNS応答の証跡
    - subdomain: 対象サブドメイン
    - dns_record: CNAME/A/ALIAS 等と値
    - provider_hint: 推定プロバイダ
    - orphan_signal: 観測シグナル（DNS/HTTP/TLS）
    - environment_hint: prod/stg/dev/unknown（命名や周辺情報から）
    - confidence: high/mid/low
    - action_priority: P0/P1/P2
- 観測の取り方（どの視点で差分を見るか）
  - 原則は OSINT：DNS/TLS/HTTP の最小観測（既知ホストのみ、過度な探索なし）
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/takeover_24 2>/dev/null
    cd ~/keda_evidence/takeover_24
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可されたスコープ** のみ（契約範囲/社内許可範囲/自前検証環境）
      - 観測は **代表点の抽出** のみ（原則は OSINT：DNS/TLS/HTTP の最小観測（既知ホストのみ、過度な探索なし））
      - 観測視点（端末/経路/ネットワーク）を記録
  - 相関キー（最低限）を作る（後で必ず効く）
    - Subdomain：subdomain
    - DnsTarget：dns_target
    - ProviderHint：provider_hint（paas_hosting/cdn/storage/pages/unknown）
    - OrphanSignal：orphan_signal（dns_broken/http_unclaimed_suspected/tls_unbound_suspected/unknown）
    - CriticalRoute：critical_route（auth/billing/support/download/general/unknown）
    - Confidence：confidence（high/mid/low）
    - ActionPriority：action_priority（P0/P1/P2）
    - Timestamp：観測日時（JSTで秒まで）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は“手段”であり“結論”ではない。必ず「何を観測している例か」を添える。

~~~~
# 最小の観測例（DNS/HTTP：例示のみ）

## 出力例（最小）
- `NoSuchBucket` 等の典型応答

# DNS（CNAME/A/NS など）

## 出力例（最小）
- `NoSuchBucket` 等の典型応答
dig +short CNAME sub.example.com
dig +short A sub.example.com
dig +short NS dev.example.com

# HTTP（最小：ヘッダ/ステータスのみ）

## 出力例（最小）
- `NoSuchBucket` 等の典型応答
curl -sS -I https://sub.example.com
~~~~

- この例で観測していること：
  - 原則は OSINT：DNS/TLS/HTTP の最小観測（既知ホストのみ、過度な探索なし）
- 出力のどこを見るか（注目点）：
  - DNS：CNAME の “末尾ドメイン” からプロバイダを推定、CNAME チェーンの途中で NXDOMAIN / SERVFAIL が出ないか（不整合の示唆）、TTL が極端に短い/長い（運用の癖）
  - HTTP：プロバイダ特有のエラーページ/ホスト未登録を示す文言/404の出方（スクショ/本文要約で証跡化）、リダイレクト（公式へ戻らず、プロバイダ側の汎用ページに落ちる（不整合の示唆））
- この例が使えないケース（前提が崩れるケース）：
  - 実際の “リソース登録/紐付け/乗っ取り確認” は状態変更に該当し得るため、原則行わない（必要なら合意・許可が前提）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：V14（設定）：DNS/ホスティング設定の不備（未使用CNAME等）は重大な設定リスク。V1（アーキ/要件）：資産境界・信頼境界（外部プロバイダ委譲）の定義と棚卸しが必要。V2（支える前提）：重要導線（認証/回復）が奪取され得ると認証全体の安全性に影響
  - 該当要件（可能ならID）：外部依存・設定・通信・境界（ASM/OSINTは“前提の崩れ”を潰す役）
  - このファイルの内容が「満たす/破れる」ポイント：
    - 破れる：DNS/ホスティング設定の不備（未使用CNAME等）を確定できないと、以降の検証で“対象外”や“前提違い”を起こし、検証精度が落ちる。
    - 満たす：外部依存・設定・通信・境界（ASM/OSINTは“前提の崩れ”を潰す役）を把握し、以降の検証（認証/認可/API/運用）を「前提崩れ」なく進める土台を作る。
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：INFO：公開情報（DNS/TLS/HTTP最小）から攻撃面と設定不備の可能性を収集・整理。CONF（支える前提）：設定ミス（DNSSEC破綻）は重大インシデントにつながり得るため、早期発見が重要
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：WSTG各観点へ入る前の“入口確定”として接続
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Intelligence Gathering：外部委譲（CNAME等）から攻撃面候補を抽出し、優先度を決める。Pre-engagement（支える前提）：制約下では深追いせず、許可依頼ポイントを設計して進める
  - 前後フェーズとの繋がり（1行）：サブドメインの “subdomain takeover（奪取）” について、ASM/OSINT の範囲で「成立条件」を推定し、成立条件（未割当・解除済み・参照先不整合）を説明できる
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Reconnaissance：公開情報から外部資産・委譲関係を把握。Resource Development（支える前提）：外部委譲の不備は攻撃準備に利用され得るため、監視・是正の入力となる
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
- DNSレコード（CNAME/ALIAS/NS委任）の意味と “外部委譲” の捉え方
- Certificate Transparency / TLS観測の基礎（正当運用の裏取りに使う）

## リポジトリ内リンク（最大3つまで）
- 関連 topics：
  - `01_topics/01_asm-osint/01_dns_委譲・境界・解釈.md`
  - `01_topics/01_asm-osint/03_http_観測（ヘッダ/挙動）と意味.md`
- 関連 labs / cases：
  - `04_labs/01_local/01_attack-box_作業端末設計.md`

---

## 深掘りリンク（最大8）
- `01_topics/01_asm-osint/02_tls_証明書・CT・外部依存推定.md`
- `01_topics/01_asm-osint/20_brand_assets_関連ドメイン推定（typo_lookalike）.md`
- `01_topics/01_asm-osint/23_vdp_scope_制約下での低アクティブ観測設計.md`
- `01_topics/01_asm-osint/16_github_code-search_漏えい（key_token_endpoint）.md`
- `01_topics/01_asm-osint/17_ci-cd_artifact_公開物（ログ_ビルド成果物）.md`
- `01_topics/01_asm-osint/18_storage_discovery（S3_GCS_AzureBlob）境界推定.md`
- `01_topics/01_asm-osint/21_third-party_外部依存（タグ_分析SDK）洗い出し.md`
- `02_playbooks/01_asm_passive-recon_資産境界→優先度付け.md`

---
