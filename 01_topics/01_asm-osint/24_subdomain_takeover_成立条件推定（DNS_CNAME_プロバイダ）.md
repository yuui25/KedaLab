# subdomain_takeover_成立条件推定（DNS_CNAME_プロバイダ）

## 目的（この技術で到達する状態）
サブドメインの “subdomain takeover（奪取）” について、ASM/OSINT の範囲で「成立条件」を推定し、次を「証跡つき」「優先度つき」で確定できる状態にする。
- DNS（CNAME/A/ALIAS 等）とプロバイダ特性から、奪取リスクのある候補を漏れなく洗い出す
- “実際に奪取する” ことなく、成立条件（未割当・解除済み・参照先不整合）を説明できる
- 影響（ブランド/認証導線/配布面）と優先度（P0/P1/P2）を付け、運用側に渡せる
- 23_vdp_scope（制約下）に沿った、低アクティブ観測・中断条件・許可依頼ポイントを持てる

## 前提（対象・範囲・想定）
- 原則は OSINT：DNS/TLS/HTTP の最小観測（既知ホストのみ、過度な探索なし）
- 目的は “奪取の実行” ではなく、奪取が成立し得る「条件の推定」と「防止/是正の意思決定」
- 実際の “リソース登録/紐付け/乗っ取り確認” は状態変更に該当し得るため、原則行わない（必要なら合意・許可が前提）
- 誤検知があり得るため、confidence を必ず付ける（DNSだけで断定しない）

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) DNSの入口：どのレコードで “外部ホスティング” に委譲しているか
奪取リスクは「外部の名前空間」へ委譲しているときに出やすい。
- CNAME：`sub.example.com -> target.provider.net`
- ALIAS/ANAME（実装依存）：ルートドメイン相当で CNAME 的に外部へ向ける
- A/AAAA：直接IPでも、クラウド/ホスティングIPで “解約後に再割当” の性質がある場合は注意（ただしCNAMEほど典型ではない）
- NS（サブドメイン委任）：`dev.example.com` 自体が別のDNSに委任されている場合、境界がさらに広い

### 2) “成立条件” の分解（奪取リスクを条件論で扱う）
subdomain takeover の成立は、概ね次の積み上げで推定できる。
- 条件A：サブドメインが外部プロバイダのリソース（ホスティング/アプリ/ストレージ/CDN）に向いている
- 条件B：参照先のリソースが “存在しない/解除済み/未割当” に見える（オーナ不在の示唆）
- 条件C：そのプロバイダが “先着登録で同名を取れる” 性質を持つ（一般論としてのリスク）
- 条件D：サブドメインが重要導線（auth/billing/support/download 等）に近い（影響が大きい）

※OSINTでは A/B/D の観測で優先度を作り、C はプロバイダ一般特性として “推定” に留める。

### 3) DNS観測で見るべきシグナル（低アクティブ）
- CNAME の “末尾ドメイン” からプロバイダを推定（例：特定のPaaS/ホスティング/CDNの命名）
- CNAME チェーンの途中で NXDOMAIN / SERVFAIL が出ないか（不整合の示唆）
- TTL が極端に短い/長い（運用の癖。短い＝頻繁に切替、長い＝放置の可能性）
- 同一プロバイダへ向くサブドメインが多数あるか（面の広さ、運用一括の可能性）

### 4) HTTP/TLS観測で “オーナ不在” を示唆するシグナル（断定しない）
DNSだけだと「単にメンテ中」もあるため、最小のHTTP/TLS観測で confidence を上げる。
- HTTP：プロバイダ特有のエラーページ/ホスト未登録を示す文言/404の出方（スクショ/本文要約で証跡化）
- TLS：証明書が不在、またはプロバイダ共通証明書のみ（SNI/host紐付けができていない示唆）
- リダイレクト：公式へ戻らず、プロバイダ側の汎用ページに落ちる（不整合の示唆）

※ここでも “攻撃の検証” はせず、「観測できた事実」と「推定」を分離する。

### 5) takeover_key_condition（後工程に渡す正規化キー）
- takeover_key_condition（推奨）
  - takeover_key_condition = <subdomain> + <dns_target> + <provider_hint> + <orphan_signal> + <critical_route> + <confidence>
- provider_hint（例）
  - paas_hosting | cdn | storage | pages | unknown
- orphan_signal（例：OSINTでの示唆）
  - dns_broken | http_unclaimed_suspected | tls_unbound_suspected | unknown
- critical_route（例）
  - auth | billing | support | download | general | unknown

記録の最小フィールド（推奨）
- source_locator: 取得日時（JST）＋DNS応答の証跡
- subdomain: 対象サブドメイン
- dns_record: CNAME/A/ALIAS 等と値
- provider_hint: 推定プロバイダ
- orphan_signal: 観測シグナル（DNS/HTTP/TLS）
- environment_hint: prod/stg/dev/unknown（命名や周辺情報から）
- confidence: high/mid/low
- action_priority: P0/P1/P2

#### 最小の観測例（DNS/HTTP：例示のみ）
~~~~
# DNS（CNAME/A/NS など）
dig +short CNAME sub.example.com
dig +short A sub.example.com
dig +short NS dev.example.com

# HTTP（最小：ヘッダ/ステータスのみ）
curl -sS -I https://sub.example.com
~~~~

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える（OSINTで確定できる）
  - 外部プロバイダへの委譲の有無（CNAME等）と、プロバイダ推定（provider_hint）
  - “不整合/オーナ不在を示唆するシグナル” の有無（orphan_signal）
  - 重要導線との近さ（critical_route）と、優先度（P0/P1/P2）
- 言えない（この段階では確定しない）
  - 実際に奪取が可能かの最終確証（状態変更を伴う検証が必要になり得る）
  - 参照先が一時障害か、解除済みかの断定（運用側情報が必要な場合がある）
  - 影響の確定（本番導線か、内部用途か）※追加の境界情報が必要

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
※“奪取のやり方”ではなく、ASMとしての意思決定。
### 優先度（P0/P1/P2）
- P0（即時是正候補）
  - orphan_signal が強い（DNS不整合＋HTTPで未登録示唆 等）かつ、critical_route が auth/billing/support/download に近い
  - サブドメインが公式ブランドに近い命名（login, account, pay, support 等）で、第三者誘導の影響が大きい
- P1（優先的に運用確認）
  - orphan_signal は中程度だが、外部委譲が明確で、同一プロバイダへ複数委譲（面が広い）
  - stg/dev っぽい命名だが、外部公開されている（境界管理の問題の示唆）
- P2（整理・棚卸し）
  - 外部委譲はあるが、HTTP/TLSで正当な運用が示唆される（誤検知の可能性）
  - 内部用途が強く、外部から到達しない（ただしDNSは公開なので運用是正候補には残す）

### 後続トピックへの接続（地続き）
- 01_dns：委譲・境界の解釈（CNAME/NSの意味づけ）
- 02_tls：証明書/SAN/CTから、運用実体（正当ホスト紐付け）を補助観測
- 03_http：低アクティブでの到達性・境界（401/403/404/302）の観測
- 20_brand_assets：ブランド導線に近いサブドメインほど影響が大きい（優先度に直結）
- 23_vdp_scope：P0兆候時は深追いせず、証跡＋許可依頼へ

## 次に試すこと（仮説A/Bの分岐と検証）
### 仮説A：外部委譲＋オーナ不在の示唆が強い（P0）
- 次の一手（OSINTの安全域）
  - 証跡を整える：DNS応答、HTTPステータス/ヘッダ、エラーページの要約（全文貼付は避ける）、日時
  - 影響推定：そのサブドメインがどの導線に使われていそうか（auth/billing/support 等）を周辺情報から整理
  - 同一パターンの横展開：同一プロバイダへの委譲が他にもあるか（面の把握）
- 次の一手（許可がある場合のみ）
  - “確定に必要な最小追加確認” を明文化して、運用/VDPへ許可依頼（こちらで状態変更をしない前提で）

### 仮説B：外部委譲はあるが、オーナ不在か不明（P1）
- 次の一手
  - TLS/HTTPの最小観測で confidence を上げる（ただし回数・負荷を増やさない）
  - 16/17（GitHub/CI）で該当ホスト名が設定断片として出るかを相関し、正当運用の可能性を評価
  - 18（storage）や 21（third-party）で、同じプロバイダが別面でも使われていないかを確認（運用一括の示唆）

### 仮説C：誤検知の可能性が高い（運用中に見える）
- 次の一手
  - 低優先度（P2）として棚卸しに残し、定期確認（変更監視）対象に回す
  - “DNS上の外部委譲を減らす/正当リソースに紐付ける” など、是正方針としてまとめる

#### 最小の是正方針（運用への落とし込み：例示のみ）
~~~~
- 未使用サブドメイン：DNSレコードを削除（CNAME等を残さない）
- 使用中サブドメイン：参照先リソースの所有/紐付けを確認し、削除予定時はDNSを先に片付ける
- 重要導線：auth/billing/support は特に第三者委譲の棚卸し頻度を上げる
~~~~

## 不明点（ここが決まると精度が上がる：回答は短くてOK）
- 23_vdp_scope を前提に「HTTP観測は HEAD/GET 1回程度まで」を固定するか（DNS/CTのみで固定するか）
- 重要導線（critical_route）の既定セットを auth/billing/support/download で固定してよいか
- “確定検証” が必要になった場合、運用/VDPへ「許可依頼してから」の運用で統一するか（本ファイルは統一前提）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回）
- ASVS：
  - V14（設定）：DNS/ホスティング設定の不備（未使用CNAME等）は重大な設定リスク
  - V1（アーキ/要件）：資産境界・信頼境界（外部プロバイダ委譲）の定義と棚卸しが必要
  - V2（支える前提）：重要導線（認証/回復）が奪取され得ると認証全体の安全性に影響
- WSTG：
  - INFO：公開情報（DNS/TLS/HTTP最小）から攻撃面と設定不備の可能性を収集・整理
  - CONF（支える前提）：設定ミスの発見と是正方針の整理
- PTES：
  - Intelligence Gathering：外部委譲（CNAME等）から攻撃面候補を抽出し、優先度を決める
  - Pre-engagement（支える前提）：制約下では深追いせず、許可依頼ポイントを設計して進める
- MITRE ATT&CK：
  - Reconnaissance：公開情報から外部資産・委譲関係を把握
  - Resource Development（支える前提）：外部委譲の不備は攻撃準備に利用され得るため、監視・是正の入力となる

## 参考（必要最小限）
- DNSレコード（CNAME/ALIAS/NS委任）の意味と “外部委譲” の捉え方
- Certificate Transparency / TLS観測の基礎（正当運用の裏取りに使う）
- “未使用CNAMEを残さない” という運用原則（棚卸し・変更管理）