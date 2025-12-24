# email_infra（SPF_DKIM_DMARC）と攻撃面

## 目的（この技術で到達する状態）
対象ドメインのメール基盤（SPF/DKIM/DMARCを中心に、MX/関連レコードも含む）を ASM/OSINT の範囲で観測し、次を「証跡つき」「優先度つき」で確定できる状態にする。
- なりすまし耐性（送信ドメイン認証）の現状を、設定値ベースで説明できる
- メール基盤の資産境界（どのプロバイダ/どのサブドメイン/どの運用形態か）を推定できる
- 付随する攻撃面（webmail/管理ポータル/自動設定エンドポイント等）の“入口候補”を増やせる
- 20_brand_assets（typo/類似）や 23_vdp_scope（制約下）へ接続できる「mail_key_boundary」を作れる

## 前提（対象・範囲・想定）
- 原則は DNS 等の公開情報（OSINT）で完結する
- 目的は “攻撃” ではなく、攻撃面とリスク（なりすまし・誤設定・運用委託境界）を確定し、次工程の意思決定材料にすること
- SPF/DKIM/DMARC は「設定がある＝安全」ではない（整合・運用・サブドメインの穴が残る）
- 本ファイルでは、なりすましの実行手順（メール送信・フィッシング手順）には踏み込まない

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) 資産境界：メール経路と委託境界（誰が送る/受けるか）
- 受信（MX）
  - MX が指すメール受信基盤（プロバイダ推定、オンプレ/クラウド、セキュリティゲートウェイ有無）
- 送信（SPF/DKIM）
  - 送信元として許可されている仕組み（自社MTA、SaaS、マーケ/CRM、チケット、採用、通知基盤）
- 委託境界（第三者SaaS）
  - SPF の include / DKIM の selector から、外部送信サービスの存在が推定できる
  - “業務委託” が多いほど、信頼境界が広がり、漏えい時の影響と統制難度が上がる

### 2) SPF（送信元IP/送信サービスの許可）で見るべき点
- レコードの有無：TXT に `v=spf1 ...` があるか
- 終端（強さ）
  - `-all`（fail）/ `~all`（softfail）/ `?all`（neutral）/ `+all`（許容し過ぎ）
- include の多さ
  - include が多いほど「委託境界が広い」「管理が難しい」「意図しない許可の温床」になりやすい
- ルックアップ回数（運用上の落とし穴）
  - SPF はDNSルックアップ上限があり、肥大化すると一部受信者で判定が破綻する（= 期待した防御にならない）

### 3) DKIM（署名）で見るべき点
- selector の存在（例：`selector1._domainkey` など）
- 複数selector運用（ローテ/移行）か、単一で固定か
- 署名ドメイン（d=）と From ドメインの関係（DMARCの整合へ接続）
- サブドメインの扱い
  - サブドメインごとにselectorが乱立している場合、運用境界（部署/委託先）の分離を示唆する

### 4) DMARC（整合＋ポリシー）で見るべき点
- レコードの有無：`_dmarc.<domain>` に `v=DMARC1; p=...;` があるか
- ポリシー強度
  - `p=none`（監視）/ `p=quarantine`（隔離）/ `p=reject`（拒否）
- サブドメインポリシー：`sp=` の有無（無い場合、サブドメインが穴になりやすい）
- 整合（alignment）の方向性：`adkim=` / `aspf=`（strict/relaxed）
- レポート先（rua/ruf）
  - 集約先ドメインから、運用委託（第三者のDMARC解析サービス）や監視成熟度を推定できる
  - レポート先が多すぎる/不明瞭な場合は、情報取り扱いの信頼境界が広い

### 5) “メール由来の攻撃面” を増やす補助観測（OSINT）
SPF/DKIM/DMARC だけでなく、以下は「入口（endpoint）」や「運用境界」の推定に効く。
- Webmail/管理入口の推定（直接アクセスは別工程。ここでは存在推定まで）
  - MXやSPF include から Microsoft 365 / Google Workspace / 特定ゲートウェイの利用を推定
- 自動設定系の露出（攻撃面の候補）
  - `autodiscover.<domain>` / `mail.<domain>` / `smtp.<domain>` / `imap.<domain>` などの命名・DNS
- TLS関連の成熟度（観測できる範囲）
  - MTA-STS：`_mta-sts.<domain>` TXT と `mta-sts.<domain>/.well-known/mta-sts.txt`（公開設定の有無）
  - TLS-RPT：`_smtp._tls.<domain>` TXT（レポート運用の有無）
- ブランド・類似ドメインとの接続
  - DMARCが強くても、lookalikeドメインが弱いとブランド毀損の入口になりやすい（20へ接続）

### 6) mail_key_boundary（後工程に渡す正規化キー）
- mail_key_boundary（推奨）
  - mail_key_boundary = <domain> + <mx_provider_hint> + <spf_strength> + <dmarc_policy> + <subdomain_posture> + <third_party_count_hint>
- subdomain_posture（推奨ラベル）
  - sp_defined | sp_missing | subdomain_split | unknown

記録の最小フィールド（推奨）
- source_locator: 取得方法（DNS問合せ結果/日時）
- domain: 対象ドメイン
- mx: MX一覧（優先度＋ホスト）
- spf_summary: 終端(all)＋include数＋特記事項
- dkim_selectors_seen: 観測できたselector（推定でOK、確証が無い場合はunknown）
- dmarc_summary: p/sp/adkim/aspf/rua の要点
- confidence: high/mid/low
- action_priority: P0/P1/P2

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える（OSINTで確定できる）
  - 送信ドメイン認証（SPF/DKIM/DMARC）の“設定上の強さ”と、サブドメイン運用の穴の有無
  - 委託境界（外部送信SaaSやゲートウェイの存在）の示唆
  - メール由来で派生し得る攻撃面（自動設定/入口命名/管理ポータル推定）に関する仮説
- 言えない（この段階では確定しない）
  - 実際の受信者側での評価結果（受信側ポリシー差分）
  - DKIM署名が実運用で常に付与されているか（送信実測が必要）
  - 特定のwebmail/管理入口が到達可能か（HTTP観測フェーズで確認）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
### 優先度（P0/P1/P2）
- P0（即時にリスク提示すべき）
  - DMARC未設定、または `p=none` のまま長期放置の疑い
  - SPF が `+all` / `?all` / include肥大で実質弱い
  - `sp=` が無く、サブドメインが統制外の可能性（ブランド/VDPで問題化しやすい）
- P1（優先的に改善提案・後続観測）
  - DKIM運用が不明瞭（selectorが見えない/移行痕跡のみ）＋ DMARC整合が弱そう
  - 外部送信SaaSが多数（委託境界が広く、統制が必要）
  - MTA-STS/TLS-RPTが未整備（対受信側のTLS強制が弱い）
- P2（面の拡張・相関用）
  - 受信基盤の推定（O365/Workspace等）を、他のOSINT（TLS/HTTP/DNS）と相関して確度を上げる
  - autodiscover/mail 等の命名を、02_web/03_http の観測対象へ追加する

## 次に試すこと（仮説A/Bの分岐と検証）
### 仮説A：なりすまし耐性が弱い（DMARC弱/無し、SPF弱、サブドメイン穴）
- 次の一手（OSINTの安全域）
  - “穴の種類” を明確化：親ドメイン/サブドメイン/委託SaaS/整合（alignment）のどれか
  - 20_brand_assets と接続し、lookalikeドメイン監視・統制の必要性を同時に提示できる形にする
  - 23_vdp_scope の観測設計（低アクティブ）として「送信実測が必要か」を切り分ける（必要なら合意事項へ）
- 次の一手（後工程への受け渡し）
  - 03_http 観測の対象に `autodiscover/mail/smtp/imap` 等を追加し、入口の存在確認へ繋ぐ
  - 16/17/18 の結果（外部SaaS、ストレージ、CI）と照合し、委託境界の棚卸し精度を上げる

### 仮説B：DMARCが強い（p=reject等）だが、サブドメイン/委託境界が不明
- 次の一手
  - `sp=` と alignment（adkim/aspf）を中心に、サブドメイン統制が実質効いているかを判断
  - include（SPF）やrua（DMARC）から第三者サービスを洗い出し、信頼境界として記録（mail_key_boundaryを更新）
  - 20_brand_assets で “類似ドメイン側” の弱さが残りやすい点を補完（本体が強くても周辺が弱い）

### 仮説C：情報が取れない/曖昧（DNS応答が特殊、記録が散在）
- 次の一手
  - 対象ドメインのサブドメイン戦略を整理（送信専用subdomainの有無：例 mail., notifications., bounce.）
  - 01_dns / 02_tls と相関し、メール基盤が別ドメイン/別委任で運用されていないかを確認
  - 「不明」を境界情報として残し、後続で実測（許可がある場合）に回す

#### 最小の観測例（DNSでの証跡化）
~~~~
# MX
dig +short MX example.com

# SPF（TXT）
dig +short TXT example.com

# DMARC（TXT）
dig +short TXT _dmarc.example.com

# MTA-STS / TLS-RPT（任意）
dig +short TXT _mta-sts.example.com
dig +short TXT _smtp._tls.example.com
~~~~

## 不明点（ここが決まると精度が上がる：回答は短くてOK）
- 対象は「親ドメインのみ」か、「送信専用サブドメイン（例：mail/notify/bounce）」も必ず見る運用か
- 19 では “入口推定（autodiscover等）” を 03_http 観測のチェックリストとして渡すところまで含めるか（含める前提で書いている）
- 23_vdp_scope（制約下）で “送信実測が可能” な案件も想定するか（本ファイルはOSINTで完結前提）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回）
- ASVS：
  - V14（設定）：ドメイン認証（SPF/DKIM/DMARC）と運用設定の不備は、なりすまし・情報漏えい・ブランド毀損に直結
  - V1（アーキ/要件）：外部送信SaaSやゲートウェイを含む信頼境界の定義（脅威モデリングの入力）
  - V2（認証・識別の支える前提）：メールはアカウント回復/通知に直結し、間接的に認証の安全性を左右する
- WSTG：
  - INFO：DNS等の公開情報から、攻撃面（入口候補）と設定リスクを収集・整理
  - CRYP/CONF（支える前提）：送信ドメイン認証とTLS運用は、機密性・真正性の基盤となる
- PTES：
  - Intelligence Gathering → Threat Modeling：メール基盤の境界（委託・運用・サブドメイン）を確定し、優先度（P0/P1/P2）を作る
- MITRE ATT&CK：
  - Reconnaissance：組織の外部露出（メール基盤/委託SaaS）を公開情報から収集
  - Initial Access（支える前提）：メール経路の弱さはソーシャルエンジニアリング起点のリスクを増やすため、境界情報として重要

## 参考（必要最小限）
- SPF / DKIM / DMARC の概要（整合・ポリシー・サブドメインの考え方）
- MTA-STS / TLS-RPT / BIMI（成熟度指標として）
- “サブドメインの統制” と “外部送信SaaSの棚卸し” の運用パターン