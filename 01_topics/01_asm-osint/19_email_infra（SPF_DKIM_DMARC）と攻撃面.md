# 19_email_infra（SPF_DKIM_DMARC）と攻撃面
Email Infra（SPF/DKIM/DMARC）と攻撃面
“なりすまし耐性（送信ドメイン認証）の現状を、設定値ベースで説明できる”

## 目的（この技術で到達する状態）
対象ドメインのメール基盤（SPF/DKIM/DMARCを中心に、MX/関連レコードも含む）を ASM/OSINT の範囲で観測し、次を「証跡つき」「優先度つき」で確定できる状態にする。
- なりすまし耐性（送信ドメイン認証）の現状を、設定値ベースで説明できる
- メール基盤の資産境界（どのプロバイダ/どのサブドメイン/どの運用形態か）を推定できる
- 付随する攻撃面（webmail/管理ポータル/自動設定エンドポイント等）の“入口候補”を増やせる
- 20_brand_assets（typo/類似）や 23_vdp_scope（制約下）へ接続できる「mail_key_boundary」を作れる

## 前提（対象・範囲・想定）
- 対象：対象ドメインのメール基盤（SPF/DKIM/DMARCを中心に、MX/関連レコードも含む）。原則は DNS 等の公開情報（OSINT）で完結する
- 想定する環境：
  - SPF/DKIM/DMARC は「設定がある＝安全」ではない（整合・運用・サブドメインの穴が残る）
  - 目的は “攻撃” ではなく、攻撃面とリスク（なりすまし・誤設定・運用委託境界）を確定し、次工程の意思決定材料にすること
- できること/やらないこと（安全に検証する範囲）：
  - できる：DNS 等の公開情報（OSINT）で完結する。なりすまし耐性（送信ドメイン認証）の現状を、設定値ベースで説明できる
  - やらない：本ファイルでは、なりすましの実行手順（メール送信・フィッシング手順）には踏み込まない
- 依存する前提知識（必要最小限）：
  - `01_topics/01_asm-osint/01_dns_委譲・境界・解釈.md`
  - `01_topics/01_asm-osint/20_brand_assets_関連ドメイン推定（typo_lookalike）.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：Email Infra（SPF/DKIM/DMARC）と攻撃面、なりすまし耐性の現状説明、資産境界の推定
  - 扱わない（別ユニットへ接続）
    - DNS観測 → `01_dns_委譲・境界・解釈.md`
    - ブランド資産 → `20_brand_assets_関連ドメイン推定（typo_lookalike）.md`
    - HTTP観測 → `01_topics/01_asm-osint/03_http_観測（ヘッダ/挙動）と意味.md`

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
- 観測対象（プロトコル/データ構造/やり取りの単位）
  - 資産境界：メール経路と委託境界（誰が送る/受けるか）
    - 受信（MX）：MX が指すメール受信基盤（プロバイダ推定、オンプレ/クラウド、セキュリティゲートウェイ有無）
    - 送信（SPF/DKIM）：送信元として許可されている仕組み（自社MTA、SaaS、マーケ/CRM、チケット、採用、通知基盤）
    - 委託境界（第三者SaaS）：SPF の include / DKIM の selector から、外部送信サービスの存在が推定できる。“業務委託” が多いほど、信頼境界が広がり、漏えい時の影響と統制難度が上がる
  - SPF（送信元IP/送信サービスの許可）で見るべき点
    - レコードの有無：TXT に `v=spf1 ...` があるか
    - 終端（強さ）：`-all`（fail）/ `~all`（softfail）/ `?all`（neutral）/ `+all`（許容し過ぎ）
    - include の多さ：include が多いほど「委託境界が広い」「管理が難しい」「意図しない許可の温床」になりやすい
    - ルックアップ回数（運用上の落とし穴）：SPF はDNSルックアップ上限があり、肥大化すると一部受信者で判定が破綻する（= 期待した防御にならない）
  - DKIM（署名）で見るべき点
    - selector の存在（例：`selector1._domainkey` など）
    - 複数selector運用（ローテ/移行）か、単一で固定か
    - 署名ドメイン（d=）と From ドメインの関係（DMARCの整合へ接続）
    - サブドメインの扱い：サブドメインごとにselectorが乱立している場合、運用境界（部署/委託先）の分離を示唆する
  - DMARC（整合＋ポリシー）で見るべき点
    - レコードの有無：`_dmarc.<domain>` に `v=DMARC1; p=...;` があるか
    - ポリシー強度：`p=none`（監視）/ `p=quarantine`（隔離）/ `p=reject`（拒否）
    - サブドメインポリシー：`sp=` の有無（無い場合、サブドメインが穴になりやすい）
    - 整合（alignment）の方向性：`adkim=` / `aspf=`（strict/relaxed）
    - レポート先（rua/ruf）：集約先ドメインから、運用委託（第三者のDMARC解析サービス）や監視成熟度を推定できる。レポート先が多すぎる/不明瞭な場合は、情報取り扱いの信頼境界が広い
  - “メール由来の攻撃面” を増やす補助観測（OSINT）
    - Webmail/管理入口の推定（直接アクセスは別工程。ここでは存在推定まで）：MXやSPF include から Microsoft 365 / Google Workspace / 特定ゲートウェイの利用を推定
    - 自動設定系の露出（攻撃面の候補）：`autodiscover.<domain>` / `mail.<domain>` / `smtp.<domain>` / `imap.<domain>` などの命名・DNS
    - TLS関連の成熟度（観測できる範囲）：MTA-STS：`_mta-sts.<domain>` TXT と `mta-sts.<domain>/.well-known/mta-sts.txt`（公開設定の有無）、TLS-RPT：`_smtp._tls.<domain>` TXT（レポート運用の有無）
    - ブランド・類似ドメインとの接続：DMARCが強くても、lookalikeドメインが弱いとブランド毀損の入口になりやすい（20へ接続）
- 境界の観点
  - 資産境界（管理主体・委託先・対象範囲の線引き）：メール経路と委託境界（誰が送る/受けるか）、受信（MX）、送信（SPF/DKIM）、委託境界（第三者SaaS）
  - 信頼境界（外部連携・第三者・越境ポイント）：SPF の include / DKIM の selector から、外部送信サービスの存在が推定できる。“業務委託” が多いほど、信頼境界が広がり、漏えい時の影響と統制難度が上がる
  - 権限境界（権限の切替/伝播/委任）：メールはアカウント回復/通知に直結し、間接的に認証の安全性を左右する
- 重要なフィールド/差分/状態（「ここが変わると意味が変わる」点）
  - mail_key_boundary（後工程に渡す正規化キー）
    - mail_key_boundary = <domain> + <mx_provider_hint> + <spf_strength> + <dmarc_policy> + <subdomain_posture> + <third_party_count_hint>
  - subdomain_posture（推奨ラベル）
    - sp_defined | sp_missing | subdomain_split | unknown

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が“確定”できるか
  - 送信ドメイン認証（SPF/DKIM/DMARC）の“設定上の強さ”と、サブドメイン運用の穴の有無
  - 委託境界（外部送信SaaSやゲートウェイの存在）の示唆
  - メール由来で派生し得る攻撃面（自動設定/入口命名/管理ポータル推定）に関する仮説
- 何が“推定”できるか（推定の根拠/前提）
  - 実際の受信者側での評価結果（受信側ポリシー差分）
- 何は“言えない”か（不足情報・観測限界）
  - 実際の受信者側での評価結果（受信側ポリシー差分）
  - DKIM署名が実運用で常に付与されているか（送信実測が必要）
  - 特定のwebmail/管理入口が到達可能か（HTTP観測フェーズで確認）
- よくある状態パターン（正常/異常/境界がズレている等）
  - パターンA：なりすまし耐性が弱い（DMARC弱/無し、SPF弱、サブドメイン穴）
  - パターンB：DMARCが強い（p=reject等）だが、サブドメイン/委託境界が不明
  - パターンC：情報が取れない/曖昧（DNS応答が特殊、記録が散在）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す“狙い目”（診断上の優先度付けとして使う）
  - P0（即時にリスク提示すべき）：DMARC未設定、または `p=none` のまま長期放置の疑い、SPF が `+all` / `?all` / include肥大で実質弱い、`sp=` が無く、サブドメインが統制外の可能性（ブランド/VDPで問題化しやすい）
  - P1（優先的に改善提案・後続観測）：DKIM運用が不明瞭（selectorが見えない/移行痕跡のみ）＋ DMARC整合が弱そう、外部送信SaaSが多数（委託境界が広く、統制が必要）、MTA-STS/TLS-RPTが未整備（対受信側のTLS強制が弱い）
  - P2（面の拡張・相関用）：受信基盤の推定（O365/Workspace等）を、他のOSINT（TLS/HTTP/DNS）と相関して確度を上げる、autodiscover/mail 等の命名を、02_web/03_http の観測対象へ追加する
- 優先度の付け方（時間制約がある場合の順序）
  - P0（即時にリスク提示すべき）→ P1（優先的に改善提案・後続観測）→ P2（面の拡張・相関用）の順
- 代表的な攻め筋（この観測から自然に繋がるもの）
  - 攻め筋1：なりすまし耐性が弱い（DMARC弱/無し、SPF弱、サブドメイン穴） → “穴の種類” を明確化（親ドメイン/サブドメイン/委託SaaS/整合（alignment）のどれか）、20_brand_assets と接続し、lookalikeドメイン監視・統制の必要性を同時に提示できる形にする、03_http 観測の対象に `autodiscover/mail/smtp/imap` 等を追加し、入口の存在確認へ繋ぐ
  - 攻め筋2：DMARCが強い（p=reject等）だが、サブドメイン/委託境界が不明 → `sp=` と alignment（adkim/aspf）を中心に、サブドメイン統制が実質効いているかを判断、include（SPF）やrua（DMARC）から第三者サービスを洗い出し、信頼境界として記録（mail_key_boundaryを更新）、20_brand_assets で “類似ドメイン側” の弱さが残りやすい点を補完（本体が強くても周辺が弱い）
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）
  - 情報が取れない/曖昧（DNS応答が特殊、記録が散在） → 対象ドメインのサブドメイン戦略を整理（送信専用subdomainの有無：例 mail., notifications., bounce.）、01_dns / 02_tls と相関し、メール基盤が別ドメイン/別委任で運用されていないかを確認

## 次に試すこと（仮説A/Bの分岐と検証）
> ここが最重要。条件が違うと次の手が変わる形で書く。

- 仮説A：なりすまし耐性が弱い（DMARC弱/無し、SPF弱、サブドメイン穴）
  - 次の検証：
    - （OSINTの安全域）“穴の種類” を明確化：親ドメイン/サブドメイン/委託SaaS/整合（alignment）のどれか。20_brand_assets と接続し、lookalikeドメイン監視・統制の必要性を同時に提示できる形にする。23_vdp_scope の観測設計（低アクティブ）として「送信実測が必要か」を切り分ける（必要なら合意事項へ）
    - （後工程への受け渡し）03_http 観測の対象に `autodiscover/mail/smtp/imap` 等を追加し、入口の存在確認へ繋ぐ。16/17/18 の結果（外部SaaS、ストレージ、CI）と照合し、委託境界の棚卸し精度を上げる
  - 期待する観測（成功/失敗時に何が見えるか）：
    - “穴の種類” の明確化、lookalikeドメイン監視・統制の必要性、入口の存在確認、委託境界の棚卸し精度
- 仮説B：DMARCが強い（p=reject等）だが、サブドメイン/委託境界が不明
  - 次の検証：
    - `sp=` と alignment（adkim/aspf）を中心に、サブドメイン統制が実質効いているかを判断
    - include（SPF）やrua（DMARC）から第三者サービスを洗い出し、信頼境界として記録（mail_key_boundaryを更新）
    - 20_brand_assets で “類似ドメイン側” の弱さが残りやすい点を補完（本体が強くても周辺が弱い）
  - 期待する観測：
    - サブドメイン統制の実質効き具合、第三者サービスの洗い出し、類似ドメイン側の弱さの補完
- 仮説C：情報が取れない/曖昧（DNS応答が特殊、記録が散在）
  - 次の検証：
    - 対象ドメインのサブドメイン戦略を整理（送信専用subdomainの有無：例 mail., notifications., bounce.）
    - 01_dns / 02_tls と相関し、メール基盤が別ドメイン/別委任で運用されていないかを確認
    - 「不明」を境界情報として残し、後続で実測（許可がある場合）に回す
  - 期待する観測：
    - サブドメイン戦略の整理、メール基盤の別ドメイン/別委任の確認、境界情報としての記録

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/01_local/01_attack-box_作業端末設計.md`（結果の保存・差分管理）
    - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`（現状確認の最小証跡）
- 取得する証跡（目的ベースで最小限）
  - mail_key_boundary（後工程に渡す正規化キー）
    - mail_key_boundary = <domain> + <mx_provider_hint> + <spf_strength> + <dmarc_policy> + <subdomain_posture> + <third_party_count_hint>
  - 記録の最小フィールド（推奨）
    - source_locator: 取得方法（DNS問合せ結果/日時）
    - domain: 対象ドメイン
    - mx: MX一覧（優先度＋ホスト）
    - spf_summary: 終端(all)＋include数＋特記事項
    - dkim_selectors_seen: 観測できたselector（推定でOK、確証が無い場合はunknown）
    - dmarc_summary: p/sp/adkim/aspf/rua の要点
    - confidence: high/mid/low
    - action_priority: P0/P1/P2
- 観測の取り方（どの視点で差分を見るか）
  - DNS 等の公開情報（OSINT）で完結する。なりすまし耐性（送信ドメイン認証）の現状を、設定値ベースで説明できる
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/email_19 2>/dev/null
    cd ~/keda_evidence/email_19
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象ドメインは **許可されたスコープ** のみ（契約範囲/社内許可範囲/自前検証環境）
      - 観測は **代表点の抽出** のみ（DNS 等の公開情報（OSINT）で完結する）
      - 観測視点（端末/経路/ネットワーク）を記録
  - 相関キー（最低限）を作る（後で必ず効く）
    - Domain：対象ドメイン
    - MXProviderHint：mx_provider_hint
    - SPFStrength：spf_strength（終端(all)＋include数）
    - DMARCPolicy：dmarc_policy（p/sp/adkim/aspf/rua）
    - SubdomainPosture：subdomain_posture（sp_defined/sp_missing/subdomain_split/unknown）
    - ThirdPartyCountHint：third_party_count_hint
    - Confidence：confidence（high/mid/low）
    - ActionPriority：action_priority（P0/P1/P2）
    - Timestamp：観測日時（JSTで秒まで）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は“手段”であり“結論”ではない。必ず「何を観測している例か」を添える。

~~~~
# 最小の観測例（DNSでの証跡化）

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

- この例で観測していること：
  - DNS 等の公開情報（OSINT）で完結する。なりすまし耐性（送信ドメイン認証）の現状を、設定値ベースで説明できる
- 出力のどこを見るか（注目点）：
  - MX：メール受信基盤（プロバイダ推定、オンプレ/クラウド、セキュリティゲートウェイ有無）
  - SPF（TXT）：レコードの有無、終端（強さ）、include の多さ、ルックアップ回数
  - DMARC（TXT）：レコードの有無、ポリシー強度、サブドメインポリシー、整合（alignment）の方向性、レポート先（rua/ruf）
  - MTA-STS / TLS-RPT：TLS関連の成熟度（観測できる範囲）
- この例が使えないケース（前提が崩れるケース）：
  - 情報が取れない/曖昧（DNS応答が特殊、記録が散在） → 対象ドメインのサブドメイン戦略を整理（送信専用subdomainの有無：例 mail., notifications., bounce.）、01_dns / 02_tls と相関し、メール基盤が別ドメイン/別委任で運用されていないかを確認

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：V14（設定）：ドメイン認証（SPF/DKIM/DMARC）と運用設定の不備は、なりすまし・情報漏えい・ブランド毀損に直結。V1（アーキ/要件）：外部送信SaaSやゲートウェイを含む信頼境界の定義（脅威モデリングの入力）。V2（認証・識別の支える前提）：メールはアカウント回復/通知に直結し、間接的に認証の安全性を左右する
  - 該当要件（可能ならID）：外部依存・設定・通信・境界（ASM/OSINTは“前提の崩れ”を潰す役）
  - このファイルの内容が「満たす/破れる」ポイント：
    - 破れる：ドメイン認証（SPF/DKIM/DMARC）と運用設定の不備を確定できないと、以降の検証で“対象外”や“前提違い”を起こし、検証精度が落ちる。
    - 満たす：外部依存・設定・通信・境界（ASM/OSINTは“前提の崩れ”を潰す役）を把握し、以降の検証（認証/認可/API/運用）を「前提崩れ」なく進める土台を作る。
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：INFO：DNS等の公開情報から、攻撃面（入口候補）と設定リスクを収集・整理。CRYP/CONF（支える前提）：送信ドメイン認証とTLS運用は、機密性・真正性の基盤となる
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：WSTG各観点へ入る前の“入口確定”として接続
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Intelligence Gathering → Threat Modeling：メール基盤の境界（委託・運用・サブドメイン）を確定し、優先度（P0/P1/P2）を作る
  - 前後フェーズとの繋がり（1行）：対象ドメインのメール基盤（SPF/DKIM/DMARCを中心に、MX/関連レコードも含む）を ASM/OSINT の範囲で観測し、なりすまし耐性と攻撃面を抽出する
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Reconnaissance：組織の外部露出（メール基盤/委託SaaS）を公開情報から収集。Initial Access（支える前提）：メール経路の弱さはソーシャルエンジニアリング起点のリスクを増やすため、境界情報として重要
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
- SPF / DKIM / DMARC の概要（整合・ポリシー・サブドメインの考え方）
- MTA-STS / TLS-RPT / BIMI（成熟度指標として）

## リポジトリ内リンク（最大3つまで）
- 関連 topics：
  - `01_topics/01_asm-osint/01_dns_委譲・境界・解釈.md`
  - `01_topics/01_asm-osint/20_brand_assets_関連ドメイン推定（typo_lookalike）.md`
- 関連 labs / cases：
  - `04_labs/01_local/01_attack-box_作業端末設計.md`

---

## 深掘りリンク（最大8）
- `01_topics/01_asm-osint/03_http_観測（ヘッダ/挙動）と意味.md`
- `01_topics/01_asm-osint/16_github_code-search_漏えい（key_token_endpoint）.md`
- `01_topics/01_asm-osint/17_ci-cd_artifact_公開物（ログ_ビルド成果物）.md`
- `01_topics/01_asm-osint/18_storage_discovery（S3_GCS_AzureBlob）境界推定.md`
- `01_topics/01_asm-osint/23_vdp_scope_制約下での低アクティブ観測設計.md`
- `02_playbooks/01_asm_passive-recon_資産境界→優先度付け.md`
- `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- `01_topics/01_asm-osint/02_tls_証明書・CT・外部依存推定.md`

---
