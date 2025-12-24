# 10_ctlog_証明書拡張観測（SAN_ワイルドカード_中間CA）.md

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS：
  - V1（アーキテクチャ/信頼境界）とV14（運用・構成）を評価する前提として、証明書発行の実態（委託先CA/中間CA/発行ポリシー）と、公開されているFQDN集合（SAN）を“境界情報”として固定する。
- WSTG：
  - Information Gathering の一部として、サブドメイン列挙（06）やHTTP観測（03）に追加の入口（SAN由来）を供給し、外部依存（CDN/ホスティング/委託）を推定する材料にする。
- PTES：
  - Intelligence Gathering（公開情報からの入口拡張）→ Vulnerability Analysis（委託境界・残存資産・例外パスの疑い）へ繋げる。
- MITRE ATT&CK：
  - Reconnaissance（公開情報の収集）として位置づける。目的は攻撃手順ではなく、診断として「公開入口（FQDN）の追加」「委託境界（CA/中間CA/発行主体）の推定」「時系列（過去→現在）」を説明可能にすること。

## 目的（この技術で到達する状態）
- CTログ（Certificate Transparency）を使い、**DNSに見えない入口**（SAN由来のFQDN）と **過去資産**（失効/更新済み証明書に載っていたSAN）を掘り起こし、優先度付けできる。
- 証明書の“内容”を、CNではなく **SAN / ワイルドカード / Issuer（中間CA）/ 有効期間 / 鍵種別** として観測し、運用境界（自社/委託/クラウド）を yes/no/unknown で状態化できる。
- 02_tls（証明書・外部依存推定）と結合し、「実際に配信されている証明書」と「CTに載っている発行履歴」の差分から、例外パス（古いFQDN・環境系）や委託変更点を説明できる。

## 前提（対象・範囲・想定）
- 対象：
  - ルートドメイン（example.com）と、既知の主要サブドメイン（login/api/id 等）
  - 06_subdomain の結果（現状入口）と、09_passive-dns の結果（履歴入口）
- 想定する環境：
  - 自動発行（ACME）で短命証明書が大量に出る
  - ワイルドカード（*.example.com）でサブドメインがCTに出にくい（= CTだけでは入口が増えない）
  - CDN/WAFの共通証明書/共有SAN（別顧客と混ざる）など、CTの“見え方”にノイズが入る
- できること/やらないこと：
  - できる：CTの公開情報を収集し、FQDN候補を作り、現状DNS/HTTPで存在確認する（最小限）
  - やらない：CT由来の候補を根拠に無制限に能動探索する（許可境界を壊さない）
- 依存する前提知識（必要最小限）：
  - `01_topics/01_asm-osint/02_tls_証明書・CT・外部依存推定.md`
  - `01_topics/01_asm-osint/06_subdomain_列挙（passive_active_辞書_優先度）.md`
  - `01_topics/01_asm-osint/09_passive-dns_履歴と再利用（過去資産の掘り起こし）.md`

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) “証明書から得たい情報”を5点に固定する
- SAN（Subject Alternative Name）：実質的な公開FQDN集合（入口候補）
- ワイルドカード：`*.example.com` があるか（入口増加の期待値が変わる）
- Issuer / 中間CA：運用・委託の匂い（どのCA製品/中間が使われているか）
- 有効期間：短命（ACME）か、長命か（運用成熟度の匂い、履歴量の見積もり）
- 鍵/署名：RSA/ECDSA、署名アルゴリズム（“良し悪し”より、運用一貫性と例外パス発見に使う）

### 2) CTログは「CN」ではなく「SAN」を起点に候補化する
- CNは歴史的互換の位置づけで、現代の入口発見はSANが主戦場。
- SANから得たFQDNは、次の観点で分類して優先度付けする：
  - 機能境界：`id/auth/login/api/admin/console` 等
  - 環境境界：`dev/stg/test/old/backup` 等
  - 組織境界：子会社/ブランド/国別（`jp/us/asia` 等）
  - 第三者境界：`cdn`, `edge`, `s3`, `blob`, `pages` など外部運用臭

### 3) ワイルドカードは“入口を隠す”可能性がある（観測の解釈）
- `*.example.com` が主要運用なら、CTにサブドメインがほとんど出ないことがある。
- その場合の意思決定：
  - CTは「入口追加」よりも、「Issuer/中間CAの委託境界」「運用ポリシー（短命/更新頻度）」「例外（ワイルドカード外の個別SAN）」の検出に寄せる。

### 4) Issuer/中間CAの“揺れ”は運用境界変化のシグナル
- 中間CAが複数ある／時期で切り替わる場合：
  - 委託先変更、CDN/WAF切替、部署別運用、買収統合などの可能性がある（断定しない）
- ここでやることは断定ではなく、クラスターを作ること：
  - クラスターA：Issuer X / 中間CA X1 / 短命
  - クラスターB：Issuer Y / 中間CA Y1 / 長命
  - それぞれに紐づくSAN群を束ね、次の観測（DNS/HTTP/Cloud推定）へ渡す。

### 5) 「配信されている証明書」と「CTの履歴」の差分を取る
- 重要：CTは“発行”の履歴であり、“今配っている”とは限らない。
- 差分の取り方（状態化）：
  - CTにあるSANだが、今はDNS解決しない（過去資産候補）
  - 今配っている証明書のSANが、CTの想定と違う（別運用/別経路/例外パスの可能性）
  - 重要ホスト（login/api/id）のIssuerが他と違う（境界分離の可能性）

### 6) 証跡（最低限）
- `ct_raw.json`（取得元と取得日時が分かる形）
- `ct_san_candidates.txt`（SANから抽出したFQDN候補）
- `ct_clusters.md`（Issuer/中間CA/短命・長命で束ねたクラスター）
- `ct_now_resolved.txt`（候補の現状DNS解決結果：yes/no/unknown）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言えること（確定/状態）：
  - CTに“発行された”証明書に載っていたFQDN候補（SAN）を列挙できる
  - Issuer/中間CAの分布（運用境界の“匂い”）をクラスター化できる
  - 現状DNS/HTTPと突合して、入口候補を「現役/過去/不明」に分類できる
- 言えないこと（断定しない）：
  - そのFQDNが必ず対象範囲である（委託/第三者/共有証明書の可能性）
  - CTに出ない＝存在しない（ワイルドカード/内部名/非公開名は見えない）
- 典型的な到達点：
  - 06（現状入口）＋09（履歴）に、CT由来の候補が加わり、「優先度付き入口リスト」が更新されている状態

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- 優先度が上がる状態（診断としての優先度付け）：
  - 環境系/管理系のSANが複数出る（例外パスの候補）
  - Issuer/中間CAが分散し、運用境界が多い（設定差分が出やすい）
  - 重要ホストだけIssuerが違う（境界分離の可能性）
- 次の仮説（例）
  - 仮説A：ワイルドカード運用が主で、CTから入口は増えにくい
    - 次：06の辞書戦略/HTTP観測/JS由来（04_js）へ時間を寄せる
  - 仮説B：CTに環境系SANが出ており、過去資産の残存が疑われる
    - 次：09（PassiveDNS）と突合し、last_seenが新しい順に現状確認（DNS→HTTP）を行う
  - 仮説C：Issuer分散が大きく、委託境界が複数ある
    - 次：05_cloud（露出面推定）・12系（CDN/WAF挙動観測があるなら）へ接続し、境界ごとに入口を整理する

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：CTはワイルドカード中心で入口が増えない
  - 次に試すこと：
    - CTからは「ワイルドカード外の個別SAN」「Issuer分散」「短命/長命」を抽出してクラスター化に専念
    - 入口増加は 06_subdomain（辞書/優先度）と 04_js（フロント由来）へ寄せる
  - 到達点：
    - CTの役割を“入口追加”から“運用境界推定”へ切り替え、無駄な探索を減らす

- 仮説B：CTに環境系/管理系SANが出ている
  - 次に試すこと：
    - SAN候補をDNS解決して yes/no を確定し、解決できるものだけHTTP到達性を最小で確認する
    - 到達できたものを 02_web/01_web_00_recon に渡し、入口・境界・検証方針を確定する
  - 到達点：
    - “CT起点で見つかった入口”として、証跡付きで説明できる

- 仮説C：Issuer/中間CAが複数に分かれ、委託境界が濃い
  - 次に試すこと：
    - クラスターごとに代表FQDNを選び、TLS/HTTPの挙動差分（ヘッダ、リダイレクト、サーバ特性）を観測する
    - Cloud推定（CDN/WAF/Storage）と束ね、責任分界・修正箇所の切り分け材料にする
  - 到達点：
    - 「境界がどこで増えているか」を運用目線で説明できる

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/` ）：
  - `04_labs/01_local/01_attack-box_作業端末設計.md`（結果保存・差分管理）
  - `04_labs/01_local/03_capture_証跡取得（pcap_harl_log）.md`（現状確認の最小証跡）
- 取得する証跡（目的ベースで最小限）：
  - CT取得結果（raw）と正規化（SAN候補）
  - 現状DNS解決結果（yes/no/unknown）
  - 代表ホストの実配信証明書（Issuer/SAN/有効期間：値はそのままで可）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
# 目的：CTからSAN由来のFQDN候補を作り、現状DNS/HTTPへ渡す（“入口追加”の最短ルート）
# 注意：CT取得は提供元により形式が異なる。ここでは「取得→候補化→現状確認」の形を示す。

# (1) 例：crt.sh からJSON取得（大量取得は避け、対象ドメインを絞る）
curl -s "https://crt.sh/?q=%25.example.com&output=json" > ct_raw.json

# (2) 候補化：name_value（SAN相当）を抜き出して正規化（重複除去）
jq -r '.[].name_value' ct_raw.json \
  | tr '\n' '\n' \
  | sed 's/\*\.//g' \
  | sort -u > ct_san_candidates.txt

# (3) 現状DNS確認：解決できる候補だけ次へ回す（yes/no）
dnsx -l ct_san_candidates.txt -a -aaaa -cname -silent > ct_now_resolved.txt

# (4) 代表ホストの“実配信証明書”を取り、Issuer/SANをCTと突合する（差分観測）
echo | openssl s_client -connect login.example.com:443 -servername login.example.com 2>/dev/null \
  | openssl x509 -noout -issuer -subject -dates -ext subjectAltName
~~~~
- この例で観測していること：
  - CT（発行履歴）由来の入口候補（SAN）→ 現状DNS解決 → 実配信証明書との差分
- 出力のどこを見るか（注目点）：
  - `ct_san_candidates.txt`：環境系/管理系/ID基盤/API系の命名
  - `ct_now_resolved.txt`：現役入口の候補（次はHTTP観測へ）
  - openssl出力：Issuer/中間CAの匂い、SANの一致/不一致、有効期間

## 参考（必要最小限）
- `01_topics/01_asm-osint/02_tls_証明書・CT・外部依存推定.md`
- `01_topics/01_asm-osint/06_subdomain_列挙（passive_active_辞書_優先度）.md`
- `01_topics/01_asm-osint/09_passive-dns_履歴と再利用（過去資産の掘り起こし）.md`

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`01_topics/01_asm-osint/02_tls_証明書・CT・外部依存推定.md`
- 関連 playbooks：`02_playbooks/01_asm_passive-recon_資産境界→優先度付け.md`
- 関連 labs：`04_labs/01_local/01_attack-box_作業端末設計.md`