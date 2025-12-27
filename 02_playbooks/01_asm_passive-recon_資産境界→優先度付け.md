# 01_asm_passive-recon_資産境界→優先度付け
パッシブ中心の外形観測で「資産/信頼/権限境界」を確定し、深掘りの優先度と次の導線を決める。

## 目的（このプレイブックで到達する状態）
- 代表ドメイン/入口（3〜5個）について、**境界の状態**（自社運用寄り/外部依存寄り/不明）を根拠付きで言える。
- 次に回すべき playbook を迷わず選べる（Web/AuthN/SaaS/NW どこが勝負か）。
- 証跡（DNS/TLS/HTTPの代表点）を最小で残せる。

## 前提（対象・範囲・制約）
- 対象：許可されたスコープ（ドメイン/ブランド/サービス名/ASなど）。
- 制約：パッシブ中心。能動（アクセス/問い合わせ/スキャン）が許可される場合でも**回数最小**・代表点のみ。
- 前提ツール（最小限）：`dig`/`nslookup`、`curl`、`openssl`（代替可）。
- 参照すべきtopics：
  - `01_topics/01_asm-osint/00_index.md`
  - `01_topics/01_asm-osint/01_dns_委譲・境界・解釈.md`
  - `01_topics/01_asm-osint/02_tls_証明書・CT・外部依存推定.md`
  - `01_topics/01_asm-osint/03_http_観測（ヘッダ・挙動）と意味.md`
  - `01_topics/01_asm-osint/05_cloud_露出面（CDN_WAF_Storage等）推定.md`

## 入口で確定すること（最小セット）
- 対象の境界（資産/信頼/権限）をどう把握するか：
  - 資産境界：公式ドメインと主要サブドメインの「管理主体」を推定する（委譲/終端/挙動）。
  - 信頼境界：CDN/WAF/SaaS/Storage 等、第三者が関与する点を列挙する（証拠つき）。
  - 権限境界：SSO/管理UI/委任（OAuth）など「権限が切り替わる入口」を抽出する。
- 完了条件（次へ進める状態）：
  - 代表点 3〜5件について「入口/境界/外部依存/次の深掘り」を1行で書ける。

## 手順（分岐中心：迷うポイントだけ）
> ここでは“全列挙”をしない。**代表点で状態を確定**し、次のplaybookに渡す。

### Step 0：最初の5分（必ずやる）
- 目的：スコープ事故と証跡不足を防ぐ。
- 観測ポイント：
  - 許可スコープ（ドメイン/AS/サービス名）と「禁止事項」（第三者宛通信/大量アクセス/スキャン）をメモ。
  - 代表点（最初は3つ）を決める：`{root domain, login, api/admin}` の形で十分。
- 証跡（最小）：
~~~~
# Windows (PowerShell)
$dir = Join-Path $HOME "keda_evidence\\asm_passive_01"
New-Item -ItemType Directory -Force $dir | Out-Null
Set-Location $dir
"scope: ...`ndate: ...`nseeds: ..." | Set-Content -Encoding utf8 00_scope.txt

# macOS/Linux (bash)
mkdir -p ~/keda_evidence/asm_passive_01
cd ~/keda_evidence/asm_passive_01
printf "scope: ...\ndate: ...\nseeds: ...\n" > 00_scope.txt
~~~~
- 次の分岐：
  - 代表点が決まった → Step 1へ

### Step 1：DNSの境界（委譲と権威）を確定する
- 目的：管理主体の切れ目（親子/別部門/外部委託）を“観測で”言えるようにする。
- 観測ポイント：
  - NS/SOA（権威の所在）、CNAME（委託先の痕跡）、TXT/CAA（運用痕跡）。
- 証跡（最小）：
~~~~
dig +noall +answer NS  <ROOT_DOMAIN> > 01_dns_ns.txt
dig +noall +answer SOA <ROOT_DOMAIN> > 01_dns_soa.txt
dig +noall +answer CNAME <SEED_HOST> > 01_dns_cname_seed.txt
dig +noall +answer TXT <ROOT_DOMAIN> > 01_dns_txt.txt
dig +noall +answer CAA <ROOT_DOMAIN> > 01_dns_caa.txt
~~~~
- 次の分岐（判断基準）：
  - NS/CNAME が明確に外部（CDN/ホスティング/委託）っぽい → Step 2Bへ（外部依存を優先）
  - すべて自社DNS/単一管理っぽい → Step 2Aへ（Web入口を優先）
  - 途中で分からない/情報不足 → Step 2Cへ（追加観測：TLS/HTTPで補強）

### Step 2A：自社運用寄り（Web入口を優先して確定）
- 目的：深掘りすべき入口（login/admin/api）を選び、次のplaybookへ渡す。
- 観測ポイント：
  - HTTPリダイレクト（SSO/IdPへ飛ぶか）、Set-Cookieの存在、API入口の痕跡。
- 証跡（最小）：
~~~~
curl -sS -I https://<SEED_HOST>/ > 02_http_head_root.txt
curl -sS -I -L https://<SEED_HOST>/login > 02_http_head_login_follow.txt
~~~~
- 次の分岐：
  - IdP/外部ドメインへリダイレクトする → `02_playbooks/03_authn_観測ポイント（SSO_MFA前提）.md`
  - 入口が管理UI/API中心に見える → `02_playbooks/02_web_recon_入口→境界→検証方針.md`

### Step 2B：外部依存寄り（CDN/WAF/SaaS/Storage を先に確定）
- 目的：責任境界（第三者が関与する地点）を列挙し、設定系の深掘りに繋げる。
- 観測ポイント：
  - TLS証明書のIssuer/SAN、HTTPヘッダのエッジ痕跡、CNAMEの委託先。
- 証跡（最小）：
~~~~
echo | openssl s_client -servername <SEED_HOST> -connect <SEED_HOST>:443 2>/dev/null | openssl x509 -noout -issuer -subject -ext subjectAltName > 02_tls_cert_seed.txt
curl -sS -I https://<SEED_HOST>/ | sed -n '1,40p' > 02_http_headers_seed.txt
~~~~
- 次の分岐：
  - WAF/ルール例外が勝負になりそう → `01_topics/01_asm-osint/12_waf-cdn_挙動観測（ブロック_チャレンジ_例外）.md`（topic）→ Web config playbookへ
  - Storage/共有が見える → `01_topics/01_asm-osint/18_storage_discovery（S3_GCS_AzureBlob）境界推定.md`（topic）→ SaaS/Configへ

### Step 2C：不明が多い（TLS/HTTPで補強して“状態”を作る）
- 目的：DNSだけで断定せず、代表点のTLS/HTTPで境界を補強する。
- 観測ポイント：Issuer/SAN、redirect収束、Set-Cookie、Server系ヘッダ。
- 次の分岐：
  - SSO/外部IdPが見える → `02_playbooks/03_authn_観測ポイント（SSO_MFA前提）.md`
  - API/管理UIが見える → `02_playbooks/02_web_recon_入口→境界→検証方針.md`

### Step 3：攻め筋の確定（優先度付け）
- 優先度の付け方（判断基準）：
  1) 権限境界が動く入口（SSO/管理UI/OAuth同意）
  2) 外部依存が強く設定で崩れやすい（CDN/WAF/Storage/共有）
  3) API比率が高い（UI≠APIのズレが出やすい）
- 次に深掘りするtopics（最大3つ）：
  - DNS境界：`01_topics/01_asm-osint/01_dns_委譲・境界・解釈.md`
  - HTTP外形：`01_topics/01_asm-osint/03_http_観測（ヘッダ・挙動）と意味.md`
  - Cloud露出：`01_topics/01_asm-osint/05_cloud_露出面（CDN_WAF_Storage等）推定.md`
- 次に回す検証（labs連動）：
  - 証跡（HAR/Proxy/メモ）：自分のテンプレに従う

## 取得する証跡（目的ベースで最小限）
- 何のため：境界（管理主体/外部依存/入口）を説明するため。
- 取得対象：NS/SOA/CNAME、代表点のTLS(issuer/SAN)、代表点のHTTPヘッダ/リダイレクト。
- 見るポイント：委譲先の変化、外部依存の痕跡、SSO入口の存在。

## コマンド/リクエスト例（例示は最小限）
~~~~
dig +noall +answer NS example.com
curl -I -L https://app.example.com/login
~~~~
- 何を観測する例か：DNS委譲（管理主体）とログイン入口のSSO有無。
- 出力の注目点：NSの管理主体、Locationの遷移先ドメイン。
- 前提が崩れるケース：社内限定DNS（Split-horizon）や、アクセス制限でHTTP観測できない場合。

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS：
  - 該当領域/章：V1（Architecture）、V2（AuthN前提）、V4（Access Control前提）、V10（Logging前提）
  - このプレイブックが支える管理策：対象/依存の確定（前提崩れ防止）
- WSTG：
  - 該当カテゴリ/テスト観点：Information Gathering / Configuration and Deployment Management
  - このプレイブックが支える前提：入口と外部依存の確定
- PTES：
  - 該当フェーズ：Intelligence Gathering → Threat Modeling
  - 前後フェーズとの繋がり：境界と入口が確定すると VA の優先度が決まる
- MITRE ATT&CK：
  - 該当戦術：Reconnaissance / Discovery
  - 攻撃者の意図：最小コストで入口と境界を確定し、次の攻め筋へ接続する

## 報告（ガイドライン程度：数行で）
- 事実：代表点3〜5の入口/外部依存/SSO有無。
- 成立条件：委譲・証明書・HTTP挙動の根拠（ファイル名で示す）。
- 影響：優先度（なぜそこを先に深掘るか）。
- 対策方向性：次に回すplaybookと追加観測。

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`01_topics/01_asm-osint/00_index.md`
- 関連 cases：`03_cases/00_index.md`
