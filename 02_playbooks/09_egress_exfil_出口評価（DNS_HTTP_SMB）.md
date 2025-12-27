# 09_egress_exfil_出口評価（DNS_HTTP_SMB）
“データ持ち出し” ではなく、出口（DNS/HTTP(S)/SMB）の成立条件（到達性・監視・制限）を観測で確定し、封じ方/優先度を分岐で決める。

## 目的（このプレイブックで到達する状態）
- DNS/HTTP(S)/SMB の出口について、**成立するか（Yes/No/Unknown）** と根拠を説明できる。
- もし成立するなら「どの制御（proxy/DNS/認証/監視/遮断）が効いているか」を状態で言える。
- 次に読むtopic（持ち出し経路/監視/設計）と、次に回す検証（範囲内での最小確認）を分岐で選べる。

## 前提知識チェックリスト（先に確認）
- 出口：DNS/HTTP/SMB のどこが通るか
- 監視：どのログが見えるか
- 制約：第三者宛通信の可否

## 前提（対象・範囲・制約）
- 対象：許可範囲の環境（クライアント/サーバ/ネットワーク）における出口。
- 制約：外部宛の能動通信は必ずスコープ確認（第三者宛通信の可否）。未確認なら “設定/ログ/到達性の推定” で進める。
- 前提ツール（最小限）：OS標準（DNS/HTTP疎通、ログ閲覧）、（任意）Proxy設定確認、（任意）pcap。
  - 理由：設定/ログでYes/No/Unknownが作れる。
  - 代替：EDR/FirewallのUIでも可。
- 参照すべきtopics：
  - `01_topics/03_network/28_exfiltration_持ち出し経路（DNS_HTTP_SMB）.md`

## 入口で確定すること（最小セット）
- 現在地点：どのホスト/ネットワークから評価するか（例：端末/踏み台/サーバ）。
- 許可範囲：外部宛通信が可能か（Yes/No/Unknown）。Unknown の場合は能動試験はしない。
- 証跡：DNSログ/Proxyログ/Firewallログ/EDRのいずれが見られるか。
- 完了条件：DNS/HTTP/SMB の出口を Yes/No/Unknown で埋める。

## 所要時間の目安
- 全体：25〜35分

## 具体的に実施する方法（最小セット）
### 0) 証跡ディレクトリ（`egress_09`）
~~~~
# Windows (PowerShell)
$dir = Join-Path $HOME "keda_evidence\\egress_09"
New-Item -ItemType Directory -Force $dir | Out-Null
Set-Location $dir
"env: ...`nnotes: ..." | Set-Content -Encoding utf8 00_context.txt
~~~~

### 1) 出口は「設定→ログ→差分」で確定する
- 設定：egress許可/denyのルール（FW/Proxy/SG）をスクショ or エクスポートして `01_egress_rules.*` に保存
- ログ：許可/拒否のイベントを `02_egress_logs.txt` に保存（時刻窓と相関キーを併記）
- 差分：DNS/HTTP/SMB それぞれ「通る/遮断」の根拠を `03_matrix.md` にまとめる

## 手順（分岐中心：迷うポイントだけ）

### Step 0：最初の5分（必ずやる / 目安: 5分）
- 目的：事故（第三者宛通信）を避けつつ、評価の枠を固定する。
- 観測ポイント：
  - 外部宛の能動通信が許可されるか（未確認なら “しない” に倒す）。
  - 監視点（DNS/Proxy/Firewall/EDR）がどこにあるか（見えるログを先に確認）。
- 証跡（最小）：
~~~~
# Windows (PowerShell)

$dir = Join-Path $HOME "keda_evidence\\egress_09"
New-Item -ItemType Directory -Force $dir | Out-Null
Set-Location $dir
"host: ...`nactive_external_allowed: Yes/No/Unknown`nlog_sources: ..." | Set-Content -Encoding utf8 00_context.txt

# macOS/Linux (bash)

mkdir -p ~/keda_evidence/egress_09
cd ~/keda_evidence/egress_09
printf "host: ...\nactive_external_allowed: Yes/No/Unknown\nlog_sources: ...\n" > 00_context.txt
~~~~
- 次の分岐：
  - 許可範囲とログが整理できた → Step 1へ
- 実際の観測例：
  - `active_external_allowed: Unknown` と明記

### Step 1：DNS出口（解決経路と監視）を確定する（目安: 8分）
- 目的：DNSが “外へ出る” 経路があるか、どこで制御されるかを確定する。
- 観測ポイント：
  - クライアントのDNS設定（どのリゾルバへ投げているか）
  - 内部リゾルバの再帰/フォワード（外部へ出るか）
  - DNSログが残るか（誰が何を引いたか）
- 次の分岐（判断基準）：
  - 外部へ再帰しない/内部限定 → DNS出口は No 寄り（HTTPへ）
  - 外部へ再帰するが監視が強い → DNS出口は Yes（監視付き）
  - 不明（ログ/設定が見えない） → Unknown（HTTP/SMBも同様に状態化）
- 実際の観測例：
  - DNSサーバが `10.x.x.x` のみ → 内部限定の可能性

### Step 2：HTTP(S)出口（proxy/直/認証/検査）を確定する（目安: 8分）
- 目的：HTTP(S)の出口が、直通なのか proxy 経由なのか、認証や検査があるかを確定する。
- 観測ポイント：
  - Proxy設定（PAC/明示proxy/透過proxy）と認証の有無
  - TLSインターセプト（社内CAで復号される兆候）
  - ログ（URL/宛先/ユーザー/端末）が残るか
- 次の分岐（判断基準）：
  - 直通で外へ出られる → HTTP出口は Yes（制限薄い）
  - proxy必須/認証必須/復号あり → HTTP出口は Yes（制御付き）
  - 外へ出られない → HTTP出口は No
- 実際の観測例：
  - PACが必須でプロキシ認証が入る

### Step 3：SMB出口（到達性/遮断/認証）を確定する（目安: 6分）
- 目的：SMB（445）が外へ出るか/内部だけか、遮断/監視があるかを確定する。
- 観測ポイント：
  - outbound 445 の遮断有無（ネットワーク/EDR/FW）
  - SMB共有の内部到達性（内部で成立するなら “内部持ち出し” の議論に繋がる）
- 次の分岐（判断基準）：
  - 外部445が遮断 → SMB出口は No（内部共有の監査へ）
  - 内部共有が広く、監査が弱い → 共有境界（SaaS/ファイル共有）も含めて優先度上げ
- 実際の観測例：
  - `Test-NetConnection` が 445 で失敗

### Step 4：攻め筋の確定（封じ方/優先度 / 目安: 5分）
- 優先度の付け方：
  1) “制限なしの直通” が残る経路（HTTP直通、DNS直通等）
  2) 監視はあるが “相関できない/保存が短い” 経路（追跡不能）
  3) 内部共有で横展開的に集約できる経路（ファイル共有/共有ドライブ等）
- 次の一手：
  - 設定/運用の封じ方へ：`02_playbooks/10_web_config_ops_設定・運用境界_初動.md`（proxy/ログ/ヘッダ/秘密の運用）
  - 技術詳細へ：`01_topics/03_network/28_exfiltration_持ち出し経路（DNS_HTTP_SMB）.md`
- 実際の観測例：
  - 直通HTTPが残る → Configへ接続

## Unknown時の代替手段（能動試験なし）
- DNS: リゾルバ設定/フォワーダ設定/監査ログで推定
- HTTP: プロキシ設定/PAC/ブラウザポリシーで推定
- SMB: FW/EDRのルールとログで推定

## よくある失敗と対処法
- 外部疎通を先に試す → 許可確認が先
- ログが取れない → 設定/ポリシーのスクショで代替
- Unknownを空欄にする → Unknownの根拠を書く

## バグバウンティでの注意点
- 第三者宛通信は原則禁止。許可が取れないなら能動試験しない
- PoCは「成立条件の説明」に止める
- 監査ログの取得可否はレポートに明記
## 取得する証跡（目的ベースで最小限）
- 何のため：出口の成立条件（到達性/制御/監視）を説明するため。
- 取得対象：DNS設定/Proxy設定の根拠、ログのサンプル（数件）、遮断ルールの根拠（あるなら）。
- 見るポイント：出口の経路、認証/復号/フィルタの有無、監査ログの相関キーと保持期間。

## コマンド例（例示は最小限）
~~~~
# DNS設定（例）

ipconfig /all

# HTTP(S)の挙動（例：proxyの有無は環境依存）

curl -sS -I https://example.com/ | sed -n '1,20p'

# SMB到達性（例：Windows）

Test-NetConnection -ComputerName <HOST> -Port 445
~~~~
- 何を観測する例か：DNS/HTTP/SMB の “出口の成立” の手掛かり。
- 出力の注目点：DNSサーバ、HTTPの疎通とproxy由来ヘッダ、445の疎通可否。
- 前提が崩れるケース：外部疎通が許可されていない（その場合は設定/ログの観測で Yes/No/Unknown 化する）。

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS：
  - 直接項目ではないが、ログ/監視（V10）と秘密情報管理（V7）の前提として、持ち出し経路の成立条件を確定する。
- WSTG：
  - 情報収集/設定管理の観点から、出口制御（proxy/DNS/共有）を評価し、検証前提を固める。
- PTES：
  - Post-Exploitation のリスク（持ち出し/追跡不能）を、観測と分岐で評価する。
- MITRE ATT&CK：
  - Exfiltration / Command and Control を、出口成立条件（到達性・制御・監視）として説明する補助に使う。

## 報告（ガイドライン程度：数行で）
- 事実：DNS/HTTP/SMB の出口が Yes/No/Unknown と根拠。
- 成立条件：どの制御（proxy/DNS/遮断/監視）が効いているか。
- 影響：持ち出し成立/追跡可能性（推定は推定と明記）。
- 対策方向性：直通排除、proxy強制、DNS制御、共有監査、ログ相関/保存の強化。

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`01_topics/03_network/28_exfiltration_持ち出し経路（DNS_HTTP_SMB）.md`
- 関連 playbooks：`02_playbooks/06_network_enum_to_post_列挙→侵入後の導線.md`
- 関連 playbooks：`02_playbooks/10_web_config_ops_設定・運用境界_初動.md`
