# ネットワークスキャン

> **スコープ**: ターゲット IP に対する nmap での TCP/UDP ポートスキャン、サービス・バージョン検出、既知 CVE 一括チェック、ポート構成・IP レンジからの環境推定まで。発見した個別サービスの深掘り（Web / SMB / LDAP / SSH / TLS / SNMP 等）は各専用ファイルへ委譲。シェル取得後の侵入後列挙は `../03_Post_Access_Linux/Enumeration_Checklist.md`。

## 着火条件

調査の最初に必ず実施する。ターゲットの IP が判明した時点で開始。

## 環境前提

- 実行環境: テスター端末
- 必要なツール: `nmap`（ペネトレ用 Linux ディストリ標準搭載）/ `searchsploit`（同標準、Exploit-DB ローカル DB 検索）/ `rustscan`（高速ポート発見・`cargo install rustscan` または `apt install rustscan`）/ `masscan`（広域高速スキャン・`apt install masscan`、要 root）/ `udp-proto-scanner`（UDP 高速プロトコル検出・`git clone` で取得）
- 外部リソース依存: なし（searchsploit のローカル DB は `searchsploit -u` で事前更新、オフラインでも検索可能）

## 先に確認すること

- **テスター側の到達可能インターフェース**: `ip a` / `ip r` でルーティング経路を確認。VLAN・VPN・専用線・ジャンプサーバー越しなど環境による
- **対象 IP がスコープ内か**: 事前合意の対象範囲を確認、隣接 IP への意図しないスキャン拡散を避ける
- **スキャン速度の事前合意**: `--min-rate` 高設定は対象システムへの負荷・IDS 発火リスクが高い。本番では `--min-rate 1000` 以下 / `-T3` 等で抑えるのが無難

**攻撃者の思考トレース:** nmap は「軽く当てて → 全体を網羅して → 気になるところを深掘り」の三段階で使う。`-sC -sV` の初期スキャンは TCP 上位 1000 ポートのみで非標準高番ポートを見逃すので、`-p-` の全ポートスキャンを必ず並走させる。UDP も同様に低速だが SNMP / DNS / NTP のような UDP サービスを見逃すと後で詰む。発見したサービスは searchsploit で既知 CVE を当て、ポート構成と IP レンジから「相手はどんな環境か」を読み解いて次のフロー（Linux / AD / Web）に分岐する。

---

## 1. 初期スキャン（-sC -sV）

**コマンド:**

```bash
# [Attacker] 速度優先の初期スキャン（root 権限あり = SYN スキャン -sS が既定）
sudo nmap -sC -sV --reason -oA nmap_initial [TARGET_IP]
# -sC      : デフォルトスクリプト（バージョン検出・サービス情報の補強）
# -sV      : バージョン検出
# --reason : 各ポート状態の判定根拠（`syn-ack` / `reset` / `no-response` 等）を表示。filtered の原因切り分けに必須
# -oA      : 3 形式（.nmap / .gnmap / .xml）で保存。後で searchsploit に XML を流し込むため必須

# [Attacker] 非 root 環境では TCP connect スキャン（-sT）が既定
nmap -sT -sC -sV --reason -oA nmap_initial [TARGET_IP]

# [Attacker] -A は便利だがノイジー（-sC -sV -O --traceroute 相当）— 偵察初手で許容されるなら
sudo nmap -A --reason -oA nmap_aggressive [TARGET_IP]
```

**スキャン方式の選択（-sS vs -sT / 偵察初手で最も影響が大きい選択）:**

| 方式 | 権限 | 速度 | 検知性 | 何が起きるか | 使い分け |
|---|---|---|---|---|---|
| `-sS`（SYN ステルス）| **root 必須**（raw socket） | 速い（接続を完了させない）| **比較的低い**（接続ログに残らないことが多い）| SYN → SYN/ACK を受けたら RST で切断（3-way handshake を完成させない）| **既定の偵察初手**。root があれば常にこれ |
| `-sT`（TCP connect）| **root 不要**（OS の `connect()` 呼出）| 遅め | **高い**（接続が完了するためアプリ層ログ・接続テーブルに残る）| 通常の 3-way handshake を完了。アプリ側の `accept()` まで到達 | 非 root 環境 / SYN が IPS で弾かれて `filtered` 多発する場合の代替 |
| `-sA`（ACK スキャン）| root 必須 | 中 | 中 | ACK のみ送って RST 応答を見る。ステートフル FW の検出に使う | ポート開閉ではなく FW ルールの有無判定 |
| `-sU`（UDP）| root 必須 | **非常に遅い** | 中 | UDP に何か送って ICMP unreachable の有無で判定 | §4 で別途 |

> **`filtered` 多発時の切替判断:** `--reason` 出力で `no-response` が多ければ FW でドロップ → `-sT` への切替で `connection refused` / `connection timed out` 区別が付くようになることがある。SYN だけ落とす ACL を組んでいる FW は `-sT` で抜けられる場合がある。

> **`-A` の扱い:** `-A` は `-sC -sV -O --traceroute` のフルセットで、**OS 推定パケット（特殊な TCP/IP フラグ組み合わせ）と traceroute が混じる**ため検知性は跳ね上がる。本番初手では避け、特定ホストの追加調査で個別に使う。

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `22/tcp open ssh` | SSH | `../02_Initial_Access/SSH.md` |
| `80/tcp open http` / `443/tcp open ssl/http` | Web | `./Web_Enumeration.md` |
| `443` / `8443` / `993` / `995` / `465` 等 TLS ポート | TLS | `./TLS_Audit.md` |
| `445/tcp open microsoft-ds` / `139/tcp open netbios-ssn` | SMB | `./SMB_Enumeration.md` |
| `389/tcp open ldap` / `636/tcp open ldaps` | LDAP | `./LDAP_Enumeration.md` |
| `2049/tcp open nfs` | NFS（共有が直接マウントできる可能性） | `showmount -e [TARGET_IP]` |
| `1433` が外に出ている | MSSQL 外部露出 | `../02_Initial_Access/MSSQL_Exploitation.md` |
| `3306` が外に出ている | MySQL / MariaDB 外部露出（誤公開の可能性） | `../02_Initial_Access/MySQL_Exploitation.md` |
| `5432` が外に出ている | PostgreSQL 外部露出（`listen_addresses = '*'` の設定不備シグナル） | `../02_Initial_Access/PostgreSQL_Exploitation.md` |
| `8080` / `8443` / `8888` 等の非標準 HTTP | 開発用管理パネル / API | まず `/` にアクセスしてフレームワーク・バージョンを特定 |
| `-sC` の HTTP スクリプト出力に `Location: http://[DOMAIN]/` やホスト名らしき文字列 | vhost ベースの Web アプリ（IP 直打ちでは 302 リダイレクトや別画面）| **`/etc/hosts` に `[TARGET_IP] [DOMAIN]` を追記してから**ブラウザ・curl でアクセス → `../06_Concepts/Hosts_File_For_AD.md` |
| ポートセットが偏っている（例: 22+80 のみ / 88+389+445+5985 揃い）| 環境タイプの推定材料 | §6 ポート構成 / IP レンジからの環境推定へ |
| `filtered` が大量 | ファイアウォール / IDS の可能性 | 「刺さらなかったとき」へ |

**注意:** `-sC -sV` は **TCP 上位 1000 ポートのみ**スキャンする。非標準高番ポート（10000 超など）の管理画面・開発版アプリを見逃すため、§2 の全ポートスキャンを必ず並走させる。

---

## 2. 全ポートスキャン（-p-）

**コマンド:**

```bash
# [Attacker] 全 65535 ポートを高速スキャン
sudo nmap -p- --min-rate 5000 --reason -oA nmap_allports [TARGET_IP]
# -p-             : 全 65535 ポート
# --min-rate 5000 : スキャン速度を上げる（本番では事前合意による）
# --reason        : 各判定の根拠を残す（後解析の精度が上がる）
```

**RustScan / Masscan → nmap パイプライン（時間制約のある実案件向け）:**

`nmap -p-` は `--min-rate` を上げても全ポート完了に分単位かかる。**先に RustScan / Masscan で open ポートだけ秒〜数十秒で特定し、そのポート群を nmap に渡す**のが現代の定石。

```bash
# [Attacker] RustScan — Rust 実装で 65535 ポートを数秒〜数十秒で特定。後段に nmap を自動連携
rustscan -a [TARGET_IP] --ulimit 5000 -- -sC -sV --reason -oA nmap_via_rust
# `--` 以降は内部で起動される nmap への引数

# [Attacker] Masscan — さらに高速だが認識精度は低い。サブネット全体に有効
sudo masscan -p1-65535 [TARGET_IP] --rate 10000 -oG masscan.gnmap
# 検出したポート群を nmap で精査
ports=$(grep -oE 'Ports: [0-9,]+' masscan.gnmap | grep -oE '[0-9]+' | sort -un | paste -sd,)
sudo nmap -sC -sV --reason -p $ports -oA nmap_via_masscan [TARGET_IP]
```

> **使い分け:** 単一ホストなら **`rustscan` が手数最小**（nmap 連携が内蔵）。**`/24` 以上の広域**なら `masscan` で開ポート全体マップを作ってから nmap で精査。`nmap -p-` 直走は単純ホストかつ時間制約が緩いケースに限定。

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| §1 で見えなかった非標準高番ポート（例: `10250` / `15672` / `31337` 等）| 隠しサービス / 開発版アプリ / 管理パネル | §3 で当該ポートに `-sC -sV` を個別実行 |
| §1 とほぼ同じ結果 | 開いているのは標準ポートのみ | §3-§4 をスキップして §5 searchsploit へ |
| 全ポート `filtered` | FW / IDS でスキャン全体がブロック | 「刺さらなかったとき」へ |
| 接続が途中で切られる | IPS のレート制限発動 | `--min-rate` を下げる（1000 以下）、`--scan-delay 1s` で間欠化 |

**注意:** `--min-rate 5000` は対象システムに負荷をかけ、IDS の異常トラフィックシグネチャを発動させやすい。本番では事前合意のうえ、抑えた値（`--min-rate 1000` 以下）または `-T3` などのタイミングテンプレートを使う。

---

## 3. 追加スクリプトスキャン（気になるポートに対して）

**コマンド:**

```bash
# [Attacker] §2 で発見した高番ポート等に絞って -sC -sV
nmap -sC -sV -p [PORT1],[PORT2] -oA nmap_targeted [TARGET_IP]

# [Attacker] OS 推定も併用したい場合（要 root）
sudo nmap -sC -sV -O -p [PORT1],[PORT2] -oA nmap_targeted_os [TARGET_IP]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| サービス名・バージョン特定 | 既知 CVE 検索の材料が揃った | §5 searchsploit へ |
| バナーから OS / ディストリ判明 | Linux / Windows / FreeBSD 等 | `../00_Playbook/00_OS_Identification.md` |
| HTTP / HTTPS | Web 列挙へ | `./Web_Enumeration.md` / `./TLS_Audit.md` |
| 不明サービスがバナー応答 | カスタム実装 | `nc [TARGET_IP] [PORT]` で手動接続して観察 |
| `-O` で `Too many fingerprints match` | TCP/IP スタックが特殊で照合失敗 | HTTPヘッダー / SMBバナー / SSHバナーから推定 → `../00_Playbook/00_OS_Identification.md` |

---

## 4. UDP スキャン

**コマンド:**

```bash
# [Attacker] UDP top 50 ポート（要 root）
sudo nmap -sU --top-ports 50 --open -oA nmap_udp [TARGET_IP]
# SNMP / DNS / NTP / TFTP / IKE 等の発見に必要
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `161/udp open\|filtered snmp` | SNMP（Community String 総当たりが効く可能性）| `./SNMP_Enumeration.md`（onesixtyone / snmpwalk で `public` `private` 等試行）|
| `53/udp open domain` | DNS（ゾーン転送・サブドメイン列挙の起点）| `./DNS_Enumeration.md` |
| `123/udp open ntp` | NTP（情報漏洩 / amplification）| `nmap -sU -sV -p 123 --script ntp-info` |
| `69/udp open tftp` | TFTP（設定ファイル取得の可能性）| `tftp [TARGET_IP]` で接続試行 |
| `500/udp open isakmp` | IPSec VPN | `ike-scan [TARGET_IP]` で詳細取得 |
| 何も返らない | ほとんどの UDP サービスは応答しない仕様 | 特定ポートに対して `nmap -sU -sV -p [PORT]` を個別実施 |

**注意:** UDP スキャンは**TCP の数倍〜数十倍遅い**。`--top-ports 50 --open` で時間と出力を絞る。全ポートスキャンを UDP で実施するのは現実的でないため、ターゲット環境で重要そうな UDP ポートを当たる方針を取る。

**UDP スキャンの高速化（時間制約のある実案件向け）:**

```bash
# [Attacker] udp-proto-scanner — 多数の UDP プロトコル別プローブを並列送信。nmap より圧倒的に速い
# https://github.com/portcullislabs/udp-proto-scanner
udp-proto-scanner.pl [TARGET_IP]
udp-proto-scanner.pl -f targets.txt   # サブネット一括

# [Attacker] unicornscan の UDP モード（Kali 標準にあれば）
unicornscan -mU -v [TARGET_IP]:1-65535
```

> **使い分け:** `nmap -sU` は OS / バージョン推定の質が高いが遅い。**先に `udp-proto-scanner` で「何が応答するか」を高速確認**してから、応答ポートに `nmap -sU -sV -p [PORT]` を当てるのが効率的。

---

## 5. searchsploit --nmap で既知 CVE 一括確認

**コマンド:**

```bash
# [Attacker] 初期スキャン結果から既知エクスプロイト一括検索
searchsploit --nmap nmap_initial.xml

# [Attacker] 全ポートスキャン結果も確認
searchsploit --nmap nmap_allports.xml
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| Remote 系（RCE / Remote File Inclusion 等）がヒット | シェル取得前の最優先候補 | バージョン一致を NVD で確認 → PoC 取得 |
| Local 系（LPE / Privilege Escalation）がヒット | シェル取得後の権限昇格候補 | 一旦記録、シェル取得後に `../03_Post_Access_Linux/` で参照 |
| `DoS` / `Denial of Service` のタイトル | 業務影響 | 本番ではスキップ（演習環境のみ検討） |
| 大量ヒット | サービス × バージョン組合せが多い | `../05_Tools_Reference/Searchsploit.md`（複数候補からの絞り込み基準） |
| ヒットなし | 既知 CVE 該当なし | Exploit-DB Web / NVD / GitHub PoC で再検索 → `../05_Tools_Reference/Searchsploit.md` |

**注意:** searchsploit はバージョン文字列の部分一致でヒットを返すため、**ヒット = 該当ではない**。NVD で対象バージョンの affected range を必ず確認する。

---

## 6. ポート構成 / IP レンジからの環境推定（判断ブロック）

§1-§4 のスキャン結果を読み解き、対象環境のタイプを推定して次のフローに分岐する。コマンドではなく**判断軸**を扱う。

**ポートセットからの環境推定:**

| 観測されるポートセット | 推測される環境 | 次のフロー |
|---|---|---|
| `21` / `22` / `80` の最小構成 | Linux + Web の典型 | `../00_Playbook/Linux_Attack_Flow.md` |
| `53` / `88` / `389` / `445` / `5985`（複数揃う）| Windows AD ドメインコントローラー | `../00_Playbook/Windows_AD_Attack_Flow.md` |
| `88` / `389` / `3268` / `5985` の組合せ | AD DC（Global Catalog あり） | 同上 |
| `8080` / `8443` / `8888` 等の非標準 HTTP | 開発環境・管理パネル | `./Web_Enumeration.md` でフレームワーク・バージョン特定 |
| `1433` 単独 | MSSQL（外部公開）| `../02_Initial_Access/MSSQL_Exploitation.md` |
| `3306` 単独 | MySQL（外部公開）| デフォルト認証情報 → `../02_Initial_Access/Default_Credentials.md` |
| `2049` | NFS（マウント可能な共有）| `showmount -e [TARGET_IP]` |
| `11211` | Memcached（無認証読み取りの可能性）| `memcached-cli` / `stats items` |

**IP レンジからの環境推定:**

| 観測される IP レンジ | 推測される環境 | 次のアクション |
|---|---|---|
| ターゲット IP が `172.17.0.x` | Docker デフォルトブリッジネットワーク。**ホスト自体がコンテナ**の可能性 | コンテナブレイクアウト経路を視野 → `../03_Post_Access_Linux/Enumeration_Checklist.md`（Docker 確認）|
| パストラバーサル等で取得した `/etc/hosts` に `172.17.0.x` | Web アプリが**コンテナ内で動作** | コンテナ ID（ホスト名のランダム 16 進文字列）を記録、`docker exec` 経路を視野 → `../03_Post_Access_Linux/Sudo_Misconfig.md`（パターン 4） |
| `10.x.x.x` | 社内 LAN / VPN / Kubernetes Pod ネットワーク等 | 文脈から判断（VPN クライアントなら 10.x が普通、本番 LAN でも 10.x はあり得る）|
| `192.168.x.x` | ローカルネットワーク | ホームルーター環境・小規模 LAN 等 |

**注意:** 環境推定は**仮説**。スキャンとフローを進める中で常に更新する。例えば「DC と判断したが LDAP に anonymous bind できる → スタンドアロン Win Server だった」のような訂正は普通に起きる。

---

## 刺さらなかったとき（全体）

| 観測される症状 | 推定原因 | 代替手段 |
|---|---|---|
| 全ポートが `filtered` で返る | ファイアウォール / IDS / IPS が SYN スキャンをブロック | `--reason` で `no-response` / `admin-prohibited` 等を確認 → SYN-only な ACL なら `-sT`（TCP connect）に切替 / `--source-port 53` で送信元ポート偽装 / `-T2` でスキャン速度低下 / フラグ化（`--scanflags FIN,PSH,URG` 等で stealth スキャン） |
| ping が通らずスキャンが開始されない | ICMP がブロックされている | `-Pn` でホスト発見をスキップ |
| `-sV` でバージョン情報が取れない | サービスがバナーを返さない / カスタム実装 | `--version-intensity 9` で強化、応答が出ない場合は手動接続（`nc [TARGET_IP] [PORT]` / `curl http://[TARGET_IP]:[PORT]/`）でレスポンス確認 |
| `-O` で OS が `Too many fingerprints` | TCP/IP スタックが特殊で照合失敗 | HTTP ヘッダー / SMB バナー / SSH バナーから推定 → `../00_Playbook/00_OS_Identification.md` |
| 全ポート閉じているように見える | テスター側の到達経路に問題 | `ip a` で到達可能インターフェース確認、`ip r` でルーティングテーブル確認、必要なら別経路から再試行 |
| UDP スキャンが何も返さない | ほとんどの UDP サービスは応答しない仕様 | `--top-ports 50 --open` で絞る、SNMP（161）/ DNS（53）/ NTP（123）等の特定ポートに対して `nmap -sU -sV` を個別実施 |
| `--min-rate` 高設定で IPS 発火 → 以降 IP ブロック | レート制限・パターン検知 | スキャン元 IP を変更、`-T2` / `--scan-delay 1s` で間欠スキャンに切替 |

## 注意点・落とし穴

- **全ポートスキャンを省略すると非標準ポートの重要なサービスを見逃す**（管理画面・開発版アプリ・後付け運用ツール等）。`-p-` は時間がかかっても並走させる
- **UDP スキャン（`-sU`）は低速だが SNMP（161）・DNS（53）・NTP（123）の確認に必要**な場合がある。SNMP の Community String が `public` のまま放置されていると内部情報が一括取得できる
- **`filtered` は「閉じている」ではない**。FW でドロップされている状態。`-sT` / `--source-port 53` で迂回できることがある
- **出力ファイルは `-oA` で必ず保存**しておく。後から searchsploit / 別解析・報告書作成で再参照できる
- **個別ブロック固有の注意は各 §N ブロック内の「注意:」を参照。** 本セクションは複数ブロック横断の話のみを置く

### 本番での前提

- **事前合意の要否**: ★（§1 / §3 / §5 / §6 は技術的判断のみで実施可。§2 全ポートスキャン + `--min-rate 5000` / §4 UDP スキャンは負荷・IDS 発火リスクで事前合意の速度設定を確認）
- **想定される SIEM / EDR 検知**: IDS の SYN スキャンシグネチャ、`--min-rate` 高設定の異常トラフィック警報、UDP スキャンの大量応答待ち、`-sC` の各種スクリプトシグネチャ
- **業務影響リスク**: `--min-rate 5000` で対象システム高負荷の可能性、IPS による IP ブロックで以降の調査用 IP が遮断される
- **原状回復必須項目**: ✅ なし（読み取り専用。対象側には変更を加えない）/ ✅ スキャン結果ファイル（`-oA` 出力）は暗号化保管、テスト完了時破棄
- **取得情報の取扱**: 内部 FQDN / バージョン情報 / ネットワーク構成は機微情報として扱う
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

## 関連技術

- 前：テスト開始（IP 渡し）/ OS 判定 → `../00_Playbook/00_OS_Identification.md`
- 後：HTTP / HTTPS ポート発見後の Web フィンガープリント → `./Web_Enumeration.md`
- 後：TLS ポート発見後のプロトコル/暗号/証明書監査 → `./TLS_Audit.md`
- 後：445 / 139 発見後の SMB 列挙 → `./SMB_Enumeration.md`
- 後：22 ポート発見後の SSH 列挙〜認証突破〜制限シェル脱出 → `../02_Initial_Access/SSH.md`
- 後：389 / 636 発見後の LDAP 列挙 → `./LDAP_Enumeration.md`
- 後：UDP 161 発見後の SNMP 列挙・内部ネットワーク観点 → `./SNMP_Enumeration.md`
- 後：53 発見後の DNS 列挙・ゾーン転送 → `./DNS_Enumeration.md`
- 後：Web ポート発見後の誤公開ファイル探索 → `./Exposed_Files.md`
- 後：検出サービス × バージョンの既知 CVE 一括確認 → `../05_Tools_Reference/Searchsploit.md`
- 後（ポートパターンからフロー判断）：Linux 環境 → `../00_Playbook/Linux_Attack_Flow.md`
- 後（ポートパターンからフロー判断）：Windows AD 環境 → `../00_Playbook/Windows_AD_Attack_Flow.md`
- 後（シェル取得後）：Linux 侵入後の列挙 → `../03_Post_Access_Linux/Enumeration_Checklist.md`
- 後（IP レンジが `172.17.0.x`）：コンテナ環境判明時の権限昇格 → `../03_Post_Access_Linux/Sudo_Misconfig.md`
