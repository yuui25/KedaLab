# SNMP 列挙（内部ネットワーク観点）

> **[HIGH IMPACT]** 書き込み可能なコミュニティ文字列を使ったネットワーク機器の設定変更は不可逆な変更を含む：
> - [ ] 業務停止リスク（サービス・認証）
> - [ ] 持続化に該当
> - [x] 不可逆な設定変更を含む（ルーター・スイッチ等のネットワーク設定変更）
> - [ ] SIEM/EDR で確実に検知される
>
> 情報読み取り（Read-Only コミュニティ文字列）は上記に該当しない。設定変更（Write）は事前合意で明示確認すること。演習環境（HTB / OSCP 等）では制約なし。

## 着火条件
- ポートスキャンで **UDP 161**（SNMP エージェント）が開いているホストが存在する
- 内部ネットワークにルーター・スイッチ・プリンター・UPS・ネットワーク対応機器が存在する
- スコープにネットワーク機器・IoT デバイスが含まれる内部 VLAN ペネトレテストである

> **nmap のデフォルトスキャンでは UDP 161 は検出されない。** SNMP は UDP のみで動作するため、`-sU -p 161` を明示的に指定しないと見落とす。内部ネットワークで「ネットワーク機器がある」と判断したら必ず UDP スキャンを追加する。

## 環境前提
- 実行環境: テスター端末
- 必要なツール:
  - `onesixtyone`（コミュニティ文字列ブルートフォース。ペネトレ用Linuxディストリ標準搭載）
  - `snmpwalk`（MIB ツリー再帰取得。net-snmp パッケージ、ペネトレ用Linuxディストリ標準搭載）
  - `snmpget`（単一 OID 取得。net-snmp パッケージ、標準搭載）
  - `snmp-check`（整形出力での情報取得。ペネトレ用Linuxディストリ標準搭載）
- オフライン代替: `nmap --script snmp-brute,snmp-info`（nmap 標準スクリプト）、`python3-pysnmp`（`pip install pysnmp --break-system-packages`）

---

## 観点・着眼点

**SNMP とは何か（内部 LAN テストにおける位置づけ）：**
Simple Network Management Protocol（シンプルネットワーク管理プロトコル）。ネットワーク機器・サーバーの死活監視・設定管理に使われるプロトコル。コミュニティ文字列（SNMPv1/v2c における認証の代わりのパスフレーズ）がデフォルト値（`public` / `private`）のままで放置されている機器が内部ネットワークに存在することが多く、認証なしで大量の内部情報を取得できる。

**攻撃者の思考トレース：** SNMP は「監視のために有効化されたまま忘れられている」サービスの代表格。TCP スキャン結果にしか目がいかないと完全に見落とす。内部ネットワークでは UDP 161 のスキャンを TCP スキャンと並行して必ず実施する。

**SNMP から得られる情報の攻撃的価値：**

| 取得できる情報 | 次のアクションへの繋がり |
|---|---|
| ホスト名・OS バージョン・稼働時間 | 次のスキャン対象の優先付け・CVE 検索の精度向上 |
| インターフェース一覧・IP アドレス | スコープ外 IP・到達可能なサブネットの発見（未発見ホストの特定） |
| ARP テーブル | 直接通信している IP リスト → nmap スキャン対象の補完 |
| ルーティングテーブル | 内部ネットワークトポロジーの把握・踏み台ルートの特定 |
| 実行中プロセス一覧 | EDR / AV の種類確認・MSSQL / IIS 等のサービス稼働確認 |
| インストール済みソフトウェア | バージョン特定 → CVE 検索・searchsploit |
| Windows ユーザーアカウント | パスワードスプレー候補リストの補完 |
| TCP 接続一覧 | 現在アクティブな接続先 IP・内部サービスポートの把握 |

**先に確認すること：**

- `nmap -sU -p 161 [IP_RANGE]` で UDP 161 が開いているホストを特定してから着手する
- SNMP Bulk Walk は UDP パケットを大量送信するため、ネットワーク過負荷に注意する（速度調整が必要な場合は `snmpwalk` の `-r` / `-t` オプションで調整）

---

## 手順

## Step 1 — UDP 161 の存在確認

```bash
# [Attacker] 対象レンジ全体を UDP 161 でスキャン（--open で開いているものだけ表示）
sudo nmap -sU -p 161 [IP_RANGE] --open -oG snmp_hosts.txt

# [Attacker] 開いているホストの IP のみ抽出
grep "/open/" snmp_hosts.txt | awk '{print $2}' | tee snmp_targets.txt
```

## Step 2 — コミュニティ文字列のブルートフォース（onesixtyone）

`onesixtyone`（SNMP コミュニティ文字列ブルートフォースツール。ペネトレ用Linuxディストリ標準搭載）

```bash
# [Attacker] まずデフォルト値だけ手動で試す（最速確認）
onesixtyone [TARGET_IP] public
onesixtyone [TARGET_IP] private

# [Attacker] 単一ホストにワードリストで試す
onesixtyone [TARGET_IP] -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt

# [Attacker] 複数ホストに一括で試す
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt \
  -i snmp_targets.txt
```

`onesixtyone` の出力例：
```
192.0.2.10 [public] Linux [HOSTNAME] 5.4.0 #1 SMP
```
コミュニティ文字列が通った場合、ホスト名・OS 情報が右側に表示される。

> SecLists は `apt install seclists`（ペネトレ用Linuxディストリ標準）でインストール。
> オフライン環境では自作リストとして最低限 `public`・`private`・`community`・`snmp`・`[組織名]` を試す。
> コミュニティ文字列は**大文字小文字を区別する**（`Public` と `public` は別物）。

## Step 3 — snmpwalk による MIB 全取得

`snmpwalk`（SNMP MIB ツリーを再帰的に取得するツール。net-snmp パッケージ、ペネトレ用Linuxディストリ標準搭載）

```bash
# [Attacker] OID ルートからツリー全体を取得（v2c）
snmpwalk -v 2c -c [COMMUNITY_STRING] [TARGET_IP]

# [Attacker] v1 を使う場合
snmpwalk -v 1 -c [COMMUNITY_STRING] [TARGET_IP]

# [Attacker] 整形出力で一覧確認したい場合（snmp-check）
snmp-check [TARGET_IP] -c [COMMUNITY_STRING]
```

> `snmpwalk` の全量取得は出力が数千行になる。まず `snmp-check` で整形出力を確認し、目当ての情報を OID 指定で絞り込むのが効率的。

## Step 4 — OID を指定した情報の抽出

**OID 1.3.6.1 系（RFC 1213 / MIB-II）の主要な読み方：**

| OID | 取得できる情報 | 攻撃的価値 |
|---|---|---|
| `1.3.6.1.2.1.1` | システム情報（ホスト名・OS・稼働時間・連絡先） | OS バージョン特定・CVE 検索 |
| `1.3.6.1.2.1.2` | インターフェース一覧（名前・MAC・速度） | ネットワーク構成の把握 |
| `1.3.6.1.2.1.4.20` | IP アドレス一覧 | 複数 IP を持つホストの特定 |
| `1.3.6.1.2.1.4.21` | ルーティングテーブル | 到達可能なサブネット・踏み台ルート |
| `1.3.6.1.2.1.4.22` | ARP テーブル | 直接通信しているホストの IP リスト |
| `1.3.6.1.2.1.6.13` | TCP 接続一覧（接続先 IP・ポート） | アクティブな接続先・内部サービスポート |
| `1.3.6.1.2.1.25.4.2` | 実行中プロセス一覧 | EDR / AV・MSSQL / IIS 等の稼働確認 |
| `1.3.6.1.2.1.25.6.3` | インストール済みソフトウェア（Windows） | バージョン特定 → CVE 検索 |
| `1.3.6.1.4.1.77.1.2.25` | Windows ユーザーアカウント（Windows 専用） | スプレー候補リストの補完 |

```bash
# [Attacker] OID を指定して特定情報のみ取得
snmpwalk -v 2c -c [COMMUNITY_STRING] [TARGET_IP] 1.3.6.1.2.1.4.22   # ARP テーブル
snmpwalk -v 2c -c [COMMUNITY_STRING] [TARGET_IP] 1.3.6.1.2.1.4.21   # ルーティングテーブル
snmpwalk -v 2c -c [COMMUNITY_STRING] [TARGET_IP] 1.3.6.1.2.1.25.4.2 # 実行中プロセス
snmpwalk -v 2c -c [COMMUNITY_STRING] [TARGET_IP] 1.3.6.1.2.1.25.6.3 # インストール済みソフト
snmpwalk -v 2c -c [COMMUNITY_STRING] [TARGET_IP] 1.3.6.1.4.1.77.1.2.25 # Windows ユーザー
```

## Step 5 — 取得情報から次の行動を判断する

```
[インターフェース / ARP テーブル / ルーティングテーブル]
         ↓
  未発見サブネット・ホストの特定
         ↓
  nmap -sn [新サブネット] でホスト発見 → スキャン対象に追加

[実行中プロセス]
         ↓
  EDR / AV（Windows Defender / CrowdStrike / Carbon Black 等）の稼働確認
  → 存在する場合は横展開での回避を意識する
         ↓
  SQL Server / IIS / Apache / Tomcat の稼働確認
  → 1433 / 80 / 443 / 8080 のスキャンと連動

[インストール済みソフトウェア]
         ↓
  バージョン確認 → searchsploit / NVD で CVE・PoC 確認

[Windows ユーザーアカウント]
         ↓
  取得したユーザーリストをパスワードスプレーの対象に追加
```

## Step 6 — SNMPv3 認証情報の確認

SNMPv3 はコミュニティ文字列の代わりにユーザー名・認証パスワード・暗号化パスワードを使う。ユーザー名が分かれば接続を試みられる。

```bash
# [Attacker] 認証なし（noAuthNoPriv）での接続試行
snmpwalk -v 3 -l noAuthNoPriv -u [USERNAME] [TARGET_IP]

# [Attacker] 認証あり・暗号化なし（authNoPriv）
snmpwalk -v 3 -l authNoPriv -u [USERNAME] -a MD5 -A [AUTH_PASSWORD] [TARGET_IP]

# [Attacker] 認証あり・暗号化あり（authPriv）
snmpwalk -v 3 -l authPriv -u [USERNAME] -a SHA -A [AUTH_PASSWORD] \
  -x AES -X [PRIV_PASSWORD] [TARGET_IP]

# [Attacker] nmap スクリプトで SNMPv3 ユーザー名をブルートフォース
nmap -sU -p 161 --script snmp-brute [TARGET_IP]
```

| セキュリティレベル | 意味 |
|---|---|
| `noAuthNoPriv` | 認証なし・暗号化なし（最弱。機器によっては通る） |
| `authNoPriv` | 認証あり（MD5 / SHA）・暗号化なし |
| `authPriv` | 認証あり・暗号化あり（DES / AES）（最強） |

> SNMPv3 のユーザー名は製品のデフォルトユーザー名（`admin` / `snmpuser` / `initial` / 製品名小文字）から試す。

## Step 7 — 書き込み可能コミュニティ文字列による設定変更（要事前合意）

> **[HIGH IMPACT]** ネットワーク機器の設定変更は業務停止リスクを伴う不可逆な操作。本番では書面承認必須。

コミュニティ文字列が Write 権限を持つ場合、`snmpset` でネットワーク機器の設定を変更できる。本番では「書き込みアクセスが可能であることを確認した」という事実の記録で十分で、実際の設定変更は通常実施しない。

```bash
# [Attacker] 書き込み権限の確認（既存の文字列を同じ値で上書き → 設定変更なし）
snmpset -v 2c -c [WRITE_COMMUNITY] [TARGET_IP] \
  1.3.6.1.2.1.1.5.0 s "[CURRENT_HOSTNAME]"

# [Attacker] インターフェース状態変更の例（理論確認用・実環境では実施しない）
# OID 1.3.6.1.2.1.2.2.1.7.[IF_INDEX] = ifAdminStatus（1=up, 2=down）
snmpset -v 2c -c [WRITE_COMMUNITY] [TARGET_IP] \
  1.3.6.1.2.1.2.2.1.7.[IF_INDEX] i 2

# 原状回復（インターフェースを up に戻す）
snmpset -v 2c -c [WRITE_COMMUNITY] [TARGET_IP] \
  1.3.6.1.2.1.2.2.1.7.[IF_INDEX] i 1
```

---

## 刺さらなかったとき

| 状況 | 判断基準と次の選択肢 |
|---|---|
| `onesixtyone` が何も返さない | コミュニティ文字列が変更済みか SNMP が無効。より広いワードリスト（SecLists SNMP/）を試すか、他のポートに移る |
| `snmpwalk` がタイムアウトし続ける | ファイアウォールで UDP 161 がフィルタされている。`-t 10`（タイムアウト秒延長）・`-r 3`（リトライ回数）を調整して再試行 |
| `snmpwalk` の出力が10行以下で止まる | `public` が Read-Only かつ MIB 公開範囲が制限されている。`private` 等の別コミュニティ文字列を試す |
| Windows ユーザー列挙 OID が空 | SNMP サービスが拡張 MIB（Windows ホスト情報）を公開していない設定。`snmp-check` でカバーされている項目を確認 |
| SNMPv1 / v2c が完全に無効で v3 のみ動作している | v1/v2c の手法はすべて無効。ユーザー名が判明していれば `nmap --script snmp-brute` で SNMPv3 ブルートフォースを試みる |

---

## 注意点・落とし穴

- UDP はパケットロストが発生するため、タイムアウトやリトライの調整（`-t [秒]` `-r [回数]`）が必要な場合がある
- コミュニティ文字列は大文字小文字を区別する。`Public`・`PUBLIC`・`public` はそれぞれ別の文字列
- `snmpwalk` の全量取得は出力が数千行になることがある。`grep -i "process\|software\|user"` で絞り込む
- SNMP Trap（UDP 162）は機器からの通知用で、テスター側からの列挙には使わない
- Windows では SNMP サービスはデフォルトでインストールされていないが、監視ソフトウェアによってインストールされている場合がある
- `snmp-check` は出力が整形されていて読みやすいが、`snmpwalk` よりカバーする OID が限定的

---

## 本番での前提

- **事前合意の要否**: ★（技術的判断のみ、情報読み取りのみ） / ★★★（書き込み・設定変更は書面承認必須）
- **想定されるSIEM/EDR検知**: ネットワーク機器のコンソールログ（大量の SNMP Bulk Walk は一部の IDS で検知される場合がある）
- **業務影響リスク**: なし（読み取りのみ） / 業務停止リスクあり（書き込み・設定変更）
- **原状回復必須項目**:
  - ✅ `snmpset` による書き込み操作を実施した場合は設定を元に戻す
  - ✅ 取得したユーザーリスト・ネットワーク設定情報は暗号化保管 → テスト完了時破棄
- **取得情報の取扱**: ユーザーアカウント情報・ネットワーク構成情報は暗号化保管、テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術
- 前：ポートスキャン（UDP スキャン `-sU -p 161`）→ `../05_Tools_Reference/Nmap.md`
- 後：ARP / ルーティングテーブルから発見した新ホストへのスキャン → `./Network_Scanning.md`
- 後：取得した Windows ユーザーリストへのパスワードスプレー → `../05_Tools_Reference/Netexec.md`
- 後：インストール済みソフトウェアのバージョンから CVE 検索 → `../05_Tools_Reference/Searchsploit.md`
- 後：内部ネットワーク全体フロー（SNMP はトポロジー把握の起点として使う） → `../00_Playbook/Internal_LAN_Pentest_Flow.md`
