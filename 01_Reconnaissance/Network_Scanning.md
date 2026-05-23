# ネットワークスキャン

## 着火条件
調査の最初に必ず実施する。ターゲットの IP が判明した時点で開始。

---

## 観点・着眼点

**何が出たら次に何をするか：**

| 観測される出力 | 示唆 | 次のアクション |
|------------|-----|------------|
| 21 / 22 / 80 だけの最小構成 | Linux + Web の典型 | `../00_Playbook/Linux_Attack_Flow.md` へ |
| 53 / 88 / 389 / 445 / 5985 が揃う | AD DC 確定 | `../00_Playbook/Windows_AD_Attack_Flow.md` へ |
| 8080 / 8443 / 8888 等の非標準 HTTP | 開発用管理パネル / API の可能性 | まず `/` にアクセスしてフレームワーク・バージョンを特定 |
| 1433 / 3306 / 5432 などの DB ポートが外に出ている | 誤った公開設定 | デフォルト認証情報で接続試行 |
| 2049（NFS） | ファイル共有が直接マウントできる可能性 | `showmount -e [IP]` |
| 全ポートスキャンで非標準の高番ポート（例: 10000 超）が追加で出現 | 初期 `-sC -sV` では見えない隠しサービス | そのポートに対して `-sC -sV` を個別実行 |
| ターゲット IP が `172.17.0.x` / パストラバーサルで拾った `/etc/hosts` に同レンジ | 対象が Docker コンテナ内 | コンテナブレイクアウト経路を視野に |
| `filtered` が大量 | ファイアウォール・IDS の可能性 | スキャン速度を下げる（`-T2`）・送信元ポート変更（`--source-port 53`） |
| UDP の 161（SNMP）が `open\|filtered` | Community String 総当たりが効く可能性 | `onesixtyone` / `snmpwalk` で `public` `private` 等を試す |
| `-sC` の HTTP スクリプト出力に `Location: http://[ドメイン名]/` やホスト名らしき文字列が含まれる | vhost ベースの Web アプリ（IP 直打ちでは 302 リダイレクトや別画面になる） | **`/etc/hosts` に `[IP] [ドメイン名]` を追記してから**ブラウザ・curl でアクセスする |

**なぜ初期スキャンと全ポートスキャンを分けるのか：** `-sC -sV` は TCP 上位 1000 ポートのみ。非標準の高番ポートで動く管理画面・開発版アプリを見落とさないために `-p-` を並走させる。

---

## 手順

**Step 1: 初期スキャン（速度優先）**
```bash
nmap -sC -sV -oA nmap_initial [IP]
```
- `-sC`: デフォルトスクリプト（バージョン検出・サービス情報）
- `-sV`: バージョン検出
- `-oA`: 3形式（.nmap / .gnmap / .xml）で保存

**Step 2: 全ポートスキャン（初期スキャンと並行または後続）**
```bash
nmap -p- --min-rate 5000 -oA nmap_allports [IP]
```
- 初期スキャンで見つからなかった非標準ポートを発見するために必須
- `-p-`: 全65535ポート
- `--min-rate 5000`: スキャン速度を上げる

**Step 3: 追加スクリプトスキャン（気になるポートに対して）**
```bash
nmap -sC -sV -p [PORT1],[PORT2] -oA nmap_targeted [IP]
```

**Step 4: UDP スキャン（必要に応じて）**
```bash
sudo nmap -sU --top-ports 50 --open -oA nmap_udp [IP]
# SNMP / DNS / NTP / TFTP 等の発見に必要
```

**Step 5: searchsploit --nmap で既知CVEを一括確認**

`-oA` で保存した XML ファイルを searchsploit に渡す。nmap が検出したすべてのサービス×バージョンに対して既知エクスプロイトを一括表示する。

```bash
# [Attacker] 初期スキャン結果を一括チェック
searchsploit --nmap nmap_initial.xml

# 全ポートスキャン結果も確認する場合
searchsploit --nmap nmap_allports.xml
```

**出力が大量に出た場合の絞り込み：**
1. Remote 系（RCE・Remote File Inclusion 等）を Local 系（LPE）より優先する（シェルを持っていない段階）
2. `DoS` / `Denial of Service` のタイトルはスキップする
3. ヒットしたバージョンが一致するか NVD で確認する → `../05_Tools_Reference/Searchsploit.md`（複数候補の絞り込み基準）

### ポート番号から環境を読む

| ポートセット | 推測される環境 |
|-------------|---------------|
| 21, 22, 80 | Linux + Web |
| 53, 88, 389, 445, 5985 | Windows AD（DC） |
| 8080, 8443, 8888 | 開発環境・管理パネル |
| 1433 | MSSQL |
| 3306 | MySQL |
| 2049 | NFS（マウント可能な共有） |
| 11211 | Memcached |

### IPアドレスレンジから環境を読む

| IPレンジ | 推測される環境 |
|---------|--------------|
| `172.17.0.x` | **Docker デフォルトブリッジネットワーク**。このレンジのIPを持つホストは Docker コンテナである可能性が高い |
| `10.x.x.x` | 社内 LAN・VPN・Kubernetes Pod ネットワーク等 |
| `192.168.x.x` | ローカルネットワーク |

**172.17.0.x が示すもの：**

- Nmap スキャン対象のホストが `172.17.0.x` → そのホスト自体はコンテナの可能性
- パストラバーサル等で取得した `/etc/hosts` に `172.17.0.x` のエントリ → **Webアプリがコンテナ内で動いている**
  - ホスト名がランダムな16進文字列（例: `172.17.0.2   [CONTAINER_ID]`）であればほぼ確実に Docker コンテナ
  - このホスト名（`[CONTAINER_ID]`）がコンテナIDとして後で使える（`docker exec` 等）
- 実際のターゲットホスト（例: `192.0.2.x`）とは別の IP → コンテナはホスト上で動作しており、SSHログイン後に `docker` コマンドが使える可能性がある

→ コンテナ環境が判明したら侵入後に確認: `../03_Post_Access_Linux/Enumeration_Checklist.md`（Dockerコンテナ環境の確認）
→ sudo docker exec の悪用: `../03_Post_Access_Linux/Sudo_Misconfig.md`（パターン4）

### Windows AD 環境の見分け方

以下のポートが複数存在する → AD環境と判断：
- 88 (Kerberos)
- 389 (LDAP)
- 3268 (Global Catalog LDAP)
- 5985 (WinRM)

### 刺さらなかったとき

| 観測される症状 | 推定原因 | 代替手段 |
|--------------|---------|---------|
| 全ポートが `filtered` で返る | ファイアウォール / IDS / IPS が SYN スキャンをブロック | `--source-port 53` で送信元ポート偽装、`-T2` でスキャン速度低下、`-sT`（TCP connect）に切替 |
| ping が通らずスキャンが開始されない | ICMP がブロックされている | `-Pn` でホスト発見をスキップ |
| `-sV` でバージョン情報が取れない | サービスがバナーを返さない / カスタム実装 | `--version-intensity 9` で強化、応答が出ない場合は手動接続（`nc` / `curl`）でレスポンス確認 |
| `-O` で OS が `Too many fingerprints` | TCP/IPスタックが特殊で照合失敗 | 上記 ④ HTTPヘッダー / ⑤ SMBバナー / ⑥ SSHバナーから推定する（`../00_Playbook/00_OS_Identification.md` 参照） |
| 全ポート閉じているように見える | スキャナー側の到達経路に問題 | テスター側の到達可能インターフェースを `ip a` で確認、ルーティングテーブル（`ip r`）で経路確認、必要なら別経路から再試行 |
| UDP スキャンが何も返さない | ほとんどの UDP サービスは応答しない仕様 | `--top-ports 50 --open` で絞る、SNMP（161）・DNS（53）・NTP（123）等の特定ポートに対して `nmap -sU -sV` を個別実施 |

---

### 注意点・落とし穴

- 全ポートスキャンを省略すると非標準ポートの重要なサービスを見逃す
- UDPスキャン (`-sU`) は低速だが SNMP (161)、DNS (53) の確認に必要な場合がある
- ファイアウォールでフィルタリングされたポートは `filtered` と表示される（閉じているわけではない）
- 出力ファイルは `-oA` で保存しておくと後から再参照できる

### 関連技術

- 前：案件開始（IP 渡し）／OS 判定 → `../00_Playbook/00_OS_Identification.md`
- 後：`./Web_Enumeration.md`（HTTP / HTTPS ポート発見後）
- 後：`./SMB_Enumeration.md`（445 / 139 発見後）
- 後：`./LDAP_Enumeration.md`（389 / 636 発見後）
- 後：`./TLS_Audit.md`（443 / 8443 / 993 / 995 / 465 等 TLS ポート発見後のプロトコル/暗号/証明書監査）
- 後：`./Exposed_Files.md`（Web ポート発見後の誤公開ファイル探索）
- 後：`./SNMP_Enumeration.md`（UDP 161 発見後の SNMP 列挙・内部ネットワーク観点）
- 後：ポートパターンからフロー判断 → `../00_Playbook/Linux_Attack_Flow.md` / `../00_Playbook/Windows_AD_Attack_Flow.md`
- 後：検出サービス×バージョンの既知 CVE 一括確認 → `../05_Tools_Reference/Searchsploit.md`
- 後：Linux 侵入後の列挙 → `../03_Post_Access_Linux/Enumeration_Checklist.md`
- 後：`172.17.0.x` 等でコンテナ環境が判明した場合の権限昇格 → `../03_Post_Access_Linux/Sudo_Misconfig.md`
