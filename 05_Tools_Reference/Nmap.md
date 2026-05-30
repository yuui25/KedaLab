# Nmap クイックリファレンス

> **スコープ**: ポートスキャン・サービス検出・バージョン検出・NSE スクリプト実行のクイックリファレンス。詳細な手順・環境判断ロジックは `../01_Reconnaissance/Network_Scanning.md` を参照。

## 着火条件

- ターゲット IP が判明して最初にスキャンを行う時点
- 特定のサービス・バージョンを深掘りしたい場合

---

## 基本スキャンセット（毎回使う）

```bash
# 初期スキャン（サービス検出）
nmap -sC -sV -oA nmap_initial [IP]

# 全ポートスキャン
nmap -p- --min-rate 5000 -oA nmap_allports [IP]

# 特定ポートへの詳細スキャン
nmap -sC -sV -p [PORT1],[PORT2] -oA nmap_targeted [IP]
```

## よく使うオプション

| オプション | 説明 |
|-----------|------|
| `-sC` | デフォルトスクリプトを実行 |
| `-sV` | バージョン検出 |
| `-sU` | UDPスキャン（低速） |
| `-p-` | 全65535ポートをスキャン |
| `--min-rate 5000` | 毎秒最低5000パケット送信（高速化） |
| `-T4` | タイミングテンプレート（高速） |
| `-oA [basename]` | .nmap / .gnmap / .xml の3形式で保存 |
| `-oN [file]` | テキスト形式で保存 |
| `--open` | 開いているポートのみ表示 |
| `-Pn` | ホスト発見をスキップ（ICMPブロックされている場合） |

## 便利なスクリプト

```bash
# SMB の詳細情報
nmap --script smb-enum-shares,smb-enum-users [IP] -p 445

# FTP匿名ログインの確認
nmap --script ftp-anon [IP] -p 21

# HTTP のヘッダー・タイトル確認
nmap --script http-title,http-headers [IP] -p 80,443,8080

# LDAP の基本情報
nmap --script ldap-rootdse [IP] -p 389

# 脆弱性スキャン（重い）
nmap --script vuln [IP]
```

## 出力ファイルの整理

```bash
# .nmap ファイルを確認
cat nmap_initial.nmap

# 開いているポートだけ抽出
grep "open" nmap_allports.nmap | grep -v "Not shown"

# XML から xmllint で整形（インストール済みの場合）
xmllint --format nmap_initial.xml
```

## `-sC` スキャン結果の読み方（AD環境）

`-sC` はデフォルトスクリプトを実行するオプション。AD環境では以下の情報が自動的に取得できる。

### 確認する順番と着眼点

**① ドメイン名・ホスト名（LDAP / SMB バナーから）**
```
389/tcp open ldap  Microsoft Windows Active Directory LDAP
|                  (Domain: example.local, Site: Default-First-Site-Name)
```
→ `Domain:` の値が AD のドメイン名。**`/etc/hosts` への登録をここで行う。**

**② ホスト名とOS（Service Info から）**
```
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1
```
→ `Host:` = NetBIOS ホスト名（DC, FILESERVER 等）。OS バージョンも判明。

**③ SMB 署名（smb2-security-mode スクリプトから）**
```
| smb2-security-mode:
|   2.1:
|_    Message signing enabled and required
```
→ `required` の場合 → **NTLM リレー攻撃は使えない**。`not required` なら使える。

**④ AD 確定の判断（ポート構成から）**

| ポートの組み合わせ | 判断 |
|-----------------|------|
| 88 (Kerberos) が開いている | AD 環境確定 |
| 53 + 88 + 389 + 445 | DC（ドメインコントローラー）の可能性が高い |
| 3268 / 3269 | Global Catalog → DC 確定 |

**⑤ 時刻ズレ（smb2-time / clock-skew）**
```
|_clock-skew: -1m13s
```
→ Kerberos は時刻ズレ **5分以内** を要求する。大きくズレている場合は `faketime` や `ntpdate` で合わせる。

### AD 環境での典型的な読み方まとめ

```
# この出力が出たら → AD環境 + DC確定
88/tcp   open  kerberos-sec  → AD確定
389/tcp  open  ldap  (Domain: example.local) → ドメイン名を /etc/hosts に登録
445/tcp  open  microsoft-ds  → SMBアクセスを試みる
smb2-security-mode: signing required → NTLMリレー不可

# 次のアクション: SMB匿名アクセス → LDAP列挙
```

---

## 刺さらなかったとき

| 状況 | 原因・対処 |
|------|-----------|
| 全ポートが `filtered` | FW がドロップしている。`-Pn` でホストアップ確認をスキップして強制スキャン |
| SYN スキャンが使えない（root なし）| `-sT`（TCP connect スキャン）に切り替える |
| `--min-rate` で結果が少ない | 高レートで一部ポートが誤 filtered 判定。`--min-rate 500` 程度に下げる |
| 全ポートスキャンが遅い | `rustscan` で先にポートを発見 → nmap で深掘りする（`Network_Scanning.md` §3 参照）|

---

## 注意点

- `--min-rate` を高くしすぎると一部のポートが `filtered` と誤判定されることがある
- AD 環境では `-Pn` が必要な場合がある（ICMP をブロックしている場合）
- 出力ファイルは調査フォルダに必ず保存して後から参照できるようにする

---

## 関連技術
- 後：`../01_Reconnaissance/Web_Enumeration.md`（Web ポートが開いていた場合）
- 後：`../01_Reconnaissance/SMB_Enumeration.md`（445 が開いていた場合）
- 後：`../01_Reconnaissance/LDAP_Enumeration.md`（389 / 636 が開いていた場合）
- 関連：`./Searchsploit.md`（バージョン検出後に既知 CVE を検索）
