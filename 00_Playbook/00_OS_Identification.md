# OS判定

スキャン開始前・スキャン中・Web確認時など、複数の段階でOSを特定する手がかりが得られる。
得られた情報を重ね合わせて確度を上げていく。

> **認証情報（ID/パスワード）が提供済みの場合**：SSH（22番）またはRDP（3389番）への接続を先に試すと、
> ログイン後のプロンプト形式（`$` → Linux 系、`>` → Windows 系）でOSが即確定する。
> TTL確認やnmapより速い。接続できた時点でOS判定は完了とし、対応Playbookの「開始条件の確認」テーブルへ進む。

> **記録しながら進める**：判定した OS・ホスト名・開いたポートは、この後のどの Playbook でも最初に参照する。控えておく（kedaweb の Workspace ＞ Worksheet 上部「OS」「HOSTNAME」欄・「PORTS」欄が対応）。kedaweb を使わない場合も手元のノートに残す。

---

## 判定の優先順位

```
① TTL 値（ping が通る場合 → スキャン前に即確認）
② nmap ポート構成（最も確実・情報量が多い）
③ HTTP レスポンスヘッダー（Web が開いている場合）
④ 大文字小文字の区別（Web が開いている場合）
⑤ SMB の OS 情報（445 が開いている場合）
⑥ SSH バナー（22 が開いている場合）
```

---

## ① TTL 値（スキャン前の最速判定）

### 着火条件
ping が通る環境であれば、nmap より先に実行できる。

> 原理（なぜ OS ごとに TTL 初期値が違うのか・ホップ数でどうズレるか・偽装の可能性） → `../06_Concepts/OS_Fingerprinting_Principles.md`

```bash
ping -c 1 [IP]
# Windows: TTL=128（ルーター1台経由なら127、2台なら126 ...）
# Linux:   TTL=64 （ルーター1台経由なら63、2台なら62 ...）
```

| 受信 TTL | 推定初期値 | OS推定 |
|---------|-----------|-------|
| 128 ± 数 | 128 | Windows |
| 64 ± 数 | 64 | Linux / macOS |
| 255 ± 数 | 255 | Cisco / 一部の Unix |

> 稀なTTL値（32: 古いOS / その他）の詳細 → `../06_Concepts/OS_Fingerprinting_Principles.md`

### 注意点
- TTL はあくまで**目安**。ルーター・中継機器（VPN・プロキシ・SDN・ロードバランサ等）を何段経由しているかで大きく変わる
- `traceroute [IP]` でホップ数を数えてから判断すると精度が上がる
- 変更可能なため、意図的に偽装されている場合もある（稀）

---

## ② nmap ポート構成（最も確実）

### 着火条件
常に実施する。ポート構成だけでほぼ OS が確定する。

```bash
nmap -sC -sV [IP]
# または OS 検出を明示的に有効化
sudo nmap -O [IP]

# 上記は1コマンドにまとめてよい（OS検出 + バージョン + デフォルトスクリプト）
sudo nmap -O -sC -sV [IP]
# -A でもほぼ等価（-O・-sV・-sC・traceroute を一括。出力は増える）
sudo nmap -A [IP]
```

> **`-O` と `-sC -sV` を分ける必然性はない。** root 権限さえあれば `-O -sC -sV` を一度に投げてよい。分割例は「OS 検出だけ後から足したい」場合の参考。

### ポートの組み合わせで判断する

| 開いているポート | OS判定 | 備考 |
|----------------|-------|------|
| 22（SSH）のみ | Linux 確定に近い | OpenSSH のバナーに `Debian` / `Ubuntu` 等が含まれる |
| 22 + 80 | Linux 寄り | |
| 135, 139, 445 | Windows | SMB / RPC が動いている |
| 88（Kerberos） | Windows AD 確定 | DC（ドメインコントローラー）がいる |
| 3389（RDP） | Windows | |
| 5985 / 5986（WinRM） | Windows | |
| 389 / 636（LDAP） | Windows AD 寄り | |
| 53（DNS）+ 88 + 389 | Windows AD 確定 | |

### nmap の `Service Info` を確認する

```
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

スキャン結果の末尾に OS が明記されることが多い。

### `-O` オプション（OS フィンガープリント）

```bash
sudo nmap -O [IP]
# → Running: Microsoft Windows 2019
# → Running: Linux 4.X|5.X
```

TCP/IP スタックの特性からOSを推定する。root 権限が必要。

**`No exact OS matches` + `TCP/IP fingerprint:` が出たとき：**

`-O` がデータベースと一致せず `No exact OS matches for host` を返し、生の `TCP/IP fingerprint:`（`OS:SCAN(...)` の塊）を吐くことがある。

| 観測 | 意味 | どうするか |
|------|------|-----------|
| `TCP/IP fingerprint:` の生ブロック | nmap.org への**投稿用データ**。その場の判定には直接使わない | 無視してよい。判定は他のシグナル（後述）で行う |
| `No exact OS matches` だが `Host script results` に `smb-os-discovery` の OS 行がある | スタック推定は外したが**サービス側が OS を明示**している | そちらを採用する（例: `OS: Windows XP` なら Windows 確定） |
| `Service Info: OSs: Windows ...` | サービスバナー由来の OS 情報 | これも有効な判定材料 |

> **`No exact OS match` ＝「判定不能」ではない。** `-O` のスタック推定が DB にヒットしなくても、`smb-os-discovery` / `Service Info` / ポート構成で OS はほぼ確定できる。生フィンガープリントの解読に時間を使わない。

### 注意点
- ファイアウォールで一部ポートが閉じられている場合は判断が難しい
- **OS が確定した後でも、初期 recon として全ポートスキャン（`-p-`）は必ず1回回す**
  OS 判定はデフォルトの上位ポートだけでも付くことが多いが、攻撃経路の選択は「全ポートを把握してから」行う。高位ポートに刺さるサービス（非標準ポートの DB・内部サービス・古い SMB 以外の RCE 経路等）を見落とさないため、対応 Playbook へ進む前に `-p-` の結果を揃える。
  ```bash
  sudo nmap -p- --min-rate 5000 [IP]
  # 開いていたポートだけ詳細スキャンし直す
  sudo nmap -p[OPEN_PORTS] -sC -sV [IP]
  ```

> **▶ 記録:** 開いたポート一覧を控える（全 Playbook で最初に参照する）。→ Worksheet「PORTS」欄。

---

## ③ HTTP レスポンスヘッダー

### 着火条件
80 / 443 / 8080 等の Web ポートが開いている場合。

```bash
curl -sI http://[IP]/
curl -sI https://[IP]/ -k
```

### 見るべきヘッダー

| ヘッダー | 値の例 | OS判定 |
|---------|--------|-------|
| `Server` | `Microsoft-IIS/10.0` | Windows |
| `Server` | `Apache/2.4.41 (Ubuntu)` | Linux |
| `Server` | `Apache/2.4.25 (Debian)` | Linux |
| `Server` | `nginx/1.18.0` | Linux 寄り（WindowsのIISでも nginx は動くが稀） |
| `X-Powered-By` | `ASP.NET` | Windows |
| `X-Powered-By` | `PHP/7.4.3` | どちらも可能 |
| `X-AspNet-Version` | 何でも | Windows（ASP.NET）|

```bash
# 例
curl -sI http://[IP]/ | grep -i "server\|x-powered-by\|x-aspnet"
```

### 注意点
- `Server` ヘッダーは無効化・偽装できる（セキュリティ設定済み環境では空になる）
- Apache は Windows でも動く。`(Debian)` 等のディストリ名が含まれていれば Linux 確定

---

## ④ 大文字・小文字の区別（Web が開いている場合）

### 着火条件
Web が動いており、既存のパス（`/index.html` 等）がわかっている場合。

> 原理（ext4 / NTFS / APFS の仕様差・アプリ側の正規化で判定が崩れるケース） → `../06_Concepts/OS_Fingerprinting_Principles.md`

**判定ルール：**

- 200 が返る → 大文字でもヒット → Windows 寄り（NTFS 既定 case-insensitive）
- 404 が返る → 大文字だと見つからない → Linux 寄り（ext4 既定 case-sensitive）

```bash
# 存在するパスを大文字に変えてアクセス
curl -s http://[IP]/INDEX.HTML -o /dev/null -w "%{http_code}\n"
```

### 注意点
- アプリ側でリダイレクト処理をしている場合は結果が変わることがある
- 確認できるパスが `/index.html` に限らず、画像ファイルや CSS でも同様に確認できる

---

## ⑤ SMB バナー（445 が開いている場合）

### 着火条件
445 番ポートが開いている場合。Windows である可能性が高いが念のため確認する。

```bash
# smbclient でバナー確認（認証不要）
smbclient -L //[IP] -N 2>&1 | head -20
# → OS=[Windows Server 2019 Standard 17763] ...

# nmap スクリプトで詳細取得
nmap -p 445 --script smb-os-discovery [IP]
# → OS: Windows Server 2019 Standard 17763
# → Computer name: [DC_HOSTNAME]
# → Domain name: example.local
```

### 注意点
- Samba（Linux 上で動く SMB 実装）が動いている場合は Linux でも 445 が開く
- Samba の場合は `OS=[Unix]` や `OS=[Samba x.x.x]` と表示される

---

## ⑥ SSH バナー（22 が開いている場合）

### 着火条件
22 番ポートが開いている場合。

```bash
# バナーを取得
nc -w 3 [IP] 22
# → SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u1

# または nmap で確認
nmap -p 22 -sV [IP]
# → 22/tcp open ssh OpenSSH 9.2p1 Debian 2+deb12u1
```

### バナーで判断できるディストリ

| バナーの文字列 | ディストリ |
|--------------|----------|
| `Ubuntu-*` | Ubuntu |
| `Debian-*` | Debian |
| `Red Hat-*` | RHEL / CentOS |
| `FreeBSD-*` | FreeBSD（Unix系） |
| バナーなし / カスタム | 設定で変更済みの可能性 |

### 注意点
- OpenSSH は Windows にもインストールできるため、SSH が開いているからといって Linux 確定ではない（ただし稀）
- バナーが変更されている場合もあるが、ディストリ情報まで消すケースは少ない

---

## 判定結果に応じた次のステップ

| 判定 | 参照するPlaybook |
|------|----------------|
| Linux | `Linux_Attack_Flow.md` |
| Windows | `Windows_AD_Attack_Flow.md`（88番 Kerberos の有無は遷移先の Step 0 で AD / スタンドアロンを読み分ける。88 がなくても同じファイルに進む）|
| 判定できない | 全ポートスキャン（`nmap -p-`）を実施してから再判定（→ 下記） |

> Windows は AD でもスタンドアロンでも入口は同じ `Windows_AD_Attack_Flow.md`。**OS 判定の段階で 88 の有無による分岐を気にする必要はない**（遷移先で判定する）。

> **▶ 記録:** 確定した OS とホスト名を控える。→ Worksheet 上部「OS」「HOSTNAME」欄。

---

## 判定できない場合の深掘り手順

全ポートスキャン（`sudo nmap -p- --min-rate 5000 [IP]`）後も判定できない場合は以下を順に試す。

**1. OS fingerprint を強制取得**

```bash
sudo nmap -O --osscan-guess [IP]
# 確信度が低い推定（例：「Aggressive OS guesses: Linux 4.X (85%)」）でも参考にする
```

**2. 全情報を網羅取得**

```bash
sudo nmap -A [IP]
# -O（OS検出）・-sV（バージョン検出）・-sC（スクリプト）・traceroute を一括実行
# サービスバナーが増えることでOS特定につながる場合がある
```

**3. 応答するポートのバナーを生取得**

```bash
nc -w 3 [IP] [OPEN_PORT]
# nmap がバナーを整形・省略してしまう場合に、生のバナー文字列を確認する
```

**4. パッシブフィンガープリント**

```bash
sudo p0f -i [INTERFACE]
# パケット送信なし。受信したパケットのTCP/IP特性からOSを推定（ステルス性が高い）
# ペネトレ用Linuxディストリ標準搭載。オフライン環境でも使用可能
```

**上記4手で判断できない場合の考え方**

ロードバランサー・WAF・リバースプロキシ経由の可能性がある。
`traceroute [IP]` でホップ数と中継機器を確認し、「スキャン対象が中継機器自体なのか、その背後のシステムなのか」を切り分ける。
→ 中継機器と判断した場合は `External_Service_Recon_Flow.md` へ切り替える。

---

## 関連技術

- 前：`../01_Reconnaissance/DNS_Enumeration.md`（ドメインのみ提供時、IP特定後にここへ。IPが手元にある場合は調査の起点となるためこの前段は無い）
- 後：`Linux_Attack_Flow.md`（Linux と判定）
- 後：`Windows_AD_Attack_Flow.md`（Windows と判定。88番 Kerberos の有無で AD / スタンドアロンを読み分ける）
- 後：`External_Service_Recon_Flow.md`（OS特定に至らず「インターネット境界機器らしい」と判断した場合）
