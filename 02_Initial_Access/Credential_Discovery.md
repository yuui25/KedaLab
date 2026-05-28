# 認証情報の発見

様々な場所・形式で認証情報が露出しているパターンと、その取得手順をまとめる。

---

## パターン一覧（早見表）

| # | パターン名 | 着火条件（一言） |
|---|-----------|--------------|
| 1 | PCAP から平文認証情報 | PCAP ファイルが取得できた（FTP / HTTP 等の平文通信を含む可能性） |
| 2 | スクリプトへの平文埋め込み | SYSVOL / スクリプトファイル（.bat / .ps1 等）が取得できた |
| 3 | LDAP カスタム属性への平文保存 | LDAP 認証情報があり属性を列挙できる |
| 4 | バイナリ・設定ファイルへのハードコード | 実行ファイルや設定ファイルが取得できた |
| 5 | Webアプリ内部 DB からハッシュ取得 | パストラバーサル等でアプリのデータディレクトリにアクセスできた |
| 6 | GPP cpassword（Group Policy Preferences） | SYSVOL に Groups.xml が存在し cpassword 属性がある |
| 7 | Webアプリの .env ファイル | Webサーバーの公開ディレクトリにシェルでアクセスできた |
| 8 | Bundler `.bundle/config` | Ruby アプリのプロセス（ruby / unicorn 等）としてシェルを取得済み |
| 9 | KeePass データベース（.kdbx）のクラック | .kdbx ファイルを取得できた |

---

## パターン1: PCAPファイルからの平文認証情報

### 着火条件
- PCAPファイル（ネットワークキャプチャ）が取得できた場合
- FTP / HTTP / Telnet など**平文通信プロトコル**のトラフィックが含まれている可能性がある

### 観点・着眼点
FTPは認証情報を**完全に平文で送信する**。Webアプリがネットワークキャプチャを保存・公開している場合、そのPCAPにログイン情報がそのまま含まれることがある。

### 手順

```bash
# FTPの認証情報を抽出
tshark -r capture.pcap -Y "ftp" -T fields -e frame.number -e ftp.request.command -e ftp.request.arg

# HTTPのBasic認証を抽出
tshark -r capture.pcap -Y "http.authorization" -T fields -e http.authorization

# 全トラフィックを確認（目視）
tshark -r capture.pcap | head -100

# strings コマンドで文字列として抽出（簡易）
strings capture.pcap | grep -i "user\|pass\|login\|auth" | head -50
```

### 注意点・落とし穴
- `PASS` コマンドの引数がパスワードになる。空パスワードでも `PASS` 行は出るため、前後の `USER` 行とセットで確認する
- PCAPが大きい場合 `strings` は GB 単位でも数秒で終わるが、誤マッチが多いため補助手段として使う
- `https` トラフィックは復号できない（鍵がない限り）。平文は `http` / `ftp` / `telnet` / `pop3` / `imap` など
- 認証情報を拾ったら **日付・ホスト名もメモしておく**。古すぎる PCAP のパスワードは現在変更されている可能性
- → 取得した認証情報の確認手順：このファイル末尾「認証情報を取得したら必ず試すこと」を参照

---

## パターン2: スクリプトファイルへの平文パスワード埋め込み

### 着火条件
- SMBの SYSVOL 共有にアクセスできた
- スクリプトファイル（`.bat`, `.ps1`, `.vbs`）が取得できた

### 観点・着眼点
管理者がユーザーアカウント作成等を自動化するスクリプトに、パスワードを平文で記述していることがある。特に `net user` コマンドを含む `.bat` ファイルは要確認。

### 手順
```bash
# ダウンロードしたスクリプトを確認
cat users.bat

# 典型的なパターン
# net user A.Username P4ssw0rd1#123
```

### 注意点・落とし穴
- `.bat` / `.ps1` / `.vbs` だけでなく `.config` / `.ini` / `.xml` にも平文認証情報があることがある
- SYSVOL はドメイン参加ユーザーなら誰でも読めるのが既定。低権限アカウントでの横展開の糸口
- `findstr /si password *.xml *.ini *.txt` を Windows 側で実行するとまとめて拾える（対応する Linux 側は `grep -risE 'pass(word)?='`）
- **スケジュールタスク XML** / **スクリプト実行時の引数** にパスワードが渡されている場合もあるので、Groups.xml 以外も全部舐める
- → 取得した認証情報の確認手順：このファイル末尾「認証情報を取得したら必ず試すこと」を参照

---

## パターン3: LDAPのカスタム属性への平文パスワード保存

### 着火条件
- LDAP認証情報が取得できており、ユーザー属性を列挙できる

### 観点・着眼点
Active Directoryの `info` フィールドや `description` フィールドに、管理者が一時パスワードや初期パスワードをメモとして記録していることがある。

### 手順
```bash
ldapsearch ... "(objectClass=user)" sAMAccountName info description \
  | grep -i "info\|description"
```

→ 詳細: `../01_Reconnaissance/LDAP_Enumeration.md`

### 注意点・落とし穴
- `info` は GUI の「説明」欄とは別の目立たないフィールド。見落とされやすい分だけ平文パスワードが残りやすい
- 一時パスワードが書かれていても `userAccountControl` に `PASSWORD_EXPIRED` が立っていないか確認。既に使われなくなっている可能性
- `description` / `info` が暗号文っぽい場合、別フィールドに鍵が書かれていることもある（例: `extensionAttribute1`）
- → 取得した認証情報の確認手順：このファイル末尾「認証情報を取得したら必ず試すこと」を参照

---

## パターン4: バイナリ・設定ファイルへのハードコード

### 着火条件
- 実行ファイル・設定ファイル・ライブラリが取得できた

### 観点・着眼点
開発者がアプリケーション内に認証情報を直接書き込んでいる場合がある（LDAP接続用パスワード等）。暗号化されていても、XOR程度の簡易暗号はバイナリ解析で復号できる。

→ 詳細: `../Binary_Analysis.md`

### 注意点・落とし穴
- `web.config` / `appsettings.json` / `.env` / `docker-compose.yml` は最優先で確認する（バイナリ解析より前）
- .NET バイナリは `strings` でも見つかることが多いが、UTF-16LE エンコードなので `strings -e l` を併用
- 見つかった認証情報が開発用で接続先が `localhost` や内部ホスト → そのホスト名が DNS で引けるか確認（パストラバーサル等で `/etc/hosts` を拾うと分かることがある）
- → 取得した認証情報の確認手順：このファイル末尾「認証情報を取得したら必ず試すこと」を参照

---

## パターン5: Webアプリの内部データベースからハッシュを取得

### 着火条件
- パストラバーサルやファイル読み取り系の脆弱性で、アプリのデータディレクトリにアクセスできた
- Grafana / WordPress / Gitea 等のWebアプリが SQLite や MySQL を使って認証情報を保存している

### 観点・着眼点
Webアプリが独自の認証機構を持つ場合、OSのユーザーではなくアプリ独自のDBにパスワードハッシュを保存している。
ハッシュ形式はアプリによって異なり、Grafanaは PBKDF2-HMAC-SHA256、WordPress は MD5 ベース等。
**取得したDBファイルはまずテーブル一覧を確認し、ユーザー・認証関連テーブルを特定する。**

### 手順

```bash
# SQLite の場合 — テーブル一覧を確認
sqlite3 [FILE].db ".tables"

# ユーザー関連テーブルを確認
sqlite3 [FILE].db "SELECT * FROM user LIMIT 5;"

# カラム構成を確認
sqlite3 [FILE].db "PRAGMA table_info(user);"
```

#### Grafana（PBKDF2-HMAC-SHA256）の場合

```bash
# ユーザー情報の取得（CLI）
sqlite3 grafana.db "SELECT id, name, login, email, password, salt FROM user;"

# 出力例:
# 1||admin|admin@localhost|[HEX_HASH]|[SALT]
# 2|username|username|user@domain.local|[HEX_HASH]|[SALT]
```

> **GUI ツールを使う場合：** `sqlitebrowser`（DB Browser for SQLite）でも同様にデータを確認できる。Table: `user` を開き Browse Data タブで全カラムを表示する（`sqlitebrowser` は別途インストールが必要；ペネトレ用Linuxディストリ非標準）。オフライン環境では `sqlite3` CLI を使う。

> **`rands` カラムについて：** Grafana の user テーブルには `password`（HEXハッシュ）・`salt`・`rands` の 3 カラムがある。PBKDF2-HMAC-SHA256 の変換には `password`（HEX）と `salt` のみ使用する。`rands` は別用途（セッション関連）のため Hashcat 変換には不要。
>
> **Grafana 9.x 以降の注意：** `password` フィールドの先頭が `$2a$` / `$2b$` で始まる場合は bcrypt ハッシュ（hashcat mode 3200）。PBKDF2 ハッシュは hex 文字列で始まる。`password` フィールドの prefix で判断してから変換式を選ぶ。

取得したハッシュを Hashcat (mode 10900) 形式に変換する：

```python
# [Attacker] 以下のスクリプトはテスター端末で実行する。ターゲット上では実行しない。
import base64, binascii

salt = b'[SALT_STRING]'
hash_hex = '[HEX_HASH]'
hash_bytes = binascii.unhexlify(hash_hex)
print(f'sha256:10000:{base64.b64encode(salt).decode()}:{base64.b64encode(hash_bytes).decode()}')
```

→ 変換後ハッシュのクラック: `../05_Tools_Reference/Hashcat.md`（mode 10900）

### 注意点・落とし穴
- ハッシュが HEX 文字列で保存されている場合、Hashcat に渡す前に base64 形式に変換が必要（アプリ依存）
- salt が別カラムに保存されていることが多い。必ずセットで取得する
- admin アカウントのハッシュが強固でクラックできなくても、一般ユーザーのハッシュがクラックできることがある
- パスワードを取得できたら必ず他サービス（SSH, FTP, 管理画面等）でも試す（使い回し確認）
- → 取得した認証情報の確認手順：このファイル末尾「認証情報を取得したら必ず試すこと」を参照

---

## パターン6: GPP (Group Policy Preferences) の cpassword

### 着火条件
- SYSVOL または Replication 共有に匿名または認証ありでアクセスできた
- `Policies/{GUID}/MACHINE/Preferences/Groups/Groups.xml` が取得できた
- XML内に `cpassword=` 属性が存在する

### 観点・着眼点

`cpassword` 属性が存在した時点で **ツール1コマンドで平文に復元できる**（誰でも即座に復号可能）。

`userName` 属性がドメインアカウントを指している場合（例: `DOMAIN\SVC_xxx`）、そのアカウントのドメインパスワードが得られる。ローカルアカウントを指している場合も、共通化されたローカル管理者パスワードである可能性が高く、ドメイン内の他端末への横展開で有効なケースが多い。

> 原理（なぜ AES 暗号化されていても復号できるのか・MS14-025 後の挙動・対象XMLの範囲） → `../06_Concepts/GPP_Credential.md`

### 手順

```bash
# gpp-decrypt（ペネトレ用Linuxディストリ標準搭載）
gpp-decrypt '[cpassword 属性の値]'

# 取得できる情報を確認
# - userName: 対象アカウント（DOMAIN\username 形式）
# - cpassword: 復号するとパスワード
```

### 注意点・落とし穴
- `action="U"` は既存アカウントの更新（パスワード変更）を意味する。現在も有効なパスワードの可能性が高い
- `Groups.xml` 以外にも GPP 認証情報が保存されるファイルがある: `Services.xml`, `ScheduledTasks.xml`, `Printers.xml`, `Drives.xml` — いずれも同様に `cpassword` を含む可能性がある
- 取得したアカウントが低権限でも、そのアカウントで LDAP・SMB・BloodHound の認証が通るため、AD全体の列挙が一気に進む
- → 取得した認証情報の確認手順：このファイル末尾「認証情報を取得したら必ず試すこと」を参照

→ 詳細な取得手順: `../01_Reconnaissance/SMB_Enumeration.md`（GPPセクション）

---

## パターン7: Webアプリの .env ファイルからの認証情報取得

### 着火条件
- Webサーバ（nginx / Apache 等）の公開ディレクトリ（`/var/www/html/` 等）にシェルでアクセスできた
- PHP / Node.js / Laravel / Django 等のフレームワークベースのWebアプリが動作している

### 観点・着眼点
`.env` ファイルはWebアプリの設定を環境変数として管理するファイル。**本番環境ではDBの認証情報・APIキー・シークレットキー等が平文で格納されている**ことが多い。

www-data等の低権限ユーザーでシェルを取得した直後に確認するべき最優先ファイルの一つ。OSユーザーのパスワードとDBパスワードが使い回されているケースが多く、そのまま `su` や SSH での横展開に使える。

**確認すべきパスと優先順位：**

```bash
# Webルートの直下（最優先）
cat /var/www/html/.env
ls -la /var/www/html/

# フレームワーク特有のパス
cat /var/www/[アプリ名]/.env
cat /opt/[アプリ名]/.env
cat /srv/[アプリ名]/.env

# 隠しファイルを含めて一覧表示
ls -la /var/www/html/
```

`.env` が見つかったら以下を確認する：

```
DB_HOST=127.0.0.1
DB_DATABASE=app_prod
DB_USERNAME=admin
DB_PASSWORD=[PASSWORD]  ← これが OS ユーザーでも使われている可能性（タイポのある弱パスワードが設定されているケースも実際には多い）
APP_KEY=base64:...               ← アプリの暗号化キー
```

### 手順

```bash
# カレントディレクトリのWebルートを確認
ls -la /var/www/html/

# .env の中身を確認
cat /var/www/html/.env

# 取得したパスワードを /etc/passwd のユーザーに対して試す
cat /etc/passwd | grep "/home"
# → ホームディレクトリを持つOSユーザーを確認
su [USERNAME]
# パスワードに .env の DB_PASSWORD 等を入力
```

### 注意点・落とし穴
- `.env` はデフォルトで隠しファイル（`.` 始まり）のため、`ls` だけでは見えない。`ls -la` で確認する
- DB_PASSWORD と OSユーザーのパスワードが同一になっているのは設定ミス（パスワード使い回し）だが、実際に多い
- `.env` が見つからない場合は `config.php`, `database.yml`, `appsettings.json`, `docker-compose.yml` 等も確認する
- アプリケーションによっては `.env.production` / `.env.local` 等の派生ファイルが存在する
- → 取得した認証情報の確認手順：このファイル末尾「認証情報を取得したら必ず試すこと」を参照

---

## パターン8: Bundler 設定ファイル（`.bundle/config`）からの認証情報取得

### 着火条件
- Ruby / Rails アプリのサーバープロセス（`ruby`, `unicorn`, `puma` 等）としてシェルが取れた
- ホームディレクトリに `.bundle/` ディレクトリが存在する

### 観点・着眼点

`.bundle/config` は Bundler（Ruby のパッケージ管理ツール）の設定ファイルで、**プライベート Gem リポジトリへの認証情報がBASIC認証の形式（username:password）で平文保存されていることがある。**

シェルを取得したユーザーのホームディレクトリを確認する際に `.bundle/` ディレクトリが見えたら必ず開く。**OS ユーザーのパスワードが RubyGems の認証情報として使い回されているケースが典型的。**

```bash
# [Target] ホームディレクトリの確認
ls -la ~
# .bundle/ が存在したら次を確認する

cat ~/.bundle/config
```

**出力例：**
```yaml
---
BUNDLE_HTTPS://RUBYGEMS__ORG/: "[USER]:[PASSWORD]"
```

フォーマット説明：
- キー部分 `BUNDLE_HTTPS://RUBYGEMS__ORG/` → RubyGems.org へのHTTPS接続用認証
- 値 `"[USERNAME]:[PASSWORD]"` → `USERNAME:PASSWORD` の形式で平文保存
- ダブルアンダースコア (`__`) はURLの `.`（ドット）を表すBundlerのエスケープ規則

**取得した認証情報の確認：**

- `[USERNAME]` が OS ユーザー名と一致する場合、`[PASSWORD]` が OS ユーザーのパスワードである可能性が高い
- `su [USERNAME]` または `ssh [USERNAME]@[HOST]` で試す

### 手順

```bash
# [Target] 現在のユーザーのホームディレクトリ確認
ls -la ~/

# [Target] .bundle/config があれば内容を確認
cat ~/.bundle/config

# [Target] 他ユーザーのホームディレクトリも確認（権限があれば）
ls -la /home/
for user in $(ls /home/); do echo "=== $user ==="; cat /home/$user/.bundle/config 2>/dev/null; done

# [Target] 取得したパスワードで別ユーザーに su
su [TARGET_USER]
# パスワードに取得した値を入力
```

### 注意点・落とし穴
- `.bundle/` ディレクトリはデフォルトで `ls -la` の結果に出るが、最初の `ls` （引数なし）では見えない。**必ず `ls -la` で確認する**
- ファイルの権限が `r-xr-xr-x`（グループ・ワールド読み取り可能）であっても内容は見えるため、ほかのユーザーのファイルも試す
- RubyGems のパスワードと OS ユーザーのパスワードが一致しないこともある。その場合は他の認証情報探索を続ける
- → 取得した認証情報の確認手順：このファイル末尾「認証情報を取得したら必ず試すこと」を参照

---

---

## パターン9: KeePass データベース（.kdbx）のクラック

### 着火条件

ターゲットのファイルシステム上（デスクトップ・Documents・共有フォルダ等）に **`.kdbx` ファイル**（KeePass パスワードマネージャーのデータベース形式）が存在する場合。マスターパスワードをクラックできれば、データベース内に保存された全サービスの認証情報にアクセスできる。

**攻撃者の思考トレース：** パスワードマネージャーは「認証情報の集約ポイント」。マスターパスワードが弱ければ、一度クラックするだけで多数のサービスへのアクセスを得られる。優先度の高い発見物。

### 環境前提

- 実行環境: テスター端末
- 必要なツール:
  - `keepass2john`（JohnTheRipper に同梱。ペネトレ用Linuxディストリ標準搭載）
  - `john` / `hashcat`（ペネトレ用Linuxディストリ標準搭載）
  - `kpcli` または `keepassxc`（データベースの内容確認用。オプション）
- オフライン代替: hashcat は単体で動作。john は wordlist があればオフラインで動作

### 観点・着眼点

**先に確認すること：** `.kdbx` ファイルはターゲットから直接開けない場合が多い（マスターパスワード・キーファイルが必要）。まずファイルをテスター端末に転送してからクラックする。

**KeePass 認証方式の種類と難易度：**

| 認証方式 | 説明 | クラック可否 |
|---------|------|------------|
| マスターパスワードのみ | パスワード単体で保護 | クラック可能（keepass2john → hashcat）|
| パスワード + キーファイル | キーファイルも必要 | キーファイルも入手できれば可能 |
| Windows ユーザーアカウント認証 | Windows 資格情報が必要 | 難易度高（その Windows ユーザーとして実行が必要）|

**何が出たら次に何をするか：**

| 状況 | 次のアクション |
|------|--------------|
| マスターパスワードがクラックできた | データベース内の全エントリを確認 → SSH・Web・サービスの認証情報を取得 |
| クラック時間が非現実的（数日以上） | 別の経路でマスターパスワードを探す（note.txt・設定ファイル・メール・メモリダンプ）|
| `.kdbx` のバージョンが古い（KeePass 1.x → `.kdb`）| `keepass2john` は `.kdb` も対応 |

### 手順

**Step 1: ターゲットからファイルを転送する**

```bash
# [Target → Attacker] certutil でBase64エンコードしてから転送（Windows シェルの場合）
certutil -encode C:\Users\[USER]\Desktop\credentials.kdbx C:\Temp\credentials.b64

# [Attacker] テスター端末でデコード
cat credentials.b64 | base64 -d > credentials.kdbx
# または
base64 -d < credentials.b64 > credentials.kdbx
```

**Step 2: keepass2john でハッシュを抽出する**

```bash
# [Attacker]
keepass2john credentials.kdbx > keepass_hash.txt
cat keepass_hash.txt
# → credentials:$keepass$*2*[iterations]*[salt]*[hash]... の形式が出力される
```

**Step 3: hashcat / john でマスターパスワードをクラックする**

```bash
# [Attacker] hashcat（GPU使用、高速）
# mode 13400 = KeePass（KDBX 3.1 / 4.0 両対応。4.0 系は AES-256 + HMAC-SHA256 構成で
# 同じ 13400 モードで扱えることが多いが、バージョンによって挙動差があるため
# keepass2john の出力 prefix（$keepass$*2* = 3.1 / $keepass$*4* = 4.0）で確認する）
hashcat -m 13400 keepass_hash.txt /usr/share/wordlists/rockyou.txt

# [Attacker] john（CPU使用）
john --wordlist=/usr/share/wordlists/rockyou.txt keepass_hash.txt
john --show keepass_hash.txt   # クラック済みパスワードの確認
```

**Step 4: データベースの内容を確認する**

```bash
# [Attacker] kpcli（CLI ツール）でデータベースを開く
# インストール: sudo apt install kpcli
kpcli --kdb=credentials.kdbx
# → マスターパスワードのプロンプトが出る → クラックしたパスワードを入力
# データベース内コマンド:
#   ls           - エントリ一覧
#   cd [path]    - フォルダ移動
#   show [entry] - エントリの詳細（パスワード含む）表示
#   quit         - 終了

# または KeePassXC（GUI）でも同様に開ける
```

**Step 5: 取得した認証情報を試す**

データベース内の各エントリを確認し、ユーザー名・パスワード・URL を記録する。  
→ このページ末尾「認証情報を取得したら必ず試すこと」に進む。

### 刺さらなかったとき

| 状況 | 対処 |
|------|------|
| wordlist でクラックできない | カスタム wordlist を試す（`hashcat -r rules/best64.rule`）または別経路でマスターパスワードを探す（ターゲットのホームディレクトリ・メール・note.txt 等）|
| `keepass2john` がエラーになる | `.kdbx` が破損している可能性。別の `.kdbx` ファイルが存在しないか探す |
| キーファイル `.key` が必要と表示される | `keepass2john` にキーファイルも渡す: `keepass2john -k [keyfile] credentials.kdbx` |

### 注意点・落とし穴

- クラックに失敗した場合でも、ターゲット内を探索して **マスターパスワードをメモした別ファイル（note.txt / readme.txt 等）** が存在する可能性がある。探索を先に行ってもよい
- KeePass のマスターパスワードは長い・複雑なケースが多く、簡単な wordlist ではクラックできないことがある。時間の読みが重要
- 取得した認証情報は必ず暗号化保管し、テスト完了時に破棄する（本番）

---

## 認証情報を取得したら必ず試すこと

**パスワードの使い回し確認：**
取得した認証情報は、判明している**全てのサービス**で試す。

| 試すサービス | コマンド |
|------------|---------|
| SSH | `ssh [USER]@[IP]` |
| SMB | `smbclient -L //[IP] -U '[USER]%[PASS]'` |
| WinRM | `evil-winrm -i [IP] -u [USER] -p '[PASS]'` |
| FTP | `ftp [IP]` → ユーザー/パスを入力 |
| Web管理画面 | ブラウザで手動ログイン試行 |

**複数ユーザーへのスプレー：**
1つのパスワードが複数のユーザーに使われていることもある。
```bash
netexec smb [IP] -u users.txt -p '[PASSWORD]' --continue-on-success
```

---

## 関連技術
- 前：PCAP から FTP 認証情報 → 同じ認証情報を SSH で試す（`./FTP.md` §6 + `./SSH.md`）
- 関連：取得した認証情報を SSH で試す前に、SSH の対応認証方式を確認（`publickey` のみなら password cred は通らない） → `./SSH.md`
- 前：LDAP認証情報でLDAPにアクセス → `../01_Reconnaissance/LDAP_Enumeration.md`
- 前：バイナリから認証情報 → `./Binary_Analysis.md`
- 前：Webアプリのファイル読み取りでDBを取得 → `./Web_Vulnerabilities/Path_Traversal.md`
- 前：`.env` / `.git/` / `.htpasswd` / Spring actuator/env / heapdump 等の誤公開から認証情報を取得した直後 → `../01_Reconnaissance/Exposed_Files.md`
- 前：GPP cpassword の取得手順 → `../01_Reconnaissance/SMB_Enumeration.md`（GPP セクション）
- 後：Grafana ハッシュのクラック → `../05_Tools_Reference/Hashcat.md`
- 後：取得したパスワードを使ったsudo悪用（YAML.load） → `../03_Post_Access_Linux/Sudo_Misconfig.md`（パターン5）
- 後：取得した認証情報を製品管理画面のデフォルト試行と組合せて他システムへ展開 → `./Default_Credentials.md`
- 後：取得済みパスワードの使い回し確認スプレー前にロックアウトポリシーを取得し試行設計を組む → `./Account_Lockout_Recon.md`
- 後：取得した cred / 秘密鍵を SSH で試行（認証突破・秘密鍵パスフレーズクラック・制限シェル脱出） → `./SSH.md`
- 参照：GPP cpassword の動作原理（AES 鍵公開・MS14-025） → `../06_Concepts/GPP_Credential.md`
