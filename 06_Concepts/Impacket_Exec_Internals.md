# Impacket exec ツール群の動作原理（DCERPC / DCOM / SCM / ATSvc）

## このファイルの位置づけ

参照元の作業ファイル：

- [`../02_Initial_Access/Impacket_Exec.md`](../02_Initial_Access/Impacket_Exec.md)（wmiexec / psexec / smbexec / atexec / dcomexec の 5 経路）
- [`../00_Playbook/Windows_AD_Attack_Flow.md`](../00_Playbook/Windows_AD_Attack_Flow.md)（Step 4 以降の Windows 接続経路選択）
- [`../05_Tools_Reference/Impacket_Suite.md`](../05_Tools_Reference/Impacket_Suite.md)（Impacket スイート全体）

Impacket exec の作業手順を実行している最中に「なぜ psexec はバイナリを置くのに smbexec は置かないのか」「なぜ atexec だけ 135 のみで通るのか」「なぜ Kerberos の SPN プレフィックスがツールによって変わるのか」「dcomexec はなぜ EDR 検知を回避できるのか」が分からなくなったときに開く。手順そのものは作業ファイル側に置き、ここでは挙動の根拠だけを扱う。

> **出典について:** 本文中で「Microsoft MS-DCOM / MS-RPCE / MS-SCMR 等のプロトコル仕様」を引用するが、**URL は記憶から書かない**。実引用時は MS-DCOM (DCOM Remote Protocol) / MS-RPCE (Remote Procedure Call Protocol Extensions) / MS-SCMR (Service Control Manager Remote Protocol) / MS-TSCH (Task Scheduler Service Remoting Protocol) / MS-WMI (Windows Management Instrumentation Remote Protocol) 等を `WebFetch` で確認すること。本ファイルは「挙動レベルでなぜそうなるか」を整理するもので、規格条文を厳密に追うものではない。

---

## 1. DCERPC とは — Windows のリモート関数呼出機構

### 1.1 一言で何か

**DCERPC = Distributed Computing Environment / Remote Procedure Call の Microsoft 実装**。Windows のさまざまな機能（サービス制御・タスクスケジューラ・WMI・ファイル共有制御など）が「DCERPC インターフェース」として公開されており、ネットワーク経由で関数呼出できる。

SMB が「ファイルとパイプの共有プロトコル」なら、DCERPC は「機能呼び出しプロトコル」。**Impacket exec は 5 ツールとも最終的に DCERPC を叩いている**（叩いているインターフェースが違うだけ）。これが「同じ cred / `-hashes` / `-k -no-pass` オプションがツール横断で効く」根拠でもある。

### 1.2 接続フローは二段構え（135 → 動的ポート）

DCERPC の典型的な接続は 2 ステップ：

```
[Step 1] クライアント → ターゲット TCP 135 (Endpoint Mapper)
         「svcctl インターフェースのポート教えて」
         ↓
         「49664 を使え」と回答

[Step 2] クライアント → ターゲット TCP 49664 (動的ポート)
         本体の DCERPC 呼出（CreateServiceW など）
```

- **TCP 135 (Endpoint Mapper / EPM)** は固定。「どのインターフェースがどのポートにいるか」の名前解決サービス
- **動的ポート（49152-65535）** は Windows 起動時にランダム割当。各サービスが自分のポートを EPM に登録

これが手順ファイル §3 で `wmiexec` 失敗時に `RPC_E_DISCONNECTED` が出る根本原因 — Step 1（135）は通っても Step 2 の動的ポートが FW でブロックされていると、EPM が返したポートに繋げず接続が切れる。

### 1.3 SMB パイプ経由の DCERPC（135 を使わない経路）

DCERPC は TCP 直接接続だけでなく **SMB の名前付きパイプ経由** でも呼べる：

```
クライアント → ターゲット TCP 445 (SMB)
            → \\[TARGET]\IPC$\svcctl  (名前付きパイプ)
            → 中身は DCERPC で CreateServiceW を呼ぶ
```

この経路では **EPM (135) を使わず 445 だけで完結する**。Impacket の `psexec` / `smbexec` はこの SMB パイプ経由で svcctl を叩く。**動的ポートが不要なので FW が緩い**ことも実用上のメリット。

`atexec` も同様に SMB パイプ経由（`\PIPE\atsvc`）で Task Scheduler RPC を叩くため「135 のみで通る」「逆に 445 のみでも通る」状況になる。**「TCP 135 開放確認」と「実際に DCERPC が呼べるか」は別問題**であることに注意。

### 1.4 DCERPC の認証 — 内部で NTLM / Kerberos が動いている

DCERPC リクエストは「**バインド時に認証する**」モデル：

1. クライアントが `BIND` パケットで「このインターフェースに繋ぎたい」と宣言
2. このとき SPNEGO 経由で NTLM または Kerberos の認証データが乗る
3. サーバが認証成功と判断したら `BIND_ACK` を返してセッション確立
4. その後の `REQUEST` パケットは認証済みコンテキストで処理

これが Impacket exec の全ツールで `-hashes` (Pass-The-Hash) や `-k -no-pass` (Kerberos) が共通で使える理由。**認証層は DCERPC 共通**で、上に乗るインターフェース（svcctl / WMI / atsvc / DCOM）が違うだけ。

> **環境が変わったとき:** SMB signing が強制（`signing:True`）でも DCERPC over SMB は通る。signing は中間者改ざん（Relay 攻撃）への防御であり、cred 自体を持っている攻撃者には影響しない。

---

## 2. 5 ツール × DCERPC インターフェース対応表

各 Impacket exec ツールが「何の DCERPC インターフェースを呼んで」「何を Windows にやらせるか」をまとめると：

| ツール | DCERPC インターフェース | プロトコル仕様 | やらせること |
|---|---|---|---|
| **wmiexec** | `IWbemServices` (WMI) on DCOM | MS-WMI / MS-DCOM | `Win32_Process.Create` で `cmd.exe /Q /c [COMMAND]` を起動 |
| **psexec** | `svcctl` (SCM = Service Control Manager) | MS-SCMR | ADMIN$ に PE 投下 → サービス作成 → 起動 → IPC$ パイプで stdin/stdout 中継 |
| **smbexec** | `svcctl` (同上) | MS-SCMR | サービスバイナリ自体を `cmd.exe /Q /c [COMMAND] > 出力ファイル` にする（PE 投下なし） |
| **atexec** | `atsvc` / `ITaskSchedulerService` | MS-TSCH | 即時実行タスク作成 → 実行 → 自動削除 |
| **dcomexec** | `MMC20.Application` 等の **既存 DCOM オブジェクト** | MS-DCOM | 既に Windows に登録されている COM オブジェクトの公開メソッドを叩く |

**構造的に重要なグルーピング:**

- **psexec と smbexec は同じ DCERPC インターフェース (`svcctl`)** を使う。違うのは「サービスバイナリに何を指定するか」だけ — psexec は外部 PE、smbexec は cmd.exe 直叩き
- **wmiexec と dcomexec は同じ DCOM 層**を使う。違うのは「どの DCOM オブジェクトを叩くか」だけ — wmiexec は WMI (`IWbemServices`)、dcomexec は MMC20.Application などの汎用 COM オブジェクト
- **atexec はタスクスケジューラ API を叩く** ため上記グループとは独立。タスク登録時に「実行ユーザ = SYSTEM」を指定できる

このグルーピングを押さえておくと「psexec が Defender で焼かれたら smbexec で代替できる（同じ svcctl だから）」「wmiexec が DCOM 動的ポートで詰まったら dcomexec も詰まる（同じ DCOM だから）」という代替経路選択の根拠が分かる。

---

## 3. DCOM とは — DCERPC との関係、WMI と dcomexec の親

### 3.1 COM と DCOM の関係

- **COM (Component Object Model)**: Windows のオブジェクト指向 IPC 基盤。アプリケーションが「メソッドを公開したオブジェクト」を提供し、別のアプリがそのメソッドを呼ぶ
- **DCOM (Distributed COM)**: COM をネットワーク越しに使える拡張。**通信路は DCERPC**

DCOM は DCERPC の上に乗っているレイヤで、「リモートホスト上の COM オブジェクトのメソッドを呼ぶ」ためのプロトコル。WMI も、MMC20.Application も、ShellWindows も、すべて DCOM で公開された COM オブジェクト。

### 3.2 接続フロー（DCOM Activation）

```
[Step 1] クライアント → ターゲット 135 (EPM)
         「IRemoteSCMActivator のポート教えて」
[Step 2] クライアント → IRemoteSCMActivator
         「CLSID=49B...（MMC20.Application）のインスタンス作って」
[Step 3] サーバ側: クライアントの認証情報でホストプロセスを起動
         （mmc.exe / wmiprvse.exe / explorer.exe 等）
[Step 4] サーバ → クライアント
         「動的ポート 49xxx で Object Reference 待ってる」
[Step 5] クライアント → 動的ポート
         オブジェクトのメソッドを DCERPC で呼出
```

これが手順ファイル §3 で「**`wmiexec` は DCOM 動的ポート (49152-65535) を使う**」と書かれている根拠。Step 4 で割当てられる動的ポートが FW でブロックされていると Step 5 で詰まる。

### 3.3 WMI = DCOM オブジェクトとして公開される管理機能

WMI (Windows Management Instrumentation) は CIM (Common Information Model) を Windows で実装したもの。**WMI クエリは DCOM 経由で `IWbemServices` インターフェースを呼ぶ**ことで実行される。

`Win32_Process.Create` は WMI クラスのメソッド：

- ローカル: `Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe"`
- リモート（wmiexec の本質）: 上記を **DCOM 経由でリモートホストの WMI サービスに対して実行**

つまり wmiexec は「ローカルで誰でもやる `Win32_Process.Create` を DCOM 越しに叩いているだけ」で、悪意の固有プロトコルは何も使っていない。**WMI の正規機能を遠隔で利用しているに過ぎない** → これが「ファイルレス」「正常運用に紛れる」性質の根拠。

### 3.4 dcomexec は「既存 DCOM オブジェクトの流用」

wmiexec が `IWbemServices` を叩くのに対し、dcomexec は **Windows に既に登録されている別の DCOM オブジェクト** を叩く：

| DCOM オブジェクト | 用途（本来）| 攻撃で叩くメソッド | ホストプロセス |
|---|---|---|---|
| `MMC20.Application` | MMC スナップイン管理 | `Document.ActiveView.ExecuteShellCommand` | `mmc.exe` |
| `ShellWindows` | Explorer の Window 列挙 | `Item().Document.Application.ShellExecute` | `explorer.exe` |
| `ShellBrowserWindow` | Explorer の Browser | `Document.Application.ShellExecute` | `explorer.exe` |

これらは「Windows の GUI ユーティリティが本来内部で使うため」に登録されている COM オブジェクトで、**たまたまリモートからも呼べるメソッドを公開している**。Impacket はこの仕様を流用してプロセス起動経路にしている。

**MMC20 が Windows 10 1803+ で既定無効化された理由**は、`ExecuteShellCommand` がリモート呼出可能なまま放置されていたことが lateral movement に悪用されたため。Microsoft が DCOM permission を絞ったが、`ShellWindows` / `ShellBrowserWindow` は GUI 連動の用途で残されている（ただし対話セッションのユーザがログイン中でないとホストプロセスが立たないため安定しない）。

---

## 4. SCM (svcctl) — psexec と smbexec の差はどこで生まれるか

### 4.1 SCM とは

**SCM (Service Control Manager)** = Windows のサービス管理機構。`services.msc` で見える「サービス一覧」を管理しているプロセス（実体は `services.exe`）。

リモートからは **`svcctl` DCERPC インターフェース** (MS-SCMR) で操作できる：

- `CreateServiceW` — サービス新規作成
- `StartServiceW` — サービス起動
- `OpenServiceW` — 既存サービスのハンドル取得
- `DeleteService` — サービス削除

psexec / smbexec はこの API シーケンスで動く。**SYSTEM 権限取得は SCM の正規機能** — 作成したサービスは既定で `LocalSystem` アカウントで起動するため、`CreateServiceW` を呼べた時点で SYSTEM コマンド実行が確定する。

### 4.2 psexec の処理フロー

```
1. SMB 445 経由で ADMIN$ 共有に接続
2. ADMIN$ (=C:\Windows\) に PE バイナリ (RemComSvc.exe 相当) を書き込む
3. svcctl::CreateServiceW で「サービスバイナリ = ADMIN$\RemComSvc.exe」のサービスを登録
4. svcctl::StartServiceW でサービス起動
5. サービスが SYSTEM 権限で動き、名前付きパイプ (\\.\pipe\RemCom_*) を作る
6. クライアントが IPC$ 経由でそのパイプに接続 → stdin/stdout を中継
7. 切断時: svcctl::ControlService (STOP) → DeleteService → PE 削除
```

**`RemComSvc.exe` の役割**: 「サービスバイナリ」として登録されるが、実態は「名前付きパイプ経由で受け取ったコマンドを cmd.exe / powershell.exe で実行して結果を返す常駐型ヘルパー」。対話シェルが取れるのはこの中継があるため。

### 4.3 smbexec の処理フロー（PE 不要の代替）

```
1. SMB 445 経由（同じ）
2. PE バイナリの書込なし
3. svcctl::CreateServiceW で「サービスバイナリ = cmd.exe /Q /c [COMMAND] > \\127.0.0.1\C$\__output 2>&1」を登録
   ← サービスバイナリ自体が cmd.exe の起動コマンドライン
4. svcctl::StartServiceW でサービス起動 → サービスとして cmd.exe が起動 → コマンド実行 → 即終了
5. クライアントが C$\__output を読み取って結果取得
6. コマンドごとに 3-5 を繰り返す（毎回サービス再作成）
```

**サービスバイナリ欄に直接 cmd.exe を仕込める**のが smbexec の核心。Windows の SCM は「サービスバイナリパス」に任意のコマンドライン（引数付き）を許容するため、`cmd.exe /c [COMMAND]` を仕込めば PE を別途置く必要がない。

### 4.4 psexec vs smbexec の比較

| 観点 | psexec | smbexec |
|---|---|---|
| PE バイナリ書込 | あり（ADMIN$ に投下）| なし |
| 対話シェル | あり（パイプ経由で stdin/stdout 中継）| なし（毎回独立 cmd で stdin 不可・cwd 引継ぎなし）|
| Event 7045 発生回数 | セッション開始時 1 回 | **コマンドごとに 1 回** |
| Defender 検知 | RemComSvc.exe シグネチャで焼かれやすい | バイナリなしだが Event 7045 大量発生で「サービス連続作成」異常として検知 |
| サービス残骸リスク | 接続切断時の cleanup 失敗で残る | 各コマンド完了で削除（残骸リスクは低い）|

**「ファイルレスだが検知性は smbexec の方が高い」のパラドックス**: Event 7045 はファイルベース検知より時系列検知の方が強いシグナル。100 コマンド実行 = サービス作成 100 件 → Service Control Manager の異常として確実に拾われる。

### 4.5 LocalAccountTokenFilterPolicy の罠 — psexec の `STATUS_ACCESS_DENIED`

ローカル管理者で接続したときに `STATUS_ACCESS_DENIED` が出る現象。原因は **UAC リモート制限**：

- Windows Vista+ で導入された UAC は、**ローカル管理者のリモート接続時に管理者トークンを剥奪**する（既定動作）
- ローカル管理者で SMB 接続できても、`CreateServiceW` を呼ぶ権限がない（標準ユーザートークンに降格されているため）
- レジストリ `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy = 1` で無効化可能（攻撃側からは設定不可だが、ドメイン管理者なら通る）

**ドメイン管理者は別ロジックで処理される**ためこの制限を受けない。psexec で「ローカル管理者は失敗するがドメイン管理者は通る」現象の根拠。

---

## 5. atsvc / Task Scheduler — なぜ 135 のみで通るのか

### 5.1 Task Scheduler の 2 系統 API

タスクスケジューラのリモート API は歴史的に 2 系統：

| API | プロトコル仕様 | 由来 |
|---|---|---|
| `atsvc` (旧 AT サービス) | MS-TSCH §3.1（古い AT サブセット） | Windows NT 系の `at.exe` の RPC バックエンド |
| `ITaskSchedulerService` (新 V2 API) | MS-TSCH §3.2 | Windows Vista+ の `schtasks.exe` / `Task Scheduler 2.0` GUI |

`impacket-atexec` は環境に応じて両者を試す。**`ITaskSchedulerService` が新 OS で標準**、`atsvc` は廃止傾向（Server 2012+ で既定無効・要 schtasks 経由）だが、Impacket 側で複数経路を持つ。

### 5.2 接続経路 — SMB パイプ経由が主

Task Scheduler の RPC は **`\PIPE\atsvc`** という名前付きパイプを通る：

```
クライアント → ターゲット 445 (SMB)
            → IPC$ に接続
            → \\[TARGET]\IPC$\atsvc を open
            → 中身は DCERPC で ITaskSchedulerService::SchRpcRegisterTask 等を呼ぶ
```

**135 (EPM) は不要**（パイプ名でインターフェースが解決されるため）。これが手順ファイル §6 で「135 のみで通る」と書かれている根拠 — 正確には「135 を使わず 445 のみで通る」のだが、ポート列挙の文脈では「**445 と 135 のどちらか一方さえあれば動く**」と理解しておく。

### 5.3 タスク実行ユーザ = SYSTEM が既定

`ITaskSchedulerService::SchRpcRegisterTask` で登録するタスク XML には `<Principal>` で実行ユーザを指定できる。**Impacket は既定で `S-1-5-18` (LocalSystem)** を指定するため、登録さえできれば SYSTEM 権限実行が確定する。

タスク登録権限自体は「Administrators メンバーなら可能」が既定。一般ユーザは自分のタスクしか登録できない。これが手順ファイル §6 で `(Pwn3d!)` が前提となる根拠。

### 5.4 atexec の痕跡 — Task Scheduler ログ

- **`Microsoft-Windows-TaskScheduler/Operational`** イベントログに以下が時系列で残る:
  - Event 106: タスク登録
  - Event 200: タスク開始
  - Event 201: タスク完了（終了コード付）
  - Event 141: タスク削除
- タスク自体は実行後に自動削除されるが、**ログは残る**。`schtasks /query` では見えないが Event Viewer には記録
- タスク名はランダム生成（`ojvbhasdf` 等）→ 識別性のため `-task-name kedalab-[CASE_ID]` で名前を付けるのが原状回復確認上有用

---

## 6. プロセスツリーの差 = 検知シグネチャの差

各ツール接続時にターゲット側で立つプロセスツリーを並べると、EDR シグネチャの違いが見える。

### 6.1 wmiexec

```
services.exe
 └── svchost.exe -k DcomLaunch (DCOM Server Process Launcher)
      └── wmiprvse.exe (WMI Provider Host)
           └── cmd.exe /Q /c [COMMAND] 1>\\127.0.0.1\ADMIN$\__[TIMESTAMP] 2>&1
```

- 親プロセスは `wmiprvse.exe` で固定
- **Sysmon Event ID 1 で `wmiprvse.exe → cmd.exe` が検知の典型シグネチャ**
- WMI ログ (`Microsoft-Windows-WMI-Activity/Operational`) に `Win32_Process::Create` の呼出が記録される

### 6.2 psexec

```
services.exe
 └── RemComSvc.exe (or -remote-binary-name 指定名)  ★ADMIN$ から起動された PE
      └── cmd.exe / powershell.exe (中継先)
           └── 実行コマンド
```

- Event 7045（サービスインストール）+ 4697（同）で **確実に検知**
- `services.exe → 未署名 PE` の親子関係は EDR の最も汎用的なシグネチャ
- ファイル設置の痕跡: `\\[TARGET]\ADMIN$\[SERVICE_NAME].exe`（cleanup 失敗時の残骸）

### 6.3 smbexec

```
services.exe
 └── cmd.exe /Q /c [COMMAND] > \\127.0.0.1\C$\__output 2>&1  ★サービスバイナリ自体が cmd.exe
      → 出力ファイルに書込んで即終了
```

- **コマンドごとに Event 7045 発生**（最大の検知ノイズ）
- `services.exe → cmd.exe` 親子関係は「正規サービスが cmd.exe を直接子に持つ」異常パターン
- 出力ファイル `\\[TARGET]\C$\__output` の連続書込も Sysmon Event ID 11（FileCreate）で検知

### 6.4 atexec

```
svchost.exe -k netsvcs (Task Scheduler)
 └── cmd.exe / powershell.exe / 指定コマンド
      └── 出力を ADMIN$\__[OUTPUT] に書込
```

- **`svchost.exe -k netsvcs` を親に持つ短命の cmd.exe** が典型シグネチャ
- Task Scheduler ログに登録・実行・削除が一連で残る → 「短期間に登録→実行→削除されるタスク」は SOC 監視ルールの定番

### 6.5 dcomexec

```
mmc.exe (MMC20.Application 経由の場合)
 or explorer.exe (ShellWindows / ShellBrowserWindow 経由)
 or iexplore.exe
  └── cmd.exe / powershell.exe / 実行コマンド
```

- **親プロセス偽装効果** = `wmiprvse.exe` でも `services.exe` でもない
- 「`wmiprvse.exe → cmd.exe`」を見ている汎用シグネチャを回避できる
- ただし「`mmc.exe → cmd.exe`」自体も別の異常パターン（mmc.exe は通常 .msc を読むだけで cmd.exe を呼ばない）
- Defender ASR ルール「Block process creations originating from PSExec and WMI commands」が有効だと DCOM 経路も巻き添えで検知される

### 6.6 検知ノイズの順序

「ファイルレス度・検知性の低さ」の順序（少ない → 多い）：

```
wmiexec < dcomexec < atexec < smbexec < psexec
```

- **wmiexec**: 親 wmiprvse.exe は WMI の正規プロセス。WMI ログを見られていなければ最も静か
- **dcomexec**: 親プロセスが mmc.exe / explorer.exe で偽装される。WMI ログには出ない
- **atexec**: 単発タスクで終わるが Task Scheduler ログに記録
- **smbexec**: Event 7045 がコマンドごとに大量発生
- **psexec**: Event 7045 + PE ファイル設置 + サービス DELETE が定型シグネチャ

---

## 7. Kerberos SPN プレフィックスの差 — cifs/ vs host/

### 7.1 SPN とは（Kerberos の宛先指定）

Kerberos の Service Ticket は「**どのサービスにアクセスするか**」を SPN (Service Principal Name) で指定する。SPN の形式：

```
[SERVICE_CLASS]/[HOSTNAME(or FQDN)][:port]
```

例: `cifs/dc01.example.local`、`host/srv02.example.local`、`HTTP/web.example.local`

SPN は AD の `servicePrincipalName` 属性に登録されており、クライアントの TGS-REQ で要求された SPN が見つからないと `KDC_ERR_S_PRINCIPAL_UNKNOWN` でチケット発行失敗。

### 7.2 サービスクラス別の意味

| サービスクラス | 何のサービス | 既定で登録されているか |
|---|---|---|
| `cifs/` | **SMB ファイル共有サービス**（C$ / ADMIN$ / IPC$ 等）| ドメイン参加コンピュータには既定で登録 |
| `host/` | 汎用ホストサービス（DCERPC・WMI・Task Scheduler 等）| 既定で登録（コンピュータアカウントに自動付与）|
| `HTTP/` | HTTP/HTTPS サービス（IIS・WinRM・WSDAPI 等）| WinRM 有効化時に登録 / IIS が SPN 登録すれば自動 |
| `LDAP/` | DC の LDAP サービス | DC に既定登録 |
| `MSSQLSvc/` | SQL Server | SQL 起動アカウントが自動登録（要権限）|

### 7.3 ツール別 SPN プレフィックスの根拠

| ツール | 必要 SPN | 理由 |
|---|---|---|
| psexec | `cifs/[FQDN]` | **ADMIN$ 共有に PE を書き込む** → SMB アクセスが必要 → `cifs/` |
| smbexec | `cifs/[FQDN]` | 同上（C$ への出力受領で SMB アクセス必要）|
| wmiexec | `host/[FQDN]` | DCOM 経由で WMI を叩く → DCOM ホストサービス全般を覆う `host/` |
| atexec | `host/[FQDN]` | Task Scheduler は host/ で受理（SMB パイプ経由でも認証は `host/` でカバー）|
| dcomexec | `host/[FQDN]` | DCOM 経由 → `host/` |

**`cifs/` と `host/` を分けている理由**: Kerberos の設計思想として「SMB ファイル共有」と「その他のホスト管理」は別サービスとして扱われる（権限の分離原則）。あるホストで SMB は許可するが WMI は許可しない、といった粒度を担保するため。実運用ではドメイン参加コンピュータは両方持つので意識する場面は少ないが、**Read-Only DC や監査用サーバ等で `cifs/` を意図的に外している**環境では psexec / smbexec が失敗して wmiexec は成功する、というレア状況が起きる。

### 7.4 `KRB_AP_ERR_MODIFIED` が出る根本

IP 直打ちで接続すると Kerberos クライアントは「SPN として `cifs/192.0.2.10` を要求しようとする」が、AD には IP ベースの SPN が登録されていない（**ホスト名/FQDN ベースのみ**）→ KDC が見つけられず失敗 → クライアントが代替として「IP の逆引き → FQDN 解決」を試みるが、ローカルに DNS 解決手段がないと最終的に MODIFIED エラーになる。

回避: `/etc/hosts` で `[IP] [FQDN]` を登録 → クライアントが正しい SPN `cifs/[FQDN]` を構築できる。詳細は [`Hosts_File_For_AD.md`](Hosts_File_For_AD.md) §1。

### 7.5 SPN 列挙 — 何が登録されているかの確認

侵入後に確認するなら：

```cmd
setspn -L [HOSTNAME]              :: 特定ホストの登録 SPN
setspn -T [DOMAIN] -Q */*          :: ドメイン全体の SPN
```

`cifs/` が無いコンピュータには psexec / smbexec で Kerberos 接続できない。

---

## 8. WinRM との対比

WinRM ([`WinRM_Protocol.md`](WinRM_Protocol.md)) と Impacket exec は「Windows へのリモート対話シェル取得」という同じポジションを占めるが、設計が根本的に違う。

| 観点 | WinRM | Impacket exec（代表: wmiexec）|
|---|---|---|
| トランスポート | HTTP/HTTPS (5985/5986) | DCERPC (135 + 動的、または SMB 445)|
| プロトコル層 | SOAP over HTTP → PSRP | DCERPC → DCOM / SCM / atsvc |
| 認証 negotiation | WWW-Authenticate ヘッダで明示 | DCERPC BIND 内で SPNEGO |
| 検知中心 | `wsmprovhost.exe` プロセスツリー | ツールごとに変化（§6 参照）|
| SPN プレフィックス | `HTTP/[FQDN]` 固定 | `cifs/` または `host/`（ツール別）|
| 二重ホップ問題 | あり（Kerberos delegation 全般の話）| あり（同じ Kerberos 委任の話）|
| ファイル設置 | なし | psexec のみあり / その他なし |
| サービス作成 | なし | psexec / smbexec のみあり / その他なし |
| 対話シェル | 完全対話（PSSession）| 半対話（wmiexec）/ 完全対話（psexec のパイプ）/ 非対話（smbexec / atexec / dcomexec）|
| 「侵入後最初の対話シェル経路」推奨度 | ◎ ネイティブ・痕跡少 | ○ WinRM 不可時の代替 |

### 8.1 接続経路の選択原則

手順ファイル冒頭で「WinRM が開いていれば WinRM を優先」と書いている根拠：

- WinRM は **MS 純正クライアント (`Enter-PSSession`) が同じプロトコル**を使う → 正常運用に紛れる
- Impacket exec は **外部ツール（Impacket）固有のシグネチャ**が乗る（特に psexec の `RemComSvc.exe`）
- WinRM の `wsmprovhost.exe` は単一プロセスで管理しやすいが、Impacket はツール別にプロセスツリーが変わるため SOC の検知ルールが複雑になる

しかし WinRM が閉じていれば（または 5985/5986 が FW で外部遮断されていれば）Impacket exec しか選択肢がない → **5 ツールの中で最も静かなもの (wmiexec) から試す**。

### 8.2 二重ホップ問題は共通

両者とも **Kerberos delegation の制約を受ける**。WinRM の `Enter-PSSession` 内から `\\C\share` が見えないのと、wmiexec で取った半対話シェルから別ホストへの認証付きアクセスができないのは、根本的に同じ問題（B が C 向けチケットを発行できない）。回避策（CredSSP / RBCD / PTT）も共通で適用可能。詳細は [`WinRM_Protocol.md`](WinRM_Protocol.md) §5。

---

## 9. 環境が変わったときどこを確認するか

| 状況 | 確認ポイント | 関連手順 |
|---|---|---|
| wmiexec が `RPC_E_DISCONNECTED` | DCOM 動的ポート (49152-65535) が FW でブロック → psexec / smbexec (445 のみ) / atexec (445 のみ) へ | [`../02_Initial_Access/Impacket_Exec.md`](../02_Initial_Access/Impacket_Exec.md) §4 / §5 / §6 |
| psexec が Defender でブロック | RemComSvc.exe known signature → smbexec (バイナリなし) / dcomexec (DCOM 経由) / wmiexec へ | [`../02_Initial_Access/Impacket_Exec.md`](../02_Initial_Access/Impacket_Exec.md) §3 / §5 / §7 |
| `STATUS_ACCESS_DENIED`（ローカル管理者で接続）| UAC リモート制限 (`LocalAccountTokenFilterPolicy=0`) → ドメイン管理者で再実行 | [`../02_Initial_Access/Impacket_Exec.md`](../02_Initial_Access/Impacket_Exec.md) §4 |
| MMC20 で `CO_E_SERVER_EXEC_FAILURE` | Win10 1803+ で既定無効 → ShellWindows / ShellBrowserWindow に切替 | [`../02_Initial_Access/Impacket_Exec.md`](../02_Initial_Access/Impacket_Exec.md) §7 |
| すべての NTLM 経路で `STATUS_LOGON_FAILURE` | NTLM 無効化環境 → Kerberos 経路（`-k -no-pass`）へ | [`../02_Initial_Access/Impacket_Exec.md`](../02_Initial_Access/Impacket_Exec.md) §9 |
| Kerberos で `KRB_AP_ERR_MODIFIED` | IP 直打ちで SPN 構築不可 → FQDN + `/etc/hosts` 登録 | [`Hosts_File_For_AD.md`](Hosts_File_For_AD.md) |
| Kerberos で `KDC_ERR_S_PRINCIPAL_UNKNOWN` | 対象 SPN が未登録（読取専用 DC で `cifs/` 削除等の特殊環境）→ 別ツール（`host/` で通るもの）へ | 本ファイル §7 |
| Kerberos で `KRB_AP_ERR_SKEW` | 時刻同期ずれ > 5 分 → `sudo ntpdate [DC_IP]` | — |
| Workgroup（ドメイン未参加）環境 | Kerberos 不可、NTLM のみ → `--local-auth` フラグ必須 | [`Windows_Standalone_vs_AD.md`](Windows_Standalone_vs_AD.md) |
| 445 / 135 とも FW で外部遮断 | DCERPC / SMB 経路全滅 → WinRM (5985/5986) / RDP / VPN へ | [`WinRM_Protocol.md`](WinRM_Protocol.md) |
| Read-Only DC で psexec 失敗・wmiexec 成功 | RODC は `cifs/` を持たないことがある（運用次第）→ `host/` 系ツール (wmiexec / atexec / dcomexec) で代替 | 本ファイル §7.3 |

---

## 関連技術

- 関連：[`../02_Initial_Access/Impacket_Exec.md`](../02_Initial_Access/Impacket_Exec.md)（手順本体）
- 関連：[`WinRM_Protocol.md`](WinRM_Protocol.md)（同じく Windows リモート対話シェル経路の動作原理。SPNEGO 認証 / 二重ホップ問題 / SSH との対比は本ファイルでは省略しこちらに集約）
- 関連：[`Hosts_File_For_AD.md`](Hosts_File_For_AD.md)（Kerberos SPN 解決のための hosts 登録）
- 関連：[`Windows_Standalone_vs_AD.md`](Windows_Standalone_vs_AD.md)（Workgroup 環境での Impacket exec の挙動差）
- 関連：[`AD_Terminology.md`](AD_Terminology.md)（SPN / TGT / TGS / Service Ticket の一言定義）
- 関連：[`../05_Tools_Reference/Impacket_Suite.md`](../05_Tools_Reference/Impacket_Suite.md)（Impacket スイート全体のツール概観）
- 関連：[`../00_Playbook/Windows_AD_Attack_Flow.md`](../00_Playbook/Windows_AD_Attack_Flow.md)（接続経路選択の判断）
