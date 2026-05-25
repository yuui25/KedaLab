# WinRM / WS-Management プロトコルと検知モデル

## このファイルの位置づけ

参照元の作業ファイル：

- [`../02_Initial_Access/WinRM.md`](../02_Initial_Access/WinRM.md)（5985 / 5986 の列挙〜対話シェル取得・Lateral movement・既知 CVE）
- [`../00_Playbook/Windows_AD_Attack_Flow.md`](../00_Playbook/Windows_AD_Attack_Flow.md)（Step 4 以降の Windows 接続経路選択）
- [`../05_Tools_Reference/Netexec.md`](../05_Tools_Reference/Netexec.md)（`nxc winrm` の `(Pwn3d!)` 判定の根拠）

WinRM の作業手順を実行している最中に「なぜ Kerberos が必要なのか」「なぜ二重ホップで失敗するのか」「なぜ HTTP.sys 系 CVE が WinRM に波及するのか」が分からなくなったときに開く。手順そのものは作業ファイル側に置き、ここでは挙動の根拠だけを扱う。

> **出典について:** 本文中で「Microsoft 公式ドキュメント」「DMTF WS-Management 仕様」等を引用するが、**URL は記憶から書かない**。実引用時は MS-WSMV プロトコル仕様・DMTF DSP0226 等を `WebFetch` 等で確認すること。本ファイルは「挙動レベルでなぜそうなるか」を整理するもので、規格条文を厳密に追うものではない。

---

## 1. WinRM は何者か — WS-Management = SOAP over HTTP の正体

### 1.1 プロトコルスタック

WinRM（Windows Remote Management）の実体は **WS-Management 仕様（DMTF DSP0226）を Microsoft が拡張実装したもの**で、HTTP / HTTPS の上に SOAP 1.2 メッセージを載せる。

| 層 | 内容 |
|---|---|
| トランスポート | TCP 5985（HTTP）または 5986（HTTPS） |
| HTTP リスナー | `http.sys`（Windows のカーネルモード HTTP スタック） |
| メッセージング | SOAP 1.2 over HTTP、エンドポイントは `/wsman` |
| 拡張仕様 | **MS-WSMV**（Microsoft Web Services Management Protocol Extensions） |
| PowerShell 層 | PSRP（PowerShell Remoting Protocol、MS-PSRP） |
| 実行プロセス | `wsmprovhost.exe`（セッションごとに起動） |

PowerShell Remoting（`Enter-PSSession` / `Invoke-Command`）は **PSRP を WS-Management の上に乗せた構造**。`evil-winrm` も `pypsrp` も `pywinrm` も最終的にはこの SOAP リクエストを組み立てて送っている。

### 1.2 なぜ 5985 / 5986 という見慣れないポートか

WinRM 1.1 までは HTTP 80 / HTTPS 443 を共用していた（IIS と衝突するため運用上の事故が多発）。WinRM 2.0（Windows 7 / Server 2008 R2 以降）で **既定で 5985 / 5986 に分離**された。

これにより：

- IIS と同居しても WinRM の listener が IIS の 80 を奪わない
- 外部スキャンで 5985 / 5986 を見たら「Windows 確定 + 管理プロトコル開放」と即判断できる（手順ファイル §1 のポート判定の根拠）

### 1.3 http.sys カーネル共有が CVE の波及を生む

`http.sys` は Windows のカーネルモード HTTP リスナーで、**IIS / WinRM / WSDAPI / Windows Update / その他 HTTP サービスがすべて共有**している。これが攻撃面の理解で重要：

- **CVE-2021-31166（HTTP Protocol Stack RCE）** が WinRM に波及するのは、5985 のリクエストパース処理が IIS と同じ `http.sys` を通るため（手順ファイル §10.1）
- `nmap -sV` で `Microsoft HTTPAPI httpd 2.0` と出るが、これは「http.sys 由来の HTTP レスポンス」というだけで、IIS とも WSDAPI とも区別できない。**ポート番号で WinRM と確定する**ロジックの根拠
- `HTTPAPI` のバージョン文字列（`2.0`）は **OS バージョンと直結しない**。`http.sys` はカーネルコンポーネントとして独立にバージョン採番されている

> **環境が変わったとき:** Server Core / Nano Server でも http.sys は共通。WinRM 自体が無効化されていても `http.sys` のパッチ未適用は別途リスク。

---

## 2. wsmprovhost.exe プロセスモデル — なぜ検知シグネチャの中心になるか

### 2.1 プロセスツリー

WinRM セッションが成立すると、ターゲット側で次のプロセスツリーが立つ：

```
services.exe
 └── svchost.exe -k DcomLaunch -p (WinRM サービス)
      └── wsmprovhost.exe (セッションごとに 1 個)
           └── 実行コマンド（cmd.exe / powershell.exe / 任意プロセス）
```

`wsmprovhost.exe` は **WinRM Provider Host** の略で、PSSession ごとに 1 つ起動する。セッション切断時にプロセスが消えるため、Sysmon Event ID 1（プロセス作成）の時系列を見れば「いつ接続して、何を実行したか」が時系列で分かる。

### 2.2 SMB ベース（psexec / wmiexec）との違い

| 観点 | WinRM (`wsmprovhost.exe`) | psexec (`PSEXESVC.exe`) | wmiexec (`wmiprvse.exe`) |
|---|---|---|---|
| 親プロセス | `svchost.exe -k DcomLaunch` | `services.exe`（一時サービス作成） | `svchost.exe -k DcomLaunch` |
| サービス作成 | なし | **あり**（Event ID 7045） | なし |
| ファイル設置 | なし | **あり**（`ADMIN$` に PSEXESVC.exe を置く） | なし |
| 主検知ログ | `Microsoft-Windows-WinRM/Operational` Event 91 / 163 | Event ID 7045 + ファイル設置 | DCOM ログ + `wmiprvse.exe` 起動 |
| ネイティブ度 | ◎ MS 純正クライアント（`Enter-PSSession`）あり | × Sysinternals ツール | △ WMIC は ネイティブだが impacket は外部 |

**WinRM が「侵入後最初の対話シェル経路」として推奨される理由**：

- サービス作成・ファイル設置の痕跡を残さない（Event 7045 が出ない）
- MS 純正クライアント（`Enter-PSSession`）が同じプロトコルを使うため、**正常運用の WinRM 通信に紛れる**（ただし「外部 IP から `wsmprovhost.exe` 直下に `cmd.exe` が立つ」というツリー自体は EDR の主要シグネチャ）
- 接続事実そのものは隠せない。Defense evasion は「接続を隠す」ではなく「**接続後に走らせるプロセスを MS 純正の枠内に留める**」方向で考える

> **手順ファイル §6 / §7 で `Invoke-Command` 中心の構成を推奨している理由**は上記の検知モデル。カスタム PE 投下を避け、`Get-WmiObject` / `Get-CimInstance` / PowerView の Invoke-Command 越し実行に留めれば子プロセスは `powershell.exe` のみで完結する。

### 2.3 主要ログソース（検知側の観察点）

- **Sysmon Event ID 1**: `wsmprovhost.exe` 子プロセスの作成。親プロセスチェーンで送信元判定
- **Security Event ID 4624**（LogonType 3）: ネットワーク経由ログオン成功
- **Security Event ID 4625**: ログオン失敗（スプレー検知の閾値ベースルールの源泉）
- **Security Event ID 4262**（2022 年 7 月 CU 以降）: WinRM 認証時に **source IP を記録**するイベント。手順ファイル §8 スプレーで「IP まで残る」と書いている根拠
- **`Microsoft-Windows-WinRM/Operational` ログ**:
  - Event 91 / 163: WinRM シェル作成（接続成功）
  - Event 182: 認証失敗（スプレー時に大量発生）
- **PowerShell ScriptBlock ロギング (Event ID 4104)**: 実行された PowerShell スクリプト本文が記録。AMSI バイパスや `Enable-PSRemoting` 本文が見える

---

## 3. 認証 negotiation — Negotiate / SPNEGO / Kerberos / NTLM / Basic / CredSSP

### 3.1 WWW-Authenticate ヘッダの読み方

非認証で `/wsman` に GET / HEAD を投げると 401 が返り、`WWW-Authenticate` ヘッダで受理可能な認証方式が列挙される。これが手順ファイル §2 で `curl -I` を最初に投げる理由。

```
HTTP/1.1 401
WWW-Authenticate: Negotiate
WWW-Authenticate: Kerberos
WWW-Authenticate: Basic realm="WSMAN"
```

各方式の意味：

| 方式 | 内部の挙動 | 攻撃側の動き |
|---|---|---|
| `Negotiate` | **SPNEGO**（RFC 4559）でクライアントとサーバが Kerberos / NTLM のどちらを使うか折衝 | クライアントが Kerberos チケットを持っていれば Kerberos、なければ NTLM にフォールバック |
| `Kerberos` | Kerberos のみ受理（NTLM フォールバック禁止） | `kinit` で TGT 取得 → `evil-winrm -k --spn HTTP/[FQDN]` |
| `NTLM` | NTLM のみ受理 | `evil-winrm -u -p` / `-H` で直接 |
| `Basic` | HTTP Basic（平文 cred を Base64 で送る） | HTTP 5985 上の Basic は **設定不備の finding 候補**（MitM で平文奪取可能） |
| `CredSSP` | 二段委任認証。cred を相手ホストに渡して相手から別ホストへ再認証させる | 二重ホップ問題（§5）の回避に使える |

### 3.2 「Negotiate のみ」表示の罠 — NTLM 無効化環境の見分け方

`WWW-Authenticate: Negotiate` だけが返っていても、内部の SPNEGO で Kerberos のみが許可されていると **NTLM 認証は `STATUS_LOGON_FAILURE` で拒否される**。これは「ヘッダの表示」と「実際に通る認証」の乖離。

- Microsoft 推奨の AD 強化構成では NTLM 無効化が進んでいる（`Network security: Restrict NTLM` 系のグループポリシー）
- 手順ファイル §4 で `Failed to authenticate. NTLM is disabled on this machine` が出る理由はこれ
- 見分け方: **`evil-winrm -u -p` で NTLM を試して失敗 → `kinit` → `evil-winrm -k --spn HTTP/[FQDN]` で Kerberos を試す**

### 3.3 SPN（Service Principal Name）の必要性

Kerberos で WinRM に接続するには **SPN `HTTP/[TARGET_FQDN]` を指定する必要がある**。理由：

- Kerberos の TGS リクエストは「サービスのホスト名」が必要（[`Hosts_File_For_AD.md`](Hosts_File_For_AD.md) §1）
- IP 直打ちでは `KRB_AP_ERR_MODIFIED` / `KDC_ERR_S_PRINCIPAL_UNKNOWN` で失敗する
- WinRM の SPN プレフィックスは **`HTTP/`**（`HTTPS/` ではない — 5986 でも `HTTP/[FQDN]` で要求する。これは Kerberos の SPN がトランスポートではなくサービスクラスを表すため）

> **環境が変わったとき:** SPN が DC 側に登録されていない場合は Kerberos 不可。`setspn -L [HOSTNAME]` で確認可能（侵入後）。攻撃側からは `nxc smb -k --kdcHost [DC_IP]` 等で間接的に Kerberos の動作確認をする。

### 3.4 Basic auth が finding になる理由

`WWW-Authenticate: Basic` が HTTP 5985 上で有効だと、**cred が Base64 のみで平文相当に流れる**。MitM 経路を持つ攻撃者は cred を奪取できる。

- 既定で Basic は無効。明示的に `Set-Item WSMan:\localhost\Service\AllowBasic -Value true` で有効化されている状態
- 緩和策（finding 推奨）: Basic 無効化、HTTPS（5986）強制、**EPA（Extended Protection for Authentication）** 有効化（NTLM Relay 防御も兼ねる）
- 手順ファイル §10.3 NTLM Relay to WinRM は **HTTP 5985 で listener が立っている** + **EPA 未有効** の組み合わせで成立する

---

## 4. TrustedHosts — なぜ NTLM 認証で必要か

### 4.1 Mutual Authentication の話

Kerberos は **相互認証**（クライアントがサーバを、サーバがクライアントを Kerberos チケットで確認する）が組み込まれている。一方 NTLM は **一方向認証**（サーバはクライアントを確認するが、クライアントはサーバの正体を Kerberos 的には確認できない）。

このため Windows の WinRM クライアントは安全側に倒して以下のように動く：

- **Domain joined（ドメイン参加）クライアント**: Kerberos で接続するので Mutual Auth が成立 → TrustedHosts 不要
- **Workgroup（ドメイン非参加）クライアント** + **NTLM 認証**: Mutual Auth が成立しない → 「**接続先サーバを明示的に信頼してもらう必要がある**」として TrustedHosts への登録を要求する

これが手順ファイル §6 で「ドメイン参加していない攻撃端末（個人 PC / 検証 VM）からの WinRM 接続では TrustedHosts エラーが出る」と書いている根拠。

### 4.2 回避経路の優先順位

| 方法 | 安全性 | 利便性 |
|---|---|---|
| HTTPS（5986）経由 | ◎ サーバ証明書で正体確認できる | △ 証明書配布が必要 |
| 個別ホスト名指定（`TrustedHosts="[HOST1],[HOST2]"`） | ○ | △ 都度設定 |
| ワイルドカード `'*'` | ✗ **広すぎる・本番危険** | ◎ |
| ドメイン参加 | ◎ Kerberos に切替わる | × 攻撃端末を join するのは現実的でない |

> **環境が変わったとき:** 「pentest 用攻撃端末を AD に join させる」のは現実的でないため、**HTTPS 接続か個別 TrustedHosts 登録**が現実解。`*` での全許可は調査中の攻撃 VM でもやめておく（自分の攻撃 VM が逆侵入された際に被害拡大）。

---

## 5. 二重ホップ問題（Double-Hop Problem）の本質

### 5.1 何が起きているか

`A → PSSession → B` で B 上のシェルから `\\C\share` にアクセスしたり `Invoke-Command -ComputerName C` で C へ飛ぶと、**B が C に対して匿名（NULL session）アクセスになって失敗する**。手順ファイル §7 の `Access is denied` の正体。

### 5.2 なぜそうなるか — Kerberos delegation の既定挙動

Kerberos の committee 設計：

- A が B に接続するとき、A の cred から **「B のサービス向けの Service Ticket」**を取得する
- このチケットは「**B で使う**」ことを前提に発行されている（受領者制限 = audience が B に固定）
- B は受け取ったチケットで A の身元を確認できるが、**そのチケットを別サーバ C に転送する権限は既定では持たない**
- 結果として B から C への接続は「B のマシンアカウント」で行われ、A の権限は失われる

これが「cred が 1 hop までしか届かない」現象の正体。**WinRM 固有の問題ではなく、Kerberos 委任全般の話**（SMB / WMI / RDP からの再接続でも同じ問題が起きる）。

### 5.3 回避策の原理

| 方式 | 何をしているか | リスク |
|---|---|---|
| **CredSSP** | cred を **平文に近い形で B に渡す**。B が C に対して A のフルアカウントで再認証 | B が侵害されると cred が C 以外にも漏洩する。**HIGH IMPACT** |
| **Resource-Based Constrained Delegation (RBCD)** | C 側に「B から委任された Kerberos リクエストを受理する」設定を入れる。B が C 向けチケットを KDC に要求できるようになる | 設定変更が必要。攻撃軸としては **コンピュータアカウントの `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性書込権を握れば任意の RBCD を仕込める**（CVE-2019-1040 / Petitpotam 周辺の文脈） |
| **Pass-The-Ticket (PTT)** | C 向けの Service Ticket を別途取得して B にインポート。B からは「正規のチケットを持ったユーザ」として C に接続できる | チケット注入が必要（Rubeus / impacket）。検知側からは Kerberos 4769 イベントで異常な S4U / 委任パターンが見える |
| **古典 Unconstrained Delegation** | B のマシンに「任意の cred 受領」設定。接続時に A の TGT 自体が B に転送される | 既定では設定されない。AD 全体の集権リスクで非推奨。攻撃軸としては「Unconstrained 設定の DC を見つけて Printer Bug でターゲットを誘導 → TGT 奪取」 |

### 5.4 検知側の観察点

- **Security Event 4769**（Service Ticket 要求）が**通常パターン外の SPN 組合せで発生**する（B のサービスアカウントから C 向けにチケット要求 → RBCD / Unconstrained の徴候）
- CredSSP 経路は **Event 4624 の Authentication Package が "CredSSP"** で記録される
- PTT は **Event 4624 の Authentication Package が "Kerberos" だが TGT 取得記録（4768）が攻撃側 IP から無い**ことで検知可能

> **環境が変わったとき:** RBCD は AD 環境固有。Workgroup / スタンドアロン Windows では Kerberos そのものが無いため二重ホップ問題は発生しないが、代わりに **NTLM の 2 段目認証は常に NULL session 化**するため同様に「PSSession 内から別ホストへの認証付きアクセス」は失敗する。

---

## 6. 環境が変わったときどこを確認するか

| 状況 | 確認ポイント | 関連手順 |
|---|---|---|
| NTLM 無効化環境 | `evil-winrm -u -p` で `NTLM is disabled`。Kerberos 経路に切替 | [`../02_Initial_Access/WinRM.md`](../02_Initial_Access/WinRM.md) §2 / §4 |
| ドメイン未参加攻撃端末 | TrustedHosts エラー。HTTPS or 個別登録 | [`../02_Initial_Access/WinRM.md`](../02_Initial_Access/WinRM.md) §6 / 本ファイル §4 |
| Kerberos が IP 直打ちで失敗 | `KRB_AP_ERR_MODIFIED`。FQDN 解決を `/etc/hosts` で先に通す | [`Hosts_File_For_AD.md`](Hosts_File_For_AD.md) |
| 二重ホップで Access Denied | Kerberos delegation 設定確認。CredSSP / RBCD / PTT へ | [`../02_Initial_Access/WinRM.md`](../02_Initial_Access/WinRM.md) §7 / 本ファイル §5 |
| Linux ホストで 5985 が開いている | **Azure OMI Agent の可能性**。OMIGOD（CVE-2021-38647） | [`../02_Initial_Access/WinRM.md`](../02_Initial_Access/WinRM.md) §10.2 |
| HTTPAPI 2.0 が出るが WinRM ではない | IIS / WSDAPI / Windows Update のどれかも http.sys 共有。ポート番号で確定 | [`../02_Initial_Access/WinRM.md`](../02_Initial_Access/WinRM.md) §1 |
| Server Core / Nano Server | WinRM の設定パスは通常版と同じ。GUI が無いだけ。`winrm` コマンド・`Set-Item WSMan:\...` は同じ | — |
| Workgroup（スタンドアロン）環境 | Kerberos 不可、NTLM のみ。`--local-auth` フラグが必要 | [`Windows_Standalone_vs_AD.md`](Windows_Standalone_vs_AD.md) |

---

## 7. WinRM と SSH の対比（概念モデルとして）

WinRM は文脈上「Windows 版 SSH」と説明されることが多いが、**プロトコル設計は全く別物**。比喩としての対応関係を整理しておく：

| 観点 | SSH | WinRM |
|---|---|---|
| トランスポート | TCP 22、独自バイナリプロトコル | TCP 5985 / 5986、SOAP over HTTP |
| 認証 | パスワード / 公開鍵 / GSSAPI(Kerberos) | NTLM / Kerberos / Basic / CredSSP / 証明書 |
| 対話シェル | TTY セッション | PSSession（PSRP over WSMan） |
| ファイル転送 | scp / sftp（独立サブシステム） | `evil-winrm` の `upload` / `download`（WSMan の Send/Receive） |
| 鍵ベース永続化 | `~/.ssh/authorized_keys` | `Remote Management Users` グループ追加 + cred（または証明書認証） |
| エージェント転送 | `ssh-agent` の `-A` フォワーディング | CredSSP の cred 委任（用途は似るがプロトコル別） |
| 検知ログ | `/var/log/auth.log` の `sshd` 行 | Security 4624/4625 + `Microsoft-Windows-WinRM/Operational` |

**比喩として有効な点:**

- 「侵入後最初の対話シェル経路」というポジションは共通（cred が取れた瞬間に最初に試す）
- ファイル転送 + コマンド実行が 1 つのプロトコルで完結する点も同じ
- 公開鍵 / 証明書による「パスワードレス再接続」の概念も類似

**比喩として誤解を生む点:**

- WinRM の認証は **AD と密結合**（Kerberos / NTLM が中心）。SSH の「ユーザ鍵を端末に置けばどこからでも入れる」モデルとは別系統
- WinRM は **二重ホップ問題が固有**（SSH では SSH エージェント転送 or 鍵を中継ホストに置けば済む）
- WinRM は **対話入力を要するコマンドが動かない**（PSSession の制約）。SSH の TTY セッションは GUI 系以外なら大抵動く

---

## 関連技術

- 関連：[`../02_Initial_Access/WinRM.md`](../02_Initial_Access/WinRM.md)（手順本体）
- 関連：[`Impacket_Exec_Internals.md`](Impacket_Exec_Internals.md)（WinRM 不可時の代替経路。DCERPC / DCOM / SCM / ATSvc の動作原理・5 ツールのプロセスツリー差・Kerberos SPN cifs/ vs host/ のツール別差）
- 関連：[`Hosts_File_For_AD.md`](Hosts_File_For_AD.md)（Kerberos SPN 解決のための hosts 登録）
- 関連：[`Windows_Standalone_vs_AD.md`](Windows_Standalone_vs_AD.md)（Workgroup 環境での WinRM の挙動差）
- 関連：[`../05_Tools_Reference/Netexec.md`](../05_Tools_Reference/Netexec.md)（`nxc winrm` の `(Pwn3d!)` 判定基準）
- 関連：[`../00_Playbook/Windows_AD_Attack_Flow.md`](../00_Playbook/Windows_AD_Attack_Flow.md)（接続経路選択の判断）
