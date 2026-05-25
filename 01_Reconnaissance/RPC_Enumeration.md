# RPC 列挙（MSRPC / rpcclient / lookupsid / samrdump）

> **スコープ**: 135（DCERPC エンドポイントマッパー）/ 139（NetBIOS-SSN）/ 445（SMB の名前付きパイプ経由 RPC）/ 593（RPC over HTTP, ncacn_http）から、ドメインユーザー・グループ・SID・パスワードポリシー等を列挙する。**Windows AD 環境の最初期偵察で最も価値が出るブロック**。匿名バインドが通る場合と認証情報あり双方を扱う。**列挙結果を使った攻撃（パスワードスプレー / Kerberoast / Pass-The-Hash 等）は本ファイル範囲外** → 該当は `../02_Initial_Access/` および `../04_Post_Access_Windows_AD/` を参照。

## 着火条件

以下のいずれかに該当する場合:

- ポートスキャンで `135/tcp open msrpc` または `139/tcp open netbios-ssn` または `445/tcp open microsoft-ds` または `593/tcp open http-rpc-epmap` を検出
- ターゲットが Windows / Samba と判定済み（`nmap -O` / SMB バナーで OS 確認済み）
- 認証情報がまだ無く、ユーザー列挙を起点に辞書攻撃・スプレーへ進めたい
- 低権限の認証情報を取得済みで、権限を使って詳細属性（`description` フィールド・グループメンバ）を引き出したい

## 環境前提

- 実行環境: テスター端末（Linux 側を想定）
- 必要なツール:
  - `rpcclient`（Samba スイート同梱の `samba-client` パッケージ、ペネトレ用 Linux ディストリ標準搭載）
  - `impacket-lookupsid` / `impacket-samrdump` / `impacket-rpcdump`（Impacket スイート同梱、ペネトレ用 Linux ディストリ標準搭載 or `pipx install impacket`）
  - `nxc`（NetExec の CLI ラッパー。SMB 認証テスト・`--users` / `--rid-brute` 等の列挙オプション持ち、ペネトレ用 Linux ディストリ標準搭載）
  - `enum4linux-ng`（rpcclient / smbclient / nmblookup を一括実行するラッパー、要インストール: `pipx install enum4linux-ng`）
- 外部リソース依存: なし（オフラインでも完結）

## 先に確認すること

- **ターゲットが Workgroup かドメイン参加か**: rpcclient で `querydominfo` を打つと `Domain:` が出る。Workgroup なら列挙対象がローカル SAM のみで母数が小さい
- **匿名バインドの可否**: Windows Server 2012 R2 以降は既定で無効化（`RestrictAnonymous=1`）。`enumdomusers` 直後に `NT_STATUS_ACCESS_DENIED` が返れば匿名は使えない → 認証情報取得後に再列挙する経路に切替
- **ロックアウト設定の事前取得**: §3 で `getdompwinfo` を必ず通す。`lockoutThreshold` を知らずに後段のスプレーに進むとアカウントロックを招く（`../02_Initial_Access/Account_Lockout_Recon.md`）
- **SMB signing は本列挙に影響しない**: signing は NTLM Relay 攻撃への防御。RPC 列挙そのものには関係ない
- **複数 NIC / IPv6 の事前確認**: ターゲットが外部 IP しか見せていない場合でも、§1 IOXIDResolver で内部 IP / IPv6 を取得できることがある。発見した内部アドレスは `/etc/hosts` 登録・別経路スキャンの起点になる

攻撃者の思考トレース: 認証情報の有無に関わらず、**「どのユーザーが存在するか」を最初に確定させる** ことで、後段の辞書攻撃・スプレー・Kerberoast の命中率が劇的に上がる。RPC 匿名列挙は LDAP 匿名バインド（[`LDAP_Enumeration.md`](LDAP_Enumeration.md)）と並んで「認証情報ゼロから入る」最重要経路。LDAP が閉じていても 135/139 が空いている古い AD は今でも頻出（Server 2008 R2 / 2012 が残る環境）。**rpcclient 1 つで 30 以上のサブコマンドが叩ける** ため、列挙の起点として最も汎用的。

> 原理（SAMR vs LSAT の権限差・列挙が badPwdCount をバイパスする境界・RestrictAnonymous の OS 依存史・RID 構造・IOXIDResolver の漏洩仕様）→ [`../06_Concepts/RPC_Enumeration_Internals.md`](../06_Concepts/RPC_Enumeration_Internals.md)

---

## 1. RPC エンドポイントマッピング（rpcdump）

**コマンド:**

```bash
# [Attacker] DCERPC エンドポイントマッパー (135) で利用可能なインターフェース列挙
impacket-rpcdump [TARGET_IP]

# [Attacker] 認証ありでより多くの bind 結果が得られる場合がある
impacket-rpcdump '[DOMAIN]/[USER]:[PASSWORD]@[TARGET_IP]'

# [Attacker] Port 593 (RPC over HTTP, ncacn_http) 経由でクエリ
impacket-rpcdump [TARGET_IP] -p 593

# [Attacker] Metasploit auxiliary scanner（rpcdump が無い環境の代替）
# use auxiliary/scanner/dcerpc/endpoint_mapper   # 全 IF 列挙
# use auxiliary/scanner/dcerpc/hidden            # 隠し IF を探索
# use auxiliary/scanner/dcerpc/management        # 管理系 IF 列挙
# use auxiliary/scanner/dcerpc/tcp_dcerpc_auditor # 任意ポートの DCERPC 監査

# [Attacker] IOXIDResolver で IPv6 アドレス・追加 NIC を取得（135 経由・認証不要）
# IPv4 で接続したターゲットが内部で IPv6 アドレスを持っているか確認
# git clone https://github.com/mubix/IOXIDResolver
python3 IOXIDResolver.py -t [TARGET_IP]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `Protocol: [MS-SAMR]: Security Account Manager (SAM) Remote Protocol` | SAMR 利用可能（`\pipe\samr`・IFID `12345778-1234-abcd-ef00-0123456789ac`） | §2 rpcclient 匿名バインド・§4 enumdomusers へ |
| `Protocol: [MS-LSAT]: Local Security Authority (Translation Methods)` | LSAT 利用可能（`\pipe\lsarpc`・IFID `12345778-1234-abcd-ef00-0123456789ab`） | §5 lookupsids / §6 lookupsid bruteforce へ |
| `Protocol: [MS-LSAD]: Local Security Authority (Domain Policy)` | LSA DS 利用可能（`\pipe\lsarpc`・IFID `3919286a-b10c-11d0-9ba8-00c04fd92ef5`・**ドメイン・信頼関係列挙**） | §3 lsaquery / `LDAP_Enumeration.md` の信頼関係列挙へ |
| `Protocol: [MS-DRSR]: Directory Replication Service` | DRSUAPI 露出（DC 側） | DCSync の候補確認（権限あれば `../04_Post_Access_Windows_AD/Credential_Dumping.md`） |
| `Protocol: [MS-WMI]: Windows Management Instrumentation Remote Protocol` | WMI 利用可能（`\pipe\epmapper` 経由 DCOM） | 認証取得後の `../02_Initial_Access/Impacket_Exec.md` §3 wmiexec 候補 |
| `Protocol: [MS-TSCH]: Task Scheduler Service Remoting Protocol` | atsvc 利用可能（`\pipe\atsvc`・IFID `1ff70682-0a51-30e8-076d-740be8cee98b`） | 認証取得後の `../02_Initial_Access/Impacket_Exec.md` §6 atexec 候補 |
| `Protocol: [MS-SCMR]: Service Control Manager Remote Protocol` | svcctl 利用可能（`\pipe\svcctl`・IFID `367abb81-9844-35f1-ad32-98f038001003`・**リモートサービス起動・停止**） | 認証取得後の `../02_Initial_Access/Impacket_Exec.md` §4 psexec / §5 smbexec 候補 |
| `Protocol: [MS-SRVS]: Server Service Remote Protocol` | srvsvc 利用可能（`\pipe\srvsvc`・**共有列挙**） | `SMB_Enumeration.md` の共有列挙へ |
| `Protocol: [MS-RRP]: Windows Remote Registry Protocol` | winreg 利用可能（`\pipe\winreg`・IFID `338cd001-2244-31f1-aaaa-900038001003`・**リモートレジストリ読書**） | 認証取得後に `reg query \\[TARGET]\HKLM\...` でレジストリ列挙 |
| 593 で `http-rpc-epmap` バナー | RPC over HTTP 露出 | Exchange / Outlook Anywhere 関連の可能性。`Edge_Appliance_CVEs.md` の Exchange CVE 照合 |
| 接続即タイムアウト | 135 が FW でブロック | 139/445 経由（SMB の名前付きパイプ）に切替 → §2 へ |
| `Protocol: [MS-RPCE]: Remote Procedure Call Protocol Extensions` のみ | 一般的な MSRPC のみ・列挙価値の高い IF なし | §2 で直接 SAMR バインドを試す |
| IOXIDResolver で IPv4 と異なる IPv6 アドレスが返る | ターゲットが IPv6 NIC を持つ・内部ネットワーク露出 | IPv6 経路で再列挙（Windows は IPv6 が IPv4 より優先される場合あり） |

**Notable RPC interfaces 早見表（HackTricks / MS-* 仕様の主要 IF を抜粋）:**

| 名前付きパイプ | IFID | 用途・列挙価値 |
|---|---|---|
| `\pipe\lsarpc` | `12345778-1234-abcd-ef00-0123456789ab` | MS-LSAT — ユーザー名 ⇔ SID 解決（§5 lookupsids）|
| `\pipe\lsarpc` | `3919286a-b10c-11d0-9ba8-00c04fd92ef5` | MS-LSAD — ドメイン・信頼関係列挙 |
| `\pipe\samr` | `12345778-1234-abcd-ef00-0123456789ac` | MS-SAMR — **SAM DB 列挙（ユーザー名・グループ・password policy）**・**account lockout policy 無関係に列挙可能** |
| `\pipe\atsvc` | `1ff70682-0a51-30e8-076d-740be8cee98b` | MS-TSCH — タスクスケジューラ経由のリモート実行（atexec） |
| `\pipe\winreg` | `338cd001-2244-31f1-aaaa-900038001003` | MS-RRP — リモートレジストリ |
| `\pipe\svcctl` | `367abb81-9844-35f1-ad32-98f038001003` | MS-SCMR — サービスマネージャ（psexec / smbexec の経路） |
| `\pipe\srvsvc` | `4b324fc8-1670-01d3-1278-5a47bf6ee188` | MS-SRVS — 共有列挙・セッション列挙 |
| `\pipe\epmapper` | `4d9f4ab8-7d1c-11cf-861e-0020af6e7c57` | DCOM 経由のオブジェクトアクティベーション（dcomexec） |

> **MS-SAMR の重要な性質**: SAMR インターフェース経由のユーザー名・グループ列挙は **AD の account lockout policy をバイパスする**（列挙は認証失敗カウンタに加算されない）。これは「lockout が有効でもスプレー可能」という意味ではなく「**列挙だけは lockout を恐れず網羅実行できる**」という意味。後段のパスワードスプレー（[`../02_Initial_Access/Default_Credentials.md`](../02_Initial_Access/Default_Credentials.md)）は別途 lockout 閾値に従う必要がある。

**注意:**

- `impacket-rpcdump` はエンドポイント一覧を返すだけで、各 IF に対するアクセス権限の有無は分からない。実際に bind できるかは §2 以降で個別に試す
- 認証ありで実行すると一部のインターフェースが追加表示されることがある（ターゲット側の `RestrictAnonymous` レジストリ値による）
- 古い Samba (3.x 系) は DCERPC エンドポイントマッパーの実装が貧弱で、本コマンドが空に近い結果を返すことがある → Samba 確定なら本ブロックスキップして §2 へ
- **IOXIDResolver は認証不要・135 経由で動く** ため、ターゲットが NAT 越し・複数 NIC 構成でも内部 IP / IPv6 アドレスを暴露する。NMap でも見えないアドレスが出ることがあり、内部ネットワークマップ作成の起点になる
- **Port 593（RPC over HTTP）** は Exchange 環境で Outlook Anywhere 用に露出することがある。発見したら Exchange バージョン特定 → ProxyLogon / ProxyShell の CVE 照合（[`../02_Initial_Access/Mail_Services.md`](../02_Initial_Access/Mail_Services.md) §8）へ

---

## 2. rpcclient 匿名バインド試行

**コマンド:**

```bash
# [Attacker] 匿名 (null session) 接続
rpcclient -U "" -N [TARGET_IP]

# [Attacker] 空ユーザー + 空パスワード（一部の Samba で挙動が違うことがある）
rpcclient -U "%" [TARGET_IP]

# [Attacker] guest アカウント（匿名拒否でも guest 有効ならこちらが通る）
rpcclient -U "guest%" [TARGET_IP]

# [Attacker] 別ポート（445 経由を強制したい場合）
rpcclient -U "" -N -p 445 [TARGET_IP]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `rpcclient $>` プロンプト | 匿名バインド成立（null session 可）| §3 §4 §5 のコマンドを順に実行 |
| `Cannot connect to server. Error was NT_STATUS_LOGON_FAILURE` | 匿名拒否（Windows Server 2012 R2+ の既定）| guest 試行 → ダメなら認証情報取得経路に戻る |
| `Cannot connect to server. Error was NT_STATUS_ACCESS_DENIED` | サーバーが匿名接続自体を拒否 | 同上 |
| `Cannot connect to server. Error was NT_STATUS_IO_TIMEOUT` | FW で 139/445 ブロック | 135 経由を試す / VPN 確認 |
| プロンプトは出るが各コマンドが `ACCESS_DENIED` | bind は通るが MS-SAMR 操作が拒否 | §5 lookupsids（LSAT 経由）を試す。SAMR より緩い場合あり |
| `Anonymous login successful` 表示後にプロンプト | 完全な null session（古い Samba / 構成ミス）| §3 §4 §5 全部通る確率高、最優先で列挙 |

**注意:**

- `rpcclient -U ""` と `rpcclient -U "%"` は微妙に挙動が違う。前者は「ユーザー名・パスワードとも空」、後者は「`""` ユーザー名 + 空パスワード」として送られる。両方試して挙動差を確認する
- 匿名バインドが通っても、その後の `enumdomusers` 等が `ACCESS_DENIED` で拒否されるパターンが多い（Windows 2008 以降の典型）。**bind 成立 ≠ 全コマンド実行可** を念頭に置く
- guest が有効化されている Samba 環境（Linux 側の旧 NAS など）では `-U "guest%"` で通常ユーザー権限相当の列挙が可能になることがある

---

## 3. ドメイン情報・パスワードポリシー（querydominfo / getdompwinfo）

**コマンド:**

```bash
# [Attacker] rpcclient に入った状態で実行（または -c で 1 行実行）
rpcclient -U "" -N [TARGET_IP] -c 'querydominfo'

# [Attacker] パスワードポリシー（ロックアウト閾値 / 最小長 / 履歴）
rpcclient -U "" -N [TARGET_IP] -c 'getdompwinfo'

# [Attacker] サーバー情報（OS バージョン・コメント・タイプ）
rpcclient -U "" -N [TARGET_IP] -c 'srvinfo'

# [Attacker] ドメインリスト（マルチドメイン環境で他ドメイン名を取得）
rpcclient -U "" -N [TARGET_IP] -c 'enumdomains'

# [Attacker] LSA でドメイン名・SID 取得
rpcclient -U "" -N [TARGET_IP] -c 'lsaquery'
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `Domain: [DOMAIN]` (querydominfo) | NetBIOS ドメイン名取得 | LDAP / Kerberos 用 FQDN を `enumdomains` / `lsaquery` で補完。`/etc/hosts` 登録（[`../06_Concepts/Hosts_File_For_AD.md`](../06_Concepts/Hosts_File_For_AD.md)）|
| `min_password_length: [N]` (getdompwinfo) | スプレー対象の最小長確定 | `[N]` 文字以上のパスワード候補のみでスプレー設計 |
| `password_properties: ...DOMAIN_PASSWORD_COMPLEX...` | 複雑性要求あり | 単純な辞書ではヒット率低い → 季節名 + 数字 + 記号系で再構築 |
| `lockout_threshold` が出力に出ない（無効）/ `lockout_threshold: 0` | ロックアウト無効化 | スプレー実施 OK（業務影響なし）|
| `lockout_threshold: 5` 等の有限値 | ロックアウト有効 | スプレー前に `Account_Lockout_Recon.md` で `observation_window` 取得必須 |
| `srvinfo` で `Wk Sv PDC` のフラグ | このホストがプライマリドメインコントローラー | LDAP / Kerberos の優先ターゲット候補（`../01_Reconnaissance/LDAP_Enumeration.md`）|
| `lsaquery` で SID 取得（例: `S-1-5-21-...`）| ドメイン SID 取得 | §6 lookupsid bruteforce の `[DOMAIN_SID]` に投入 |
| `getdompwinfo` で `ACCESS_DENIED` | 匿名で password policy 非公開（強化構成）| 認証取得後に再実行 / `impacket-samrdump` で代替（§7）|

**注意:**

- `getdompwinfo` は **匿名で取れる環境がまだまだ残っている**（特に Server 2008 R2 / 2012 系・Samba 互換構成）。スプレー設計に必須なので最優先で取りに行く
- `srvinfo` の `Wk Sv` 等のフラグの意味:
  - `Wk` = Workstation
  - `Sv` = Server
  - `PDC` = Primary Domain Controller
  - `BDC` = Backup Domain Controller（古い NT 用語、現代では Read-Only DC として残る）
  - `Tim` = Time Server
  - `NT` = Windows NT 互換サーバー
- `lsaquery` で取得する SID は **ドメイン SID**（コンピューター SID とは別）。§6 RID bruteforce で必須

---

## 4. ユーザー・グループ列挙（enumdomusers / enumdomgroups）

**コマンド:**

```bash
# [Attacker] ドメインユーザー一覧（RID + ユーザー名）
rpcclient -U "" -N [TARGET_IP] -c 'enumdomusers'
# 出力例:
# user:[Administrator] rid:[0x1f4]
# user:[Guest] rid:[0x1f5]
# user:[krbtgt] rid:[0x1f6]
# user:[svc_sql] rid:[0x44f]

# [Attacker] ドメイングループ一覧
rpcclient -U "" -N [TARGET_IP] -c 'enumdomgroups'

# [Attacker] エイリアス（ローカルグループ）列挙
rpcclient -U "" -N [TARGET_IP] -c 'enumalsgroups builtin'
rpcclient -U "" -N [TARGET_IP] -c 'enumalsgroups domain'

# [Attacker] ユーザー名のみ抽出（後段の辞書作成用）
rpcclient -U "" -N [TARGET_IP] -c 'enumdomusers' | \
  grep -oP 'user:\[\K[^\]]+' > users.txt

# [Attacker] nxc 経由でも同等の列挙が可能（出力フォーマットが揃って便利）
nxc smb [TARGET_IP] -u '' -p '' --users
nxc smb [TARGET_IP] -u '' -p '' --groups

# [Attacker] enum4linux-ng でラップ実行（rpcclient / smbclient / nmblookup を一括）
enum4linux-ng -A [TARGET_IP]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| ユーザー一覧が返る | パスワードスプレー対象リスト完成 | `Account_Lockout_Recon.md` でロック閾値確認 → `Default_Credentials.md` / `Netexec.md` のスプレーへ |
| `krbtgt` ユーザーが見える | **ドメインコントローラー確定**（krbtgt は DC のみに存在）| 当該ホストを優先ターゲットに |
| `svc_*` / `sql_*` / `web_*` / `iis_*` 等のサービスアカウント名 | **Kerberoast 候補**（SPN 持ちの可能性高） | 認証取得後に `../04_Post_Access_Windows_AD/Kerberos_Attacks/Kerberoasting.md` |
| `enumdomgroups` に `Remote Management Users` がある | WinRM 経路の候補グループ | 当該グループメンバを §5 で取得 → メンバ cred を狙う |
| `enumdomgroups` に `Enterprise Admins` / `Domain Admins` | AD 管理者候補 | §5 でメンバ取得して優先ターゲット決定 |
| `enumalsgroups builtin` に `Backup Operators` | バックアップ権限経由の DCSync / SAM dump 候補 | メンバを §5 で取得 |
| `enumdomusers` で `ACCESS_DENIED` | 匿名列挙が無効化 | §6 lookupsid RID bruteforce（より緩い権限要件で通ることがある）|

**注意:**

- **RID 500 = Administrator / 502 = krbtgt / 501 = Guest** は固定値（ドメイン SID の suffix）。これが見える時点でドメイン構造が明らかになる
- **RID 1000 以降のユーザー** がドメイン管理者が作成したアカウント。RID が連番で並んでいたらその順序が作成順なので、初期管理者・移行アカウント・サービスアカウントの推定に使える
- `enum4linux-ng -A` は全部入りで便利だが、本番ではログが大量に出るのでターゲット側の検知器に拾われやすい。**ピンポイントで `rpcclient -c '...'` を実行する方が痕跡を抑えられる**
- ユーザー名一覧は `users.txt` として永続化し、SSH / FTP / WinRM の認証スプレー（`./SSH.md` / `./FTP.md` / `./WinRM.md`）でも使い回す

---

## 5. 詳細属性取得（queryuser / lookupsids / queryusergroups）

**コマンド:**

```bash
# [Attacker] 特定 RID のユーザー詳細属性
rpcclient -U "" -N [TARGET_IP] -c 'queryuser 0x44f'
# または 10進数で
rpcclient -U "" -N [TARGET_IP] -c 'queryuser 1103'

# [Attacker] ユーザー名 → SID 解決
rpcclient -U "" -N [TARGET_IP] -c 'lookupnames Administrator'

# [Attacker] SID → ユーザー名・タイプ解決
rpcclient -U "" -N [TARGET_IP] -c 'lookupsids S-1-5-21-[DOMAIN_SID]-500'

# [Attacker] ユーザーの所属グループ
rpcclient -U "" -N [TARGET_IP] -c 'queryusergroups 0x1f4'

# [Attacker] グループのメンバ
rpcclient -U "" -N [TARGET_IP] -c 'querygroupmem 0x200'  # Domain Admins (RID 512 = 0x200)

# [Attacker] エイリアスメンバ取得（Enterprise Admins / Administrators 等の builtin）
rpcclient -U "" -N [TARGET_IP] -c 'queryaliasmem builtin 0x220'  # Administrators

# [Attacker] 全ユーザーの description フィールドを一気に取る（パスワード平文が埋まっていることがある）
for rid in $(rpcclient -U "" -N [TARGET_IP] -c 'enumdomusers' | grep -oP 'rid:\[\K[^\]]+'); do
  echo "=== RID $rid ==="
  rpcclient -U "" -N [TARGET_IP] -c "queryuser $rid" | grep -E 'User Name|Description|Account Name|Full Name|Acct Flags'
done
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `queryuser` の `Description` フィールドに「初期パスワード: ...」「Pwd: ...」等の文字列 | **運用ミスで平文パスワード露出** | 即座にそのパスワードで `nxc smb` 認証確認 → ヒットすればフラッグ的 finding |
| `Account Flags: [UD]` / `[NORMAL_ACCOUNT]` | 通常ユーザー | スプレー対象 |
| `Account Flags: [DD]` / `Account disabled` | 無効アカウント | スプレー対象外（時間節約）|
| `Account Flags: [NRP]` / `Password never required` | パスワード不要アカウント | **空パスワードで認証試行**（[`../02_Initial_Access/Default_Credentials.md`](../02_Initial_Access/Default_Credentials.md)）|
| `Account Flags: [DNE]` / `Don't expire password` | パスワード期限なし | サービスアカウント候補（変更されないので長期 valid） |
| `Account Flags: [TS]` / `Trusted for Delegation` | 委任有効 | `../04_Post_Access_Windows_AD/Delegation_Attacks/` 参照（Unconstrained / Constrained）|
| `Bad Password Count: [N]` (queryuser) | 直近の認証失敗回数 | スプレー設計の余裕計算に使う（閾値 - N の回数だけ試行可能）|
| `querygroupmem 0x200` でユーザー RID 一覧 | Domain Admins メンバ確定 | 当該ユーザーを優先ターゲット化（cred 取れれば即 DA）|
| `queryaliasmem builtin 0x220` でユーザー一覧 | ローカル Administrators 相当 | LM_HASH 取得 / SAM dump の候補 |

**注意:**

- **`Description` フィールドの平文パスワード**は **非常に頻繁に出現する** finding。新人作成時の初期パスワードを書きっぱなしのケースや、運用上のメモを残したケースが典型。**1 ユーザーずつ全部 grep する価値がある**
- RID は **16 進・10 進どちらでも受け付ける** が、`queryuser` の RID 引数表記はバージョン依存。両方試す
- `Account Flags` の略号一覧:
  - `U` Account active / `D` Account disabled
  - `N` Password not required / `D` Password doesn't expire
  - `M` Machine account / `T` Temp duplicate account
  - `S` MNS logon account / `K` Smartcard required
  - `R` Server trust account / `L` Workstation trust account
  - `W` Interdomain trust account / `P` Use DES key only
  - `O` Don't require pre-auth ← **AS-REP Roastable 候補**（[`../04_Post_Access_Windows_AD/Kerberos_Attacks/ASREProast.md`](../04_Post_Access_Windows_AD/Kerberos_Attacks/ASREProast.md) があれば参照）

---

## 6. lookupsid による RID bruteforce

**コマンド:**

```bash
# [Attacker] 匿名で全 RID を網羅的に試行（enumdomusers が拒否される環境向け）
impacket-lookupsid '[TARGET_IP]' -no-pass

# [Attacker] 認証ありでより多くの RID が解決できる
impacket-lookupsid '[DOMAIN]/[USER]:[PASSWORD]@[TARGET_IP]'

# [Attacker] guest 認証
impacket-lookupsid 'guest@[TARGET_IP]' -no-pass

# [Attacker] 試行範囲指定（既定 4000、AD では 10000+ が安全）
impacket-lookupsid '[DOMAIN]/[USER]:[PASSWORD]@[TARGET_IP]' 10000

# [Attacker] nxc 経由（同等機能、出力整形が見やすい）
nxc smb [TARGET_IP] -u '' -p '' --rid-brute 10000
nxc smb [TARGET_IP] -u '[USER]' -p '[PASSWORD]' --rid-brute 10000

# [Attacker] rpcclient 単体でも RID bruteforce 可（手動）
for rid in $(seq 500 4000); do
  rpcclient -U "" -N [TARGET_IP] -c "lookupsids S-1-5-21-[DOMAIN_SID]-$rid" 2>/dev/null
done
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `[NUMERIC_RID]: [DOMAIN]\[USER] (SidTypeUser)` 行が大量 | RID bruteforce 成立 | ユーザー一覧として保存・スプレー対象化 |
| `(SidTypeGroup)` / `(SidTypeAlias)` 行 | グループ・エイリアス | §5 querygroupmem で展開 |
| `(SidTypeWellKnownGroup)` | Everyone / Authenticated Users 等の組込 | 列挙対象外（参考情報のみ）|
| `(SidTypeDomain)` / `(SidTypeUnknown)` | 未割当 RID | スキップ |
| `(SidTypeComputer)` | コンピューターアカウント | `$` 付きのアカウント名（`HOSTNAME$`）→ AD コンピューター列挙の起点 |
| 全行 `ACCESS_DENIED` | LSAT も拒否（強化構成）| 認証取得後に再実行 / LDAP 経由（[`LDAP_Enumeration.md`](LDAP_Enumeration.md)）|
| 0-500 までしか返らない | ローカル SAM のみ・Workgroup 環境 | ドメイン参加していないホスト確定 |
| RID 500・502 含む 1000+ が大量 | フル AD 環境 | スプレー対象が大量・優先度設計が必要 |

**注意:**

- **`enumdomusers` が拒否される環境でも lookupsid は通ることがある** — SAMR より LSAT の方が権限要件が緩いため。**enumdomusers で詰まったら必ず lookupsid を試す**
- **RID bruteforce は AD アカウントロックアウトを発動させない** — SAMR / LSAT 経由の SID 解決は認証ではなく**読み取り操作**。`bad password count` を増やさないため、`lockoutThreshold` を気にせず網羅実行できる（§1 「MS-SAMR の重要な性質」と同根）。**列挙は無制限・スプレーは制限**という境界を明確に意識する
- 既定の 4000 件試行は AD 中規模環境ではユーザー全部を拾えない。**`10000` 以上を指定する** か、コンピューターアカウントが多い大規模 AD では `100000` まで広げる
- **ノイズの大半は `(SidTypeUnknown)`** なので、`grep -v Unknown` で抑制。ユーザーだけ欲しければ `grep SidTypeUser`
- ドメインコンピューターアカウント（`HOSTNAME$`）を `grep SidTypeUser | grep '\$$'` で抽出 → AD 内ホスト網羅マップに使う

---

## 7. impacket-samrdump による包括的列挙

**コマンド:**

```bash
# [Attacker] SAMR インターフェース経由で全ドメインユーザー・グループ・パスワードポリシー一括取得
impacket-samrdump [TARGET_IP]

# [Attacker] 認証あり
impacket-samrdump '[DOMAIN]/[USER]:[PASSWORD]@[TARGET_IP]'

# [Attacker] NTLM ハッシュ認証
impacket-samrdump -hashes :[NTLM_HASH] '[DOMAIN]/[USER]@[TARGET_IP]'

# [Attacker] Kerberos 認証
impacket-samrdump -k -no-pass '[DOMAIN]/[USER]@[TARGET_FQDN]'

# [Attacker] 445 ポートを使わず 139 経由で
impacket-samrdump [TARGET_IP] 139/SMB
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `Found user: [USER], uid = [RID]` 行が大量 | 全ユーザー列挙成立 | §4 と組み合わせて重複排除 |
| `Password Info for Domain: [DOMAIN]` ブロック | パスワードポリシー完備 | §3 `getdompwinfo` が拒否された環境での代替経路 |
| `Min password length: [N]` | スプレー設計の制約 | `[N]` 未満のパスワードは試さない |
| `Password history length: [N]` | パスワード履歴数（前 `[N]` 個が再利用不可） | 既知パスワードのバリエーション試行に役立つ |
| `Lockout threshold: None` | ロックアウト無効 | スプレー実施 OK |
| `Lockout threshold: [N]` | 有限値 | `Account_Lockout_Recon.md` で観察期間取得 |
| `Pwd Last Set: ...` がユーザーごとに出る | パスワード最終変更時刻 | 長期未変更のサービスアカウント候補抽出（古い hash の使い回しを期待）|
| `[-] Connect error: ... SMB SessionError: STATUS_ACCESS_DENIED` | 匿名 SAMR 拒否 | guest 試行 / 認証取得後再実行 |

**注意:**

- `impacket-samrdump` は **rpcclient `getdompwinfo` + `enumdomusers` + `queryuser` を 1 回で一括取得** する効率的なツール。**最初に samrdump → 詰まったら rpcclient で個別ピンポイント** の流れが速い
- 出力の `Password Info` ブロックは **`getdompwinfo` よりリッチ**（履歴長・最大年数・最小年数まで出る）。これだけで `Account_Lockout_Recon.md` で取りたい情報のほとんどが揃う
- 認証ありで実行すると `Account Active: True/False` `Account Flags: ...` がユーザーごとに付くので、無効アカウントをスプレー対象から除外できる
- 大規模 AD では出力が数千行になる。`> samrdump_[TARGET_IP].txt` でファイル保存し、後で grep する設計にする

---

## 8. 認証情報取得後の再列挙（権限差分の確認）

**着火条件:** 匿名で得られなかった情報を、低権限ユーザー cred を取得後に再列挙する。匿名 → guest → 認証ユーザー → 管理者 と権限段階を上げるたびに、列挙できる情報量が階段状に増える。

**コマンド:**

```bash
# [Attacker] 認証ありでフル再列挙
rpcclient -U "[DOMAIN]\[USER]%[PASSWORD]" [TARGET_IP]
# プロンプト内で以下を順に
rpcclient $> querydominfo
rpcclient $> getdompwinfo
rpcclient $> enumdomusers
rpcclient $> enumdomgroups
rpcclient $> enumalsgroups builtin
rpcclient $> queryuser 0x44f
rpcclient $> querygroupmem 0x200   # Domain Admins
rpcclient $> queryaliasmem builtin 0x220   # Administrators

# [Attacker] NTLM ハッシュ認証（パスワード不明・hash のみある場合）
rpcclient -U "[DOMAIN]\[USER]" --pw-nt-hash [NTLM_HASH] [TARGET_IP]

# [Attacker] Kerberos 認証（kinit 後）
export KRB5CCNAME=/tmp/krb5cc_$(id -u)
kinit [USER]@[DOMAIN.UPPER]
rpcclient -k [TARGET_FQDN]

# [Attacker] nxc で一括認証列挙（匿名・guest・認証ありを比較）
nxc smb [TARGET_IP] -u '' -p '' --users --groups --pass-pol
nxc smb [TARGET_IP] -u '[USER]' -p '[PASSWORD]' --users --groups --pass-pol --loggedon-users --shares
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 匿名で見えなかったユーザー / グループが見える | RestrictAnonymous で隠されていた | スプレー対象を更新 |
| `--loggedon-users` でログイン中ユーザー一覧 | 認証ユーザー以上の権限が必要 | ログイン中ユーザーの cred を Mimikatz / lsass dump で奪う候補（[`../04_Post_Access_Windows_AD/Credential_Dumping.md`](../04_Post_Access_Windows_AD/Credential_Dumping.md)）|
| `--shares` で書込可能共有 | 認証後に共有書込権が見える | `../01_Reconnaissance/SMB_Enumeration.md` の共有列挙へ |
| `queryuser` で全フィールドが返る | 認証ユーザーは Description / Password Last Set / Bad Password Count まで読める | §5 の description grep を再実行・全ユーザー対象 |
| `queryusergroups` で他ユーザーのグループ所属が見える | 認証 cred で BloodHound 同等の情報が引ける | [`../05_Tools_Reference/BloodHound.md`](../05_Tools_Reference/BloodHound.md) で全体構造把握 |
| 管理者 cred で `getdompwinfo` 全フィールド見える | password policy 完備 | スプレー設計を最終化 |
| 認証情報でも `ACCESS_DENIED` | 強化構成（特定グループのみ列挙可能）| BloodHound で writable ACE を辿って権限経路探索 |

**注意:**

- **匿名で取れたユーザーリストと認証後リストを `diff` して差分を取る** と、隠されていたサービスアカウント・特権アカウントが浮かび上がることが多い
- `nxc smb -u ... -p ... --users --groups --pass-pol` は rpcclient / samrdump を内部で叩いて整形した出力を返す。**スクリプト化しやすい**のでスプレー前の最終確認に便利
- 認証ありでも `ACCESS_DENIED` が出るのは **AD 強化構成**（`ms-DS-MachineAccountQuota=0` / 認証ユーザーグループの権限剥奪等）。BloodHound で writable ACE / GenericWrite / GenericAll を辿る経路に切替（`../04_Post_Access_Windows_AD/`）
- 認証情報取得後の RPC 再列挙は **LDAP 認証列挙（[`LDAP_Enumeration.md`](LDAP_Enumeration.md)）と組み合わせる** ことで漏れを最小化できる。RPC は MS-SAMR ベース・LDAP は AD オブジェクト本体ベースで、見えるものが微妙に違う

---

## 刺さらなかったとき（全体）

| 状況 | 推定原因 | 代替手段 |
|---|---|---|
| `rpcclient -U "" -N` が `LOGON_FAILURE` で即拒否 | Server 2012 R2+ の既定で匿名無効 / `RestrictAnonymous=1` | guest 試行 / 認証取得経路に戻る（[`../02_Initial_Access/Default_Credentials.md`](../02_Initial_Access/Default_Credentials.md) のスプレー） |
| プロンプトは出るが `enumdomusers` で `ACCESS_DENIED` | bind は通るが SAMR 操作拒否 | §6 lookupsid（LSAT 経由）に切替 |
| `enumdomusers` も `lookupsid` も拒否 | 全面強化 | LDAP 匿名バインド（[`LDAP_Enumeration.md`](LDAP_Enumeration.md)）/ Kerberos username enum（事前認証エラー観察） |
| 135/139/445 すべて FW でブロック | 外部から RPC 不可 | Port 593（RPC over HTTP, `impacket-rpcdump -p 593`）を試す / LDAP / Kerberos（389/88）/ HTTP 経由の代替経路を探す |
| nmap で見えるアドレスが 1 つだけ・内部経路が不明 | ターゲットが NAT 越し・複数 NIC 構成 | §1 IOXIDResolver で IPv6 / 内部 IP を取得 → そのアドレスに対して再列挙 |
| Samba ターゲットで `lookupsids` が空 | Samba 4.x の挙動差 | `rpcclient -c 'enumdomusers'` を直接 / `enum4linux-ng -A` の一括出力で代替 |
| `getdompwinfo` で `ACCESS_DENIED` | 匿名で password policy 取れない | `impacket-samrdump`（§7）で代替・低権限 cred 取得後に再実行 |
| `impacket-lookupsid` がタイムアウト多発 | ネットワーク遅延 / レート制限 | 試行範囲を絞る（既定 4000 → 1000 等）/ 1 つずつ rpcclient で手動 |
| 認証情報ありでも全コマンド拒否 | 認証ユーザーグループの権限剥奪・強化構成 | BloodHound で writable ACE / GenericWrite を辿る（`../04_Post_Access_Windows_AD/`） |
| `nxc smb --rid-brute` の出力が空 | guest / 匿名拒否環境 + 認証なし | 認証取得後に `--rid-brute` 再実行 |
| ユーザー一覧は取れたがパスワードスプレーが全部失敗 | パスワードポリシーで `min_length` が長い・複雑性要求 | 季節 + 年 + 記号系で再構築・組織名ベース辞書を作成 |

## 注意点・落とし穴

> **本ファイルは「列挙」のみを扱う。** ここで取得したユーザー一覧を後段のパスワードスプレー（[`../02_Initial_Access/Default_Credentials.md`](../02_Initial_Access/Default_Credentials.md) / [`../05_Tools_Reference/Netexec.md`](../05_Tools_Reference/Netexec.md)）に投入する際は、**先に `Account_Lockout_Recon.md` でロックアウト閾値・観察期間を取得すること**。本ファイル §3 / §7 で取れた `lockout_threshold` / `lockout_observation_window` 値をそのまま流用する。

> **個別のブロック固有の注意は各 §N ブロック内の「注意:」を参照。** 本セクションは複数ブロックを横断する全体的な落とし穴のみを置く。

- **匿名で取れる情報の範囲は OS バージョン依存**: Windows Server 2003 ≫ 2008 R2 ≫ 2012 R2 ≫ 2016+ の順に閉じていく。古い OS が混在する AD 環境では、**最も古い DC をターゲットに匿名列挙を試す** のが定石
- **同じ情報が rpcclient / lookupsid / samrdump / nxc で取れる場合がある** が、権限要件・出力フォーマットが微妙に違う。**1 つで詰まったら別経路を試す**: SAMR 拒否 → LSAT、rpcclient 拒否 → samrdump、samrdump 拒否 → nxc --rid-brute
- **RID 1000-2000 帯のサービスアカウント検出が最重要**: 一般ユーザー RID（1000+）に紛れて `svc_*` / `sql_*` / `web_*` / `iis_*` 等が並ぶ。**サービスアカウントは SPN を持つことが多く Kerberoast 対象**になる
- **description フィールドの平文パスワードは何度でも確認する**: §5 の手動 grep を、**匿名 → guest → 認証ユーザー → 管理者** の各権限段階で再実行する。権限が上がるたびに見える description が増えるため
- **rpcclient セッションを開きっぱなしにしない**: 短時間で連続コマンドを実行する場合は `-c 'command'` で 1 回ずつ叩く方が痕跡が短く済む。本番では Event ID 5145（共有オブジェクトアクセス）が出力対象になり得る

### 本番での前提

- **事前合意の要否**: ★★（口頭確認可 — 本ファイルは列挙のみで業務影響なし。ただし対象組織との合意範囲は確認）/ §8 認証ありの列挙はその cred 取得経路次第で書面承認必須
- **想定される SIEM / EDR 検知**:
  - Event ID 4624（LogonType 3 ネットワーク経由・匿名は `ANONYMOUS LOGON`）
  - Event ID 5140 / 5145（共有・名前付きパイプアクセス・`\\IPC$` / `\\samr` / `\\lsarpc`）
  - SAMR / LSAT 監査が有効化されている環境では `Microsoft-Windows-Security-Auditing` で MS-SAMR メソッド呼出が記録される（既定では無効）
  - 大量 RID bruteforce は IDS で「SAMR enumeration」シグネチャに一致する場合あり
- **業務影響リスク**: なし（読み取り専用）。ただし §8 認証ありで誤ってロックアウト閾値を超えると業務影響発生 → スプレーは別ファイルで設計
- **原状回復必須項目**:
  - ✅ Kerberos チケット使用時は `kdestroy`
  - ✅ 取得した認証情報・ハッシュ・ユーザー一覧ファイルの安全な破棄
- **取得情報の取扱**: ユーザー一覧・パスワードポリシーはテスト完了時に破棄 / 対象組織への返却
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

## 関連技術

- 前：135 / 139 / 445 ポートの発見 → `Network_Scanning.md`
- 前：SMB バナー・OS バージョン判定 → `SMB_Enumeration.md`
- 関連：LDAP 経由の補完列挙（AD オブジェクト本体）→ `LDAP_Enumeration.md`
- 関連：DNS 経由でのドメイン構造把握 → `DNS_Enumeration.md`
- 関連：列挙結果を流す前のロックアウト事前確認 → `../02_Initial_Access/Account_Lockout_Recon.md`
- 関連：NetExec のリファレンス（`--users` / `--groups` / `--rid-brute` / `--pass-pol`）→ `../05_Tools_Reference/Netexec.md`
- 関連：Impacket スイート全体（samrdump / lookupsid / rpcdump）→ `../05_Tools_Reference/Impacket_Suite.md`
- 関連：AD 環境での hosts 登録（FQDN 解決が必要なとき）→ `../06_Concepts/Hosts_File_For_AD.md`
- 後：取得したユーザー一覧でのパスワードスプレー → `../02_Initial_Access/Default_Credentials.md`
- 後：認証情報取得後の Impacket exec 経路 → `../02_Initial_Access/Impacket_Exec.md`
- 後：WinRM 経由の対話シェル取得 → `../02_Initial_Access/WinRM.md`
- 後：SSH 認証突破・侵入（取得ユーザー名の SSH 横使い回し）→ `../02_Initial_Access/SSH.md`
- 後：BloodHound で AD 全体把握（writable ACE / GenericWrite 探索）→ `../05_Tools_Reference/BloodHound.md`
- 後：Kerberoast / AS-REP Roast（サービスアカウント・事前認証無効ユーザーへの攻撃）→ `../04_Post_Access_Windows_AD/Kerberos_Attacks/Kerberoasting.md`
