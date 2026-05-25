# MSRPC 列挙の動作原理（SAMR / LSAT / RID / null session）

## このファイルの位置づけ

参照元の作業ファイル：

- [`../01_Reconnaissance/RPC_Enumeration.md`](../01_Reconnaissance/RPC_Enumeration.md)（rpcclient / lookupsid / samrdump による列挙手順本体）
- [`../01_Reconnaissance/LDAP_Enumeration.md`](../01_Reconnaissance/LDAP_Enumeration.md)（並列の AD オブジェクト本体列挙経路）
- [`../02_Initial_Access/Account_Lockout_Recon.md`](../02_Initial_Access/Account_Lockout_Recon.md)（本ファイル §5 「列挙はロックアウトをバイパスする」の境界線をスプレー設計に持ち込む側）
- [`Impacket_Exec_Internals.md`](Impacket_Exec_Internals.md)（DCERPC 共通基盤の詳細。本ファイルは列挙視点で必要な範囲のみ触れる）
- [`AD_Terminology.md`](AD_Terminology.md)（SID / RID / SAM / LSA など AD 共通用語の定義）

RPC 列挙の作業手順を実行している最中に「なぜ `enumdomusers` が拒否されても `lookupsid` は通るのか」「なぜ RID bruteforce はアカウントロックアウトを発動させないのか」「なぜ `RestrictAnonymous` の挙動が OS バージョンで段階的に違うのか」「IOXIDResolver はなぜ認証なしで内部 IP / IPv6 を返してくるのか」が分からなくなったときに開く。手順そのものは作業ファイル側に置き、ここでは挙動の根拠だけを扱う。

> **出典について:** 本文では Microsoft の MS-RPCE / MS-SAMR / MS-LSAT / MS-LSAD / MS-DCOM / MS-NRPC 等のプロトコル仕様、および `RestrictAnonymous` / `RestrictAnonymousSAM` レジストリ値の歴史的経緯を引用するが、**条文番号・各 OS バージョンの厳密な既定値・URL は記憶から書かない**。実引用時は `WebFetch` で Microsoft Open Specifications / docs.microsoft.com を確認すること。本ファイルは「挙動レベルでなぜそうなるか」を整理するもので、規格の厳密参照を行うものではない。年号・SP 番号は経験則ベース。

---

## 1. MSRPC とは — 列挙視点での最低限の前提

### 1.1 一言で何か

**MSRPC = Microsoft RPC = DCERPC (Distributed Computing Environment / RPC) の Microsoft 実装**。Windows のサービス制御・SAM データベース読み書き・LSA 名前解決・タスクスケジューラ・WMI 等が「DCERPC インターフェース」として公開されている。列挙ツール（rpcclient / lookupsid / samrdump / nxc）はいずれもこの DCERPC インターフェースに対する関数呼出（クエリ）を発行する。

DCERPC 自体の接続フロー（135 エンドポイントマッパー → 動的ポート、SMB パイプ経由、SPNEGO/NTLM/Kerberos 認証）は [`Impacket_Exec_Internals.md`](Impacket_Exec_Internals.md) §1 で詳説しているため、本ファイルは「列挙時に特有の挙動」だけを扱う。

### 1.2 列挙が DCERPC を起点にする理由

列挙対象の「ドメインユーザー一覧」「グループメンバ」「SID ⇔ 名前変換」「パスワードポリシー」はすべて **AD / ローカル SAM の内部 API** で、LDAP / SMB バナーからは取れない。これらを外から叩く唯一の正式インターフェースが DCERPC 経由の SAMR / LSAT / LSAD。LDAP も並列の経路だが、LDAP は AD オブジェクト本体（`CN=Users,DC=...` のディレクトリ表現）を見るのに対し、SAMR は SAM データベースの API 層を呼ぶ。**同じユーザー情報が違う層から取れる**ため、片方が閉じていても片方は通ることがある。

---

## 2. ncacn_* バインディングと名前付きパイプ

DCERPC の「トランスポート + プロトコル」の組合せは `ncacn_<transport>` という識別子で表現される。列挙時に出会う主要な 3 種類：

| バインディング | トランスポート | 典型ポート | 列挙時の意味 |
|---|---|---|---|
| `ncacn_ip_tcp` | TCP 直接 | 135 + 動的ポート（49152-65535） | エンドポイントマッパー → 動的ポートで本体接続。FW が動的ポートを通さないと §1 EPM クエリは通っても本体に繋がらない |
| `ncacn_np` | SMB の名前付きパイプ | 445 (or 139) | `\\[TARGET]\IPC$\[PIPE_NAME]` 経由。`\pipe\samr` `\pipe\lsarpc` 等のパイプ名で個別 RPC IF に到達。**動的ポート不要なので FW を抜けやすい** |
| `ncacn_http` | RPC over HTTP | 593 (or 80/443) | Exchange の Outlook Anywhere、IIS 上の RPC Proxy 経由。Exchange 周辺でしか見ないことが多い |

**列挙視点で重要な含意：**

- `rpcclient -U "" -N [TARGET]` は **デフォルトで `ncacn_np`（SMB パイプ経由）** で接続する。つまり 445 が開いていれば 135 が閉じていても列挙できる
- `impacket-rpcdump [TARGET]` は **デフォルトで `ncacn_ip_tcp`（135 経由）** で EPM をクエリする。135 が閉じていれば即タイムアウト → SMB パイプ経由（`impacket-rpcdump [TARGET] -port 139`）にフォールバックする発想が必要
- `impacket-samrdump [TARGET] 139/SMB` のような末尾オプションは「トランスポート明示指定」。SAMR は両経路で同じインターフェースが叩けるが、片方しか通らない FW 構成は実環境で頻出

### 2.1 「TCP 135 開放確認」と「実際に DCERPC が呼べるか」は別

`nmap` で `135/tcp open msrpc` と出ても、EPM が返す動的ポート（例: 49664）が FW でブロックされていれば本体 RPC は呼べない。一方 SMB パイプ経由（`ncacn_np`）なら 445 一本で完結する。**手順ファイル §1 で「135 が閉じていたら §2 に進む」と書いてあるのはこのため**。

---

## 3. 列挙視点の主要 RPC インターフェース

列挙ツールが叩く主要インターフェースと、それぞれが何を返すか：

| インターフェース | 名前付きパイプ | プロトコル仕様 | 返すもの | 列挙手順 §N |
|---|---|---|---|---|
| **SAMR** (Security Account Manager Remote) | `\pipe\samr` | MS-SAMR | ユーザー一覧・グループ一覧・グループメンバ・パスワードポリシー・アカウントフラグ | §3 §4 §5 §7 |
| **LSAT** (LSA Translation) | `\pipe\lsarpc` | MS-LSAT | SID ⇔ 名前変換（双方向）| §5 lookupsids / §6 lookupsid |
| **LSAD** (LSA Domain Policy) | `\pipe\lsarpc` | MS-LSAD | ドメイン名・ドメイン SID・信頼関係 | §3 lsaquery |
| **SRVSVC** | `\pipe\srvsvc` | MS-SRVS | 共有列挙・セッション列挙 | （SMB_Enumeration.md 側）|
| **WKSSVC** | `\pipe\wkssvc` | MS-WKST | ワークステーション情報・ログオンユーザー | nxc `--loggedon-users` |
| **NETLOGON** | `\pipe\netlogon` | MS-NRPC | ドメインコントローラー発見・認証経路 | Zerologon 等の CVE（本ファイル範囲外）|

> **`\pipe\lsarpc` に 2 つの IFID がぶら下がる理由:** 同じ「LSA」と呼ばれる機能群が、歴史的に名前変換系 (LSAT) とドメインポリシー系 (LSAD) で別インターフェースに分かれている。両者は同じパイプ名でアクセスできるが、IFID（インターフェース ID）が違うため `BIND` 時に別物として扱われる。手順ファイル §1 の早見表で同じ `\pipe\lsarpc` が 2 行ある根拠。

### 3.1 LDAP との対比 — 「同じユーザー情報が違う層から取れる」の正体

| 項目 | RPC (SAMR) 経由 | LDAP 経由 |
|---|---|---|
| アクセス層 | SAM データベースの操作 API | AD ディレクトリオブジェクト本体 |
| 典型ポート | 445 (SMB pipe) / 135+動的 | 389 / 636 (LDAPS) / 3268 (GC) |
| 匿名で取れる範囲 | OS バージョン依存・既定では限定的 | namingcontexts のみ匿名可能なことが多い |
| 取得できる情報 | ユーザー名・RID・パスワードポリシー・グループメンバ | ユーザー名・属性全部（description / memberOf / userAccountControl 等）|
| 隠れているとき | LDAP で取れることがある | RPC で取れることがある |

**含意:** 片方を試して詰まったらもう片方を試す。手順ファイル §6「`enumdomusers` も `lookupsid` も拒否」のときに LDAP 匿名バインドを試すのはこの対比に基づく。逆も成立する（LDAP が ACL で固められていても RPC SAMR が緩い構成は存在）。

---

## 4. MS-SAMR と MS-LSAT — 役割の違いと権限要件の差

ここから本ファイルの中核。**「`enumdomusers` (SAMR) が `ACCESS_DENIED` でも `lookupsid` (LSAT) が通る」現象の根拠**。

### 4.1 SAMR の権限要件

SAMR は SAM データベース全体の操作インターフェース。代表的なクエリ手順：

```
SamrConnect5()             ← Server ハンドル取得（最初の関門。ここで匿名拒否されることが多い）
  → SamrEnumerateDomainsInSamServer()
SamrOpenDomain()           ← Domain ハンドル取得（ドメイン SID 指定）
  → SamrEnumerateUsersInDomain()    ← enumdomusers の中身
  → SamrLookupNamesInDomain()       ← 名前 → RID 変換
  → SamrOpenUser()                  ← User ハンドル取得
    → SamrQueryInformationUser2()   ← queryuser の中身（description / pwd_last_set 等）
```

各ハンドル取得時に **「DesiredAccess マスク」** を要求する。具体例：

- `SamrConnect5` で `SAM_SERVER_ENUMERATE_DOMAINS` を要求する場合、SAM サーバーの ACL で「Everyone」「Anonymous」に当該権限が無いと `STATUS_ACCESS_DENIED`
- `SamrOpenDomain` で `DOMAIN_LIST_ACCOUNTS` を要求する場合、ドメインオブジェクトの ACL で同様

これらの ACL は **`RestrictAnonymous` / `RestrictAnonymousSAM` レジストリ値** や Group Policy（「ネットワーク アクセス: SAM アカウントの匿名列挙を許可しない」「ネットワーク アクセス: SAM アカウントと共有の匿名列挙を許可しない」相当の設定）で制御される。OS バージョンで既定値が違うのは §6 で扱う。

### 4.2 LSAT の権限要件

LSAT は「SID ⇔ 名前」の変換に特化したインターフェース：

```
LsarOpenPolicy() / LsarOpenPolicy2()   ← Policy ハンドル取得
  → LsarLookupSids() / LsarLookupSids2() / LsarLookupSids3()    ← SID → 名前
  → LsarLookupNames() / LsarLookupNames2() / LsarLookupNames3() / LsarLookupNames4()  ← 名前 → SID
```

LSAT の **DesiredAccess は `POLICY_LOOKUP_NAMES` 単独で十分**。SAMR の `SAM_SERVER_ENUMERATE_DOMAINS` + `DOMAIN_LIST_ACCOUNTS` のように複数権限の AND 条件ではない。

そして **LSA Policy オブジェクトの ACL は SAM データベースの ACL より歴史的に緩く構成されている** ことが多い。具体的には：

- Server 2003 以降、SAM 列挙の匿名アクセスは段階的に閉じられた
- LSAT の名前変換は「他システム連携で SID を名前に解決する」基本機能のため、より広く許可される傾向（Group Policy 上の「LSA」項目で別途絞らないと閉じない）

**含意:** 手順ファイル §6 「`enumdomusers` で詰まったら必ず lookupsid を試す」は、SAMR と LSAT が **別 ACL** を持つことに根拠がある。LSAT が通れば RID を 1 つずつ振って網羅できる（§7 RID bruteforce）。

### 4.3 双方向変換が可能なゆえの RID bruteforce

LSAT は **「名前 → SID」だけでなく「SID → 名前」の両方向を提供する**。攻撃者視点では：

1. `LsarOpenPolicy2` で Policy ハンドルを取得（一度の認証）
2. ドメイン SID（`S-1-5-21-X-Y-Z`）を `lsaquery` 等で取得
3. RID を `500, 501, 502, 1000, 1001, ...` と振って `LsarLookupSids` を連発
4. 返ってきた行を `(SidTypeUser)` / `(SidTypeGroup)` 等で分類

これが `impacket-lookupsid` / `nxc smb --rid-brute` の正体。**1 回の認証で大量の SID を解決できる**ため、コストが極めて低い。次節の「ロックアウトをバイパスする」性質と組み合わさることで、ほぼ無制限に網羅実行できる経路になる。

---

## 5. なぜ「列挙」は AD アカウントロックアウトをバイパスするか

手順ファイル §1（MS-SAMR の重要な性質）と §6（RID bruteforce）で 2 回繰り返している原理。

### 5.1 ロックアウトが発動する条件

AD のアカウントロックアウトは **「`badPwdCount` 属性のインクリメント」** で発動する：

- ユーザーが対話的 / ネットワーク経由 / Kerberos 経由などで **認証を試行して失敗** すると、DC が当該ユーザーオブジェクトの `badPwdCount` を +1
- `badPwdCount` が `lockoutThreshold` に達すると `lockoutTime` が設定され、`Account_Lockout_Recon.md` で取得する `lockoutDuration` の間ロック
- `observationWindow` を超えても次の失敗が来なければ `badPwdCount` はリセット

**ポイント:** ロックアウトのトリガは **「認証試行 (Authentication)」** であって、「読み取り (Lookup / Enumerate)」ではない。

### 5.2 SAMR / LSAT 経由のクエリは「認証」ではなく「読み取り」

SAMR / LSAT のクエリは次のステップで実行される：

```
[Step 1] DCERPC BIND
         SPNEGO 経由で NTLM / Kerberos / 匿名 のいずれかで認証
         認証成功 → BIND_ACK で RPC コンテキスト確立
         認証失敗 → ここで失敗（このときは badPwdCount が +1 されうる）

[Step 2] BIND 成功後、RPC メソッド呼出（読み取り）
         SamrEnumerateUsersInDomain
         LsarLookupSids
         SamrQueryInformationDomain
         ... 何回呼んでも認証ではなく読み取り
         ACL チェックは入るが badPwdCount は変動しない
```

**含意:** 一度 `BIND` に成功してしまえば（匿名でも guest でも認証ユーザーでも）、同じハンドル / セッション内で **何千回 SID 解決を呼んでもロックアウト閾値に触れない**。これが「列挙は無制限」の正体。

### 5.3 一方、パスワードスプレーは「認証試行」そのもの

`nxc smb [TARGET] -u user1 -p Pass1` のような認証は **Step 1（BIND）の段階で** ユーザーごとに別認証を発行する。失敗すれば各ユーザーの `badPwdCount` が +1 され、`lockoutThreshold` に達すればロック。だから「列挙は無制限・スプレーは閾値制限」の境界が引かれる。

### 5.4 例外と注意

- **DCERPC BIND 自体での認証失敗は badPwdCount を増やす可能性がある**。匿名 BIND を試して `LOGON_FAILURE` が返るケースは「匿名アカウントが存在しないので失敗扱い」となり通常は無害だが、特定ユーザーで何度も BIND 失敗を起こす実装ミスをすると、そのユーザーがロックされる。`rpcclient -U "[USER]%[WRONG_PASS]"` を連発するのは「スプレー」と同じ
- **NetLogon / Kerberos 経由の username 列挙**（事前認証エラー観察による存在確認）は通常 badPwdCount を増やさないが、特定構成では監査ログに残る
- **古い Samba 実装** は ACL チェックや認証カウンタの実装が Windows と微妙に違うことがある。Samba ターゲットで上記原理がそのまま適用できると断定しない

### 5.5 出典の弱さに関する注釈

「SAMR / LSAT の読み取りメソッドが badPwdCount を増やさない」ことは **長年の実観測・運用知識として広く知られている** が、Microsoft 公式ドキュメントで明文化された記述として私が確信を持っている引用は無い。MS-SAMR / MS-LSAT 仕様書には個別メソッドの ACL 要件は記載されているが、「badPwdCount に影響しない」という明示的な記述があるかは未確認。本番で「ロックアウトしないと言ったのにロックした」事態を避けるため、**重要本番では小規模試行 → 数分待機 → `badPwdCount` 観察** で実環境挙動を確認するのが安全。

---

## 6. RestrictAnonymous の歴史と OS バージョン依存

「古い OS ほど匿名で取れる」「Server 2012 R2+ は匿名拒否が既定」の経験則の根拠。

### 6.1 おおまかな経緯（記憶ベース、要 WebFetch 確認）

| 時期 / OS | レジストリ値 | 既定挙動 |
|---|---|---|
| NT 4.0 SP3 まで | （設定なし） | 匿名で SAM / Share 列挙可能。null session が大量に開く |
| NT 4.0 SP3 以降 | `RestrictAnonymous=0` 既定 | 列挙制限なし（`=1` で限定的に絞れる） |
| Windows 2000 | `RestrictAnonymous=0` 既定 | 同上 |
| Server 2003 | `RestrictAnonymous=1` 既定、`RestrictAnonymousSAM=1` 既定 | SAM 列挙の匿名はかなり絞られる |
| Server 2008 / 2008 R2 | 強化継続 | 匿名 SAMR `enumdomusers` 拒否が増える |
| Server 2012 / 2012 R2 | 既定で匿名拒否強化 | `rpcclient -U "" -N` が `NT_STATUS_LOGON_FAILURE` で蹴られるのが既定 |
| Server 2016+ | さらに強化 | LSAT の匿名 lookup も絞られることがある（Group Policy 次第） |

**年号・SP 番号・既定値は記憶ベース。** 本番で OS バージョン依存挙動を断言する必要があれば、Microsoft docs の「Network access: Allow anonymous SID/Name translation」「Network access: Do not allow anonymous enumeration of SAM accounts」「Network access: Do not allow anonymous enumeration of SAM accounts and shares」を `WebFetch` で確認すること。

### 6.2 関連レジストリ値・Group Policy 設定

- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymous`
- `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM`
- `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\RestrictNullSessAccess`
- `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\NullSessionPipes`
- `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\NullSessionShares`

Group Policy 上は「コンピューターの構成 → Windows の設定 → セキュリティの設定 → ローカル ポリシー → セキュリティ オプション」に同等項目があり、ドメインで一括配信されるのが一般的。

### 6.3 含意

- **古い DC / 古いメンバーサーバーが残っている AD は匿名列挙が通る確率が上がる**。手順ファイル §1〜§7 のコマンドを **OS バージョンが古いホストから試す** のが効率的
- 強化構成（`RestrictAnonymous=2` 相当 + `RestrictNullSessAccess=1`）では SAM だけでなく LSAT も絞られる。この場合は LDAP / Kerberos 経路（[`../01_Reconnaissance/LDAP_Enumeration.md`](../01_Reconnaissance/LDAP_Enumeration.md)）に切替
- guest アカウントが有効化されている古い Samba（Linux NAS の SMB 公開等）は **これらのレジストリと無関係**。Samba は独自の `guest ok` / `map to guest` 設定で動くので、Windows の強化状況と独立して列挙可能なことがある

---

## 7. RID とドメイン SID の構造

`rpcclient` 出力中の `rid:[0x1f4]` `rid:[0x44f]` や `S-1-5-21-...` を理解するための前提。

### 7.1 SID の組成

ドメインユーザーの SID は以下の形：

```
S-1-5-21-[X]-[Y]-[Z]-[RID]
↑ ↑ ↑  ↑    ↑    ↑    ↑
│ │ │  └────┴────┘    └── RID (Relative ID)
│ │ │   ドメイン識別子（3 つの 32-bit 整数）
│ │ └── 21 = SECURITY_NT_NON_UNIQUE_AUTHORITY（NT ドメイン用）
│ └── 5 = SECURITY_NT_AUTHORITY
└── Revision (常に 1)
```

ローカル SAM の SID は `S-1-5-21-[X]-[Y]-[Z]` 部分がコンピューター固有の値、AD ドメインの SID は DC で生成されたドメイン全体の固有値。**`lsaquery` で取れるのはドメイン SID の `S-1-5-21-[X]-[Y]-[Z]` 部分**。これに RID を付け足したものが完全な SID。

### 7.2 RID 固定値

| RID | アカウント | 備考 |
|---|---|---|
| 500 (0x1f4) | Administrator | 名前変更されていても RID 500 で固定識別可能 |
| 501 (0x1f5) | Guest | 同上 |
| 502 (0x1f6) | krbtgt | **AD ドメインコントローラーにのみ存在**。これが見えれば DC 確定 |
| 512 (0x200) | Domain Admins (グループ) | |
| 513 (0x201) | Domain Users (グループ) | |
| 514 (0x202) | Domain Guests (グループ) | |
| 515 (0x203) | Domain Computers (グループ) | |
| 516 (0x204) | Domain Controllers (グループ) | |
| 518 (0x206) | Schema Admins | |
| 519 (0x207) | Enterprise Admins | |
| 520 (0x208) | Group Policy Creator Owners | |

`builtin` グループ（`Administrators` / `Backup Operators` / `Remote Management Users` 等）は **別の SID 系統**（`S-1-5-32-RID`）で、RID 544 / 551 / 580 等が当たる。手順ファイル §5 で `queryaliasmem builtin 0x220` を叩くのはこちら（`S-1-5-32-544` = Administrators）。

### 7.3 RID 1000+ の連番性

ユーザー作成時、SAM は **モノトニックに増加するカウンタ** で RID を割り当てる：

- 既定では 1000 から開始
- 新規ユーザー / グループ / コンピューターアカウントが作られるたびに +1（厳密には何 N 個か飛ぶ実装もあるが、おおむね連番）
- 削除した RID は **再利用しない**（SID の一意性保証）

**含意:**

- RID 1000 から並んでいる順序は概ね「ドメイン構築初期からの作成順」に対応する
- 初期管理者・移行アカウント・移行後のユーザー・サービスアカウントの **時系列推定** に使える
- RID bruteforce の最大値は「ドメインに今までに作られたオブジェクト数 + α」で決まる。中規模 AD では数千〜数万、大規模 AD では 10 万超もありうる
- コンピューターアカウント（`HOSTNAME$`）も同じカウンタを共有するため、コンピューターが多い AD では RID bruteforce の試行範囲を広げる必要がある

### 7.4 SidType 値

`lookupsid` の出力に出る `(SidTypeUser)` 等の分類：

| SidType | 意味 | 列挙価値 |
|---|---|---|
| `SidTypeUser` | 通常ユーザーアカウント | ★★★（スプレー対象） |
| `SidTypeGroup` | グローバルグループ | ★★（querygroupmem で展開）|
| `SidTypeDomain` | ドメイン自体 | ★（ドメイン SID 確認）|
| `SidTypeAlias` | ローカル / Builtin グループ | ★★ |
| `SidTypeWellKnownGroup` | Everyone / Authenticated Users 等 | ☆ |
| `SidTypeDeletedAccount` | 削除済みアカウント | ☆ |
| `SidTypeInvalid` | 未割当 RID | ☆（スキップ）|
| `SidTypeUnknown` | 解決不能 | ☆（ノイズ）|
| `SidTypeComputer` | コンピューターアカウント (`HOSTNAME$`) | ★★（AD 内ホスト網羅マップに使う）|

---

## 8. IOXIDResolver — DCOM 経由の内部 IP / IPv6 漏洩

手順ファイル §1 で触れている「認証不要で内部アドレスが返る」現象の原理。

### 8.1 元の用途

DCOM (Distributed COM) はリモートオブジェクト呼出機構で、**負荷分散 / 高可用構成のため「サーバーが持つ全 NIC のアドレス」をクライアントに通知する** 仕組みを持つ。具体的には：

- `IObjectExporter::ServerAlive2()` — サーバーの生存確認 + ネットワーク情報
- `IObjectExporter::ResolveOxid2()` — OXID（Object Exporter ID）からバインディング情報解決

これらは **DCERPC のシステム IF（IID `99FCFEC4-5260-101B-BBCB-00AA0021347A`）** として 135 にバインドしており、認証不要で呼べる仕様。返り値の `STRINGBINDING` 配列にサーバーの全 NIC のアドレスが入る。

### 8.2 攻撃者視点での価値

ターゲットが NAT 越しに外部 IP しか見せていなくても、**内部 IP / IPv6 アドレス / ループバック以外の全インターフェース** が暴露される。具体的には：

- DMZ ホストの内部側 IP（プライベートレンジ）
- IPv6 が有効化されているが NMap で見えていなかったアドレス
- マルチホーム構成の管理セグメント側 IP

**含意:**

- 外部スキャンで見えない内部ネットワーク経路の起点として使える
- 暴露された IP に対して再列挙（SMB / LDAP / Kerberos）を行うと、外部経由よりも認証要件が緩いことがある
- IPv6 が返ってきた場合、Windows は IPv4 より IPv6 を優先することがあるため、IPv6 経路で SMB pipe に繋ぐと別挙動になることも

### 8.3 認知の経緯

この情報漏洩は DCOM 仕様の本来の動作で、**バグでも脆弱性でもない**。2017 年頃に `mubix/IOXIDResolver` ツールが公開されて以降、ペネトレ業界で広く認知された。Microsoft も「仕様通り」のスタンスで CVE 化されていない。Windows Server 2022 / Windows 11 でも既定で有効。

### 8.4 対策（防御者視点）

- 135 を外部公開しない（ファイアウォール）
- `RpcDisableOidcResolver` / DCOM の COM セキュリティ強化系の設定
- ただし内部からは認証なしで取れるため、**多層防御の前提で扱う**

---

## 環境が変わったときに確認すること

本ファイルの原理は「Windows AD ドメイン参加環境」を主前提に書いている。以下の環境変化があれば挙動が変わるため、その時点で再確認する：

| 環境変化 | 確認ポイント | 影響 |
|---|---|---|
| ターゲットが **Workgroup** | `querydominfo` のドメイン名 / `enumdomains` 結果 | SAM はローカル DB のみ。RID 母数小・krbtgt 不在 |
| ターゲットが **Samba 実装** | `srvinfo` / バナー | Windows と ACL 実装差。匿名挙動・SidType 解決が微妙に違う |
| **Server 2016+ / Windows 10+ 強化構成** | `RestrictAnonymous*` 値 | LSAT も絞られる可能性。LDAP / Kerberos 経路へ切替 |
| **読み取り専用 DC (RODC)** | `srvinfo` フラグ | 一部 SAM 操作が拒否。書込系 RPC は通らない |
| **マルチドメイン / フォレスト** | `enumdomains` / `lsaquery` | 信頼関係越しの列挙は別 ACL。各ドメインで再列挙 |
| **Azure AD / Hybrid** | DC ホスト名・FQDN | クラウド側の同期は LDAP/Graph 経由で別物 |
| **監査ログ強化環境** | Event ID 4624 / 5145 / 4661 監査有無 | 列挙でも痕跡が大量に残る。本番では事前合意で告知 |

---

## 関連技術

- 関連：RPC 列挙の作業手順本体 → [`../01_Reconnaissance/RPC_Enumeration.md`](../01_Reconnaissance/RPC_Enumeration.md)
- 関連：並列の AD オブジェクト本体列挙 → [`../01_Reconnaissance/LDAP_Enumeration.md`](../01_Reconnaissance/LDAP_Enumeration.md)
- 関連：本ファイル §5「列挙はロックアウトをバイパスする」境界線をスプレー側で扱う → [`../02_Initial_Access/Account_Lockout_Recon.md`](../02_Initial_Access/Account_Lockout_Recon.md)
- 関連：DCERPC の共通基盤（135 / 動的ポート / SMB パイプ / SPNEGO 認証） → [`Impacket_Exec_Internals.md`](Impacket_Exec_Internals.md)
- 関連：AD 共通用語（SID / RID / SAM / LSA / krbtgt） → [`AD_Terminology.md`](AD_Terminology.md)
- 関連：Workgroup と AD の境界 → [`Windows_Standalone_vs_AD.md`](Windows_Standalone_vs_AD.md)
- 関連：FQDN 解決のための hosts 登録 → [`Hosts_File_For_AD.md`](Hosts_File_For_AD.md)
