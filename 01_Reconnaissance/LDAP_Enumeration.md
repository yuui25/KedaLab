# LDAP列挙

## 着火条件
389 (LDAP) または 636 (LDAPS) が開いており、AD 環境と判断した場合。
匿名バインドでも部分情報が取れるが、認証情報が取れた時点で本格的に実施する。

---

## 観点・着眼点

**何が出たら次に何をするか：**

| 観測される出力 | 示唆 | 次のアクション |
|------------|-----|------------|
| `info` / `description` フィールドに文字列がある | 運用メモとしてパスワードが書かれていることがある | `grep -i "pass\|pwd\|cred"` で抽出 → そのまま認証情報として試す |
| `servicePrincipalName` が設定されたユーザーがある | Kerberoast 可能なサービスアカウント | SPN を持つユーザーに対して Kerberoasting |
| `userAccountControl` に `DONT_REQ_PREAUTH` フラグ（値 4194304） | AS-REP Roasting が可能 | 該当ユーザーで `GetNPUsers.py` |
| `memberOf` に `Domain Admins` / `Enterprise Admins` | 高権限ユーザーの特定 | そのユーザーの認証情報取得が最優先目標 |
| `pwdLastSet=0` | 初回ログイン前 / パスワードリセット直後 | 既定パスワードの可能性 |
| `adminCount=1` だが `Domain Admins` 外 | 過去に特権を持っていたアカウント（AdminSDHolder） | BloodHound で現在の ACL を確認 |
| `ms-Mcs-AdmPwd` 属性が読める | **LAPS のローカル管理者パスワード平文が読める** — 委譲権限の付与ミス | 値を取得して該当ホストに `Administrator` で接続 → `../04_Post_Access_Windows_AD/LAPS_Dump.md` |
| `msDS-GroupMSAMembership` に自分のグループが含まれる | gMSA パスワード読取権限がある | `gMSADumper.py` で `msDS-ManagedPassword` を取得 |
| `ms-DS-MachineAccountQuota` が 10（既定値）| 任意ユーザーが計算機アカウントを 10 個まで作成可能 | RBCD 攻撃の前提が揃う → `../04_Post_Access_Windows_AD/Delegation_Attacks/RBCD.md` |
| `(objectClass=trustedDomain)` でエントリが返る | フォレスト / ドメイン信頼が存在 | 信頼先ドメインへの横展開経路の検討（forest-wide DA への昇格経路） |
| 匿名バインドが通り `objectClass=*` で `Pre-Windows 2000 Compatible Access` メンバの権限相当が見える | 互換性のため `Pre-Windows 2000 Compatible Access` に `Anonymous Logon` 等が含まれている弱化構成 | 匿名で広範な列挙が可能（**finding**） |
| 匿名バインドで `sizeLimitExceeded` が返る | 匿名でも検索が通っている | 検索範囲・属性を絞って再実行 |
| 匿名バインドで `operationsError` | 匿名アクセスは拒否されている | 認証情報取得まで後回し |

**カスタム属性の扱い：** 標準属性だけでなく `info`、社内で独自追加された属性にも目を通す。`info` は GUI の「説明」欄とは別のフィールドで、GUI では編集されにくいため平文パスワードが残っていることがある。

---

## 手順

**匿名バインドの試行（最初の一手）：**
```bash
ldapsearch -x -H ldap://[IP] -b "DC=[domain],DC=[tld]"
# サブツリー指定なしで naming context を列挙
ldapsearch -x -H ldap://[IP] -s base namingcontexts
```

**基本的なユーザー列挙：**
```bash
ldapsearch -x -H ldap://[IP] \
  -D "[DOMAIN]\[USER]" \
  -w '[PASSWORD]' \
  -b "DC=[domain],DC=[tld]" \
  "(objectClass=user)" sAMAccountName info description memberOf userAccountControl
```

**全属性を取得（詳細調査）：**
```bash
ldapsearch -x -H ldap://[IP] \
  -D "[DOMAIN]\[USER]" \
  -w '[PASSWORD]' \
  -b "DC=[domain],DC=[tld]" \
  "(objectClass=user)"
```

**コンピューターアカウントの列挙：**
```bash
ldapsearch -x -H ldap://[IP] \
  -D "[DOMAIN]\[USER]" \
  -w '[PASSWORD]' \
  -b "DC=[domain],DC=[tld]" \
  "(objectClass=computer)" sAMAccountName dNSHostName operatingSystem
```

**有効なユーザーのみを抽出（無効化アカウントを除外）：**
```bash
# userAccountControl のビット 1 (ACCOUNTDISABLE = 0x2)
# OID 1.2.840.113556.1.4.803 はビット AND マッチ（LDAP_MATCHING_RULE_BIT_AND）
# `:=2` は「ACCOUNTDISABLE が立っている」→ 先頭の `!` で否定して「無効化されていない」を表現
ldapsearch -x -H ldap://[IP] \
  -D "[DOMAIN]\[USER]" -w '[PASSWORD]' \
  -b "DC=[domain],DC=[tld]" -s sub \
  "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" \
  sAMAccountName | grep sAMAccountName
```

> **なぜ無効化アカウントを除外するか：** Kerberoast / AS-REP Roast の標的を選ぶ際、無効化アカウントに SPN が残っていることがある。これらに対して TGS を要求しても認証できないため事前に除外する。**Active Directory の標準的な権限昇格調査では「有効ユーザーのみ抽出 → SPN フィルタを追加 → Kerberoast 候補を絞る」の2段階で進む。**

**SPN 付きユーザーの抽出（Kerberoast 候補）：**
```bash
# シンプルな SPN 検索
ldapsearch -x -H ldap://[IP] \
  -D "[DOMAIN]\[USER]" -w '[PASSWORD]' \
  -b "DC=[domain],DC=[tld]" \
  "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# 有効ユーザーのみに絞った SPN 検索（推奨）
# `servicePrincipalName=*/*` は `service/host` 形式の SPN を典型パターンとして抽出
ldapsearch -x -H ldap://[IP] \
  -D "[DOMAIN]\[USER]" -w '[PASSWORD]' \
  -b "DC=[domain],DC=[tld]" -s sub \
  "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(servicePrincipalName=*/*))" \
  sAMAccountName servicePrincipalName | grep -B 1 servicePrincipalName
```

> **`Administrator` に SPN が設定されているケースに注意：** 通常の Kerberoast は `SVC_xxx` のサービスアカウントが対象だが、設計ミスで Administrator アカウントに SPN（例: `cifs/[HOST]`）が付いていることがある。**この場合クラックに成功すれば即 DA**。SPN フィルタ実行後 `Administrator` の名前が出たら最優先で TGS 要求。

**AS-REP Roast 対象の抽出：**
```bash
# userAccountControl のビット 22 (DONT_REQ_PREAUTH = 0x400000)
ldapsearch ... "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName
```

**よく使う userAccountControl ビット値の早見表：**

| ビット値（10進） | フラグ名 | 意味 | フィルタ用途 |
|----------------|---------|------|------------|
| `2` | ACCOUNTDISABLE | アカウント無効化 | 有効なユーザーのみ抽出するため `!(...:=2)` で除外 |
| `512` | NORMAL_ACCOUNT | 標準ユーザーアカウント | コンピューターアカウントと区別 |
| `4096` | WORKSTATION_TRUST_ACCOUNT | コンピューターアカウント | ホスト一覧抽出 |
| `8192` | SERVER_TRUST_ACCOUNT | DC のコンピューターアカウント | DC 特定 |
| `65536` | DONT_EXPIRE_PASSWORD | パスワード無期限 | 古いサービスアカウント発見 |
| `524288` | TRUSTED_FOR_DELEGATION | Unconstrained Delegation | 委任攻撃の標的 |
| `4194304` | DONT_REQ_PREAUTH | 事前認証不要 | AS-REP Roast 候補 |
| `16777216` | TRUSTED_TO_AUTH_FOR_DELEGATION | Constrained Delegation | 委任攻撃の標的 |

> 詳細・他のビット値: `https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties`

**認証情報候補の一括抽出：**
```bash
ldapsearch ... | grep -i "info\|description\|pass\|pwd\|cred"
```

**LAPS パスワードの読み取り（読取権限が委譲されている場合）：**
```bash
# 認可ユーザーに LAPS 読取権限が委譲されていれば `ms-Mcs-AdmPwd` が平文で見える
ldapsearch -x -H ldap://[IP] \
  -D "[DOMAIN]\[USER]" -w '[PASSWORD]' \
  -b "DC=[domain],DC=[tld]" -s sub \
  "(&(objectClass=computer)(ms-Mcs-AdmPwd=*))" \
  sAMAccountName dNSHostName ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime

# nxc でも同等
nxc ldap [IP] -u [USER] -p '[PASSWORD]' -M laps
```

> 取得した平文パスワードでの侵入手順は [`../04_Post_Access_Windows_AD/LAPS_Dump.md`](../04_Post_Access_Windows_AD/LAPS_Dump.md) を参照。**Windows LAPS（v2 / 2023+）では属性名が `msLAPS-Password` 等に変わり、暗号化版もある**ので新環境では両方確認する。

**gMSA パスワード読取権限の確認（gMSADumper の前提）：**
```bash
# msDS-GroupMSAMembership に読取権限を持つグループが書かれている。自分のグループ SID が含まれていれば取得可能
ldapsearch -x -H ldap://[IP] \
  -D "[DOMAIN]\[USER]" -w '[PASSWORD]' \
  -b "DC=[domain],DC=[tld]" -s sub \
  "(objectClass=msDS-GroupManagedServiceAccount)" \
  sAMAccountName msDS-GroupMSAMembership servicePrincipalName

# 読取可能なら gMSADumper で blob を NTLM ハッシュに変換
gMSADumper.py -u [USER] -p '[PASSWORD]' -d [DOMAIN] -l [IP]
```

**MachineAccountQuota の確認（RBCD 攻撃前提）：**
```bash
# 既定 10 なら任意ユーザーが 10 個の計算機アカウントを作成可能（RBCD の前提が揃う）
ldapsearch -x -H ldap://[IP] \
  -D "[DOMAIN]\[USER]" -w '[PASSWORD]' \
  -b "DC=[domain],DC=[tld]" -s base \
  "(objectClass=domainDNS)" ms-DS-MachineAccountQuota

# nxc でも同等
nxc ldap [IP] -u [USER] -p '[PASSWORD]' -M maq
```

> `ms-DS-MachineAccountQuota = 0` なら RBCD の機械アカウント作成経路は塞がれている（既存の writable ACE 経由を探す方向）。

**ドメイン信頼（Trust）の列挙：**
```bash
# フォレスト / ドメイン信頼の有無・方向・タイプを確認
ldapsearch -x -H ldap://[IP] \
  -D "[DOMAIN]\[USER]" -w '[PASSWORD]' \
  -b "DC=[domain],DC=[tld]" -s sub \
  "(objectClass=trustedDomain)" \
  flatName trustPartner trustDirection trustType trustAttributes

# trustDirection の値: 1=Inbound / 2=Outbound / 3=Bidirectional
# trustAttributes に 0x40 (FOREST_TRANSITIVE) があれば forest trust
```

**NetExec を使った高速列挙：**
```bash
netexec ldap [IP] -u [USER] -p '[PASSWORD]' --users
netexec ldap [IP] -u [USER] -p '[PASSWORD]' --kerberoasting kerberoast.out
netexec ldap [IP] -u [USER] -p '[PASSWORD]' --asreproast asrep.out
netexec ldap [IP] -u [USER] -p '[PASSWORD]' --trusted-for-delegation     # Unconstrained / Constrained 検出
netexec ldap [IP] -u [USER] -p '[PASSWORD]' --password-not-required      # PASSWD_NOTREQD ユーザー検出
```

**ldapdomaindump（BloodHound 前の全体把握ツール・HTML/JSON 一括ダンプ）：**
```bash
# 認証情報があればドメイン全体の users / groups / computers / trusts / policy を HTML + JSON で吐く
mkdir ldd_out && cd ldd_out
ldapdomaindump -u '[DOMAIN]\[USER]' -p '[PASSWORD]' ldap://[IP]

# ブラウザで domain_users.html / domain_computers.html / domain_trusts.html を確認
# BloodHound を回す前にこれで概観を掴むと、何を狙うかの当たりが付きやすい
```

---

## 刺さらなかったとき

| 観測される症状 | 推定原因 | 代替手段 |
|--------------|---------|---------|
| 匿名バインドで `operationsError` が返る | 匿名アクセスは拒否されている | 認証情報取得まで後回し。`../00_Playbook/Windows_AD_Attack_Flow.md` Step 3（初期認証情報の取得）へ戻る |
| 認証ありで結果が空 | `-b "DC=..."` の DN を間違えている | `ldapsearch -x -H ldap://[IP] -s base namingcontexts` で正しい Naming Context を確認してから再実行 |
| `objectClass=user` で何も返らないが他は通る | カスタムスキーマ / オブジェクトクラスが標準と異なる | `(objectClass=*)` で広く取得し、属性 `objectClass` を見て実際のクラス名を確認する |
| 大量結果が `sizeLimitExceeded` で途中で切れる | デフォルト 1000 件上限 | `-E pr=500/noprompt` でページング、または `-l unlimited` を試す（サーバー側設定次第） |
| `info` / `description` フィールドに何も書かれていない | 運用上メモ機能を使っていない組織 | `extensionAttribute1`〜`extensionAttribute15` 等のカスタム属性を確認、または属性指定なしで全属性取得して網羅 |
| LDAPS（636）に接続できない | 証明書の Subject / SAN とアクセス先（IP）が不一致 | `/etc/hosts` にホスト名を登録してから `ldaps://[FQDN]` で再接続（`../06_Concepts/Hosts_File_For_AD.md` 参照） |
| LDAPS で `TLS: peer cert untrusted` / `Hostname verification failed` | AD の LDAPS は社内 CA / オレオレ証明書が大半 | 環境変数で証明書検証を無効化: `LDAPTLS_REQCERT=never ldapsearch -H ldaps://[IP] ...`（クライアント側の `/etc/ldap/ldap.conf` に `TLS_REQCERT never` でも可。**finding 化用に正規証明書ならどう失敗するかを併記する**）|
| `ldapsearch` が `Can't contact LDAP server` | 389 / 636 が閉じている / FW でブロック | nmap で再確認、別 DC（複数ある場合）の IP を試す |

---

## 注意点・落とし穴

- `info` フィールドは GUI（Active Directory ユーザーとコンピューター）の「説明」欄とは別の、あまり目立たないフィールド。GUI 運用だと見落とされがち
- デフォルトの `sizeLimit` は 1000 件。超えると結果が途中で切れる。`-E pr=500/noprompt` のページング指定で回避
- 大量の出力は `tee` でファイルに保存しながら確認する（後からの `grep` のため）
- 匿名バインドが通っても `objectClass=user` で中身が返らない環境がある。その場合は `(objectClass=*)` や `domain` レベルで再度試す
- DN の `DC=` 部分を間違えると結果が空になるだけでエラーは返らない。必ず `namingcontexts` で正しい DN を先に確認する
- ldap:// と ldaps:// で結果が変わることはほぼないが、認証情報送信の安全性のため資格情報を送る際は ldaps:// を優先
- **`Pre-Windows 2000 Compatible Access` グループ** は旧 NT 互換用の特殊グループで、ここに `Anonymous Logon` / `Authenticated Users` 等が含まれている古い AD では、**匿名 / 弱認証でも広範な列挙が可能**になる。新規ドメインでは含まれていないことが多いが、長年運用されている AD では残存している場合がある。`memberOf` 検索で `CN=Pre-Windows 2000 Compatible Access` のメンバを確認

---

## 関連技術
- 前：ポートスキャンで 389 / 636 を発見 → `./Network_Scanning.md`
- 前：AD 攻撃フロー上の現在地確認・初期認証情報の取得 → `../00_Playbook/Windows_AD_Attack_Flow.md`
- 前：メタデータから得たユーザー名・ドメイン名を起点に列挙 → `./Metadata_Analysis.md`
- 前：rpcclient / SMB 側の列挙と併用 → `SMB_Enumeration.md` / `RPC_Enumeration.md`
- 後：ユーザー一覧が取得できた → パスワードスプレー `../05_Tools_Reference/Netexec.md`
- 後：SPN 付きユーザーを発見 → `../04_Post_Access_Windows_AD/Kerberos_Attacks/Kerberoasting.md`
- 後：AS-REP Roast 可能ユーザーを発見 → `../04_Post_Access_Windows_AD/Kerberos_Attacks/ASREPRoasting.md`
- 後：`ms-Mcs-AdmPwd` が読めた → `../04_Post_Access_Windows_AD/LAPS_Dump.md`
- 後：`ms-DS-MachineAccountQuota` が 0 でない + 任意ユーザー権限 → `../04_Post_Access_Windows_AD/Delegation_Attacks/RBCD.md`
- 後：`TRUSTED_FOR_DELEGATION` / `TRUSTED_TO_AUTH_FOR_DELEGATION` を発見 → `../04_Post_Access_Windows_AD/Delegation_Attacks/Unconstrained.md` / `../04_Post_Access_Windows_AD/Delegation_Attacks/RBCD.md`
- 後：全体の権限マッピング → `../05_Tools_Reference/BloodHound.md`
- 後：`info` フィールドにパスワード → `../02_Initial_Access/Credential_Discovery.md`
