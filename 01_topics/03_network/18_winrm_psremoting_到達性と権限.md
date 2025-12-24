## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS
  - 破れる：WinRM/PSRemoting は「正規の遠隔管理」の皮を被った **横展開・運用破壊の“高速レーン”**。到達性（FW/分離）・認証方式（Kerberos/NTLM/Basic/CredSSP）・権限制御（エンドポイント権限/JEA）・ログ/監査が揃っていないと、Valid Accounts だけで広範囲に操作される。
  - 満たす：管理用インターフェースは **公開しない/最小到達性**（管理サブネット/踏み台限定）、**強い認証**（Kerberos優先、HTTPS、Basic無効、CredSSP最小）、**最小権限（JEA/制約付きエンドポイント）**、**監査（WinRM/PowerShell/ログオン）** を設計として固定する。
- WSTG
  - 該当観点：WSTG-CONF の「Network Infrastructure Configuration」「Admin Interfaces Enumeration」は、Webだけでなく **“運用系インターフェース（WinRM）”の露出/制御** に直結する。特に「必要ポートの定義」「管理ツールの棚卸」「既定設定/既知脆弱性の検証」は本テーマそのもの。  
    - 根拠URL（WSTG-CONF-01）：https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration
- PTES
  - 位置づけ：Intelligence Gathering/ Vulnerability Analysis の **到達性確認→サービス同定→認証成立条件→権限境界の確認** が WinRM で一気通貫。Post-Exploitation/ Pivoting にも直結するため、**観測と証跡を最優先**し、範囲外操作（永続化/ダンプ等）は別手順へ分離する。  
    - 根拠URL（PTES）：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK
  - T1021.006 Windows Remote Management：到達性（5985/5986）と Valid Accounts による遠隔操作が中核。  
    - 根拠URL（Technique）：https://attack.mitre.org/techniques/T1021/006/
  - DET0477：WinRM を使った遠隔実行の検知戦略（4624/4648、WinRMログ、Sysmon 1、NSM 5985/5986）に落とせる。  
    - 根拠URL（Detection）：https://attack.mitre.org/detectionstrategies/DET0477/

---

## タイトル
WinRM/PSRemoting：到達性（5985/5986）と権限（認証方式/エンドポイント/JEA/二段跳び）を“観測→判断→次の一手”で確定する

---

## 目的（このファイルで到達する状態）
- 対象ネットワークで WinRM/PSRemoting が **どこから・どこまで** 使えるかを、推測ではなく証跡で説明できる。
  1) **到達性**：どの経路/セグメントから 5985/5986 が開いているか（FW/ACL/経路の境界）
  2) **Listener 実在**：WinRM が “ポートが開いているだけ” ではなく、/wsman に応答できる状態か
  3) **認証方式**：Kerberos/NTLM/Basic/Cert/CredSSP のどれが許されているか（危険設定の有無）
  4) **権限境界**：どのアカウントが接続でき、接続後に何ができるか（Admin/JEA/制約エンドポイント）
  5) **二段跳び（Second hop）**：遠隔セッションからさらに別資源（SMB/SQL/LDAP 等）へ触れる条件が何か
  6) **検知/証跡**：Blue視点で追えるログ（WinRM/PowerShell/4624/4648/NSM）へ落とし込める

---

## 扱う範囲（本ファイルの守備範囲）
- 扱う
  - 5985/5986 到達性確認（外部/内部/踏み台経由）
  - WinRM Listener の確認（HTTP/HTTPS、/wsman）
  - 認証方式（Kerberos/NTLM/Basic/CredSSP）と危険設定の判定
  - PSRemoting の「接続できる/できない」「接続後に権限が足りない」の切り分け
  - Second hop（CredSSP/制約付き委任など“成立条件”として）
  - ログと検知観点（最小フィールド）
- 扱わない（別ファイルで）
  - NTLM Relay/LLMNR（成立条件・実行）は `10_ntlm_relay_成立条件（SMB署名_LLMNR）.md`
  - Kerberoast/AS-REP roast は `12_kerberos_asrep_kerberoast_成立条件.md`
  - Delegation/RBCD は `14_delegation（unconstrained_constrained_RBCD）.md`
  - 侵入後の永続化は `27_persistence_永続化（schtasks_services_wmi）.md`

---

## 前提：WinRM と PSRemoting の関係（混同しない）
- WinRM：Windows のサービス/プロトコル（WS-Management）で、HTTP/HTTPS 上で管理操作を受ける。既定ポートは 5985(HTTP) / 5986(HTTPS)。  
  - 根拠URL：https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management
- PowerShell Remoting（PSRemoting）：WinRM(WSMan) を transport として PowerShell セッション（PSSession）を張る仕組み（Enter-PSSession / Invoke-Command）。  
- 重要な落とし穴：
  - 「5985 が開いてる」＝「PowerShell で遠隔操作できる」ではない  
  - 「セッションが張れる」＝「管理者操作できる」ではない（UAC/Endpoint/権限境界が別）

---

## 境界モデル：WinRM/PSRemoting を壊す・守る論点を“層”で分ける
### 境界1：ネットワーク到達性（FW/ACL/経路/踏み台）
- 5985/5986 がどのセグメントから開いているかが第一境界。
- “管理系”は原則、利用元（管理端末/踏み台）を限定して到達性を絞る（許可リスト）。

### 境界2：Listener（HTTP/HTTPS、IPv4/IPv6、URLPrefix）
- WinRM サービスが動いていても Listener が無いと受けない。
- Listener は HTTP/HTTPS とフィルタ（IPv4Filter/IPv6Filter）を持つ。  
  - 根拠URL：https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management

### 境界3：認証方式（Kerberos/NTLM/Basic/Cert/CredSSP）
- Kerberos：ドメイン前提で強いが、SPN/名前解決/時刻ズレ等が絡む。
- NTLM：ワークグループやローカルアカウントでも成立しやすいが、Relay 等の論点へ接続。
- Basic：資格情報がそのまま飛ぶ前提になるため、HTTPS 以外は原則禁止。
- CredSSP：二段跳びを可能にするが、**資格情報委任**を伴うため利用条件を強く絞る。  
  - 根拠URL（CredSSP/認証方式の説明含む）：https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management

### 境界4：認可（誰が“遠隔 PowerShell”を使えるか）
- 「WinRM に認証できる」≠「PowerShell セッション構成（Endpoint）を使える」。
- Endpoint（Session Configuration）の ACL が本体。既定は管理者のみ、例外は明示的に設計が必要。  
  - 根拠URL（Remote Troubleshooting）：https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/about-remote-troubleshooting?view=powershell-7.5

### 境界5：接続後の権限（管理者操作が通る/通らない）
- 接続できても、UAC のリモートトークン/制限で「管理者なのに管理者として動かない」ケースがある。
- “接続成功” と “特権操作成功” を別試験として切り分ける。

### 境界6：Second hop（二段跳び）
- リモートセッション内で別のネットワーク資源（例：ファイル共有/SQL/LDAP）へ認証が必要になると詰まる。
- 解決は CredSSP/制約付き委任/SSPI 設計など。まずは **どの操作が二段跳びに当たるか** を特定する。  
  - 根拠URL（Second hop）：https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/ps-remoting-second-hop?view=powershell-7.5

---

## 実施方法（最高に具体的）：観測→判断→次の一手（外部Kali / 内部Windows踏み台の両対応）
> 注意：必ず許可されたスコープで実施。特に WinRM は運用影響が出やすい（ログ/アカウントロック/監視アラート）。

### 0) 事前に“観測シート”を作る（後で迷わない）
- 対象ホスト（IP/名前/FQDN/OS推定/所属セグメント）
- 観測元（あなたの端末 / 踏み台 / pivot先）と経路
- 期待する認証コンテキスト（ドメイン参加/ワークグループ、利用する資格情報の種類）
- 取得した証跡の保存先（コマンド出力・pcap・ログ抜粋）

---

## 1) 到達性（5985/5986）を“経路ごと”に確定する
### 1-A) Linux（Kali等）から：ポート開閉と最小バナー
~~~~
# まずはTCP開閉（ICMPは当てにしない）
nmap -Pn -sT -p 5985,5986 --open -n <target_ip>

# 可能なら service 推定（過剰なスキャンは避ける）
nmap -Pn -sT -sV -p 5985,5986 -n <target_ip>

# HTTPとして /wsman へ当て、401 を確認（= WinRMが“応答”している可能性が高い）
curl -i --max-time 5 http://<target_ip>:5985/wsman
~~~~

#### 観測ポイント（判断に使う）
- `nmap` で open：FW/ACL 的には通る（ただし “サービス稼働” は未確定）
- `curl` が 401 + `WWW-Authenticate: Negotiate` や `NTLM` 等：WinRM/WSMan 応答の可能性が高い
- TCP open だがタイムアウト/無応答：中間FW/IPS、Listener不在、HTTP以外のアプリがバインド等を疑う

#### 次の一手
- 401 が返るなら → 2) 認証方式/HTTPS/証明書の確認へ
- TCP が閉じている/filtered なら → “観測元を変える”（踏み台/pivot 経由）か、許可範囲で FW/ACL 設計の問題として報告用に整理

---

### 1-B) TLS（5986）を“暗号化の実在”として確定する
~~~~
# 証明書とハンドシェイクを確認（ALPNは環境により無い/意味が薄いこともある）
openssl s_client -connect <target_ip>:5986 -servername <target_fqdn> -alpn http/1.1 < /dev/null

# HTTPSで /wsman を確認（証明書検証はまず挙動観測優先で -k も許容）
curl -k -i --max-time 5 https://<target_ip>:5986/wsman
~~~~

#### 観測ポイント
- 証明書の CN/SAN：名前解決（FQDN）前提か、IP直打ちでも通る構成か
- `curl -k` で 401 が返る：HTTPS の WinRM が実在
- 証明書エラーで接続不可：運用品質（管理手順の破綻）としても論点

#### 根拠（既定ポート）
- 既定の HTTP=5985 / HTTPS=5986：  
  https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management  
  https://learn.microsoft.com/ja-jp/troubleshoot/windows-client/system-management-components/configure-winrm-for-https

---

## 2) WinRM “Listener 実在”と設定を確認する（権限がある場合の最短手順）
> ここは「対象ホスト上で確認できるか」が鍵。権限があるなら、推測よりも設定値で確定する。

### 2-A) 対象ホスト上（Windows）で Listener を列挙（管理権限がある場合）
~~~~
# Listener の実在と HTTP/HTTPS/Port/ListeningOn を確定
winrm enumerate winrm/config/listener

# WSManの既定設定や認証方式の許可（Kerberos/Negotiate/Basic/CredSSPなど）を確認
winrm get winrm/config/service
winrm get winrm/config/client
~~~~

#### 判断（例）
- Listener が HTTP のみ：暗号化要件（HTTPS化）/到達性制御が弱い可能性
- `Basic = true` かつ HTTP：重大（資格情報露出）
- `TrustedHosts` が広い（`*` 等）：別ドメイン/ワークグループに対して無差別に資格情報を投げうる  
  - 根拠（TrustedHostsの注意）：https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management

---

## 3) PSRemoting の“接続可否”を確定する（Windows踏み台からが最も確実）
### 3-A) まず “疎通（WSMan応答）” だけを確認（資格情報不要の範囲）
~~~~
# PowerShell（踏み台/管理端末）で疎通確認
Test-WSMan <target_fqdn_or_ip>
~~~~

- ここで通らない場合、次のどれかに寄る：
  - FW/ACL（5985/5986）遮断
  - WinRM service/Listener 不在
  - 名前解決やプロキシ、TLS（証明書）問題  
- 典型切り分けは “about_Remote_Troubleshooting” に沿う（後述のエラー別対応）。

### 3-B) 接続（PSSession作成）を最小コマンドで試す
~~~~
# 1回の実行だけなら Invoke-Command が楽（結果が返る/ログも残る）
$cred = Get-Credential
Invoke-Command -ComputerName <target_fqdn_or_ip> -Credential $cred -ScriptBlock { whoami; hostname }

# 対話が必要なら
Enter-PSSession -ComputerName <target_fqdn_or_ip> -Credential $cred
~~~~

#### ここでの“観測ポイント”
- 接続が失敗する：認証/到達性/Listener/TrustedHosts/ドメイン要件の問題
- 接続は成功するが管理操作が失敗：UAC/権限/エンドポイント制約の問題（次章）

---

## 4) “接続できるのに Access Denied” を権限境界として確定する
### 4-A) 失敗の種類を必ず分ける
- A：PSSession自体が作れない（New-PSSession/Enter-PSSession が失敗）
- B：PSSessionは作れるが、特定のコマンドが拒否される（管理者操作・サービス操作等）
- C：二段跳び操作（別サーバの共有/DB/LDAP）だけ失敗する

### 4-B) B（接続後に拒否）を“Endpoint権限”で確認（対象上で権限がある場合）
~~~~
# 対象ホスト側で、どの Session Configuration があり、誰に許可されているか
Get-PSSessionConfiguration

# 既定エンドポイントの権限（SDDL）を確認し、設計上の許可・禁止を明確化
Get-PSSessionConfiguration -Name Microsoft.PowerShell | Format-List *

# 許可設計を変える場合（運用者向け）：GUIで権限を調整（監査・手順化必須）
Set-PSSessionConfiguration -Name Microsoft.PowerShell -ShowSecurityDescriptorUI
~~~~

- ここが「管理者だけ」「特定グループだけ」「JEAエンドポイントだけ」等、組織方針の反映点。
- 根拠（非管理者への許可は Session Configuration の権限調整）：  
  https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/about-remote-troubleshooting?view=powershell-7.5

### 4-C) 最小権限（JEA/制約付きエンドポイント）の“確認観点”
- 何を見るべきか（攻め手順ではなく“評価項目”）
  - 利用可能なコマンドレットが制限されているか
  - 任意 PowerShell（Add-Type、外部exe起動、ファイル書込等）を抑止できているか
  - ロール（運用者/監査者/開発者）でエンドポイントが分離されているか

---

## 5) Second hop（二段跳び）を“操作単位”で特定し、成立条件を切り出す
### 5-A) 二段跳びが起きる典型操作（例）
- リモートセッション内で：
  - `dir \\fileserver\share`（SMB）
  - `Invoke-Sqlcmd -ServerInstance ...`（MSSQL）
  - `Get-ADUser ...`（LDAP/AD）
- これらは「リモート先から別資源へ」認証が必要になり、詰まりやすい。

### 5-B) 原則：まず“どの操作が詰まるか”を1つに絞って再現
~~~~
# 例：遠隔で whoami は通るが、SMBアクセスだけ失敗するか確認
Invoke-Command -ComputerName <target> -Credential $cred -ScriptBlock {
  whoami
  dir \\<fileserver>\share
}
~~~~

### 5-C) 次の一手（成立条件の整理）
- CredSSP を使う/使わないの判断（危険性と必要性）
  - 使うなら「どのサーバ間」「どのユーザ」「どの期間」だけ許すかを設計に落とす
- 制約付き委任（Kerberos Delegation/RBCD）で解決する余地（AD設計側の論点）
- 根拠（Second hopと解決手段の整理）：  
  https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/ps-remoting-second-hop?view=powershell-7.5

---

## 6) エラー別：最短の切り分け（観測→判断→次の一手）
### ケース1：5985/5986 open だが Test-WSMan が失敗
- 観測：TCPは開いているが WSMan 応答がない/拒否
- 判断候補：
  - Listener が無い（サービス起動のみ等）
  - HTTPS必須だが 5986 側の証明書/Listenerが不完全
  - 中間FW/Proxyが HTTP を落としている
- 次の一手（権限があるなら設定で確定）
  - `winrm enumerate winrm/config/listener`（Listener実在）
  - `curl http(s)://<target>:<port>/wsman`（HTTPレベル応答）
  - 根拠（Listener/ポート/設定項目）：https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management

### ケース2：Enter-PSSession が “Access is denied”
- 観測：認証前後のどこで拒否か（ログ/エラー文）を控える
- 判断候補：
  - Session Configuration の許可が無い（既定は管理者のみ）
  - UAC/トークン問題で“管理者として扱われない”
- 次の一手：
  - 対象で `Get-PSSessionConfiguration` の Permission/SDDL を確認
  - 必要なら `Set-PSSessionConfiguration -ShowSecurityDescriptorUI` で明示的に設計
  - 根拠（既定は管理者、許可は Session Configuration）：  
    https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/about-remote-troubleshooting?view=powershell-7.5

### ケース3：接続はできるが、別サーバ資源アクセスだけ失敗（Second hop）
- 観測：どの操作が失敗するかを単独再現
- 判断：Second hop に該当
- 次の一手：CredSSP/委任/JEA設計へ切り出し、影響と必要性で判断
  - 根拠：https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/ps-remoting-second-hop?view=powershell-7.5

---

## 7) 証跡（ログ/通信）として何を残すべきか（報告で刺さる最小セット）
### 7-A) Red（診断側）が残す証跡
- 到達性：観測元ごとの `nmap` / `curl` / `openssl s_client` 出力
- 接続可否：`Test-WSMan` / `Invoke-Command` の成否とエラー全文
- 設定確認（権限がある場合）：`winrm get ...` / `winrm enumerate ...` / `Get-PSSessionConfiguration` 出力

### 7-B) Blue（検知側）が追えるログ（“この設定だと検知できる/できない”まで言う）
- MITRE DET0477 に沿う最小：
  - Security 4624/4648（ログオン/明示資格情報）
  - WinRM ログ（Operational等、環境により）
  - Sysmon 1（プロセス作成）
  - NSM（5985/5986 の接続フロー）
- 根拠（検知戦略の構成要素）：https://attack.mitre.org/detectionstrategies/DET0477/

---

## 8) 安全な是正方針（“落としどころ”を提案できる形）
- 到達性：管理サブネット/踏み台からのみ許可（5985/5986 をセグメントで絞る）
- 暗号化：可能な限り HTTPS(5986) を採用、証明書管理を手順化  
  - 根拠（HTTPS構成例）：https://learn.microsoft.com/ja-jp/troubleshoot/windows-client/system-management-components/configure-winrm-for-https
- 認証方式：Kerberos/Negotiate優先、Basic無効、CredSSPは必要最小（理由と範囲を明文化）  
  - 根拠（認証方式・CredSSPの説明）：https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management
- 権限境界：既定エンドポイントを絞る or JEA を採用し、運用ロール別に分離
- 監査：WinRM/PowerShell/4624/4648 を相関できる設計（相関キー：srcIP, user, target, timewindow）

---

## 参考URL（本文の根拠として使用：そのまま貼る）
- WinRM（既定ポート/Listener/TrustedHosts/認証方式/Basic/CredSSP等）  
  https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management
- WinRM を HTTPS で構成（既定 5986、listener確認）  
  https://learn.microsoft.com/ja-jp/troubleshoot/windows-client/system-management-components/configure-winrm-for-https
- PowerShell Remoting：トラブルシュート（Access denied、Session Configuration 等）  
  https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/about-remote-troubleshooting?view=powershell-7.5
- PowerShell Remoting：Second hop（CredSSP 等）  
  https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/ps-remoting-second-hop?view=powershell-7.5
- MITRE ATT&CK：T1021.006 WinRM  
  https://attack.mitre.org/techniques/T1021/006/
- MITRE ATT&CK：DET0477 WinRM検知戦略  
  https://attack.mitre.org/detectionstrategies/DET0477/
- OWASP WSTG（Network Infrastructure Configuration）  
  https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration
- OWASP ASVS（参照元）  
  https://github.com/OWASP/ASVS
- PTES（参照元）  
  https://pentest-standard.readthedocs.io/

---

## 深掘りリンク（最大8）
- `05_scanning_到達性把握（nmap_masscan）.md`
- `06_service_fingerprint（banner_tls_alpn）.md`
- `07_pivot_tunneling（ssh_socks_chisel）.md`
- `09_smb_enum_共有・権限・匿名（null_session）.md`
- `10_ntlm_relay_成立条件（SMB署名_LLMNR）.md`
- `12_kerberos_asrep_kerberoast_成立条件.md`
- `14_delegation（unconstrained_constrained_RBCD）.md`
- `19_rdp_設定と認証（NLA）.md`
