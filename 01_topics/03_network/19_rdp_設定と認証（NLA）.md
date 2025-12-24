## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS
  - 破れる：RDP は「正規のGUI遠隔操作」だが、Valid Accounts が一度でも取れると横展開の主経路になりやすい。特に **NLA無効**・**TLS不徹底**・**誰でもログオン権限**・**到達性が広い（インターネット/他セグメント）** が揃うと、攻撃者に“低コストで高操作性”を提供する。
  - 満たす：到達性最小化（管理網/踏み台/RD Gateway）、NLA必須、TLS（証明書/暗号スイート）明確化、ログオン権限の最小化（Remote Desktop Users/特権分離）、監査（4624 type10等）を設計として固定する。
- WSTG
  - 該当観点：WSTG-CONF の「Network Infrastructure Configuration」「Admin Interfaces Enumeration」は、RDP の露出・暗号・認証・到達性の検証そのもの。
  - 根拠URL（WSTG-CONF-01）：https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration
- PTES
  - 位置づけ：Information Gathering → (到達性/経路) → Vulnerability Analysis → (NLA/TLS/権限境界) → Post-Exploitation/Lateral Movement（必要な場合のみ）。RDP は「到達性×認証×権限」で成立/不成立が決まるため、**観測と設定値で確定**して報告に落とす。
  - 根拠URL（PTES）：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK
  - T1021.001 Remote Desktop Protocol：Valid Accounts により RDP で横展開され得る。緩い到達性と権限設計があると、標準機能だけで侵害が進む。
  - 根拠URL（Technique）：https://attack.mitre.org/techniques/T1021/001

---

## タイトル
RDP：到達性（3389/RD Gateway）・暗号/TLS・NLA（CredSSP）・権限（RDU/特権）を“設定値と観測”で確定する

---

## 目的（このファイルで到達する状態）
- 対象環境の RDP について、推測ではなく **設定値（レジストリ/GPO）と観測（ネットワーク/ログ）** で次を説明できる。
  1) 到達性：どの経路/セグメントから 3389（または RD Gateway 443 経由）に到達できるか
  2) 暗号：SecurityLayer（RDP/Negotiate/TLS）が何か、証明書/TLS の実在があるか
  3) NLA：UserAuthentication（NLA必須か）と、CredSSP の前提（TLS + Kerberos/NTLM）を満たしているか
  4) 権限境界：誰が「RDPでログオン可能」か（Remote Desktop Users / Allow log on through RDS / Deny）
  5) 証跡：成功/失敗を Blue 視点で追えるイベント（4624 type10 等）に落ちるか、相関キーは何か

---

## 扱う範囲（本ファイルの守備範囲）
- 扱う
  - 3389 到達性（filtered/open の解釈、経路ごとの観測）
  - RDP の暗号/認証レイヤ（SecurityLayer、NLA、CredSSP、証明書）
  - 権限設計（RDPログオン権限、RDU、Denyの優先）
  - 監査・証跡（4624 type10、関連ログ）
- 扱わない（別ファイルへ接続）
  - 認証情報奪取（LSA/DPAPI等）→ `26_credential_dumping_所在（LSA_DPAPI）.md`
  - NTLM Relay/LLMNR → `10_ntlm_relay_成立条件（SMB署名_LLMNR）.md`
  - Delegation/RBCD/ADCS → `14_delegation...` / `13_adcs...`
  - ブルートフォース手順（攻撃実行）は本ファイルでは扱わない（“検知・対策・観測”に寄せる）

---

## 前提：RDP / NLA / CredSSP の関係（ここが境界の核）
- NLA（Network Level Authentication）は「RDP セッション確立“前”にユーザ認証を要求する」設定で、Windows 側では `UserAuthentication` の値で表現される。  
  - `UserAuthentication = 0`：NLA不要（既定値という扱いのドキュメントもある）  
  - `UserAuthentication = 1`：NLA必須  
  - 根拠URL（UserAuthentication）：https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-terminalservices-rdp-winstationextensions-userauthentication
- SecurityLayer は「RDP/Negotiate/TLS のどれで事前認証/暗号を行うか」を表し、TLS 強制（2）を設計として選べる。  
  - 根拠URL（SecurityLayer）：https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-terminalservices-rdp-winstationextensions-securitylayer
- RDP は CredSSP を使ってクレデンシャル委任を行い得る（= “安全にやる”には TLS と Kerberos/NTLM の成立条件が重要）。  
  - 根拠URL（RDPがCredSSPを使う概要）：https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-authsod/32f5a0b9-21d9-4b9c-b7d1-e80d72db47a7
  - 根拠URL（RDPBCGR：CredSSP/TLS/Kerberos/NTLM）：https://learn.microsoft.com/ja-jp/openspecs/windows_protocols/ms-rdpbcgr/8e11581d-094f-461a-9fde-ba51af90cf8b

---

## 境界モデル（“どこで壊れる/守る”を層で分ける）
### 境界1：到達性（3389 / RD Gateway 443 / セグメント）
- 3389 が広範囲に到達可能だと、Valid Accounts だけで横展開の高速道路になる。
- “理想”は「3389 は管理網のみ」「外部は RD Gateway/VPN のみ」。

### 境界2：暗号・事前認証（SecurityLayer）
- SecurityLayer=2（TLS）を強制できているか。
- 証明書が自己署名のまま/期限切れ/ホスト名不一致だと、運用上 “検証無視” が常態化し、MITM耐性が落ちる。

### 境界3：NLA（UserAuthentication）と CredSSP 成立条件
- NLA は “事前に” 認証を要求する。UserAuthentication=1 で固定できているか。
- CredSSP は TLS チャネル上で Kerberos/NTLM を選択し得るため、Kerberos前提（ドメイン/名前解決/時刻）と証明書前提（TLS）のどちらが成立しているかを観測する。  
  - 根拠URL（CredSSPがTLS + Kerberos/NTLMの合成である旨）：https://learn.microsoft.com/ja-jp/openspecs/windows_protocols/ms-rdpbcgr/8e11581d-094f-461a-9fde-ba51af90cf8b

### 境界4：権限（RDPでログオンできる人の定義）
- 「Remote Desktop Users に入っている」＋「Allow log on through Remote Desktop Services」が原則条件。
- Deny が設定されていると Allow より優先される。
  - 根拠URL（Allow log on through RDS）：https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn221985(v=ws.11)
  - 根拠URL（Deny が優先）：https://learn.microsoft.com/ja-jp/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/deny-log-on-through-remote-desktop-services

### 境界5：証跡（成功・失敗が監査ログで追えるか）
- 成功ログ：Security 4624（Logon Type 10 = RemoteInteractive）が基礎証跡。  
  - 根拠URL（4624 と type10）：https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624
- 切断：4779 等が補助。  
  - 根拠URL（基本監査イベント）：https://learn.microsoft.com/ja-jp/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/basic-audit-logon-events

---

## 実施方法（最高に具体的）：観測→判断→次の一手
> 注意：実施は許可スコープ内。RDPは運用監視に直撃しやすいので、試行回数は最小にし、ログを残す。

### 0) 事前に“観測台帳”を作る（必須）
- 対象：IP / ホスト名 / FQDN / セグメント / 重要度（DC/管理サーバ/端末）
- 観測元：あなたの端末 / 踏み台 / pivot先（どこから観測したか）
- 想定：ドメイン参加か、ローカルアカウントか、RD Gateway/VPN必須か
- 保存：コマンド出力（txt）・pcap（必要なら）・スクショ（RDP証明書警告等）

---

## 1) 到達性：3389 を“経路ごと”に確定する（外から/内から）
### 1-A) Linux（Kali等）から最小の到達性確認
~~~~
# ICMPに依存しない（-Pn）/ DNS逆引きで遅くしない（-n）
nmap -Pn -n -sT -p 3389 --open <target_ip>

# 到達性が不明瞭なら “filtered” を含めて結果保存（報告根拠）
nmap -Pn -n -sT -p 3389 <target_ip> -oN rdp_3389_reachability_<target>.txt
~~~~

#### 判断
- open：FW/ACL上は通る（ただし “RDPである” は次で確定）
- filtered：経路上の遮断（セグメント制御/IPS/ACL）可能性が高い
- closed：ホスト側で待ち受け無し or 端末FWで拒否

#### 次の一手
- open → 2) サービス同定（RDPであること）へ
- filtered/closed → 観測元を変える（踏み台/管理網）か、設計として「管理到達性が限定されている」証拠として記録

---

## 2) サービス同定：本当に RDP か（nmapスクリプトで“暗号とNLA”まで一気に観測）
### 2-A) nmap NSE で RDP の特徴と暗号設定を観測
~~~~
# RDP関連の代表スクリプト（環境により存在/結果が異なる点は“観測”として記録）
nmap -Pn -n -sT -p 3389 --script "rdp-enum-encryption,rdp-ntlm-info,ssl-cert" <target_ip> -oN rdp_enum_<target>.txt
~~~~

#### 観測ポイント（報告に刺さる）
- rdp-enum-encryption：暗号の種別（RDP/Negotiate/TLS）やNLAの有無が推定できることがある
- rdp-ntlm-info：対象がドメイン参加/ホスト名等の“情報露出”が出ることがある（出た/出ないも記録）
- ssl-cert：TLSが絡む場合、証明書の提示が観測できることがある

#### 次の一手
- “NLA無効っぽい”/“RDP Security Layerっぽい” → 3) 設定値（SecurityLayer/UserAuthentication）で確定（可能なら）
- “TLSあり” → 証明書の妥当性（CN/SAN/期限/自己署名）を追加観測

---

## 3) 設定値で確定：NLA（UserAuthentication）と SecurityLayer（TLS強制）を“対象側”で確認
> ここが最重要。ネット観測は揺れるので、可能なら対象ホスト上の設定で確定する。

### 3-A) 対象ホスト（Windows）でレジストリ確認（読み取り権限がある場合）
~~~~
# RDP有効/無効（0=許可, 1=拒否）
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections

# NLA（UserAuthentication：1=必須）
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication

# SecurityLayer（0=RDP, 1=Negotiate, 2=TLS）
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer
~~~~

#### レジストリ値の“意味”を根拠付きで説明する（報告用）
- UserAuthentication：NLA必須かどうか（0/1）  
  - 根拠URL：https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-terminalservices-rdp-winstationextensions-userauthentication
- SecurityLayer：RDP/Negotiate/TLS のどれを要求するか（0/1/2）  
  - 根拠URL：https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-terminalservices-rdp-winstationextensions-securitylayer
  - 補助根拠URL（Win32_TSGeneralSetting SetSecurityLayer）：https://learn.microsoft.com/en-us/windows/win32/termserv/win32-tsgeneralsetting-setsecuritylayer

#### 判断のテンプレ（そのまま報告に使う）
- NLA：UserAuthentication=1 → “NLA必須（事前認証あり）”
- TLS：SecurityLayer=2 → “TLSを強制（証明書が必須）”
- リスクが強い例：
  - UserAuthentication=0（NLA不要） かつ SecurityLayer=0（RDP Security Layer）  
    → “事前認証が弱く、TLS強制もされない可能性”

---

## 4) 権限境界：誰がRDPログオンできるかを“ポリシーとグループ”で確定
### 4-A) 最短の確認観点（対象ホスト/ADの両面）
- ローカルグループ：Remote Desktop Users（対象ホストのローカル）
- ユーザー権利：Allow log on through Remote Desktop Services
- 除外：Deny log on through Remote Desktop Services（Allowより優先）

### 4-B) 根拠付きで報告できる状態にする
- Allow log on through Remote Desktop Services の説明：  
  - 「RDSで正常にログオンするには、Remote Desktop Users または Administrators のメンバーであり、当該ユーザー権利が必要」  
  - 根拠URL：https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn221985(v=ws.11)
- Deny の優先（両方に該当する場合は Deny が勝つ）：  
  - 根拠URL：https://learn.microsoft.com/ja-jp/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/deny-log-on-through-remote-desktop-services

---

## 5) 認証の“成立条件”を整理：NLAが有効でも詰まる典型（運用上よく起きる）
### 5-A) NLA（CredSSP）は何に依存するか（診断で言語化）
- RDP は CredSSP により、TLS チャネル上で Kerberos/NTLM 等を用いて認証し得る。  
  - 根拠URL（RDPとCredSSP）：https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-authsod/32f5a0b9-21d9-4b9c-b7d1-e80d72db47a7
  - 根拠URL（CredSSPはTLS + Kerberos/NTLMの合成）：https://learn.microsoft.com/ja-jp/openspecs/windows_protocols/ms-rdpbcgr/8e11581d-094f-461a-9fde-ba51af90cf8b
- よって、NLAが“必須”でも失敗する時は、概ね次のどれか：
  - 名前解決/FQDN不一致（証明書検証やKerberosの前提が崩れる）
  - 時刻ズレ（Kerberosが落ちる）
  - 証明書運用不備（TLSが成立しない/警告を無視する文化が固定化）
  - ドメイン到達性（DC到達不可）  
  - 資格情報の種類（ローカル/ドメイン、UAC/特権境界）

---

## 6) “Restricted Admin mode” などの特殊モード（境界として知っておく）
- Restricted Admin mode は「RDPで接続する際に資格情報をホストへ送らない」目的のモードとして説明されている（ただし制約がある）。  
  - 根拠URL（RestrictedAdmin Modeの説明と制約）：https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn283323(v=ws.11)
  - 補助根拠URL（Security Advisory 2871997：Restricted Admin mode 概要）：https://learn.microsoft.com/en-us/security-updates/securityadvisories/2016/2871997
- 実務的な“境界”：
  - 資格情報保護には寄与し得るが、接続後に他資源へシームレスアクセスできない等の運用制約がある（＝“どこまでをRDPでやるか”の設計問題）。

---

## 7) 証跡（監査ログ）：RDPの成功・失敗を“最低限これ”で追えるようにする
### 7-A) 最低限の成功証跡：Security 4624（Logon Type 10）
- 4624 は “ログオンセッションが作られた” ことを示し、Logon Type 10 が “RemoteInteractive（RDP/Terminal Services）” に該当する。  
  - 根拠URL：https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624
- 報告に必要な最小フィールド（例）
  - Target（ログオン先）/ Account（ユーザ）/ Logon Type（10）/ Source IP / Logon ID（相関用）

### 7-B) 失敗・切断の補助証跡
- 監査イベント一覧（4648/4779等）：  
  - 根拠URL：https://learn.microsoft.com/ja-jp/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/basic-audit-logon-events
- 追加（環境により有効化状況が異なるため“参考”として扱う）
  - TerminalServices の運用ログ（1149等）は環境依存。公式Learnでの一枚岩の説明がないため、現場では **4624 type10 を一次証跡**に据え、補助として扱う（実機で有効/無効を確認して台帳へ）。

---

## 8) 是正の落としどころ（診断結果から“どう直す”を最短で言える形）
- 到達性
  - 3389 を管理網/踏み台に限定、外部は RD Gateway/VPN 経由のみ（設計で固定）
- 暗号
  - SecurityLayer=2（TLS）をポリシーで強制し、証明書運用（CN/SAN/期限/配布）を手順化  
    - 根拠URL（SecurityLayer）：https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-terminalservices-rdp-winstationextensions-securitylayer
- NLA
  - UserAuthentication=1（NLA必須）をポリシーで固定  
    - 根拠URL（UserAuthentication）：https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-terminalservices-rdp-winstationextensions-userauthentication
- 権限
  - “ログオンできる人” を Remote Desktop Users と Allow log on through RDS で最小化し、Deny を使う場合は衝突（Allowより優先）を明示して運用へ落とす  
    - 根拠URL（Allow）：https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn221985(v=ws.11)  
    - 根拠URL（Deny優先）：https://learn.microsoft.com/ja-jp/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/deny-log-on-through-remote-desktop-services
- 監査
  - 4624 type10 を基礎証跡として相関（srcIP/user/target/timewindow）できる設計へ  
    - 根拠URL：https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624
- 横展開観点（ATT&CK）
  - RDPは T1021.001 として横展開に悪用され得るため、Mitigation（到達性制御/MFA/監査/特権分離）をセットで提案する。  
    - 根拠URL：https://attack.mitre.org/techniques/T1021/001

---

## 参考URL（本文の根拠として使用：そのまま貼る）
- MITRE ATT&CK：T1021.001 Remote Desktop Protocol  
  https://attack.mitre.org/techniques/T1021/001
- Microsoft Learn：UserAuthentication（NLA必須の値）  
  https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-terminalservices-rdp-winstationextensions-userauthentication
- Microsoft Learn：SecurityLayer（RDP/Negotiate/TLS）  
  https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-terminalservices-rdp-winstationextensions-securitylayer
- Microsoft Learn：Win32_TSGeneralSetting SetSecurityLayer（補助）  
  https://learn.microsoft.com/en-us/windows/win32/termserv/win32-tsgeneralsetting-setsecuritylayer
- Microsoft Learn（Open Specs）：RDP/WSMan が CredSSP で資格情報委任する概要  
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-authsod/32f5a0b9-21d9-4b9c-b7d1-e80d72db47a7
- Microsoft Learn（Open Specs）：RDPBCGR CredSSP（TLS + Kerberos/NTLM）  
  https://learn.microsoft.com/ja-jp/openspecs/windows_protocols/ms-rdpbcgr/8e11581d-094f-461a-9fde-ba51af90cf8b
- Microsoft Learn：4624（Logon Type 10 = RemoteInteractive）  
  https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624
- Microsoft Learn：基本監査ログオンイベント（4779等）  
  https://learn.microsoft.com/ja-jp/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/basic-audit-logon-events
- Microsoft Learn：Allow log on through Remote Desktop Services  
  https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn221985(v=ws.11)
- Microsoft Learn：Deny log on through Remote Desktop Services（Denyが優先）  
  https://learn.microsoft.com/ja-jp/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/deny-log-on-through-remote-desktop-services
- Microsoft Learn：RestrictedAdmin Mode（RDPで資格情報を送らない/制約あり）  
  https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn283323(v=ws.11)
- Microsoft Learn：Security Advisory 2871997（Restricted Admin mode補助）  
  https://learn.microsoft.com/en-us/security-updates/securityadvisories/2016/2871997
- OWASP WSTG：Network Infrastructure Configuration  
  https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration
- PTES（参照元）  
  https://pentest-standard.readthedocs.io/
- OWASP ASVS（参照元）  
  https://github.com/OWASP/ASVS

---

## 深掘りリンク（最大8）
- `05_scanning_到達性把握（nmap_masscan）.md`
- `06_service_fingerprint（banner_tls_alpn）.md`
- `07_pivot_tunneling（ssh_socks_chisel）.md`
- `10_ntlm_relay_成立条件（SMB署名_LLMNR）.md`
- `12_kerberos_asrep_kerberoast_成立条件.md`
- `14_delegation（unconstrained_constrained_RBCD）.md`
- `17_laps_ローカル管理者パスワード境界.md`
- `18_winrm_psremoting_到達性と権限.md`
