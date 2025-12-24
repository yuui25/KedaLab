## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS
  - 破れる：Web侵入が起点でも、最終的な被害（横展開・永続化・クラウド侵害）は “資格情報の奪取” で決まる。Windowsでは特に **LSA（LSASSメモリ/LSA Secrets）** と **DPAPI（ユーザ保護ストア）** が「所在（どこにあるか）」としての主戦場になる。
  - 満たす：WDigestの平文キャッシュ抑止、LSA保護（RunAsPPL）、Credential Guard、最小特権（SeDebug等の制御）、資格情報の保存禁止/制限（CredManポリシー）、監査と相関（LSASSアクセス/DPAPIイベント/サービス変更/横展開）を一体で設計。
  - 参照：https://github.com/OWASP/ASVS
- WSTG
  - WSTG-CONF-01：OS/基盤の“資格情報の保存と保護”はアプリ外でも致命傷。侵入後の横展開リスク評価として、LSA/DPAPIの保護状態と監査設計を検証対象に含める。  
    https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration
- PTES
  - Post-Exploitation / Credential Access：推測や“出来そう”ではなく、(1) 所在の棚卸し → (2) 成立条件（必要権限/設定/防御）→ (3) 安全な確認（非破壊・秘匿）→ (4) 監査/検知の可否 → (5) 是正案、で確定する。  
    https://pentest-standard.readthedocs.io/
- MITRE ATT&CK（所在を“技術ID”に接続）
  - T1003 OS Credential Dumping（Windowsの代表）  
    https://attack.mitre.org/techniques/T1003/ :contentReference[oaicite:0]{index=0}
  - T1003.001 LSASS Memory（LSASSプロセスメモリからの取得）  
    https://attack.mitre.org/techniques/T1003/001/ :contentReference[oaicite:1]{index=1}
  - T1003.004 LSA Secrets（HKLM\SECURITY\Policy\Secrets 等：SYSTEM相当でアクセス）  
    https://attack.mitre.org/techniques/T1003/004/ :contentReference[oaicite:2]{index=2}
  - T1555 Credentials from Password Stores（DPAPI配下の保存場所を含む“パスワードストア”）  
    https://attack.mitre.org/techniques/T1555 :contentReference[oaicite:3]{index=3}
  - T1555.004 Windows Credential Manager（Credential Locker/Vault：DPAPIで保護）  
    https://attack.mitre.org/techniques/T1555/004 :contentReference[oaicite:4]{index=4}

---

## タイトル
Credential Dumpingの所在：LSA（LSASS/LSA Secrets）とDPAPI（MasterKey/Vault/CredMan）を“観測→成立条件→安全な検証→検知/是正”で確定する

---

## 目的（このファイルで到達する状態）
- 侵入後（低権限/ローカル管理者/ドメインユーザ等を含む）に、以下を **Yes/No/Unknown** で“所在と境界”として説明できる。
  1) LSASS（メモリ）に残り得る資格情報の種類と、取得成立の前提（必要権限・防御機構）
  2) LSA Secrets（レジストリ：HKLM\SECURITY\Policy\Secrets）の所在と成立条件（SYSTEM等）
  3) DPAPIの所在（MasterKey/Protect、Credential Manager/Vault）と、復号成立の前提（ユーザコンテキスト・バックアップキー等）
  4) 防御状態（WDigest、RunAsPPL、Credential Guard、監査）を“観測結果”で示す
  5) 検知と相関（LSASSアクセス→ダンプ兆候、DPAPI監査イベント、CredManアクセス）をログ設計に落とす

> 重要：本ユニットは「所在・境界・防御評価」が主。具体的な“窃取手順（ダンプ/復号コマンド等）”は誤用リスクが高いため扱わない。実施は必ず合意済みのルールと検証環境で行う。

---

## 扱う範囲（本ファイルの守備範囲）
- 扱う
  - LSA/LSASS：メモリ境界、LSA保護（PPL/Credential Guard）、WDigest平文キャッシュの有無
  - LSA Secrets：所在（レジストリ）とアクセス境界（SYSTEM等）
  - DPAPI：MasterKeyの所在、ドメインバックアップ機構、監査イベント（4692等）
  - Credential Manager/Vault：所在（ストア/ファイル/概念）、監査・検知観点
- 扱わない（別ユニットに接続）
  - 具体的なダンプ/復号の攻撃手順（ツール/コマンド列）
  - AD側（NTDS/DCSync等）詳細 → `12_kerberos...` / `15_acl_abuse...` / AD編へ
  - 永続化・横展開の実行 → `27_persistence...` / `18_winrm...` / `19_rdp...`

---

## まず押さえる：資格情報は“どこに残るか”で評価が変わる
### A. LSASS（メモリ）に残り得るもの（所在：プロセスメモリ）
- 定義：LSASSメモリから資格情報を得る行為が T1003.001（LSASS Memory）。 :contentReference[oaicite:5]{index=5}
- 成立条件（境界）
  - 取得側に高権限（管理者/SYSTEM）や特権（例：デバッグ系）が要求されがち
  - 防御（RunAsPPL / Credential Guard）で難易度と検知性が大きく変わる

### B. LSA Secrets（所在：レジストリSECURITYハイブ）
- 定義：LSA secrets は `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets` に保存され得る（SYSTEM相当でのアクセスが前提）。 :contentReference[oaicite:6]{index=6}
- 特徴：サービスアカウント系の機密（運用由来）が入るため、発見＝影響が大きい。

### C. DPAPI（所在：ユーザプロファイル + ドメインバックアップ）
- MasterKeyはユーザプロファイル配下に保存される（イベント4692の説明に所在が明記）。 :contentReference[oaicite:7]{index=7}
- ドメイン参加機では、MasterKeyのバックアップ機構が存在し、4692等の監査が出る。 :contentReference[oaicite:8]{index=8}

### D. Credential Manager / Vault（所在：Windowsの資格情報ストア）
- ATT&CKでは Windows Credential Manager を T1555.004 として整理。 :contentReference[oaicite:9]{index=9}
- ここは “保存されている事実” 自体が運用リスク。復号可否はDPAPI境界へ接続する。

---

## 実施方法（最高に具体的）：観測→判断→次の一手
> 方針：非破壊・秘匿（パスワード等の実値を扱わない）。原則として「設定」「存在」「監査」を証跡化し、窃取（ダンプ/復号）は合意がある場合のみ別手順（別ユニット）で実施。

---

## 0) 証跡ディレクトリ（必須）
~~~~
mkdir %USERPROFILE%\keda_evidence\cred_dumping_26 2>nul
cd /d %USERPROFILE%\keda_evidence\cred_dumping_26
~~~~

---

## 1) 環境の前提確定（OS / ドメイン参加 / 現在トークン）
### 1-A) OS / ビルド
~~~~
ver > os_ver.txt
systeminfo > systeminfo.txt
~~~~

### 1-B) ドメイン参加（影響：DPAPIバックアップ/AD連動が変わる）
~~~~
wmic computersystem get domain,partofdomain > domain_join.txt
~~~~

### 1-C) 現在トークン（管理者所属・特権・整合性レベル）
~~~~
whoami > whoami.txt
whoami /groups > whoami_groups.txt
whoami /priv > whoami_priv.txt
~~~~

判断（Yes/No/Unknown）
- DomainJoined=TRUE：DPAPIのドメインバックアップ境界（4692等）が現実的
- 管理者所属だが未昇格：後続の設定確認が読めない/失敗する場合は “UAC境界” として扱う

---

## 2) 防御状態を“設定で”確定する（ここが薄いと報告が弱い）
### 2-A) WDigest（平文がLSASSに残り得る境界）
- Microsoftは WDigest の UseLogonCredential によりメモリ上の資格情報保持が変わる旨を説明（0で保持しない、1で保持）。 :contentReference[oaicite:10]{index=10}
~~~~
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential > wdigest_UseLogonCredential.txt 2>&1
~~~~
判断
- 値が 1：平文が残り得る方向（強い是正優先）
- 値が 0、または（OSにより）未設定で既定0：抑止方向
- 読めない：権限/UACのため Unknown（ただし“境界として不明”を明記して良い）

### 2-B) LSA保護（RunAsPPL：lsassをPPLで保護）
- Microsoftは追加のLSA保護（RunAsPPL）の設定手段を案内している。 :contentReference[oaicite:11]{index=11}
~~~~
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL > lsa_RunAsPPL.txt 2>&1
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPLBoot > lsa_RunAsPPLBoot.txt 2>&1
~~~~
判断
- RunAsPPL=1：LSASS保護あり（ただし“絶対安全”ではない＝検知と組にする）
- RunAsPPL=0/未設定：LSASSアクセス難易度が下がり得る（優先是正）

### 2-C) Credential Guard（VBS：資格情報をlsass外（Lsaiso等）へ）
- Microsoft Learnは Credential Guard の有効化と、検証方法（msinfo32/PowerShell/EventViewer）を示している。 :contentReference[oaicite:12]{index=12}
非管理者でも可能な確認（msinfo32手動）
- `msinfo32.exe` → System Summary → “Virtualization-based Security Services Running” に Credential Guard が出るか

PowerShell（昇格が必要な場合あり）
~~~~
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
"(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning" ^
> credential_guard_services_running.txt 2>&1
~~~~
判断
- 1が含まれる：Credential Guard稼働（設計境界として強い）
- 0のみ：無効（優先是正）
- エラー/取得不可：Unknown（権限・WMI制限）

---

## 3) “所在”の棚卸し（実値は取らず、存在とパスだけを証跡化）
### 3-A) LSA Secrets（所在：HKLM\SECURITY\Policy\Secrets）
- ATT&CK/関連資料は、LSA Secrets が `HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets` に保存され得ると整理。 :contentReference[oaicite:13]{index=13}
実務手順（安全）
- ここは通常、低権限では参照できない。参照できない場合は “境界として正しい” ので Unknownではなく「アクセス不可（期待どおり）」として記録する。
~~~~
reg query "HKLM\SECURITY\Policy\Secrets" > lsa_secrets_query.txt 2>&1
~~~~
判断
- Access is denied：通常（アクセス境界が効いている）
- 一覧が出る：強い所見（権限過多または既に高権限を得ている）。取得“手順”ではなく「所在が露出している状態」を重大として報告。

### 3-B) DPAPI MasterKey（所在：ユーザプロファイル）
- 4692の説明に、Master Keyが `%APPDATA%\Roaming\Microsoft\Windows\Protect\%SID%` にある旨が明記。 :contentReference[oaicite:14]{index=14}
安全な棚卸し（ファイル名/件数/更新日だけ）
~~~~
set "DPAPI_PROTECT=%APPDATA%\Microsoft\Protect"
echo %DPAPI_PROTECT% > dpapi_protect_path.txt

dir /a /s "%DPAPI_PROTECT%" > dpapi_protect_dir.txt 2>&1

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
"Get-ChildItem -Force -Recurse \"$env:APPDATA\Microsoft\Protect\" | " ^
"Select-Object FullName,Length,LastWriteTime | Out-File -Encoding UTF8 dpapi_protect_inventory.txt" ^
2>&1
~~~~
判断
- ファイルが存在：DPAPI利用あり（通常）
- 異常な更新タイミング（インシデント時刻と一致）：DFIR観点で重要（4692/4693等と相関）

### 3-C) Credential Manager / Vault（存在確認：秘密は表示しない）
- ATT&CKのT1555.004は Credential Manager からの資格情報取得を整理し、検知戦略も存在する。 :contentReference[oaicite:15]{index=15}
安全な観測（“保存されているか/何件か”）
~~~~
cmdkey /list > cmdkey_list.txt 2>&1
~~~~
判断
- 登録が多い：運用上の保存リスク（“保存を許すべきか”を是正へ）
- 0件：保存リスクは低い（ただしDPAPI/ブラウザ等は別）

---

## 4) 監査（Blueが追えるか）：必須ログと“相関キー”
### 4-A) LSASSメモリアクセスの検知観点（プロセスアクセス→ダンプ兆候）
- MITREの検知戦略は「lsassへの高権限ハンドル取得 → ダンプ/ファイル作成等」の連鎖を推奨している。 :contentReference[oaicite:16]{index=16}
必要ログ（例）
- Sysmon Event ID 10（Process Access：lsassへのアクセス）
- Sysmon Event ID 1（Process Creation）
- Sysmon Event ID 11（File Creation）
- Security 4673/4688 等（特権使用/プロセス作成）

相関キー（最低限）
- TargetProcess = lsass.exe
- AccessMask（フルアクセスなど）
- Parent/ProcessName/CommandLine
- DumpFilePath（TempやWindows\Temp等）
- 時系列（TimeWindow：例 5分以内） :contentReference[oaicite:17]{index=17}

### 4-B) DPAPI監査（4692等）
- Microsoft Learn：4692はDPAPI Master Keyのバックアップ試行で生成され、MasterKeyの所在も説明している。 :contentReference[oaicite:18]{index=18}
- 4692は“情報目的で悪性判定は難しい”とも記載されるため、単独ではなく相関で扱う。 :contentReference[oaicite:19]{index=19}

相関キー
- Subject（Account/LogonId）
- Key Identifier（MasterKey GUID相当）
- Recovery Server（DC名）
- 発生時刻（横展開・リモートログオン・権限変更と合わせる）

### 4-C) Password Stores（CredMan等）の検知戦略
- MITREは T1555（Password Stores）として、LSASS/DPAPI/CredMan等への不審アクセスを相関で検知する方針を示している。 :contentReference[oaicite:20]{index=20}

---

## 5) 安全な検証（PoC）：原則“窃取せず”に成立条件を確定する
> ここでやるのは「奪える」ではなく「奪える前提（境界が弱い）が揃っている」を確定すること。

### 5-A) 設定ベースの確定（推奨）
- WDigest（UseLogonCredential）
- RunAsPPL（LSA保護）
- Credential Guard（Win32_DeviceGuard / msinfo32）
- CredMan登録件数（cmdkey /list）
- DPAPI MasterKeyファイルの存在（Protect配下）

→ これだけで「所在と境界（露出面）」はレポート可能。

### 5-B) 合意がある場合のみ（別手順へ分離すべき理由）
- LSASSダンプやDPAPI復号は、実データ（パスワード/チケット/鍵）へ直結し、情報漏えい・再利用リスクが高い。
- 実施するなら
  - “検証用アカウント/検証用端末” のみ
  - 取得データは暗号化・持出し制御
  - 実施・保管・廃棄の手順を事前合意
  を明文化した上で、専用ユニット（手順管理）に分離する。

---

## 6) レポートへ落とす書き方（テンプレ：Yes/No/Unknown + 根拠）
### Finding 1：WDigestにより平文がLSASSに残り得る（例）
- 判定：Yes
- 根拠：`HKLM...\WDigest\UseLogonCredential = 1`（Microsoftが値の意味を説明） :contentReference[oaicite:21]{index=21}
- 影響：T1003.001（LSASS Memory）により資格情報奪取の成立条件が緩む :contentReference[oaicite:22]{index=22}
- 是正：UseLogonCredential=0（GPOで管理）、Credential Guard/RunAsPPLを併用 :contentReference[oaicite:23]{index=23}
- 証跡：wdigest_UseLogonCredential.txt / whoami_priv.txt / credential_guard_services_running.txt

### Finding 2：LSA保護（RunAsPPL）が無効（例）
- 判定：Yes（無効）
- 根拠：RunAsPPL 未設定 or 0（Microsoftが追加LSA保護として案内） :contentReference[oaicite:24]{index=24}
- 影響：LSASSへのプロセスアクセス監視（Sysmon10等）を強化しないと、LSASSメモリ窃取の検知が難化 :contentReference[oaicite:25]{index=25}

### Finding 3：Credential Managerに多数の登録（例）
- 判定：Yes
- 根拠：cmdkey /list の登録件数（秘密は含めず）＋T1555.004の所在整理 :contentReference[oaicite:26]{index=26}
- 是正：保存禁止ポリシー/運用の見直し、端末の防御（Credential Guard） :contentReference[oaicite:27]{index=27}

---

## 7) 是正（優先順：現場で通る）
1. WDigest（UseLogonCredential）を抑止（平文キャッシュを残さない） :contentReference[oaicite:28]{index=28}
2. Credential Guard を有効化し、検証手順（msinfo32/DeviceGuard/WInInitログ）を運用に組み込む :contentReference[oaicite:29]{index=29}
3. 追加LSA保護（RunAsPPL）を検討し、互換性（認証プロバイダ等）も含めて変更管理する :contentReference[oaicite:30]{index=30}
4. 資格情報ストア（Credential Manager/Vault）に “保存させない運用” を徹底（特に共有端末・管理端末）
5. 検知：LSASSアクセス連鎖（ProcessAccess→Dump兆候）を相関し、正当ツールは最小限に許可（DET0363の観点） :contentReference[oaicite:31]{index=31}
6. DPAPI監査（4692等）は単独では弱いので、横展開/権限変更/不審プロセスと相関（Audit DPAPI Activityの位置づけに注意） :contentReference[oaicite:32]{index=32}

---

## 参考URL（本文の根拠として使用：そのまま貼る）
- MITRE ATT&CK：T1003 OS Credential Dumping  
  https://attack.mitre.org/techniques/T1003/ :contentReference[oaicite:33]{index=33}
- MITRE ATT&CK：T1003.001 LSASS Memory  
  https://attack.mitre.org/techniques/T1003/001/ :contentReference[oaicite:34]{index=34}
- MITRE ATT&CK：T1003.004 LSA Secrets  
  https://attack.mitre.org/techniques/T1003/004/ :contentReference[oaicite:35]{index=35}
- MITRE ATT&CK：T1555 Credentials from Password Stores  
  https://attack.mitre.org/techniques/T1555 :contentReference[oaicite:36]{index=36}
- MITRE ATT&CK：T1555.004 Windows Credential Manager  
  https://attack.mitre.org/techniques/T1555/004 :contentReference[oaicite:37]{index=37}
- MITRE Detection Strategy：LSASS Memory（アクセス→ダンプの相関）DET0363  
  https://attack.mitre.org/detectionstrategies/DET0363/ :contentReference[oaicite:38]{index=38}
- Microsoft：WDigest UseLogonCredential（0/1の意味）  
  https://support.microsoft.com/en-us/topic/microsoft-security-advisory-update-to-improve-credentials-protection-and-management-may-13-2014-93434251-04ac-b7f3-52aa-9f951c14b649 :contentReference[oaicite:39]{index=39}
- Microsoft Learn：Configure Credential Guard（有効化・検証方法）  
  https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage :contentReference[oaicite:40]{index=40}
- Microsoft Learn：Configure additional LSA protection（RunAsPPL）  
  https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection :contentReference[oaicite:41]{index=41}
- Microsoft Learn：Event 4692（DPAPI MasterKeyバックアップ、MasterKey所在の説明）  
  https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4692 :contentReference[oaicite:42]{index=42}
- Microsoft Learn：Audit DPAPI Activity（4692-4695の位置づけ）  
  https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-dpapi-activity :contentReference[oaicite:43]{index=43}
- OWASP WSTG-CONF-01  
  https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration
- PTES  
  https://pentest-standard.readthedocs.io/
- OWASP ASVS  
  https://github.com/OWASP/ASVS

---

## 深掘りリンク（最大8）
- `15_acl_abuse（AD権限グラフ）.md`
- `16_gpo_永続化と権限境界.md`
- `17_laps_ローカル管理者パスワード境界.md`
- `18_winrm_psremoting_到達性と権限.md`
- `19_rdp_設定と認証（NLA）.md`
- `20_mssql_横展開（xp_cmdshell_linkedserver）.md`
- `25_windows_priv-esc_入口（サービス権限_UAC）.md`
- `27_persistence_永続化（schtasks_services_wmi）.md`
