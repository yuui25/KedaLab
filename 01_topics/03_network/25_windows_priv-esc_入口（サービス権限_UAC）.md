## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS
  - 破れる：アプリが堅くても、ホスト側の「昇格境界（ローカル権限）」が緩いと、侵入後に横展開・永続化・証跡消しまで一気に波及する。Windowsでは特に **サービス（Windows Service）のDACL/実体（ImagePath/ServiceDll）** と **UAC（管理者でも“昇格前”がある）** が入口になりやすい。
  - 満たす：サービスは最小権限（専用アカウント/gMSA、不要な特権の剥奪、実体パスの保護、DACLの最小化、変更管理/監査）、UACは「設計境界として運用」し、昇格操作は承認・ログ・相関で追えるようにする。
  - 参照：https://github.com/OWASP/ASVS
- WSTG
  - WSTG-CONF-01：OS/ミドル/管理系機構（サービス、権限、監査）の不備はアプリと同等に重大。サービス権限・管理UI（UAC）・到達性・監査設計を検証対象に含める。  
    https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration
- PTES
  - Post-Exploitation（Privilege Escalation）：(1) 現在トークン境界の確定 → (2) サービスの“変更できる面”の列挙（DACL/実体/レジストリ）→ (3) 成立条件（権限×設定×監査）→ (4) 安全なPoC（無害な変更で確認）→ (5) 是正/検知提案、で推測ゼロに落とす。  
    https://pentest-standard.readthedocs.io/
- MITRE ATT&CK
  - T1543.003 Create or Modify System Process: Windows Service（サービス作成/改変による権限獲得）  
    https://attack.mitre.org/techniques/T1543/003/
  - T1548.002 Abuse Elevation Control Mechanism: Bypass User Account Control（UAC境界の回避）  
    https://attack.mitre.org/techniques/T1548/002/
  - T1574.002 Hijack Execution Flow: DLL Search Order Hijacking（サービスDLL/依存DLLでの探索順ハイジャックに接続）  
    https://attack.mitre.org/techniques/T1574/002/

---

## タイトル
Windows Priv-Esc 入口：サービス権限（ACL/パス/実体）とUAC（トークン境界）を“観測→成立条件→安全な検証→是正/検知”で確定する

---

## 目的（このファイルで到達する状態）
- 侵入後（低権限/管理者・未昇格を含む）に、次を **Yes/No/Unknown** で説明できる（＝報告が強くなる状態）。
  1) 現在のトークン：管理者所属か／UACによりフィルタされているか／整合性レベル（Medium/High/System）
  2) サービス改変の入口があるか：
     - サービスのDACLで **構成変更（ChangeConfig）** が可能
     - サービスの実体（exe/dll）のパス/ディレクトリが **書込み可能**
     - サービス関連レジストリ（ImagePath/Parameters/ServiceDll）が **書込み可能**
     -（補助）パスの引用符不備（Unquoted Service Path）などで“意図しない実体”へ到達し得る
  3) 監査・証跡：サービス変更/起動/プロセス生成/レジストリ変更をBlueが相関できるか
  4) 是正：最小権限（アカウント/ACL/パス保護/UAC運用）へ落とせる

> 注意：本ファイルは「評価・検証（許可された範囲）」を目的とする。攻撃用のバイナリ作成や隠密化の手順は扱わない。PoCは無害（テキスト作成等）で行い、原状復帰までを手順化する。

---

## 扱う範囲（本ファイルの守備範囲）
- 扱う
  - UAC：管理者でも“昇格前”があるという境界の確定（整合性レベル、UAC設定）
  - サービス：構成（SCM）権限、実体（ImagePath/ServiceDll）の保護、レジストリ権限
  - 監査：イベントログ/プロセスログの相関設計
- 扱わない（別ファイルへ接続）
  - タスクスケジューラ永続化 → `27_persistence_永続化（schtasks_services_wmi）.md`
  - 認証情報の所在/抽出 → `26_credential_dumping_所在（LSA_DPAPI）.md`
  - 横展開（WinRM/RDP/SMB等） → `18_winrm...` `19_rdp...` `09_smb...`

---

## 前提：Windowsにおける“権限境界”の現実（ここを誤ると薄い）
### 1) 「管理者＝常に高権限」ではない（UAC）
- 同じユーザがAdministratorsグループ所属でも、通常は“未昇格（Medium Integrity）”で動くことがある。
- このため「ローカル管理者が取れた」≠「SYSTEM相当の権限で自由」にならないケースがある。
- 境界として見るべきは **(a) グループ所属** と **(b) 現在トークンの整合性レベル**。

### 2) サービスは “正規の運用機能” なので穴が残りやすい
- アプリより先に運用が決まり、後から権限を絞りにくい（監視/バックアップ/エージェント等）。
- 入口は主に3つ：
  1) SCM（Service Control Manager）上のDACL（構成変更できるか）
  2) 実体ファイル/ディレクトリのACL（置換/追記できるか）
  3) レジストリ（ImagePath/Parameters/ServiceDll）のACL（実体参照先を変えられるか）

---

## 境界モデル（成立条件：何が揃うと“昇格が成立”するか）
### 境界A：UACトークン境界（現在の権限の上限を決める）
- Yes：High Integrity / SeDebug等特権が有効 / “昇格済み” → サービス改変の可否が広がり得る
- No：Medium Integrity（管理者所属でも未昇格） → “構成変更できるはず”が失敗することがある（ここが診断で重要）

### 境界B：サービス構成変更（ChangeConfig）が可能（SCM DACL）
- 成立条件：対象サービスに対して、現ユーザ（または所属グループ）が **SERVICE_CHANGE_CONFIG** 等を持つ
- 影響：ImagePath/ServiceDll 等の参照先変更、起動アカウント変更、起動種別変更が可能になり得る

### 境界C：サービス実体（exe/dll）を書き換えられる（ファイルACL）
- 成立条件：実体ファイルまたは親ディレクトリに、現ユーザが書込み（Modify/Write）を持つ
- 影響：実体置換/追記により、サービス起動時に意図しない処理が実行され得る

### 境界D：サービス関連レジストリを書き換えられる（Reg ACL）
- 成立条件：HKLM配下の該当キーに書込み権限がある（通常は無い＝あれば強い所見）
- 影響：ImagePath/ServiceDll/Parameters等の変更で、実行フローが変えられ得る

### 境界E：監査（Blueが追える）
- “成立”しても、監査が堅ければ検知・抑止が可能。逆に監査が無いとリスクは跳ね上がる。

---

## 実施方法（最高に具体的）：観測→判断→次の一手
> すべて「証跡を残す」前提。コマンド出力はファイル保存し、サービス名・実体パス・ACLを紐づける。

---

## 0) 証跡ディレクトリ（必須）
~~~~
mkdir %USERPROFILE%\keda_evidence\win_priv_esc_25 2>nul
cd /d %USERPROFILE%\keda_evidence\win_priv_esc_25
~~~~

---

## 1) 現在トークン境界（UAC）を確定する
### 1-A) whoami（最重要：整合性レベルと特権）
- 目的：この後の「できる/できない」を“UAC境界”として説明できるようにする。
~~~~
whoami > whoami.txt
whoami /groups > whoami_groups.txt
whoami /priv > whoami_priv.txt
~~~~
観測ポイント
- `Mandatory Label\...` が **Medium / High / System** のどれか（整合性レベル）
- `BUILTIN\Administrators` が含まれるか（所属）
- SeDebugPrivilege 等が有効か（Enable/Disableは状況依存）

### 1-B) UAC設定（レジストリ：EnableLUA等）
- 目的：UACが有効か、プロンプト強度がどうかを“設定根拠”で示す。
~~~~
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA > uac_EnableLUA.txt
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin > uac_ConsentPromptBehaviorAdmin.txt
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop > uac_PromptOnSecureDesktop.txt
~~~~
判断テンプレ（例）
- EnableLUA=1：UAC有効（通常）
- EnableLUA=0：UAC無効（運用上の重大所見になり得る）
- ConsentPromptBehaviorAdmin / PromptOnSecureDesktop：運用ポリシーの強さ（組織標準との比較が重要）

参考（UAC全般）：https://learn.microsoft.com/windows/security/identity-protection/user-account-control/user-account-control-overview

---

## 2) サービス全体の棚卸し（“当たり”を作る）
### 2-A) サービス一覧（実体パス・起動ユーザ・自動起動を抽出）
- 目的：優先順位を付ける（Auto/Running × LocalSystem/高権限アカウント × 実体がサードパーティ）。
PowerShell（推奨：整形しやすい）
~~~~
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
"Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,StartName,PathName | Sort-Object StartMode,StartName,Name | Out-File -Encoding UTF8 services_inventory.txt"
~~~~
観測ポイント（優先度の付け方）
- StartMode=Auto（再起動で確実に動く）
- StartName=LocalSystem / NetworkService / LocalService / ドメインアカウント
- PathName に “引数付き/空白/引用符なし” がある（後述のパス境界）

参考（Win32_Service）：https://learn.microsoft.com/windows/win32/cimwin32prov/win32-service

---

## 3) サービス構成変更の可否（SCM DACL）を判定する
### 3-A) 対象サービスのDACL（SDDL）を取得
- 目的：ChangeConfig相当が付いていないかを“設定として”確定する。
~~~~
sc.exe sdshow <ServiceName> > svc_<ServiceName>_sdshow.txt
sc.exe qc <ServiceName> > svc_<ServiceName>_qc.txt
~~~~
観測ポイント
- `sc qc` の `BINARY_PATH_NAME`（実体と引数）
- `sdshow` の SDDL（DACLに、Users/Authenticated Users/Everyone/当該ユーザが強い権限を持つACEが無いか）

参考（sc）：https://learn.microsoft.com/windows-server/administration/windows-commands/sc

### 3-B) “自分が変更できるか” をツールで短時間に確定（AccessChk）
- 目的：SDDLを手で解析する前に、実務では “権限の有無” を素早く当てる。
- AccessChk はSysinternals。サービス権限確認にも使える。  
  https://learn.microsoft.com/sysinternals/downloads/accesschk
~~~~
# 例：サービスに対するアクセス権を表示（表記は環境/バージョンで差がある）
accesschk.exe -qc <ServiceName> > svc_<ServiceName>_accesschk.txt
~~~~
判断テンプレ
- ChangeConfig/WriteDac/WriteOwner/FullControl 等が出る：サービス改変入口（強い所見）
- Query/Start/Stop 程度：通常（入口としては弱い）

> 補足：AccessChkが使えない環境では、sdshowのSDDLを保存し、レビュー時に解析する（“Unknown”を残さない）。

---

## 4) サービス実体（exe）/ディレクトリのACLを判定する（最重要）
### 4-A) 実体パス（exe）を正確に取り出す（引数を除去）
- 目的：PathName は `"C:\Path\svc.exe" -k ...` のように引数が付く。ACL確認は exe とディレクトリに分ける。
PowerShellで“先頭のexeパス”を抽出（現場で強い）
~~~~
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
"$svc='<ServiceName>'; $p=(Get-CimInstance Win32_Service -Filter \"Name='$svc'\").PathName; $p | Out-File -Encoding UTF8 svc_${svc}_pathname_raw.txt; " ^
"$exe = ($p -replace '^\s*\"([^\""]+)\".*$','$1'); if($exe -eq $p){ $exe = ($p -split '\s+')[0] } ; " ^
"$exe | Out-File -Encoding UTF8 svc_${svc}_exe_path.txt; " ^
"Split-Path -Parent $exe | Out-File -Encoding UTF8 svc_${svc}_exe_dir.txt"
~~~~

### 4-B) ACL確認（icacls）
- 目的：低権限ユーザが **書込み（M/W）** を持っていないかを確定する。
~~~~
set /p EXE=<svc_<ServiceName>_exe_path.txt
icacls "%EXE%" > svc_<ServiceName>_icacls_exe.txt

for %%D in ("%EXE%") do icacls "%%~dpD" > svc_<ServiceName>_icacls_dir.txt
~~~~
判断テンプレ（例）
- exe またはディレクトリに、Users/Authenticated Users/Everyone に (M)(W) 等がある：**実体置換の入口**
- Program Files 配下で通常のACL：入口なし（他の境界へ）

参考（icacls）：https://learn.microsoft.com/windows-server/administration/windows-commands/icacls

---

## 5) Unquoted Service Path（引用符不備）の境界を判定する（有無を確定→影響評価）
> これは「成立条件」を丁寧に書かないと薄くなる。ポイントは “空白＋未引用＋途中ディレクトリに書込み可能” の組合せ。

### 5-A) 未引用パス（空白を含む）を抽出
~~~~
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
"Get-CimInstance Win32_Service | Where-Object { $_.PathName -match '\s' -and $_.PathName -notmatch '^\s*\"' } | " ^
"Select-Object Name,StartName,StartMode,PathName | Out-File -Encoding UTF8 services_unquoted_path_candidates.txt"
~~~~

### 5-B) “途中パスの書込み可否” を確認（成立条件の根）
- 例：`C:\Program Files\Vendor App\Service.exe` が未引用の場合、探索順で `C:\Program.exe` 等が問題になる、という古典的整理。
- 実務では“途中に落ちる候補”を列挙し、その候補ディレクトリが書込み可能か（icacls）を確認する。
~~~~
# ここはサービスごとに候補が異なるため、候補ディレクトリを列挙した上で icacls で確認する
# 例：C:\, C:\Program Files\, C:\Program Files\Vendor App\ のACLを見る
icacls "C:\" > acl_C_root.txt
icacls "C:\Program Files" > acl_program_files.txt
~~~~
判断テンプレ
- 未引用＋途中候補に書込み可：成立条件が揃っている（重大）
- 未引用だが途中候補に書込み不可：成立条件未達（所見は弱まるが、是正（引用符付与）は推奨）

> 注意：実際の動作検証（サービス再起動等）は業務影響が出るため、原則は設定根拠（PathName/ACL）で結論を出し、PoCは合意・メンテ枠でのみ行う。

---

## 6) サービス関連レジストリ（ImagePath/ServiceDll）の境界を判定する
### 6-A) サービスキーの値（構成根拠）
~~~~
reg query "HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>" > svc_<ServiceName>_reg_root.txt
reg query "HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\Parameters" /s > svc_<ServiceName>_reg_params.txt 2>nul
~~~~
観測ポイント
- `ImagePath`（exe）
- `ObjectName`（サービス実行アカウント）
- `Parameters\ServiceDll`（svchost系/サービスDLL）

### 6-B) レジストリACL（書込み可否）
PowerShell（Registry:: でACL取得）
~~~~
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
"Get-Acl 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\<ServiceName>' | Format-List | Out-File -Encoding UTF8 svc_<ServiceName>_reg_acl.txt"
~~~~
補助（AccessChk：レジストリ権限の短時間確定）
~~~~
accesschk.exe -qk "HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>" > svc_<ServiceName>_accesschk_reg.txt
~~~~
判断テンプレ
- Users等に SetValue/CreateSubKey：強い所見（通常はほぼ無い）
- 管理者のみ：通常

---

## 7) UAC境界を“権限昇格の読み替え”として報告に落とす（やりがちミス防止）
### 7-A) ケース分類（報告用テンプレ）
- Case 1：非管理者（Administrators非所属）
  - 期待：サービス改変（HKLM/SCM）は基本不可。入口があるならそれ自体が重大（DACL/ACL逸脱）。
- Case 2：管理者所属だが未昇格（Medium Integrity）
  - 期待：一部操作が失敗する。昇格要求（正規のUACプロンプト）を踏まえた運用設計が必要。
- Case 3：昇格済み（High Integrity）
  - 期待：多くの管理操作が可能。ここで入口がある場合、最終的にSYSTEM相当へ到達し得る（T1543.003と接続）。

### 7-B) UACの“回避”は扱いを分ける（本ファイルの方針）
- UACバイパスはT1548.002に該当し得るが、具体的なバイパステクニック列挙は誤用リスクが高い。
- 本ファイルでは、
  - 「UAC設定が弱い（無効/低プロンプト）」の評価
  - 「管理者未昇格の前提で、サービス境界がどう見えるか」
  - 「監査と運用で“昇格操作”を追えるか」
  に限定する。

参考（UAC概要）：https://learn.microsoft.com/windows/security/identity-protection/user-account-control/user-account-control-overview  
参考（ATT&CK T1548.002）：https://attack.mitre.org/techniques/T1548/002/

---

## 8) 安全な検証（PoC）：無害・原状復帰・合意前提
> PoCは「成立条件が揃っている」ことを“無害に確認”するためのもの。業務影響がある操作（サービス停止/再起動/構成変更）は、合意・メンテ枠・ロールバック手順が前提。

### 8-A) 変更できる“証拠”だけを取る（推奨：変更しないPoC）
- sc qc / sdshow / icacls / reg query の結果を揃え、成立条件（B/C/D）を根拠で確定する。

### 8-B) 合意がある場合のみ：最小の変更（すぐ戻せるもの）
- 例：サービス説明（Description）変更など、実行フローに影響しない変更で “ChangeConfig権限の実在” を確認
~~~~
# 影響の小さい項目で権限確認（環境により許可/禁止が異なる）
sc.exe description <ServiceName> "keda-test-priv-esc-25" > svc_<ServiceName>_poc_desc_set.txt

# 元に戻す（必須）
sc.exe description <ServiceName> "" > svc_<ServiceName>_poc_desc_restore.txt
~~~~
判断
- 成功：ChangeConfig相当の入口が“事実”として確認できる
- 失敗：入口無し、またはUAC未昇格等の境界（Case分類へ戻す）

---

## 9) 監査・検知（Blue向け）：相関キーと最低限の監視点
### 9-A) 重要イベント（例：Windows標準ログ）
- サービスインストール/登録
  - System：Service Control Manager（例：7045 など）
  - Security：4697（有効なら）
- サービス設定変更（起動種別・バイナリパス等）
  - System：SCMイベント（環境により差）
  - Sysmon（導入時）：Registry value set / File create / Process create 等と相関

### 9-B) 相関キー（最低限）
- 変更主体：ユーザ（Securityログ）/端末/セッション
- 対象：ServiceName、ImagePath/ServiceDll の変更前後
- 実行：サービス起動によるプロセス生成（親子関係）
- ファイル：実体ファイルの更新（ハッシュ/作成時刻/署名）

### 9-C) ATT&CK接続（検知観点の整理）
- T1543.003（サービス改変）：サービス作成/変更とプロセス生成の相関  
  https://attack.mitre.org/techniques/T1543/003/
- T1548.002（UAC境界）：昇格に関わる操作を“管理イベント”として監査対象に含める  
  https://attack.mitre.org/techniques/T1548/002/

---

## 10) 是正（最小コストで効く順：現場で通る言い方）
### サービス設計（最優先）
1. 実行アカウントを最小化（LocalSystem濫用を止める。可能ならgMSA/専用ローカルアカウント）
2. サービスのDACLを最小化（Users/Authenticated Users へ ChangeConfig を付けない）
3. 実体パスを保護
   - Program Files 配下に配置、ディレクトリACLを堅く
   - 実体（exe/dll）を一般ユーザが書き換えられない
4. Unquoted Service Path を解消（空白を含むパスは必ず引用符で囲む）
5. レジストリ（Services配下）権限の棚卸（書込みが残っていれば是正）

### UAC運用（境界として固定）
1. EnableLUA を無効化しない（原則）
2. 管理操作は “昇格の承認” と “監査（ログ/相関）” を前提に運用
3. ローカル管理者付与を最小化（管理者未昇格の“つもり運用”を避ける）

---

## 参考URL（本文の根拠として使用：そのまま貼る）
- sc（サービスの照会/設定、sdshow/qc 等）  
  https://learn.microsoft.com/windows-server/administration/windows-commands/sc
- Win32_Service（サービスのPathName/StartName等を取得）  
  https://learn.microsoft.com/windows/win32/cimwin32prov/win32-service
- icacls（NTFS ACL確認）  
  https://learn.microsoft.com/windows-server/administration/windows-commands/icacls
- Sysinternals AccessChk（サービス/レジストリ権限確認に有用）  
  https://learn.microsoft.com/sysinternals/downloads/accesschk
- UAC overview（UACの前提・運用）  
  https://learn.microsoft.com/windows/security/identity-protection/user-account-control/user-account-control-overview
- MITRE ATT&CK：T1543.003 Windows Service  
  https://attack.mitre.org/techniques/T1543/003/
- MITRE ATT&CK：T1548.002 Bypass User Account Control  
  https://attack.mitre.org/techniques/T1548/002/
- MITRE ATT&CK：T1574.002 DLL Search Order Hijacking  
  https://attack.mitre.org/techniques/T1574/002/
- OWASP WSTG-CONF-01  
  https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration
- PTES  
  https://pentest-standard.readthedocs.io/
- OWASP ASVS  
  https://github.com/OWASP/ASVS

---

## 深掘りリンク（最大8）
- `05_scanning_到達性把握（nmap_masscan）.md`
- `07_pivot_tunneling（ssh_socks_chisel）.md`
- `09_smb_enum_共有・権限・匿名（null_session）.md`
- `18_winrm_psremoting_到達性と権限.md`
- `19_rdp_設定と認証（NLA）.md`
- `20_mssql_横展開（xp_cmdshell_linkedserver）.md`
- `26_credential_dumping_所在（LSA_DPAPI）.md`
- `27_persistence_永続化（schtasks_services_wmi）.md`
