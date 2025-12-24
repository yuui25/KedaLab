## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS
  - 破れる：Web侵入が起点でも、最終的な被害（再侵入・横展開・データ持ち出し・長期潜伏）は「永続化」に依存する。OS側の“自動起動・イベント駆動”が残っていると、アプリ修正後も再侵入される。
  - 満たす：永続化面（タスク/サービス/WMI）を資産・変更管理・最小権限・監査相関で“運用として潰す”。許可された自動実行のみを棚卸し、逸脱は即時検知できる状態にする。
  - 参照：https://github.com/OWASP/ASVS
- WSTG
  - WSTG-CONF-01：OS/基盤の運用設定（自動実行、管理インタフェース、監査）に起因するリスクを、アプリと同等に検証対象へ含める。  
    https://owasp.org/www-project-web-security-testing-guide/
- PTES
  - Post-Exploitation：永続化は「できる/できない」ではなく、(1) 所在の棚卸し → (2) 成立条件（必要権限・置換点・監査）→ (3) 非破壊の確認 → (4) 是正・検知の具体化、で結論を固定する。  
    https://pentest-standard.readthedocs.io/
- MITRE ATT&CK（本ファイルの主軸）
  - Scheduled Task/Job（T1053）  
    https://attack.mitre.org/techniques/T1053/
  - Scheduled Task（T1053.005）  
    https://attack.mitre.org/techniques/T1053/005/
  - Windows Service（T1543.003）  
    https://attack.mitre.org/techniques/T1543/003
  - Windows Management Instrumentation（Execution：T1047）  
    https://attack.mitre.org/techniques/T1047
  - WMI Event Subscription（Persistence：T1546.003）  
    https://attack.mitre.org/techniques/T1546/003/

---

## タイトル
永続化：Scheduled Tasks / Windows Services / WMI Event Subscription を“所在→成立条件→監査→封じ方”で確定する（観測中心）

---

## 目的（このファイルで到達する状態）
- 対象ホストで、以下を **Yes/No/Unknown** で説明できる（＝報告で推測を排除できる）。
  1) Scheduled Tasks：どのタスクが、誰の権限で、何を、いつ/何をトリガに実行するか（XML含む）
  2) Windows Services：どのサービスが、どの実体（PathName/ServiceDll）を、どのアカウントで、自動起動するか
  3) WMI Event Subscription：root\subscription の Filter / Consumer / Binding の所在と、実行が WmiPrvSE 経由になる境界
  4) 成立条件：一般ユーザが“追加/改変/置換”できる入口（ACL・DACL・パス・レジストリ）があるか
  5) 監査：作成/変更/実行のログを Blue が相関できるか（最小ログセット＋相関キー）
  6) 是正：削除/無効化、最小権限、許可リスト化、変更管理、検知ルールまで落とせる

> 注意：本ファイルは「棚卸し・監査・封じ方（防御/評価）」が中心。永続化の“作成手順（攻撃的な具体手順）”は扱わない。必要な場合は合意済みの検証環境・規程に沿って別紙で管理する。

---

## 扱う範囲（本ファイルの守備範囲）
- 扱う：schtasks（タスク）、services（サービス）、WMI（イベント購読）
- 扱わない（別ファイルへ接続）
  - Runキー/Startup Folder/Logon Script などの“その他永続化面”（別ユニットへ）
  - 認証情報奪取（LSA/DPAPI） → `26_credential_dumping_所在（LSA_DPAPI）.md`
  - 権限昇格の入口（サービス権限/UAC） → `25_windows_priv-esc_入口（サービス権限_UAC）.md`

---

## 永続化を“境界”として捉える（薄さを避けるための整理）
永続化の強さは「自動実行機構」×「実行コンテキスト」×「置換点」×「監査」の積で決まる。

- 自動実行機構
  - タスク：時間/ログオン/起動/イベント等で起動
  - サービス：起動時や依存関係で起動（StartMode）
  - WMI購読：イベント発火で実行（Filter→Consumer→Binding）
- 実行コンテキスト
  - SYSTEM/高権限サービスアカウント/gMSA/一般ユーザ
- 置換点（ここが“成立条件”）
  - 実行ファイル/スクリプトのパス（ユーザ書込み可能か）
  - 設定（XML/レジストリ/サービスDACL/WMI名前空間権限）
- 監査
  - “作成/変更” と “実行” を相関できるか（TimeWindow、UserContext、親子プロセス）

---

## 実施方法（最高に具体的）：共通の証跡作法
### 0) 証跡ディレクトリ（必須）
~~~~
mkdir %USERPROFILE%\keda_evidence\persistence_27 2>nul
cd /d %USERPROFILE%\keda_evidence\persistence_27
~~~~

### 1) 前提確定（OS / ドメイン / 現トークン）
~~~~
ver > os_ver.txt
systeminfo > systeminfo.txt
wmic computersystem get domain,partofdomain > domain_join.txt
whoami > whoami.txt
whoami /groups > whoami_groups.txt
whoami /priv > whoami_priv.txt
~~~~
判断メモ（後でレポートに直結）
- 管理者所属か、UACで未昇格か（操作が失敗した理由を“境界”として説明できる）
- ドメイン参加か（中央管理タスク/サービスが多い＝誤検知防止の基礎情報）

---

## 1/3 Scheduled Tasks（schtasks）：所在→危険度→成立条件
### 1-A) 全タスクの棚卸し（一覧＋XMLの証跡）
- 目的：タスクの“何を実行するか”は XML（TaskContent）に本体がある。一覧だけだと薄い。
- 参照（schtasks）：https://learn.microsoft.com/windows-server/administration/windows-commands/schtasks
~~~~
schtasks /query /fo LIST /v > tasks_query_list_v.txt 2>&1
schtasks /query /fo CSV /v > tasks_query_csv_v.csv 2>&1
~~~~

XML取得（タスクごと。数が多いので“疑わしい候補→個別取得”が現実的）
- まずは候補抽出（後述）→ その TaskName のみ /XML を取得する。
~~~~
REM 例：候補タスクのXML取得（TaskNameを指定して実行）
schtasks /query /tn "<TaskName>" /xml > task_<TaskName>_xml.txt 2>&1
~~~~

### 1-B) まず“疑わしい候補”を作る（実務で効くフィルタ）
優先度が高い候補（上から見る）
- 実行ユーザが SYSTEM、または特権アカウント（/ru）
- トリガが ONSTART / ONLOGON / “短間隔（毎分等）”
- 実行パスが以下にある
  - `C:\Users\` / `C:\ProgramData\` / `C:\Windows\Temp\` / `C:\Temp\`
- コマンドラインがスクリプト実行（PowerShell/cscript/wscript/mshta 等）や難読（長いbase64等）
- タスク名がランダム/偽装（正規タスク名の類似、文字列のエントロピーが高い）
- Author/Description が空、または不自然

実務の“次の一手”
- 候補タスクを 5〜20件に絞る
- 各タスクについて「XML」「実行ファイル」「親ディレクトリACL」「作成者/最終更新」を揃える

### 1-C) 成立条件（タスク改変が可能か）を確認する
タスクの改変は、主に2系統で成立する。
1) タスク定義そのものを変更できる（タスクファイル/タスクフォルダのACL）
2) 実行対象（exe/ps1等）を置換できる（実行パスのACL）

#### 1-C-1) タスクファイルの所在とACL
- タスク定義ファイルは通常 `C:\Windows\System32\Tasks\...` 配下にある（名前はフォルダ階層に対応）。
- ここが一般ユーザに書き込み可能だと、タスク改変の入口になり得る。
~~~~
REM 例：タスクファイルのACL確認（TaskNameに対応するパスへ）
icacls "C:\Windows\System32\Tasks" > icacls_tasks_root.txt 2>&1
~~~~
実務ポイント
- “Tasks配下は基本堅い”のが期待。例外があれば強い所見。

#### 1-C-2) 実行ファイル（/TR相当）のACL
- XML内の Command / Arguments を抽出し、実体のファイルと親ディレクトリに書込みがないか確認する。
~~~~
REM 例：手動でXMLから実行パスを特定 → ファイルとディレクトリのACL
icacls "<FullPathToExecutableOrScript>" > icacls_task_target_file.txt 2>&1
for %I in ("<FullPathToExecutableOrScript>") do icacls "%~dpI" > icacls_task_target_dir.txt 2>&1
~~~~
判断テンプレ
- Users/Authenticated Users に (M)(W)：成立条件が強い（置換で永続化が成立し得る）
- Program Files配下で堅い：成立条件は弱い（ただし別の入口があり得る）

### 1-D) 監査（作成/変更/実行を追えるか）
- MITREの検知戦略では、作成/変更（例：4698/4702）と実行（svchost/taskeng 等）を相関する考え方が示される。  
  https://attack.mitre.org/detectionstrategies/DET0441/
- MITRE T1053 でも Windows Security Event ID 4698（タスク作成）などに触れられる。  
  https://attack.mitre.org/techniques/T1053/

実務での最低限ログ
- Security：4698（作成）, 4702（変更）, 4699（削除）※環境の監査設定に依存
- TaskScheduler Operational：タスクの登録/実行（運用側で有効化が必要な場合あり）
- Sysmon：Process Creation（schtasks.exe / taskeng.exe / svchost.exe の親子）、File Create（実行ファイル落下）

相関キー
- TaskName（パス含む）
- TaskContent（XML：Command/Arguments/Principal）
- UserContext（作成者/実行者）
- TimeWindow（例：作成→実行が短時間）

---

## 2/3 Windows Services（services）：自動起動・実行アカウント・実体保護
### 2-A) サービス棚卸し（Name/StartMode/StartName/PathName）
- 目的：永続化は “Auto + SYSTEM/高権限 + 実体の置換可能性” が揃うと強い。
- 参照（ATT&CK Windows Service）：https://attack.mitre.org/techniques/T1543/003
~~~~
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
"Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,StartName,PathName | Sort-Object StartMode,StartName,Name | Out-File -Encoding UTF8 services_inventory.txt"
~~~~

### 2-B) まず疑わしい候補を作る（優先順位）
- StartMode=Auto かつ StartName=LocalSystem/高権限
- PathName が以下にある
  - `C:\Users\` / `C:\ProgramData\` / `C:\Windows\Temp\` / `C:\Temp\`
- 署名のない/未知のベンダ、または名称偽装
- サービス説明が不自然、または空
- 既知の正規製品なのに実体パスが逸脱（通常は Program Files 配下）

### 2-C) 成立条件（サービス改変・置換の入口）を確認する
本体は「サービス構成」「実体（exe/dll）」「レジストリ」の3点セット。

#### 2-C-1) サービス構成（sc qc / レジストリ）
- 参照（sc）：https://learn.microsoft.com/windows-server/administration/windows-commands/sc
~~~~
sc.exe qc "<ServiceName>" > svc_<ServiceName>_qc.txt 2>&1
reg query "HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>" > svc_<ServiceName>_reg.txt 2>&1
~~~~
見るべき箇所
- BINARY_PATH_NAME（実体パス＋引数）
- Start（起動種別）
- ObjectName（実行アカウント）
- Parameters\ServiceDll（svchost系のDLL実体）

#### 2-C-2) 実体ファイル/ディレクトリのACL
- ここが最重要。低権限が書ければ“置換”が成立し得る。
~~~~
REM qcやregから実体パスを特定した上で
icacls "<FullPathToServiceBinaryOrDll>" > svc_<ServiceName>_icacls_file.txt 2>&1
for %I in ("<FullPathToServiceBinaryOrDll>") do icacls "%~dpI" > svc_<ServiceName>_icacls_dir.txt 2>&1
~~~~

#### 2-C-3) サービスDACL（構成変更可否）
- ここは `25_windows_priv-esc_入口（サービス権限_UAC）.md` と直結。
~~~~
sc.exe sdshow "<ServiceName>" > svc_<ServiceName>_sdshow.txt 2>&1
~~~~
判断
- 一般ユーザ/広いグループに ChangeConfig 相当が付与：強い所見（運用ミス）
- 管理者のみ：通常

### 2-D) 監査（作成/変更/起動を追えるか）
- MITRE DET0552：サービス作成・変更の検知（4697、レジストリ変更、Sysmonなど）  
  https://attack.mitre.org/detectionstrategies/DET0552/
- Windows Service（T1543.003）  
  https://attack.mitre.org/techniques/T1543/003

相関キー（最低限）
- ServiceName / ImagePath（変更前後）
- 作成者/変更者（Security 4697 等）
- 起動プロセス（親子関係、署名、配置ディレクトリ）
- レジストリ（HKLM\System\CurrentControlSet\Services 配下の変更）

---

## 3/3 WMI（T1047）と WMI Event Subscription（T1546.003）：見落としやすい“イベント駆動永続化”
### 3-A) まず区別する（薄さ回避）
- T1047：WMIを使った実行（管理実行の手段）  
  https://attack.mitre.org/techniques/T1047
- T1546.003：WMIの永続化（Event Filter / Consumer / Binding を作り、イベントで実行）  
  https://attack.mitre.org/techniques/T1546/003/

実務ポイント
- WMI永続化は “root\subscription” の3点セットが本体：
  - `__EventFilter`
  - `__EventConsumer`（例：CommandLineEventConsumer/ActiveScriptEventConsumer 等）
  - `__FilterToConsumerBinding`

また、Microsoft Learn には permanent subscription の CreatorSID 等の前提が整理されている（監査/権限境界の理解に有用）。  
https://learn.microsoft.com/windows/win32/wmisdk/receiving-events-securely

### 3-B) root\subscription の棚卸し（存在を確定する）
- 目的：Filter/Consumer/Binding を“件数と内容”で証跡化する。
- 実務では PowerShell（CIM）での抽出が安定。
~~~~
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
"Get-CimInstance -Namespace root\subscription -ClassName __EventFilter | " ^
"Select-Object Name,QueryLanguage,Query,EventNamespace,CreatorSID | Out-File -Encoding UTF8 wmi_eventfilter.txt" ^
2>&1

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
"Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer | " ^
"Select-Object __CLASS,Name,CreatorSID | Out-File -Encoding UTF8 wmi_eventconsumer.txt" ^
2>&1

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
"Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding | " ^
"Select-Object Filter,Consumer,CreatorSID | Out-File -Encoding UTF8 wmi_filtertobinding.txt" ^
2>&1
~~~~

判定（疑わしい候補）
- Query が “ログオン/起動/一定時間” など永続化に典型のイベント条件
- Consumer が CommandLine/Script 系（環境の正当利用がある場合は許可リスト化が必要）
- CreatorSID が不自然（正規管理者運用と一致しない）

### 3-C) 監査（WMIログ）を前提にする
- MITREの検知戦略（DET0086）：WMI Event Subscription の作成（5857等）と、WmiPrvSE の異常子プロセス等を相関する方針。  
  https://attack.mitre.org/detectionstrategies/DET0086/
- WMI実行乱用の検知戦略（DET0364）も“プロセス＋WMIログ”の相関を示す。  
  https://attack.mitre.org/detectionstrategies/DET0364/

最低限ログ（例）
- Microsoft-Windows-WMI-Activity/Operational（5857/5858/5860/5861 等：環境で有効化要）
- Sysmon：Process Creation（WmiPrvSE.exe の子プロセス）、Network（リモート絡み）
- 変更点：root\subscription の CIMオブジェクト増減（定期棚卸しと差分監視）

相関キー
- Namespace（root\subscription）
- Object Class（__EventFilter / __EventConsumer / __FilterToConsumerBinding）
- CreatorSID / 実行ユーザ
- WmiPrvSE の子プロセス（Image/CommandLine）
- TimeWindow（作成→実行の時間）

---

## “成立条件”をYes/Noで切るためのチェックリスト（現場用）
### A. Scheduled Tasks
- [ ] タスク一覧（LIST/CSV）を証跡化した
- [ ] 疑わしい候補を絞り、XMLを取得した（/XML）
- [ ] 実行対象（Command/Arguments）のファイル/ディレクトリACLを確認した
- [ ] タスク定義の置換点（Tasks配下/フォルダACL）を確認した
- [ ] 作成/変更/実行のログ有無と相関キーを整理した（4698/4702/TaskScheduler/Sysmon）

### B. Services
- [ ] サービス棚卸し（StartMode/StartName/PathName）を証跡化した
- [ ] Auto + SYSTEM/高権限の候補を抽出した
- [ ] 実体（exe/dll）と親ディレクトリのACLを確認した
- [ ] 構成（sc qc、Servicesレジストリ）を証跡化した
- [ ] DACL（sdshow）まで確認できた（できない場合は理由＝権限境界を記録）
- [ ] 作成/変更/起動のログと相関（4697/レジストリ/Sysmon）を整理した

### C. WMI Event Subscription
- [ ] root\subscription の Filter/Consumer/Binding を全件ダンプした
- [ ] WMI Activity ログの有効化状況を確認した（無いなら“検知できない”が所見）
- [ ] WmiPrvSE 子プロセスの監視可否（Sysmon等）を確認した

---

## 安全な検証（PoC）：作らずに“監査と封じ方”を確認する
- 目的：永続化を実際に作成せずとも、評価として強い結論を出す。
- 実施（推奨）
  1) 現状のタスク/サービス/WMI購読を全量棚卸し（証跡）
  2) “候補”について、置換点（ACL/DACL）と実行コンテキストを確定
  3) ログの有無（作成/変更/実行）を確認し、相関が成立するかを判断
- 合意がある場合（別紙管理が前提）
  - 検証用端末で、監査ログが期待通り出るかを“運用テスト”として実施（手順は組織ルールに統合）

---

## 是正（最小コストで効く順）
1) “許可リスト化”：正規タスク/サービス/WMI購読を棚卸し、変更管理（チケット/承認）に乗せる
2) 置換点の封鎖：実行ファイル/ディレクトリのACLを最小化（Users書込み排除）
3) 実行コンテキストの最小化：SYSTEM濫用を止め、専用アカウント/gMSAへ（必要権限のみ）
4) 監査の必須化：4698/4702/4697、TaskScheduler/WMI Activity、Sysmon（可能なら）を相関できる形で収集
5) 検知：MITRE検知戦略（DET0441/DET0552/DET0086）をベースに、環境の正当運用に合わせてチューニング  
   - https://attack.mitre.org/detectionstrategies/DET0441/  
   - https://attack.mitre.org/detectionstrategies/DET0552/  
   - https://attack.mitre.org/detectionstrategies/DET0086/

---

## 参考URL（本文の根拠として使用：そのまま貼る）
- schtasks（コマンド仕様）  
  https://learn.microsoft.com/windows-server/administration/windows-commands/schtasks
- sc（サービスの照会/設定）  
  https://learn.microsoft.com/windows-server/administration/windows-commands/sc
- MITRE ATT&CK：Scheduled Task/Job（T1053）  
  https://attack.mitre.org/techniques/T1053/
- MITRE ATT&CK：Scheduled Task（T1053.005）  
  https://attack.mitre.org/techniques/T1053/005/
- MITRE ATT&CK：Windows Service（T1543.003）  
  https://attack.mitre.org/techniques/T1543/003
- MITRE ATT&CK：WMI（T1047）  
  https://attack.mitre.org/techniques/T1047
- MITRE ATT&CK：WMI Event Subscription（T1546.003）  
  https://attack.mitre.org/techniques/T1546/003/
- Microsoft Learn：Receiving Events Securely（Permanent subscription / CreatorSID）  
  https://learn.microsoft.com/windows/win32/wmisdk/receiving-events-securely
- MITRE Detection Strategy：Scheduled Task 作成/実行（DET0441）  
  https://attack.mitre.org/detectionstrategies/DET0441/
- MITRE Detection Strategy：Windows Service 作成/変更（DET0552）  
  https://attack.mitre.org/detectionstrategies/DET0552/
- MITRE Detection Strategy：WMI Event Subscription（DET0086）  
  https://attack.mitre.org/detectionstrategies/DET0086/
- MITRE Detection Strategy：WMI Execution乱用（DET0364）  
  https://attack.mitre.org/detectionstrategies/DET0364/

---

## 深掘りリンク（最大8）
- `25_windows_priv-esc_入口（サービス権限_UAC）.md`
- `26_credential_dumping_所在（LSA_DPAPI）.md`
- `18_winrm_psremoting_到達性と権限.md`
- `19_rdp_設定と認証（NLA）.md`
- `15_acl_abuse（AD権限グラフ）.md`
- `16_gpo_永続化と権限境界.md`
- `17_laps_ローカル管理者パスワード境界.md`
- `28_exfiltration_持ち出し経路（DNS_HTTP_SMB）.md`
