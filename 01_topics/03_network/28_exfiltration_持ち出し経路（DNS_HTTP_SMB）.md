## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS
  - 破れる：侵入の成否よりも「外へ出せるか（Egress）」で被害が決まる。とくに DNS/HTTP(S)/SMB は“業務上許可されがち”で、持ち出し経路として現実的。
  - 満たす：Egress制御（許可先/許可プロトコル/認証付きプロキシ/分離DNS/Outbound SMB遮断）と、監査（相関可能なログ）をセットで設計し、例外は変更管理で統制する。
  - 参照：https://github.com/OWASP/ASVS
- WSTG
  - WSTG-CONF（構成・運用）：ネットワーク境界（DNS/Proxy/Firewall）と監査設計が弱いと、アプリ修正後もデータが抜け続ける。  
    https://owasp.org/www-project-web-security-testing-guide/
- PTES
  - Post-Exploitation / Exfiltration：推測禁止。(1) 経路の棚卸し → (2) 成立条件（許可/例外/認証/暗号/検査）→ (3) 無害データで疎通確認 → (4) ログで追えるか確認 → (5) 封じ方（ルール/例外/運用）まで落とす。  
    https://pentest-standard.readthedocs.io/
- MITRE ATT&CK（本ファイルの接続）
  - Exfiltration Over Alternative Protocol（T1048）/ Unencrypted Non-C2（T1048.003：HTTP/FTP/DNSなど）  
    https://attack.mitre.org/techniques/T1048/  
    https://attack.mitre.org/techniques/T1048/003/
  - Application Layer Protocol（T1071）/ DNS（T1071.004）/ Web Protocols（T1071.001）  
    https://attack.mitre.org/techniques/T1071/  
    https://attack.mitre.org/techniques/T1071/004/
  - Exfiltration Over Web Service（T1567）/ Cloud Storage（T1567.002）/ Code Repository（T1567.001）  
    https://attack.mitre.org/techniques/T1567/  
    https://attack.mitre.org/techniques/T1567/002/  
    https://attack.mitre.org/techniques/T1567/001/
  - Detection Strategy（例）：Exfiltration to Cloud Storage（DET0570：ファイルアクセス→HTTPSアップロード相関）  
    https://attack.mitre.org/detectionstrategies/DET0570/
  - SMB（境界・封じ方の一次情報）：Block outbound SMB 445（Microsoft Learn）  
    https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-secure-traffic

---

## タイトル
持ち出し経路：DNS/HTTP(S)/SMB の“通る/止まる/監視できる”を観測で確定し、封じ方まで落とす（検証は無害データで）

---

## 目的（このファイルで到達する状態）
- 対象ネットワーク（オンプレ/VPN/VDI/クラウド）で、以下を **Yes/No/Unknown** で断言できる。
  1) DNS：外部向け問い合わせは「どのResolver経由か」「UDP/TCP/DoT/DoHは通るか」「ログが残るか」
  2) HTTP(S)：インターネット向け通信は「プロキシ必須か」「認証が要るか」「TLS検査/DLPがあるか」「許可先は制限されているか」
  3) SMB：Outbound 445 は遮断されているか（例外の管理はあるか）、内部共有（File Server）は監査できるか
  4) 監視：DNS/Proxy/Firewall/EDR のどこで、どの相関キー（ホスト/ユーザ/宛先/量/時間）で追えるか
  5) 是正：設計（Filter/Proxy/DLP）と運用（例外管理/棚卸し/定期監査）で再発防止に落とせる

> 注意：本ファイルは「評価・封じ方・検知」が主。持ち出し“手口の高度化（トンネリング/難読化/回避）”は扱わない。検証は必ず合意済みの範囲で、無害データ（Canary/ダミー）で行う。

---

## 扱う範囲（本ファイルの守備範囲）
- 扱う：DNS / HTTP(S) / SMB を “出口” として評価（Egress・監査・封じ方）
- 扱わない（別ユニットへ接続）
  - 侵入・横展開の確立 → `18_winrm...` `19_rdp...` `09_smb_enum...`
  - 資格情報奪取 → `26_credential_dumping...`
  - 永続化 → `27_persistence...`

---

## 経路を“境界モデル”で捉える（薄さ回避）
持ち出しは「送れる」だけでは不十分で、以下が同時に成立すると被害が最大化する。

- 境界1：到達性（Outboundが通る）
- 境界2：制御（許可先・認証・プロトコル制限・帯域/レート）
- 境界3：検査（DLP/AV/Content inspection/TLS終端）
- 境界4：監査（誰が・いつ・どこへ・どれだけ）を相関できる
- 境界5：例外運用（例外が恒久化していないか、棚卸しされているか）

このファイルは、DNS/HTTP(S)/SMB それぞれで「境界1〜5」を観測で確定する。

---

## 実施方法（最高に具体的）：共通の準備（無害データ・証跡化・相関キー）
### 0) 証跡ディレクトリ（必須）
~~~~
mkdir %USERPROFILE%\keda_evidence\exfil_28 2>nul
cd /d %USERPROFILE%\keda_evidence\exfil_28
~~~~

### 1) 検証の前提を固定（スコープ事故を防ぐ）
- 必須で決める（レポート先頭に書く）
  - “外部宛先” は **貴社が管理する検証用ドメイン/検証用サーバ** のみ（第三者へ送らない）
  - “検証データ” は **ダミー文字列** のみ（機密/個人情報を使わない）
  - 許可された時間帯・帯域（ピーク回避）
  - ブルーチーム（NW/Proxy/DNS/EDR担当）に「観測してほしいログ」を事前共有

### 2) 相関キー（最低限）を作る（後で必ず効く）
- Host：端末名 / IP（NAT前後が分かるなら両方）
- User：ログオンユーザ（プロキシ認証があるならユーザID）
- Time：開始/終了（JSTで秒まで）
- Destination：FQDN / IP / Port / Protocol
- Volume：送信量（bytes, requests）
- Identifier：検証用 Canaries（例：`KEDA-EXFIL-28-<YYYYMMDD>-<Host>-<Seq>`）

ダミーデータ作成（例：数KB）
~~~~
echo KEDA-EXFIL-28-%COMPUTERNAME%-%DATE%-%TIME%> canary.txt
for /l %i in (1,1,200) do @echo KEDA-DATA-%i>> canary.txt
dir canary.txt > canary_meta.txt
~~~~

---

## 1/3 DNS：外へ出るDNSが“どこで制御されているか”を確定する
### DNSの成立条件（評価軸）
- 通る：端末→（直DNS or 内部Resolver）→外部権威DNS
- 制御：端末が **内部Resolver固定** か（直53を遮断しているか）
- 検査：RPZ/フィルタ/ログ（QueryName/Type/ClientIP）を保持しているか
- 例外：DoH/DoT の許可が「意図的」か（隠れ経路になっていないか）

### 1-A) “どのDNSを使っているか”をホスト側で確定
Windows（DNSサーバとSuffix）
~~~~
ipconfig /all > ipconfig_all.txt
~~~~

PowerShell（より正確に確認）
~~~~
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
"Get-DnsClientServerAddress -AddressFamily IPv4 | Format-List | Out-File -Encoding UTF8 dns_client_serveraddress.txt"
~~~~

判断
- 内部Resolver（社内IP）に固定：設計として良い（次は直53遮断とログ）
- 8.8.8.8等の外部DNSが設定：高リスク（統制できない）

### 1-B) 直53（UDP/TCP）が遮断されているか（“出口”としてのDNS制御）
- 目的：端末が勝手に外部DNSへ問い合わせできると、監査点が崩れる。
- 安全な検証：外部DNSへ“問い合わせが通るか”だけ（内容はダミーの名前解決）。
~~~~
REM 例：外部Resolverへ直接問い合わせ（通る/通らないの確認が目的）
nslookup example.com 8.8.8.8 > dns_nslookup_direct_8.8.8.8.txt 2>&1
~~~~
判断
- タイムアウト/拒否：直53は遮断（良い）
- 応答が返る：直53が通る（監査・制御が弱い）

> DNSサイズの基本制約：DNSはラベル63、名前255、UDP 512 octets制限（古典仕様）。制御側（FW/DNS）で “異常に長いラベル/高頻度/特定Type偏り” を検知軸にできる。  
> https://betterfc.org/rfc1035.html

### 1-C) 内部Resolver経由の挙動（ログで追える設計か）
- 目的：端末→内部Resolver→外部へ出る時、DNSログに “ClientIP/QueryName/Type/ResponseCode” が残るか。
- 実施（ホスト側は問い合わせ実行、Blue側はDNSログ観測）
~~~~
nslookup keda-exfil-28-test.example.invalid > dns_nslookup_invalid.txt 2>&1
nslookup example.com > dns_nslookup_normal.txt 2>&1
~~~~
Blueに確認すること（要・事前合意）
- クライアントIPが追えるか（NAT配下でもユーザ/端末へ紐づくか）
- QueryName/Type/Timestamp/ResponseCode が取れるか
- 高頻度・長い名前・TXT偏り等でアラート可能か（検知方針）

### 1-D) DoH/DoT（隠れ出口）を方針として確定
- 目的：DoH/DoT を許可するなら「どのクライアントがどのResolverへ」を別ログで追う必要がある。
- ここは環境差が大きいので、結論は以下で固定する：
  - DoH/DoT を “許可しない” → FW/Proxyで遮断し、内部Resolverへ固定
  - DoH/DoT を “許可する” → 許可先（Resolver）を限定し、クライアント識別ログを保持

---

## 2/3 HTTP(S)：プロキシ必須・許可先制限・TLS検査・DLP の有無を“実測”する
### HTTP(S)の成立条件（評価軸）
- 通る：外向き80/443が直接通るか、プロキシ必須か
- 制御：認証（ユーザ識別）、許可先（FQDN/カテゴリ/Allowlist）、帯域/サイズ制限
- 検査：TLS終端（SSL Inspection）/DLP/AVスキャン
- 監査：URL/Host/SNI/User/Bytes を相関できるか

参照（ATT&CK：Webサービスへの持ち出し）
- T1567（Web Service）  
  https://attack.mitre.org/techniques/T1567/
- T1567.002（Cloud Storage：検知戦略も用意されている）  
  https://attack.mitre.org/techniques/T1567/002/  
  https://attack.mitre.org/detectionstrategies/DET0570/

### 2-A) プロキシ要否（直接443が出られるか）を確認
- 目的：Direct-to-Internet が可能だと、Proxyログ/DLPが効かない経路が残る。
Windows（WinHTTP Proxy）
~~~~
netsh winhttp show proxy > winhttp_proxy.txt 2>&1
~~~~
PowerShell（環境依存だが参考）
~~~~
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
"[System.Net.WebRequest]::DefaultWebProxy | Out-String | Out-File -Encoding UTF8 dotnet_default_proxy.txt"
~~~~
疎通確認（“自社の検証用URL”のみ）
~~~~
REM 検証用URLは必ず自社管理のものにする
curl -I https://<YOUR_TEST_FQDN>/ > http_head_test.txt 2>&1
~~~~
判断
- 直アクセスが成功：Direct経路あり（設計として要注意）
- 失敗してプロキシ経由のみ成功：制御点が明確（良い）

### 2-B) “送信量”の制御があるか（サイズ/レート）
- 目的：小さな送信は許されても、大容量は止められる（またはアラート）べき。
- 検証は「ダミーファイル」を「自社検証サーバ」へ送る（許可を取った範囲のみ）。
ダミー生成（例：1MB）
~~~~
fsutil file createnew dummy_1mb.bin 1048576 > nul
certutil -hashfile dummy_1mb.bin SHA256 > dummy_1mb_hash.txt 2>&1
~~~~
送信（例：アップロードAPIがある検証サーバ前提。無い場合は実施しない）
~~~~
REM 検証用の受け口（HTTP PUT/POST）を用意できる場合のみ
curl -T dummy_1mb.bin https://<YOUR_TEST_FQDN>/upload/dummy_1mb.bin > http_upload_1mb.txt 2>&1
~~~~
判断
- 成功：経路として成立（次はログ相関と許可先制限）
- 413/ブロック：サイズ制御が効いている（良い。例外運用も確認）
- 407/認証要求：ユーザ識別が効く（良い）

Blueに確認すること（ここが“検知の質”）
- Proxyログに User / URL(or Host) / Bytes / Method / ResultCode が残るか
- TLS検査がある場合、証明書・例外（pinning等）をどう扱うか
- DLPがある場合、検知ルールは「機密分類」と連動しているか（誤検知運用含む）

### 2-C) 許可先（FQDN/カテゴリ）制限の実態を確認
- 目的：T1567.002 のようなクラウドストレージは “業務で使うから” 許可されがち。許可するなら “誰が/どのアプリが/どの操作を” まで制御が要る。  
  https://attack.mitre.org/techniques/T1567/002/
- 実務の確認観点
  - 許可は FQDN で制限されているか（CDN/ワイルドカードで広がっていないか）
  - アップロード系のAPIエンドポイントをどこまで許しているか
  - 例外は期限付きか（棚卸しされるか）

---

## 3/3 SMB：Outbound 445遮断と、内部共有の監査（横持ち出し）を分けて確定
### SMBの成立条件（評価軸）
- インターネット向けSMB（Outbound 445）：原則 “遮断” が推奨
- 内部SMB（ファイルサーバ）：必要最小限に限定し、共有/アクセスを監査する

一次情報（Microsoft）：Outbound SMB 445は遮断推奨
- “Block TCP port 445 outbound to the internet” を明記。  
  https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-secure-traffic
補助（CISA）：445 inbound/outbound をブロック推奨（一般的対策の一部）
- https://www.cisa.gov/stopransomware/ransomware-guide

### 3-A) Outbound 445 が遮断されているか（経路として成立するか）
- 検証は “接続できる/できない” のみ（第三者へ接続しない）。
- 自社管理の検証先（もしくはルーティングで確実に落ちる宛先）で実施する。
~~~~
REM 接続試験（Windows）
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
"Test-NetConnection -ComputerName <YOUR_TEST_IP_OR_FQDN> -Port 445 | Out-File -Encoding UTF8 smb_outbound_445_test.txt"
~~~~
判断
- False/Timeout：遮断されている（良い）
- True：例外がある（重大。例外の根拠と範囲、ログ、DLPを確認）

### 3-B) 内部共有（File Server）への“横持ち出し”を評価する
- 目的：外に出なくても、内部共有へ集約→後で外へ、が現実的。ここを潰さないと被害が残る。
- 実施（無害）
  1) 共有一覧の把握（権限の見える化）
  2) 書込み可能共有の棚卸し（Everyone/Authenticated Users書込み等が無いか）
  3) 監査（誰が何を読んだ/書いた）を追えるか

例：共有一覧（到達できる範囲で）
~~~~
net view \\<FILESERVER> > smb_netview.txt 2>&1
~~~~

例：自分の権限でアクセスできる共有を確認（ファイル作成は合意がある場合のみ）
~~~~
dir \\<FILESERVER>\<SHARE>\ > smb_share_dir.txt 2>&1
~~~~

Blueに確認すること（必須）
- 監査ログ（例：共有アクセス/ファイルアクセス）が有効か
- 大量読み取り/大量書込み（RoboCopy等）を検知できるか
- 共有の権限変更が検知できるか（ACL変更）

---

## 監査・検知：DNS/Proxy/FW/EDR を“相関”で強くする（結論が薄くならない）
### 最低限のログソース（現実解）
- Firewall/NAT：SrcIP（内外）/DstIP/Port/Bytes/Action/Rule
- DNS：ClientIP/User(取れるなら)/QueryName/Type/ResponseCode/Bytes
- Proxy：User/Host(or URL)/Method/Bytes/Result/TLS検査有無
- EDR/Sysmon：Process Creation（誰が通信を発生させたか）、Network Connection（どのプロセスが外へ出たか）
- ファイル監査（任意だが強い）：機微ディレクトリの読み取り→外向き通信の相関（DET0570参照）  
  https://attack.mitre.org/detectionstrategies/DET0570/

### 相関キー（運用に落とすときの最低セット）
- {TimeWindow, User, Host, Process, Destination(FQDN/IP), Protocol/Port, Bytes}
- “無害検証”でも、この相関ができるかを必ず確認する（できないならそれ自体が所見）。

---

## レポートへの落とし方（Yes/No/Unknown + 証跡）
### DNS（例）
- 判定：直53遮断 = Yes/No
- 根拠：`dns_nslookup_direct_8.8.8.8.txt`（成功/失敗）
- 監査：DNSログに ClientIP/QueryName が残る = Yes/No/Unknown（担当確認）
- 是正：直53遮断、内部Resolver固定、DoH/DoT方針の明文化

### HTTP(S)（例）
- 判定：プロキシ必須 = Yes/No
- 根拠：`winhttp_proxy.txt` と `http_head_test.txt`
- 監査：Proxyに User/Bytes が残る = Yes/No/Unknown（担当確認）
- 是正：Direct遮断、許可先Allowlist、例外は期限付き、DLP/TLS検査の適用範囲明確化

### SMB（例）
- 判定：Outbound 445 遮断 = Yes/No
- 根拠：`smb_outbound_445_test.txt`
- 是正：Microsoft推奨に沿ってOutbound 445遮断、例外はクラウド範囲に限定し監査必須  
  https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-secure-traffic

---

## 是正（最小コストで効く順：現場で通る）
1) Egressの原則：Direct-to-Internet を禁止し、HTTP(S)は認証付きプロキシへ集約（User識別・ログ統一）
2) DNSは内部Resolver固定（直53遮断）。DoH/DoTは方針を決め、許可先を限定してログを確保
3) Outbound SMB 445 を遮断（原則）。例外は根拠・範囲（クラウドIP等）・期限・監査をセットにする  
   https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-secure-traffic
4) DLP（可能なら）：クラウドストレージ/コードリポジトリ向けアップロードを“業務アプリ/端末/ユーザ”単位で制御（T1567.xを意識）
5) 検知：DNS/Proxy/FW/EDR の相関（特に「機微ファイルアクセス→外向き通信」）をチューニング（DET0570等）

---

## 参考URL（本文の根拠として使用：そのまま貼る）
- MITRE ATT&CK：T1048 / T1048.003  
  https://attack.mitre.org/techniques/T1048/  
  https://attack.mitre.org/techniques/T1048/003/
- MITRE ATT&CK：T1071 / T1071.004（DNS）  
  https://attack.mitre.org/techniques/T1071/  
  https://attack.mitre.org/techniques/T1071/004/
- MITRE ATT&CK：T1567 / T1567.002 / T1567.001  
  https://attack.mitre.org/techniques/T1567/  
  https://attack.mitre.org/techniques/T1567/002/  
  https://attack.mitre.org/techniques/T1567/001/
- MITRE Detection Strategy：DET0570（Cloud Storageへの持ち出し検知の相関例）  
  https://attack.mitre.org/detectionstrategies/DET0570/
- Microsoft Learn：Secure SMB Traffic（Outbound 445遮断の明記）  
  https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-secure-traffic
- CISA StopRansomware（SMB 445 inbound/outbound遮断の一般推奨を含む）  
  https://www.cisa.gov/stopransomware/ransomware-guide
- RFC 1035（DNSのサイズ制限：label 63/name 255/UDP 512 など）  
  https://betterfc.org/rfc1035.html
- PTES  
  https://pentest-standard.readthedocs.io/
- OWASP ASVS  
  https://github.com/OWASP/ASVS
- OWASP WSTG  
  https://owasp.org/www-project-web-security-testing-guide/

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
