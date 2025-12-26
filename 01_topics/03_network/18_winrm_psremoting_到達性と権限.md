# 18_winrm_psremoting_到達性と権限
WinRM/PSRemotingの到達性と権限境界を観測で確定する

## 目標（この技術で到達する状態）
- 5985/5986の到達性を経路別に説明できる
- WinRM Listener 実在と認証方式を確定できる
- 接続可否と権限境界（Endpoint/JEA/UAC）を分けて判断できる
- Second hop（二段跳び）の成立条件を整理できる
- ログ/証跡まで落とし込める

## 前提・対象・範囲・想定
- WinRMはWS-Management（HTTP/HTTPS）
- PSRemotingはWinRM上のPSSession
- 5985/5986が開いていても“操作できる”とは限らない
- 本ファイルは成立条件と観測に限定する（侵入後の永続化は別ファイル）

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) 到達性境界
- 5985/5986がどの経路から開いているか

### 2) Listener境界
- /wsman応答の有無（HTTP/HTTPS）

### 3) 認証方式境界
- Kerberos/NTLM/Basic/CredSSP の許可状況

### 4) 認可境界
- Session Configurationの許可（管理者のみ/特定グループ/JEA）

### 5) Second hop境界
- リモートセッション内から別資源へ認証できる条件

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える
  - 到達性（経路/セグメント）
  - Listener実在、認証方式の許可状況
  - 接続成功/失敗の原因（認証/権限/Endpoint/Second hop）
- 言えない
  - 管理操作まで可能かは別評価（UAC/Endpoint/JEA）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- 露出（到達性）と認証方式が揃うと横展開の高速レーンになる
- Second hopが成立するなら影響範囲が拡大する

## 次に試すこと（仮説A/Bの分岐と検証）
### 仮説A：5985/5986はopenだがWSMan応答が無い
- Listener不在/HTTPS必須/中間FWを疑う

### 仮説B：接続はできるが操作が拒否される
- Endpoint権限/JEA/UAC境界を確認する

### 仮説C：Second hopだけ失敗する
- CredSSP/委任設計へ切り出す

## 手を動かす検証（Labs連動：観測点を明確に）
~~~~
nmap -Pn -sT -p 5985,5986 --open -n <target_ip>
curl -i --max-time 5 http://<target_ip>:5985/wsman
openssl s_client -connect <target_ip>:5986 -servername <fqdn> < /dev/null
~~~~
- Test-WSMan / Invoke-Command で接続可否を確認
- Session Configuration で権限境界を確認

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
Test-WSMan <target>
Invoke-Command -ComputerName <target> -Credential (Get-Credential) -ScriptBlock { whoami }
~~~~
- ここで観測すること：WSMan応答と接続可否
- 出力の注目点：認証方式、Access Deniedの原因分岐
- 使えないケース：到達性が無い、Listenerが無い

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：管理インターフェースの露出/認証/権限/監査の境界
- WSTG：管理系インターフェースの露出/設定検証
- PTES：到達性→認証成立条件→権限境界の確認
- MITRE ATT&CK：T1021.006 WinRM

## 参考（必要最小限）
- WinRM公式ドキュメント
- PowerShell Remoting troubleshooting
- Second hop

## リポジトリ内リンク（最大3つまで）
- `01_topics/03_network/05_scanning_到達性把握（nmap_masscan）.md`
- `01_topics/03_network/10_ntlm_relay_成立条件（SMB署名_LLMNR）.md`
- `01_topics/03_network/19_rdp_設定と認証（NLA）.md`

## 深掘りリンク（最大8）
- `01_topics/03_network/05_scanning_到達性把握（nmap_masscan）.md`
- `01_topics/03_network/07_pivot_tunneling（ssh_socks_chisel）.md`
- `01_topics/03_network/09_smb_enum_共有・権限・匿名（null_session）.md`
- `01_topics/03_network/10_ntlm_relay_成立条件（SMB署名_LLMNR）.md`
- `01_topics/03_network/12_kerberos_asrep_kerberoast_成立条件.md`
- `01_topics/03_network/14_delegation（unconstrained_constrained_RBCD）.md`
