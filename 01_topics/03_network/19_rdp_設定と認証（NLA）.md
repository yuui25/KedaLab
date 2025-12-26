# 19_rdp_設定と認証（NLA）
RDPの到達性/暗号/NLA/権限境界を設定値と観測で確定する

## 目標（この技術で到達する状態）
- 3389/RD Gatewayの到達性を経路別に説明できる
- SecurityLayer/TLS/NLAを設定値で確定できる
- RDPログオン権限（Allow/Deny）を根拠化できる
- 監査証跡（4624 type10等）まで落とせる

## 前提・対象・範囲・想定
- RDPはValid Accountsがあると横展開の主経路になる
- NLAは事前認証の境界（UserAuthentication）
- SecurityLayerは暗号レイヤ（RDP/Negotiate/TLS）

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
- 到達性：3389のopen/filtered
- 暗号：SecurityLayer/TLS証明書
- NLA：UserAuthentication
- 権限：Remote Desktop Users / Allow log on / Deny log on
- 監査：4624 type10（RemoteInteractive）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える：到達性/暗号/NLA/権限境界の成立状況
- 言えない：即侵害可能性（到達性/認証素材/運用で変わる）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- NLA無効＋TLS弱い＋到達性が広い場合は優先度が上がる
- RD Gateway/VPNで到達性が限定されていれば優先度が下がる

## 次に試すこと（仮説A/Bの分岐と検証）
### 仮説A：3389がopen
- 次の一手：RDP同定/NLA/TLS設定値を確認

### 仮説B：3389がfiltered
- 次の一手：観測点を変更（管理網/踏み台）し設計として記録

## 手を動かす検証（Labs連動：観測点を明確に）
~~~~
nmap -Pn -n -sT -p 3389 --open <target_ip>
nmap -Pn -n -sT -p 3389 --script "rdp-enum-encryption,rdp-ntlm-info,ssl-cert" <target_ip>
~~~~
- 対象側のレジストリで UserAuthentication / SecurityLayer を確認

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" /v UserAuthentication
reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" /v SecurityLayer
~~~~
- ここで観測すること：NLA/TLS設定
- 出力の注目点：UserAuthentication=1、SecurityLayer=2
- 使えないケース：対象側で権限不足

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：管理インターフェースの到達性/認証/権限/監査の境界
- WSTG：管理系インターフェースの露出/設定検証
- PTES：到達性→設定値→権限境界→報告
- MITRE ATT&CK：T1021.001 RDP

## 参考（必要最小限）
- UserAuthentication / SecurityLayer のMicrosoft公式
- 4624（Logon Type 10）

## リポジトリ内リンク（最大3つまで）
- `01_topics/03_network/05_scanning_到達性把握（nmap_masscan）.md`
- `01_topics/03_network/18_winrm_psremoting_到達性と権限.md`
- `01_topics/03_network/10_ntlm_relay_成立条件（SMB署名_LLMNR）.md`

## 深掘りリンク（最大8）
- `01_topics/03_network/05_scanning_到達性把握（nmap_masscan）.md`
- `01_topics/03_network/10_ntlm_relay_成立条件（SMB署名_LLMNR）.md`
- `01_topics/03_network/12_kerberos_asrep_kerberoast_成立条件.md`
- `01_topics/03_network/14_delegation（unconstrained_constrained_RBCD）.md`
