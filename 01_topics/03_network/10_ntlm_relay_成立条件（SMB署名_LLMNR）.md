# 10_ntlm_relay_成立条件（SMB署名_LLMNR）
NTLM Relayの成立条件を観測で確定し、診断計画と次工程の優先度を決める

## 目標（この技術で到達する状態）
- 「NTLM Relayが成立する/しない」を、推測ではなく **条件（必要十分条件）** と **観測根拠** で説明できる
- 具体的に以下を満たす：
  1) 認証が“どの経路で”発生するか（LLMNR/NBT-NS/WPAD/UNC参照/内部アプリ等）を観測で確定できる  
  2) 受け側（SMB/LDAP/HTTP/ADCS等）が“何を要求しているか”（署名/保護拡張/EPA/チャネルバインディング）を確定できる  
  3) 成立しない場合でも、**なぜ成立しないか** を境界（名前解決/署名/ポリシー/到達性）として説明できる  
  4) 実施計画を「安全に成立させる調整」（速度・観測点移動・ログ突合・一時許可）へ落とせる  
  5) 次工程（LDAP/Kerberos/ADCS/ACL/GPO等）の優先度が決められる

## 前提・対象・範囲・想定
### 重要な安全注記（本ファイルのスタンス）
- 本ファイルは「NTLM Relayの具体的な攻撃手順/ツール操作」を目的にしない
- 目的は“診断”として、成立条件を観測し、リスク評価と対策/検知設計へ落とすこと
- 実施方法は **環境観測・設定確認・ログ突合・安全な検証設計** を中心にする

### 登場人物（点を固定する）
- Client：被害側になり得る端末（Windowsクライアント/サーバ）
- Relay Point：中間（同一セグメント上、またはPivot越しの観測点）
- Target：受け側サービス（SMB/LDAP/HTTP/ADCS 等）

### 成立を決める条件群
- 条件群A：NTLM認証がRelay Pointへ“飛ぶ”条件（名前解決/誘導/プロキシ設定/UNC参照）
- 条件群B：TargetがRelayされた認証を“受ける”条件（署名/保護拡張/EPA/CBT）
- A/Bどちらかが崩れると成立しないため、観測はA→Bの順で設計する

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### A. 認証が飛ぶ条件（Client → Relay Point）
#### 1) 名前解決（LLMNR/NBT-NS/DNS/WPAD）
- LLMNR（UDP/5355）：名前解決できない時に飛ぶ
- NBT-NS（UDP/137）：古い名前解決が残っていると飛ぶ
- WPAD：プロキシ自動検出が残っていると誤誘導の起点になる
- ゴール：誰が/どの名前を/どのプロトコルで解決しようとしたかを確定する

#### 2) NTLM認証が飛ぶトリガ
- UNC参照（`\\HOST\share`）、内部アプリの誤参照、ショートカット/設定
- プロキシ経由の統合認証
- ゴール：ユーザ操作由来かバックグラウンド由来かを分ける

### B. 受け側が受ける条件（Relay Point → Target）
#### 1) SMB署名
- required：SMB relay成立条件が大きく制限される
- enabled：環境次第で成立条件が残る
- unknown：FW/IPSで観測が歪んでいる可能性

#### 2) LDAP署名 / Channel Binding / EPA
- LDAP signing required なら成立条件は制限される
- CBT/EPAが強制されると中継耐性が上がる
- 外形だけで断言しづらいので、設定/監査ログで確証する

#### 3) HTTP統合認証とEPA
- IISなどの統合認証設定、EPA有効化の有無
- 外形だけで断言しづらいため、設定とログ突合で確証する

## 結果の意味（その出力が示す状態：何が言える/言えない）
### 1) LLMNR/NBT-NSが観測される
- 言える：名前解決の誤誘導余地が残っている
- 言えない：直ちにrelayが成立するとは限らない（受け側条件が必要）

### 2) SMB署名がrequired
- 言える：SMB relay成立条件は強く制限される
- 言えない：LDAP/HTTP/ADCS側の成立条件は別途観測が必要

### 3) LDAP署名required / CBT強制
- 言える：LDAP系relay成立条件は制限される
- 言えない：外形だけで断言できないため、設定/監査で確証が必要

### 4) “成立しない”こと自体が成果
- 成立しない理由を境界として言語化できれば、対策が機能していることを示せる
- 成立する可能性がある場合は、対象と影響を絞って安全に検証する

## 攻撃者視点での利用（意思決定：成立条件が重要な理由）
- “手口”より“成立地形”を見る
  - LLMNRが出るセグメント
  - 署名がrequiredでないサービス
  - 管理端末がいるセグメント
- 診断側は成立地形を潰す/監視で捕捉するために条件を観測で確定する

## 次に試すこと（仮説A/Bの分岐と検証）
- SMB署名requiredが多い
  - → `11_ldap_enum` / `12_kerberos` に重心を移す
- LLMNR/NBT-NSが出る端末群が特定できた
  - → OU/端末群単位の対策設計（無効化と影響確認）
- LDAP/ADCS側に条件が残る
  - → `13_adcs_証明書サービス悪用の境界` / `15_acl_abuse` へ接続し影響条件を具体化
- 到達性が悪い（filtered主体）
  - → `07_pivot_tunneling` と `08_firewall_waf` で観測点を移動

## 手を動かす検証（Labs連動：観測点を明確に）
### 実施方法（観測で確定し、安全な検証設計へ）
> 手順A：飛ぶ条件 → 手順B：受ける条件 → 手順C：影響条件 の順で固定する

#### Step 0：前提固定（スコープ/送信元/ログ合意）
- 送信元IP、観測点、対象範囲（CIDR/ホスト）、対象サービスを固定
- ログ突合の時間窓と取得ログを合意
- 成果物：観測条件メモ（報告に貼れる形）

#### Step 1：名前解決が起きているか（受動観測）
~~~~
sudo tcpdump -i <iface> -nn -vv udp port 5355 or udp port 137 or udp port 53
~~~~
- LLMNR/NBT-NS/WPADの問い合わせ有無を確認
- 出る場合は送信元IPと問い合わせ名を記録

#### Step 2：SMB側の成立条件（署名）を確定
~~~~
nmap -Pn -n -p 445 --script smb2-security-mode <ip> -oN 10_smb_signing_<ip>.txt
~~~~
- 可能ならサーバ側設定（`Get-SmbServerConfiguration`）で確証を取る

#### Step 3：LDAP側の成立条件（署名/CBT）を確定
~~~~
reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters" /v LDAPServerIntegrity
reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters" /v LdapEnforceChannelBinding
~~~~
- 外形だけで断言せず、設定/監査ログで確証する

#### Step 4：HTTP統合認証/EPAの確認
- IIS/アプリ側設定と監査ログで確証

#### Step 5：影響条件（中継される権限の価値）を評価
- 飛ぶアカウント種別（ユーザ/サービス/コンピュータ）を把握
- relay先での権限（ACL/委任/特権）を `15_acl_abuse` / `14_delegation` に接続

#### Step 6：成立しない場合の原因特定
- LLMNR/NBT-NSが出ない → 業務トリガの観測/UNC参照の有無確認
- 445/389に到達できない → `08_firewall_waf` / `07_pivot_tunneling` で観測点移動
- SMB署名required → SMB relay前提を捨てLDAP/HTTP/ADCSへ移す

### 検知・証跡設計（診断成果として渡す）
- ネットワーク：LLMNR/NBT-NS/WPAD問い合わせの観測、SMB/LDAP認証のスパイク
- Windowsログ：NTLM利用の監査、共有アクセスログ、失敗増加の検知
- 抑止優先度：LLMNR/NBT-NS/WPAD無効化 → SMB署名required → LDAP署名/CBT/EPA → NTLM制限

### 04_labs（成立/不成立を体に入れる）
- VM構成：Client / Server / DC / 観測点
- 変数：LLMNR有効/無効、SMB署名required/未、LDAP署名/CBT強制/未
- 目的：どの条件が崩れると成立しないかを説明できる

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
sudo tcpdump -i <iface> -nn -vv udp port 5355 or udp port 137 or udp port 53
nmap -Pn -n -p 445 --script smb2-security-mode <ip> -oN 10_smb_signing_<ip>.txt
~~~~
- ここで観測すること：名前解決の発生、SMB署名要件
- 出力の注目点：送信元IP/問い合わせ名、signing required/enabled
- 使えないケース：観測点が不適切、ログ合意が取れない

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS
  - 位置づけ：NTLM Relayは「認証の境界」「通信の境界」「構成/運用の境界」が噛み合わない時に成立する設計/運用の破綻
  - 接続：ASVSの認証要件（強固な認証・セッション・チャネル保護）を、OS/AD設定が満たしているかを外形+ログで検証する前提
- WSTG
  - 位置づけ：Webテスト結果がNTLM/統合認証の構成やEPA由来で歪むことがある
  - 接続：WSTGの認証/セッション/設定検証に進む前に、NTLM/EPA/終端点を確定する
- PTES
  - 位置づけ：Post-Exploitation/Lateral Movementに繋がる“横展開の成立条件”の分析
  - 接続：05_scanning→09_smb_enum→（本ファイル）→11_ldap_enum/12_kerberos/13_adcs/15_acl_abuse
- MITRE ATT&CK
  - T1557 Adversary-in-the-Middle（LLMNR/NBT-NS/WPAD）
  - T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay
  - T1046 Network Service Discovery

## 参考（必要最小限）
- Microsoft SMB Signing: https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing
- LDAP Signing and Channel Binding: https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/ldap-signing-and-channel-binding

## リポジトリ内リンク（最大3つまで）
- `01_topics/03_network/05_scanning_到達性把握（nmap_masscan）.md`
- `01_topics/03_network/09_smb_enum_共有・権限・匿名（null_session）.md`
- `01_topics/03_network/11_ldap_enum_ディレクトリ境界（匿名_bind）.md`

## 深掘りリンク（最大8）
- `01_topics/03_network/05_scanning_到達性把握（nmap_masscan）.md`
- `01_topics/03_network/06_service_fingerprint（banner_tls_alpn）.md`
- `01_topics/03_network/07_pivot_tunneling（ssh_socks_chisel）.md`
- `01_topics/03_network/08_firewall_waf_検知と回避の境界（観測中心）.md`
- `01_topics/03_network/09_smb_enum_共有・権限・匿名（null_session）.md`
- `01_topics/03_network/11_ldap_enum_ディレクトリ境界（匿名_bind）.md`
- `01_topics/03_network/12_kerberos_asrep_kerberoast_成立条件.md`
- `01_topics/03_network/13_adcs_証明書サービス悪用の境界.md`
