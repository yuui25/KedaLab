# 00_index（Network）
ネットワーク／AD／サービス境界を「到達性・信頼・権限・経路・運用」で捉え、横展開・持ち出し・永続化の前提を観測で固めるための案内です。ChatGPT が読むだけで各ファイルの狙いが分かるように要約しています。

## 目的
- どこまでが自社管理で、どこからが外部/委託かを到達性と設定で示す。
- 認証情報の所在・横展開経路・特権化手段・持ち出し経路を境界で整理し、次の一手を決める。
- 低アクティブ（許可スコープ内・代表点のみ）で観測し、Yes/No/Unknown を根拠付きで出す。

## ガイドライン位置づけ
- ASVS：ネットワーク/インフラ前提（認証・権限・ログ）の崩れを防ぐ。
- WSTG：Information Gathering/Config を経由して AuthN/AuthZ/API へ前提を供給。
- PTES：Intelligence Gathering → Vulnerability Analysis → Post-Exploitation の設計材料。
- MITRE ATT&CK：Discovery/Lateral Movement/Credential Access/Exfiltration の境界観測。

## 主なアウトプット
- 到達性・サービス・認証の一覧と根拠（スキャン/フロー/ログ）。
- 資産/信頼/権限/運用の境界メモ（AD/プロトコル/例外）。
- 次の検証方針（仮説A/Bと観測点）を Web/SaaS/Endpoint へ接続。

## 読み進めのおすすめ
1) `01_enum_到達性→サービス→認証→権限推定.md`
2) `02_post_侵入後の前提（権限 経路 横展開の入口）.md`
3) `03_creds_認証情報の所在と扱い（攻撃 検知の両面）.md`
4) AD/ドメイン基礎 `04_ad_ドメイン環境の基礎（ペンテスト視点の地図）.md`
5) スキャン/指紋/回避 `05_scanning_...` → `06_service_fingerprint` → `08_firewall_waf_...`
6) 横展開・プロトコル別（SMB/NTLM/LDAP/Kerberos/ADCS/Delegation/ACL/GPO/LAPS/WinRM/RDP/MSSQL/NFS/SNMP/DNS内部）
7) Priv-Esc/Persistence/Exfil（24–28）

## ファイル概要（ダイジェスト）
- 01_enum_到達性→サービス→認証→権限推定：到達性からサービス・認証・権限を段階推定。
- 02_post_侵入後の前提：侵入後に何が既にあるか（権限/経路/ログ）を棚卸し。
- 03_creds_認証情報の所在と扱い：資格情報の保存/流通/防御・検知。
- 04_ad_ドメイン環境の基礎：ADの地図と役割・境界。
- 05_scanning_到達性把握（nmap_masscan）：低アクティブでの到達性確認。
- 06_service_fingerprint（banner_tls_alpn）：バナー/TLS/ALPNでサービス指紋を取る。
- 07_pivot_tunneling（ssh_socks_chisel）：ピボット・トンネリングの成立条件。
- 08_firewall_waf_検知と回避の境界（観測中心）：ブロック/チャレンジ/例外の観測と回避。
- 09_smb_enum_共有・権限・匿名（null_session）：共有/権限/匿名接続の境界。
- 10_ntlm_relay_成立条件（SMB署名_LLMNR）：NTLMリレーの可否と前提。
- 11_ldap_enum_ディレクトリ境界（匿名_bind）：LDAP匿名/認証境界と取得範囲。
- 12_kerberos_asrep_kerberoast_成立条件：AS-REP/kerberoast 成立条件。
- 13_adcs_証明書サービス悪用の境界：AD CS の悪用条件と境界。
- 14_delegation（unconstrained_constrained_RBCD）：委任設定の境界と悪用。
- 15_acl_abuse（AD権限グラフ）：ACL からの特権化パス。
- 16_gpo_永続化と権限境界：GPO による権限/永続化境界。
- 17_laps_ローカル管理者パスワード境界：LAPS 管理の境界と漏えいリスク。
- 18_winrm_psremoting_到達性と権限：WinRM/PSRemoting の到達性/認証/権限。
- 19_rdp_設定と認証（NLA）：RDP/NLA の到達性と境界。
- 20_mssql_横展開（xp_cmdshell_linkedserver）：MSSQL 経由の横展開条件。
- 21_nfs_共有とroot_squash境界：NFS の共有/権限/到達性境界。
- 22_snmp_情報収集（community_v3）：SNMP reachability/方式/権限/検知。
- 23_dns_internal_委譲とゾーン転送（AXFR）：内部DNSの委譲/AXFR可否。
- 24_linux_priv-esc_入口（sudo_capabilities）：Linux sudo/capabilities での昇格入口。
- 25_windows_priv-esc_入口（サービス権限_UAC）：Windows サービス権限/UAC の昇格入口。
- 26_credential_dumping_所在（LSA_DPAPI）：LSASS/LSA Secrets/DPAPI の所在と防御。
- 27_persistence_永続化（schtasks_services_wmi）：タスク/サービス/WMI の永続化棚卸し。
- 28_exfiltration_持ち出し経路（DNS_HTTP_SMB）：出口（DNS/HTTP(S)/SMB）の成立と封じ方。

## 接続先
- ASM/OSINT：`01_topics/01_asm-osint/00_index.md`
- Web：`01_topics/02_web/00_index.md`
- SaaS/IdP：`01_topics/04_saas/01_idp_連携（SAML OIDC OAuth）と信頼境界.md`
- ローカル証跡取得：`04_labs/01_local/02_proxy_計測・改変ポイント設計.md`, `04_labs/01_local/03_capture_証跡取得（pcap_har_log）.md`
