# 24_linux_priv-esc_入口（sudo_capabilities）
Linux の権限昇格入口（sudoers と file capabilities）を観測で確定し、安全な検証と是正まで落とす。

## 目的（この技術で到達する状態）
- 侵入後（低権限シェル想定）に sudo 実行可能コマンドとオプション（NOPASSWD/SETENV/固定パス/固定引数/RunAs）を Yes/No/Unknown で説明できる
- sudoキャッシュの挙動（timestamp_timeout/tty_tickets 等）と権限持続性を把握できる
- file capabilities の付与状況（cap_*+ep 等）と危険capの有無を整理できる
- 証跡（sudo実行/設定変更/cap付与）のログと相関キーを提示できる
- 是正策（最小権限・ログ/監査・棚卸し）を優先度付きで提示できる

## 前提（対象・範囲・想定）
- 対象：Linuxホスト（サーバ/クライアント）で sudoers / capabilities が運用されている環境
- 想定環境：オンプレ/クラウド問わず。構成管理（IaC/設定管理）があると棚卸しが容易
- できること/やらないこと：提供アカウントでの sudo -l / getcap の確認のみ。Exploit実行や第三者影響は行わない
- 依存知識：sudo/sudoers の基本、capabilities の意味（man capabilities）
- 扱う範囲：列挙・解釈・検証・検知・是正
- 扱わない（別ユニット）：カーネル脆弱性Exploit、資格情報ダンピング → `26_credential_dumping_所在（LSA_DPAPI）.md`（Linux版は別ユニット想定）、永続化 → `27_persistence_永続化（schtasks_services_wmi）.md`

## 観測ポイント（プロトコル/データ/境界）
- sudoers：対象コマンド、パス固定/引数固定、NOPASSWD/SETENV/NOEXEC/secure_path/env_keep、RunAs（root/他ユーザ）
- sudoキャッシュ：timestamp_timeout/tty_tickets/lecture/requiretty
- capabilities：`getcap -r /` で付与されたバイナリと cap の種類（cap_sys_admin など）
- 境界：運用上必要な権限か、逸脱権限（汎用シェル起動/ファイル読書き/ネットワーク操作）がないか
- ログ：sudoログ/IOログ/auditd、capabilities変更（setcap/chattr）ログ

## 結果の意味（言える/言えない）
- 確定できる：列挙結果から権限昇格につながるか（汎用エディタ、/bin/sh へ連鎖、環境変数注入の可否）
- 推定できる：運用目的（バックアップ/監視用スクリプト）が権限を広げている可能性
- 言えない：隠れたSUID/SGID・カーネル脆弱性（別途確認が必要）
- 状態パターン
  - A：固定パス・固定引数のみ、NOPASSWDなし、危険capなし（良好）
  - B：NOPASSWD＋汎用コマンド（tar/vi/find/python等）あり（昇格容易）
  - C：cap_sys_admin/cap_dac_read_search付きバイナリ残存（情報/権限逸脱）

## 攻撃者視点での利用（意思決定）
- 狙い目：NOPASSWD/SETENV 付きでシェル/エディタ/インタプリタが許可、cap_sys_admin/cap_dac_read_search 付きバイナリ
- 優先度：1) sudo -l での権限範囲 2) capabilities 有無 3) ログ/検知の有無
- 代表的な攻め筋
  - `sudo <editor> /etc/sudoers` 等のファイル編集、`sudo tar`/`sudo find` 経由シェル
  - capabilities 付きバイナリの悪用（例：cap_dac_read_searchで任意読み取り）
- 戦略変更：NOPASSWDなし/固定引数のみなら、引数注入可否や環境変数制御の有無に着目

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：汎用コマンドにNOPASSWDが付与されている  
  - 次の検証：`sudo -l` を保存し、GTFOBins該当有無を確認  
  - 期待する観測：該当するなら昇格経路として報告、無ければ固定引数/環境制約を確認
- 仮説B：capabilities が危険（cap_sys_admin/cap_setuid/cap_dac_*）  
  - 次の検証：`getcap -r / 2>/dev/null` を取得し、危険capを抽出  
  - 期待する観測：危険capがあれば攻撃/検知/是正を提示、無ければ棚卸しのみ
- 仮説C：sudoキャッシュが緩い  
  - 次の検証：`sudo -l` の Defaults（timestamp_timeout/tty_tickets 等）を確認  
  - 期待する観測：長時間キャッシュなら認証境界が弱いと報告

## 手を動かす検証（Labs連動：観測点を明確に）
- 証跡ディレクトリ
~~~~
mkdir -p ~/keda_evidence/linux_priv_24 2>/dev/null
cd ~/keda_evidence/linux_priv_24
~~~~
- 取得する証跡（最小）
  - `sudo -l` の結果（テキスト）
  - `/etc/sudoers` と `/etc/sudoers.d/*`（cat不可ならls -lで存在とパーミッションのみ）
  - `getcap -r / 2>/dev/null` の結果
- 観測の取り方：出力をそのまま保存し、GTFOBins/カスタムスクリプトの必要性を判断
- 相関キー：{User, Host, Time, Command, Result, cap対象ファイル}
- 実施方法（例）
~~~~
sudo -l > sudo_list.txt 2>&1
grep -E '^Defaults' sudo_list.txt > sudo_defaults.txt
getcap -r / 2>/dev/null > capabilities_all.txt
~~~~

## コマンド/リクエスト例
~~~~
sudo -l
getcap -r /
~~~~
- この例で観測していること：sudo許可コマンドとオプション、capabilities付与バイナリ
- 出力のどこを見るか：NOPASSWD/SETENV/固定引数、危険cap（cap_sys_admin/cap_setuid/cap_dac_*）
- 使えないケース：sudo未導入環境、getcap未インストール（apt/yumで導入可だが許可が必要）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS  
  - 破れる：sudoers/capabilitiesの緩い設定でアプリ境界外の権限へ拡大し、検知しづらい形で被害が拡大。  
  - 満たす：最小権限（固定パス/固定引数）、NOPASSWD最小化、SETENV抑止、capabilities最小化、sudoログ/IOログ/auditdで監査。  
  - 参照：https://github.com/OWASP/ASVS
- WSTG  
  - WSTG-CONF-01：基盤設定（OS/ミドル/権限制御）の検証として sudo/capabilities を確認。  
  - 参照：https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration
- PTES  
  - Post-Exploitation / Privilege Escalation の入口として sudo権限/キャッシュ/capabilities を列挙→影響評価→是正まで落とす。  
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK  
  - T1548.003 Sudo and Sudo Caching  
    https://attack.mitre.org/techniques/T1548/003/  
  - T1548.001 Setuid and Setgid（同系統の権限制御悪用として capabilities も同観点）  
    https://attack.mitre.org/techniques/T1548/001/  
  - Detection例：DET0052（sudo利用/改変）、DET0110（setuid/setgid変更・異常なEUID実行）  
    https://attack.mitre.org/detectionstrategies/DET0052/  
    https://attack.mitre.org/detectionstrategies/DET0110/

## 参考（必要最小限）
- sudo man：https://www.sudo.ws/docs/man/sudo.man/
- sudoers man：https://www.sudo.ws/docs/man/sudoers.man/
- capabilities man：https://man7.org/linux/man-pages/man7/capabilities.7.html
- WSTG-CONF-01： https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration
- PTES： https://pentest-standard.readthedocs.io/
- OWASP ASVS： https://github.com/OWASP/ASVS

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`08_firewall_waf_検知と回避の境界（観測中心）.md`
- 関連 playbooks：なし
- 関連 labs / cases：任意

---

## 深掘りリンク（最大8）
- `05_scanning_到達性把握（nmap_masscan）.md`
- `06_service_fingerprint（banner_tls_alpn）.md`
- `07_pivot_tunneling（ssh_socks_chisel）.md`
- `18_winrm_psremoting_到達性と権限.md`
- `19_rdp_設定と認証（NLA）.md`
- `20_mssql_横展開（xp_cmdshell_linkedserver）.md`
- `26_credential_dumping_所在（LSA_DPAPI）.md`
- `27_persistence_永続化（schtasks_services_wmi）.md`
