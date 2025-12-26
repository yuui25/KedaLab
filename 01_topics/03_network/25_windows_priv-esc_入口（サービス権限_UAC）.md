# 25_windows_priv-esc_入口（サービス権限_UAC）
Windows の権限昇格入口（サービス権限/UAC/権限割り当て）を観測で確定し、安全な検証と是正に落とす。

## 目的（この技術で到達する状態）
- サービス実行アカウントとバイナリパス（権限/書込み可否）を列挙し、昇格可否を Yes/No/Unknown で説明できる
- 権限割り当て（SeImpersonate/SeAssignPrimaryToken 等）やUAC設定を観測し、影響を評価できる
- 証跡（sc qc/query, accesschk, whoami /priv）の結果を根拠として残せる
- 是正（最小権限アカウント、バイナリパス保護、不要権限除去、UAC設定）を提案できる

## 前提（対象・範囲・想定）
- 対象：Windows サーバ/クライアント（AD参加を含む）
- 想定環境：オンプレ/クラウド問わず。管理者権限なしの侵入後シナリオを想定
- できること/やらないこと：サービス停止/変更は行わない。列挙と安全な書込み判定のみ
- 依存知識：Windows サービスの仕組み、UAC、権限割り当て（whoami /priv）
- 扱う範囲：列挙・解釈・検知・是正
- 扱わない（別ユニット）：資格情報ダンピング → `26_credential_dumping_所在（LSA_DPAPI）.md`、永続化 → `27_persistence_永続化（schtasks_services_wmi）.md`

## 観測ポイント（プロトコル/データ/境界）
- サービス：実行アカウント（LocalSystem/LocalService/DomainAccount）、バイナリパス、パスのACL（自分が書けるか）、ImagePathにスペース+引数の有無
- 権限割り当て：whoami /priv での SeImpersonate/SeAssignPrimaryToken/SeBackup/SeRestore 等
- UAC：ConsentPromptBehavior、LSA保護（RunAsPPL）
- 境界：非管理者が書き込み可能なサービスバイナリ/フォルダ、弱い権限割り当てがあるか
- ログ：サービス変更（イベントログ：System/Service Control Manager）、権限割り当て変更（Securityポリシー変更）

## 結果の意味（言える/言えない）
- 確定できる：書込み可能サービス/パスの有無、強権限（SeImpersonate等）の有無、UAC設定
- 推定できる：運用上の理由で権限が広いサービス（バックアップ/監視等）
- 言えない：未観測の計画タスクや隠れたS4U設定（別途確認）
- 状態パターン
  - A：サービスは専用低権限アカウント＋書込み不可、強権限なし（良好）
  - B：LocalSystemサービスのバイナリパスを書き換え可能（昇格容易）
  - C：SeImpersonate/SeAssignPrimaryTokenあり（Potato系成立の可能性）

## 攻撃者視点での利用（意思決定）
- 狙い目：LocalSystem実行サービスの書込み可能パス、引数注入、強権限（SeImpersonate/SeAssignPrimaryToken）
- 優先度：1) 書込み可否 2) 実行アカウント 3) 権限割り当て 4) UAC/LSA保護
- 代表的な攻め筋
  - サービスバイナリ差し替え/パスハイジャック（スペース＋未引用）
  - Potato系（SeImpersonate/SeAssignPrimaryToken + 向き先サービス）
- 戦略変更：書込み不可なら権限割り当て経由（Potato系）や別タスク列挙へ

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：書込み可能なサービスバイナリ/フォルダがある  
  - 次の検証：`sc qc` 出力から ImagePath を抽出し ACL を確認（icacls/accesschk）  
  - 期待する観測：Users/Authenticated Users 書込み可なら昇格経路候補
- 仮説B：強権限（SeImpersonate/SeAssignPrimaryToken）が付与されている  
  - 次の検証：`whoami /priv` を保存し、Enabled/Available を確認  
  - 期待する観測：Enabled なら Potato系成立の可能性あり
- 仮説C：UAC が緩い  
  - 次の検証：レジストリ/ローカルセキュリティポリシーを確認（ConsentPromptBehavior）  
  - 期待する観測：低い設定なら昇格阻止が弱いと報告

## 手を動かす検証（Labs連動：観測点を明確に）
- 証跡ディレクトリ
~~~~
mkdir -p %USERPROFILE%\\keda_evidence\\win_priv_25 2>nul
cd /d %USERPROFILE%\\keda_evidence\\win_priv_25
~~~~
- 取得する証跡
  - サービス一覧と設定：`sc query type= service state= all > sc_query.txt`
  - 個別サービス詳細：`sc qc <SERVICE>` を重点対象のみ
  - 権限割り当て：`whoami /priv > whoami_priv.txt`
  - パスACL：`icacls "<PATH>"` または Sysinternals `accesschk -quv <PATH>`
- 観測の取り方：バイナリパス/フォルダの書込み可否を優先、引数未引用の有無も確認
- 相関キー：{ServiceName, BinPath, RunAs, Writable(Yes/No), Privileges, Time}

## コマンド/リクエスト例
~~~~
sc query type= service state= all
sc qc <SERVICE>
whoami /priv
icacls "C:\\Path\\to\\service.exe"
~~~~
- この例で観測していること：サービス実行アカウント、バイナリパス、権限割り当て、パスの書込み可否
- 出力のどこを見るか：SERVICE_START_NAME、BINARY_PATH_NAME、Users/Authenticated Users の権限、SeImpersonate/SeAssignPrimaryToken の Enabled
- 使えないケース：アクセス権で sc/Whoami が制限されている場合（管理者補助が必要）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS  
  - 破れる：サービス権限や強権限が緩いとアプリ境界外での昇格が成立し、影響範囲が拡大。  
  - 満たす：専用低権限アカウントで実行、バイナリパスへの書込み禁止、強権限の付与最小化、変更は監査/変更管理に載せる。  
  - 参照：https://github.com/OWASP/ASVS
- WSTG  
  - WSTG-CONF-01：基盤設定検証としてサービス権限・権限割り当て・UAC/LSA保護を確認。  
  - 参照：https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration
- PTES  
  - Post-Exploitation / Privilege Escalation：サービス/権限割り当てを列挙→昇格可否を判断→報告。  
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK  
  - T1574.002 Hijack Execution Flow: DLL Search Order Hijacking（サービスバイナリ差替え系に接続）  
  - T1134.001/T1134.002（Token Impersonation/Potato系に接続）  
  - 参照：https://attack.mitre.org/

## 参考（必要最小限）
- Microsoft Docs（SCコマンド）：https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc
- whoami /priv：https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/whoami
- icacls：https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls
- WSTG-CONF-01： https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration
- PTES： https://pentest-standard.readthedocs.io/
- OWASP ASVS： https://github.com/OWASP/ASVS

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`18_winrm_psremoting_到達性と権限.md`
- 関連 playbooks：なし
- 関連 labs / cases：任意

---

## 深掘りリンク（最大8）
- `09_smb_enum_共有・権限・匿名（null_session）.md`
- `18_winrm_psremoting_到達性と権限.md`
- `19_rdp_設定と認証（NLA）.md`
- `20_mssql_横展開（xp_cmdshell_linkedserver）.md`
- `26_credential_dumping_所在（LSA_DPAPI）.md`
- `27_persistence_永続化（schtasks_services_wmi）.md`
- `28_exfiltration_持ち出し経路（DNS_HTTP_SMB）.md`
