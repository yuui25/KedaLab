# 26_credential_dumping_所在（LSA_DPAPI）
Windows でのクレデンシャル所在（LSASS/LSA Secrets/DPAPI）を観測し、保護状態と是正を確定する。

## 目的（この技術で到達する状態）
- LSASSメモリ・LSA Secrets・DPAPI（MasterKey/Protect/Credential Manager/Vault）の所在と成立条件を Yes/No/Unknown で説明できる
- 防御状態（RunAsPPL/Credential Guard/WDigestの平文キャッシュ/特権割り当て）を観測で示せる
- 取得を試みずとも、検知・監査の相関キー（イベント/プロセス/特権使用）を提示できる
- 是正（保護有効化・保存禁止/制限・監査）を優先度付きで提示できる

## 前提（対象・範囲・想定）
- 対象：Windows クライアント/サーバ（AD参加を含む）
- 想定環境：侵入後の低権限ユーザ/ローカル管理者/ドメインユーザが得られている状態
- できること/やらないこと：本ファイルは所在・防御評価が主。実際のダンプ/復号は合意済み検証環境のみで実施（ここでは扱わない）
- 依存知識：LSASS/LSA Secrets/DPAPI の基本、レジストリ/イベントログ確認
- 扱う範囲：所在・成立条件・防御状態・検知/是正
- 扱わない（別ユニット）：具体的なダンプツールや復号手順、ADレプリ系（DCSync 等）→ `12_kerberos...` `15_acl_abuse...`

## 観測ポイント（プロトコル/データ/境界）
- LSASS：RunAsPPL 有効か、Credential Guard 有無、WDigestの UseLogonCredential
- LSA Secrets：`HKLM\\SECURITY\\Policy\\Secrets`（SYSTEMレベルが前提）
- DPAPI：MasterKey 保存場所 `%APPDATA%\\Microsoft\\Protect\\<SID>\\`、ドメインバックアップキー有無、Vault/CredMan ファイル位置
- 権限：SeDebugPrivilege/SeBackupPrivilege の付与、LSA へのアクセスが許可されるか
- 監査：関連イベント（LSASS保護 3065/3066、WDigest変更 4713、DPAPI 4692/4693/4694/4695 等）

## 結果の意味（言える/言えない）
- 確定できる：RunAsPPL/Credential Guard/WDigest設定、MasterKey/Secretsの所在、特権付与
- 推定できる：防御が無効ならダンプ成立余地が高い、特権があるならメモリ/レジストリアクセスが可能
- 言えない：実際の資格情報値（本ユニットでは取得しない）、不明なサードパーティ秘密ストア
- 状態パターン
  - A：RunAsPPL＋Credential Guard有効、WDigest無効（堅牢）
  - B：RunAsPPL無効＋WDigest有効＋特権付与（高リスク）
  - C：RunAsPPL有効だがドメインバックアップキー管理不明（DPAPI復号余地あり）

## 攻撃者視点での利用（意思決定）
- 狙い目：RunAsPPL無効/WDigest有効、SeDebug/SeBackup 保持、MasterKey/Vaultファイルの取得可能性
- 優先度：1) RunAsPPL/CredGuard 2) WDigest 3) 特権 4) DPAPIバックアップキーの所在
- 代表的な攻め筋：RunAsPPL無効なら LSASS ダンプ、SeBackup でハイブコピー → Secrets/DPAPI 復号基盤を整える
- 戦略変更：保護が強い場合はキーロギング/クラウドトークン等の別経路へ

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：RunAsPPL/Credential Guard が無効  
  - 次の検証：レジストリ `HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa` の RunAsPPL、BCDEditで Credential Guard 有無を確認  
  - 期待：無効なら LSASS ダンプ成立余地ありと報告
- 仮説B：WDigest が平文キャッシュを許可  
  - 次の検証：`HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential` を確認  
  - 期待：1/未設定ならリスク（平文キャッシュ）。0なら抑止
- 仮説C：特権（SeDebug/SeBackup）が付与されている  
  - 次の検証：`whoami /priv`（Windows）やローカルセキュリティポリシーを確認  
  - 期待：Enabledならメモリ/ハイブ取得の前提が満たされる

## 手を動かす検証（Labs連動：観測点を明確に）
- 証跡ディレクトリ
~~~~
mkdir -p %USERPROFILE%\\keda_evidence\\creddump_26 2>nul
cd /d %USERPROFILE%\\keda_evidence\\creddump_26
~~~~
- 取得する証跡
  - LSA保護/WDigest設定（reg query）
  - 特権（whoami /priv）
  - DPAPI ファイル/ログの存在確認（パスのみ、内容は取得しない）
- 実施方法（例）
~~~~
reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL > lsa_protection.txt 2>&1
reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest /v UseLogonCredential > wdigest.txt 2>&1
whoami /priv > whoami_priv.txt 2>&1
dir %APPDATA%\\Microsoft\\Protect\\ > dpapi_protect_dir.txt 2>&1
~~~~
- 相関キー：{Host, User, Time, RunAsPPL(Yes/No), WDigest(0/1), Privileges}

## コマンド/リクエスト例
~~~~
reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL
reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest /v UseLogonCredential
whoami /priv
~~~~
- この例で観測していること：LSA保護、WDigest平文キャッシュ可否、特権付与
- 出力のどこを見るか：RunAsPPL=0/1、UseLogonCredential=0/1、SeDebug/SeBackup の Enabled
- 使えないケース：レジストリ参照が禁止されている端末（管理者支援が必要）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS  
  - 破れる：RunAsPPL無効やWDigest平文キャッシュで資格情報が容易に取得され、横展開/永続化に直結。  
  - 満たす：RunAsPPL/Credential Guard有効、WDigest平文キャッシュ禁止、特権最小化と監査。  
  - 参照：https://github.com/OWASP/ASVS
- WSTG  
  - WSTG-CONF-01：OS/基盤における資格情報保存と保護の確認。  
  - 参照：https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration
- PTES  
  - Post-Exploitation / Credential Access：所在棚卸し → 成立条件 → 防御評価 → 検知/是正を報告。  
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK  
  - T1003 OS Credential Dumping（LSASS Memory/LSA Secrets）  
  - T1555 Credentials from Password Stores（DPAPI/Credential Manager/Vault）  
  - 参照：https://attack.mitre.org/

## 参考（必要最小限）
- MITRE T1003/T1555：https://attack.mitre.org/
- RunAsPPL/Credential Guard 設定：https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage
- WDigest 設定：https://support.microsoft.com/help/2871997
- WSTG-CONF-01： https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration
- PTES： https://pentest-standard.readthedocs.io/
- OWASP ASVS： https://github.com/OWASP/ASVS

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`12_kerberos_asrep_kerberoast_成立条件.md`
- 関連 playbooks：なし
- 関連 labs / cases：任意

---

## 深掘りリンク（最大8）
- `18_winrm_psremoting_到達性と権限.md`
- `19_rdp_設定と認証（NLA）.md`
- `25_windows_priv-esc_入口（サービス権限_UAC）.md`
- `27_persistence_永続化（schtasks_services_wmi）.md`
- `28_exfiltration_持ち出し経路（DNS_HTTP_SMB）.md`
