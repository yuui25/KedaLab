# 27_persistence_永続化（schtasks_services_wmi）

## 前提知識（最低限）
- 永続化は複数経路で成立

## 具体例（注目点）
- 監査ログと登録先の照合
Windows の永続化入口（タスク・サービス・WMI）を棚卸しし、成立条件と是正を確定する。

## 目的（この技術で到達する状態）
- 定期/起動/イベント駆動の実行点（Scheduled Task/Service/WMI Subscription）を列挙し、正当・不正を Yes/No/Unknown で説明できる
- 成立条件（権限/トリガ/バイナリ所在/署名/パス書込み可否）を観測で示せる
- 証跡（schtasks/sc/query/WMI出力）を残し、検知・監査用の相関キーを提示できる
- 是正（不要タスク/サービス削除、書込み不可化、監査ルール）を優先度付きで提示できる

## 前提（対象・範囲・想定）
- 対象：Windows クライアント/サーバ
- 想定環境：侵入後、管理者/低権限問わず観測を行う。変更は行わない
- できること/やらないこと：列挙とバイナリ/パスの存在確認のみ。サービス停止/削除やバイナリ操作は行わない
- 依存知識：Scheduled Task/Service/WMI の基本、イベントログの位置
- 扱う範囲：schtasks/Service/WMIの棚卸し、成立条件、検知/是正
- 扱わない（別ユニット）：クラウド側の永続化、ブートキット等

## 観測ポイント（プロトコル/データ/境界）
- Scheduled Task：トリガ（ログオン/起動/時間）、実行ユーザ、アクションパス、パスの書込み可否、署名
- Service：実行アカウント（LocalSystem/その他）、BinPath の書込み可否/未引用パス、StartType
- WMI：永久イベントサブスクリプション（__EventFilter/CommandLineEventConsumer/FilterToConsumerBinding）
- 境界：バイナリ格納パスが Users/Authenticated Users に書込み可能か、UNC 宛か
- 監査：タスク/サービス作成・変更イベント、WMI サブスクリプション作成（Event ID 5861 等）、Sysmon Event 19/20/21

## 結果の意味（言える/言えない）
- 確定できる：既存タスク/サービス/WMI Subscription の一覧、書込み可否、トリガ/実行ユーザ
- 推定できる：正当運用/不審（署名なし、匿名共有パス、奇妙なトリガ）
- 言えない：実際の悪性/良性判定（別途IR・ホワイトリストと突合必要）
- 状態パターン
  - A：署名付き/標準パスのみ・書込み不可（良好）
  - B：ユーザ書込み可能パスを実行（置換容易）
  - C：WMI永続化が残存（検知難度高）

## 攻撃者視点での利用（意思決定）
- 狙い目：書込み可能なタスク/サービスのバイナリ、未引用パス、WMIサブスクリプション
- 優先度：1) 書込み可否 2) 実行ユーザ/アカウント 3) トリガの頻度 4) 署名/ハッシュ
- 代表的な攻め筋：バイナリ置換、タスクアクション上書き、WMI consumer 書換え
- 戦略変更：書込み不可なら新規永続化試行は避け、検知逃れ目的の調整へ

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：タスク実行ファイルに書込み可能  
  - 次の検証：`schtasks /query /fo LIST /v` でパスを抽出し `icacls` でACL確認  
  - 期待：Users/Authenticated Users が書込み可なら置換可能性あり
- 仮説B：サービスバイナリ/フォルダに書込み可能  
  - 次の検証：`sc query state= all` → `sc qc <SERVICE>` で BinPath を確認し `icacls`  
  - 期待：書込み可なら永続化/昇格経路
- 仮説C：WMI 永久イベントサブスクリプションが存在  
  - 次の検証：PowerShell で __EventFilter/CommandLineEventConsumer/FilterToConsumerBinding を列挙  
  - 期待：不審な consumer/コマンドを特定

## 手を動かす検証（Labs連動：観測点を明確に）
- 証跡ディレクトリ
~~~~
mkdir -p %USERPROFILE%\\keda_evidence\\persistence_27 2>nul
cd /d %USERPROFILE%\\keda_evidence\\persistence_27
~~~~
- 取得する証跡
  - タスク一覧：`schtasks /query /fo LIST /v > schtasks_all.txt`
  - サービス一覧：`sc query state= all > sc_query_all.txt`
  - 重点サービス詳細：`sc qc <SERVICE> >> sc_qc_focus.txt`
  - WMIサブスクリプション：PowerShell で `Get-WmiObject -Namespace root\\subscription -Class __EventFilter` など
- 観測の取り方：パスとACLをセットで見る。署名/ハッシュ確認は必要に応じて追加
- 相関キー：{Type(Task/Service/WMI), Name, User, Trigger, Path, Writable(Yes/No)}

## コマンド/リクエスト例
~~~~
schtasks /query /fo LIST /v
sc query state= all
sc qc <SERVICE>
powershell -NoProfile -Command "Get-WmiObject -Namespace root\\subscription -Class __EventFilter"
~~~~
- この例で観測していること：実行点の一覧とバイナリパス
- 出力のどこを見るか：アクション/Path、実行ユーザ、StartType/Trigger、ACLでの書込み可否
- 使えないケース：ポリシーで schtasks/sc/WMI が制限されている場合（管理者支援が必要）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS  
  - 破れる：OS側の自動実行点が緩いとアプリ修正後も再侵入・潜伏が継続。  
  - 満たす：許可された実行点のみ棚卸し、最小権限アカウントで実行、バイナリパス書込み禁止、変更監査と相関。  
  - 参照：https://github.com/OWASP/ASVS
- WSTG  
  - WSTG-CONF-01：OS/基盤設定（自動実行・監査）を検証対象に含める。  
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES  
  - Post-Exploitation：永続化の所在を棚卸し→成立条件→非破壊確認→是正/検知。  
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK  
  - T1053（Scheduled Task/Job）、T1053.005（Scheduled Task）、T1543.003（Windows Service）、T1047（WMI Execution）、T1546.003（WMI Event Subscription）  
  - 参照：https://attack.mitre.org/

## 参考（必要最小限）
- schtasks：https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks
- sc：https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc
- WMI event subscription 解説：https://learn.microsoft.com/en-us/windows/win32/wmisdk/receiving-a-wmi-event
- WSTG：https://owasp.org/www-project-web-security-testing-guide/
- PTES：https://pentest-standard.readthedocs.io/
- OWASP ASVS：https://github.com/OWASP/ASVS

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`25_windows_priv-esc_入口（サービス権限_UAC）.md`
- 関連 playbooks：なし
- 関連 labs / cases：任意

---

## 深掘りリンク（最大8）
- `18_winrm_psremoting_到達性と権限.md`
- `19_rdp_設定と認証（NLA）.md`
- `26_credential_dumping_所在（LSA_DPAPI）.md`
- `28_exfiltration_持ち出し経路（DNS_HTTP_SMB）.md`
