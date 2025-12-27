# 12_audit_logs_取得と相関（誰が何をいつ）
SaaS の監査ログを収集・相関し、「誰が何をいつどこで」を説明できる状態を作る。

## 目的（この技術で到達する状態）
- 主要イベント（認証/権限変更/共有/外部連携/データ操作）をログで把握し、保持期間と取得方法を説明できる
- 相関キー（User/Actor/Resource/Action/Time/Client/IP）を抽出し、他のログ（IdP/Proxy/EDR）と紐付けられる
- 欠損（保持期間不足/特定イベント未記録）を Yes/No/Unknown で示し、是正案を提示できる

## 前提（対象・範囲・想定）
- 対象：主要SaaS（M365/Google/Okta/Slack/GitHub等）の監査ログ
- 想定環境：複数SaaSを併用し、SIEMやローカル収集を行う
- できること/やらないこと：ログ取得・確認のみ。保持期間変更やエクスポート設定変更は事前合意が必要
- 依存知識：各SaaSのログAPI/エクスポート方式、時刻同期、PII取り扱い
- 扱う範囲：ログの有無・粒度・保持・相関方法
- 扱わない：検知ルール詳細（別途SOC設計）

## 観測ポイント（プロトコル/データ/境界）
- イベント種別：Auth/Consent/Role/Sharing/AppInstall/Webhook/Download/Delete 等
- 保持期間とライセンス：無料/標準/有償での期間差、アーカイブ可否
- 取得方法：API/Pull、Webhook/Push、CSV/JSONエクスポート、SIEM連携
- 相関キー：User/Actor, ResourceId, Action, Time(UTC), Client/AppId, IP/Location, Tenant

## 結果の意味（何が言える/言えない）
- 確定できる：ログの有無・保持期間・取得手段、相関に必要なキーが含まれるか
- 推定できる：保持不足による遡及不可範囲、相関欠損（IPなし/Resourceなし）
- 言えない：ビジネス上の正当性（別途IR/運用確認）
- 状態パターン
  - A：長期保持＋API/SIEM連携＋主要キー完備（良好）
  - B：短期保持＋手動エクスポートのみ（高リスク）
  - C：イベント粒度不足だが外部ログで補完可能（部分的）

## 攻撃者視点での利用（意思決定）
- 狙い目：保持期間短いSaaS、IP/Resource が記録されないイベント、Webhook経由の外部送信で追跡困難な箇所
- 優先度：1) 保持期間 2) 取得手段 3) 相関キーの有無 4) 欠損イベント
- 攻め筋：保持切れを待つ、相関できないチャネルを使う
- 戦略変更：保持が強い場合は量や匿名化で検知を逃れる必要がある（別検討）

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：保持期間が短い
  - 次の検証：各SaaSの保持期間/アーカイブ設定を確認
  - 期待：短期ならエクスポート/延長を提案
- 仮説B：主要キーが欠損
  - 次の検証：サンプルイベントで User/Resource/IP/Client が含まれるか確認
  - 期待：欠損なら補完（Proxy/EDR 連携）を提案
- 仮説C：取得が手動のみ
  - 次の検証：API/Webhook/SIEM 連携可否を確認
  - 期待：自動化できない場合は運用リスク

## 手を動かす検証（Labs連動：観測点を明確に）
- 証跡ディレクトリ
~~~~
mkdir -p ~/keda_evidence/audit_logs_12 2>/dev/null
cd ~/keda_evidence/audit_logs_12
~~~~
- 取得する証跡：各SaaSのログサンプル（JSON/CSV）、保持設定画面、APIレスポンス例
- 相関キー：{User, Resource, Action, Time(UTC), Client/AppId, IP, Tenant}

## コマンド/リクエスト例
~~~~
# 例：Slack Audit Logs API (Enterprise)

## 相関例（最小）
- `user + time` でIdP/SaaSのログを結合
curl -H "Authorization: Bearer <TOKEN>" "https://api.slack.com/audit/v1/logs?limit=10"

# 例：GitHub Audit Log API

## 相関例（最小）
- `user + time` でIdP/SaaSのログを結合
curl -H "Authorization: Bearer <TOKEN>" "https://api.github.com/orgs/<org>/audit-log?per_page=10"
~~~~
- 注目点：キーの有無（actor, action, created_at, ip, resource）、保持期間
- 使えないケース：契約/権限が不足する場合（GUIエクスポートで代替）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS：ログ・監査の確保、時間同期、改ざん防止。
  https://github.com/OWASP/ASVS
- WSTG：情報収集/テスト計画でログ取得と相関を前提にする。
  https://owasp.org/www-project-web-security-testing-guide/
- PTES：情報収集→報告で根拠としてログを提示。
  https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：Collection/Exfiltration/Defense Evasion での検知基盤。
  https://attack.mitre.org/

## 参考（必要最小限）
- 各SaaSの Audit API ドキュメント（Slack/GitHub/M365/Google/Okta 等）
- 時刻同期とログ設計のベストプラクティス

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`02_saas_共有・外部連携・監査ログの勘所.md`
- 関連 playbooks：なし
- 関連 labs / cases：任意

---

## 深掘りリンク（最大8）
- `05_okta_サインオンポリシーとトークン境界.md`
- `07_github_組織権限境界（PAT_App_Actions）.md`
- `08_slack_トークン境界（xox_署名検証）.md`
- `15_token_lifetime_更新と失効（SaaS側）.md`
