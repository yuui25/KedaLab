# 09_atlassian_外部連携と権限境界
Atlassian Cloud（Jira/Confluence等）の外部連携と権限境界を観測し、データ漏えい・越権の成立条件を特定する。

## 目的（この技術で到達する状態）
- 外部連携（OAuth/PAT/Webhook/AppLink）の許可条件と権限を把握し、誰が発行できるか説明できる
- プロダクト権限（グローバル権限/プロジェクト権限/スペース権限）と外部共有設定を Yes/No/Unknown で示せる
- 監査ログで連携作成・権限変更・データアクセスを追えるか判断し、是正策を提示できる

## 前提（対象・範囲・想定）
- 対象：Atlassian Cloud（Jira/Confluence）組織、PAT、OAuth 2.0 (Forge/Connect)、Webhook
- 想定環境：外部ユーザ招待やリンク共有が許可されている場合あり
- できること/やらないこと：設定確認とログ確認のみ。権限変更やトークン発行は行わない
- 依存知識：Atlassian 権限モデル、アプリ スコープ、Audit Log
- 扱う範囲：外部連携・権限・監査
- 扱わない：アプリ実装の脆弱性

## 観測ポイント（プロトコル/データ/境界）
- 連携：PATのスコープと期限、OAuthアプリのスコープ、AppLink/Webhook の送信先、外部ドメイン制限
- 権限：グローバル権限（jira-administrators 等）、プロジェクトロール、スペース権限、匿名/リンク共有
- 監査：Audit Log（トークン発行/アプリ追加/権限変更/外部共有）、アクセスログ
- 境界：外部ユーザ招待、リンク共有（Confluence page/Jira issues）、メール送信

## 結果の意味（何が言える/言えない）
- 確定できる：連携のスコープと発行者、外部共有可否、主要権限設定、監査ログの有無
- 推定できる：PAT/外部アプリによるデータ持ち出し余地、匿名アクセスの影響
- 言えない：個別権限の業務正当性
- 状態パターン
  - A：外部共有禁止＋短期PAT＋スコープ最小化＋監査有効（良好）
  - B：匿名/リンク共有許可＋広いPAT＋外部アプリ自由（高リスク）
  - C：外部共有許可だが監査充実（可視化で緩和）

## 攻撃者視点での利用（意思決定）
- 狙い目：広権限PAT、外部OAuthアプリ、匿名/リンク共有ページ、Webhook送信先
- 優先度：1) 外部共有設定 2) PAT/アプリ権限 3) Webhook送信先 4) 監査ログ
- 攻め筋：PAT/アプリで課題・Wikiを取得、Webhookで外部に送信、リンク共有で匿名閲覧
- 戦略変更：外部共有が閉じている場合は内部ロールの過剰権限を確認

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：リンク共有/匿名アクセスが許可  
  - 次の検証：スペース/プロジェクトの共有設定を確認し、匿名閲覧の可否を確認  
  - 期待：許可なら所見
- 仮説B：広いPAT/アプリスコープが存在  
  - 次の検証：PAT一覧と有効期限、アプリのスコープを確認  
  - 期待：広権限なら失効/再発行を提案
- 仮説C：Webhookが外部へ送信  
  - 次の検証：Webhook設定と送信先を確認し、IP制限/署名有無を確認  
  - 期待：外部送信なら監査と制限を提案

## 手を動かす検証（Labs連動：観測点を明確に）
- 証跡ディレクトリ
~~~~
mkdir -p ~/keda_evidence/atlassian_09 2>/dev/null
cd ~/keda_evidence/atlassian_09
~~~~
- 取得する証跡：PAT/アプリ設定画面、共有設定、Webhook設定、Audit Log 抜粋
- 相関キー：{TokenType, Scope, Expires, Shared(Yes/No), WebhookURL, EventTime}

## コマンド/リクエスト例
~~~~
# Jira Cloud PAT (API) でプロジェクト一覧取得例（権限要）
curl -H "Authorization: Bearer <PAT>" \
  "https://your-domain.atlassian.net/rest/api/3/project"
~~~~
- 注目点：PATのスコープ/期限、アプリスコープ、匿名/リンク共有設定
- 使えないケース：APIアクセス無効な場合（GUIで確認）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS：アクセス制御とデータ保護。  
  https://github.com/OWASP/ASVS
- WSTG：Configuration/Authorization 観点で外部連携・共有設定を確認。  
  https://owasp.org/www-project-web-security-testing-guide/
- PTES：情報収集→脆弱性分析で連携/権限/共有を棚卸し。  
  https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：Valid Accounts（SaaS）、Exfiltration Over Web Service。  
  https://attack.mitre.org/

## 参考（必要最小限）
- PAT：https://support.atlassian.com/atlassian-account/docs/create-and-manage-api-tokens/
- App scopes：https://developer.atlassian.com/cloud/jira/platform/scopes/
- Audit log：https://support.atlassian.com/security-and-access-policies/docs/audit-logs/

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`08_slack_トークン境界（xox_署名検証）.md`
- 関連 playbooks：なし
- 関連 labs / cases：任意

---

## 深掘りリンク（最大8）
- `07_github_組織権限境界（PAT_App_Actions）.md`
- `10_saas_oauth_consent_phishing_成立条件.md`
- `12_audit_logs_取得と相関（誰が何をいつ）.md`
