# 07_github_組織権限境界（PAT_App_Actions）
GitHub 組織における PAT/Apps/Actions 権限を観測し、ソースコード・シークレット流出の成立条件を特定する。

## 目的（この技術で到達する状態）
- PAT/ユーザ権限/組織権限/リポジトリ権限の関係を説明し、どこで越権が起こるかを示せる
- GitHub Apps/Actions の権限とインストール範囲（組織/リポジトリ）が適切かを Yes/No/Unknown で示せる
- シークレット（Actions secrets/Dependabot/Code scanning 等）のスコープと漏えい経路を把握し、監査ログで追えるか判断できる

## 前提（対象・範囲・想定）
- 対象：GitHub Enterprise/Cloud 組織、PAT/SSH鍵/GitHub Apps/Actions
- 想定環境：複数リポジトリ/チームが存在し、外部コントリビュータや自動化がある
- できること/やらないこと：権限設定とログ確認のみ。権限変更・トークン発行は行わない
- 依存知識：GitHub権限モデル、Actions ワークフロー、Apps/PAT スコープ
- 扱う範囲：権限境界、トークン・シークレットの管理、監査
- 扱わない：コード脆弱性

## 観測ポイント（プロトコル/データ/境界）
- 組織ポリシー：外部コラボ、2FA必須、デフォルト権限、セキュリティポリシー
- トークン：PATスコープ、期限、発行者、Fine-grained PAT の対象リポジトリ
- GitHub Apps：権限（Metadata/Contents/Actions/Administration 等）、インストール先、個人/組織所有
- Actions：Workflow permissions（contents:read/write, id-token）、フォークからの PR 実行、シークレットのスコープ
- 監査：Audit log / Security log / Actions log

## 結果の意味（何が言える/言えない）
- 確定できる：権限/トークン/アプリのスコープ、シークレットの共有範囲、フォークPR実行の可否
- 推定できる：トークン再利用や外部PR経由のシークレット漏えい余地
- 言えない：各トークンの利用正当性（オーナー確認が必要）
- 状態パターン
  - A：Fine-grained PAT + 短期 + 2FA 必須 + Actions 限定権限（良好）
  - B：Classic PAT 長期 + contents:write + 全リポジトリ（高リスク）
  - C：GitHub Apps が全権限で全リポジトリにインストール（高リスク）

## 攻撃者視点での利用（意思決定）
- 狙い目：Classic PAT 長寿命、広権限 GitHub Apps、フォークPRで secrets 可視、Actions の id-token 曝露
- 優先度：1) トークン種別/期限/スコープ 2) Apps 権限とインストール範囲 3) Actions permissions とシークレットスコープ 4) 監査ログ
- 攻め筋：盗取トークン再利用、悪性Actionsでシークレット exfil、Apps権限の悪用
- 戦略変更：厳格な設定ならリポジトリ設定（保護ブランチ/環境シークレット）を確認

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：Classic PAT が長寿命・広権限  
  - 次の検証：組織ポリシーと監査ログで Classic PAT 利用を確認  
  - 期待：存在するなら失効/再発行ポリシーを提案
- 仮説B：GitHub Apps が全リポジトリに高権限でインストール  
  - 次の検証：アプリの権限と対象リポジトリを確認  
  - 期待：必要最小権限へ再設定を提案
- 仮説C：Actions がフォーク PR で secrets を渡す  
  - 次の検証：リポジトリ設定（Require approval for first-time contributors、workflow permissions）を確認  
  - 期待：渡しているなら漏えい経路

## 手を動かす検証（Labs連動：観測点を明確に）
- 証跡ディレクトリ
~~~~
mkdir -p ~/keda_evidence/github_07 2>/dev/null
cd ~/keda_evidence/github_07
~~~~
- 取得する証跡：組織ポリシー画面、PAT/Apps/Actions 設定エクスポート、監査ログサンプル
- 相関キー：{TokenType, Scope, Expires, AppPermissions, InstallTargets, WorkflowPermissions}

## コマンド/リクエスト例
~~~~
# Actions ワークフロー権限確認 (GraphQL API例)
curl -H "Authorization: Bearer <TOKEN>" -X POST https://api.github.com/graphql -d '{
  "query": "query { repository(owner: \"ORG\", name: \"REPO\") { actionsDefaultWorkflowPermissions, actionsCanApprovePullRequestReviews } }"
}'
~~~~
- 注目点：workflow permissions、id-token 発行有無、Secrets のスコープ
- 使えないケース：APIトークン権限不足

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS：ソースコード保護・認証情報保護。  
  https://github.com/OWASP/ASVS
- WSTG：Configuration/Authorization 観点でリポジトリ権限・トークンを確認。  
  https://owasp.org/www-project-web-security-testing-guide/
- PTES：情報収集→脆弱性分析でトークンと自動化の境界を棚卸し。  
  https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：Valid Accounts（Code Repo）、Exfiltration Over Web Service。  
  https://attack.mitre.org/

## 参考（必要最小限）
- Fine-grained PAT：https://docs.github.com/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token
- GitHub Apps 権限：https://docs.github.com/developers/apps/building-github-apps/understanding-github-app-permissions
- Actions permissions：https://docs.github.com/actions/using-workflows/workflow-syntax-for-github-actions#permissions

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`12_audit_logs_取得と相関（誰が何をいつ）.md`
- 関連 playbooks：なし
- 関連 labs / cases：任意

---

## 深掘りリンク（最大8）
- `08_slack_トークン境界（xox_署名検証）.md`
- `09_atlassian_外部連携と権限境界.md`
- `10_saas_oauth_consent_phishing_成立条件.md`
