# 08_slack_トークン境界（xox_署名検証）
Slack のトークン種類と署名検証を観測し、ボット/ユーザトークンの越権や漏えい経路を特定する。

## 目的（この技術で到達する状態）
- トークン種別（xoxp/xoxb/xoxa/xoxe 等）と権限スコープを把握し、誰が発行・再利用できるかを説明できる
- 署名検証（Signing Secret, Request Timestamp, body）の要否と実装有無を Yes/No/Unknown で示せる
- イベントサブスクリプション/Webhook/Workflow の送信先・権限を確認し、監査ログで追えるか判断できる
- 是正（最小スコープ・ローテーション・署名検証必須）を提示できる

## 前提（対象・範囲・想定）
- 対象：Slack ワークスペース、Slack Apps/Bots、トークン/Signing Secret、Webhook/Workflow
- 想定環境：複数ワークスペースやゲスト、外部連携が存在
- できること/やらないこと：設定確認・ログ確認のみ。トークン発行/投稿は行わない
- 依存知識：Slack API 基本、署名検証手順、イベント API
- 扱う範囲：トークン境界、署名検証、Webhook/イベント連携
- 扱わない：アプリコードの脆弱性

## 観測ポイント（プロトコル/データ/境界）
- トークン：種類、Scope、発行者（ユーザ/ワークスペース）、有効期限
- 署名：`X-Slack-Signature`/`X-Slack-Request-Timestamp` の検証実装、Signing Secret の保管
- イベント/Webhook：送信先URL、TLS検証、許可IP、リトライ挙動
- 監査：Audit Logs API（Enterprise）、Access Logs、App 安全性設定

## 結果の意味（何が言える/言えない）
- 確定できる：トークン種別とスコープ、署名検証有無、Webhook送信先
- 推定できる：漏えい時の被害範囲（チャンネル読み取り/投稿/ファイルDL）、外部送信経路
- 言えない：各トークン利用の正当性（オーナー確認が必要）
- 状態パターン
  - A：最小スコープ＋署名検証必須＋短期トークン（良好）
  - B：広いスコープの長寿命トークン＋署名検証なし（高リスク）
  - C：Webhookが外部に開放・IP制限なし（漏えい経路）

## 攻撃者視点での利用（意思決定）
- 狙い目：広権限xoxp/xoxb、署名検証欠落のエンドポイント、外部公開Webhook
- 優先度：1) トークンスコープ/期限 2) 署名検証実装 3) Webhook/イベント送信先 4) 監査ログ
- 攻め筋：トークン窃取→APIでチャンネル/ファイル取得、署名検証欠落を突いたリクエスト偽装
- 戦略変更：エンドポイントが堅牢ならトークン保管場所（CI/CD・Actions）を確認

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：署名検証が実装されていない
  - 次の検証：受信エンドポイントに過去タイムスタンプ/改変ボディを送信（許可範囲で）し検証の有無を確認
  - 期待：通る場合は重大所見
- 仮説B：広いスコープのトークンが存在
  - 次の検証：App 設定で付与スコープを確認し、最小化できるか判断
  - 期待：`channels:history/files:read` 等が不要なら削減提案
- 仮説C：Webhookが外部公開
  - 次の検証：送信先URLの制限/IP Allowlist有無を確認
  - 期待：外部向けなら漏えい経路

## 手を動かす検証（Labs連動：観測点を明確に）
- 証跡ディレクトリ
~~~~
mkdir -p ~/keda_evidence/slack_08 2>/dev/null
cd ~/keda_evidence/slack_08
~~~~
- 取得する証跡：App スコープ設定、Signing Secret 管理画面、イベント/Webhook設定、Audit/Access Logs 抜粋
- 相関キー：{TokenType, Scope, Expires, Signing(Yes/No), WebhookURL, EventTime}

## コマンド/リクエスト例
~~~~
# Audit Logs API（Enterprise）

## 前提知識（最低限）
- xoxp/xoxb/xoxa/xoxe の用途差
curl -H "Authorization: Bearer <TOKEN>" \
  "https://api.slack.com/audit/v1/logs?limit=100"
~~~~
- 注目点：app_installed/app_scopes_updated/token_revoked 等のイベント
- 使えないケース：Audit Logs API 未契約のワークスペース

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS：認証情報保護と外部連携の最小化。
  https://github.com/OWASP/ASVS
- WSTG：Configuration/Authorization テストでトークン・Webhook を確認。
  https://owasp.org/www-project-web-security-testing-guide/
- PTES：情報収集→脆弱性分析でトークン/署名/外部連携を棚卸し。
  https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：Valid Accounts（SaaS）、Exfiltration Over Web Service。
  https://attack.mitre.org/

## 参考（必要最小限）
- Slack API 基本：https://api.slack.com/
- 署名検証：https://api.slack.com/authentication/verifying-requests-from-slack
- Audit Logs API：https://api.slack.com/admins/audit-logs

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`07_github_組織権限境界（PAT_App_Actions）.md`
- 関連 playbooks：なし
- 関連 labs / cases：任意

---

## 深掘りリンク（最大8）
- `09_atlassian_外部連携と権限境界.md`
- `10_saas_oauth_consent_phishing_成立条件.md`
- `12_audit_logs_取得と相関（誰が何をいつ）.md`
