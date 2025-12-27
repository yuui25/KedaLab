# 04_azuread_条件付きアクセス（CA）と例外パス
Azure AD 条件付きアクセス(CA)の適用範囲と例外を観測し、バイパス成立条件を特定する。

## 目的（この技術で到達する状態）
- CA の適用対象（ユーザ/グループ/アプリ/場所/デバイス）と例外を Yes/No/Unknown で示せる
- ポリシー適用順序/ブロック/許可がどう決まるかを理解し、例外経路を列挙できる
- 監査ログでポリシー適用結果と理由を追跡し、是正案を提示できる

## 前提（対象・範囲・想定）
- 対象：Azure AD CA ポリシー（クラウドアプリ含む）
- 想定環境：複数ポリシーが並存、緊急アクセスやIP制限例外が存在
- できること/やらないこと：ポリシー表示とサインインログ確認のみ。適用/無効化は行わない
- 依存知識：サインインログ、トークン発行フロー、デバイス登録/準拠
- 扱う範囲：ポリシー適用条件、例外、監査
- 扱わない：オンプレAD FS側の設定

## 観測ポイント（プロトコル/データ/境界）
- 対象：ユーザ/グループ/ロール、クラウドアプリ、条件（場所/クライアントアプリ/デバイス状態/リスク）
- 制御：Grant（MFA/準拠デバイス/ハイブリッドAD参加/パスワード変更）、Session制御
- 例外：信頼済み場所、緊急アカウント、旧クライアント（legacy auth）、サービスアカウント
- 監査：サインインログの Conditional Access タブ（Result/Policy/ResultDetail）

## 結果の意味（何が言える/言えない）
- 確定できる：どのポリシーが適用/スキップされたか、その理由（場所/クライアント/例外）
- 推定できる：MFA回避・ポリシーバイパスの余地、旧プロトコル許可の影響
- 言えない：ビジネス上の例外正当性（担当確認が必要）
- 状態パターン
  - A：緊急アカウントのみ例外、旧プロトコル遮断（良好）
  - B：信頼済み場所広すぎ、旧プロトコル許可（MFA回避リスク）
  - C：サービスアカウント多数除外（横展開リスク）

## 攻撃者視点での利用（意思決定）
- 狙い目：信頼済み場所、旧プロトコル許可、サービス/共有アカウント例外
- 優先度：1) 除外設定 2) 旧クライアント許可 3) 信頼済み場所の範囲 4) ログでの検知可否
- 攻め筋：旧プロトコルでのパスワードスプレー、信頼済み場所からのMFA回避、サービスアカウント悪用
- 戦略変更：例外が少ない場合はトークン存続期間やデバイス準拠判定を確認

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：旧プロトコル許可が残存
  - 次の検証：CA ポリシーの「クライアントアプリ」で旧プロトコルが対象外か確認
  - 期待：対象外なら回避余地、対象なら遮断
- 仮説B：信頼済み場所が広い
  - 次の検証：Named Location の設定範囲を確認（国/IPv4/IPv6）
  - 期待：広い場合はMFA回避経路
- 仮説C：サービスアカウントが除外
  - 次の検証：対象/除外のグループにサービスアカウントが含まれるか確認
  - 期待：含まれる場合は監査と代替制御を要提案

## 手を動かす検証（Labs連動：観測点を明確に）
- 証跡ディレクトリ
~~~~
mkdir -p ~/keda_evidence/ca_04 2>/dev/null
cd ~/keda_evidence/ca_04
~~~~
- 取得する証跡：CA ポリシー設定エクスポート、サインインログ（Result/Policy）、Named Location 設定
- 相関キー：{User, App, ClientApp, Location, DeviceState, Policy, ResultDetail}

## コマンド/リクエスト例
~~~~
# Graph: CA ポリシー一覧

## 状態パターンの根拠
- 例外パスは認証強度を下げるため高リスク
curl -H "Authorization: Bearer <TOKEN>" \
  https://graph.microsoft.com/beta/identity/conditionalAccess/policies

# サインインログ取得（例）

## 状態パターンの根拠
- 例外パスは認証強度を下げるため高リスク
curl -H "Authorization: Bearer <TOKEN>" \
  "https://graph.microsoft.com/beta/auditLogs/signIns?$top=20"
~~~~
- 注目点：state/conditions/grantControls、ResultDetail（MFA required / blocked 等）
- 使えないケース：Graph 権限不足（AuditLog.Read.All 等が必要）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS：認証・セッションの強化として MFA/デバイス条件を強制。
  https://github.com/OWASP/ASVS
- WSTG：Authentication テストで MFA/ポリシー適用を確認。
  https://owasp.org/www-project-web-security-testing-guide/
- PTES：情報収集→脆弱性分析でポリシー例外を棚卸し。
  https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：Valid Accounts/Multi-Factor Authentication Interception。
  https://attack.mitre.org/

## 参考（必要最小限）
- CA ポリシー概要：https://learn.microsoft.com/azure/active-directory/conditional-access/overview
- サインインログ：https://learn.microsoft.com/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes
- Named location：https://learn.microsoft.com/azure/active-directory/conditional-access/location-condition

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`05_okta_サインオンポリシーとトークン境界.md`
- 関連 playbooks：なし
- 関連 labs / cases：任意

---

## 深掘りリンク（最大8）
- `03_m365_権限境界（アプリ登録_Consent）.md`
- `10_saas_oauth_consent_phishing_成立条件.md`
- `12_audit_logs_取得と相関（誰が何をいつ）.md`
- `14_sso_bypass_パス（ローカルログイン残存）.md`
