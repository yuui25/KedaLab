# 05_okta_サインオンポリシーとトークン境界
Okta のサインオン/アプリポリシーとトークン設定を観測し、バイパスや越権の成立条件を特定する。

## 目的（この技術で到達する状態）
- サインオンポリシー（条件/MFA/ネットワーク/デバイス）とアプリポリシーの適用・例外を説明できる
- トークン設定（認可サーバ/アクセストークン/IDトークン/リフレッシュトークン）の有効期間と検証責務を把握できる
- 監査ログでサインオン結果・MFA適用・トークン発行を追えるか判断し、是正案を提示できる

## 前提（対象・範囲・想定）
- 対象：Okta サインオンポリシー、アプリポリシー、Authorization Server 設定
- 想定環境：ネットワーク/デバイス条件あり、外部IdPフェデレーションがある場合も想定
- できること/やらないこと：設定表示・ログ確認のみ。ポリシー変更/トークン失効は行わない
- 依存知識：Okta Policy/Rule、OIDC/OAuth 基本、MFA
- 扱う範囲：ポリシー適用条件、トークン境界、監査
- 扱わない：アプリ内部の脆弱性

## 観測ポイント（プロトコル/データ/境界）
- サインオンポリシー：対象（ユーザ/グループ/アプリ）、条件（場所/デバイス/ネットワーク）、アクション（MFA/ブロック/Session lifetime）
- アプリポリシー：特定アプリの追加条件や MFA 要求
- トークン：Auth Server/Issuer/Audience、署名鍵、トークン有効期間、リフレッシュトークンローテーション
- 監査：System Log の eventType（policy.evaluate, user.session.start, token.issued 等）

## 結果の意味（何が言える/言えない）
- 確定できる：どの条件でMFA/ブロック/許可になるか、トークン有効期間と検証先
- 推定できる：ネットワーク例外や古いデバイスルールによるバイパス余地
- 言えない：個別アプリのビジネス権限
- 状態パターン
  - A：全ユーザMFA＋信頼済みネットワーク限定＋短期トークン（良好）
  - B：ネットワーク例外/長期トークン/リフレッシュローテーション無し（リスク高）
  - C：外部IdP経由でポリシー未適用（境界不明）

## 攻撃者視点での利用（意思決定）
- 狙い目：信頼済みネットワーク例外、外部IdPバイパス、長寿命トークン、リフレッシュローテーション無効
- 優先度：1) 例外ルール 2) トークン寿命/ローテーション 3) 署名検証責務 4) 監査ログの有無
- 攻め筋：例外ネットワークからMFA回避、長寿命/ローテーション無しトークンの再利用
- 戦略変更：例外が無い場合はトークン検証ミス（aud/iss/sig）を狙う

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：信頼済みネットワークでMFA不要  
  - 次の検証：該当ネットワークからサインオンし System Log で rule/decision を確認  
  - 期待：MFAが省略されるなら所見
- 仮説B：トークンが長寿命  
  - 次の検証：Auth Server 設定のトークン期限/リフレッシュローテーション設定を確認  
  - 期待：長期なら失効設計を要提案
- 仮説C：外部IdP経由でポリシー未適用  
  - 次の検証：IdP Routing/アプリポリシーを確認し、外部IdPのフローで System Log を比較  
  - 期待：policy.evaluate が出ない場合はバイパス

## 手を動かす検証（Labs連動：観測点を明確に）
- 証跡ディレクトリ
~~~~
mkdir -p ~/keda_evidence/okta_policy_05 2>/dev/null
cd ~/keda_evidence/okta_policy_05
~~~~
- 取得する証跡：ポリシー設定スクリーンショット/エクスポート、Auth Server 設定、System Log 抜粋
- 相関キー：{User, App, NetworkZone, Device, PolicyRule, Result, Token(exp/rot)}

## コマンド/リクエスト例
~~~~
# System Log 取得例
curl -H "Authorization: SSWS <API_TOKEN>" \
  "https://<ORG>.okta.com/api/v1/logs?filter=eventType eq \"policy.evaluate\""

# トークン設定取得（Auth Server）
curl -H "Authorization: SSWS <API_TOKEN>" \
  "https://<ORG>.okta.com/api/v1/authorizationServers"
~~~~
- 注目点：rule 条件・アクション、token_lifetime、refresh token rotation
- 使えないケース：APIトークン権限不足

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS：MFA/セッション管理/トークン失効を強制する設定。  
  https://github.com/OWASP/ASVS
- WSTG：Authentication テストで IdP 側ポリシーとトークンを確認。  
  https://owasp.org/www-project-web-security-testing-guide/
- PTES：情報収集→脆弱性分析でポリシー例外を棚卸し。  
  https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：Valid Accounts、Multi-Factor Authentication Interception。  
  https://attack.mitre.org/

## 参考（必要最小限）
- Okta Policy ドキュメント：https://help.okta.com/
- Auth Server 設定：https://developer.okta.com/docs/guides/customize-authz-server/
- System Log API：https://developer.okta.com/docs/reference/api/system-log/

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`04_azuread_条件付きアクセス（CA）と例外パス.md`
- 関連 playbooks：なし
- 関連 labs / cases：任意

---

## 深掘りリンク（最大8）
- `03_m365_権限境界（アプリ登録_Consent）.md`
- `06_google_workspace_oauth_スコープ境界.md`
- `10_saas_oauth_consent_phishing_成立条件.md`
- `12_audit_logs_取得と相関（誰が何をいつ）.md`
