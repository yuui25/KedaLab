# 03_m365_権限境界（アプリ登録_Consent）
Microsoft 365/Azure AD のアプリ登録と同意モデルを観測し、どこで権限が決まり越権が生じるかを特定する。

## 目的（この技術で到達する状態）
- アプリの同意モデル（委任/アプリケーション、ユーザ同意/管理者同意）がどこで決まり、誰が発行できるかを説明できる
- アプリ登録設定（マルチテナント/Redirect URI/権限スコープ）のリスクを Yes/No/Unknown で示せる
- 監査（サインインログ/同意ログ/アプリ変更ログ）で追えるかを判断し、是正策を提示できる

## 前提（対象・範囲・想定）
- 対象：Azure AD/M365 テナントのアプリ登録、Enterprise Applications、同意ポリシー
- 想定環境：マルチテナントSaaS利用、ユーザ同意を許可している組織も含む
- できること/やらないこと：ポータル/Graphでの設定確認とログ確認のみ。権限付与・削除は行わない
- 依存知識：OAuth/OIDC 基本、Graph 権限モデル、Conditional Access
- 扱う範囲：権限境界、同意フロー、監査
- 扱わない：アプリコードの脆弱性

## 観測ポイント（プロトコル/データ/境界）
- アプリ登録：シングル/マルチテナント設定、Redirect URI（Web/SPAs/ネイティブ）、機密/パブリッククライアント
- 権限：委任スコープ（User.Read 等）とアプリケーション権限（Directory.Read.All 等）、同意の可否
- ポリシー：ユーザ同意設定、検証済み発行者、管理者同意ワークフロー、同意の制限
- 監査：サインインログ、同意ログ、アプリ変更（Directory Audit）

## 結果の意味（何が言える/言えない）
- 確定できる：誰がどの権限で同意可能か、マルチテナント可否、危険権限の付与状況、ログ有無
- 推定できる：不正アプリ登録/同意フィッシングの成立余地、外部テナントへの露出
- 言えない：個別アプリの正当性（オーナー確認が必要）
- 状態パターン
  - A：ユーザ同意禁止＋管理者同意ワークフロー＋検証済み発行者のみ（良好）
  - B：ユーザ同意許可＋高権限スコープ要求（高リスク）
  - C：マルチテナント開放＋検証なし（外部悪用リスク）

## 攻撃者視点での利用（意思決定）
- 狙い目：ユーザ同意許可、マルチテナント、危険権限（Mail.ReadWrite/Directory.Read.All 等）、長寿命シークレット/証明書
- 優先度：1) 同意ポリシー 2) 権限スコープ 3) アプリ登録設定 4) 監査ログ
- 攻め筋：同意フィッシングでトークン取得、マルチテナントアプリで外部テナントを横断、長寿命シークレットで持続
- 戦略変更：同意が厳しい場合は既存承認済みアプリの権限昇格経路を探る

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：ユーザ同意が許可されている  
  - 次の検証：ポータル設定と Graph `/policies/authorizationPolicy` を確認  
  - 期待：許可なら同意フィッシング余地あり
- 仮説B：高権限スコープが既に承認済み  
  - 次の検証：Enterprise Applications の権限一覧をエクスポートし危険権限を抽出  
  - 期待：Directory.Read.All 等があれば要レビュー
- 仮説C：マルチテナント/redirect_uri が緩い  
  - 次の検証：アプリ登録の設定を確認し、ワイルドカードやローカルホスト登録の有無を確認  
  - 期待：緩い場合は不正再利用リスク

## 手を動かす検証（Labs連動：観測点を明確に）
- 証跡ディレクトリ
~~~~
mkdir -p ~/keda_evidence/m365_app_03 2>/dev/null
cd ~/keda_evidence/m365_app_03
~~~~
- 取得する証跡：同意ポリシー設定、アプリ権限エクスポート、サインイン/同意ログサンプル
- 相関キー：{AppId, Publisher, Tenant, Permission, ConsentType(User/Admin), IssuedAt}

## コマンド/リクエスト例
~~~~
# Graph: ユーザ同意設定の確認
curl -H "Authorization: Bearer <TOKEN>" \
  https://graph.microsoft.com/v1.0/policies/authorizationPolicy/authorizationPolicy

# Graph: アプリの権限一覧
curl -H "Authorization: Bearer <TOKEN>" \
  "https://graph.microsoft.com/v1.0/applications/<APP-ID>/requiredResourceAccess"
~~~~
- 注目点：defaultUserRolePermissions、permissionGrantPolicy、requiredResourceAccess のスコープ/権限
- 使えないケース：Graph権限不足（管理者承認が必要）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS：認証/セッションの前提として IdP/同意モデルの制御。  
  https://github.com/OWASP/ASVS
- WSTG：Authentication/Authorization テストにおける IdP 設定確認。  
  https://owasp.org/www-project-web-security-testing-guide/
- PTES：情報収集→脆弱性分析で同意ポリシーと権限を棚卸し。  
  https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：Valid Accounts（Cloud Accounts）、Exfiltration Over Web Service。  
  https://attack.mitre.org/

## 参考（必要最小限）
- 同意ポリシー：https://learn.microsoft.com/azure/active-directory/enterprise-users/configure-consent-once-per-app
- Graph permissions：https://learn.microsoft.com/graph/permissions-reference
- マルチテナントアプリ：https://learn.microsoft.com/azure/active-directory/develop/howto-convert-app-to-be-multi-tenant

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`10_saas_oauth_consent_phishing_成立条件.md`
- 関連 playbooks：なし
- 関連 labs / cases：任意

---

## 深掘りリンク（最大8）
- `04_azuread_条件付きアクセス（CA）と例外パス.md`
- `05_okta_サインオンポリシーとトークン境界.md`
- `06_google_workspace_oauth_スコープ境界.md`
- `12_audit_logs_取得と相関（誰が何をいつ）.md`
- `15_token_lifetime_更新と失効（SaaS側）.md`
