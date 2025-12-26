# 02_saas_共有・外部連携・監査ログの勘所
SaaS での共有設定・外部連携・監査ログを観測し、越権と漏えいの成立条件を特定する。

## 目的（この技術で到達する状態）
- 共有範囲（組織/外部/リンク共有）と権限（閲覧/編集/管理）がどこで決まるかを説明できる
- 外部連携（OAuthアプリ/Webhook/APIキー）の許可条件と監査有無を Yes/No/Unknown で示せる
- 監査ログの粒度（誰が何をいつどこへ）を確認し、相関キーを提示できる
- 是正（デフォルト共有/外部連携ポリシー/監査保持）の提案ができる

## 前提（対象・範囲・想定）
- 対象：主要SaaS（ストレージ/コラボ/プロダクティビティ等）の共有・連携設定
- 想定環境：組織テナント内で外部ユーザ/外部アプリを許可する運用がある
- できること/やらないこと：GUI/APIでの設定確認とログ確認のみ。実データの外部送信は行わない
- 依存知識：各SaaSの共有リンク種別、OAuthアプリ承認モデル、監査ログ取得方法
- 扱う範囲：共有/外部連携/監査ログの成立条件
- 扱わない：個別アプリ固有の脆弱性

## 観測ポイント（プロトコル/データ/境界）
- 共有：デフォルト共有範囲（組織内/外部可/リンク公開）、ロール（Viewer/Editor/Owner）、リンク保護（期限/パスワード）
- 外部連携：OAuthアプリ承認（誰ができるか）、Webhook送信先、APIキーの発行/スコープ
- 監査：イベント種別（共有変更/外部共有/アプリ承認/ダウンロード/削除）、保持期間、エクスポート方法
- 境界：組織外メール/ドメイン制限、承認フロー（管理者同意/セキュリティレビュー）、ネットワーク制御（IP Allow/Block）

## 結果の意味（何が言える/言えない）
- 確定できる：共有デフォルト設定、外部共有可否、外部アプリ承認ポリシー、監査ログ有無と保持期間
- 推定できる：外部連携が持ち出し経路になる余地、監査抜けの範囲
- 言えない：個別ファイルの正当性（オーナー確認が必要）
- 状態パターン
  - A：外部共有禁止＋管理者同意必須＋長期監査（良好）
  - B：リンク公開が既定＋ユーザ承認可能＋短期監査（高リスク）
  - C：外部共有許可だが監査充実（リスクは可視化で緩和）

## 攻撃者視点での利用（意思決定）
- 狙い目：公開リンク/外部共有、ユーザが自由に承認できる外部アプリ、Webhook送信先
- 優先度：1) 共有デフォルト 2) 外部連携承認モデル 3) 監査保持とエクスポート 4) 制限（ドメイン/IP）
- 攻め筋：外部メール招待、公開リンク生成、OAuthアプリでデータ取得、Webhookで外部送信
- 戦略変更：外部共有が閉じている場合は内部横持ち出し（別SaaS/ローカル同期）を検討

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：外部共有がデフォルト許可  
  - 次の検証：新規アイテム共有ダイアログで外部メール可否、公開リンク生成可否を確認  
  - 期待：可能ならデフォルト設定を所見として記録
- 仮説B：ユーザが外部アプリを自由に承認できる  
  - 次の検証：OAuthアプリ同意画面を表示し、管理者同意要否を確認  
  - 期待：ユーザ同意のみでトークン発行されるならリスク
- 仮説C：監査ログが不足  
  - 次の検証：共有変更/アプリ承認/ダウンロードイベントが記録されるか確認  
  - 期待：不足なら保持/出力設定を是正提案

## 手を動かす検証（Labs連動：観測点を明確に）
- 証跡ディレクトリ
~~~~
mkdir -p ~/keda_evidence/saas_share_02 2>/dev/null
cd ~/keda_evidence/saas_share_02
~~~~
- 取得する証跡：共有設定画面スクリーンショット/設定エクスポート、OAuth同意画面、監査ログサンプル
- 観測の取り方：同じリソースで共有先・リンク種別を変え、イベントの差分を確認
- 相関キー：{Resource, ShareType, ExternalDomain, AppId, Scope, EventTime}

## コマンド/リクエスト例
- SaaSごとの API/CLI（例：Microsoft Graph, Google Drive API, Slack Admin API）で共有設定・監査イベントを取得
~~~~
# 例：Graph API で SharePoint 共有リンク一覧を取得（適切な権限付与前提）
curl -H "Authorization: Bearer <TOKEN>" \
  "https://graph.microsoft.com/v1.0/sites/<site-id>/drive/items/<item-id>/permissions"
~~~~
- 見るべき箇所：link/type/scope/expiration、grantedTo、roles
- 使えないケース：管理者権限やAPI許可が無い場合（GUIで代替）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS：アクセス制御/データ保護の前提として、共有と外部連携の最小化と監査。  
  https://github.com/OWASP/ASVS
- WSTG：Configuration/Deployment Management と Authorization テストで共有設定・外部連携を確認。  
  https://owasp.org/www-project-web-security-testing-guide/
- PTES：情報収集→脆弱性分析で共有/外部連携の境界を評価。  
  https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：Exfiltration Over Web Service（T1567）、Valid Accounts（SaaSトークン）。  
  https://attack.mitre.org/

## 参考（必要最小限）
- Microsoft Graph sharing API：https://learn.microsoft.com/graph/api/resources/permission
- Google Drive permissions：https://developers.google.com/drive/api/guides/manage-sharing
- Slack admin/SCIM API：https://api.slack.com/admin

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`12_audit_logs_取得と相関（誰が何をいつ）.md`
- 関連 playbooks：なし
- 関連 labs / cases：任意

---

## 深掘りリンク（最大8）
- `03_m365_権限境界（アプリ登録_Consent）.md`
- `05_okta_サインオンポリシーとトークン境界.md`
- `06_google_workspace_oauth_スコープ境界.md`
- `10_saas_oauth_consent_phishing_成立条件.md`
- `13_shadow_it_発見（DNS_CASB_ログ）.md`
- `15_token_lifetime_更新と失効（SaaS側）.md`
- `28_exfiltration_持ち出し経路（DNS_HTTP_SMB）.md`
