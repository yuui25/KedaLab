# 06_google_workspace_oauth_スコープ境界
Google Workspace の OAuth スコープとアプリ信頼設定を観測し、越権の成立条件を特定する。

## 目的（この技術で到達する状態）
- OAuth クライアントの種類（内部/外部）とスコープ許可（リスク分類）を把握し、誰が同意できるかを説明できる
- ドメイン全体の委任（Domain-wide Delegation）の有無と影響を Yes/No/Unknown で示せる
- 監査ログでアプリ承認/トークン発行を追えるか判断し、是正策を提示できる

## 前提（対象・範囲・想定）
- 対象：Google Cloud Console のOAuthクライアント、WorkspaceのAPIアクセス制御、DWD設定
- 想定環境：外部アプリの利用、Marketplace アプリ、Service Account DWD が存在する可能性
- できること/やらないこと：設定確認とログ確認のみ。権限付与・削除は行わない
- 依存知識：OAuth 2.0、Google スコープ分類（制限/非推奨/機密）、Service Account
- 扱う範囲：スコープ境界、承認モデル、監査
- 扱わない：アプリ実装の脆弱性

## 観測ポイント（プロトコル/データ/境界）
- OAuthクライアント：内部/外部設定、承認済みリダイレクトURI、発行元
- スコープ：制限付き/機密/非機密、要求スコープ一覧、consent screen のリスク表示
- DWD：Service Account の client id と許可スコープ、対象グループ/ユーザ
- 監査：Admin Audit（OAuth承認、DWD変更）、Token/Drive/Calendar などのアクセスログ

## 結果の意味（何が言える/言えない）
- 確定できる：外部アプリ同意可否、要求スコープ、DWD 設定有無、承認済みクライアント一覧
- 推定できる：制限スコープ要求や外部クライアントによるデータ取得リスク
- 言えない：個別アプリの正当性（オーナー確認が必要）
- 状態パターン
  - A：外部制限＋DWDなし＋承認済みアプリ審査済み（良好）
  - B：外部アプリ自由＋制限スコープ要求＋DWD有効（高リスク）
  - C：外部は禁止だがDWDが広い（内部からの越権リスク）

## 攻撃者視点での利用（意思決定）
- 狙い目：外部アプリ許可、DWDで広いスコープ付与、制限スコープを要求する Marketplace/非審査アプリ
- 優先度：1) 外部アプリ許可設定 2) DWD スコープ 3) 承認済みアプリ一覧 4) 監査ログ
- 攻め筋：外部アプリ同意フィッシング、DWD サービスアカウントキー流出による全域アクセス
- 戦略変更：外部が閉じている場合は既存承認済みアプリ/Service Account キー管理を確認

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：外部アプリが許可  
  - 次の検証：APIアクセス制御で「外部アプリを許可」が有効か確認、consent screen 種別を見る  
  - 期待：許可ならフィッシング成立余地
- 仮説B：DWD が有効  
  - 次の検証：セキュリティ > API の管理で DWD 設定を確認し、client id とスコープを抽出  
  - 期待：広いスコープなら越権余地
- 仮説C：制限スコープが要求されている  
  - 次の検証：承認済みアプリのスコープ一覧を確認し、制限スコープが含まれるか確認  
  - 期待：含まれる場合は承認プロセス/審査要否を確認

## 手を動かす検証（Labs連動：観測点を明確に）
- 証跡ディレクトリ
~~~~
mkdir -p ~/keda_evidence/gws_oauth_06 2>/dev/null
cd ~/keda_evidence/gws_oauth_06
~~~~
- 取得する証跡：API アクセス制御設定、承認済みアプリ一覧、DWD 設定画面、Admin Audit ログ抜粋
- 相関キー：{ClientId, AppType(internal/external), Scopes, DWD(Yes/No), EventTime}

## コマンド/リクエスト例
~~~~
# Admin SDK: DWD 設定取得例（要権限）
curl -H "Authorization: Bearer <TOKEN>" \
  "https://admin.googleapis.com/admin/directory/v1/customer/my_customer/delegatedAdmin/roles"
~~~~
- 注目点：client id と scopes、external/internal の設定
- 使えないケース：API 権限不足（管理者承認が必要）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS：データ保護/アクセス制御の前提として、外部アプリ制御とスコープ最小化。  
  https://github.com/OWASP/ASVS
- WSTG：Configuration/Authorization テストで OAuth 設定を確認。  
  https://owasp.org/www-project-web-security-testing-guide/
- PTES：情報収集→脆弱性分析でスコープ/外部アプリ/委任を棚卸し。  
  https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：Valid Accounts（Cloud）、Exfiltration Over Web Service。  
  https://attack.mitre.org/

## 参考（必要最小限）
- APIアクセス制御：https://support.google.com/a/answer/7281227
- スコープ分類：https://developers.google.com/identity/protocols/oauth2/scopes
- DWD：https://developers.google.com/identity/protocols/oauth2/service-account#delegatingauthority

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`10_saas_oauth_consent_phishing_成立条件.md`
- 関連 playbooks：なし
- 関連 labs / cases：任意

---

## 深掘りリンク（最大8）
- `03_m365_権限境界（アプリ登録_Consent）.md`
- `05_okta_サインオンポリシーとトークン境界.md`
- `12_audit_logs_取得と相関（誰が何をいつ）.md`
- `13_shadow_it_発見（DNS_CASB_ログ）.md`
