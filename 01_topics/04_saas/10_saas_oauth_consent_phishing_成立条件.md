# 10_saas_oauth_consent_phishing_成立条件
SaaS/OAuth の同意フィッシングが成立する条件を観測し、封じ方を示す。

## 目的（この技術で到達する状態）
- 同意フィッシングに必要な要素（外部アプリ許可、ユーザ同意可、危険スコープ）を列挙し、成立可否を Yes/No/Unknown で示せる
- 誘導経路（メール/リンク/QR）と検証責務（発行者/redirect_uri/スコープ）を把握し、検知ポイントを提示できる
- 是正策（外部アプリ制限、同意ワークフロー、警告表示、監査）を提案できる

## 前提（対象・範囲・想定）
- 対象：SaaS/IdP（Azure AD/Google/Okta 等）のOAuth同意フロー
- 想定環境：ユーザ同意が許可される可能性がある
- できること/やらないこと：正規フローでの観測のみ。実際のフィッシングメール送信は行わない
- 依存知識：OAuth 2.0、同意画面、scopes、発行者検証
- 扱う範囲：成立条件、検知・是正
- 扱わない：メール/ブラウザの脆弱性利用

## 観測ポイント（プロトコル/データ/境界）
- 外部アプリ許可設定、ユーザ同意の可否、検証済み発行者（verified publisher）の要否
- redirect_uri の制限、state/nonce の有無、スコープ内容（高権限か）
- 同意画面のブランド表示と発行者名、メール/リンク誘導のドメイン
- 監査：同意イベント、アプリ登録/権限付与のログ

## 結果の意味（何が言える/言えない）
- 確定できる：外部/ユーザ同意の可否、スコープの危険度、redirect_uri制限、検証済み発行者有無
- 推定できる：フィッシングが成立する可能性（ユーザが承認すれば権限付与されるか）
- 言えない：実際の被害規模（ユーザ行動依存）
- 状態パターン
  - A：外部/ユーザ同意禁止＋検証済み発行者のみ＋高権限は管理者同意（良好）
  - B：ユーザ同意許可＋高権限スコープ＋redirect_uri緩い（高リスク）
  - C：外部同意不可だが既存アプリが高権限（持続リスク）

## 攻撃者視点での利用（意思決定）
- 狙い目：外部同意許可、検証済み発行者要件なし、高権限スコープ、長寿命トークン
- 優先度：1) 同意ポリシー 2) スコープ 3) redirect_uri/verified publisher 4) 監査ログ
- 攻め筋：偽ブランドの同意画面でスコープ承認を取る、マルチテナントアプリで外部テナントを狙う
- 戦略変更：同意が厳しい場合は既存承認済みアプリの権限昇格/トークン長寿命を確認

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：ユーザ同意が許可
  - 次の検証：同意ポリシー設定を確認し、ユーザが高権限スコープに同意できるかをテスト（許可範囲で）
  - 期待：可能なら同意フィッシング成立余地
- 仮説B：redirect_uri が緩い
  - 次の検証：許可リスト/ワイルドカード有無を確認
  - 期待：緩い場合はコード/トークン窃取の余地
- 仮説C：verified publisher 要件なし
  - 次の検証：検証済み発行者の強制設定有無を確認
  - 期待：なしならブランド偽装余地

## 手を動かす検証（Labs連動：観測点を明確に）
- 証跡ディレクトリ
~~~~
mkdir -p ~/keda_evidence/oauth_phish_10 2>/dev/null
cd ~/keda_evidence/oauth_phish_10
~~~~
- 取得する証跡：同意ポリシー設定、同意画面スクリーンショット、同意イベントログ
- 相関キー：{AppId, Publisher, Scope, ConsentType(User/Admin), RedirectURI, EventTime}

## コマンド/リクエスト例
~~~~
# 例：OAuth 認可リクエストを生成（実行は自テナント・検証用ドメインのみ）

## 追加観点
- 検知/対応の動線を明示する
https://login.microsoftonline.com/<tenant>/oauth2/v2.0/authorize?
client_id=<APPID>&response_type=code&redirect_uri=<REDIRECT>&scope=<SCOPES>&state=xyz&nonce=abc
~~~~
- 観測：同意画面での発行者表示、スコープ内容、redirect_uri が許可されるか
- 使えないケース：外部同意が完全禁止のテナント

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS：外部連携と認証情報保護の観点で、発行者検証と同意制御を強制。
  https://github.com/OWASP/ASVS
- WSTG：Authentication/Authorization テストで OAuth 設定と同意画面を確認。
  https://owasp.org/www-project-web-security-testing-guide/
- PTES：情報収集→脆弱性分析で同意ポリシーとスコープを棚卸し。
  https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：Valid Accounts（Cloud）、Phishing (T1566) との組み合わせ。
  https://attack.mitre.org/

## 参考（必要最小限）
- OAuth 2.0：https://datatracker.ietf.org/doc/html/rfc6749
- Verified publisher（Azure AD）：https://learn.microsoft.com/azure/active-directory/develop/publisher-verification-overview
- Google 外部アプリ制限：https://support.google.com/a/answer/7281227

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`03_m365_権限境界（アプリ登録_Consent）.md`
- 関連 playbooks：なし
- 関連 labs / cases：任意

---

## 深掘りリンク（最大8）
- `06_google_workspace_oauth_スコープ境界.md`
- `04_azuread_条件付きアクセス（CA）と例外パス.md`
- `15_token_lifetime_更新と失効（SaaS側）.md`
