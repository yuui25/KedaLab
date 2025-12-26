# 01_idp_連携（SAML OIDC OAuth）と信頼境界
SAML/OIDC/OAuth 連携で本人性・権限・信頼境界がどこで成立するかを観測し、誤設定リスクを特定する。

## 目的（この技術で到達する状態）
- 本人性がどこで確定するか（IdP/トークン/クッキー）、権限がどこで決まるか（claim/scope/属性）の境界を説明できる
- 連携フローを観測し、戻り先/パラメータ/署名/期限が適切かを Yes/No/Unknown で示せる
- 連携失敗や属性差分を A/B で比較し、攻撃成立条件（不正リダイレクト・属性偽装・委任の過剰化）を判断できる
- ログ（IdP/SP/プロキシ）で追える相関キーを提示し、是正策（設定・監査）を提案できる

## 前提（対象・範囲・想定）
- 対象：SAML/OIDC/OAuth を使う社内SSO/SaaS/業務Web/API 連携
- 想定環境：IdP/SP 役割が分離、ブラウザ/ネイティブ/SPA の混在を想定
- できること/やらないこと：許可された連携での観測とパラメータ差分のみ。任意のIdPなりすましや第三者宛は行わない
- 依存知識：HTTPリダイレクト、JWT/SAML 署名・検証、クッキー/セッションの基礎
- 扱う範囲：信頼・権限・委任境界の確認、代表的な誤設定の検証
- 扱わない：認証UIの脆弱性、OSINT系のIdP列挙

## 観測ポイント（プロトコル/データ/境界）
- 役割：IdP/SP/クライアント（OAuth）と信頼関係
- フロー：リダイレクト連鎖、state/nonce、Issuer/Audience、署名鍵と検証側
- 権限：SAML Attribute / OIDC ID Token claim / OAuth scope・consent、ロールマッピング
- 戻り先：redirect_uri/AssertionConsumerService の固定度、許可リスト
- 境界：どこでトークン発行/検証されるか、どのログが残るか

## 結果の意味（何が言える/言えない）
- 確定できる：本人性成立点、権限決定点、信頼先（IdP/外部アプリ）、戻り先の制約
- 推定できる：属性マッピングやscopeが過剰で越権余地があるか、検証責務の抜け
- 言えない：実際のビジネス権限正当性（担当確認が必要）
- 状態パターン
  - A：固定された戻り先＋署名検証＋最小属性（良好）
  - B：ワイルドカード戻り先＋過剰scope/属性（リスク高）
  - C：検証責務の曖昧さ（SP/ゲートウェイどちらも不明）

## 攻撃者視点での利用（意思決定）
- 狙い目：ワイルドカード redirect_uri、RelayState/State 混在、署名未検証、過剰claim/scope、外部IdP信頼
- 優先度：1) 戻り先制御 2) 署名/検証鍵 3) claim/scope とロールマッピング 4) トークン有効期限/再利用
- 攻め筋
  - 不正リダイレクト/オープンリダイレクトを経由してトークン回収
  - 属性/claim を悪用した越権（別テナント/別ロール）
  - OAuth consent の過剰scope取得
- 戦略変更：検証が強い場合は IdP 側設定の例外（外部IdP/動的登録）を調査

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：戻り先が緩い  
  - 次の検証：正規/異常 redirect_uri で state/nonce を変えずに試行  
  - 期待：拒否されない場合は不正リダイレクト余地
- 仮説B：claim/scope が権限に直結  
  - 次の検証：ロール違いユーザで SAML Attribute / ID Token claim / scope を比較  
  - 期待：差分が権限に直結し、操作結果が変わるかを確認
- 仮説C：署名・検証責務が曖昧  
  - 次の検証：Issuer/Audience/署名鍵と検証ログを確認（IdP or SP or Gateway）  
  - 期待：検証が一箇所なら責務明確、無いなら重大

## 手を動かす検証（Labs連動：観測点を明確に）
- 証跡ディレクトリ
~~~~
mkdir -p ~/keda_evidence/idp_01 2>/dev/null
cd ~/keda_evidence/idp_01
~~~~
- 取得する証跡：ブラウザネットワークログ(har)、SAML Response / JWT(ID/Access)、state/nonce、redirect_uri、発行者/受信者
- 観測の取り方：同一ユーザ・同一入口でパラメータのみ変更し差分を見る
- 相関キー：{User, App, Flow(SAML/OIDC/OAuth), redirect_uri, state/nonce, Iss/Aud}

## コマンド/リクエスト例（例示は最小限）
~~~~
# JWTのヘッダ/ペイロードを確認
python - <<'PY'
import jwt,sys
token=sys.stdin.read().strip()
print(jwt.get_unverified_header(token))
print(jwt.decode(token, options={"verify_signature": False}))
PY
~~~~
- 観測していること：iss/aud/sub/exp/nonce/claims の妥当性
- 出力の注目点：Issuer/Audience/exp/nbf、scope/role/tenant
- 使えないケース：暗号化SAML/暗号化JWTのみ提供の場合（IdP/ゲートウェイで復号確認が必要）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS：認証・セッションの前提として IdP 連携の信頼/署名/戻り先を固定する（AuthN/AuthZ 章）。  
  https://github.com/OWASP/ASVS
- WSTG：Authentication/Authorization テストで SSO フローとトークン検証を観測する。  
  https://owasp.org/www-project-web-security-testing-guide/
- PTES：Intelligence Gathering→Vulnerability Analysis で連携境界を確認、攻撃面（戻り先/属性/委任）を特定。  
  https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：Credential Access/Privilege Escalation（信頼崩壊によるトークン奪取・越権）。  
  https://attack.mitre.org/

## 参考（必要最小限）
- SAML/SSO 基本：https://www.oasis-open.org/standards#samlv2.0
- OIDC Core：https://openid.net/specs/openid-connect-core-1_0.html
- OAuth 2.0：https://datatracker.ietf.org/doc/html/rfc6749
- JWT：https://datatracker.ietf.org/doc/html/rfc7519

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`01_topics/02_web/02_authn_認証・セッション・トークン.md`
- 関連 playbooks：なし
- 関連 labs / cases：`04_labs/01_local/02_proxy_計測・改変ポイント設計.md`

---

## 深掘りリンク（最大8）
- `02_saas_共有・外部連携・監査ログの勘所.md`
- `10_saas_oauth_consent_phishing_成立条件.md`
- `14_sso_bypass_パス（ローカルログイン残存）.md`
- `15_token_lifetime_更新と失効（SaaS側）.md`
- `03_m365_権限境界（アプリ登録_Consent）.md`
- `05_okta_サインオンポリシーとトークン境界.md`
- `06_google_workspace_oauth_スコープ境界.md`
- `12_audit_logs_取得と相関（誰が何をいつ）.md`
