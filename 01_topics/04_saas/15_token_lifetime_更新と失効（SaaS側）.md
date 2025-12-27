# 15_token_lifetime_更新と失効（SaaS側）
SaaS 側のトークン有効期間・更新・失効挙動を観測し、持続リスクと封じ方を特定する。

## 目的（この技術で到達する状態）
- アクセストークン/IDトークン/リフレッシュトークン/長期セッションの有効期間と更新条件を把握し、持続リスクを Yes/No/Unknown で示せる
- 失効方法（手動失効/ローテーション/デバイス管理）と即時性を確認し、どこで検証されるかを説明できる
- ログでトークン発行/更新/失効が追えるか判断し、是正策を提示できる

## 前提（対象・範囲・想定）
- 対象：SaaS/IdP が発行する各種トークン、セッションCookie、Remember me/長期セッション設定
- 想定環境：複数デバイス/クライアント、SSO/IdP連携、MFAあり
- できること/やらないこと：設定確認と許可されたテストでの発行/更新/失効確認のみ。大量試行はしない
- 依存知識：OAuth/OIDC、セッション管理、デバイス/ブラウザ識別
- 扱う範囲：有効期間・更新条件・失効手段・ログ
- 扱わない：IdP側条件付きアクセス（別ファイル）

## 観測ポイント（プロトコル/データ/境界）
- 有効期間：アクセストークン/IDトークン/リフレッシュトークン/セッションCookie の exp・MaxAge
- 更新条件：リフレッシュローテーションの有無、グレース期間、Remember me の期限
- 失効：手動/管理者失効、パスワード変更/MFAリセット時の失効、デバイス紐付け解除
- 検証責務：どこで exp/iss/aud/nonce を検証するか（IdP/SP/Gateway）
- 監査：発行/更新/失効イベントのログ有無

## 結果の意味（何が言える/言えない）
- 確定できる：各トークンの期限、ローテーション有無、パスワード変更で失効するか、ログ有無
- 推定できる：持続リスク（長期リフレッシュ、ローテーション無効）、セッション固定の可能性
- 言えない：端末側の安全性（マルウェア有無）
- 状態パターン
  - A：短期アクセストークン＋リフレッシュローテーション＋パスワード変更で即失効（良好）
  - B：長寿命リフレッシュ＋ローテーションなし＋Remember me 長期（高リスク）
  - C：失効は提供されるがログ・検証責務が曖昧（部分的）

## 攻撃者視点での利用（意思決定）
- 狙い目：長寿命リフレッシュ、ローテーション無効、パスワード変更でも無効化されないトークン、Remember me 長期
- 優先度：1) リフレッシュ期限/ローテーション 2) パスワード変更時の失効 3) セッション固定の可否 4) ログ
- 攻め筋：トークン窃取後に長期利用、ローテーション無効を悪用、Remember me でMFA回避
- 戦略変更：期限が短い場合はブラウザ/デバイスのセッション復元やトークンキャッシュを狙う

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：リフレッシュローテーションが無効
  - 次の検証：同一リフレッシュトークンで複数回更新を試し、再利用できるか確認（許可範囲で）
  - 期待：再利用できるなら持続リスク
- 仮説B：パスワード変更でもトークンが失効しない
  - 次の検証：パスワード変更後に既存セッション/トークンが有効か確認
  - 期待：有効なら失効設計不足
- 仮説C：Remember me が長期
  - 次の検証：クッキー期限と再認証要否を確認
  - 期待：長期ならMFA回避リスク

## 手を動かす検証（Labs連動：観測点を明確に）
- 証跡ディレクトリ
~~~~
mkdir -p ~/keda_evidence/token_life_15 2>/dev/null
cd ~/keda_evidence/token_life_15
~~~~
- 取得する証跡：トークンのデコード結果(exp等)、更新/失効試験ログ、管理者設定画面
- 相関キー：{User, Client, TokenType, exp, RefreshRotation(Yes/No), PasswordChange(失効Yes/No)}

## コマンド/リクエスト例
~~~~
# JWT デコード（署名検証なし例）

## 前提知識（最低限）
- トークン種別（access/refresh）の違い
python - <<'PY'
import jwt,sys
token=sys.stdin.read().strip()
print(jwt.decode(token, options={"verify_signature": False}))
PY
~~~~
- 注目点：exp/iat/nbf/iss/aud、nonce、refresh_token の有効期限
- 使えないケース：暗号化トークンのみの場合（IdP側で確認）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS：セッション管理・トークン失効要件。
  https://github.com/OWASP/ASVS
- WSTG：Authentication/Session Management テストで期限/失効を確認。
  https://owasp.org/www-project-web-security-testing-guide/
- PTES：情報収集→脆弱性分析で長寿命トークンを棚卸し。
  https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：Valid Accounts、Defense Evasion（長期トークン保持）。
  https://attack.mitre.org/

## 参考（必要最小限）
- OAuth Token Lifetime ベストプラクティス（各IdPドキュメント）
- Refresh Token Rotation（例：Auth0/Okta/Azure AD）
- セッション管理のセキュリティ考慮事項

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`01_idp_連携（SAML OIDC OAuth）と信頼境界.md`
- 関連 playbooks：なし
- 関連 labs / cases：任意

---

## 深掘りリンク（最大8）
- `03_m365_権限境界（アプリ登録_Consent）.md`
- `05_okta_サインオンポリシーとトークン境界.md`
- `06_google_workspace_oauth_スコープ境界.md`
- `14_sso_bypass_パス（ローカルログイン残存）.md`
