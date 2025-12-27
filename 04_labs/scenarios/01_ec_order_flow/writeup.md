# writeup.md（EC注文フロー）

## 注意事項（教育目的）
- 本資料は教育目的です。許可された環境のみで使用してください。
- 実システムへの適用・悪用は禁止です。
- 自己責任で利用し、作成者は一切の責任を負いません。

## 概要
このシナリオは、注文APIの境界（所有者/ロール/テナント）を差分観測で説明し、  
`kedaLab{...}` を取得するまでの「成立条件」を言語化する練習。

## 観測フロー（要点：参照するtopicsを明記）
1) Cookie属性の境界を観測する  
   - `01_topics/02_web/02_authn_01_cookie属性と境界（Secure_HttpOnly_SameSite_Path_Domain）.md`
2) セッション寿命/失効/固定化の差分を観測する  
   - `01_topics/02_web/02_authn_02_session_lifecycle（更新_失効_固定化_ローテーション）.md`
3) 認証CSRFとstate設計の有無を観測する  
   - `01_topics/02_web/02_authn_13_login_csrf_認証CSRFとstate設計.md`
4) ログアウト設計と無効化の成立点を観測する  
   - `01_topics/02_web/02_authn_14_logout_設計（RP_IdP_フロントチャネル）.md`
5) 多端末/同時ログイン制御の差分を観測する  
   - `01_topics/02_web/02_authn_15_session_concurrency（多端末_同時ログイン制御）.md`

## 成立条件（安全な書き方）
- “他ユーザーの注文にアクセスできる条件” を差分で特定する  
  例: 所有者境界が効いていない / テナント境界は効いている
- 入力条件は **型（どのIDをどこで変えるか）** を記述する

## 対象外/今回扱わないtopics（理由を明記）
- `01_topics/02_web/02_authn_03_token設計（Bearer_JWT_Refresh_Rotation）.md`  
  - 本シナリオはCookieセッション中心
- `01_topics/02_web/02_authn_04_sso_oidc_flow観測（state_nonce_code_PKCE）.md`  
  - OIDC未導入
- `01_topics/02_web/02_authn_05_sso_saml_flow観測（assertion_audience_recipient）.md`  
  - SAML未導入
- `01_topics/02_web/02_authn_06_mfa_成立点と例外パス（step-up_device_trust）.md`  
  - MFA未導入
- `01_topics/02_web/02_authn_07_client_storage（localStorage_sessionStorage_memory）.md`  
  - ストレージ設計は扱わない
- `01_topics/02_web/02_authn_08_device_binding（端末紐付け_IP_UA_fingerprint）.md`  
  - 端末紐付け未導入
- `01_topics/02_web/02_authn_09_password_policy（強度_漏えい照合_禁止語）.md`  
  - パスワード強度ポリシー未導入
- `01_topics/02_web/02_authn_10_password_reset_回復経路（token_失効_多要素）.md`  
  - パスワードリセット未導入
- `01_topics/02_web/02_authn_11_account_recovery_本人確認（サポート代行_回復コード）.md`  
  - 回復フロー未導入
- `01_topics/02_web/02_authn_12_bruteforce_rate-limit_lockout（例外パス）.md`  
  - レート制限/ロックアウト未導入
- `01_topics/02_web/02_authn_16_step-up_再認証境界（重要操作_再確認）.md`  
  - 重要操作の再認証未導入
- `01_topics/02_web/02_authn_17_refresh_token_rotation_盗用検知（reuse）.md`  
  - Refreshトークン未導入
- `01_topics/02_web/02_authn_18_token_binding（DPoP_mTLS）観測.md`  
  - DPoP/mTLS未導入
- `01_topics/02_web/02_authn_19_webauthn_passkeys_登録・回復境界.md`  
  - Passkey未導入
- `01_topics/02_web/02_authn_20_magic-link_メールリンク認証の成立条件.md`  
  - Magic Link未導入

## 取得した証跡（例）
- HAR（ログイン前/後、対象API）
- Proxyログ（差分比較）
- 相関ID（x-request-id）と監査ログの突合

## 対策方向性（最小）
- 所有者/テナントのサーバ側検証を一貫化
- 監査ログの相関キーを必須化
- UI≠API の差分を前提に検証を回す
