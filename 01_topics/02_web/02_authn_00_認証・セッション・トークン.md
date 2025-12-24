# 02_authn_00_認証・セッション・トークン
認証（AuthN）を「ログインできる/できない」で終わらせず、**本人性がどこで・何で・いつ確定し、どの範囲に伝播するか** を観測で説明する

---

## 目的（この技術で到達する状態）
- 認証（AuthN）を「ログインできる/できない」で終わらせず、**本人性がどこで・何で・いつ確定し、どの範囲に伝播するか** を観測で説明できる。
- セッション（Cookie）/トークン（Bearer/JWT等）を、**境界（ドメイン/パス/テナント/端末/ブラウザ）** と **成立条件（更新/失効/再認証/MFA）** の観点で理解し、検証に使える。
- 次の認可（AuthZ）検証に繋がる「権限伝播の入口（どの属性が何に効くか）」を確定できる。

## 前提（対象・範囲・想定）
- 対象：許可された範囲のWebアプリ/環境のみ。
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - SSO（SAML/OIDC）、MFA、SPA+API、CDN/WAF、SaaS連携が一般的。
- できること/やらないこと（安全に検証する範囲）：
  - やらないこと：破壊的試験や過剰負荷。認証系は特にロック/監視に注意し、最小観測で判断する。
- 依存する前提知識（必要最小限）：
  - `01_topics/02_web/01_web_00_recon_入口・境界・攻め筋の確定.md`
  - `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
  - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：
    - 認証の成立点（どこでCookie/トークンが発行されるか）
    - セッション境界（Cookieのスコープ、ライフサイクル）
    - トークン境界（Bearer/JWT等の伝播範囲）
    - SSO/MFAの越境点
    - 認証状態の条件差（未ログイン/ログイン、端末差、期限差）
  - 扱わない（別ユニットへ接続）：
    - Cookie属性の詳細 → `01_topics/02_web/02_authn_01_cookie属性と境界（Secure_HttpOnly_SameSite_Path_Domain）.md`
    - セッションライフサイクルの詳細 → `01_topics/02_web/02_authn_02_session_lifecycle（更新_失効_固定化_ローテーション）.md`
    - トークン設計の詳細 → `01_topics/02_web/02_authn_03_token設計（Bearer_JWT_Refresh_Rotation）.md`
    - SSO/OIDCの詳細 → `01_topics/02_web/02_authn_04_sso_oidc_flow観測（state_nonce_code_PKCE）.md`
    - SSO/SAMLの詳細 → `01_topics/02_web/02_authn_05_sso_saml_flow観測（assertion_audience_recipient）.md`
    - MFAの詳細 → `01_topics/02_web/02_authn_06_mfa_成立点と例外パス（step-up_device_trust）.md`

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) 認証の“成立点”を特定する
- 認証開始：どのURL/どのリダイレクトで始まるか（アプリ/IdP）
- 認証成立：どのレスポンスで「状態が変わる」か（Set-Cookie、トークン返却、302先など）
- 認証確認：どのリクエストで“ログイン済み”が判定されるか（/me、/session、/profile等）

### 2) セッション境界（Cookie）
- Cookieのスコープ
  - Domain / Path：どこまで届くか（サブドメイン/アプリ領域）
  - SameSite：クロスサイト遷移（SSO/外部遷移）で影響する
  - Secure/HttpOnly：輸送/JSアクセス境界
- セッションのライフサイクル
  - 発行、更新（回転/延長）、失効（ログアウト/タイムアウト）
  - 並行セッション（複数端末/複数ブラウザ）での挙動差

### 3) トークン境界（Bearer/JWT等）
- どこに現れるか：Authorizationヘッダ、Cookie、ローカルストレージ等（観測で確認）
- 何が含まれるか：sub/uid、tenant、role/scope、exp/iat、aud/iss（断定せず観測で）
- どこまで伝播するか：フロント→API、API→バックエンドで何が渡るか

### 4) SSO/MFAがある場合の“越境点”
- IdPドメインへのリダイレクト（state/nonce等の有無、戻り先のパターン）
- MFA成立の境界（追加チャレンジの挿入点）
- “越境”に伴う条件差（SameSite、サブドメイン、ブラウザ設定、端末差）

### 5) 条件差（同じ操作でも結果が変わる条件）
- 未ログイン/ログイン、端末差、ブラウザプロファイル差
- セッション期限（時間経過）での挙動差
- ログアウト後の残存（キャッシュ、再ログイン不要など）の有無

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が"確定"できるか：
  - 認証の成立点（どこでCookie/トークンが発行されるか）
  - セッション/トークンのスコープ（どこまで届くか、何が境界か）
  - 認証状態がAPIにどう反映されるか（どのヘッダ/Cookieが鍵か）
- 何が"推定"できるか（推定の根拠/前提）：
  - IdP/アプリの責任分界（どこが外部依存か）
  - トークンの意味（tenant/role/scope等）が何に効くか（認可検証へ繋ぐ）
- 何は"言えない"か（不足情報・観測限界）：
  - 認証が正しい/安全の断定（実装詳細、バックエンド挙動まで必要）
  - MFAの強度評価（運用や実装の詳細が必要）
  - "HttpOnlyだから安全"の断定（別経路の成立条件があり得る）
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：認証はSSOで、境界が複数ドメインに跨っている → リダイレクトの流れと、Cookie/トークンがどのドメインで発行されるかを確定する
  - パターンB：SPA+APIで、認証はトークン（Bearer等）が鍵 → API呼び出しをProxyでトレースし、どのヘッダ/トークンが必須かを確定する
  - パターンC：ログアウトしても一部が生き残る/条件で再ログイン不要になる → ログアウト時に消えるCookie/残るCookieを比較する

## 攻撃者視点での利用（意思決定：次に何を深掘りするか）
- 認証の“鍵”を特定する
  - 何を持っていればログイン状態として扱われるか（Cookie/Token/両方/別ヘッダ）
- 越境点を把握する
  - SSO/外部遷移で、どの境界（ドメイン/サイト）を跨ぐか
- 認可検証の準備をする
  - token/cookie内の tenant/role/scope が見えれば、次のAuthZで「境界モデル」を立てやすい
- API中心の場合
  - UIではなくAPIが主戦場になるため、認証状態がAPIにどう伝播するかを優先して固める

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：認証はSSOで、境界が複数ドメインに跨っている
  - 次の検証：
    - リダイレクトの流れと、Cookie/トークンがどのドメインで発行されるかを確定する
    - SameSite/Domain/Pathの条件差で、成立が変わるかを最小セットで観測する
  - 期待する観測：
    - “どこで本人性が成立し、どこまで届くか”が説明できる
- 仮説B：SPA+APIで、認証はトークン（Bearer等）が鍵
  - 次の検証：
    - API呼び出しをProxyでトレースし、どのヘッダ/トークンが必須かを確定する
    - トークン更新（refresh）や失効の境界を観測する
  - 期待する観測：
    - “何が鍵か”が確定し、AuthZ（IDOR/BOLA）検証の前提が整う
- 仮説C：ログアウトしても一部が生き残る/条件で再ログイン不要になる
  - 次の検証：
    - ログアウト時に消えるCookie/残るCookieを比較する
    - 別プロファイル/別端末で同条件を再現し、原因がキャッシュかセッションか切り分ける
  - 期待する観測：
    - 認証状態の境界が整理され、誤判定（ログイン扱いのズレ）を防げる

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
    - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- 取得する証跡（目的ベースで最小限）：
  - HAR + Proxyログ + 検証メモ
  - 未ログインで入口にアクセス → ログイン実施 → ログイン後の同画面/同APIを再アクセス
  - 追加：ログアウト → 同操作を再度（残存差分を見る）
- 観測の取り方（どの視点で差分を見るか）：
  - メモに必ず残す項目：視点（端末/経路/プロファイル）、成立点（どのレスポンスで状態が変わったか）、鍵（どのCookie/ヘッダ/トークンが必須か）、条件差（SameSite/Domain/期限/端末差）
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/authn 2>/dev/null
    cd ~/keda_evidence/authn
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可されたスコープ** のみ
      - 観測は **最小限の差分セット** のみ（破壊的試験や過剰負荷は行わない）
      - 認証系は特にロック/監視に注意し、最小観測で判断する
  - 相関キー（最低限）を作る（後で必ず効く）
    - Host、User、Time、Cookie/Token、認証状態（未ログイン/ログイン/ログアウト）、成立点（どのレスポンスで状態が変わったか）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は"手段"であり"結論"ではない。必ず「何を観測している例か」を添える。

~~~~
# 例：未ログインで入口を観測（ログイン誘導・リダイレクト）
curl -i -L https://example.com/

# 例：APIの認証要否を観測（401/403/200の差分）
curl -i https://api.example.com/me
~~~~

- この例で観測していること：
  - 認証境界（入口）と、APIが認証前に見える範囲
- 出力のどこを見るか（注目点）：
  - ステータス、Location、Set-Cookie、WWW-Authenticate等
- この例が使えないケース（前提が崩れるケース）：
  - JS必須/SSO必須の場合、curlだけでは成立しない（ブラウザ+HAR/Proxyで観測へ）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：認証、セッション管理、トークン処理の要件に直接接続する。成立点と境界を観測で確定し、以後の検証観点を外さないための基盤。
  - 該当要件（可能ならID）：認証、セッション管理、トークン処理の要件
  - このファイルの内容が「満たす/破れる」ポイント：
    - 満たす：成立点と境界を観測で確定し、以後の検証観点を外さないための基盤。
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：認証（Authentication Testing）とセッション管理（Session Management Testing）へ直結。未ログイン/ログイン/ログアウトの差分観測で境界を固める。
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：認証境界の観測と理解
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Vulnerability Analysisで"認証境界"を誤ると全検証がズレるため、入口確定→成立点確定→鍵の特定の順で土台を作る。
  - 前後フェーズとの繋がり（1行）：入口確定→成立点確定→鍵の特定の順で土台を作る。
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Credential Access / Valid Accounts
  - 攻撃者の目的（この技術が支える意図）：Credential Access/Valid Accounts等の戦術・技術に直接"手法"として寄せるのではなく、検証側では「本人性の成立条件」を観測して理解する（分類で終わらせない）。
  - 参照：https://attack.mitre.org/tactics/TA0006/（Credential Access）、https://attack.mitre.org/tactics/TA0001/（Initial Access - Valid Accounts）

## 参考（必要最小限）
- OWASP Application Security Verification Standard: https://github.com/OWASP/ASVS
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- PTES (Penetration Testing Execution Standard): https://pentest-standard.readthedocs.io/
- MITRE ATT&CK: https://attack.mitre.org/

## リポジトリ内リンク（最大3つまで）
- 関連 labs：`04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
- 関連 labs：`04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- 関連 topics：`01_topics/02_web/01_web_00_recon_入口・境界・攻め筋の確定.md`

---

## 深掘りリンク（最大8）
- `01_topics/02_web/02_authn_01_cookie属性と境界（Secure_HttpOnly_SameSite_Path_Domain）.md`
- `01_topics/02_web/02_authn_02_session_lifecycle（更新_失効_固定化_ローテーション）.md`
- `01_topics/02_web/02_authn_03_token設計（Bearer_JWT_Refresh_Rotation）.md`
- `01_topics/02_web/02_authn_04_sso_oidc_flow観測（state_nonce_code_PKCE）.md`
- `01_topics/02_web/02_authn_06_mfa_成立点と例外パス（step-up_device_trust）.md`
- `01_topics/02_web/03_authz_00_認可（IDOR BOLA BFLA）境界モデル化.md`
- `01_topics/02_web/04_api_00_権限伝播・入力・バックエンド連携.md`
- `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`

---
