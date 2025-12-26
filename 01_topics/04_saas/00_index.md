# 00_index（SaaS）
SaaS/IdP/外部連携を「資産・信頼・権限・共有・監査」の境界で捉え、Web/NWと同じ粒度で扱うための案内です。ChatGPT が読むだけで各ファイルの狙いが分かるよう要約しています。

## 目的
- SaaSを“サービス紹介”で終わらせず、境界（本人性/権限/共有/外部連携/監査）で説明できるようにする。
- SSO/共有/外部アプリ/監査ログを観測し、越境リスクと是正を Yes/No/Unknown で出す。
- 次の検証へ持ち込む仮説A/Bと観測点を用意する（許可スコープ内・低アクティブ）。

## ガイドライン位置づけ
- ASVS：認証・認可・監査が SaaS 連携で成立/崩れる前提を固める。
- WSTG：SSO/外部連携/設定ミスを Web テストの一部として観測点を供給。
- PTES：Intelligence Gathering で連携先と責任境界を確定し、以降の検証をずらさない。
- MITRE ATT&CK：Credential Access / Collection / Exfiltration / Privilege Escalation を SaaS 側の境界崩壊として説明。

## 主なアウトプット
- 境界メモ（資産/信頼/権限/共有/監査）と外部依存一覧。
- 連携の入口（SSO/OAuth/外部アプリ/Webhook/共有）の棚卸しと優先度。
- 次の検証方針（仮説A/Bと観測点）を Web/Network へ接続。

## 読み進めのおすすめ
1) `01_idp_連携（SAML OIDC OAuth）と信頼境界.md`
2) `02_saas_共有・外部連携・監査ログの勘所.md`
3) 各サービス別の権限/ポリシー系（03–09）
4) 攻撃経路/検知系（10–15）

## ファイル概要（ダイジェスト）
- 01_idp_連携（SAML OIDC OAuth）と信頼境界：本人性/権限がどこで成立し、誰を信頼するか。
- 02_saas_共有・外部連携・監査ログの勘所：共有設定・外部アプリ・監査ログの成立条件。
- 03_m365_権限境界（アプリ登録_Consent）：同意モデルと危険権限。
- 04_azuread_条件付きアクセス（CA）と例外パス：CA 適用/例外/信頼済み場所。
- 05_okta_サインオンポリシーとトークン境界：サインオン/アプリポリシーとトークン寿命。
- 06_google_workspace_oauth_スコープ境界：外部アプリ許可、制限スコープ、DWD。
- 07_github_組織権限境界（PAT_App_Actions）：PAT/Apps/Actions 権限とシークレット漏えい経路。
- 08_slack_トークン境界（xox_署名検証）：トークン種別/スコープと署名検証・Webhook。
- 09_atlassian_外部連携と権限境界：PAT/OAuth/Webhook と権限/共有設定。
- 10_saas_oauth_consent_phishing_成立条件：同意フィッシング成立条件と封じ方。
- 11_scim_jit_provisioning_境界（権限初期値）：SCIM/JIT の初期ロールとマッピング。
- 12_audit_logs_取得と相関（誰が何をいつ）：監査ログの有無・保持・相関キー。
- 13_shadow_it_発見（DNS_CASB_ログ）：Shadow IT の検出と対処。
- 14_sso_bypass_パス（ローカルログイン残存）：SSO 強制の例外経路と封じ方。
- 15_token_lifetime_更新と失効（SaaS側）：トークン寿命/更新/失効の成立条件と持続リスク。

## 接続先
- ASM/OSINT：`01_topics/01_asm-osint/00_index.md`
- Web：`01_topics/02_web/00_index.md`
- Network：`01_topics/03_network/00_index.md`
- ローカル証跡取得：`04_labs/01_local/02_proxy_計測・改変ポイント設計.md`, `04_labs/01_local/03_capture_証跡取得（pcap_har_log）.md`
