# 03_authn_観測ポイント（SSO_MFA前提）
AuthN/SSO/MFA/セッションの成立点を観測で確定し、例外・寿命・次の深掘り（AuthZ/API/SaaS/creds）を分岐で決める。

## 目的（このプレイブックで到達する状態）
- 本人性がどこで成立するか（アプリ内/IdP/両方）を、根拠付きで説明できる。
- セッション材料（Cookie/Token/Refresh/端末紐付け）と寿命（更新/失効）を Yes/No/Unknown で整理できる。
- MFA/再認証（step-up）の適用条件と例外を、観測で列挙できる。
- 次に進むべきトピック（AuthZ/API/SaaS/creds）を迷わず選べる。

## 前提知識チェックリスト（先に確認）
- 境界：本人性が成立する地点（アプリ/IdP）
- 差分観測：同一操作の条件差（同端末/別端末、短時間/時間経過）
- 成立条件：何が揃うとログインが成立するか

## 前提（対象・範囲・制約）
- 対象：許可範囲のログイン導線（UI/API/モバイル）、SSO導線（IdP）、MFA導線。
- 制約：認証試行は最小回数（連打しない）。ロックアウトや監視を意識して“代表点のみ”。
- 前提ツール（最小限）：ブラウザ+Proxy(HAR)、（任意）JWTデコード、スクショ。
  - 理由：HARで成立点、JWTで寿命/権限材料を確認できるため。
  - 代替：トークン解析はブラウザ拡張やオンラインデコーダでも可（実環境では扱い注意）。
- 参照すべきtopics（最初に読む/途中で参照）：
  - 総論：`01_topics/02_web/02_authn_00_認証・セッション・トークン.md`
  - Cookie：`01_topics/02_web/02_authn_01_cookie属性と境界（Secure_HttpOnly_SameSite_Path_Domain）.md`
  - セッション寿命：`01_topics/02_web/02_authn_02_session_lifecycle（更新_失効_固定化_ローテーション）.md`
  - トークン設計：`01_topics/02_web/02_authn_03_token設計（Bearer_JWT_Refresh_Rotation）.md`
  - OIDC：`01_topics/02_web/02_authn_04_sso_oidc_flow観測（state_nonce_code_PKCE）.md`
  - SAML：`01_topics/02_web/02_authn_05_sso_saml_flow観測（assertion_audience_recipient）.md`
  - MFA：`01_topics/02_web/02_authn_06_mfa_成立点と例外パス（step-up_device_trust）.md`
  - ログインCSRF：`01_topics/02_web/02_authn_13_login_csrf_認証CSRFとstate設計.md`
  - ログアウト：`01_topics/02_web/02_authn_14_logout_設計（RP_IdP_フロントチャネル）.md`
  - SaaS/IdP：`01_topics/04_saas/01_idp_連携（SAML OIDC OAuth）と信頼境界.md`
  - creds：`01_topics/03_network/03_creds_認証情報の所在と扱い（攻撃 検知の両面）.md`

## 入口で確定すること（最小セット）
- 認証方式：SSO（OIDC/SAML）か、ローカルログインか、魔法リンク等があるか。
- セッション材料：Cookie/Token/Refresh がどこにあり、期限がどれか。
- MFA：必須/条件付き/例外（信頼済み端末/ネットワーク/remember）を列挙。
- 完了条件：上記が Yes/No/Unknown で埋まり、次に深掘りする方向が決まる。

## 所要時間の目安
- 全体：40〜60分

## 具体的に実施する方法（最小セット）
### 1) 入口のリダイレクトを保存（SAML/OIDCの当たり）
~~~~
curl -sS -I -L https://example.com/login > 01_login_follow.txt
~~~~
- 注目点：
  - SAML寄り：`SAMLRequest` / `SAMLResponse`
  - OIDC寄り：`/authorize`、`code=`、`/.well-known/openid-configuration`

### 2) OIDC候補なら well-known を確認
~~~~
curl -sS https://example.com/.well-known/openid-configuration > 02_oidc_wellknown.json
~~~~

### 3) 誤判定時の対処
- SAML/OIDCが曖昧なら「混在/例外」として入口を変えて再観測し、差分を `03_mixed_notes.txt` に残す

## 手順（分岐中心：迷うポイントだけ）

### Step 0：最初の5分（必ずやる / 目安: 5分）
- 目的：以降の観測を“比較可能”にする。
- 観測ポイント：
  - テスト主体を2つ準備：ユーザA（一般）/ユーザB（別ロール or 別テナント）。無理なら Unknown として進む。
  - ブラウザプロファイルを固定（シークレットウィンドウ推奨）。ProxyでHAR取得を有効化。
  - “代表フロー”を1つ決める：`ログイン → トップ表示` まで。
- 証跡（最小）：
~~~~
# Windows (PowerShell)
$dir = Join-Path $HOME "keda_evidence\\authn_03"
New-Item -ItemType Directory -Force $dir | Out-Null
Set-Location $dir
"base_url: ...`nuserA: ...`nuserB: ...`nflow: login->home" | Set-Content -Encoding utf8 00_context.txt

# macOS/Linux (bash)
mkdir -p ~/keda_evidence/authn_03
cd ~/keda_evidence/authn_03
printf "base_url: ...\nuserA: ...\nuserB: ...\nflow: login->home\n" > 00_context.txt
~~~~
- 次の分岐：
  - 代表フローが決まった → Step 1へ
- 実際の観測例：
  - `flow: login -> home -> /me`

### Step 1：フロー観測（入口→リダイレクト→成立点）を1回だけ取る（目安: 10分）
- 目的：認証が“どこで”成立するかを確定する（UI感覚ではなく観測）。
- 観測ポイント（HARで見る）：
  - ドメイン遷移：`app → idp → app` の有無（どのドメインを跨ぐか）
  - 結合パラメータ：OIDCなら `state/nonce/code`、SAMLなら `RelayState` の存在
  - 成功時に増えるもの：`Set-Cookie`/`Authorization`/`token`レスポンス
- 証跡（最小）：
  - HAR（login開始→ログイン完了→トップ表示）
  - `Set-Cookie` と `Location` の抜粋メモ
- 次の分岐：
  - 外部IdPへ遷移する → Step 2B（SSO）
  - アプリ内で完結する → Step 2A（ローカル）
- 実際の観測例：
  - `Set-Cookie: session=...` がログイン直後に増える

### Step 2A：ローカル認証（Cookie/セッション境界が本体 / 目安: 8分）
- 目的：セッション材料と寿命を観測で確定し、固定化/更新/失効の次検証へ繋げる。
- 観測ポイント：
  - Cookie属性：Secure/HttpOnly/SameSite/Path/Domain、Expires/Max-Age
  - セッション更新：同一セッションでの延命（sliding）/再発行/固定化の兆候
  - ログインCSRF対策：ログインPOSTにCSRF token/state相当があるか
- 次の分岐：
  - Cookieが長寿命/更新が曖昧 → Step 4（寿命/失効観測を優先）
  - ロール差で見える機能が変わる → `02_playbooks/04_authz_境界モデル→検証観点チェック.md` へ
- 実際の観測例：
  - `Set-Cookie` に `Max-Age=86400` が付与される

### Step 2B：SSO（OIDC/SAML の成立点が本体 / 目安: 10分）
- 目的：SSOで何を信頼し、何を検証しているか（iss/aud/署名/PKCE等）を観測で確定する。
- 観測ポイント（どちらかを見分ける）：
  - OIDCっぽい：`/authorize` `code=` `state=` `nonce=` `pkce(code_challenge)` が見える
  - SAMLっぽい：`SAMLResponse` `RelayState` `ACS` が見える
- 次の分岐：
  - OIDC → Step 3A
  - SAML → Step 3B
  - 判別できない（ゲートウェイ等で隠れる） → Step 3C（アプリ側セッション材料から逆算）
- 実際の観測例：
  - `SAMLResponse` がPOSTボディに含まれる

#### OIDC / SAML 判定の簡易フロー
~~~~
authorize/code/state/nonce が見える -> OIDC
SAMLResponse/RelayState/ACS が見える -> SAML
どちらも見えない -> Step 3C（アプリ側から逆算）
~~~~

### Step 3A：OIDC観測（state/nonce/code/PKCE / 目安: 10分）
- 目的：OIDCの“結合材料”と“検証責務”を確定し、次の検証方針（AuthZ/Token/CA）を作る。
- 観測ポイント：
  - `state` が毎回変わるか（再利用されないか）
  - `nonce` があるか（ID Tokenで検証される想定）
  - PKCE：`code_challenge` が存在するか（SPA/モバイルは重要）
  - トークン：ID Token/Access Token の `iss/aud/exp/sub`、scope/roles
- 次の分岐：
  - Token/Refresh/長期化が見える → `01_topics/02_web/02_authn_03_token設計（Bearer_JWT_Refresh_Rotation）.md` へ
  - 権限がclaimで決まる気配 → `02_playbooks/04_authz_境界モデル→検証観点チェック.md` へ
  - IdPポリシー/例外が鍵 → `01_topics/04_saas/04_azuread_条件付きアクセス（CA）と例外パス.md` などへ
- 実際の観測例：
  - `code_challenge` があり、`code_verifier` が後段で送られる

### Step 3B：SAML観測（assertion/audience/recipient/署名 / 目安: 10分）
- 目的：SAMLの“誰が発行し誰が検証するか”を観測で確定し、属性→権限の接続へ渡す。
- 観測ポイント（SAMLResponseを見られる範囲で）：
  - Audience/Recipient/ACS の一致（対象サービス固定か）
  - 署名の有無（Assertion/Response）と証明書（x509）
  - Attribute（role/group/tenant）が権限に効いていそうか
- 次の分岐：
  - 属性が権限に直結しそう → `02_playbooks/04_authz_境界モデル→検証観点チェック.md`
  - ローカルログイン/回復経路が残る疑い → `01_topics/04_saas/14_sso_bypass_パス（ローカルログイン残存）.md`
- 実際の観測例：
  - `Audience` が `https://app.example.com/saml` で固定

### Step 3C：SSOが見えづらい（アプリ側セッション材料から確定 / 目安: 5分）
- 目的：IdPが見えない環境でも、アプリが何を“本人性材料”として扱っているかを確定する。
- 観測ポイント：
  - アプリ側Cookie/Tokenの種類と寿命（ログイン直後の差分）
  - ログアウトで材料が無効化されるか（Cookie削除/トークン失効の兆候）
- 次の分岐：
  - 材料がCookie中心 → Step 4（寿命/失効）
  - 材料がBearer中心 → `02_playbooks/05_api_権限伝播→検証観点チェック.md`（API側で検証）
- 実際の観測例：
  - ログアウトで `session` Cookie が削除される

### Step 4：MFA/再認証/寿命（“例外パス”を列挙する / 目安: 10分）
- 目的：MFAが「いつ」「どこで」要求されるか、例外（remember/端末信頼/ネットワーク）を状態として確定する。
- 観測ポイント（安全に差分）：
  - 同一端末/同一ブラウザでの再ログイン：MFAは毎回か、rememberがあるか
  - 重要操作（設定変更/決済/権限変更）で step-up があるか
  - セッション期限：一定時間後に再認証が必要か、refreshがあるか
- 次の分岐：
  - step-upが鍵 → `01_topics/02_web/02_authn_16_step-up_再認証境界（重要操作_再確認）.md`
  - refresh rotation/盗用検知が鍵 → `01_topics/02_web/02_authn_17_refresh_token_rotation_盗用検知（reuse）.md`
  - “外部例外（CA/ポリシー）”が鍵 → SaaS側ポリシーへ
- 実際の観測例：
  - 同一端末はMFAスキップ、別端末は必須

### Step 5：攻め筋の確定（次の深掘りを最大3つに絞る / 目安: 5分）
- 優先度の付け方：
  1) 認証が壊れると被害が最大化（SSO/管理者/回復経路）
  2) セッションが長寿命/失効が弱い（継続的な不正利用が可能）
  3) AuthN→AuthZへ権限伝播が強い（claim/role/tenant）
- 次に深掘りするtopics（最大3つ）：
  - OIDC：`01_topics/02_web/02_authn_04_sso_oidc_flow観測（state_nonce_code_PKCE）.md`
  - SAML：`01_topics/02_web/02_authn_05_sso_saml_flow観測（assertion_audience_recipient）.md`
  - セッション寿命：`01_topics/02_web/02_authn_02_session_lifecycle（更新_失効_固定化_ローテーション）.md`
  - MFA：`01_topics/02_web/02_authn_06_mfa_成立点と例外パス（step-up_device_trust）.md`
- 次に回す検証（playbook）：
  - AuthZ：`02_playbooks/04_authz_境界モデル→検証観点チェック.md`
  - API：`02_playbooks/05_api_権限伝播→検証観点チェック.md`
- 実際の観測例：
  - `refresh_token` が長寿命 → セッション寿命 topic を優先

## よくある失敗と対処法
- ログイン試行を連打する → 代表フロー1回に絞る
- Tokenの保存場所が不明 → HARとストレージを分けて確認
- SSO種別の断定が早い → まずは見えるパラメータで判断

## バグバウンティでの注意点
- ロックアウトが発生しやすいので試行回数は最小
- 認証情報の扱い（スクショ/HAR）に注意
- レポートは「成立点の根拠（HAR/パラメータ）」を明記

## 取得する証跡（目的ベースで最小限）
- 何のため：認証成立点と例外を説明し、再現性を持たせるため。
- 取得対象：HAR（1回のログイン）、Set-Cookie抜粋、トークンのデコード結果（必要なら）。
- 見るポイント：外部遷移、state/nonce/RelayStateの存在、cookie属性、exp/iss/aud。

## コマンド/リクエスト例（例示は最小限）
~~~~
# JWTのclaim観測（署名検証なし）

python - <<'PY'
import jwt,sys
token=sys.stdin.read().strip()
print(jwt.decode(token, options={"verify_signature": False}))
PY
~~~~
- 何を観測する例か：exp/iss/aud/scope/roles など“権限と寿命”の材料。
- 出力の注目点：exp（寿命）、roles/scope（権限伝播）、tenant/orgの手掛かり。
- 前提が崩れるケース：暗号化トークンやトークンをクライアントが保持しない構成（HARで代替）。

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS：
  - 該当領域/章：V2（AuthN）、V3（Session）、V4（AuthZ前提）、V10（Logging）
  - このプレイブックが支える管理策：成立点/例外/寿命の確定（前提崩れ防止）
- WSTG：
  - 該当カテゴリ/テスト観点：Authentication / Session Management
  - このプレイブックが支える前提：SSO境界の観測（state/nonce/署名/失効）
- PTES：
  - 該当フェーズ：Vulnerability Analysis
  - 前後フェーズとの繋がり：AuthNが固まるとAuthZ/APIの検証が外れない
- MITRE ATT&CK：
  - 該当戦術：Credential Access / Defense Evasion
  - 攻撃者の意図：セッション材料・長寿命トークン・例外経路で継続利用する

## 報告（ガイドライン程度：数行で）
- 事実：認証方式（SSO/ローカル）、MFA適用/例外、セッション材料と寿命。
- 成立条件：観測根拠（HAR/Set-Cookie/token claim）。
- 影響：長寿命/例外/回復経路によるリスク。
- 対策方向性：短寿命化/失効強化/例外削減/監査強化（詳細はtopicsへ）。

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`01_topics/02_web/02_authn_00_認証・セッション・トークン.md`
- 関連 cases：`03_cases/00_index.md`
