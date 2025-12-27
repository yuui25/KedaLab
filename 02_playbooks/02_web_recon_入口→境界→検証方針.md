# 02_web_recon_入口→境界→検証方針
Webの入口（画面/API/管理/連携）を境界（資産/信頼/権限/実行/運用）で整理し、次の深掘り（AuthN/AuthZ/API/Input/Config）を外さず選ぶ。

## 目的（このプレイブックで到達する状態）
- 入口Top3〜5について、**何が守るべき資産で、どこが第三者で、どこで権限が切り替わるか**を説明できる。
- 「次に読むtopic」と「次に回す検証」を、観測結果から分岐で決められる。
- 代表点の証跡（HAR/ヘッダ/リダイレクト/JS断片）を残せる。

## 前提知識チェックリスト（先に確認）
- 境界：資産/信頼/権限/運用の切り替わり地点
- 差分観測：未ログイン/ログイン/ロール差の比較
- 成立条件：何を変えると挙動が変わるか

## 前提（対象・範囲・制約）
- 対象：許可範囲のWebアプリ（SPA/モバイルAPI含む）、関連API、管理UI、SSO入口。
- 制約：低アクティブ（代表点のみ）。ディレクトリ総当たり/クローリング/大量リクエストはしない。
- 前提ツール（最小限）：ブラウザ + Proxy(HAR)、`curl`、（任意）`jq`/`ripgrep`。
  - 理由：HARで入口/遷移を可視化、curlでヘッダ差分、jq/rgで差分抽出が速い。
  - 代替：`Invoke-WebRequest` / `Select-String` で代用可。
- 参照すべきtopics：
  - `01_topics/02_web/01_web_00_recon_入口・境界・攻め筋の確定.md`
  - `01_topics/02_web/02_authn_00_認証・セッション・トークン.md`
  - `01_topics/02_web/03_authz_00_認可（IDOR BOLA BFLA）境界モデル化.md`
  - `01_topics/02_web/04_api_00_権限伝播・入力・バックエンド連携.md`
  - `01_topics/02_web/06_config_00_設定・運用境界（CORS ヘッダ Secrets）.md`

## 入口で確定すること（最小セット）
- 対象の境界（資産/信頼/権限）をどう把握するか：
  - 資産境界：扱うデータ（ユーザ/権限/ファイル/決済等）と“重要操作”の入口を特定する。
  - 信頼境界：SSO/外部SaaS/CDN/WAF/Storage/Webhookなど、第三者を跨ぐ点を特定する。
  - 権限境界：ロール/所有者/テナント/共有/スコープがどこで決まるかの手掛かりを取る。
- 完了条件：
  - 入口Top3〜5が「入口URL/用途/境界/外部依存/次の深掘り」に落ちた状態。

## 所要時間の目安
- 全体：30〜45分

## 具体的に実施する方法（最小セット）
### 0) 証跡ディレクトリ（`web_recon_02`）
~~~~
# Windows (PowerShell)
$dir = Join-Path $HOME "keda_evidence\\web_recon_02"
New-Item -ItemType Directory -Force $dir | Out-Null
Set-Location $dir
"base_url: https://example.com`naccounts: userA/userB" | Set-Content -Encoding utf8 00_context.txt

# macOS/Linux (bash)
mkdir -p ~/keda_evidence/web_recon_02
cd ~/keda_evidence/web_recon_02
printf "base_url: https://example.com\naccounts: userA/userB\n" > 00_context.txt
~~~~

### 1) HARを取る（ブラウザ）
- DevTools → Network → Preserve log → ログイン/主要操作を実行 → “Save all as HAR” を `01_browser.har` として保存
- 注目点：入口URL、リダイレクト、Cookie、API呼び出し先、外部ドメイン

### 2) 入口のヘッダ差分（CLIで保存）
~~~~
curl -sS -I https://example.com/ > 02_head_root.txt
curl -sS -I -L https://example.com/login > 02_head_login_follow.txt
~~~~
- 注目点：`Location`、`Set-Cookie`、`Server`、`Cache-Control`

### 3) JSから設定/面を拾う（最小）
~~~~
rg -n \"apiKey|client_id|redirect_uri|token|secret|/api/|/graphql\" -S . > 03_rg_js_hints.txt
~~~~

## 手順（分岐中心：迷うポイントだけ）

### Step 0：最初の5分（必ずやる / 目安: 5分）
- 目的：以降の検証を“外さない”ための準備（証跡と代表点）。
- 観測ポイント：
  - 代表点を3つ選ぶ（例）：`/`（トップ）, `/login`（ログイン）, `/api` or “主要操作1つ”（例：検索/ファイル/決済）。
  - テストユーザ2種（ロール/テナント差）が用意できるか（用意できないなら “Unknown” として進む）。
  - Proxyを起動し、HARを取れる状態にする。
- 証跡（最小）：
~~~~
# Windows (PowerShell)
$dir = Join-Path $HOME "keda_evidence\\web_recon_02"
New-Item -ItemType Directory -Force $dir | Out-Null
Set-Location $dir
"scope: ...`nbase_url: ...`nseeds: ...`naccounts: ..." | Set-Content -Encoding utf8 00_context.txt

# macOS/Linux (bash)
mkdir -p ~/keda_evidence/web_recon_02
cd ~/keda_evidence/web_recon_02
printf "scope: ...\nbase_url: ...\nseeds: ...\naccounts: ...\n" > 00_context.txt
~~~~
- 次の分岐：
  - 代表点とHAR取得準備ができた → Step 1へ
- 実際の観測例：
  - `seeds: / , /login , /orders`

### Step 1：入口の“型”を確定する（UI/API/管理/連携 / 目安: 10分）
- 目的：入口を列挙するのではなく、役割で分類して優先度付けする。
- 観測ポイント（代表点で十分）：
  - UI入口：トップ/ログイン/主要機能（検索/作成/ファイル/決済など1つ）
  - API入口：Networkタブで `fetch/XHR` の宛先（`/api` `/graphql` 等）
  - 管理入口：`/admin` `console` など（無ければUnknownでよい）
  - 連携入口：SSO遷移、外部決済、外部ストレージ、Webhook設定画面の有無
- 証跡（最小）：
  - ブラウザHAR：トップ→ログイン表示まで（ログインはまだしなくて良い）
  - 代表点のHTTPヘッダ（curlで可）
~~~~
curl -sS -I https://<BASE>/ > 01_head_root.txt
curl -sS -I -L https://<BASE>/login > 01_head_login_follow.txt
~~~~
- 次の分岐：
  - ログインで外部ドメインへ遷移（IdP） → Step 2B（SSO境界が本体）
  - 入口がUI/API中心で外部遷移が薄い → Step 2A
- 実際の観測例：
  - Networkで `/api/orders` が見える → API入口あり

### Step 2A：Web内完結寄り（境界変数を“差分”で取る / 目安: 10分）
- 目的：AuthZ/API/Config のどこが本体かを決める材料（差分）を作る。
- 観測ポイント（差分が主役）：
  - 未ログイン vs ログイン後：見える機能/APIの差
  - 役割差：一般ユーザA vs 権限差ユーザB（可能なら）
  - テナント差：同一tenant vs 別tenant（可能なら）
- 証跡（最小）：
  - HAR（ログイン1回＋主要操作1回）
  - Cookie（Set-Cookie属性）と、API呼び出しの宛先一覧（3件程度）
- 次の分岐（判断基準）：
  - 画面制限よりAPIの差が大きい（APIが本体） → Step 3C（APIへ）
  - “ID/tenant/role”がURL/レスポンスに見える（AuthZが本体） → Step 3B（AuthZへ）
  - CORS/ヘッダ/ログ表示/Secrets露出が見える（運用が本体） → Step 3D（Configへ）
  - 入力点（テンプレ/ファイル/外部URL）が中心（実行境界が本体） → Step 3E（Inputへ）
- 実際の観測例：
  - `GET /api/orders` がログイン後にのみ現れる → API差分の根拠

### Step 2B：SSO/外部連携あり（信頼境界が本体 / 目安: 10分）
- 目的：本人性がどこで成立し、どの材料で戻ってくるかを観測で確定する（断定しない）。
- 観測ポイント（SSOの“成立点”）：
  - リダイレクト連鎖：App→IdP→App（どのドメインが出るか）
  - 結合パラメータ：OIDCなら `state/nonce/code/PKCE`、SAMLなら `RelayState/ACS` の手掛かり
  - Cookie/Token：アプリ側セッションが何で成立しているか（Cookie or Bearer）
- 証跡（最小）：
  - HAR（SSO開始→戻り→ログイン後トップまで）
  - 重要パラメータ（state/nonce/RelayState）の存在メモ
- 次の分岐：
  - OIDC/SAMLのフローが観測できた → `02_playbooks/03_authn_観測ポイント（SSO_MFA前提）.md`
  - SSO強制なのにローカルログインが残りそう → `01_topics/04_saas/14_sso_bypass_パス（ローカルログイン残存）.md`（topic）へ
- 実際の観測例：
  - `state`/`nonce` がログイン開始〜戻りで確認できる

### Step 3B：AuthZが本体（越権の成立条件を作る / 目安: 5分）
- 優先度の付け方：
  - 所有者/テナント/ロール境界が動く機能（一覧/検索/参照/更新/共有）を優先。
- 次に深掘りするtopics（最大3つ）：
  - `01_topics/02_web/03_authz_00_認可（IDOR BOLA BFLA）境界モデル化.md`
  - `01_topics/02_web/03_authz_03_multi-tenant_分離（org_id_tenant_id）.md`
  - `01_topics/02_web/03_authz_06_privileged_action_重要操作（承認_送金_権限）.md`
- 次に回す検証（playbook）：
  - `02_playbooks/04_authz_境界モデル→検証観点チェック.md`
- 実際の観測例：
  - URLに `order_id` が含まれる → 所有差の差分観測へ

### Step 3C：APIが本体（UI≠APIのズレを起点にする / 目安: 5分）
- 優先度の付け方：
  - UIから呼ばれるAPI（3本まで）を選び、主体差/所有差/テナント差で差分を取る。
- 次に深掘りするtopics（最大3つ）：
  - `01_topics/02_web/04_api_00_権限伝播・入力・バックエンド連携.md`
  - `01_topics/02_web/04_api_03_rest_filters_検索・ソート・ページング境界.md`
  - `01_topics/02_web/04_api_04_webhook_受信側の信頼境界（署名_再送）.md`
- 次に回す検証（playbook）：
  - `02_playbooks/05_api_権限伝播→検証観点チェック.md`
- 実際の観測例：
  - UIでは見えない `PATCH /api/admin/...` が存在する

### Step 3D：設定/運用が本体（CORS/Secrets/Headers/ログ / 目安: 5分）
- 優先度の付け方：
  - “外部に滲む”もの（CORS/Secrets/詳細エラー/ログ/キャッシュ）を優先。
- 次に回す検証（playbook）：
  - `02_playbooks/10_web_config_ops_設定・運用境界_初動.md`
- 実際の観測例：
  - `Access-Control-Allow-Origin: *` が見える

### Step 3E：入力→実行が本体（テンプレ/デシリアライズ/SSRF等 / 目安: 5分）
- 優先度の付け方：
  - 入力点を3つ選び、どこで解釈されるか（サーバ/DB/外部呼び出し）を観測で特定する。
- 次に回す検証（playbook）：
  - `02_playbooks/07_input_to_rce_入力→実行の導線.md`
- 実際の観測例：
  - 外部URL入力欄がある → SSRF系の観測へ

## よくある失敗と対処法
- 入口を広げすぎる → 代表点3つに固定してから拡張
- HARが取れていない → Proxyの有効化と保存先の確認
- 差分が曖昧 → 変えるのは1条件だけにする

## バグバウンティでの注意点
- クローリング/総当たりは禁止されがち。必ず代表点のみで実施
- 影響のある操作（write）は最小限で、検証環境がある場合に限定
- レポートは「観測根拠（HAR/ヘッダ）」を必ず添える

## 取得する証跡（目的ベースで最小限）
- 何のため：入口と境界（資産/信頼/権限/運用）を説明するため。
- 取得対象：
  - HAR（未ログイン1回、ログイン1回、主要操作1回）
  - curlヘッダ（トップ/ログイン）
  - SSOの場合：リダイレクト連鎖と主要パラメータの存在メモ
- 見るポイント：外部遷移、Cookie属性、API宛先、境界変数（id/tenant/role）の手掛かり。

## コマンド/リクエスト例（例示は最小限）
~~~~
curl -sS -I https://<BASE>/ | sed -n '1,40p'
curl -sS -I -L https://<BASE>/login | sed -n '1,60p'
~~~~
- 何を観測する例か：外部遷移（SSO/CDN）とCookieの付与、CORS/セキュリティヘッダの有無。
- 出力の注目点：Location、Set-Cookie、Access-Control-*、Content-Security-Policy 等。
- 前提が崩れるケース：SPAでcurlだけでは情報が薄い場合（HARで補う）。

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS：
  - 該当領域/章：V1/V2/V3/V4/V10（入口と境界が前提）
  - このプレイブックが支える管理策：対象/外部依存/入口の確定（前提崩れ防止）
- WSTG：
  - 該当カテゴリ/テスト観点：Information Gathering / Configuration / Authentication / Authorization
  - このプレイブックが支える前提：差分観測（未ログイン/ログイン/ロール差）で検証対象を外さない
- PTES：
  - 該当フェーズ：Intelligence Gathering → Vulnerability Analysis
  - 前後フェーズとの繋がり：入口と境界が確定すると、検証ケースが減り精度が上がる
- MITRE ATT&CK：
  - 該当戦術：Discovery（構造把握）/Credential Access（SSO）/Collection（外部依存）
  - 攻撃者の意図：境界が動く地点（SSO/管理/API）を最短で見つける

## 報告（ガイドライン程度：数行で）
- 事実：入口Top3〜5、SSO有無、API有無、外部依存。
- 成立条件：観測根拠（HAR/ヘッダ/リダイレクト）。
- 影響：どの境界が勝負か（AuthN/AuthZ/API/Input/Config）。
- 対策方向性：次に回すplaybookと必要な追加観測。

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`01_topics/02_web/00_index.md`
- 関連 cases：`03_cases/00_index.md`
