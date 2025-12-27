# 05_api_権限伝播→検証観点チェック
API を「エンドポイント列挙」ではなく、権限伝播（主体→サービス→内部連携）と境界変数（owner/tenant/role/scope）で捉え、差分観測→分岐で次の一手を決める。

## 目的（このプレイブックで到達する状態）
- “誰が・どの範囲で・何をできるか” を、API単位で説明できる（主体/範囲/操作）。
- UI≠API を前提に、越権/漏洩の成立条件を差分観測で絞れる。
- 内部連携（別サービス/ジョブ/Webhook）の可能性を推定し、次に読むtopic/回す検証へ繋げられる。

## 前提知識チェックリスト（先に確認）
- 境界変数：id/owner/tenant/role/scope のどれが効いているか
- 差分観測：主体差→所有差→テナント差→操作差の順で比較
- 成立条件：変えたのは1点だけ、を守る

## 前提（対象・範囲・制約）
- 対象：許可範囲の REST / GraphQL / モバイルAPI / 内部API。
- 制約：まず read-only。write は安全な対象で “1項目だけ” の変更に限る。
- 前提ツール（最小限）：ブラウザ + Proxy（HAR）、（任意）`curl`、（任意）`jq`。
  - 理由：HARで差分の根拠、curl/jqで最小再現を作る。
  - 代替：Postman / `Invoke-WebRequest` でも可。
- 参照すべきtopics：
  - `01_topics/02_web/04_api_00_権限伝播・入力・バックエンド連携.md`

## 入口で確定すること（最小セット）
- 代表API（3本まで）：主要機能（検索/ファイル/設定/決済など）から選ぶ。
- 主体（最低2つ）：ユーザーA / ユーザーB（可能ならロール差 or テナント差）。
- 境界変数候補：`id`/`owner`/`tenant`/`role`/`scope` のどれが見えているか（Yes/No/Unknown）。
- 完了条件：代表API 3本について「境界変数」と「拒否点（どこで拒否されるべきか）」を1行で書ける。

## 所要時間の目安
- 全体：35〜50分

## 具体的に実施する方法（最小セット）
### 0) 証跡ディレクトリ（`api_05`）
~~~~
# Windows (PowerShell)
$dir = Join-Path $HOME "keda_evidence\\api_05"
New-Item -ItemType Directory -Force $dir | Out-Null
Set-Location $dir
"api: /api/* or /graphql" | Set-Content -Encoding utf8 00_context.txt
~~~~

### 1) フロント→APIの相関を取る
- ブラウザで1回操作し、HARを `01_front.har` として保存
- 同時にAPIの代表リクエストを `curl -v` 等で再現し、`02_api_replay.txt` に保存

### 2) GraphQLの最小観測例（差分観測）
~~~~
curl -sS https://example.com/graphql \
  -H \"Content-Type: application/json\" \
  -d '{\"query\":\"query { me { id role } }\"}' > 03_graphql_me.json
~~~~
- 注目点：ロール/テナント差で返るフィールドや件数が変わるか

## 手順（分岐中心：迷うポイントだけ）

### Step 0：最初の5分（必ずやる / 目安: 5分）
- 目的：比較可能な“代表APIセット”と証跡を作る。
- 観測ポイント：
  - Proxyで HAR を取り、同じ操作を A と B で1回ずつ実行できる状態にする。
  - 代表APIは「一覧/検索」「参照」「更新（できれば）」の形で1本ずつにする（合計3本まで）。
- 証跡（最小）：
~~~~
# Windows (PowerShell)

$dir = Join-Path $HOME "keda_evidence\\api_05"
New-Item -ItemType Directory -Force $dir | Out-Null
Set-Location $dir
"base_url: ...`nuserA: ...`nuserB: ...`napis: ..." | Set-Content -Encoding utf8 00_context.txt

# macOS/Linux (bash)

mkdir -p ~/keda_evidence/api_05
cd ~/keda_evidence/api_05
printf "base_url: ...\nuserA: ...\nuserB: ...\napis: ...\n" > 00_context.txt
~~~~
- 次の分岐：
  - 代表API 3本が揃った → Step 1へ
- 実際の観測例：
  - `apis: GET /orders, GET /orders/{id}, PATCH /orders/{id}`

### Step 1：APIの“地図”を作る（量より構造 / 目安: 8分）
- 目的：検証対象を増やさず、重要な差分だけを見る。
- 観測ポイント（代表API 3本で十分）：
  - 認証方式：Cookieか Bearer か（混在もある）
  - リソース種別：users/files/orders/projects…
  - 操作：read/write/admin（どれに当たるか）
- 次の分岐（判断基準）：
  - Bearer が主材料 → Step 2Aへ（token/scope/claim）
  - Cookie が主材料 → Step 2Bへ（session/csrf）
  - GraphQL が主材料 → Step 2Cへ（schema/field境界）
- 実際の観測例：
  - `Authorization: Bearer ...` が全APIで使われる

### Step 2A：Bearer/Token中心（scope/claim が境界変数 / 目安: 8分）
- 目的：権限伝播の材料（scope/role/tenant）を “観測” で確定する。
- 観測ポイント：
  - tokenの所在（Header/Storage）と寿命の手掛かり（exp等）
  - scope/roles/tenant/org の有無（Yes/No/Unknown）
- 次の分岐：
  - scope/role/tenant がリクエストで上書きできそう → Step 3（境界変数の差分へ）
  - tokenが長寿命/失効が弱そう → `02_playbooks/03_authn_観測ポイント（SSO_MFA前提）.md` に戻る
- 実際の観測例：
  - `scope` に `admin` が含まれる

### Step 2B：Cookie中心（session/csrf が境界変数 / 目安: 8分）
- 目的：UI操作でもAPIでも、同じ拒否点で守れているかを見る。
- 観測ポイント：
  - Cookie属性（Secure/HttpOnly/SameSite）、CSRF token の有無
  - ロール差/所有差で API の挙動が変わるか（差分）
- 次の分岐：
  - UIで隠される操作がAPIで通りそう → `02_playbooks/04_authz_境界モデル→検証観点チェック.md`（AuthZへ）
  - セッション寿命/更新が疑わしい → `02_playbooks/03_authn_観測ポイント（SSO_MFA前提）.md`
- 実際の観測例：
  - CSRF token が付いていないAPIがある

### Step 2C：GraphQL中心（field-level の境界 / 目安: 8分）
- 目的：認可が「エンドポイント」ではなく「フィールド/リゾルバ」にある前提で差分を取る。
- 観測ポイント：
  - `query/mutation` の種類、引数（id/tenant等）、返るフィールドの差分
  - `__schema`/`__type` などの introspection が許可されているか
  - 同じ query で role/tenant を変えた時の field 差
- 次の分岐：
  - field差で漏れる/通る兆候 → AuthZへ戻る（`02_playbooks/04_authz_境界モデル→検証観点チェック.md`）
- 実際の観測例：
  - 一般ユーザで `adminNotes` フィールドが返る

### Step 3：境界変数の差分を作る（主体差→所有差→テナント差→操作差 / 目安: 10分）
- 目的：“どこで境界が効いていないか” を最短で絞る。
- 観測ポイント（順序を固定する）：
  1) 主体差：A vs B（同じリソースで）
  2) 所有差：自分ID vs 他人ID（同じ主体で）
  3) テナント差：同一tenant vs 別tenant（可能なら）
  4) 操作差：read vs write（影響制御）
- 次の分岐（判断基準）：
  - 越権/漏洩が疑わしい → Step 4A（最小再現の作り込み）
  - 内部連携/ジョブ/Webhook臭が強い → Step 4B（伝播先へ）
  - 入力が裏側実行境界に繋がりそう → Step 4C（入力境界へ）
- 実際の観測例：
  - IDだけ変えると 200 が返る

### Step 4A：分岐A（越権/漏洩の最小再現を作る / 目安: 5分）
- 次の一手：
  - 期待拒否/実結果の差が最小になるよう、**変数を1つだけ**変える設計に落とす。
  - AuthZモデルに戻して説明力を上げる：`02_playbooks/04_authz_境界モデル→検証観点チェック.md`

### Step 4B：分岐B（内部連携：別サービス/ジョブ/Webhook / 目安: 5分）
- 次の一手：
  - “どの境界で判定しているか” を推定する（ゲートウェイ/サービス/DB/ワーカー）。
  - 必要ならネットワーク側（到達性/サービス）に接続する：`02_playbooks/06_network_enum_to_post_列挙→侵入後の導線.md`

### Step 4C：分岐C（入力境界：実行/参照/委任に繋がる / 目安: 5分）
- 次の一手：
  - “どこで解釈/実行が起きるか” を観測で確定してから検証設計する：`02_playbooks/07_input_to_rce_入力→実行の導線.md`
- 実際の観測例：
  - Webhook登録APIが見える

## よくある失敗と対処法
- APIを増やしすぎる → 3本までに絞る
- writeを先に試す → read差分で成立条件を固めてから
- GraphQLをRESTと同じ扱いにする → field差分で観測する

## バグバウンティでの注意点
- 内部API/管理APIはスコープ外になりやすいので要確認
- 大量アクセスは避け、差分1〜2回で示す
- レポートは「境界変数」と「拒否点」を明記
## 取得する証跡（目的ベースで最小限）
- 何のため：APIの拒否点（どこで誰が拒否されるべきか）と、成立条件を説明するため。
- 取得対象：代表API 1〜3本の HAR、主体A/B、対象ID対応表、期待拒否/実結果の差分メモ。
- 見るポイント：境界変数（id/tenant/role/scope）、存在隠蔽/部分漏洩、UI≠APIのズレ、内部連携の兆候。

## コマンド/リクエスト例（例示は最小限）
~~~~
# 例：同じAPIを主体差で比較する（read-only）

curl -sS -H "Authorization: Bearer <TOKEN_A>" "https://<BASE>/api/<resource>/<id>" -D - -o /dev/null
curl -sS -H "Authorization: Bearer <TOKEN_B>" "https://<BASE>/api/<resource>/<id>" -D - -o /dev/null
~~~~
- 何を観測する例か：主体差（A/B）で同じリソースに対する拒否点を比較する。
- 出力の注目点：ステータスだけでなく、本文の意味（権限不足/存在隠蔽/部分漏洩）。
- 前提が崩れるケース：Cookie中心の場合は `curl` だけで再現しづらい（HAR差分中心で進める）。

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS：
  - V4（Access Control）/V2（AuthN）/V3（Session）を、境界変数（owner/tenant/role/scope）として観測し、成立条件を絞る。
- WSTG：
  - APIのテスト観点を、差分観測（主体/所有/テナント/操作）で回すための導線を提供する。
- PTES：
  - Vulnerability Analysis：権限判定点のズレ（伝播/分散）を特定する。
- MITRE ATT&CK：
  - Collection / Privilege Escalation / Credential Access を、API境界崩壊の説明補助として用いる。

## 報告（ガイドライン程度：数行で）
- 事実：代表API 3本の境界変数と、差分観測の結果。
- 成立条件：何を変えると通る/漏れるか（変数）と、拒否点（どこで拒否されるべきか）。
- 影響：越権/漏洩/不正操作の範囲（推定は推定と明記）。
- 対策方向性：サーバ側一貫判定、境界変数の正規化、スコープ最小化、監査強化。

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`01_topics/02_web/04_api_00_権限伝播・入力・バックエンド連携.md`
- 関連 playbooks：`02_playbooks/04_authz_境界モデル→検証観点チェック.md`
- 関連 playbooks：`02_playbooks/07_input_to_rce_入力→実行の導線.md`
