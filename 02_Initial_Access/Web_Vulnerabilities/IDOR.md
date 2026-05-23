# IDOR（Insecure Direct Object Reference）

## 概要

オブジェクト（ファイル・データ・リソース）への参照に、認可チェックなしで直接アクセスできる脆弱性。URLやパラメータのIDを変えるだけで他ユーザーのデータや古いデータにアクセスできる。

---

## 着火条件

- URLに連番・数値ID・ユーザーIDが含まれている（例: `/data/3`, `/download/5`, `/user/42/profile`）
- ファイルダウンロード機能がある
- 「自分のデータ」として表示されるページのURLにIDが含まれている

---

## 観点・着眼点

**IDの推測可能性を確認する：**
1. 自分がアクセスした際のIDを記録する（例: `/capture` → `/data/3` にリダイレクト）
2. IDを `0` や `1` から順に変えてアクセスしてみる
3. UUIDでも連番でも、とにかく「変えてみる」習慣を持つ

**特に注意するパターン：**

- ファイルダウンロードエンドポイント（`/download/[ID]`）→ 古いファイルや他ユーザーのファイルが取得できることがある
- 現在のIDより小さい値（`0`, `1`）に特に重要なデータが保存されていることが多い
- IDが「現在のセッションで生成された番号」であれば、`0` は「最初のセッション」のデータを指す可能性がある

---

## 手順

**ブラウザで確認する場合：**
URLのID部分を手動で変更してアクセスするだけ。

**curl で確認する場合：**
```bash
# 現在のエンドポイントを確認
curl -s http://[TARGET]/download/3

# IDを変えて取得
curl -s http://[TARGET]/download/0 -o output_id0.file
curl -s http://[TARGET]/download/1 -o output_id1.file
```

**連番を一括試行する場合（bash）：**
```bash
for i in $(seq 0 10); do
  echo "=== ID: $i ===" 
  curl -s -o /tmp/idor_$i http://[TARGET]/download/$i
  file /tmp/idor_$i
done
```

---

## 発見後の動き

取得したファイルの種類によって次のステップが変わる：

| ファイルの種類 | 次のアクション |
|--------------|--------------|
| PCAP（ネットワークキャプチャ） | tshark で認証情報を探す → `../Credential_Discovery.md` |
| テキスト・設定ファイル | 認証情報・内部情報を確認 |
| バイナリ・実行ファイル | 解析する → `../Binary_Analysis.md` |

---

## 注意点・落とし穴

- セッションCookieやトークンが必要な場合は `-H "Cookie: ..."` を追加する
- レスポンスのHTTPステータスコードだけでなく、**レスポンスサイズ**も確認する（403でもボディにデータがある場合がある）
- GUIDやUUID形式のIDは推測が困難だが、`0`や`null`は試す価値がある

---

## 刺さらなかったとき

- **IDがUUID形式で連番推測が困難な場合** → 他のエンドポイントのレスポンスJSONに `user_id` / `file_id` / `object_id` 等の有効なIDが漏れていないか確認する（例：自分のプロフィールAPIのレスポンスに他ユーザーのIDが含まれる場合がある）
- **全IDに403が返る場合** → CookieやAuthorizationヘッダーの渡し方を確認する。セッション切れやトークン不足の可能性がある
- **存在するIDに全て404が返る場合** → エンドポイントパスの推測が間違っている。gobusterで正しいパスを再確認する → `../../01_Reconnaissance/Web_Enumeration.md`

---

## 関連技術

- 前：Web列挙でIDを含むURLを発見 → `../../01_Reconnaissance/Web_Enumeration.md`
- 後：PCAPファイルが取得できた → `../Credential_Discovery.md`
- 後：バイナリが取得できた → `../Binary_Analysis.md`
- 関連：パストラバーサル（同じ「ファイルアクセス」系の脆弱性） → `./Path_Traversal.md`
