## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS
  - 重要点：Prototype Pollution は「入力値のサニタイズ」ではなく、入力が **キーとして構造に入る** ときの制御不備（危険キーの遮断、マージ手法、型の固定、未知キー拒否）で起きる。
  - したがって要件は、(1) parse層の危険キー拒否、(2) merge層の安全実装、(3) 重要オブジェクトへの外部入力マージ禁止、(4) 例外露出抑制、(5) 依存ライブラリ更新と設定固定。
- WSTG
  - 入力バリデーションの観点として、HPP（同名パラメータの多重送信）や、ネスト表現（bracket/dot）による構造化をテストし、アプリが **どのようにオブジェクトを構築しているか** を確定する。:contentReference[oaicite:0]{index=0}
- PTES
  - 情報収集：どの入口が「構造化入力」を受け、どのライブラリでオブジェクト化するかを特定（query parser / body parser / JSON / YAML / XML / cookie / websocket）。
  - 脆弱性分析：source（parse/merge/set）を特定し、危険キーが通るかを差分で確定。sink（別ファイル）に接続して影響評価。
- MITRE ATT&CK
  - 初期侵入：T1190（公開アプリ脆弱性悪用）
  - 影響：ロジック破壊、権限逸脱、DoS（オブジェクト汚染がトリガになるケース）
  - 注：本ファイルは source（侵入点）に限定し、実行連鎖は `05_input_14_prototype_pollution_02_sinks` 側で扱う。

---

## タイトル
Prototype Pollution の source を分解する
parse と merge と set のどこで危険キーが通るかを差分で確定する

---

## 目的（このファイルで到達する状態）
- 次を「成立根拠」として説明できる。
  1) どの入力面が、ユーザ入力をオブジェクトのキーとして扱うか
  2) parse と merge と set のどの段で危険キーが遮断されていないか
  3) 依存ライブラリや設定差分により、同じ見た目でも成立可否が変わる理由
- PoCの芸当ではなく、設計欠陥として報告できる形に落とす。
  - 「危険キーが到達する経路」＋「防御境界が欠けている箇所」＋「影響は次ファイルで接続」

根拠資料
- PortSwigger の定義と解説（概念、サーバサイドの成立条件）:contentReference[oaicite:1]{index=1}
- JSON.parse での __proto__ の振る舞い差分など、サーバサイド検出研究:contentReference[oaicite:2]{index=2}
- OWASP の予防策整理（防御設計の方向性）:contentReference[oaicite:3]{index=3}
- 依存ライブラリ起因の代表例（lodash.merge、qs）:contentReference[oaicite:4]{index=4}

---

## 位置づけ（Prototype Pollution を入力境界で捉える）
Prototype Pollution は「値の注入」ではなく「キーの注入」である。

- 通常の入力バリデーションが守るもの
  - value が想定範囲か、文字種か、長さか
- Prototype Pollution が壊すもの
  - key が想定集合か
  - key が「内部状態オブジェクト」へ書込みできるか
  - key の解釈が parse や merge によって変わるか

結論
- 本質的な検査対象は **フィールド名（キー）** と **構造化の規則**。
- 「JSONだから安全」「URL query だから安全」は成立しない。parseの実装が鍵になる。:contentReference[oaicite:5]{index=5}

---

## 境界モデル（source の3分類）
Prototype Pollution の入口は、実装上ほぼ次の3類型に収束する。

### 1) parse 型 source
文字列入力を「オブジェクト」に変換する段階で、危険キーがオブジェクトに入る。

- 例
  - query string parser（ネスト対応）
  - body parser（JSON、form、multipart のうち、構造化されるもの）
  - cookie parser（key-value をオブジェクト化）
  - WebSocket メッセージ（JSON を parse）
- 典型の落とし穴
  - 危険キーのブラックリストが不完全
  - bracket や dot の解釈が期待とずれる
  - 同名パラメータ多重送信で配列やオブジェクトに化ける（HPP）:contentReference[oaicite:6]{index=6}

### 2) merge 型 source
入力オブジェクトを既存オブジェクトに「深くマージ」して汚染が伝播する。

- 例
  - lodash の merge 系（既知の脆弱性・修正履歴あり）:contentReference[oaicite:7]{index=7}
  - 自作 deepMerge
  - 設定の上書き（defaultsDeep 的な合成）
- 典型の落とし穴
  - 「深いマージ」はキー空間の境界を壊しやすい
  - 危険キーの遮断が merge 実装に依存する

### 3) set 型 source
入力を「パス表現」で受け取り、ネストオブジェクトへ代入する。

- 例
  - a.b.c のような dot path
  - a[b][c] のような bracket path
  - lodash.set 互換、あるいはフォームのネスト復元ロジック
- 典型の落とし穴
  - パス分割規則により、危険キーへ到達する経路が生まれる
  - allowlist が値側のみで、キー側が無制限

本ファイルは source の確定まで。影響評価（どこに効くか）は sinks 側で行う。

---

## 主要な parse 型 source の棚卸し（実務で出やすい順）
### A. query string の構造化パース
成立根拠として見るべき差分は「ネストの表現が有効か」「危険キーが拒否されるか」。

- ネスト表現が有効になる条件
  - bracket 記法を展開する
  - dot 記法を展開する
  - 同名パラメータを配列やオブジェクトにまとめる
- 代表的リスクの一次情報
  - qs の advisory では、__proto__ を含むキーが DoS に繋がり得ることが明記されている。:contentReference[oaicite:8]{index=8}
- 診断での観測点
  - パラメータの重複で、型が string から array に変化するか（HPP）:contentReference[oaicite:9]{index=9}
  - 入力がネストとして復元されるか（アプリが返す JSON、ログ、エラーメッセージ、挙動で推定）

### B. JSON body の parse
JSON は「構造が固定」に見えるが、危険キーがそのまま入ると、後段 merge で汚染が成立する。

- 重要な差分
  - JSON.parse は __proto__ を通常のプロパティとして扱う挙動差があり、検出や成立条件に関わる。:contentReference[oaicite:10]{index=10}
- 診断での観測点
  - 入力 JSON の未知キーがサーバで保持されるか（echo、保存、ログ）
  - 例外文言に「型解決」「マッピング」「未知フィールド」が出るか（境界の位置がわかる）

### C. form 系（application/x-www-form-urlencoded、multipart の一部）
- フレームワークやミドルウェア次第で、query と同様に bracket 展開される場合がある。
- 典型の落とし穴
  - query は安全化していても、body の form パースだけ古い実装が残る
  - multipart のメタ情報やフィールド名がそのままキーになる

### D. cookie のオブジェクト化
cookie は鍵が短いと思われがちだが、パーサが構造化を許すと source になり得る。
- 観測点
  - cookie 名に特殊文字が許容されるか
  - サーバ側で cookie を JSON へ展開している形跡があるか

---

## 主要な merge 型 source の棚卸し（危険度が上がる条件）
### A. 深いマージを使っている
- 代表例
  - lodash の merge/mergeWith/defaultsDeep は Prototype Pollution の既知事例がある（過去に修正あり）。:contentReference[oaicite:11]{index=11}
- 危険度が上がる条件
  - 入力をそのまま config や userProfile や policy のような「広い影響範囲のオブジェクト」にマージ
  - マージ前にキー allowlist がない
  - マージ後の検証がない（検証順序が逆）

### B. シャローに見えても実質 merge になっている
- 次のような操作は、設計次第で「汚染を伝播」させる。
  - Object.assign
  - スプレッド構文によるコピー
  - 既存オブジェクトへの逐次代入
- ポイント
  - 「深いマージ」だけが問題ではなく、危険キーを含むオブジェクトを “信頼オブジェクト” に取り込む行為が source になる。

### C. マージ対象がグローバルまたは共有オブジェクト
- 共有の config、キャッシュ、テンプレ context、認可ポリシー、ログコンテキストなどに入力が混ざると影響が大きい。
- 成立根拠としては「共有されること」自体が重要で、汚染の拡散モデルを説明できる。

---

## set 型 source の棚卸し（パス解釈が境界）
### A. パス表現で代入する設計
- 例
  - ユーザが keyPath を送って、サーバがそのパスへ set する
  - フォームのネストを “パス” として受け取る
- 典型の落とし穴
  - パスセパレータの扱いが環境で異なる
  - パス分割後のキーに対して危険キー拒否がない

### B. 正規化の欠如
- 「見た目は同じキー」を別扱いにされると、ブラックリスト回避が起きる。
  - Unicode 正規化
  - 大文字小文字の扱い
  - エスケープの扱い
- ここは “手口” の列挙ではなく、実装として「正規化点が必要」という設計論として扱う。

---

## 危険キーとガードの考え方（ブラックリストより境界固定）
重要：危険キーの列挙に依存すると抜ける。OWASP も防御を複層で提案している。:contentReference[oaicite:12]{index=12}

- すべきこと
  - 許容キーの allowlist
  - ネスト深さ、配列長、オブジェクト総ノード数の上限
  - マージ対象の固定（入力を共有オブジェクトへ混ぜない）
  - 依存ライブラリを最新へ（既知CVEの回避）:contentReference[oaicite:13]{index=13}
- ブラックリストの位置づけ
  - 最後の保険としては有効だが、これ単体では成立根拠を潰せない（過去事例がそれを示す）:contentReference[oaicite:14]{index=14}

---

## 診断での成立根拠の作り方（差分で source を確定する）
ここでは攻撃手順ではなく「どの段が source か」を確定するための観測設計を示す。

### 1) 入口の同定
- どの入力面が “構造化キー” を受けるかを列挙する
  - query
  - json body
  - form
  - websocket
  - import
  - cookie
- それぞれで「ネストが作れるか」「同名が配列化するか」を観測する。:contentReference[oaicite:15]{index=15}

### 2) parse と merge の切り分け
- parse だけで危険キーが残るか
  - 入力が “そのまま保持される” 兆候（echo、保存、ログ）
- merge が絡むか
  - 入力が “既存オブジェクトに吸収される” 兆候（元に無かったフィールドが増える、設定が変わる）
- PortSwigger の研究は、サーバサイドでの検出を「DoSを起こさずに」行う観点を整理しているため、観測設計の参考になる。:contentReference[oaicite:16]{index=16}

### 3) 依存と設定の確定
- Node の query parser が qs かどうか、バージョン差があるかを推定する
- lodash merge を使っている兆候があるかを推定する
  - 例外のスタック、ビルド成果物、ヘッダ、ソースマップ、依存一覧など
- 既知の脆弱性履歴がある依存（lodash.merge、qs）は成立根拠の補強材料になる。:contentReference[oaicite:17]{index=17}

---

## 実務で起きやすい source の典型シナリオ
### シナリオA
- プロフィール更新や設定更新で JSON を受け取り、既存の user/config に深いマージをしている
- 依存が merge 系（lodash など）で、危険キー遮断がない
- 結果として、プロトタイプ汚染が共有オブジェクトへ広がる

根拠となる一般説明
- Prototype Pollution の定義と、なぜ危険かは PortSwigger と OWASP が明確に述べている。:contentReference[oaicite:18]{index=18}

### シナリオB
- query string のネストパースでオブジェクトが生成され、そのオブジェクトを後段で merge している
- qs の advisory のように、特定キーによりプロセスが不安定になる類型がある。:contentReference[oaicite:19]{index=19}

---

## 防御設計（source を潰す順序）
1) 入口で危険キーを拒否する
   - parse 直後に「許容キーのみ」を残す
2) merge をやめるか、安全な merge に置き換える
   - 深いマージを避け、明示的フィールド代入へ
3) 共有オブジェクトへ入力を混ぜない
   - リクエスト単位のコピーに閉じる
4) 構造制限を必須化
   - 深さ、ノード数、配列長、最大サイズ
5) 依存の更新と固定
   - lodash.merge の既知脆弱性や、qs の advisory のような経路を潰す。:contentReference[oaicite:20]{index=20}

OWASP のチートシートは、これらを複層防御として整理している。:contentReference[oaicite:21]{index=21}

---

## 次に進む前のチェックリスト（source 確定用）
- どの入力面で「ネスト」が作れるかを列挙できたか
- 同名パラメータ多重送信で型が変わるかを観測したか（HPP）:contentReference[oaicite:22]{index=22}
- parse と merge の境界がどこかを説明できるか
- 依存ライブラリと設定差分が疑える根拠が取れているか
- 共有オブジェクトへマージされる設計かを推定できるか

---

## コマンドやペイロード例について
本プロジェクトは実務の診断員向けだが、source の章は「手口の列挙」よりも、境界を確定するための観測設計と防御設計を優先する。
具体的な入力差分は、許可された検証環境で `04_labs` とセットで組み立てる。

---

## 深掘りリンク（最大8）
- `05_input_14_prototype_pollution_02_sinks（authz_template_rce）.md`
- `05_input_13_deserialization_01_json（polymorphism_typehint）.md`
- `05_input_13_deserialization_02_yaml（anchors_tags）.md`
- `05_input_18_http_request_smuggling_01_te_cl（proxy_desync）.md`
- `05_input_19_cache_poisoning_01_keying（vary_normalization）.md`
- `04_api_09_error_model_情報漏えい（例外_スタック）.md`
- `06_config_02_Secrets管理と漏えい経路（JS_ログ_設定_クラウド）.md`
- `03_authz_01_境界モデル（オブジェクト_ロール_テナント）.md`
