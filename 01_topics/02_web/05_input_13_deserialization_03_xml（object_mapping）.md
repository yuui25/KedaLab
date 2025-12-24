## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS
  - XMLの危険はXXE（外部実体）だけではなく、**XML→オブジェクト復元（binding/object mapping）**が「型決定」「暗黙変換」「フック実行」を含み、入力→実行境界になり得る点。
  - 破綻パターンは、(1) 任意クラス/型を外部入力が選べる、(2) 反射/動的ロードにより“予期しない型”が生成される、(3) 復元後のフック（setter/callback/validation）が危険sinkへ到達、(4) パーサ機能（DTD/XInclude等）により到達性や情報漏えいが発生、(5) リソース制限不足でDoS。
- WSTG
  - XML入力を扱う機能（SAML、SOAP、RSS/Atom、Office系XML、独自Import）で、XXEに加えて **オブジェクトマッピング（JAXB/XStream/XmlSerializer等）**の境界（型・構造・深さ・未知要素・属性・名前空間）を差分で検証する。
- PTES
  - 情報収集：XMLが入る入口（SAML/SOAP/import/webhook/連携）と実装（言語・ライブラリ・設定）を特定。
  - 脆弱性分析：object mapping の“型決定点”と“復元後に何が走るか（フック/変換/評価）”をモデル化。
  - 侵害評価：RCEに短絡せず、まず「外部入力で型/構造が制御できる」→「危険な処理経路へ到達する」までを成立根拠として固める。
- MITRE ATT&CK
  - 初期侵入：T1190（公開アプリの脆弱性悪用：XML入力→unsafe mapping）
  - 実行/影響（成立条件つき）：
    - 型選択や危険フックが成立し、かつ実行権限・到達性がある場合に、SSRF/情報漏えい/改ざん/DoS、場合によりRCEへ接続。

---

## タイトル
XML（object mapping）：型・名前空間・属性が“復元モデル”を切り替え、入力→実行境界を太くする

---

## 目的（このファイルで到達する状態）
- 「XML＝XXE」だけで終わらず、XML→オブジェクト復元で現実に問題になる境界を、次の形で説明できる。
  1) 入口（どの機能がXMLを受け、どの“復元器”が動くか）
  2) 型決定（どのクラス/型へバインドされるかが入力で揺れるか）
  3) 復元後フック（setter/callback/validation/transform）で何が走るか
  4) 例外/フォールバック（安全な復元→危険な復元へ落ちる経路があるか）
  5) 影響（SSRF/情報漏えい/DoS/設定改ざん/権限逸脱、必要ならRCE評価）
- 診断では、少数の“差分入力”で「object mapping が存在する」「型/構造の境界が弱い」を確定し、修正提案を設計条件で出せる。

---

## 扱う範囲（本ファイルの守備範囲）
- 本ファイル：XML→オブジェクト復元（object mapping / data binding）
  - 例：Java（JAXB/XStream等）、.NET（XmlSerializer/DataContractSerializer等）、PHP（XML→配列/オブジェクト）、Python（lxml等のobjectify）
  - 型決定、名前空間、属性、要素順、未知要素、ポリモーフィズム、復元後フック、DoS（深さ/要素数）
- 直接は扱わない（ただし接続は必須）：
  - XXE（外部実体/DTD/OOB）は `05_input_08_xxe_*` で深掘り済み
  - XPath/XSLT 等の“クエリ注入”は別論点（必要なら追加分割）
- 接続先：
  - `05_input_08_xxe_01_parser（doctype_entity）.md`
  - `05_input_08_xxe_03_to_ssrf（internal_reachability）.md`
  - `05_input_13_deserialization_01_json（polymorphism_typehint）.md`
  - `05_input_13_deserialization_02_yaml（anchors_tags）.md`

---

## 前提：XMLが現れる“実務の入口”一覧（攻撃面の棚卸し）
- SAML / WS-Fed / SOAP（XML前提のプロトコル）
- 監査・設定のimport/export（バックアップ復元、ルール定義、ポリシー）
- Office系（docx/xlsx/pptxはZIP＋XML：中身はXML）
- フィード（RSS/Atom）、メタデータ（SVG、古い画像/文書系）
- 内部連携（B2BでXML連携、EDI、決済/配送の古いIF）

結論：XMLは“レガシー”ではなく、SaaS/SSO/業務連携で現役。入口が管理者限定でも、被害は大きい。

---

## 境界モデル（XML→オブジェクト復元の本質）
### 1) データフロー（最小モデル）
XML bytes
→ Parser（構文解析：DTD/名前空間/エンコーディング）
→ Binder（オブジェクト復元：クラス/型にマップ）
→ Hooks（setter/callback/adapter/converter）
→ Domain（検証/保存/実行）
→ Sink（HTTP fetch/テンプレ/FS/SQL/コマンド/ジョブ…）

危険が出る位置は2つ：
- Parser：XXE/DTD/XInclude/巨大展開（別ファイルと接続）
- Binder/Hooks：型決定・反射・フック実行（本ファイルの主戦場）

### 2) 「XMLならではの型決定ポイント」
- 名前空間（xmlns）や要素名が “別の型” を意味する（実装次第で分岐）
- 属性（xsi:type 等）が “派生型” を指示する（ポリモーフィズムの土台）
- 要素順・省略・未知要素が、復元ルール（デフォルト値/フォールバック）を変える

---

## 破綻パターン（差分＝成立根拠で使う）
> 重要：RCEの手順ではなく、「境界が壊れている事実」を差分で固める。

### パターンA：外部入力で“型が選べる”（ポリモーフィズム/派生型）
- 兆候（観測しやすい差分）：
  - 同じエンドポイントで、要素名/名前空間/属性を変えると別のエラーメッセージ・別の処理結果になる
  - “subtype/type/cannot instantiate abstract” のようなエラーが出る
- 何が危険か：
  - 型が変わる＝復元後に走るsetter/adapter/converterが変わり、sinkへ到達する経路が増える

### パターンB：任意クラス/危険クラスの生成（unsafe mapping）
- 兆候：
  - クラス名や型名に相当する文字列がエラーに出る／指定できる設計がある
  - “セキュリティ例外（許可されない型）” が出るなら、逆に言うと“型ガードが必要な設計”になっている
- 何が危険か：
  - 型ガードがないと、入力で“思っていないオブジェクト”が生成され得る（影響は環境に依存）

### パターンC：復元後フックが危険sinkへ到達（最も現実的）
- 典型：
  - setterでURLを解釈しフェッチ（SSRF）
  - converter/adapterがファイルパスを解釈（path traversal/ローカル参照）
  - validationの前にテンプレ評価・式評価が走る（入力→実行）
- 兆候：
  - “復元は成功するが、後段で通信/ファイルアクセス/重い処理” が発生する
  - ログで「復元直後に別サービスへアクセス」などが見える

### パターンD：フォールバック経路が穴（安全→危険に落ちる）
- 典型：
  - まず厳格スキーマでパース→失敗したら“ゆるい復元”（Map/Any）へ
  - バージョン互換（v1/v2）で複数の復元器を持つ
- 兆候：
  - 同じ入力でも、わずかな違いで “別エラー分類” になる（例：400→500、validation→binding）

### パターンE：リソース枯渇（XML bombs/深いネスト/要素数）
- XXE由来のBillion Laughsだけでなく、**オブジェクト生成の数**（大量要素→大量インスタンス）もDoS要因
- 兆候：
  - 要素数/深さに比例して極端に遅い、タイムアウトがない、ワーカーが詰まる

---

## 観測ポイント（薄くしない：どこを見ると境界が確定するか）
### 1) HTTP（外部から取れる根拠）
- Content-Typeの扱い（application/xml / text/xml / soap+xml / form内XML文字列）
- エラーの語彙（parser/binder/hook/validationのどこで落ちたか）
- 同一入力で、要素名・名前空間・属性だけ変えた場合の差分（エラー種別、処理時間、結果）

### 2) 成功時の“反映”のされ方
- GETで返るXML/JSONに、入力の要素・属性がどこまで残るか（正規化/削除の有無）
- デフォルト値が補完されるか（= binderが動いている兆候）
- 未知要素が無視されるか、拒否されるか（strict vs lax）

### 3) サーバログ（可能なら依頼：価値が高い）
~~~~
request_id
endpoint / feature (saml|soap|import|feed)
xml_parser (name/version if possible)
dtd_enabled / external_entities / xinclude (on/off)
binding_framework (name)
target_type (base type)
polymorphism_enabled (yes/no; discriminator)
unknown_element_policy (reject|ignore|collect)
schema_validation (pre|post|none)
hook_invoked (converter/adapter/setter)
error_class (parse|bind|validate|domain)
payload_bytes / max_depth / element_count
~~~~

---

## 検証設計（意味→判断→次の一手：差分で“復元器の存在”を確定）
> 攻撃手順ではなく「成立根拠」を作るための設計。

### 差分セットX1：名前空間/要素名の変更（型決定の有無）
- 目的：要素名やxmlnsで処理が分岐するか（= bindingが型/モデルに依存）
- 判断：
  - エラー分類が変わる／別のフィールドが反映される → 型/モデルの境界がある

### 差分セットX2：未知要素の注入（strictnessの確定）
- 目的：unknown element を拒否するか、無視するか
- 判断：
  - 拒否：スキーマ/モデルが強い（ただしフォールバックがないか確認）
  - 無視：余剰データが後段で拾われる可能性（“二段階パース”がないか要注意）

### 差分セットX3：属性による分岐（ポリモーフィズムの土台）
- 目的：属性が型/処理経路を変えるか（xsi:type相当の挙動）
- 判断：
  - 具体型を示唆するエラーが出る／挙動が変わる → 派生型の仕組みがある

### 差分セットX4：要素数/深さの上限（DoS土壌）
- 目的：サイズ・深さ・要素数の制限があるか
- 判断：
  - 明確に拒否（413/400など）→ 健全
  - 受理して重くなる→ DoS所見（再現は安全に最小で止める）

---

## 攻撃者視点（現実寄り）：狙う入口と“影響の出し方”
### 1) “import/復元”がある管理機能は最優先
- 理由：復元後に設定が反映され、影響が即“システム挙動”として出る（通知先、連携先、権限ルール）

### 2) SAML/SOAPは「XMLを食う」だけでなく「型/検証の層」が複雑
- 署名検証（XML canonicalization）や検証タイミングが絡むと、例外パスで別処理に落ちやすい
- 本ファイルの焦点は object mapping だが、実務では `XXE` と “検証順序” が事故の主因になりがち

### 3) “RCE”より先に現実的なゴール（SSRF/設定改ざん/情報漏えい/DoS）
- XML復元は、URL/パス/テンプレ等の設定値を運ぶ器になりやすい
- 復元後フックで通信が出るなら、SSRFは現実的で再現性が高い（ただし詳細テクはSSRF側で深掘り）

---

## 防御（設計としての優先順位：復元器の能力を落とす）
### 1) XML parser を安全化（XXE対策は前提）
- DTD/外部実体/XIncludeを無効化、サイズ/深さ/要素数の上限
- これは `05_input_08_xxe_*` と必ず整合させる（“片方だけ”は破綻する）

### 2) object mapping は “型を外部入力から切り離す”
- 任意クラス生成を禁止（型名直指定の禁止）
- ポリモーフィズムが必要なら：
  - discriminator（短い識別子）を allowlist でマップ
  - 未知 subtype は拒否
- 復元先は `Any/Object` を避け、スキーマ固定（strict）

### 3) スキーマ検証（XSD等）は「復元前」に寄せ、復元後も不変条件を検証
- pre：構造・必須要素・型・長さ・回数
- post：業務不変条件、認可境界（role/tenant/objectの整合）

### 4) フック（adapter/converter/setter）の危険sinkを排除
- 例：復元直後にURLフェッチ、FSアクセス、テンプレ評価をしない
- 必要なら“後段で明示的に”行い、許可リスト・到達性制御・監査を入れる

### 5) 例外のサニタイズと監査ログ
- エラーでクラス名・パス・スタックを返さない（情報露出は攻撃の加速材）
- ただし内部ログには `error_class` と `reject_reason` を残し、運用で検知できる形にする

---

## 次に試すこと（仮説A/B：検証の分岐）
### 仮説A：strict binding + schema検証あり（比較的健全）
- 次の一手：
  - フォールバック（lax parsing / Map復元）が存在しないかを探す（例外時だけ動く経路）
  - unknown element が無視されるなら、二段階パース（XML→文字列→別評価）がないか確認

### 仮説B：lax binding / ポリモーフィズム有効 / フックが強い（高リスク）
- 次の一手：
  - “型が変えられる入口”の権限境界を確定（一般ユーザ・外部連携なら優先度最大）
  - 復元後に到達するsink（URL/FS/テンプレ/ジョブ）を特定し、影響を業務機能として報告に落とす
  - RCE再現に固執せず、境界欠陥（型決定開放＋危険フック）を主所見にする

---

## 04_labs での再現（境界理解用：実装比較で学ぶ）
- 追加候補Lab（例）
  - `04_labs/02_web/05_input/13_deserialization_xml_object_mapping/`
- Lab設計要件（差分で理解する）
  1) 安全：DTD無効＋strict schema＋allowlist subtype＋未知要素拒否
  2) 中：DTD無効だが、unknown element ignore、ポリモーフィズムあり
  3) 危険：lax binding（型自由度高い）＋復元後フックで外部参照（※実害は出さず“外部参照が走る”観測で止める）
- ログに必須：
  - `dtd_enabled/external_entities/xinclude`
  - `binding_framework/target_type/polymorphism_enabled`
  - `unknown_element_policy/schema_validation_phase`
  - `hook_invoked`

---

## コマンド/リクエスト例（例示は最小限：概念のみ）
~~~~
# 目的は「型決定/未知要素/属性分岐があるか」を差分で観測すること
# - 要素名/名前空間だけ変えてエラー分類が変わるか
# - 未知要素が拒否されるか無視されるか
# - 属性の付与で分岐（subtype）が起きるか
~~~~

---

## 深掘りリンク（最大8）
- `05_input_13_deserialization_01_json（polymorphism_typehint）.md`
- `05_input_13_deserialization_02_yaml（anchors_tags）.md`
- `05_input_08_xxe_01_parser（doctype_entity）.md`
- `05_input_08_xxe_02_blind（oob）.md`
- `05_input_08_xxe_03_to_ssrf（internal_reachability）.md`
- `05_input_09_ssrf_01_reachability（internal_localhost_metadata）.md`
- `05_input_01_入力→実行境界（テンプレート注入_SSTI）.md`
- `04_api_09_error_model_情報漏えい（例外_スタック）.md`
