# 05_input_14_prototype_pollution_01_sources（merge_parse）
Prototype Pollution の source を分解する。parse と merge と set のどこで危険キーが通るかを差分で確定する

---

## 目的（この技術で到達する状態）
- 次を「成立根拠」として説明できる。
  1) どの入力面が、ユーザ入力をオブジェクトのキーとして扱うか
  2) parse と merge と set のどの段で危険キーが遮断されていないか
  3) 依存ライブラリや設定差分により、同じ見た目でも成立可否が変わる理由
- PoCの芸当ではなく、設計欠陥として報告できる形に落とす。
  - 「危険キーが到達する経路」＋「防御境界が欠けている箇所」＋「影響は次ファイルで接続」

## 前提（対象・範囲・想定）
- 対象：許可された範囲のWebアプリ/環境のみ。
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - Node.js、Python、Ruby等のサーバサイド実装が一般的。
- できること/やらないこと（安全に検証する範囲）：
  - やらないこと：破壊的試験や過剰負荷。DoSを起こさずに観測する。
- 依存する前提知識（必要最小限）：
  - `01_topics/02_web/05_input_00_入力→実行境界（テンプレ デシリアライズ等）.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：
    - parse 型 source（query string、JSON body、form、cookie の構造化）
    - merge 型 source（深いマージ、共有オブジェクトへの混入）
    - set 型 source（パス表現での代入）
    - 危険キーとガードの考え方
  - 扱わない（別ユニットへ接続）：
    - sink（影響点）の詳細 → `05_input_14_prototype_pollution_02_sinks（authz_template_rce）.md`
    - デシリアライズの詳細 → `05_input_13_deserialization_*.md`

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
- 観測対象（プロトコル/データ構造/やり取りの単位）：
  - 入力面（query string、JSON body、form、cookie、WebSocket、import）
  - parse の挙動（ネスト展開、同名パラメータの扱い、危険キーの拒否）
  - merge の挙動（深いマージ、共有オブジェクトへの混入）
  - set の挙動（パス解釈、正規化）
- 境界の観点：
  - 資産境界（管理主体・委託先・対象範囲の線引き）：入力がどのオブジェクトに到達するか
  - 信頼境界（外部連携・第三者・越境ポイント）：外部入力が内部状態オブジェクトに混入するか
  - 権限境界（権限の切替/伝播/委任）：汚染が認可判定に影響するか（sink側で評価）
- 重要なフィールド/差分/状態（「ここが変わると意味が変わる」点）：
  - ネスト表現（bracket/dot）の有効性
  - 同名パラメータ多重送信（HPP）での型変化
  - 危険キー（__proto__、constructor、prototype等）の遮断有無
  - 依存ライブラリ（qs、lodash.merge等）のバージョンと設定

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が"確定"できるか：
  - どの入力面で構造化が行われているか
  - parse と merge の境界がどこか
  - 危険キーが通る経路があるか
- 何が"推定"できるか（推定の根拠/前提）：
  - 依存ライブラリの種類とバージョン（例外、スタック、ビルド成果物から）
  - 共有オブジェクトへの混入の可能性（設計・ログから）
- 何は"言えない"か（不足情報・観測限界）：
  - 実害（sink）の有無（次ファイルで評価）
  - すべての入力面を網羅した断定（観測範囲に依存）
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：query string のネストパースでオブジェクトが生成され、後段で merge している → qs の advisory のように、特定キーによりプロセスが不安定になる類型がある
  - パターンB：JSON body の parse で危険キーが残り、後段で merge している → プロフィール更新や設定更新で成立しやすい
  - パターンC：依存ライブラリ（lodash.merge、qs）の既知脆弱性があるが、バージョンや設定で成立可否が変わる

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す"狙い目"：
  - 入力が構造化され、既存オブジェクトにマージされる設計
  - 共有オブジェクト（config、policy、template context）への混入
- 優先度の付け方（時間制約がある場合の順序）：
  1) 認可判定に使われるオブジェクトへの到達（sink側で評価）
  2) テンプレ変数解決に使われるオブジェクトへの到達（sink側で評価）
  3) 危険APIのオプションオブジェクトへの到達（sink側で評価）
- 代表的な攻め筋（この観測から自然に繋がるもの）：
  - 攻め筋1：query string のネストパースで危険キーを通し、後段 merge で共有オブジェクトを汚染
  - 攻め筋2：JSON body の parse で危険キーを通し、プロフィール更新等で merge して汚染
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）：
  - 依存ライブラリの種類が不明な場合、例外やスタックから推定する
  - 設定差分（parser のオプション）で成立可否が変わるため、環境差を考慮する

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：query string のネストパースでオブジェクトが生成される
  - 次の検証：
    - パラメータの重複で、型が string から array に変化するか（HPP）を観測
    - 入力がネストとして復元されるか（アプリが返す JSON、ログ、エラーメッセージ、挙動で推定）
  - 期待する観測（成功/失敗時に何が見えるか）：
    - ネストが作れることが確定し、危険キーが通る可能性が示される
- 仮説B：JSON body の parse で危険キーが残る
  - 次の検証：
    - 入力 JSON の未知キーがサーバで保持されるか（echo、保存、ログ）を観測
    - 例外文言に「型解決」「マッピング」「未知フィールド」が出るか（境界の位置がわかる）
  - 期待する観測：
    - 危険キーが parse 段階で残ることが確定し、後段 merge での汚染可能性が示される
- 仮説C：依存ライブラリや設定差分で成立可否が変わる
  - 次の検証：
    - Node の query parser が qs かどうか、バージョン差があるかを推定する
    - lodash merge を使っている兆候があるかを推定する（例外のスタック、ビルド成果物、ヘッダ、ソースマップ、依存一覧など）
  - 期待する観測：
    - 既知の脆弱性履歴がある依存（lodash.merge、qs）は成立根拠の補強材料になる

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/02_web/05_input/14_prototype_pollution_sources/`（追加候補）
- 取得する証跡（目的ベースで最小限）：
  - HTTPログ/har、サーバログ、例外スタック、依存一覧
  - 入力→parse→merge の各段階でのオブジェクト状態
- 観測の取り方（どの視点で差分を見るか）：
  - メモに必ず残す項目：入力面、parse の挙動、merge の有無、危険キーの遮断有無、依存ライブラリ
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/prototype_pollution_sources 2>/dev/null
    cd ~/keda_evidence/prototype_pollution_sources
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可されたスコープ** のみ
      - 観測は **最小限の差分セット** のみ（DoSを起こさずに観測する）
      - 依存ライブラリの特定は例外やスタックから推定し、過度な探索は行わない
  - 相関キー（最低限）を作る（後で必ず効く）
    - Host、User、Time、入力面（query/body/form/cookie）、parse 段階、merge 段階、危険キー、依存ライブラリ

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は"手段"であり"結論"ではない。必ず「何を観測している例か」を添える。

~~~~
# 例：query string のネストパースを観測
curl -i "https://example.com/api?user[name]=test&user[__proto__][isAdmin]=true"

# 例：JSON body の parse を観測
curl -i -X POST https://example.com/api/profile \
  -H "Content-Type: application/json" \
  -d '{"name":"test","__proto__":{"isAdmin":true}}'
~~~~

- この例で観測していること：
  - parse 段階で危険キーが通るか、ネストが作れるか
- 出力のどこを見るか（注目点）：
  - レスポンスの JSON、エラーメッセージ、ログ、例外スタック
- この例が使えないケース（前提が崩れるケース）：
  - 入力バリデーションで早期に拒否される場合、parse 段階まで到達しない

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：入力検証、データ保護
  - 該当要件（可能ならID）：入力値のサニタイズ、危険キーの遮断
  - このファイルの内容が「満たす/破れる」ポイント：
    - 破れる：Prototype Pollution は「入力値のサニタイズ」ではなく、入力が **キーとして構造に入る** ときの制御不備（危険キーの遮断、マージ手法、型の固定、未知キー拒否）で起きる。
    - 満たす：parse層の危険キー拒否、merge層の安全実装、重要オブジェクトへの外部入力マージ禁止、例外露出抑制、依存ライブラリ更新と設定固定。
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：入力バリデーションの観点として、HPP（同名パラメータの多重送信）や、ネスト表現（bracket/dot）による構造化をテストし、アプリが **どのようにオブジェクトを構築しているか** を確定する。
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：入力が構造化される経路の特定
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：情報収集、脆弱性分析
  - 前後フェーズとの繋がり（1行）：情報収集でどの入口が「構造化入力」を受け、どのライブラリでオブジェクト化するかを特定（query parser / body parser / JSON / YAML / XML / cookie / websocket）。脆弱性分析でsource（parse/merge/set）を特定し、危険キーが通るかを差分で確定。sink（別ファイル）に接続して影響評価。
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：初期侵入：T1190（公開アプリ脆弱性悪用）
  - 攻撃者の目的（この技術が支える意図）：影響：ロジック破壊、権限逸脱、DoS（オブジェクト汚染がトリガになるケース）。注：本ファイルは source（侵入点）に限定し、実行連鎖は `05_input_14_prototype_pollution_02_sinks` 側で扱う。
  - 参照：https://attack.mitre.org/tactics/TA0001/（Initial Access）

## 参考（必要最小限）
- PortSwigger の定義と解説（概念、サーバサイドの成立条件）
- JSON.parse での __proto__ の振る舞い差分など、サーバサイド検出研究
- OWASP の予防策整理（防御設計の方向性）
- 依存ライブラリ起因の代表例（lodash.merge、qs）

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`05_input_14_prototype_pollution_02_sinks（authz_template_rce）.md`
- 関連 topics：`05_input_13_deserialization_01_json（polymorphism_typehint）.md`
- 関連 labs：`04_labs/02_web/05_input/14_prototype_pollution_sources/`（追加候補）

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

---
