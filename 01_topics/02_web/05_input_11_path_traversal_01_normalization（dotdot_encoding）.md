# 05_input_11_path_traversal_01_normalization（dotdot_encoding）

正規化（dotdot / encoding）の破綻で起きる Path Traversal：検証前の「見かけの安全」が崩れる

## 目的（この技術で到達する状態）
- 「../」を試す段階で止まらず、**正規化のどの段が欠けて境界が壊れたか**を説明できる。
- 実務で次を即断できる：
  - 入力点ごとの正規化（URL path / query / body / header）の違い
  - デコード順（1回/複数回）と正規化（dot segment解決、区切り統一）の不一致が起こす差分
  - ベースディレクトリ拘束の"強い実装"と"弱い実装"の見分け
- 次ファイルへ接続できる：
  - `05_input_11_path_traversal_02_join_root（allowlist_basedir）.md`：base dir拘束とrealpath/シンボリックリンク
  - `05_input_12_file_upload_05_archive_processor（zip_tar_7z）.md`：アーカイブ展開時の正規化不備

## 前提（対象・範囲・想定）
- 対象：ユーザ入力（ファイル名/パス/ID）をそのままファイルAPIへ渡す設計、Path Traversal（CWE-22）、正規化（Normalization / Canonicalization）の破綻
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - クラウド/オンプレミス、ミドルウェア（リバプロ/フレームワーク）が先にデコードや正規化をする環境
  - OSが最終的に解決する環境（dot segment、区切り、ドライブ、UNC、シンボリックリンク等）
  - worker/バッチ/別言語サービスでファイル解釈が異なる環境
- できること/やらないこと（安全に検証する範囲）：
  - できること：正規化パイプラインの整合性を差分で立証する、成立根拠（N1→N3の鎖）を固める
  - やらないこと：破壊的な処理の実行、本番環境での過度な試行、設定改変・永続化・実行連鎖の実証（許可範囲外）
- 依存する前提知識（必要最小限）：
  - `05_input_00_入力→実行境界（テンプレ デシリアライズ等）.md`
  - `03_authz_08_file_access_ダウンロード認可（署名URL）.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：
    - Path Traversal（CWE-22）：入力から構築したパスが、本来許可された親ディレクトリ配下に収まる想定なのに、`..` や区切り等の特殊要素により親ディレクトリ外へ解決されること
    - 正規化（Normalization / Canonicalization）：(1) デコード、(2) 区切り文字統一、(3) dot segment（`.`/`..`）解決、(4) ルート・ドライブ・UNC等の扱い
    - base directory（制限親ディレクトリ）：許可されたファイル参照が収まるべき基準パス
    - 正規化パイプライン（decode→normalize→join→resolve）のどこがズレるか
  - 扱わない（別ユニットへ接続）：
    - base dir拘束とrealpath/シンボリックリンク → `05_input_11_path_traversal_02_join_root（allowlist_basedir）.md`
    - アーカイブ展開時の正規化不備 → `05_input_12_file_upload_05_archive_processor（zip_tar_7z）.md`
    - 認可境界（IDOR型のファイル参照） → `03_authz_08_file_access_ダウンロード認可（署名URL）.md`

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
- 観測対象（プロトコル/データ構造/やり取りの単位）：
  - アプリログ（raw_input / decoded_input / normalized_path / base_dir / resolved_path / decision / trace_id / request_id）
  - ネットワーク/HTTP観測（どの入力点に入ったか、どの層で変換されたか、成功時の"差分"）
- 境界の観点：
  - 資産境界（管理主体・委託先・対象範囲の線引き）：
    - アプリが「入力をパスに変換する瞬間」
    - ミドルウェア（リバプロ/フレームワーク）が「先にデコードや正規化をする瞬間」
    - OSが「最終的に解決する瞬間（dot segment、区切り、ドライブ、UNC、シンボリックリンク等）」
  - 信頼境界（外部連携・第三者・越境ポイント）：
    - 実装側は多くの場合「禁止文字を除く」「../を含むなら弾く」などの"見かけの検査"を入れる
    - 攻撃側は「同じ意味を別表現で作る」ことで検査をすり抜ける（`..` の表現揺れ、区切りの表現揺れ、解釈層の差）
  - 権限境界（権限の切替/伝播/委任）：
    - 検証が"正規化前の文字列"に対して行われている場合、権限境界が崩れる可能性がある
- 重要なフィールド/差分/状態（「ここが変わると意味が変わる」点）：
  - 状態N0：ファイル参照が入力で選べる
  - 状態N1：検証が"正規化前の文字列"に対して行われている
  - 状態N2：アプリ/ミドルウェア/OSでデコード・正規化の回数や対象がズレる
  - 状態N3：最終的に base directory 外の実体へ解決される

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が"確定"できるか：
  - 正規化のどの段が欠けて境界が壊れたか
  - 入力点ごとの正規化（URL path / query / body / header）の違い
  - デコード順（1回/複数回）と正規化（dot segment解決、区切り統一）の不一致が起こす差分
  - ベースディレクトリ拘束の"強い実装"と"弱い実装"の見分け
- 何が"推定"できるか（推定の根拠/前提）：
  - どの層がどう正規化しているか（同じ入力点で、表現だけ変えてレスポンス差分が出るか）
  - 正規化の有無（成功/失敗、エラー種別、サイズの差分）
  - 正規化バイパスの可能性（dotdot（..）の表現揺れ、区切り（separator）の表現揺れ、デコード回数・順序、OS/実行環境差）
- 何は"言えない"か（不足情報・観測限界）：
  - 診断で重要なのは「禁止表現の網羅」ではなく、**正規化パイプラインの整合性**を差分で立証すること
  - 設定改変・永続化・実行連鎖の実証（許可範囲外）
  - 実行系の内部実装詳細（デコード回数の具体的な値、正規化アルゴリズムの詳細）
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：デコード・正規化が一貫しており、dotdot/encoding では外に出られない（比較的安全）
  - パターンB：正規化前検証 or 解釈ズレがあり、dotdot/encoding で境界が崩れる（高リスク）
  - パターンC：入口の分類（URL path に混ざる traversal、query / body の traversal、保存先パス）で正規化が変わる

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す"狙い目"：
  - 価値が高い到達先（アプリ設定、ソース/テンプレ、環境情報）
  - 入口の棚卸し（download/view/include/template/render/export/upload）
  - "ファイル名っぽい値"だけでなく、言語/テーマ/テンプレ名（lang=, theme=）も対象
- 優先度の付け方（時間制約がある場合の順序）：
  1) 入口の棚卸し（入力点×機能）
  2) 正規化の有無を差分で推定（どの層がどう正規化しているか）
  3) 成立根拠を固める（N1→N3の鎖）
- 代表的な攻め筋（この観測から自然に繋がるもの）：
  - 攻め筋1：正規化バイパス（dotdot（..）の表現揺れ、区切り（separator）の表現揺れ、デコード回数・順序、OS/実行環境差）
  - 攻め筋2：正規化前検証の回避（decode/normalizeの順序差を利用）
  - 攻め筋3：解釈ズレの利用（アプリ/ミドルウェア/OSでデコード・正規化の回数や対象がズレる）
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）：
  - 実装側は多くの場合「禁止文字を除く」「../を含むなら弾く」などの"見かけの検査"を入れる
  - 攻撃側は「同じ意味を別表現で作る」ことで検査をすり抜ける
  - 診断で重要なのは「禁止表現の網羅」ではなく、**正規化パイプラインの整合性**を差分で立証すること

## 次に試すこと（仮説A/Bの分岐と検証）
> ここが最重要。条件が違うと次の手が変わる形で書く。

- 仮説A：デコード・正規化が一貫しており、dotdot/encoding では外に出られない
  - 次の検証：
    - `05_input_11_path_traversal_02_join_root（allowlist_basedir）.md` の観点へ移動：シンボリックリンク/ショートカット/別マウント等で"実体が外に出る"可能性を確認
    - 認可境界（03_authz）へ接続：そもそも"参照してよいファイル"の権限モデルがあるか（IDOR型のファイル参照）
  - 期待する観測（成功/失敗時に何が見えるか）：
    - 表現揺れ（encoded/混在）でも挙動が変わらない
    - 正規化後に必ず拒否される（rule_idが一定）
- 仮説B：正規化前検証 or 解釈ズレがあり、dotdot/encoding で境界が崩れる
  - 次の検証：
    - 影響の切り分け：読み取りのみか、書き込みまで届くか（アップロード保存先・エクスポート・ログ）
    - 連鎖評価：秘密情報・設定・テンプレ等、二次被害に直結する"高価値ファイル"のクラスを特定（具体ファイル名の列挙でなく、カテゴリで整理）
    - 修正提案：ID参照化 or 正規化後の実体判定＋base dir拘束（次ファイルの対策へ接続）
  - 期待する観測：
    - 表現を変えると拒否/許可が変わる（再現性がある）
    - 同一機能で参照先が変わる／存在判定ができる

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：`04_labs/02_web/05_input/11_path_traversal_normalization/`（追加候補）
- 取得する証跡（目的ベースで最小限）：
  - request_id、入力点（path/query/body/header）、正規化各段の値、最終解決パス、判定ルールID
  - アプリログ（raw_input / decoded_input / normalized_path / base_dir / resolved_path / decision / trace_id / request_id）
  - ネットワーク/HTTP観測（どの入力点に入ったか、どの層で変換されたか、成功時の"差分"）
- 観測の取り方（どの視点で差分を見るか）：
  - 同一機能に対し、(1) 正規化前検証、(2) decode回数差、(3) separator混在、を切り替えられる最小アプリを用意し、`raw_input -> decoded -> normalized -> resolved_path -> decision` をログで一貫して観測できる状態にする
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/path_traversal_normalization 2>/dev/null
    cd ~/keda_evidence/path_traversal_normalization
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可されたスコープ** のみ
      - 観測は **代表点の抽出** のみ
      - 設定改変・永続化・実行連鎖の実証は許可範囲外
  - 相関キー（最低限）を作る（後で必ず効く）
    - request_id, input_channel, raw_input, decoded_input, normalized_input, base_dir, resolved_path, decision, rule_id

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は"手段"であり"結論"ではない。必ず「何を観測している例か」を添える。

~~~~
# 観測ログの最小フィールド例（設計用）
# - request_id
# - input_channel: path|query|body|header|cookie
# - raw_input
# - decoded_input
# - normalized_input
# - base_dir
# - resolved_path
# - decision: allow|deny
# - rule_id
~~~~

- この例で観測していること：
  - 正規化パイプライン（decode→normalize→join→resolve）のどこがズレるか
  - 正規化前検証の回避可能性
  - 解釈ズレの利用可能性
- 出力のどこを見るか（注目点）：
  - raw_input → decoded_input → normalized_input → resolved_path の各段階での値の変化
  - decision と rule_id の一貫性
  - 成功時の"差分"（期待したファイルと別のファイルが返る、エラーが変わる）
- この例が使えないケース（前提が崩れるケース）：
  - ログが取得できない環境、またはログ設計が不十分な場合

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：V5 Validation, Sanitization and Encoding
  - 該当要件（可能ならID）：V5.1.1、V5.1.2、V5.2.1
  - このファイルの内容が「満たす/破れる」ポイント：
    - ユーザ入力（ファイル名/パス/ID）をそのままファイルAPIへ渡す設計は、パストラバーサル（CWE-22）の温床。特に「正規化（canonicalization）前の検証」「デコード順の不一致」「区切り文字の混在」「dot-segment（..）の解釈差」は、allowlist/denylistを容易に破る。
    - "ファイル名メタデータを直接使わない"要件（ASVS 4.0系の代表要求）は、まさに本ファイルの対象（入力→FS境界）を押さえる。
    - 満たす：入力で"パス"を受け取らない（ID参照へ寄せる）、「単一パイプライン」で decode→normalize→拘束 を固定する、base directory 拘束は"正規化後の実体"で判定する、ログと拒否理由を"安全に"残す
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：WSTG-ATHZ-01 Directory Traversal / File Include
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：
    - Directory Traversal / File Include（WSTG-ATHZ-01）を、単なる「../試す」から一段進めて「正規化パイプライン（decode→normalize→join→resolve）のどこがズレるか」を観測で確定する。
    - 入力点の特定（param/header/path/cookie/body）→ 正規化の差分（単純../ vs encoded/double-encoded vs separator混在）→ 結果の差分（403/404/200/別ファイル）→ ログで"実際に解決されたパス"を証拠化。
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Vulnerability Analysis、Exploitation、Reporting
  - 前後フェーズとの繋がり（1行）：
    - Vulnerability Analysis：正規化の設計欠陥（decode回数、区切り文字、OS差、ミドルウェア差）をモデル化する。Exploitation：目的はペイロード網羅ではなく「どの層の正規化が欠け、base directory境界が崩れたか」を再現性で立証する。Reporting：修正は"入力を厳しく"ではなく「安全な参照方式（ID→サーバ引き当て）」「正規化後の実体判定」「base dir拘束」「シンボリックリンク対策」「監査ログ」のセットで提案する。
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Initial Access、Credential Access、Discovery、Impact、Execution
  - 攻撃者の目的（この技術が支える意図）：
    - 入口：T1190（公開アプリの脆弱性悪用）
    - Credential Access：設定/秘密情報ファイルの読取（クラウドキー、DB接続情報、APIキー）
    - Discovery：内部パス構造・デプロイ構成・環境変数の特定
    - Impact/Execution：書込みや実行可能パスに到達できると、RCEや永続化へ連鎖し得る（ただし"成立条件"で切り分ける）
  - 参照：https://attack.mitre.org/tactics/TA0001/

## 参考（必要最小限）
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
- OWASP Path Traversal
- OWASP WSTG: Testing for Directory Traversal / File Include
- PortSwigger: Path traversal

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`05_input_11_path_traversal_02_join_root（allowlist_basedir）.md`
- 関連 topics：`05_input_12_file_upload_05_archive_processor（zip_tar_7z）.md`
- 関連 topics：`03_authz_08_file_access_ダウンロード認可（署名URL）.md`

---

## 深掘りリンク（最大8）
- `05_input_11_path_traversal_02_join_root（allowlist_basedir）.md`
- `05_input_11_path_traversal_03_archive（zip_slip）.md`
- `05_input_12_file_upload_02_storage_path（bucket_acl_traversal）.md`
- `03_authz_08_file_access_ダウンロード認可（署名URL）.md`
- `06_config_02_Secrets管理と漏えい経路（JS_ログ_設定_クラウド）.md`
- `04_api_08_file_export_エクスポート境界（CSV_PDF）.md`
- `02_playbooks/02_web_recon_入口→境界→検証方針.md`
- `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
