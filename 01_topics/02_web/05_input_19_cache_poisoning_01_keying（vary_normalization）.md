# 05_input_19_cache_poisoning_01_keying（vary_normalization）
Cache Poisoning（Keying）：Varyと正規化差でキャッシュキーが崩れると、ユーザ/テナント境界が"キャッシュ側で"破壊される

---

## 目的（この技術で到達する状態）
- 「キャッシュがあるか/効いているか」を超えて、**キャッシュキー＝境界定義** を特定し、壊れ方を根拠付きで説明できる。
  1) どの階層がキャッシュしているか（ブラウザ/CDN/Reverse Proxy/アプリ内）
  2) キーが何で構成されているか（Host/Path/Query/Header/Cookie 等）
  3) 正規化（canonicalization）がどの層でどう行われているか
  4) Keyingが壊れる条件（衝突/分裂）を "観測シグナル→確定証跡" で固める
  5) 実害評価を「境界（ユーザ/テナント/機能）」で切り分け、修正要件へ落とす

## 前提（対象・範囲・想定）
- 対象：許可された範囲のWebアプリ/環境のみ。
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - 多段キャッシュ（ブラウザ/CDN/Reverse Proxy/アプリ内）が一般的。
- できること/やらないこと（安全に検証する範囲）：
  - やらないこと：検証は **少数試行＋証跡重視**（第三者影響の抑制）。侵害評価は「高価値分岐（認可/テナント/管理/配布物）」に届くかで確定する。
- 依存する前提知識（必要最小限）：
  - `01_topics/02_web/06_config_00_設定・運用境界（CORS ヘッダ Secrets）.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：
    - Keying / Vary / Normalization
    - キーの推定（何がキーに入る/入らない）
    - Varyの意味、誤用、現実の"無視されるVary"問題
    - 正規化差（Host/Path/Query/Header）の分類と、衝突/分裂のモデル
    - 多段キャッシュでの「層間不一致」が生む失敗パターン
  - 扱わない（別ユニットへ接続）：
    - unkeyed input の具体パターン → `05_input_19_cache_poisoning_02_unkeyed（headers_params）.md`
    - poisoned object（格納済みの誤レスポンス配布） → `05_input_19_cache_poisoning_03_poisoned_object（stored_response）.md`

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
- 観測対象（プロトコル/データ構造/やり取りの単位）：
  - キャッシュ階層（ブラウザ/CDN/Reverse Proxy/アプリ内）
  - キーの構成要素（Host/Path/Query/Header/Cookie 等）
  - 正規化（canonicalization）がどの層でどう行われているか
  - Keyingが壊れる条件（衝突/分裂）
- 境界の観点：
  - 資産境界（管理主体・委託先・対象範囲の線引き）：どの階層がキャッシュしているか（ブラウザ/CDN/Reverse Proxy/アプリ内）
  - 信頼境界（外部連携・第三者・越境ポイント）：キャッシュは「リクエスト→レスポンス」を保存し、以後は **生成元（Origin）に届く前に** 応答する
  - 権限境界（権限の切替/伝播/委任）：別ユーザ向けのレスポンスが返る（ユーザ境界破壊）、別テナント向けのレスポンスが返る（テナント境界破壊）
- 重要なフィールド/差分/状態（「ここが変わると意味が変わる」点）：
  - キーの典型構成要素（scheme、authority、path、query、headers、cookies/authorization、method）
  - Keyingの"壊れ方"（衝突（Collision）：別物が同一キーになる、分裂（Fragmentation）：同一が別キーになる）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が"確定"できるか：
  - どの階層がキャッシュしているか（ブラウザ/CDN/Reverse Proxy/アプリ内）
  - キーが何で構成されているか（Host/Path/Query/Header/Cookie 等）
  - 正規化（canonicalization）がどの層でどう行われているか
- 何が"推定"できるか（推定の根拠/前提）：
  - Keyingが壊れる条件（衝突/分裂）を "観測シグナル→確定証跡" で固める
  - 実害評価を「境界（ユーザ/テナント/機能）」で切り分け、修正要件へ落とす
- 何は"言えない"か（不足情報・観測限界）：
  - すべての階層での完全な断定（観測範囲に依存）
  - すべての正規化差の完全な網羅（観測範囲に依存）
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：衝突（Collision）：別物が同一キーになる → 混線/漏えい/誤配布（危険）
  - パターンB：分裂（Fragmentation）：同一が別キーになる → 効率低下→例外運用→安全策剥離（間接的に危険）
  - パターンC：Vary不足は"衝突"を作る（危険）、Vary過多は"運用崩壊→例外増"を作る（危険）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す"狙い目"：
  - ユーザ境界（認証済み/個人化）：レスポンスがユーザに依存するのに、キャッシュ可能/キー設計が不十分
  - テナント境界（B2B：org/subdomain）：テナント識別がHost/path/queryに埋め込まれている場合、正規化差で衝突すると致命的
  - 機能境界（管理/設定/エクスポート）：/admin、設定画面、出力（CSV/PDF）など
- 優先度の付け方（時間制約がある場合の順序）：
  1) テナント境界（B2B：org/subdomain）→ 別組織データの露出、監査破綻（最優先で重大）
  2) ユーザ境界（認証済み/個人化）→ 情報漏えい、他者の画面表示
  3) 機能境界（管理/設定/エクスポート）→ 誤った内容の配布、管理画面断片の露出
- 代表的な攻め筋（この観測から自然に繋がるもの）：
  - 攻め筋1：Host/Authority 正規化（マルチテナントで致命傷） → CDNは正規化して同一視、Originは別扱い（または逆）
  - 攻め筋2：Query 正規化（最も差分が出やすい） → Cacheは順序を無視して同一キー、Originは順序/重複を意味として扱う
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）：
  - 正規化差は "層間差" を取りに行く → 同じ入力でも、フロントログ上の正規化後URI、Originが受け取ったHost/path/query、キャッシュキー（取れるなら）が一致しない場合、そこが衝突/分裂の起点になる

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：同じURLなのに、2回目が急に速い/遅い
  - 次の検証：
    - Age等のヘッダ・ログで層を確定（CDNかProxyか）
  - 期待する観測（成功/失敗時に何が見えるか）：
    - キャッシュ関与の可能性が示される
- 仮説B：Query順序/エンコード差でヒットが揺れる
  - 次の検証：
    - Origin側が受け取るQueryの形（ログ）を確認し、CacheとOriginの解釈差を特定
  - 期待する観測：
    - Query正規化がキーに影響している（または逆に無視して衝突している）ことが示される
- 仮説C：Host表現差で挙動が揺れる
  - 次の検証：
    - upstream先・SNI/Hostの取り扱い、テナント識別子がキーに入っているかを評価（最優先で重大）
  - 期待する観測：
    - authority/Host正規化差、マルチテナント境界のリスクが示される

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/02_web/05_input/19_cache_poisoning_01_keying_vary_normalization/`（追加候補）
- 取得する証跡（目的ベースで最小限）：
  - レスポンスの Cache-Control / Expires / Pragma、Vary の有無と内容、キャッシュ関与の兆候ヘッダ（Age / Via / cache-status / X-Cache 等）、1回目/2回目の応答時間差（Hit/Miss推定）、可能なら：CDN/Proxyログ（hit/miss、キー、bypass理由）
- 観測の取り方（どの視点で差分を見るか）：
  - メモに必ず残す項目：キャッシュ階層、キーの構成要素、正規化差、衝突/分裂の有無
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/cache_poisoning_keying 2>/dev/null
    cd ~/keda_evidence/cache_poisoning_keying
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可されたスコープ** のみ
      - 観測は **少数試行＋証跡重視**（第三者影響の抑制）
      - 侵害評価は「高価値分岐（認可/テナント/管理/配布物）」に届くかで確定する
  - 相関キー（最低限）を作る（後で必ず効く）
    - Host、User、Time、キャッシュ階層、キーの構成要素、正規化差、衝突/分裂

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は"手段"であり"結論"ではない。必ず「何を観測している例か」を添える。

~~~~
# この領域は「入力を増やすほど第三者影響のリスク」が上がる。
# 目的は Keying（何がキーに入るか）と Normalization（同一視/別扱い）を、観測で固めること。
# - ベースライン固定
# - 差分は1軸ずつ
# - Hit/Missは複数証拠で判定
# - 可能なら cacheログとoriginログで相関
~~~~

- この例で観測していること：
  - Keying（何がキーに入るか）と Normalization（同一視/別扱い）を、観測で固める
- 出力のどこを見るか（注目点）：
  - 1回目/2回目の応答時間差（Hit/Miss推定）、Age等のヘッダ、キャッシュログ（hit/miss）
- この例が使えないケース（前提が崩れるケース）：
  - キャッシュ機能がない場合、観測できない

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：キャッシュ設定、データ保護
  - 該当要件（可能ならID）：キャッシュ可否（Cache-Control等）・キー構成（Host/Path/Query/Header）・正規化（canonicalization）・例外（bypass条件）を **設計として固定**。多段（CDN→Proxy→Origin）でルールを揃える。ユーザ依存レスポンスは原則キャッシュしない/キーにユーザ境界を入れる。
  - このファイルの内容が「満たす/破れる」ポイント：
    - 破れる：キャッシュは「同一キー→同一レスポンス」という"境界装置"。Keying/正規化が壊れると、認証・認可が正しくても **(1) 別ユーザ/別テナントのレスポンス混線**、**(2) 誤った内容の配布（Poisoned配信）**、**(3) 監査・再現性の破綻** が起きる。
    - 満たす：キャッシュ可否（Cache-Control等）・キー構成（Host/Path/Query/Header）・正規化（canonicalization）・例外（bypass条件）を **設計として固定**。多段（CDN→Proxy→Origin）でルールを揃える。ユーザ依存レスポンスは原則キャッシュしない/キーにユーザ境界を入れる。異常系（エラー/リダイレクト/変換）でキャッシュしない。ヒット/ミスと生成元を追跡できるログ相関を必須化。
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：キャッシュは"中継点"を含む入力処理。テストは **(1) キャッシュ可能性**、**(2) キー推定（何がキーに入るか）**、**(3) 正規化差の検出（同一視/別扱いのズレ）**、**(4) 影響（混線/汚染/漏えい）の切り分け** を観測で行う。
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：キャッシュキー＝境界定義の特定と成立条件の詰め方
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Recon/分析、侵害評価
  - 前後フェーズとの繋がり（1行）：Recon/分析でキャッシュ階層とキー仮説を作り、検証は **少数試行＋証跡重視**（第三者影響の抑制）。侵害評価は「高価値分岐（認可/テナント/管理/配布物）」に届くかで確定する。
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：T1190（公開アプリの脆弱性悪用）に接続し得るが、本ファイルの焦点は **成立根拠（観測）**。Defense Evasion：エッジ層の挙動（キャッシュ）でフロント/バックの見え方が変わり、検知・再現が困難化し得る。Collection / Impact：混線（漏えい）・誤配布（影響）に接続（ただし根拠の積み上げが前提）。
  - 攻撃者の目的（この技術が支える意図）：キャッシュキー＝境界定義の特定と成立条件の詰め方
  - 参照：https://attack.mitre.org/tactics/TA0001/（Initial Access）

## 参考（必要最小限）
- Cache Poisoning（Keying）の定義と解説
- Varyと正規化差の説明
- 多段キャッシュでの「層間不一致」が生む失敗パターン

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`05_input_19_cache_poisoning_02_unkeyed（headers_params）.md`
- 関連 topics：`05_input_19_cache_poisoning_03_poisoned_object（stored_response）.md`
- 関連 labs：`04_labs/02_web/05_input/19_cache_poisoning_01_keying_vary_normalization/`（追加候補）

---

## 深掘りリンク（最大8）
- `05_input_19_cache_poisoning_02_unkeyed（headers_params）.md`
- `05_input_19_cache_poisoning_03_poisoned_object（stored_response）.md`
- `05_input_18_http_request_smuggling_03_http2_frontend（h2_to_h1）.md`
- `05_input_18_http_request_smuggling_04_observable_signals（timing_error_cache）.md`
- `05_input_11_path_traversal_01_normalization（dotdot_encoding）.md`
- `05_input_20_crlf_injection_02_downstream（proxy_log_cache）.md`
- `06_config_00_設定・運用境界（CORS ヘッダ Secrets）.md`
- `02_playbooks/02_web_recon_入口→境界→検証方針.md`

---
