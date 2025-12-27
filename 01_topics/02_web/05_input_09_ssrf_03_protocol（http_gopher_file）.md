# 05_input_09_ssrf_03_protocol（http_gopher_file）

## このファイルで扱う概念
- スキーム差分（http/gopher/file等）による到達境界。

## 危険性を一言で
- プロトコル差で内部データや他サービスに到達する。

## 最小限の成立判断（目安）
- スキーム差分で応答/到達が変わることを確認する。

## 観測例（差分のイメージ）
- A: httpのみ、B: file/gopherで別挙動が出る。

## 観測が取れない場合の代替
- 使用可能スキームのallowlist設定を確認する。

## 時間制約下の最小観測点
- 許容スキームの特定。

## 対策の優先順位
1) スキームのallowlist
2) 送信先の制限
3) 解析/実行環境の隔離

## 目的（この技術で到達する状態）
- SSRFを「internal/localhost/metadataへ到達できるか」だけでなく、**どのプロトコル（scheme）で到達できるか**を評価単位にできる。
- http/https・gopher・file の差分を「成立根拠（なぜ成立するか）」として説明できる。
- 実務で次を即断できる
  - Fetcherが許可するschemeは何か（httpのみか、複数か）
  - redirect追従やDNS再解決など、httpの"付随挙動"が境界を破っていないか
  - gopherが許可される場合、SSRFが"内部のテキストプロトコル操作"へ変質し得る理由
  - fileが許可される場合、SSRFが"ネットワーク"ではなく"ローカル資産"へ接続する理由
- 次ファイル（SaaS機能SSRF）へ接続できる（Webhook/preview/PDF等は「どのschemeを許す設計か」が必ず絡む）

## 前提（対象・範囲・想定）
- 対象：SSRF注入点、URL入力、サーバ側のネットワーク到達性・信頼関係、プロトコル（scheme）差による到達性・副作用・検知性の変化
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - 位置づけ：SSRFは「到達性 × プロトコル × 観測」の積、到達性（internal/localhost/metadata）だけを見ていると、重要な差が抜ける、"同じ到達先"でも、プロトコルが変わると以下が変わる：送れるデータの自由度（HTTPヘッダ程度か、任意バイト列に近いか）、受け取れるデータの扱い（レスポンス反映/OOB/タイム差分）、中継点の挙動（redirect・proxy・TLS・認証）、したがって、SSRFの深掘りは「プロトコル境界」を別ファイルで固定する価値がある
- できること/やらないこと（安全に検証する範囲）：
  - できること：SSRFを「internal/localhost/metadataへ到達できるか」だけでなく、**どのプロトコル（scheme）で到達できるか**を評価単位にできる、http/https・gopher・file の差分を「成立根拠（なぜ成立するか）」として説明できる、実務で次を即断できる、Fetcherが許可するschemeは何か（httpのみか、複数か）、redirect追従やDNS再解決など、httpの"付随挙動"が境界を破っていないか、gopherが許可される場合、SSRFが"内部のテキストプロトコル操作"へ変質し得る理由、fileが許可される場合、SSRFが"ネットワーク"ではなく"ローカル資産"へ接続する理由
  - やらないこと：影響実証は最小限（成立根拠の確定まで）。高負荷/外部到達/大量出力は避ける
- 依存する前提知識（必要最小限）：
  - `01_topics/02_web/05_input_09_ssrf_01_reachability（internal_localhost_metadata）.md`
  - `01_topics/02_web/05_input_09_ssrf_02_url_tricks（redirect_dns_idn_ip）.md`
  - `01_topics/02_web/05_input_09_ssrf_04_saas_features（webhook_preview_pdf）.md`
  - `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
  - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
- 観測対象（プロトコル/データ構造/やり取りの単位）：
  - SSRF注入点、URL入力、サーバ側のネットワーク到達性・信頼関係、プロトコル（scheme）差による到達性・副作用・検知性の変化、プロトコル差が生まれる3つの境界
- 境界の観点：
  - 資産境界（管理主体・委託先・対象範囲の線引き）：
    - 文字列→URL構造（Parser）境界：scheme/host/port/path の解釈が実装で揺れる、"scheme禁止"は、文字列判定ではなく「パーサが確定した scheme」で判定しないと破綻する
  - 信頼境界（外部連携・第三者・越境ポイント）：
    - URL構造→Fetcher（取得実装）境界：取得実装が何を使っているかで、受け付けるschemeが変わる、例：HTTP専用クライアント（http/httpsのみ）、例：多機能転送ライブラリ（file/ftp/gopher等も扱える）、ここは"設計の想定"ではなく、実際の挙動（ログ/エラー/ネットワーク観測）で確定する、Fetcher→ネットワーク/OS（実行環境）境界：httpはproxy・TLS・redirect等の"HTTP都合"に引っ張られる、fileはネットワークを介さず、OSのファイルアクセス権へ引っ張られる、gopherはHTTPの枠を外れて、内部の"テキストプロトコル"に触れ得る（成立すると影響の質が変わる）
  - 権限境界（権限の切替/伝播/委任）：
    - プロトコル差が生まれる3つの境界：文字列→URL構造（Parser）境界、URL構造→Fetcher（取得実装）境界、Fetcher→ネットワーク/OS（実行環境）境界
- 重要なフィールド/差分/状態（「ここが変わると意味が変わる」点）：
  - プロトコル別（差分＝成立根拠）：http/https、何が成立しやすいか（成立根拠）：多くの取得機能は「URL＝HTTPリソース」という前提で実装され、http/httpsが最優先でサポートされる、http/httpsは、以下の"付随挙動"が境界を跨ぎやすい：redirect追従（最終宛先が変わる）、DNS再解決（検証時と接続時でIPが変わる）、proxy経由（許可範囲がproxy設定に依存）、ヘッダ付与（認証ヘッダ等が自動で付く設計だと影響が増える）、何が"深刻化ポイント"か（評価の焦点）：internal/localhost/metadata 到達（前ファイル）、取得したレスポンスがどこに流れるか（画面/ログ/キャッシュ/後続処理）、"レスポンスが読めない"場合でも、到達性が成立している根拠（OOB/ログ/タイム差分）、観測ポイント（最小）：schemeはhttp/https固定か（入力の他schemeが拒否されるか）、redirect追従があるか（ホップ再検証されるか）、DNS解決のタイミング（検証時/接続時/ホップごと）と、実接続先IP、gopher、何が成立しやすいか（成立根拠）：gopherが許可される理由は大半が「Fetcherが多機能ライブラリで、scheme制限をしていない」こと、gopherはHTTPの枠を外れ、内部のテキストプロトコル（行ベース/コマンドベース）に"近い形"で接続でき得るため、SSRFが「内部HTTPの取得」から「内部サービスへ"指示"を渡す（副作用を起こす）」に変質し得る、重要：この変質が起きるかは、(A) gopher許可、(B) internal/localhost到達、(C) 内部に"テキストで操作できる面"がある、の積で決まる、file、何が成立しやすいか（成立根拠）：fileが許可される理由は「取得機能が"URLなら何でも取れる"設計」か「URL解釈がOSファイルへフォールバックする」設計のいずれか、fileはネットワークの到達性ではなく、**実行環境のファイルアクセス権**で成立可否が決まる、egress制御でSSRFを止めたつもりでも、fileが残っていると"別経路"が開く

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が"確定"できるか：
  - 到達性 × プロトコル：評価をブレさせない「状態マトリクス」、H1：http/https のみ + internal/localhost/metadata 到達あり、典型SSRF。redirect/DNS/ヘッダ付与の設計不備が深刻化要因、G2：gopher あり + internal/localhost 到達あり、SSRFが"内部プロトコル操作"へ変質し得る（副作用証拠が鍵）、F1：file あり、SSRFというより「ローカル資産境界（ファイル）」へ接続。egress制御だけでは止まらない、重要：このマトリクスで"何が言える/言えない"を固定してから、次の検証へ進む
- 何が"推定"できるか（推定の根拠/前提）：
  - 影響を"状態"として書く（報告に耐える形）、gopher：状態G1：gopher scheme が受理され、サーバ発の接続が発生する、意味：HTTP以外の輸送経路が開いている（scheme境界が崩れている）、状態G2：internal/localhost へのgopher接続が成立する、意味：内部サービス探索（T1046）に直結し得る、状態G3：内部サービスが"副作用を起こす命令入力"を受け付ける（レスポンス不要でも成立）、意味：Blindでも重大化し得る（OOB/ログ/メトリクスで副作用を証拠化）、file：状態F1：file scheme が受理され、ローカルパス解決が発生する、意味：ネットワーク境界ではなく、OS資産境界へ入力が接続されている、状態F2：アプリが読み取り結果を返す/ログに残す/後続へ渡す、意味：機密性（設定/鍵/環境情報）に直結し得る（反映経路が鍵）、状態F3：パス正規化/ベースディレクトリ制限が無い、または"別表現"で回避できる、意味：設計上の許可範囲が守られていない（資産境界が崩れている）
- 何は"言えない"か（不足情報・観測限界）：
  - 到達性（internal/localhost/metadata）だけを見ていると、重要な差が抜ける、"同じ到達先"でも、プロトコルが変わると以下が変わる：送れるデータの自由度（HTTPヘッダ程度か、任意バイト列に近いか）、受け取れるデータの扱い（レスポンス反映/OOB/タイム差分）、中継点の挙動（redirect・proxy・TLS・認証）
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：http/https のみ + internal/localhost/metadata 到達あり → 典型SSRF。redirect/DNS/ヘッダ付与の設計不備が深刻化要因
  - パターンB：gopher あり + internal/localhost 到達あり → SSRFが"内部プロトコル操作"へ変質し得る（副作用証拠が鍵）
  - パターンC：file あり → SSRFというより「ローカル資産境界（ファイル）」へ接続。egress制御だけでは止まらない

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す"狙い目"：
  - SSRFを「internal/localhost/metadataへ到達できるか」だけでなく、**どのプロトコル（scheme）で到達できるか**を評価単位にできる、http/https・gopher・file の差分を「成立根拠（なぜ成立するか）」として説明できる
- 優先度の付け方（時間制約がある場合の順序）：
  - まず scheme を確定する（httpだけか、gopher/fileが開いているか）、gopher/fileが開いている場合、内部到達性の価値が跳ね上がる（到達の質が変わる）、次に internal/localhost/metadata の到達性を確定する（前ファイルの枠組み）、レスポンス反映が無い場合でも諦めない、gopher：副作用ログ/メトリクス/エラー差分で成立根拠を固める、http：OOB（DNS/HTTP）や差分（timeout）で到達性を固める、file：アクセス試行の痕跡と反映経路の有無を固める
- 代表的な攻め筋（この観測から自然に繋がるもの）：
  - 攻め筋1：SSRFを「internal/localhost/metadataへ到達できるか」だけでなく、**どのプロトコル（scheme）で到達できるか**を評価単位にできる、http/https・gopher・file の差分を「成立根拠（なぜ成立するか）」として説明できる、実務で次を即断できる、Fetcherが許可するschemeは何か（httpのみか、複数か）、redirect追従やDNS再解決など、httpの"付随挙動"が境界を破っていないか、gopherが許可される場合、SSRFが"内部のテキストプロトコル操作"へ変質し得る理由、fileが許可される場合、SSRFが"ネットワーク"ではなく"ローカル資産"へ接続する理由
  - 攻め筋2：結果として、攻撃者の意思決定は「取得」ではなく「どの境界を跨げるか（ネットワーク/OS/内部手続き）」に寄る、次ファイル（SaaS機能SSRF）へ接続できる（Webhook/preview/PDF等は「どのschemeを許す設計か」が必ず絡む）
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）：
  - 判断モデル：やることの優先順位が変わる、まず scheme を確定する（httpだけか、gopher/fileが開いているか）、次に internal/localhost/metadata の到達性を確定する（前ファイルの枠組み）、レスポンス反映が無い場合でも諦めない

## 次に試すこと（仮説A/Bの分岐と検証）
> ここが最重要。条件が違うと次の手が変わる形で書く。

- 仮説A：（http/https しか受け付けない）
  - 次の検証：redirect追従の有無（ホップ再検証があるか）、DNS解決とIP判定（v4/v6、link-local、metadata）の実装確認、レスポンス反映がない場合の証拠化（OOB/ログ/タイム差分）
  - 期待する観測（成功/失敗時に何が見えるか）：
    - 成功："プロトコルで深さを出せない"なら、"到達性と観測"で深さを出す（薄い結論にしない）
    - 失敗：H1：http/https のみ + internal/localhost/metadata 到達あり、典型SSRF。redirect/DNS/ヘッダ付与の設計不備が深刻化要因
- 仮説B：（gopher または file が受理される）
  - 次の検証：gopher：内部到達性（internal/localhost）と副作用観測点（内部ログ/メトリクス）を最優先で設計、file：実行環境のファイル権限と反映経路（レスポンス/ログ/後続処理）を最優先で特定
  - 期待する観測：
    - 成功：重要：この分岐は「攻撃のやり方」ではなく「観測設計」と「報告の強さ」を決める分岐、G2：gopher あり + internal/localhost 到達あり、SSRFが"内部プロトコル操作"へ変質し得る（副作用証拠が鍵）、F1：file あり、SSRFというより「ローカル資産境界（ファイル）」へ接続。egress制御だけでは止まらない
    - 失敗：状態G1：gopher scheme が受理され、サーバ発の接続が発生する、状態F1：file scheme が受理され、ローカルパス解決が発生する

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/` ）：
  - 参照ファイル：`04_labs/02_web/05_input/09_ssrf_protocol_http_gopher_file/`
- 取得する証跡（目的ベースで最小限）：
  - アプリログ：parsed scheme/host/port、request_id/job_id、ネットワークログ：DNS/プロキシ/FW（可能な範囲）、内部側ログ（副作用根拠）：内部サービスのアクセスログ、メトリクス、観測ポイント（最小）：schemeはhttp/https固定か（入力の他schemeが拒否されるか）、redirect追従があるか（ホップ再検証されるか）、DNS解決のタイミング（検証時/接続時/ホップごと）と、実接続先IP、アプリログ：scheme/host/port がパーサでどう確定しているか、ネットワーク観測：HTTPプロキシログに出るか（出ないなら別経路で出ている可能性）、成立根拠：接続が発生した証拠（FW/SG/プロキシ/アプリログ）、副作用根拠：内部側ログ・メトリクス・エラー差分（レスポンス反映に依存しない）、scheme受理の有無（fileが拒否されるか）、実行環境（コンテナ/サーバ）と権限（読める範囲）の把握、反映経路（レスポンス/ログ/キャッシュ/エクスポート等）、"読めない"場合の根拠：エラー差分・アクセスログ（ファイルアクセス試行の痕跡）
- 観測の取り方（どの視点で差分を見るか）：
  - 設計ゴール：同一のURL入力点に対して、Fetcher実装を差し替え（HTTP専用 / 多機能 / ローカル対応）し、許可scheme、internal/localhost/metadata 到達性、観測（レスポンス反映 / OOB / ログ / 差分）、を比較できるようにする

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は"手段"であり"結論"ではない。必ず「何を観測している例か」を添える。

~~~~
# 目的：scheme差（http/gopher/file）を"実装と観測"で確定する。

# - 入力 → パーサが確定した scheme/host/port をログ化

# - Fetcher が実際に接続した宛先（IP:port）を相関

# - レスポンス反映が無い場合は、副作用ログ/メトリクス/OOBで根拠化

# ※具体の攻撃文字列集ではなく、成立根拠の取り方を固定する。

~~~~

- この例で観測していること：プロトコル差が生まれる3つの境界、文字列→URL構造（Parser）境界、URL構造→Fetcher（取得実装）境界、Fetcher→ネットワーク/OS（実行環境）境界、プロトコル別（差分＝成立根拠）：http/https、gopher、file
- 出力のどこを見るか（注目点）：アプリログ：parsed scheme/host/port、request_id/job_id、ネットワークログ：DNS/プロキシ/FW（可能な範囲）、内部側ログ（副作用根拠）：内部サービスのアクセスログ、メトリクス、観測ポイント（最小）：schemeはhttp/https固定か（入力の他schemeが拒否されるか）、redirect追従があるか（ホップ再検証されるか）、DNS解決のタイミング（検証時/接続時/ホップごと）と、実接続先IP
- この例が使えないケース（前提が崩れるケース）：SSRF注入点が存在しない場合、またはURL入力が発生しない場合

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：V5 Validation, Sanitization and Encoding
  - 該当要件（可能ならID）：V5.1.1、V5.1.2、V5.2.1
  - このファイルの内容が「満たす/破れる」ポイント：
    - 満たす/破れる点：SSRFは「入力（URL等）→サーバ側の外部/内部アクセス」という Input→Execution 境界。プロトコル（scheme）差で到達性・副作用・検知性が激変するため、(1) 許可するschemeの明示、(2) 正規化後URLの検証、(3) 解決後IPの拒否（localhost/internal/link-local/metadata）、(4) redirect含む最終宛先の再検証、を組み合わせて境界を閉じる
- WSTG：
  - 該当カテゴリ/テスト観点：WSTG-INPV-08 Testing for SSRF
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：
    - SSRFテストでは、注入点の特定に加え「サーバが到達できる範囲（internal/localhost/metadata）」「どのプロトコルで到達できるか」「レスポンスが読めない場合の証拠化」を評価する。http以外（gopher/file等）が許可されると、SSRFの質が"単なる取得"から"内部手続きの代理実行"へ変質し得る点を重視する
- PTES：
  - 該当フェーズ：Vulnerability Analysis、Exploitation、Reporting
  - 前後フェーズとの繋がり（1行）：Vulnerability Analysis：URL入力点ごとに、Fetcher（取得実装）が受け付けるschemeと挙動（redirect・DNS・proxy・timeout）を棚卸しし、到達性マップを作る、Exploitation：ここでの"深さ"は攻撃文字列ではなく、成立根拠（観測点）と影響の境界（何ができる/できない）を確定すること、Reporting：修正は「SSRF対策」ではなく、(A) 取得機能の必要性削減、(B) scheme allowlist、(C) egress制御、(D) 監視、の因果で提示する
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Initial Access、Discovery
  - 攻撃者の目的（この技術が支える意図）：入口：T1190（公開アプリの脆弱性悪用）、到達性の利用：T1046（内部サービス探索）へ接続し得る、クラウド：T1552.005（インスタンスメタデータAPI）に接続し得る、本ファイルは「到達性を借りる」ための"輸送層（プロトコル）差"を扱う

## 参考（必要最小限）
- OWASP Server-Side Request Forgery Prevention Cheat Sheet
- PortSwigger Web Security Academy: SSRF
- RFC 1738 / RFC 4266（URL schemeとしてのgopher/fileの位置づけ）

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/05_input_09_ssrf_01_reachability（internal_localhost_metadata）.md`
- `01_topics/02_web/05_input_09_ssrf_02_url_tricks（redirect_dns_idn_ip）.md`
- `01_topics/02_web/05_input_09_ssrf_04_saas_features（webhook_preview_pdf）.md`

---

## 深掘りリンク（最大8）
- `01_topics/02_web/05_input_00_入力→実行境界（テンプレ デシリアライズ等）.md`
- `01_topics/02_web/05_input_09_ssrf_01_reachability（internal_localhost_metadata）.md`
- `01_topics/02_web/05_input_09_ssrf_02_url_tricks（redirect_dns_idn_ip）.md`
- `01_topics/02_web/05_input_09_ssrf_04_saas_features（webhook_preview_pdf）.md`
- `01_topics/02_web/05_input_09_ssrf_05_dns_rebinding（time_based_reachability）.md`
- `01_topics/02_web/05_input_09_ssrf_06_parser_differential（url_parse_smuggling）.md`
- `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
- `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`

## プロトコル別（差分＝成立根拠）：http/https
### 何が成立しやすいか（成立根拠）
- 多くの取得機能は「URL＝HTTPリソース」という前提で実装され、http/httpsが最優先でサポートされる。
- http/httpsは、以下の“付随挙動”が境界を跨ぎやすい：
  - redirect追従（最終宛先が変わる）
  - DNS再解決（検証時と接続時でIPが変わる）
  - proxy経由（許可範囲がproxy設定に依存）
  - ヘッダ付与（認証ヘッダ等が自動で付く設計だと影響が増える）

### 何が“深刻化ポイント”か（評価の焦点）
- internal/localhost/metadata 到達（前ファイル）
- 取得したレスポンスがどこに流れるか（画面/ログ/キャッシュ/後続処理）
- “レスポンスが読めない”場合でも、到達性が成立している根拠（OOB/ログ/タイム差分）

### 観測ポイント（最小）
- schemeはhttp/https固定か（入力の他schemeが拒否されるか）
- redirect追従があるか（ホップごと再検証されるか）
- DNS解決のタイミング（検証時/接続時/ホップごと）と、実接続先IP

---

## プロトコル別（差分＝成立根拠）：gopher
> ここは「具体的にどう叩くか」ではなく、“なぜ危険度が跳ね上がるか”を固定する。

### 何が成立しやすいか（成立根拠）
- gopherが許可される理由は大半が「Fetcherが多機能ライブラリで、scheme制限をしていない」こと。
- gopherはHTTPの枠を外れ、内部のテキストプロトコル（行ベース/コマンドベース）に“近い形”で接続でき得るため、
  - SSRFが「内部HTTPの取得」から
  - 「内部サービスへ“指示”を渡す（副作用を起こす）」に変質し得る。
- 重要：この変質が起きるかは、(A) gopher許可、(B) internal/localhost到達、(C) 内部に“テキストで操作できる面”がある、の積で決まる。

### 影響を“状態”として書く（報告に耐える形）
- 状態G1：gopher scheme が受理され、サーバ発の接続が発生する
  - 意味：HTTP以外の輸送経路が開いている（scheme境界が崩れている）
- 状態G2：internal/localhost へのgopher接続が成立する
  - 意味：内部サービス探索（T1046）に直結し得る
- 状態G3：内部サービスが“副作用を起こす命令入力”を受け付ける（レスポンス不要でも成立）
  - 意味：Blindでも重大化し得る（OOB/ログ/メトリクスで副作用を証拠化）

### 観測ポイント（最小）
- アプリログ：scheme/host/port がパーサでどう確定しているか
- ネットワーク観測：HTTPプロキシログに出るか（出ないなら別経路で出ている可能性）
- 成立根拠：接続が発生した証拠（FW/SG/プロキシ/アプリログ）
- 副作用根拠：内部側ログ・メトリクス・エラー差分（レスポンス反映に依存しない）

---

## プロトコル別（差分＝成立根拠）：file
### 何が成立しやすいか（成立根拠）
- fileが許可される理由は「取得機能が“URLなら何でも取れる”設計」か「URL解釈がOSファイルへフォールバックする」設計のいずれか。
- fileはネットワークの到達性ではなく、**実行環境のファイルアクセス権**で成立可否が決まる。
  - egress制御でSSRFを止めたつもりでも、fileが残っていると“別経路”が開く。

### 影響を“状態”として書く（報告に耐える形）
- 状態F1：file scheme が受理され、ローカルパス解決が発生する
  - 意味：ネットワーク境界ではなく、OS資産境界へ入力が接続されている
- 状態F2：アプリが読み取り結果を返す/ログに残す/後続へ渡す
  - 意味：機密性（設定/鍵/環境情報）に直結し得る（反映経路が鍵）
- 状態F3：パス正規化/ベースディレクトリ制限が無い、または“別表現”で回避できる
  - 意味：設計上の許可範囲が守られていない（資産境界が崩れている）

### 観測ポイント（最小）
- scheme受理の有無（fileが拒否されるか）
- 実行環境（コンテナ/サーバ）と権限（読める範囲）の把握
- 反映経路（レスポンス/ログ/キャッシュ/エクスポート等）
- “読めない”場合の根拠：エラー差分・アクセスログ（ファイルアクセス試行の痕跡）

---

## 到達性 × プロトコル：評価をブレさせない「状態マトリクス」
- H1：http/https のみ + internal/localhost/metadata 到達あり
  - 典型SSRF。redirect/DNS/ヘッダ付与の設計不備が深刻化要因。
- G2：gopher あり + internal/localhost 到達あり
  - SSRFが“内部プロトコル操作”へ変質し得る（副作用証拠が鍵）。
- F1：file あり
  - SSRFというより「ローカル資産境界（ファイル）」へ接続。egress制御だけでは止まらない。
- 重要：このマトリクスで“何が言える/言えない”を固定してから、次の検証へ進む。

---

## 攻撃者視点での利用（判断モデル：やることの優先順位が変わる）
- まず scheme を確定する（httpだけか、gopher/fileが開いているか）
  - gopher/fileが開いている場合、内部到達性の価値が跳ね上がる（到達の質が変わる）
- 次に internal/localhost/metadata の到達性を確定する（前ファイルの枠組み）
- レスポンス反映が無い場合でも諦めない
  - gopher：副作用ログ/メトリクス/エラー差分で成立根拠を固める
  - http：OOB（DNS/HTTP）や差分（timeout）で到達性を固める
  - file：アクセス試行の痕跡と反映経路の有無を固める
- 結果として、攻撃者の意思決定は「取得」ではなく「どの境界を跨げるか（ネットワーク/OS/内部手続き）」に寄る

---

## 次に試すこと（仮説A/B：条件で手が変わる）
### 仮説A：http/https しか受け付けない
- 次の一手
  - redirect追従の有無（ホップ再検証があるか）
  - DNS解決とIP判定（v4/v6、link-local、metadata）の実装確認
  - レスポンス反映がない場合の証拠化（OOB/ログ/タイム差分）
- “プロトコルで深さを出せない”なら、“到達性と観測”で深さを出す（薄い結論にしない）

### 仮説B：gopher または file が受理される
- 次の一手
  - gopher：内部到達性（internal/localhost）と副作用観測点（内部ログ/メトリクス）を最優先で設計
  - file：実行環境のファイル権限と反映経路（レスポンス/ログ/後続処理）を最優先で特定
- 重要：この分岐は「攻撃のやり方」ではなく「観測設計」と「報告の強さ」を決める分岐

---

## 手を動かす検証（Labs設計：手順書ではなく設計）
- 追加候補Lab
  - `04_labs/02_web/05_input/09_ssrf_protocol_http_gopher_file/`
- 設計ゴール
  - 同一のURL入力点に対して、Fetcher実装を差し替え（HTTP専用 / 多機能 / ローカル対応）し、
    - 許可scheme
    - internal/localhost/metadata 到達性
    - 観測（レスポンス反映 / OOB / ログ / 差分）
    を比較できるようにする。
- 観測点（必須）
  - アプリログ：parsed scheme/host/port、request_id/job_id
  - ネットワークログ：DNS/プロキシ/FW（可能な範囲）
  - 内部側ログ（副作用根拠）：内部サービスのアクセスログ、メトリクス

---

## 例（最小限：検証の“型”だけ）
~~~~
# 目的：scheme差（http/gopher/file）を“実装と観測”で確定する。

# - 入力 → パーサが確定した scheme/host/port をログ化

# - Fetcher が実際に接続した宛先（IP:port）を相関

# - レスポンス反映が無い場合は、副作用ログ/メトリクス/OOBで根拠化

# ※具体の攻撃文字列集ではなく、成立根拠の取り方を固定する。

~~~~

---

## 参考（一次情報）
- OWASP Server-Side Request Forgery Prevention Cheat Sheet
  - https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- PortSwigger Web Security Academy: SSRF
  - https://portswigger.net/web-security/ssrf
- RFC 1738 / RFC 4266（URL schemeとしてのgopher/fileの位置づけ）
  - https://www.rfc-editor.org/rfc/rfc1738.html
  - https://www.rfc-editor.org/rfc/rfc4266

---

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/05_input_09_ssrf_01_reachability（internal_localhost_metadata）.md`
- `01_topics/02_web/05_input_09_ssrf_02_url_tricks（redirect_dns_idn_ip）.md`
- `01_topics/02_web/05_input_09_ssrf_04_saas_features（webhook_preview_pdf）.md`

---

## 次（作成候補順）
- `01_topics/02_web/05_input_09_ssrf_04_saas_features（webhook_preview_pdf）.md`
