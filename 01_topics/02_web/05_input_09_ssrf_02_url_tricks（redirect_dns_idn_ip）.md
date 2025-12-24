# 05_input_09_ssrf_02_url_tricks（redirect_dns_idn_ip）

## 目的（この技術で到達する状態）
- SSRFの防御・診断を「URLを正規表現で弾く」から卒業し、**Validator と Fetcher の差分**という実務の本体に落とす。
- URLトリックを"ペイロード暗記"ではなく、次の4分類で説明・検証・修正提案できる。
  1) redirect（追従と最終宛先）
  2) DNS（解決タイミング／再解決／ピン留め）
  3) IDN（Unicode/ Punycode / 正規化）
  4) IP表現（v4/v6混在、数値表記、IPv4-mapped等）
- 結果として、次の質問に即答できる
  - その入力点は「ホストallowlist」なのか「IP allowlist」なのか（どの層で閉じているか）
  - redirect を追うか、追うなら何を再検証しているか
  - DNSをいつ引いて、いつ固定し、いつ再解決しているか
  - "同じURL"をValidatorとFetcherが同じ意味で解釈しているか

## 前提（対象・範囲・想定）
- 対象：SSRF注入点、URL入力、サーバ側のネットワーク到達性・信頼関係、URL検証（Validator）とHTTPクライアント（Fetcher）の差分
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - まず固定する前提：URLは"文法"より"実装差分"で危険になる、URI構文（RFC 3986）が示す分解：URIは scheme / authority / path / query / fragment に分解され、authority は userinfo / host / port を取り得る、したがって `@`（userinfo）や `:`（port）、`[]`（IPv6）などは"仕様として正当"であり、文字列フィルタは誤判定しやすい、実務で起きる問題：Validator と Fetcher が別実装、多くの事故は「検証はAライブラリ、接続はBライブラリ」で発生する、例：Node.js では WHATWG URL と legacy url.parse() の差分が明示されている（同じ文字列でもプロパティの扱いが異なる）、PortSwiggerは URL validation bypass の根として「曖昧URLによる解析不一致」を指摘している
- できること/やらないこと（安全に検証する範囲）：
  - できること：URLトリックを"ペイロード暗記"ではなく、次の4分類で説明・検証・修正提案できる、redirect（追従と最終宛先）、DNS（解決タイミング／再解決／ピン留め）、IDN（Unicode/ Punycode / 正規化）、IP表現（v4/v6混在、数値表記、IPv4-mapped等）、結果として、次の質問に即答できる、その入力点は「ホストallowlist」なのか「IP allowlist」なのか（どの層で閉じているか）、redirect を追うか、追うなら何を再検証しているか、DNSをいつ引いて、いつ固定し、いつ再解決しているか、"同じURL"をValidatorとFetcherが同じ意味で解釈しているか
  - やらないこと：影響実証は最小限（成立根拠の確定まで）。高負荷/外部到達/大量出力は避ける
- 依存する前提知識（必要最小限）：
  - `01_topics/02_web/05_input_09_ssrf_01_reachability（internal_localhost_metadata）.md`
  - `01_topics/02_web/05_input_09_ssrf_03_protocol（http_gopher_file）.md`
  - `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
  - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
- 観測対象（プロトコル/データ構造/やり取りの単位）：
  - SSRF注入点、URL入力、サーバ側のネットワーク到達性・信頼関係、URL検証（Validator）とHTTPクライアント（Fetcher）の差分、URLトリックは、攻撃テクの羅列ではなく、次のズレ（differential）でモデル化する
- 境界の観点：
  - 資産境界（管理主体・委託先・対象範囲の線引き）：
    - ズレA：文字列判定 vs 正規化後の構造判定：文字列の contains / startsWith / regex で host を見ている、実際はURLパーサが「host」を別の値として解釈する、防御の原則：**文字列ではなく、パーサが返した構造**を基準に判定する（OWASPは"ライブラリの出力値をIP比較に使う"方針を明示）、入力→正規化（Validator側）の観測：取得したいログ（最低限）、parsed host / port / scheme（正規化後）、正規化前の raw input（比較用）、IDN変換後（A-label/Punycode）の値、期待する"状態"の例、状態V1：Validatorが host を A と解釈している、状態V2：Validatorが host を B（別値）と解釈している（差分が根拠）
  - 信頼境界（外部連携・第三者・越境ポイント）：
    - ズレB：host allowlist vs 接続先IP allowlist："許可ホスト名"を見てOKにしても、DNSの解決先が内部/localhost/link-localになり得る、防御の原則：許可リストは「最終的に接続されるIP（v4/v6）」で比較し、v6も含める、名前解決（DNS）と接続先IPの観測：重要：**接続先IPはDNSの瞬間値**であり、比較対象は host ではなく IP（v4/v6）である、取得したいログ、解決したA/AAAAレコード（タイムスタンプ付）、実際に接続したソケット宛先（IP:port）、"到達性クラス"の結論（前ファイルと接続）、localhost / internal / metadata のどれへ到達し得たか（状態として言い切る）、ズレC：初回検証の宛先 vs redirect後の最終宛先："最初のURL"は許可、redirectで最終宛先が変わる、PortSwiggerは open redirect を使って SSRF制限を回避する学習ケースを提示している（「最初はローカルしか許可」でも、redirectで内部へ寄せられる）、防御の原則：redirectを追従するなら **各ホップで再検証**、追従しないなら仕様として無効化、redirect の観測（Fetcher側）：取得したいログ、redirect追従の有無、ホップごとの Location と最終URL、各ホップで再検証が走っているか（ログで確定）、PortSwiggerが示す通り、redirectは SSRF制限の現実的なバイパス要因であるため、追従設計は監査ポイントになる
  - 権限境界（権限の切替/伝播/委任）：
    - ズレD：IDN/Unicode 表示名 vs 実際のDNSラベル（Punycode）：IDNはUnicode（U-label）とASCII（A-label）を相互変換しうる、Unicode TR46（互換処理）も存在し、実装が"どの処理系（TR46/IDNA2008等）を採用するか"で差分が生じる、結果：表示上は"許可ドメインに見える"／判定側は"別ラベルとして扱う"、またはその逆、が起き得る
- 重要なフィールド/差分/状態（「ここが変わると意味が変わる」点）：
  - 状態S-REDIRECT：redirectが"検証境界を跨いでいる"、意味：最初のURL検証が最終宛先を保証していない、影響：allowlistの"意図"が破綻し、内部/localhost/metadataへ接続し得る、状態S-DNS：DNSの解決タイミング差で"検証と接続が一致しない"、意味：検証時にOKだったが、接続時に別IPへ向く（または再解決する）、影響：host allowlistが実質無力化するため、IP allowlist・ピン留め・再検証が必要になる、状態S-IDN：表示・正規化・比較の不一致で"同一視/別物扱い"が揺れる、意味：A-label/U-label/TR46処理の差で、allowlist比較が破綻し得る、影響：許可ドメインになりすまし／誤ブロック／ログと実体の乖離（監視も壊れる）、状態S-IPFORMAT：IP表現の同値性が判定と接続でズレる、意味：同じ到達先でも、表現の揺れ（v6、IPv4-mapped等）で判定がすり抜ける、影響：内部/localhost/link-localの除外が漏れる可能性（特にv6未考慮）、OWASPは allowlist を v4/v6含めたIPで構築し、ライブラリの出力値を比較に使う、としている（この状態の対策原則になる）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が"確定"できるか：
  - 状態S-REDIRECT：redirectが"検証境界を跨いでいる"、意味：最初のURL検証が最終宛先を保証していない、影響：allowlistの"意図"が破綻し、内部/localhost/metadataへ接続し得る、状態S-DNS：DNSの解決タイミング差で"検証と接続が一致しない"、意味：検証時にOKだったが、接続時に別IPへ向く（または再解決する）、影響：host allowlistが実質無力化するため、IP allowlist・ピン留め・再検証が必要になる
- 何が"推定"できるか（推定の根拠/前提）：
  - 状態S-IDN：表示・正規化・比較の不一致で"同一視/別物扱い"が揺れる、意味：A-label/U-label/TR46処理の差で、allowlist比較が破綻し得る、影響：許可ドメインになりすまし／誤ブロック／ログと実体の乖離（監視も壊れる）、状態S-IPFORMAT：IP表現の同値性が判定と接続でズレる、意味：同じ到達先でも、表現の揺れ（v6、IPv4-mapped等）で判定がすり抜ける、影響：内部/localhost/link-localの除外が漏れる可能性（特にv6未考慮）、OWASPは allowlist を v4/v6含めたIPで構築し、ライブラリの出力値を比較に使う、としている（この状態の対策原則になる）
- 何は"言えない"か（不足情報・観測限界）：
  - 本ファイルでは「トリックを挙げる」より、**どこを見ればズレが確定するか**を固定する、URLトリックは、攻撃テクの羅列ではなく、次のズレ（differential）でモデル化する
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：redirectが"検証境界を跨いでいる" → 意味：最初のURL検証が最終宛先を保証していない、影響：allowlistの"意図"が破綻し、内部/localhost/metadataへ接続し得る
  - パターンB：DNSの解決タイミング差で"検証と接続が一致しない" → 意味：検証時にOKだったが、接続時に別IPへ向く（または再解決する）、影響：host allowlistが実質無力化するため、IP allowlist・ピン留め・再検証が必要になる
  - パターンC：表示・正規化・比較の不一致で"同一視/別物扱い"が揺れる → 意味：A-label/U-label/TR46処理の差で、allowlist比較が破綻し得る、影響：許可ドメインになりすまし／誤ブロック／ログと実体の乖離（監視も壊れる）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す"狙い目"：
  - SSRFの防御・診断を「URLを正規表現で弾く」から卒業し、**Validator と Fetcher の差分**という実務の本体に落とす、URLトリックを"ペイロード暗記"ではなく、次の4分類で説明・検証・修正提案できる、redirect（追従と最終宛先）、DNS（解決タイミング／再解決／ピン留め）、IDN（Unicode/ Punycode / 正規化）、IP表現（v4/v6混在、数値表記、IPv4-mapped等）
- 優先度の付け方（時間制約がある場合の順序）：
  - 分岐A：redirect追従があるか、ある：最終宛先で再検証していないなら、制限回避の余地が増える（内部到達性へ寄せられる）、ない：DNS/IDN/IP表現など、"初回URL解釈"の差分に重心が移る、分岐B：host allowlist か IP allowlist か、hostのみ：DNS差分（検証時と接続時のズレ）で内部到達に寄る余地が残りやすい、IPまで：次は「redirect後の再検証」「v6含む同値判定」「DNS再解決制御」の監査に移る、分岐C：IDN処理が統一されているか、表示・比較・ログが別体系：許可/拒否の境界が揺れ、監視も誤作動しやすい（運用品質にも直結）、IDNA/TR46に統一：少なくとも"表記揺れ"起因の差分は縮む
- 代表的な攻め筋（この観測から自然に繋がるもの）：
  - 攻め筋1：URLトリックを"ペイロード暗記"ではなく、次の4分類で説明・検証・修正提案できる、redirect（追従と最終宛先）、DNS（解決タイミング／再解決／ピン留め）、IDN（Unicode/ Punycode / 正規化）、IP表現（v4/v6混在、数値表記、IPv4-mapped等）、結果として、次の質問に即答できる、その入力点は「ホストallowlist」なのか「IP allowlist」なのか（どの層で閉じているか）、redirect を追うか、追うなら何を再検証しているか、DNSをいつ引いて、いつ固定し、いつ再解決しているか、"同じURL"をValidatorとFetcherが同じ意味で解釈しているか
  - 攻め筋2：ここは具体ペイロード集ではなく、攻撃者が何を見て次の手を選ぶかの判断モデル、分岐A：redirect追従があるか、分岐B：host allowlist か IP allowlist か、分岐C：IDN処理が統一されているか
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）：
  - 実務で起きる問題：Validator と Fetcher が別実装、多くの事故は「検証はAライブラリ、接続はBライブラリ」で発生する、例：Node.js では WHATWG URL と legacy url.parse() の差分が明示されている（同じ文字列でもプロパティの扱いが異なる）、PortSwiggerは URL validation bypass の根として「曖昧URLによる解析不一致」を指摘している

## 次に試すこと（仮説A/Bの分岐と検証）
> ここが最重要。条件が違うと次の手が変わる形で書く。

- 仮説A：（SSRFは成立しているが、制限（allowlist等）がある）
  - 次の検証：redirect追従の有無（ホップログ）、DNS解決のタイミング（検証時/接続時/redirect後で再解決するか）、IP比較が v4/v6 を含んでいるか（v6漏れは最優先で疑う）
  - 期待する観測（成功/失敗時に何が見えるか）：
    - 成功："最終宛先"で再検証が走るか（走らないなら設計不備として指摘可能）、ValidatorとFetcherの実装差（別ライブラリ）を切り分ける（Lab化）
    - 失敗：状態S-REDIRECT：redirectが"検証境界を跨いでいる"、状態S-DNS：DNSの解決タイミング差で"検証と接続が一致しない"、状態S-IPFORMAT：IP表現の同値性が判定と接続でズレる
- 仮説B：（SSRFは成立しない（接続自体が抑止されている）ように見える）
  - 次の検証：URLは解釈されているか（parsed host等）、DNSは引いているか（問い合わせログ）、localhostは別枠で成立し得るため、egress遮断だけで否定しない
  - 期待する観測：
    - 成功：実行環境（フロント/ワーカー）差を疑い、同一入力でも処理系が変わる経路（非同期/変換）を探す
    - 失敗：状態S-IDN：表示・正規化・比較の不一致で"同一視/別物扱い"が揺れる、状態S-IPFORMAT：IP表現の同値性が判定と接続でズレる

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：`04_labs/02_web/05_input/09_ssrf_url_tricks_redirect_dns_idn_ip/`
- 取得する証跡（目的ベースで最小限）：
  - parsed host（A/Bそれぞれ）、DNS問い合わせログ（A/AAAA）、実際のソケット接続先（IP:port）、redirectホップ列（Locationの連鎖）
  - 取得したいログ（最低限）：parsed host / port / scheme（正規化後）、正規化前の raw input（比較用）、IDN変換後（A-label/Punycode）の値、解決したA/AAAAレコード（タイムスタンプ付）、実際に接続したソケット宛先（IP:port）、redirect追従の有無、ホップごとの Location と最終URL、各ホップで再検証が走っているか（ログで確定）
- 観測の取り方（どの視点で差分を見るか）：
  - 目的：ValidatorとFetcherの差分が、どの条件で"接続先のズレ"になるかを再現し、観測点（ログ）を固定する
  - 設計差分：URLパーサ差：A（厳格）/B（別仕様 or legacy）、DNS差：検証時に解決→接続時に再解決、などタイミング差を作る、redirect差：追従なし/あり（ホップ再検証なし/あり）、IDN差：U-label入力→A-label比較、TR46処理あり/なし、IP差：v4/v6の両方を扱うallowlistの有無
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/ssrf_url_tricks 2>/dev/null
    cd ~/keda_evidence/ssrf_url_tricks
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可されたスコープ** のみ
      - 観測は **代表点の抽出** のみ
      - 高負荷/外部到達/大量出力は避ける
  - 相関キー（最低限）を作る（後で必ず効く）
    - request_id, raw_url, normalized_url, parsed_host, resolved_ips, destination_ip, redirect_chain

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は"手段"であり"結論"ではない。必ず「何を観測している例か」を添える。

~~~~
# このファイルの要点は「ペイロード集」ではなく、
# (1) Validator と Fetcher の差分
# (2) 正規化後の判定
# (3) DNS解決→IP比較（v4/v6）
# (4) redirectホップごとの再検証
# (5) IDNの統一（A-label/U-label/TR46）
# を設計として固定すること。
~~~~

- この例で観測していること：URLトリックを"ペイロード暗記"ではなく、次の4分類で説明・検証・修正提案できる、redirect（追従と最終宛先）、DNS（解決タイミング／再解決／ピン留め）、IDN（Unicode/ Punycode / 正規化）、IP表現（v4/v6混在、数値表記、IPv4-mapped等）、Validator と Fetcher の差分、正規化後の判定、DNS解決→IP比較（v4/v6）、redirectホップごとの再検証、IDNの統一（A-label/U-label/TR46）
- 出力のどこを見るか（注目点）：parsed host（A/Bそれぞれ）、DNS問い合わせログ（A/AAAA）、実際のソケット接続先（IP:port）、redirectホップ列（Locationの連鎖）、取得したいログ（最低限）、parsed host / port / scheme（正規化後）、正規化前の raw input（比較用）、IDN変換後（A-label/Punycode）の値、解決したA/AAAAレコード（タイムスタンプ付）、実際に接続したソケット宛先（IP:port）、redirect追従の有無、ホップごとの Location と最終URL、各ホップで再検証が走っているか（ログで確定）
- この例が使えないケース（前提が崩れるケース）：SSRF注入点が存在しない場合、またはURL入力が発生しない場合

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：V5 Validation, Sanitization and Encoding
  - 該当要件（可能ならID）：V5.1.1、V5.1.2、V5.2.1
  - このファイルの内容が「満たす/破れる」ポイント：
    - 満たす/破れる点：SSRFは「URL入力→サーバ側取得」という入力→実行境界。URL"文字列"の検証ではなく、(1) 正規化後のURL構造、(2) 解決後のIP（v4/v6）、(3) リダイレクト追従後の最終宛先、(4) DNS再解決のタイミング、の境界で閉じる
- WSTG：
  - 該当カテゴリ/テスト観点：WSTG-INPV-08 Testing for SSRF
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：
    - SSRFは「意図しない宛先へのサーバ発リクエスト」を成立させる。URLトリックは、フィルタ/allowlistの"判定と実際の接続先"の差分（検証・解釈・接続の非同一性）を突く
- PTES：
  - 該当フェーズ：Vulnerability Analysis、Exploitation、Reporting
  - 前後フェーズとの繋がり（1行）：Vulnerability Analysis で「URL検証（Validator）とHTTPクライアント（Fetcher）の差分」を特定し、Exploitation は"成立根拠の証拠化"に限定（OOB/ログ/差分）。Reporting は「正規化→IP判定→再解決制御→redirect制御」の順で原因と対策を分解する
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Initial Access、Discovery
  - 攻撃者の目的（この技術が支える意図）：T1190（公開アプリの脆弱性悪用）として入口になりうる、到達性が広がると内部探索（T1046）や、クラウドならメタデータ（T1552.005）に接続しうる

## 参考（必要最小限）
- OWASP SSRF Prevention Cheat Sheet（IP allowlist、v4/v6、ライブラリ出力利用）
- OWASP Top 10 2021 A10 SSRF（定義と影響）
- PortSwigger SSRF（SSRFの概念と典型）
- PortSwigger Research：URL validation bypass cheat sheet（解析不一致が根）
- PortSwigger Lab：open redirect経由のSSRF回避（redirect境界の教材）
- RFC 3986（URI分解の基礎）
- RFC 5890 / RFC 3492（IDN：A-label/U-label、Punycode）
- Unicode TR46（IDNA互換処理の代表）
- Node.js URL docs（WHATWGとlegacyの差分が明文化）

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`05_input_09_ssrf_01_reachability（internal_localhost_metadata）.md`
- 関連 topics：`05_input_09_ssrf_03_protocol（http_gopher_file）.md`
- 関連 topics：`05_input_09_ssrf_04_saas_features（webhook_preview_pdf）.md`

---

## 深掘りリンク（最大8）
- `05_input_00_入力→実行境界（テンプレ デシリアライズ等）.md`
- `05_input_09_ssrf_01_reachability（internal_localhost_metadata）.md`
- `05_input_09_ssrf_03_protocol（http_gopher_file）.md`
- `05_input_09_ssrf_04_saas_features（webhook_preview_pdf）.md`
- `05_input_09_ssrf_05_dns_rebinding（time_based_reachability）.md`
- `05_input_09_ssrf_06_parser_differential（url_parse_smuggling）.md`
- `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
- `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
