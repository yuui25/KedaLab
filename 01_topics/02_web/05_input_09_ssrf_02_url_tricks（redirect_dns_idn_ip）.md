## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS
  - 位置づけ：SSRFは「URL入力→サーバ側取得」という入力→実行境界。URL“文字列”の検証ではなく、(1) 正規化後のURL構造、(2) 解決後のIP（v4/v6）、(3) リダイレクト追従後の最終宛先、(4) DNS再解決のタイミング、の境界で閉じる。:contentReference[oaicite:0]{index=0}
- WSTG
  - 位置づけ：SSRFは「意図しない宛先へのサーバ発リクエスト」を成立させる。URLトリックは、フィルタ/allowlistの“判定と実際の接続先”の差分（検証・解釈・接続の非同一性）を突く。:contentReference[oaicite:1]{index=1}
- PTES
  - 観点：Vulnerability Analysis で「URL検証（Validator）とHTTPクライアント（Fetcher）の差分」を特定し、Exploitation は“成立根拠の証拠化”に限定（OOB/ログ/差分）。Reporting は「正規化→IP判定→再解決制御→redirect制御」の順で原因と対策を分解する。:contentReference[oaicite:2]{index=2}
- MITRE ATT&CK
  - T1190（公開アプリの脆弱性悪用）として入口になりうる。
  - 到達性が広がると内部探索（T1046）や、クラウドならメタデータ（T1552.005）に接続しうる。

---

## タイトル
SSRF URLトリック（redirect / DNS / IDN / IP表現）境界モデル：検証した“つもり”と実際の接続先のズレ

---

## 目的（このファイルで到達する状態）
- SSRFの防御・診断を「URLを正規表現で弾く」から卒業し、**Validator と Fetcher の差分**という実務の本体に落とす。:contentReference[oaicite:5]{index=5}
- URLトリックを“ペイロード暗記”ではなく、次の4分類で説明・検証・修正提案できる。
  1) redirect（追従と最終宛先）
  2) DNS（解決タイミング／再解決／ピン留め）
  3) IDN（Unicode/ Punycode / 正規化）
  4) IP表現（v4/v6混在、数値表記、IPv4-mapped等）
- 結果として、次の質問に即答できる
  - その入力点は「ホストallowlist」なのか「IP allowlist」なのか（どの層で閉じているか）
  - redirect を追うか、追うなら何を再検証しているか
  - DNSをいつ引いて、いつ固定し、いつ再解決しているか
  - “同じURL”をValidatorとFetcherが同じ意味で解釈しているか

---

## 1. まず固定する前提：URLは“文法”より“実装差分”で危険になる
### 1.1 URI構文（RFC 3986）が示す分解
- URIは scheme / authority / path / query / fragment に分解され、authority は userinfo / host / port を取り得る。:contentReference[oaicite:6]{index=6}
- したがって `@`（userinfo）や `:`（port）、`[]`（IPv6）などは“仕様として正当”であり、文字列フィルタは誤判定しやすい。

### 1.2 実務で起きる問題：Validator と Fetcher が別実装
- 多くの事故は「検証はAライブラリ、接続はBライブラリ」で発生する。
- 例：Node.js では WHATWG URL と legacy url.parse() の差分が明示されている（同じ文字列でもプロパティの扱いが異なる）。:contentReference[oaicite:7]{index=7}
- PortSwiggerは URL validation bypass の根として「曖昧URLによる解析不一致」を指摘している。:contentReference[oaicite:8]{index=8}

---

## 2. 境界モデル：URLトリックは“4つのズレ”で説明できる
URLトリックは、攻撃テクの羅列ではなく、次のズレ（differential）でモデル化する。

### ズレA：文字列判定 vs 正規化後の構造判定
- 文字列の contains / startsWith / regex で host を見ている
- 実際はURLパーサが「host」を別の値として解釈する
- 防御の原則：**文字列ではなく、パーサが返した構造**を基準に判定する（OWASPは“ライブラリの出力値をIP比較に使う”方針を明示）。:contentReference[oaicite:9]{index=9}

### ズレB：host allowlist vs 接続先IP allowlist
- “許可ホスト名”を見てOKにしても、DNSの解決先が内部/localhost/link-localになり得る
- 防御の原則：許可リストは「最終的に接続されるIP（v4/v6）」で比較し、v6も含める。:contentReference[oaicite:10]{index=10}

### ズレC：初回検証の宛先 vs redirect後の最終宛先
- “最初のURL”は許可、redirectで最終宛先が変わる
- PortSwiggerは open redirect を使って SSRF制限を回避する学習ケースを提示している（「最初はローカルしか許可」でも、redirectで内部へ寄せられる）。:contentReference[oaicite:11]{index=11}
- 防御の原則：redirectを追従するなら **各ホップで再検証**、追従しないなら仕様として無効化。

### ズレD：IDN/Unicode 表示名 vs 実際のDNSラベル（Punycode）
- IDNはUnicode（U-label）とASCII（A-label）を相互変換しうる。:contentReference[oaicite:12]{index=12}
- Unicode TR46（互換処理）も存在し、実装が“どの処理系（TR46/IDNA2008等）を採用するか”で差分が生じる。:contentReference[oaicite:13]{index=13}
- 結果：表示上は“許可ドメインに見える”／判定側は“別ラベルとして扱う”、またはその逆、が起き得る。

---

## 3. 観測ポイント（ここが薄いと全体が薄くなる）
本ファイルでは「トリックを挙げる」より、**どこを見ればズレが確定するか**を固定する。

### 3.1 入力→正規化（Validator側）の観測
- 取得したいログ（最低限）
  - parsed host / port / scheme（正規化後）
  - 正規化前の raw input（比較用）
  - IDN変換後（A-label/Punycode）の値
- 期待する“状態”の例
  - 状態V1：Validatorが host を A と解釈している
  - 状態V2：Validatorが host を B（別値）と解釈している（差分が根拠）

### 3.2 名前解決（DNS）と接続先IPの観測
- 重要：**接続先IPはDNSの瞬間値**であり、比較対象は host ではなく IP（v4/v6）である。:contentReference[oaicite:14]{index=14}
- 取得したいログ
  - 解決したA/AAAAレコード（タイムスタンプ付）
  - 実際に接続したソケット宛先（IP:port）
- “到達性クラス”の結論（前ファイルと接続）
  - localhost / internal / metadata のどれへ到達し得たか（状態として言い切る）

### 3.3 redirect の観測（Fetcher側）
- 取得したいログ
  - redirect追従の有無
  - ホップごとの Location と最終URL
  - 各ホップで再検証が走っているか（ログで確定）
- PortSwiggerが示す通り、redirectは SSRF制限の現実的なバイパス要因であるため、追従設計は監査ポイントになる。:contentReference[oaicite:15]{index=15}

---

## 4. 結果の意味（“状態”として出す：yes/noで終わらせない）
### 状態S-REDIRECT：redirectが“検証境界を跨いでいる”
- 意味：最初のURL検証が最終宛先を保証していない
- 影響：allowlistの“意図”が破綻し、内部/localhost/metadataへ接続し得る

### 状態S-DNS：DNSの解決タイミング差で“検証と接続が一致しない”
- 意味：検証時にOKだったが、接続時に別IPへ向く（または再解決する）
- 影響：host allowlistが実質無力化するため、IP allowlist・ピン留め・再検証が必要になる

### 状態S-IDN：表示・正規化・比較の不一致で“同一視/別物扱い”が揺れる
- 意味：A-label/U-label/TR46処理の差で、allowlist比較が破綻し得る
- 影響：許可ドメインになりすまし／誤ブロック／ログと実体の乖離（監視も壊れる）

### 状態S-IPFORMAT：IP表現の同値性が判定と接続でズレる
- 意味：同じ到達先でも、表現の揺れ（v6、IPv4-mapped等）で判定がすり抜ける
- 影響：内部/localhost/link-localの除外が漏れる可能性（特にv6未考慮）
- OWASPは allowlist を v4/v6含めたIPで構築し、ライブラリの出力値を比較に使う、としている（この状態の対策原則になる）。:contentReference[oaicite:16]{index=16}

---

## 5. 攻撃者視点での利用（意思決定に効く“分岐”として）
※ここは具体ペイロード集ではなく、攻撃者が何を見て次の手を選ぶかの判断モデル。

### 分岐A：redirect追従があるか
- ある：最終宛先で再検証していないなら、制限回避の余地が増える（内部到達性へ寄せられる）
- ない：DNS/IDN/IP表現など、“初回URL解釈”の差分に重心が移る

### 分岐B：host allowlist か IP allowlist か
- hostのみ：DNS差分（検証時と接続時のズレ）で内部到達に寄る余地が残りやすい
- IPまで：次は「redirect後の再検証」「v6含む同値判定」「DNS再解決制御」の監査に移る:contentReference[oaicite:17]{index=17}

### 分岐C：IDN処理が統一されているか
- 表示・比較・ログが別体系：許可/拒否の境界が揺れ、監視も誤作動しやすい（運用品質にも直結）
- IDNA/TR46に統一：少なくとも“表記揺れ”起因の差分は縮む:contentReference[oaicite:18]{index=18}

---

## 6. 次に試すこと（仮説A/B：条件で次の手が変わる）
### 仮説A：SSRFは成立しているが、制限（allowlist等）がある
- 観測でまず確定する
  - redirect追従の有無（ホップログ）
  - DNS解決のタイミング（検証時/接続時/redirect後で再解決するか）
  - IP比較が v4/v6 を含んでいるか（v6漏れは最優先で疑う）:contentReference[oaicite:19]{index=19}
- 次の一手
  - “最終宛先”で再検証が走るか（走らないなら設計不備として指摘可能）
  - ValidatorとFetcherの実装差（別ライブラリ）を切り分ける（Lab化）

### 仮説B：SSRFは成立しない（接続自体が抑止されている）ように見える
- 観測でまず確定する
  - URLは解釈されているか（parsed host等）
  - DNSは引いているか（問い合わせログ）
  - localhostは別枠で成立し得るため、egress遮断だけで否定しない
- 次の一手
  - 実行環境（フロント/ワーカー）差を疑い、同一入力でも処理系が変わる経路（非同期/変換）を探す

---

## 7. 防御設計（“文字列フィルタ”から卒業する：優先順位）
OWASP SSRF Prevention Cheat Sheet は、防御観点として「ライブラリ出力を使ったIP比較」「v4/v6を含むallowlist」「多層の検証」を明確に示す。:contentReference[oaicite:20]{index=20}

### 7.1 正規化後に判定する（Validatorの統一）
- URLは「パーサで構造化」→「host/scheme/portを取り出す」→「許可条件と比較」
- 文字列の包含判定・部分一致を禁止する（比較対象がhostなのかURL全体なのかが曖昧になる）

### 7.2 接続先IPで判定する（DNS差分対策の基礎）
- host allowlist だけでは不十分になりやすい
- 解決したIP（A/AAAA）を基準に、許可/拒否（内部/localhost/link-local/metadata等）を判定する:contentReference[oaicite:21]{index=21}

### 7.3 redirect を制御する（追従するなら各ホップ再検証）
- redirect無効化が可能なら優先（仕様として）
- 追従するなら、**ホップごとに正規化→解決→IP判定**を再実施（“最初だけ検証”を禁止）

### 7.4 IDN処理の統一（ログ・比較・表示の一貫性）
- 比較はA-label（Punycode）で統一する、など「運用と検証の整合」を取る
- RFC 5890 の A-label / U-label、RFC 3492 のPunycode、Unicode TR46 の互換処理、の採用範囲を明文化する:contentReference[oaicite:22]{index=22}

---

## 8. 手を動かす検証（Labs：手順書ではなく“設計”）
- 追加候補Lab
  - `04_labs/02_web/05_input/09_ssrf_url_tricks_redirect_dns_idn_ip/`
- 目的
  - ValidatorとFetcherの差分が、どの条件で“接続先のズレ”になるかを再現し、観測点（ログ）を固定する
- 設計差分
  - URLパーサ差：A（厳格）/B（別仕様 or legacy）
  - DNS差：検証時に解決→接続時に再解決、などタイミング差を作る
  - redirect差：追従なし/あり（ホップ再検証なし/あり）
  - IDN差：U-label入力→A-label比較、TR46処理あり/なし
  - IP差：v4/v6の両方を扱うallowlistの有無:contentReference[oaicite:23]{index=23}
- 観測点
  - parsed host（A/Bそれぞれ）
  - DNS問い合わせログ（A/AAAA）
  - 実際のソケット接続先（IP:port）
  - redirectホップ列（Locationの連鎖）

---

## 9. コマンド/例（最小限：方針の形だけ）
~~~~
# このファイルの要点は「ペイロード集」ではなく、
# (1) Validator と Fetcher の差分
# (2) 正規化後の判定
# (3) DNS解決→IP比較（v4/v6）
# (4) redirectホップごとの再検証
# (5) IDNの統一（A-label/U-label/TR46）
# を設計として固定すること。
~~~~

---

## 参考（一次情報に近いもの中心）
- OWASP SSRF Prevention Cheat Sheet（IP allowlist、v4/v6、ライブラリ出力利用）:contentReference[oaicite:24]{index=24}
- OWASP Top 10 2021 A10 SSRF（定義と影響）:contentReference[oaicite:25]{index=25}
- PortSwigger SSRF（SSRFの概念と典型）:contentReference[oaicite:26]{index=26}
- PortSwigger Research：URL validation bypass cheat sheet（解析不一致が根）:contentReference[oaicite:27]{index=27}
- PortSwigger Lab：open redirect経由のSSRF回避（redirect境界の教材）:contentReference[oaicite:28]{index=28}
- RFC 3986（URI分解の基礎）:contentReference[oaicite:29]{index=29}
- RFC 5890 / RFC 3492（IDN：A-label/U-label、Punycode）:contentReference[oaicite:30]{index=30}
- Unicode TR46（IDNA互換処理の代表）:contentReference[oaicite:31]{index=31}
- Node.js URL docs（WHATWGとlegacyの差分が明文化）:contentReference[oaicite:32]{index=32}

---

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/05_input_09_ssrf_01_reachability（internal_localhost_metadata）.md`
- `01_topics/02_web/05_input_09_ssrf_03_protocol（http_gopher_file）.md`
- `01_topics/02_web/05_input_09_ssrf_04_saas_features（webhook_preview_pdf）.md`

---

## 次（作成候補順）
- `01_topics/02_web/05_input_09_ssrf_03_protocol（http_gopher_file）.md`
