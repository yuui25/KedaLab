# CDN / WAF エッジの識別とバイパス起点

> **スコープ**: ブラックボックス外部偵察で「対象が CDN / WAF / リバースプロキシの前段配下に居るか」を判定し、製品を特定し、エッジを迂回する起点（クライアント IP ヘッダ詐称・オリジン IP 特定）を作るところまで。観測される TLS / バナー / ヘッダがオリジンのものかフロントのものかの切り分けが主目的。WAF シグネチャの具体的回避は [`Exposed_Files.md`](./Exposed_Files.md) と各 Web 脆弱性ファイル側で扱う。Akamai を主例にするが、判定ロジックは Cloudflare / Fastly / Imperva 等にも共通。

## 着火条件

以下のいずれかに該当する場合:

- Web 対象の `Server:` ヘッダや TLS 証明書 CN/SAN が generic（`*.akamaized.net` / `*.cloudflare.com` 等）で、観測値がオリジンのものか疑わしい
- ディレクトリ列挙・ファジング・TLS スキャンが急に 403 / RST / challenge ページに変わる（前段の WAF / Bot 対策を疑う）
- IP 制限・地理制限・レート制限に当たっており、前段がクライアント IP をヘッダ経由で受けている可能性がある
- DNS に複数 A レコード / CNAME チェーンがあり、実体（オリジン）と配信面（エッジ）が分離していそう

## 環境前提

- 実行環境: テスター端末
- 必要なツール: `dig` / `host` / `curl` / `openssl`（標準）、`wafw00f`（WAF 製品判定。ペネトレ用 Linux ディストリで `apt` / `pipx` 導入、一部標準同梱）、`whatweb` / `nuclei`（フィンガープリント補完）
- 外部リソース依存: オリジン特定（§5）の履歴 DNS / 証明書透明性ログ検索はインターネットアクセス必須。オフライン環境では実施不可、ローカルで取れる CNAME / バナー判定（§1〜§4）に留める

## 先に確認すること

- **観測している値がフロント側か**: CDN 配下では `Server:` ヘッダ・TLS 設定・レスポンスヘッダはエッジのものであってオリジンのものではない。`../01_Reconnaissance/TLS_Audit.md` の CN/SAN 判定と必ず突き合わせる
- **どの面を叩いているか**: apex ドメイン・www・API サブドメイン・古いサブドメインで前段構成が異なることが多い（API だけ素通し等）

**攻撃者の思考トレース:** エッジ配下のホストを正面から殴っても、見えているのは「CDN/WAF が見せたい姿」でしかない。最初にやるのは「前段が居るか・何の製品か」の確定。確定したら方針は2つに割れる ―― (a) **エッジを通したまま騙す**（クライアント IP ヘッダ詐称で ACL/レート制限を抜く・製品固有のデバッグ機能を引き出す）、(b) **エッジを迂回する**（オリジン IP を特定して直接叩き、WAF/Bot 対策ごとスキップする）。(b) が通れば WAF ルールの個別回避を考える必要が消えるので、判定と並行してオリジン特定を走らせる。

---

## 1. CDN / WAF 配下かの判定

**コマンド:**

```bash
# [Attacker] CNAME チェーンを辿る（エッジへの委譲が見える）
dig +noall +answer CNAME [TARGET_DOMAIN]
host -t CNAME [TARGET_DOMAIN]

# [Attacker] レスポンスヘッダ一式（Server / Via / X-Cache 系を見る）
curl -sI https://[TARGET_DOMAIN]/ | grep -iE "server|via|x-cache|x-served-by|x-akamai|cf-ray|x-iinfo|set-cookie"

# [Attacker] WAF 製品の自動判定
wafw00f -a https://[TARGET_DOMAIN]/
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| CNAME が `*.edgekey.net` / `*.edgesuite.net` / `*.akamaiedge.net` / `*.akamai.net` / `*.akamaized.net` / `*.akamaihd.net` | Akamai 配下 | §2 で製品確定 → §3/§4 へ |
| CNAME が `*.cloudflare.net` / `cf-ray` ヘッダ / `__cfduid` `cf_clearance` Cookie | Cloudflare 配下 | §2 の比較表で挙動差を確認 |
| `x-served-by` / `x-cache` に `cache-*` ノード名 / Fastly の `Via` | Fastly 配下 | 同上 |
| `X-Iinfo` ヘッダ / `incap_ses_*` `visid_incap_*` Cookie | Imperva (Incapsula) | 同上 |
| `Server: AkamaiGHost` | Akamai エッジ（Ghost）が応答 | §3 デバッグヘッダ・§4 IP ヘッダへ |
| バナー・CN/SAN がオリジンの実製品名（nginx / Apache / IIS のバージョン付き） | **前段が居ない or 素通し**。直接叩ける | 通常の Web 偵察（`Web_Enumeration.md`）に戻る |
| `wafw00f` が `No WAF detected` だが challenge ページは出る | 検出 DB 未対応の WAF / Bot 対策 | §1 の Cookie / ヘッダを手動確認、challenge の文言で製品推定 |

**注意:** CNAME チェーンは多段（apex → CDN → さらに別 CDN）になることがある。`dig` の ANSWER SECTION を全行見る。apex に CNAME を置けない制約から、apex だけ A レコード直書き＝オリジン露出というパターンがある（§5 に直結）。

---

## 2. CDN / WAF 製品の見分け（フィンガープリント）

**コマンド:**

```bash
# [Attacker] Bot 対策の Set-Cookie パターンを観察
curl -sI https://[TARGET_DOMAIN]/ | grep -i set-cookie

# [Attacker] フィンガープリント補完（ヘッダ・JS・Cookie を横断判定）
whatweb -a 3 https://[TARGET_DOMAIN]/
```

**観測される出力 → 製品の示唆:**

| シグナル | 製品 | 備考 |
|---|---|---|
| `_abck` / `bm_sv` / `bm_mi` / `bm_so` / `bm_lso` / `ak_bmsc` Cookie | Akamai Bot Manager | センサーデータ検証で自動化を弾く。`Web_Enumeration.md` で「除外対象」とした Cookie 群と同一 |
| `Server: AkamaiGHost` / `X-Akamai-*` ヘッダ | Akamai エッジ | §3 デバッグヘッダの対象 |
| `cf-ray` / `Server: cloudflare` / `cf_clearance` | Cloudflare | challenge は `503` + JS / Turnstile |
| `x-served-by: cache-*` / `x-cache: HIT/MISS` + Fastly ノード | Fastly | デバッグは `Fastly-Debug: 1` 系（製品依存） |
| `X-Iinfo` / `incap_ses_*` | Imperva Incapsula | |
| `X-Sucuri-ID` / `X-Sucuri-Cache` | Sucuri | |

**注意:** Bot 対策 Cookie（`_abck` 等）はテスト対象セッションではないので Web アプリのテスト時は除外する（`Web_Enumeration.md` 既出）。**ただし攻撃側視点では「これが付く＝自動化ツールが弾かれる前段が居る」シグナル**であり、ffuf / gobuster / nuclei が急に 403 や challenge を返す原因の切り分けに使う。Bot Manager 下ではツールの並列・速度を落としても根本的に通らないことが多く、その場合はオリジン直叩き（§5）に切り替える。

---

## 3. Akamai デバッグヘッダ（Pragma: akamai-x-*）

> **要実機検証**: 以下はエッジのデバッグ機能を引き出す古典的手法だが、**Akamai は経年でこのデバッグ応答をデフォルト無効化・要明示有効化の方向に締めている**ため、現代の構成では応答しないことが多い。「効けば強い偵察、空振りが普通」という前提で試す。出典 URL は未確認（記憶ベース）なので、効いた／効かなかったの実観測を優先する。

**コマンド:**

```bash
# [Attacker] リクエストに akamai-x-* デバッグ指示を Pragma で渡す
curl -sI https://[TARGET_DOMAIN]/ \
  -H 'Pragma: akamai-x-cache-on, akamai-x-cache-remote-on, akamai-x-check-cacheable, akamai-x-get-cache-key, akamai-x-get-true-cache-key, akamai-x-get-request-id, akamai-x-serial-no' \
  | grep -iE "x-cache|x-true-cache-key|x-cache-key|x-check-cacheable|x-serial|x-akamai|akamai"
```

**観測される出力 → 示唆:**

| 応答ヘッダ | 示唆 | 次のアクション |
|---|---|---|
| `X-Cache: TCP_MISS from a.b.c.d` 等 | エッジ→オリジン経路・キャッシュ判定が露出 | キャッシュ挙動を把握。キャッシュ可能パスは Web キャッシュ汚染/欺瞞の調査対象 |
| `X-Cache-Key` / `X-True-Cache-Key` | **キャッシュキーの構成**（どのパラメータ/ヘッダがキーに含まれるか）が露出 | キーに含まれない入力はキャッシュ汚染の候補。アンキーinputの特定に使う |
| `X-Check-Cacheable: YES` | そのパスがキャッシュ可能 | キャッシュ欺瞞（認証ページを静的拡張子に見せる）の検討材料 |
| `X-Serial` / `X-Akamai-*` に内部識別子 | エッジノードの内部情報露出 | 情報露出として記録（直接の悪用は限定的） |
| デバッグヘッダが何も返らない | デバッグ無効化済み（現代の既定）/ Akamai でない | この手法は打ち切り、§4・§5 へ |

**注意:** キャッシュキー露出が取れた場合、Web キャッシュ汚染（unkeyed header / param 経由）やキャッシュ欺瞞の調査に直結するが、それ自体は別技術（本ファイルのスコープ外）。ここでは「キャッシュ構造の偵察ができた」ところまでに留め、汚染 PoC は事前合意を確認してから別途扱う。

---

## 4. クライアント IP ヘッダ詐称によるアクセス制御バイパス

**コマンド:**

```bash
# [Attacker] 制限ページに対し、信頼されうる client IP ヘッダを複数試す
#  ※ Akamai は既定で True-Client-IP にクライアント IP を載せてオリジンへ渡す
for H in "True-Client-IP" "X-Forwarded-For" "X-Real-IP" "Client-IP" "X-Client-IP" "X-Originating-IP"; do
  echo "=== $H ===";
  curl -s -o /dev/null -w "%{http_code}\n" https://[TARGET_DOMAIN]/admin -H "$H: 127.0.0.1";
done
```

**観測される出力 → 示唆:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| いずれかのヘッダで `403`/`401` → `200` に変化 | オリジン/WAF がそのヘッダを無検証で信頼。**IP ベース ACL バイパス成立** | 内部限定パス・管理画面・地理制限コンテンツへ到達を試す |
| `True-Client-IP` だけ挙動が変わる | Akamai 既定ヘッダをオリジンが信頼 | 同上。Akamai 配下で最も当たりやすい |
| レート制限のカウントが IP ヘッダ値ごとにリセットされる | レート制限がヘッダ由来 IP で集計 | ヘッダ値をローテーションしてレート制限を回避 |
| どのヘッダでも変化なし | 前段が client IP ヘッダを上書き/剥離、またはオリジンが TCP 由来 IP のみ信頼 | この経路は不成立。§5 のオリジン直叩きへ |

**注意:** `True-Client-IP` が Akamai 既定のクライアント IP 転送ヘッダ名なのは確度高めだが、**悪用可否はオリジン側がそれを無検証で信頼しているかに依存**する。ヘッダ名は配信設定で変更可能なので、`True-Client-IP` 不発でも `X-Forwarded-For` 系を一通り試す。地理制限回避を目的に外部 IP を詐称する場合、対象国の IP レンジを値に使う。**アクセス制御を実際に越える操作は事前合意の範囲内か確認する**（認可境界の突破に当たるため）。

---

## 5. オリジン IP の特定（エッジを迂回する）

**コマンド:**

```bash
# [Attacker] apex は CNAME を置けず A 直書き＝オリジン露出のことがある
dig +short A [TARGET_DOMAIN]
dig +short A www.[TARGET_DOMAIN]

# [Attacker] エッジ配下に入っていない古い/別サブドメインを探す（各 IP が CDN レンジ外なら候補）
#   → サブドメイン列挙は DNS_Enumeration.md の bruteforce / 証明書透明性ログ経路を使う

# [Attacker] オリジン候補 IP に Host ヘッダを付けて直接当て、同一サイトが返るか確認
curl -sI https://[ORIGIN_CANDIDATE_IP]/ -H "Host: [TARGET_DOMAIN]" -k | head
```

**観測される出力 → 示唆:**

| 観測 | 示唆 | 次のアクション |
|---|---|---|
| 候補 IP が CDN レンジ外 + `Host:` 指定で本物のサイトが返る | **オリジン直叩き成立**。WAF/Bot 対策をスキップできる | 以降の Web 攻撃をこの IP へ直接行う（エッジ非経由） |
| TLS 証明書 SAN にオリジンの実 FQDN / 内部ホスト名 | オリジン名・内部命名が露出 | その FQDN/IP を直叩き候補に追加 |
| メール系サブドメイン（mx / mail）が CDN 外 IP | メールサーバ等が同一インフラ上のオリジン近傍 | 同セグメントのオリジン推定に使う |
| 候補 IP に当てても CDN の challenge / 別サイト | オリジンが IP ACL でエッジからのみ受信 | この経路は不成立。エッジ経由（§3/§4）に戻る |

**オリジン特定の主な経路（詳細は各ファイル）:**

- 履歴 DNS / 証明書透明性ログ / サブドメイン列挙 → `DNS_Enumeration.md`（CDN 化以前の A レコードや、エッジに載っていないサブドメインを拾う）
- TLS 証明書 SAN / Issuer からの実 FQDN 推定 → `TLS_Audit.md`
- アプリ内の IP 露出（`SERVER_ADDR` / エラーページ / メールヘッダの `Received:`）→ `Exposed_Files.md` / `DNS_Enumeration.md`
- SSRF が取れている場合のオリジン側 IP 反射 → `../02_Initial_Access/Web_Vulnerabilities/SSRF.md`

**注意:** オリジンが「エッジの IP レンジからのみ受信する」ACL を張っていると直叩きは弾かれる（正しい設定）。その場合は迂回を諦めてエッジ経由の手法（§3/§4・WAF 回避）に戻る。オリジン IP を掴んでも、Host ヘッダを付けないとデフォルトサイト/エラーが返る点に注意。

---

## 刺さらなかったとき（全体）

| 状況 | 推定原因 | 代替手段 |
|---|---|---|
| 製品が判定できない | 検出 DB 未対応 / 多段 CDN / ヘッダ書き換え | challenge ページの文言・JS の読み込み元ドメイン・favicon ハッシュで手動推定 |
| デバッグヘッダ（§3）が全く返らない | 現代の既定で無効化 | 期待しない。§4・§5 に注力 |
| IP ヘッダ詐称（§4）が全滅 | 前段がヘッダを剥離/上書き | オリジン直叩き（§5）に切替。それも不可なら WAF 個別回避へ |
| オリジン直叩き（§5）が弾かれる | オリジンが エッジ IP のみ許可 | エッジ経由のまま WAF シグネチャ回避（`Exposed_Files.md` のエンコード揺らし）を検討 |
| ファジングが challenge で全部詰まる | Bot Manager 等の自動化検知 | 速度/並列を落としても根本解決しないことが多い。手動列挙＋オリジン特定に方針転換 |

## 注意点・落とし穴

- **観測値の帰属を常に意識する。** CDN 配下では `Server:` / TLS / レスポンスヘッダはエッジのもの。これをオリジンの設定として記録すると誤った結論になる。`TLS_Audit.md` の CN/SAN 判定と必ず突き合わせる
- **TLS / ディレクトリスキャンの連続接続は前段の WAF / IPS を発火させ、以降の調査用 IP が遮断され得る**（`TLS_Audit.md` 既出）。CDN/WAF 配下と判明したら、列挙速度を落とすかオリジン直叩きへ切り替える
- **§3 のデバッグ機能・§4 の IP 詐称は「エッジの設計上の挙動を突く」ものであり、製品固有・構成依存。** 効かないのが普通という前提で、空振りしたら長居せず次へ

## 本番での前提

- **事前合意の要否**: ★（§1/§2 のフィンガープリント・§3 デバッグヘッダ観察・§5 のオリジン特定は受動的で技術的判断のみ）/ ★★（§4 の IP ヘッダ詐称で実際にアクセス制御を越える行為・§5 でオリジン直叩きに切り替える行為は、認可境界・スコープ境界に触れるため事前確認推奨）
- **想定される SIEM / EDR 検知**: WAF の異常ヘッダ検知（大量の IP ヘッダ試行・Pragma akamai-x-* の連打）、Bot Manager のスコアリング、オリジン直叩き時の「エッジ非経由アクセス」アラート
- **業務影響リスク**: なし（偵察主体）。ただし IP ヘッダ詐称でレート制限を回避すると過負荷を招き得るので試行量に注意
- **スコープの注意**: オリジン IP / 別サブドメインが**スコープ外の資産**である可能性がある。直叩き前に対象範囲を確認する
- **演習環境での扱い**: 制約なし

## 関連技術

- 前：TLS 証明書 CN/SAN からの CDN 配下判定・製品推定 → `TLS_Audit.md`
- 前：CNAME チェーン・複数 A レコード・サブドメイン列挙・履歴 DNS → `DNS_Enumeration.md`
- 前：Cookie / Server ヘッダ / generator からのフレームワーク判定（Bot 対策 Cookie 除外） → `Web_Enumeration.md`
- 後：オリジン特定後の通常 Web 偵察 → `Web_Enumeration.md` / `Exposed_Files.md`
- 後：WAF シグネチャの個別回避（エンコード揺らし・大文字混在） → `Exposed_Files.md`
- 関連：エッジ*アプライアンス*（SSL-VPN / 次世代 FW / LB）製品確定時の CVE 照合 → `../00_Playbook/External_Service_Recon_Flow.md` / `../02_Initial_Access/Edge_Appliance_CVEs.md`
- 関連：オリジン側 IP を反射させる SSRF 経路 → `../02_Initial_Access/Web_Vulnerabilities/SSRF.md`
