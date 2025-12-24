# 14_js_sourcemap_公開物から攻撃面抽出（endpoint_key）.md

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS：V1（アーキテクチャ/信頼境界）・V14（構成/デプロイ）を支える前提として、公開静的資産（JS/.map）から漏れる「内部境界情報（URL/ホスト/環境差分）」を観測し、露出の有無を状態化する。
- WSTG：Information Gathering（公開情報・アプリ構造の把握）/ Configuration and Deployment（不要なデバッグ資産の露出）として、`sourceMappingURL` と `.map` 到達性を入口の一部として扱う。
- PTES：Intelligence Gathering → Threat Modeling → Vulnerability Analysis に接続。目的は“ソースを見る”ことではなく、**攻撃面（endpoint）と運用境界（env差分/内部ホスト）**を抽出し、次の検証（Web/API/Config）へ優先度付きで渡すこと。
- MITRE ATT&CK：Reconnaissance（公開資産からの情報収集）として位置づける。攻撃者が探索コストを下げるのと同じ論理で、診断側は「最短で重要入口へ到達する」ために使う。

## 目的（この技術で到達する状態）
- 公開JSに含まれる `sourceMappingURL` を起点に、`.map` の到達性・内容（`sourcesContent` の有無）を**観測根拠つき**で確定できる。
- `.map` から **endpoint（API/GraphQL/WebSocket/管理UI）**、**外部依存（計測SDK/IdP/決済）**、**内部境界（stg/dev/internal host）**、**設定断片（キーらしき文字列）** を抽出し、入口の優先度を更新できる。
- 抽出結果を「次のファイルへ渡せる形（少数の代表点＋状態）」に整形し、02_web の recon / api / config へ迷わず接続できる。

## 前提（対象・範囲・想定）
- 対象：
  - 04_js で見つけた主要JS（bundle/chunk/vendor）と、その配信ホスト（CDN含む）
  - 03_http（ヘッダ/挙動）・12_waf_cdn（外周）で把握した入口差分（ホスト/パス）
- 範囲（守るべき境界）：
  - “公開物の取得”と“内容の解釈”が中心。抽出したキーや内部URLを根拠に、許可なく範囲拡大しない。
- 想定される実装差：
  - `.map` が本番では無効（404/403/非公開）
  - `.map` はあるが `sourcesContent` が空（ソース本文は含まれない）
  - `.map` が Data URL（JS内に埋め込み）
  - 環境差（stg/dev だけ `.map` が公開、prodは非公開）
- 成果物（最低限）：
  - `map_accessibility`（到達性）と `extracted_attack_surface`（endpoint/依存/境界情報）の2つに分けて残す

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) `sourceMappingURL` の有無と形（入口としての第一分岐）
- 見るもの：
  - JS末尾付近の `//# sourceMappingURL=...`
- 分岐（状態）：
  - A：存在しない（= `.map` 入口がない/別経路の可能性）
  - B：相対URL（`app.js.map` 等）
  - C：絶対URL（別ホスト・別パスへ飛ぶ）
  - D：Data URL（`data:application/json;base64,...`）
- 意味：
  - B/C は “追加の公開資産（.map）” が存在し得るという状態
  - D は “JS単体でソース情報が含まれる可能性” がある状態（取得と保管の優先度が上がる）

### 2) `.map` 到達性（403/404/200）と外周境界（WAF/CDN）の影響
- 見るもの：
  - ステータス（200/30x/403/404）
  - 主要ヘッダ（Cache, CDN/WAF系、Content-Type、ETag）
- 意味：
  - 404：本番で無効化されている可能性（ただし環境差の疑いは残る）
  - 403：外周（WAF/CDN/ACL）で制御されている可能性（12_waf_cdn のクラスターと突合）
  - 200：内容の精査へ（次の観測ポイントへ）

### 3) `.map` 構造（JSON）で見るべきフィールド（“情報量”の判定）
- 典型キー：
  - `sources`：元ソースのパス一覧（= 内部構造/リポジトリ構成の匂い）
  - `sourcesContent`：ソース本文（最重要。ここがあるかないかで情報量が大きく変わる）
  - `file`：ビルド対象ファイル名（bundle名）
- 状態化：
  - A：`sources`のみ（構造ヒントはあるが本文なし）
  - B：`sourcesContent`あり（本文から endpoint/key を抽出可能）
- 境界の意味：
  - `sources` に `src/`, `internal/`, `admin/`, `staging/` 等が出るなら “運用/環境境界の匂い”
  - Windowsパスや絶対パスが出るなら “ビルド環境の露出” の匂い（責任分界/運用改善に繋がる）

### 4) 抽出対象（“攻撃面”として意味がある文字列だけ拾う）
- endpoint候補（Web/APIへ渡せる）：
  - `/api`, `/graphql`, `/admin`, `/internal`, `/v1`, `/oauth`, `/callback`, `/webhook`
  - `wss://`, `ws://`, `sse`, `socket`
  - 完全修飾URL（`https://api.` など）と、相対パス（`/v1/...`）の両方
- 外部依存（信頼境界の説明材料）：
  - IdP/SSO（issuer, authorization endpoint などの断片）
  - 監視/分析SDK（Sentry等のDSN、計測エンドポイント）
  - 決済/メール/地図等（第三者API）
- “キーらしきもの”（取り扱い注意：断定しない）：
  - `apiKey`, `client_id`, `dsn`, `token` 等のラベル
  - ここでやるのは **存在の観測と露出経路の特定**。有効性の検証は 06_config（Secrets）側の設計で最小限に行う。

### 5) 境界（資産/信頼/権限）に落とす
- 資産境界：
  - `.map` が「同一ホスト/別ホスト（CDN/別ドメイン）」どちらで配られているか
  - “prodは非公開・stgは公開” のような環境境界が見えるか
- 信頼境界：
  - `.map` が第三者CDN配下で配布される場合、削除・制御の責任分界（誰が直すか）を説明できる
  - `.map` 内の外部依存（SDK/IdP等）を列挙し、04_saas や 02_web/authn へ繋げられる
- 権限境界：
  - `.map` から管理UIや内部APIが見える場合、以降の検証で「認証/認可/例外パス（authz/api）」の優先度が上がる（見える＝触れる、ではない点は維持）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言えること（状態）：
  - `.map` の到達性（存在/非存在/制御されている）
  - 情報量（`sourcesContent` の有無）と、そこから抽出された “攻撃面候補” の一覧
  - 環境境界（stg/dev/prod差）や外部依存（第三者境界）が見える/見えない
- 言えないこと（断定しない）：
  - 抽出したURLが“実際に到達可能”か（到達性は別観測：03_http / 08_asn_bgp / 12_waf_cdn）
  - 抽出したキーが“有効/権限あり”か（有効性は別検証：06_config/02_Secrets管理）
- 最低限のアウトプット形式（例）：
  - `sourcemap_inventory.csv`：host, js_url, map_url, status, has_sourcesContent, notes
  - `sourcemap_attack_surface.csv`：host, source_hint, extracted_type(endpoint/third-party/key_hint), value, confidence(高/中/低)

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- 優先度が上がる状態：
  - `.map` が 200 で取れて、`sourcesContent` がある（= 攻撃面抽出の精度が高い）
  - `admin/internal/graphql/webhook` など “境界が濃い入口” が見える
  - 外部依存（IdP/決済/分析）が多く、信頼境界が複雑（= 02_web/authn・04_saasへ直結）
- 次の仮説：
  - 仮説A：`.map` は無い/取れない（到達不可） → JS本体（04_js）とHTTP挙動（03_http）から入口を掘るのが主戦場
  - 仮説B：`.map` はあるが本文なし（sourcesのみ） → 構造ヒント（パス/モジュール名）から入口候補を作り、到達性は別観測で固める
  - 仮説C：`.map` に本文あり → 抽出した endpoint を 02_web/01_web_00_recon に渡し、入口→境界→検証方針を更新する

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A（`.map` なし/到達不可）：
  - 次の一手：
    - JS本体から endpoint 文字列（`/api` 等）を最小抽出し、03_http で到達性・挙動を確認
    - 12_waf_cdn のクラスターと突合し、外周制御で “.mapだけ抑止” なのか “ホスト全体” なのかを状態化
  - 到達点：
    - `.map` 非公開という運用状態を確定し、以降は通常のJS観測へ戻せる

- 仮説B（`.map` あり、本文なし）：
  - 次の一手：
    - `sources` のパス構造から “機能境界” を推定（例：`admin/`, `auth/`, `billing/`）し、代表入口の優先度を付ける
    - 02_web/01_web_00_recon に「候補機能（どの境界を先に見るか）」として渡す
  - 到達点：
    - ソース本文がなくても、入口の優先度が上がる（探索の無駄が減る）

- 仮説C（`.map` に本文あり）：
  - 次の一手：
    - endpoint候補を “重要度（auth/admin/api/webhook）×到達性（見える/見えない）” で整列し、代表点から 02_web（authn/authz/api/config）へ接続
    - キーらしき露出がある場合は、06_config_02（Secrets）へ “露出経路” として渡し、最小限の有効性確認（権限境界を壊さない範囲）に限定する
  - 到達点：
    - 「公開物→攻撃面抽出→検証計画」まで一貫して回せる

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
# 目的：JSから sourceMappingURL を見つけ、.map の到達性と情報量（sourcesContent有無）を確定する

# (1) JS末尾の sourceMappingURL を確認（代表のbundle/chunkに対して）
curl -sk https://example.com/assets/app.js | tail -n 5

# (2) .map を取得してステータス確認（403/404/200）
curl -sk -D - -o /dev/null https://example.com/assets/app.js.map | sed -n '1,20p'

# (3) .map の情報量確認（sourcesContent があるか）
curl -sk https://example.com/assets/app.js.map \
  | python -c "import sys,json; d=json.load(sys.stdin); print('sources=',len(d.get('sources',[])),'sourcesContent=',len(d.get('sourcesContent',[]) or []))"

# (4) endpoint候補の粗抽出（本文がある場合のみ。過剰にやらない）
curl -sk https://example.com/assets/app.js.map \
  | python -c "import sys,json,re; d=json.load(sys.stdin); sc=d.get('sourcesContent') or []; s='\n'.join([x for x in sc if isinstance(x,str)]); \
print('\n'.join(sorted(set(re.findall(r'https?://[^\\s\"\\']+|/api/[^\\s\"\\']+|/graphql\\b|/admin\\b', s))) ) )" \
  | head -n 50
~~~~
- 観測していること：
  - `.map` 入口があるか（sourceMappingURL）
  - `.map` が取れるか（到達性：status）
  - 抽出可能な情報量があるか（sourcesContent）
  - “攻撃面として意味のあるものだけ”を少数抽出する（次工程へ渡す）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回）
- ASVS：
  - V1：信頼境界（CDN/WAF/静的配布）と資産境界（prod/stg）を誤らないための観測
  - V14：デバッグ資産（sourcemap）の公開/制御、ビルド成果物の公開範囲の管理
  - （接続）06_config（Secrets/ヘッダ/デバッグ露出）へ渡し、運用改善・再発防止に落とす
- WSTG：
  - Information Gathering：公開資産からの構造把握（入口抽出）
  - Configuration and Deployment：不要なデバッグ/開発支援ファイルの露出確認
  - （接続）抽出した endpoint を Web/API のテスト計画へ反映する
- PTES：
  - Intelligence Gathering → Threat Modeling → Vulnerability Analysis
  - 前後の繋がり：入口（endpoint）と境界（外部依存/環境差）を先に固めることで、以降の検証（Authn/Authz/API/Config）の優先度が決まる
- MITRE ATT&CK：
  - Reconnaissance：公開情報からの情報収集（アプリ構造/外部依存/入口探索の効率化）
  - （接続）攻撃者の探索ロジックを、診断側は“境界説明と検証計画”に転用する

## 参考（必要最小限）
- `01_topics/01_asm-osint/04_js_フロント由来の攻撃面抽出.md`
- `01_topics/01_asm-osint/03_http_観測（ヘッダ・挙動）と意味.md`
- `01_topics/01_asm-osint/12_waf_cdn_挙動観測（ブロック_チャレンジ_例外）.md`
- `01_topics/02_web/01_web_00_recon_入口・境界・攻め筋の確定.md`
- `01_topics/02_web/06_config_02_Secrets管理と漏えい経路（JS_ログ_設定_クラウド）.md`
