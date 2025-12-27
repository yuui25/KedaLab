# 14_js_sourcemap_公開物から攻撃面抽出（endpoint_key）
JS Sourcemap 公開物から攻撃面抽出（endpoint/key）
“攻撃面（endpoint）と運用境界（env差分/内部ホスト）”を抽出し、次の検証（Web/API/Config）へ優先度付きで渡す

## 目的（この技術で到達する状態）
- 公開JSに含まれる `sourceMappingURL` を起点に、`.map` の到達性・内容（`sourcesContent` の有無）を**観測根拠つき**で確定できる。
- `.map` から **endpoint（API/GraphQL/WebSocket/管理UI）**、**外部依存（計測SDK/IdP/決済）**、**内部境界（stg/dev/internal host）**、**設定断片（キーらしき文字列）** を抽出し、入口の優先度を更新できる。
- 抽出結果を「次のファイルへ渡せる形（少数の代表点＋状態）」に整形し、02_web の recon / api / config へ迷わず接続できる。

## 前提（対象・範囲・想定）
- 対象：04_js で見つけた主要JS（bundle/chunk/vendor）と、その配信ホスト（CDN含む）、03_http（ヘッダ/挙動）・12_waf_cdn（外周）で把握した入口差分（ホスト/パス）
- 想定する環境：
  - `.map` が本番では無効（404/403/非公開）
  - `.map` はあるが `sourcesContent` が空（ソース本文は含まれない）
  - `.map` が Data URL（JS内に埋め込み）
  - 環境差（stg/dev だけ `.map` が公開、prodは非公開）
- できること/やらないこと（安全に検証する範囲）：
  - できる：“公開物の取得”と“内容の解釈”が中心。抽出したキーや内部URLを根拠に、許可なく範囲拡大しない。
  - やらない：抽出したキーや内部URLを根拠に、許可なく範囲拡大しない。有効性の検証は 06_config（Secrets）側の設計で最小限に行う。
- 依存する前提知識（必要最小限）：
  - `01_topics/01_asm-osint/04_js_フロント由来の攻撃面抽出.md`
  - `01_topics/01_asm-osint/03_http_観測（ヘッダ・挙動）と意味.md`
  - `01_topics/01_asm-osint/12_waf-cdn_挙動観測（ブロック_チャレンジ_例外）.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：JS Sourcemap公開物から攻撃面抽出（endpoint/key）、運用境界の特定
  - 扱わない（別ユニットへ接続）
    - JS観測 → `04_js_フロント由来の攻撃面抽出.md`
    - HTTP観測 → `03_http_観測（ヘッダ/挙動）と意味.md`
    - 外周観測 → `12_waf-cdn_挙動観測（ブロック_チャレンジ_例外）.md`
    - Secrets管理 → `01_topics/02_web/06_config_02_Secrets管理と漏えい経路（JS_ログ_設定_クラウド）.md`

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
- 観測対象（プロトコル/データ構造/やり取りの単位）
  - `sourceMappingURL` の有無と形（入口としての第一分岐）
    - 見るもの：JS末尾付近の `//# sourceMappingURL=...`
    - 分岐（状態）：
      - A：存在しない（= `.map` 入口がない/別経路の可能性）
      - B：相対URL（`app.js.map` 等）
      - C：絶対URL（別ホスト・別パスへ飛ぶ）
      - D：Data URL（`data:application/json;base64,...`）
    - 意味：
      - B/C は “追加の公開資産（.map）” が存在し得るという状態
      - D は “JS単体でソース情報が含まれる可能性” がある状態（取得と保管の優先度が上がる）
  - `.map` 到達性（403/404/200）と外周境界（WAF/CDN）の影響
    - 見るもの：ステータス（200/30x/403/404）、主要ヘッダ（Cache, CDN/WAF系、Content-Type、ETag）
    - 意味：
      - 404：本番で無効化されている可能性（ただし環境差の疑いは残る）
      - 403：外周（WAF/CDN/ACL）で制御されている可能性（12_waf_cdn のクラスターと突合）
      - 200：内容の精査へ（次の観測ポイントへ）
  - `.map` 構造（JSON）で見るべきフィールド（“情報量”の判定）
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
  - 抽出対象（“攻撃面”として意味がある文字列だけ拾う）
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
- 境界の観点
  - 資産境界（管理主体・委託先・対象範囲の線引き）：`.map` が「同一ホスト/別ホスト（CDN/別ドメイン）」どちらで配られているか。“prodは非公開・stgは公開” のような環境境界が見えるか
  - 信頼境界（外部連携・第三者・越境ポイント）：`.map` が第三者CDN配下で配布される場合、削除・制御の責任分界（誰が直すか）を説明できる。`.map` 内の外部依存（SDK/IdP等）を列挙し、04_saas や 02_web/authn へ繋げられる
  - 権限境界（権限の切替/伝播/委任）：`.map` から管理UIや内部APIが見える場合、以降の検証で「認証/認可/例外パス（authz/api）」の優先度が上がる（見える＝触れる、ではない点は維持）
- 重要なフィールド/差分/状態（「ここが変わると意味が変わる」点）
  - `sourceMappingURL` の有無と形（相対URL/絶対URL/Data URL）
  - `.map` 到達性（403/404/200）
  - `sourcesContent` の有無（情報量の判定）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が“確定”できるか
  - `.map` の到達性（存在/非存在/制御されている）
  - 情報量（`sourcesContent` の有無）と、そこから抽出された “攻撃面候補” の一覧
  - 環境境界（stg/dev/prod差）や外部依存（第三者境界）が見える/見えない
- 何が“推定”できるか（推定の根拠/前提）
  - 抽出したURLが“実際に到達可能”か（到達性は別観測：03_http / 08_asn_bgp / 12_waf_cdn）
- 何は“言えない”か（不足情報・観測限界）
  - 抽出したURLが“実際に到達可能”か（到達性は別観測：03_http / 08_asn_bgp / 12_waf_cdn）
  - 抽出したキーが“有効/権限あり”か（有効性は別検証：06_config/02_Secrets管理）
- よくある状態パターン（正常/異常/境界がズレている等）
  - パターンA：`.map` は無い/取れない（到達不可）
  - パターンB：`.map` はあるが本文なし（sourcesのみ）
  - パターンC：`.map` に本文あり（抽出可能）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す“狙い目”
  - `.map` が 200 で取れて、`sourcesContent` がある（= 攻撃面抽出の精度が高い）
  - `admin/internal/graphql/webhook` など “境界が濃い入口” が見える
  - 外部依存（IdP/決済/分析）が多く、信頼境界が複雑（= 02_web/authn・04_saasへ直結）
- 優先度の付け方（時間制約がある場合の順序）
  - `.map` の到達性と情報量（`sourcesContent` の有無）で優先度を付ける
- 代表的な攻め筋（この観測から自然に繋がるもの）
  - 攻め筋1：`.map` は無い/取れない（到達不可） → JS本体（04_js）とHTTP挙動（03_http）から入口を掘るのが主戦場
  - 攻め筋2：`.map` はあるが本文なし（sourcesのみ） → 構造ヒント（パス/モジュール名）から入口候補を作り、到達性は別観測で固める
  - 攻め筋3：`.map` に本文あり → 抽出した endpoint を 02_web/01_web_00_recon に渡し、入口→境界→検証方針を更新する
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）
  - `.map` が本番では無効（404/403/非公開） → 環境差（stg/dev だけ `.map` が公開、prodは非公開）を疑う

## 次に試すこと（仮説A/Bの分岐と検証）
> ここが最重要。条件が違うと次の手が変わる形で書く。

- 仮説A：`.map` なし/到達不可
  - 次の検証：
    - JS本体から endpoint 文字列（`/api` 等）を最小抽出し、03_http で到達性・挙動を確認
    - 12_waf_cdn のクラスターと突合し、外周制御で “.mapだけ抑止” なのか “ホスト全体” なのかを状態化
  - 期待する観測（成功/失敗時に何が見えるか）：
    - `.map` 非公開という運用状態を確定し、以降は通常のJS観測へ戻せる
- 仮説B：`.map` あり、本文なし
  - 次の検証：
    - `sources` のパス構造から “機能境界” を推定（例：`admin/`, `auth/`, `billing/`）し、代表入口の優先度を付ける
    - 02_web/01_web_00_recon に「候補機能（どの境界を先に見るか）」として渡す
  - 期待する観測：
    - ソース本文がなくても、入口の優先度が上がる（探索の無駄が減る）
- 仮説C：`.map` に本文あり
  - 次の検証：
    - endpoint候補を “重要度（auth/admin/api/webhook）×到達性（見える/見えない）” で整列し、代表点から 02_web（authn/authz/api/config）へ接続
    - キーらしき露出がある場合は、06_config_02（Secrets）へ “露出経路” として渡し、最小限の有効性確認（権限境界を壊さない範囲）に限定する
  - 期待する観測：
    - 「公開物→攻撃面抽出→検証計画」まで一貫して回せる

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/01_local/01_attack-box_作業端末設計.md`（結果の保存・差分管理）
    - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`（現状確認の最小証跡）
- 取得する証跡（目的ベースで最小限）
  - `sourcemap_inventory.csv`：host, js_url, map_url, status, has_sourcesContent, notes
  - `sourcemap_attack_surface.csv`：host, source_hint, extracted_type(endpoint/third-party/key_hint), value, confidence(高/中/低)
  - `map_accessibility`（到達性）と `extracted_attack_surface`（endpoint/依存/境界情報）の2つに分けて残す
- 観測の取り方（どの視点で差分を見るか）
  - `.map` 入口があるか（sourceMappingURL）、`.map` が取れるか（到達性：status）、抽出可能な情報量があるか（sourcesContent）
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/sourcemap_14 2>/dev/null
    cd ~/keda_evidence/sourcemap_14
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象JSは **許可されたスコープ** のみ（契約範囲/社内許可範囲/自前検証環境）
      - 観測は **代表点の抽出** のみ（抽出したキーや内部URLを根拠に、許可なく範囲拡大しない）
      - 観測視点（端末/経路/ネットワーク）を記録
  - 相関キー（最低限）を作る（後で必ず効く）
    - Host：対象ホスト
    - JSUrl：JSファイルのURL
    - MapUrl：sourceMappingURL（相対URL/絶対URL/Data URL）
    - Status：`.map` 到達性（200/30x/403/404）
    - HasSourcesContent：`sourcesContent` の有無（yes/no）
    - ExtractedType：抽出タイプ（endpoint/third-party/key_hint）
    - Value：抽出値（endpoint/依存/境界情報）
    - Confidence：確度（高/中/低）
    - Timestamp：観測日時（JSTで秒まで）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は“手段”であり“結論”ではない。必ず「何を観測している例か」を添える。

~~~~
# 目的：JSから sourceMappingURL を見つけ、.map の到達性と情報量（sourcesContent有無）を確定する

## 出力例（最小）
- `sources` に内部パスが残る

# (1) JS末尾の sourceMappingURL を確認（代表のbundle/chunkに対して）

## 出力例（最小）
- `sources` に内部パスが残る
curl -sk https://example.com/assets/app.js | tail -n 5

# (2) .map を取得してステータス確認（403/404/200）

## 出力例（最小）
- `sources` に内部パスが残る
curl -sk -D - -o /dev/null https://example.com/assets/app.js.map | sed -n '1,20p'

# (3) .map の情報量確認（sourcesContent があるか）

## 出力例（最小）
- `sources` に内部パスが残る
curl -sk https://example.com/assets/app.js.map \
  | python -c "import sys,json; d=json.load(sys.stdin); print('sources=',len(d.get('sources',[])),'sourcesContent=',len(d.get('sourcesContent',[]) or []))"

# (4) endpoint候補の粗抽出（本文がある場合のみ。過剰にやらない）

## 出力例（最小）
- `sources` に内部パスが残る
curl -sk https://example.com/assets/app.js.map \
  | python -c "import sys,json,re; d=json.load(sys.stdin); sc=d.get('sourcesContent') or []; s='\n'.join([x for x in sc if isinstance(x,str)]); \
print('\n'.join(sorted(set(re.findall(r'https?://[^\\s\"\\']+|/api/[^\\s\"\\']+|/graphql\\b|/admin\\b', s))) ) )" \
  | head -n 50
~~~~

- この例で観測していること：
  - `.map` 入口があるか（sourceMappingURL）
  - `.map` が取れるか（到達性：status）
  - 抽出可能な情報量があるか（sourcesContent）
  - “攻撃面として意味のあるものだけ”を少数抽出する（次工程へ渡す）
- 出力のどこを見るか（注目点）：
  - JS末尾：`//# sourceMappingURL=...` の有無と形（相対URL/絶対URL/Data URL）
  - ステータス：200/30x/403/404
  - `sourcesContent` の有無：情報量の判定
  - endpoint候補：`/api`, `/graphql`, `/admin`, `/internal`, `/v1`, `/oauth`, `/callback`, `/webhook` 等
- この例が使えないケース（前提が崩れるケース）：
  - `.map` が本番では無効（404/403/非公開） → 環境差（stg/dev だけ `.map` が公開、prodは非公開）を疑う

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：V1（アーキテクチャ/信頼境界）・V14（構成/デバッグ）を支える前提として、公開静的資産（JS/.map）から漏れる「内部境界情報（URL/ホスト/環境差分）」を観測し、露出の有無を状態化する
  - 該当要件（可能ならID）：外部依存・設定・通信・境界（ASM/OSINTは“前提の崩れ”を潰す役）
  - このファイルの内容が「満たす/破れる」ポイント：
    - 破れる：公開静的資産（JS/.map）から漏れる「内部境界情報（URL/ホスト/環境差分）」を観測できないと、以降の検証で“対象外”や“前提違い”を起こし、検証精度が落ちる。
    - 満たす：外部依存・設定・通信・境界（ASM/OSINTは“前提の崩れ”を潰す役）を把握し、以降の検証（認証/認可/API/運用）を「前提崩れ」なく進める土台を作る。
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：Information Gathering（公開情報・アプリ構造の把握）/ Configuration and Deployment（不要なデバッグ資産の露出）として、`sourceMappingURL` と `.map` 到達性を入口の一部として扱う
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：WSTG各観点へ入る前の“入口確定”として接続
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Intelligence Gathering → Threat Modeling → Vulnerability Analysis に接続。目的は“ソースを見る”ことではなく、**攻撃面（endpoint）と運用境界（env差分/内部ホスト）**を抽出し、次の検証（Web/API/Config）へ優先度付きで渡すこと。
  - 前後フェーズとの繋がり（1行）：入口（endpoint）と境界（外部依存/環境差）を先に固めることで、以降の検証（Authn/Authz/API/Config）の優先度が決まる
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Reconnaissance（公開資産からの情報収集）
  - 攻撃者の目的（この技術が支える意図）：攻撃者が探索コストを下げるのと同じ論理で、診断側は「最短で重要入口へ到達する」ために使う。Reconnaissance / Discovery として、攻め筋の確率を上げるための境界特定・依存推定。
  - 参照：https://attack.mitre.org/tactics/TA0043/

## 参考（必要最小限）
- OWASP ASVS
  https://github.com/OWASP/ASVS
- OWASP WSTG
  https://owasp.org/www-project-web-security-testing-guide/
- PTES
  https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：Reconnaissance
  https://attack.mitre.org/tactics/TA0043/
- Source Map Revision 3 Proposal
  https://sourcemaps.info/spec.html

## リポジトリ内リンク（最大3つまで）
- 関連 topics：
  - `01_topics/01_asm-osint/04_js_フロント由来の攻撃面抽出.md`
  - `01_topics/01_asm-osint/03_http_観測（ヘッダ/挙動）と意味.md`
- 関連 labs / cases：
  - `04_labs/01_local/01_attack-box_作業端末設計.md`

---

## 深掘りリンク（最大8）
- `01_topics/01_asm-osint/12_waf-cdn_挙動観測（ブロック_チャレンジ_例外）.md`
- `01_topics/01_asm-osint/15_api_spec_公開（OpenAPI_GraphQLスキーマ）から面抽出.md`
- `01_topics/02_web/01_web_00_recon_入口・境界・攻め筋の確定.md`
- `01_topics/02_web/06_config_02_Secrets管理と漏えい経路（JS_ログ_設定_クラウド）.md`
- `02_playbooks/01_asm_passive-recon_資産境界→優先度付け.md`
- `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- `01_topics/01_asm-osint/16_github_code-search_漏えい（key_token_endpoint）.md`
- `01_topics/04_saas/00_index.md`

---
