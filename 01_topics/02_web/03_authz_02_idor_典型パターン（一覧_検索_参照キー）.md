# 03_authz_02_idor_典型パターン（一覧_検索_参照キー）
IDOR/BOLA を「参照キーの差し替え」ではなく、(1)キーの露出面、(2)スコープ（認可）の表現、(3)入口（一覧/検索/参照）の不一致、の3点で分解し、短時間で"当たり筋"を特定する

---

## 目的（この技術で到達する状態）
- IDOR/BOLA を「参照キーの差し替え」ではなく、(1)キーの露出面、(2)スコープ（認可）の表現、(3)入口（一覧/検索/参照）の不一致、の3点で分解し、短時間で“当たり筋”を特定できる
- API/UI/モバイル/GraphQL/ファイルDLなど入口が増えても、同じ観測モデルで再現性を保って評価できる
- 修正指示を「どこにチェックが無いか」だけで終わらせず、設計として「スコープをどこで強制するか（handler/service/query/policy）」まで落とし込める
- 後続（03 multi-tenant、04 RBAC/ABAC、05 mass-assignment、06 重要操作、07 GraphQL、08 ファイル、09 運用UI、10 状態遷移）へ、IDOR観測から“分岐すべき論点”を確定した形で渡せる

## 前提（対象・範囲・想定）
- 対象：Webアプリ/API（REST中心を基準に、SPA/MVC/モバイルも同型で扱う）
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - 想定するID種別（混在前提）：連番ID / UUID / スラッグ / 複合キー（org_id + id 等）
  - 想定する入口：一覧（list）、検索（search）、詳細参照（get）、更新/削除（update/delete）、派生（エクスポート、関連一覧、添付DL、管理画面）
- できること/やらないこと（安全に検証する範囲）：
  - できること：テストアカウント（少なくとも2ユーザ、可能なら2テナント）で、差分観測を最小回数で行う、"大量列挙"より、一覧→参照→派生の経路で「スコープ破綻の有無」を確定する
  - やらないこと：影響のある更新系は、可能なら"確認画面まで"や"dry-run相当"で止め、証跡（HTTP/ログ）を優先する
- 依存する前提知識（必要最小限）：
  - `01_topics/02_web/03_authz_00_認可（IDOR BOLA BFLA）境界モデル化.md`
  - `01_topics/02_web/03_authz_01_境界モデル（オブジェクト_ロール_テナント）.md`
  - `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
  - `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：
    - IDOR/BOLA を「参照キーの差し替え」ではなく、(1)キーの露出面、(2)スコープ（認可）の表現、(3)入口（一覧/検索/参照）の不一致、の3点で分解し、短時間で"当たり筋"を特定する
    - API/UI/モバイル/GraphQL/ファイルDLなど入口が増えても、同じ観測モデルで再現性を保って評価する
    - 修正指示を「どこにチェックが無いか」だけで終わらせず、設計として「スコープをどこで強制するか（handler/service/query/policy）」まで落とし込む
  - 扱わない（別ユニットへ接続）：
    - 大量列挙の可否や最大漏洩量（実行は許可・影響評価が必要） → 別ユニット

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) IDORを「参照キー露出 → スコープ強制 → 入口の不一致」で分解する
- 参照キー露出：
  - どこに object_id が出るか（URL path/query、JSON body、hidden field、GraphQL variables、署名URL、HTML内data属性）
- スコープ強制：
  - サーバ側が「その object_id が現在ユーザのスコープ内か」を必ず判定しているか
- 入口の不一致：
  - 一覧/検索はスコープされているが、詳細参照が未スコープ
  - 逆に詳細は守るが、検索APIが他人のレコードを返す（漏洩）
  - UIは守るがAPI直叩きが守らない（例外パス）

この3点を揃えると、IDの種類（連番/UUID）に依存せず評価できる。

### 2) 入口別の典型（一覧 / 検索 / 参照）
#### 2.1 一覧（list）起点：ページング・並び替え・関連一覧がスコープ破綻を起こす
- 観測対象
  - GET /items?page=..&size=..、GET /orgs/{org_id}/items、GET /users/{id}/items
  - sort/filter の追加（?sort=created_at&status=...）
  - 関連一覧（/projects/{project_id}/members 等）
- 重要な見方
  - 一覧が返す “参照キー集合” は、後続の詳細参照/更新の入力になる（攻撃面の生成器）
  - 一覧がスコープされていない場合、IDORはほぼ確定（詳細が守れていても情報漏洩）
- 証跡として残す
  - レスポンス内の参照キーの形（id/uuid/slug/複合）
  - tenant/org を示すフィールド（org_id/tenant_id）が返るか（03へ接続）
  - “自分のものだけ”という保証がどこにも無い（スコープフィールド不在、件数が不自然等）

#### 2.2 検索（search）起点：検索条件がスコープを越える（漏洩）/逆に詳細だけ穴がある
- 観測対象
  - GET /items/search?q=...、POST /search { filters... }、/reports?user_id=...
  - “便利系”の検索（メール/電話/請求番号/伝票番号などユニークキー）
- 典型の破綻
  - 検索は全体インデックスを叩き、結果のスコープフィルタが抜ける
  - “管理者用検索”が一般ユーザへ露出している（09へ接続）
  - 検索結果に詳細URL/参照キーが混ざり、参照の入口を増殖させる
- 証跡として残す
  - 存在判定（ヒット/非ヒット）で情報が漏れるか（列挙・個人情報）
  - 検索結果に「権限判定理由」が無い（単に返っている/返っていないだけ）

#### 2.3 参照（get）起点：詳細/ダウンロード/関連APIが “IDを渡すだけ” で成立する
- 観測対象
  - GET /items/{id}、GET /items?id=...、GET /download/{file_id}
  - 関連参照（/items/{id}/comments、/invoices/{id}/pdf 等）
- 典型の破綻
  - object_id が有効なら誰でも見える（認可が “存在チェック” に退化）
  - “自分のものか”チェックがUI側にしか無い（APIで抜ける）
  - 参照キーが複合なのに、片方だけで参照できる（org_id無視）＝03の入口
- 証跡として残す
  - 403/404の使い分け（存在隠蔽か、認可失敗か）※ここは“是非”ではなく観測
  - エラー時に object_id の存在や属性が漏れるか（エラーメッセージ/差分）

### 3) 参照キーの型別に「列挙可能性」と「スコープ破綻点」を整理する
- 連番ID
  - リスク：推測が容易（ただしIDが推測可能でも、スコープ強制が正しければ問題にならない）
  - 観測：一覧/検索がID生成器として機能していないか（自分の一覧から他人の推測へ飛べるか）
- UUID
  - リスク：推測は困難だが、漏洩（ログ/URL共有/Referer/分析タグ）で即IDORになる
  - 観測：URL露出/共有導線/リダイレクト/ファイルDL（08）で漏れないか
- スラッグ
  - リスク：人間可読で推測されやすい、公開ページとの境界が曖昧になりやすい
  - 観測：公開/非公開の境界（stateやvisibility）と認可が一致しているか（10へ接続）
- 複合キー（org_id + id 等）
  - リスク：片方を無視して参照できると越境が成立（03へ直結）
  - 観測：org_idを変えても通る/無視される兆候、サーバ側でorg_idを信用している兆候

### 4) “スコープ”の実装位置を推定し、直すべき箇所を特定する
観測結果から、スコープがどこで崩れているかを推定する（修正提案の質が上がる）。
- handler/controller で都度チェック型
  - 典型：一覧はチェックあるが、派生APIで抜ける（実装漏れ）
- service/policy で統一型（04へ接続）
  - 典型：ポリシーがあるのに呼ばれていない/例外パスがある（管理API、バッチ）
- DBクエリで自然スコープ型
  - 典型：検索だけ別テーブル/別インデックスでWHEREが抜ける
- 混在
  - 典型：機能追加のたびに入口が増え、どこかで必ず漏れる（このファイルの主戦場）

### 5) TLPT/バグバウンティで効く「派生入口」（IDORの増幅器）
- エクスポート/レポート（CSV/PDF）：
  - 一覧/検索の結果がそのまま大量データになる（Impact増幅）
- ファイル/添付ダウンロード（08）：
  - file_id がオブジェクト分離を破る（“本文は守るが添付が抜ける”が多い）
- 管理コンソール（09）：
  - “内部向け検索/参照” が露出すると一気に横展開する
- 状態遷移（10）：
  - draft/approved 等で「見える範囲」が変わるのに、APIが追随しない

### 6) idor_key_surface（正規化キー：後続へ渡す）
- 推奨キー：idor_key_surface
  - idor_key_surface = <object_class>(user|order|invoice|project|file|report|unknown) + <entrypoint>(list|search|get|download|admin|mixed) + <key_type>(seq|uuid|slug|composite|unknown) + <scope_axis>(user_id|org_id|tenant_id|role|state|unknown) + <enforcement_layer>(handler|service_policy|db_query|unknown) + <evidence_level>(http_only|http+logs|unknown) + <confidence>
- 記録の最小フィールド（推奨）
  - endpoint（method+path）
  - object_class / key_type / scope_axis
  - “期待されるスコープ” と “観測された挙動”
  - 入口（list/search/get/派生）
  - evidence（HAR、レスポンス差分、UI表示差、ログ断片）
  - action_priority（P0/P1/P2）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が"確定"できるか：
  - どの入口（一覧/検索/参照/派生）で、参照キーが露出し、スコープが強制されている/いないか
  - 同一テナント内の越権か、テナント越境の兆候か（org_id/tenant_idの扱いから03へ分岐）
  - IDの種類が何であっても、"スコープ強制が一貫しているか" を評価できる
- 何が"推定"できるか（推定の根拠/前提）：
  - 一覧/検索のどちらかが漏れている場合、詳細/更新/ダウンロードにも同系統の漏れが存在する可能性が高い（入口増殖の性質）
  - enforcement_layer が混在しているほど、派生APIで抜けやすい（修正はpolicy統一 or queryスコープの強制へ寄せるべき）
- 何は"言えない"か（不足情報・観測限界）：
  - 大量列挙の可否や最大漏洩量（実行は許可・影響評価が必要）
  - "本当に他人データか" の断定（テストデータ/ダミーの可能性があるため、証跡と運用確認が必要）
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：一覧/検索が漏れている（参照キー集合が得られる） → 一覧/検索の代表エンドポイントを固定し、2ユーザ/2テナントで結果差分が出るかを見る
  - パターンB：一覧/検索は守るが、参照（get/download/派生）で抜ける → "自分が見えるID" と "他ユーザが見えるID" の2点で、参照の挙動差（403/404/成功）を確認する
  - パターンC：同一テナント内は守るが、テナント越境が怪しい（org_id/tenant_idが鍵） → 複合キーの片方が無視されていないか（org_idを変えても同じ結果等）を観測
  - パターンD：権限（role）や状態（state）で見える範囲が変わるのに、APIが追随していない → role差分（一般/管理）と state差分（draft/approved 等）で、一覧/検索/参照の整合を観測

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- 優先度（P0/P1/P2）
  - P0：
    - 参照（get/download）でスコープ強制が無い（他人の資産が取得できる）
    - 検索/一覧がスコープされず、参照キー集合が得られる（横展開が容易）
    - テナント越境の兆候（org_id/tenant_id無視、複合キー片落ち）がある（03へ直行）
    - 重要操作（更新/削除/承認/送金等）に同型のIDORが波及している（06へ直行）
  - P1：
    - スコープはあるが入口差分（UIは守るがAPIが抜ける、特定エンドポイントだけ例外）
    - 監査ログが無く、侵害時の追跡が困難（運用リスク）
  - P2：
    - 仕様として公開/共有が存在し、境界は意図通りだが説明/設計が曖昧（誤設定で事故りやすい）
- “成立条件”としての整理（技術者が直すべき対象）
  - すべての入口（list/search/get/派生）で、同一のスコープ判定を必ず通す
  - スコープは「要求パラメータを信用しない」（org_id等はサーバ側で確定）方向に寄せる
  - policy統一（04）または queryスコープ強制（WHERE tenant_id=...）へ寄せ、実装漏れを構造的に減らす
  - 監査ログに object_id / actor / tenant / action を残し、IDORを検知・追跡可能にする

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：一覧/検索が漏れている（参照キー集合が得られる）
  - 次の検証（最小差分）：
    - 一覧/検索の代表エンドポイントを固定し、2ユーザ/2テナントで結果差分が出るかを見る
    - 結果に含まれる参照キーを “詳細参照・派生（関連/添付/エクスポート）” の入力にして、入口不一致が無いかを確認
  - 判断：
    - スコープ差分が無い/越境兆候：P0（03へ分岐）
- 仮説B：一覧/検索は守るが、参照（get/download/派生）で抜ける
  - 次の検証（最小差分）：
    - “自分が見えるID” と “他ユーザが見えるID” の2点で、参照の挙動差（403/404/成功）を確認する
    - 添付/エクスポート/関連参照など派生入口を優先（Impactが大きい）
  - 判断：
    - 参照で抜け：P0（08/06へ分岐）
- 仮説C：同一テナント内は守るが、テナント越境が怪しい（org_id/tenant_idが鍵）
  - 次の検証（最小差分）：
    - 複合キーの片方が無視されていないか（org_idを変えても同じ結果等）を観測
    - テナント切替機構（URL/ヘッダ/サブドメイン）がある場合、その境界でスコープが追随しているかを見る
  - 判断：
    - 越境兆候：03（multi-tenant分離）を先に深掘る
- 仮説D：権限（role）や状態（state）で見える範囲が変わるのに、APIが追随していない
  - 次の検証：
    - role差分（一般/管理）と state差分（draft/approved 等）で、一覧/検索/参照の整合を観測
  - 判断：
    - roleが効いている：04/09へ分岐
    - stateが効いている：10へ分岐

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/` ）：
  - `04_labs/02_web/03_authz/02_idor_patterns_list_search_key/`
    - 構成案：
      - 2ユーザ×2テナントのデータを持つ簡易アプリ（list/search/get/download/export）
      - enforcement_layer を切替（handler漏れ / policy統一 / dbスコープ）できる
      - 例外パス（downloadだけ未スコープ、searchだけ未スコープ）を意図的に作り、観測→原因切り分けを再現
      - 監査ログ：access_granted/denied（actor, object, tenant, endpoint, reason）を必ず出す
- 取得する証跡（深掘り向け：HTTP＋周辺ログ）
  - HTTP：HAR（一覧/検索/参照/派生の一連）
  - 差分観測：ユーザAとユーザBのレスポンス差（件数/フィールド/参照キー）
  - ログ：認可理由（deny理由）、tenant確定値、policy判定点（取れる場合）
  - 監査：誰がどのobjectにアクセスしたか（後追い可能性）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
# 典型の入口（擬似）
GET  /items?page=1&size=20               # 一覧（参照キー集合の生成器）
GET  /items/search?q=invoice             # 検索（全体インデックスで漏れやすい）
GET  /items/123                          # 参照（IDORの本丸）
GET  /items/123/attachments/999/download # 派生（本文は守るが添付が抜けやすい）

# 観測すること（擬似）
- list/search/get で “同じスコープ” が一貫して適用されているか
- key_type（seq/uuid/slug/composite）と scope_axis（user/org/tenant/state）が何か
- 派生入口（download/export/admin）だけ例外になっていないか
~~~~
- この例で観測していること：
  - 「参照キーがある」ことではなく、「参照キーを入力にしてもスコープが崩れない」こと
- 出力のどこを見るか（注目点）：
  - レスポンス差分（件数/フィールド/エラー）、参照キーの露出場所、org_id/tenant_idの扱い、派生入口の存在
- この例が使えないケース（前提が崩れるケース）：
  - 共有リンク/公開ページが混在し、意図的に他者閲覧が成立する（この場合は境界条件とポリシー設計を明示し、10/09へ接続する）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：オブジェクト参照の認可（BOLA/IDOR）、リソース単位のアクセス制御、一覧/検索/参照の一貫したスコープ制御、マルチテナント分離（03へ接続）、監査ログ（誰が何にアクセスしたか）と不正検知
  - 該当要件（可能ならID）：V4（Access Control）
  - このファイルの内容が「満たす/破れる」ポイント：
    - 満たす：認証（AuthN）が強くても、参照キー（id/uuid/slug）を差し替えるだけで他人の資産に到達できると被害が直結することを観測で確定し、以後の検証観点を外さないための基盤。
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：Authorization Testing（IDOR/BOLA、Insecure Direct Object References）、Business Logic（一覧/検索の漏洩）、API Testing（BOLA）
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：一覧→詳細、検索→詳細、参照キー差分、ページネーション/フィルタ、GraphQL/ファイルDL等の派生入口を、HTTP差分で体系的に観測する
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Information Gathering（参照キー/境界の抽出）、Vulnerability Analysis（スコープ破綻の特定）、Exploitation（許可範囲での最小差分検証）
  - 前後フェーズとの繋がり（1行）：AuthNで得た"セッション/ユーザ差分"を入力に、AuthZの「スコープ（誰の何に届くか）」を一覧/検索/参照の3経路で確定し、03〜10の各論点へ分岐する。
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Discovery / Collection / Privilege Escalation / Impact
  - 攻撃者の目的（この技術が支える意図）：参照キーを手掛かりに他ユーザ/他テナントのデータへ到達し、情報収集・権限拡大・操作（削除/承認/送金等）につなげる（※手順ではなく成立条件の判断）。
  - 参照：https://attack.mitre.org/tactics/TA0007/（Discovery）、https://attack.mitre.org/tactics/TA0009/（Collection）、https://attack.mitre.org/tactics/TA0004/（Privilege Escalation）、https://attack.mitre.org/tactics/TA0040/（Impact）

## 参考（必要最小限）
- OWASP Application Security Verification Standard: https://github.com/OWASP/ASVS
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- PTES (Penetration Testing Execution Standard): https://pentest-standard.readthedocs.io/
- MITRE ATT&CK: https://attack.mitre.org/

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`01_topics/02_web/03_authz_00_認可（IDOR BOLA BFLA）境界モデル化.md`
- 関連 topics：`01_topics/02_web/03_authz_03_multi-tenant_分離（org_id_tenant_id）.md`
- 関連 topics：`01_topics/02_web/03_authz_06_privileged_action_重要操作（承認_送金_権限）.md`

---

## 深掘りリンク（最大8）
- `01_topics/02_web/03_authz_00_認可（IDOR BOLA BFLA）境界モデル化.md`
- `01_topics/02_web/03_authz_01_境界モデル（オブジェクト_ロール_テナント）.md`
- `01_topics/02_web/03_authz_03_multi-tenant_分離（org_id_tenant_id）.md`
- `01_topics/02_web/03_authz_04_rbac_abac_判定点（policy_engine）.md`
- `01_topics/02_web/03_authz_06_privileged_action_重要操作（承認_送金_権限）.md`
- `01_topics/02_web/03_authz_07_graphql_authz（field_level）.md`
- `01_topics/02_web/03_authz_08_file_access_ダウンロード認可（署名URL）.md`
- `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`

---
