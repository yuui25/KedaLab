## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - この技術で満たす/破れる点：リソース単位のアクセス制御（ファイル＝高頻度に抜ける）、マルチテナント分離（03）、最小権限（閲覧/ダウンロード/共有/公開）、機密データ保護（PII/契約/請求/添付）、署名URLの安全な運用（期限・スコープ・権限）、監査（誰が何をダウンロードしたか）
  - 支える前提：本文やAPIは守れていても、添付/ダウンロード経路だけが“例外パス”になりやすい。IDOR/越境のImpact増幅器。
- WSTG：
  - 該当テスト観点：Authorization Testing（IDOR/BOLA、File Authorization）、API Testing（署名URL/リダイレクト/メタデータ）、Business Logic（共有/公開リンク）、Session Management（Cookie付与有無、リファラ漏洩）
  - どの観測に対応するか：ファイルアクセスを「参照（メタ）→取得（実体）→派生（共有/変換/サムネ）」に分解し、どこで認可が抜けるかを差分で確定する
- PTES：
  - 該当フェーズ：Information Gathering（ファイル入口の列挙：UI/API/GraphQL/メール）、Vulnerability Analysis（署名URL・ストレージキー・アプリ経由DLの境界）、Exploitation（最小差分検証：2ユーザ/2テナント）
  - 前後フェーズとの繋がり（1行）：02/03で見つけた参照キー集合と越境兆候を、08で「file_id/キー/署名URL」に写像し、漏れが“実体データ”に波及しているかを確定して06/09/10へ接続する
- MITRE ATT&CK：
  - 戦術：Collection / Exfiltration / Impact
  - 目的：添付・契約書・請求書・本人確認書類など高価値ファイルを取得し、情報漏洩・恐喝・不正操作の材料にする（※手順ではなく成立条件の判断）

## タイトル
file_access_ダウンロード認可（署名URL）

## 目的（この技術で到達する状態）
- ファイルアクセスを「本文（リソース）とは別の認可境界」として扱い、(1)ファイルの識別子（file_id/key）、(2)取得経路（アプリ経由/署名URL/公開リンク）、(3)派生物（サムネ/変換/エクスポート）、(4)有効期限と共有、(5)監査、の観点で短時間にリスクを確定できる
- 署名URL（S3/GCS/Azure等）を“便利機能”ではなく、権限のスコープ設計（誰がいつ何にアクセスできるか）として評価できる
- 02（IDOR）/03（越境）/07（GraphQL）/06（重要操作）と結合したときに、漏洩の最大Impact（実体データ）を見積もれる
- エンジニアへ「アプリ経由DLに寄せるべきか」「署名URLの条件」「キー設計（tenant/owner）」を具体化できる

## 前提（対象・範囲・想定）
- 対象：Web/API/GraphQL/モバイルでのファイルアップロード・添付・ダウンロード
- ファイル種別（代表）
  - ユーザ提供：本人確認書類、プロフィール画像、添付資料
  - システム生成：請求書PDF、レポートCSV、エクスポート、ログ
  - 派生物：サムネ、変換後ファイル（pdf化、zip化）
- 取得経路（混在前提）
  - アプリ経由DL：`GET /files/{id}/download` のようにサーバが認可してストリームする
  - 署名URL：アプリが短命URLを発行し、ストレージへ直接GETする
  - 公開/共有リンク：share_id 等で誰でもアクセス可能（仕様境界）
  - CDN経由：キャッシュが絡む
- 検証の安全な範囲（実務的）
  - 2ユーザ×2テナントで、同一file_id/同一署名URLの到達可能性を差分で観測
  - 実体取得は必要最小限に留め、メタ情報（サイズ/Content-Type/ETag）で証跡化できるなら優先する
  - 共有リンクは仕様の範囲を確認し、意図しない公開（期限なし/権限なし/対象束縛なし）を狙って成立条件を確定する

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) ファイルアクセスは2段階（メタ→実体）で崩れる
- 段階A：メタデータ参照
  - file_id、owner、tenant、path、mime、size、hash、storage_key、signed_url（発行）
- 段階B：実体取得
  - 実際のバイト列（PDF/画像/ZIP等）
- 典型の破綻
  - メタは守るが実体が抜ける（直リンク/ストレージキー直叩き）
  - 実体は短命URLで守るが、発行APIが抜ける（誰でも署名URLを発行できる）
  - 派生物（サムネ/変換）が別経路で抜ける（最頻出）

観測の結論：
- 08は「発行（issuer）」「取得（getter）」「派生（derivative）」の3点を必ず見る。

### 2) 取得経路別の境界：どこで認可が強制されるか（PEP）
#### 2.1 アプリ経由DL（アプリが最終PEP）
- 強み：アクセス時に毎回認可できる（user/tenant/role/state）
- 典型の穴
  - `file_id` のIDOR（02）：他人のfile_idで取れる
  - “本文の認可”と“ファイルの認可”が別実装で、ファイル側が抜ける（例外パス）
  - Range/partial content や変換エンドポイント（/preview, /thumbnail）が別実装で抜ける

#### 2.2 署名URL（ストレージがPEP、アプリは発行者）
- 強み：スケール/性能
- 典型の穴（実務で最重要）
  - 署名URLの有効期限が長すぎる（漏洩耐性が弱い）
  - 署名対象が広すぎる（バケット/プレフィックス単位で署名）
  - 署名URLが第三者へ漏れる導線（Referer、ログ、メール、フロントJS、エラー）
  - 発行APIが弱い（誰でも/過剰に発行できる、tenant束縛が弱い：03）
  - 署名URLが“再利用可能”で、権限変更後もアクセスできる（失効モデル不在）
- 観測で確定したい点
  - 署名URLのTTL（Expires）と対象（キーの粒度）
  - URLが誰に露出するか（フロントに出る＝漏洩耐性が必要）
  - 失効の考え方（原則：短命＋再発行）

#### 2.3 公開/共有リンク（仕様境界：意図された越境）
- 重要：ここは「存在自体が脆弱性」ではない。成立条件が安全かを評価する。
- 安全な共有の条件（観測軸）
  - 対象束縛：share_idが特定ファイル/特定リソースに束縛される
  - 期限：短命または回収可能
  - 権限：閲覧のみ等、操作権限が付与されない
  - 露出面：インデックス/推測/列挙に弱くない（短く連番だと危険）
  - 監査：誰がアクセスしたかを追える（可能なら）
- 典型の穴
  - share_idが推測可能（連番/短い）
  - 期限なし、回収不可
  - share_idで“別ファイル”に差し替え可能（パラメータ改変）
  - 共有リンクから派生（サムネ/zip）が無制限

### 3) ファイル識別子の種類と危険度（02と接続）
- file_id（DBのID、UUID等）
  - IDORで突破される（アプリ経由DLで多い）
- storage_key / path（S3 key等）
  - 推測・列挙・漏洩で突破される（署名URLや直リンクで多い）
- 派生キー（thumbnail_key、preview_key）
  - 本体よりガードが弱くなりがち（実務で高確率）
- 観測で確定したい点
  - どの識別子がクライアントへ露出しているか（URL、JSON、HTML、GraphQL）
  - 露出している識別子が“そのまま取得入口”になっていないか

### 4) テナント境界（03）とファイルの束縛：最頻出の越境原因
ファイルは「所属」の束縛が弱いと越境しやすい。
- 束縛の形（良い方向）
  - file → owning_resource（invoice/project/user等） → tenant
  - file_id単体で認可せず、必ず owning_resource の認可を通す
- 危険な兆候
  - file_idだけで取得でき、tenant/ownerのチェックが薄い
  - 署名URL発行が tenant を参照せず、keyだけで発行する
  - DataLoader/キャッシュが tenant をキーに持たない（07/03の再燃）

### 5) 重要操作（06）としてのファイル：アップロード/差し替え/削除/共有は高Impact
- ファイルの重要操作
  - アップロード（不正ファイル/内容差し替え）
  - 置換（既存ファイルの差し替え）
  - 削除（証拠隠滅/業務妨害）
  - 共有設定変更（非公開→共有）
  - 署名URL発行（大量発行、長寿命）
- 観測で確定したい点
  - これらが通常更新で成立していないか（05）
  - step-upや承認が必要な設計か（06/16）
  - 監査が残るか（誰が共有をオンにしたか）

### 6) 監査・検知（誰が何を取ったか）：ファイルは“取得”のログが重要
- 監査の最小フィールド（推奨）
  - actor_id、tenant_id、file_id / storage_key、owning_resource、action（download/share/issue_signed_url）、ip/user-agent、request_id、result（allow/deny）
- 観測で確定したい点
  - 署名URL経由（ストレージ直GET）でも監査が追えるか（難しい場合が多い）
  - 追えないなら、署名URL発行ログ（誰がいつ発行したか）を強化すべき（設計提案）

### 7) file_access_key_boundary（正規化キー：後続へ渡す）
- 推奨キー：file_access_key_boundary
  - file_access_key_boundary = <delivery_mode>(app_proxy|signed_url|public_share|mixed|unknown) + <identifier_exposure>(file_id|storage_key|both|unknown) + <tenant_binding>(strong|weak|unknown) + <derivative_paths>(present/none/unknown) + <signed_url_ttl>(short|long|unknown) + <revocation_model>(short_ttl_only|explicit_revoke|none|unknown) + <audit_strength>(strong|partial|weak|unknown) + <confidence>
- 記録の最小フィールド（推奨）
  - endpoints（meta/getter/issuer/thumbnail/preview/export）
  - identifier（file_id / key / share_id）
  - 認可の根拠（owner/tenant/role/state）
  - 署名URLのTTL・対象（キー粒度）
  - 派生物の入口と認可
  - evidence（HAR、URL断片、レスポンスヘッダ、監査ログ断片）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える（確定できる）：
  - ファイル取得がどの経路（アプリ/署名URL/共有）で成立し、どこが最終PEPか
  - file_id/key/share_id の露出と、それが取得入口に直結しているか
  - tenant束縛が強いか弱いか（越境リスク）
  - 派生物（thumbnail/preview/export）が例外パスになっていないか
  - 署名URLのTTL・スコープ・失効モデルの強度
- 推定（根拠付きで言える）：
  - 署名URLが長寿命で露出面が広い場合、漏洩時のImpactが大きい（防御は短命化/再発行/束縛強化）
  - 派生物が別経路にある場合、本体より抜けやすい（重点検証）
- 言えない（この段階では断定しない）：
  - 最大漏洩量（大量取得は許可範囲次第）。ただし入口と束縛からリスクは示せる。

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- 優先度（P0/P1/P2）
  - P0：
    - 他人/他テナントのファイル実体が取得できる（IDOR/越境確定）
    - 署名URL発行APIが弱く、他人のkey/file_idで署名を発行できる
    - 派生物（thumbnail/preview/export）で認可が抜けて実体が取れる
    - share_idが推測可能/期限なし/回収不可で、機密が恒久的に露出する
  - P1：
    - TTLが長い、対象が広い、発行ログが無い（漏洩時の検知・封じが難しい）
    - キャッシュ/loader混入の兆候（ユーザ切替で不自然）
  - P2：
    - 設計は堅牢だが運用が難しく、サポート代行（11）や例外運用で穴が開きやすい
- “成立条件”としての整理（技術者が直すべき対象）
  - fileは必ず owning_resource の認可（tenant/owner/role/state）に束縛し、file_id単体で許可しない
  - 署名URLは短命・最小スコープ（キー粒度）で発行し、発行ログを残す
  - 派生物（preview/thumbnail/export）の入口も同じ認可を強制し、例外パスを作らない
  - 共有リンクは対象束縛・期限・回収・監査をセットで設計する

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：アプリ経由DLでIDOR（file_id差替）できる
  - 次の検証（最小差分）：
    - 2ユーザ/2テナントで、同一file_idの参照・取得が拒否されるか差分観測
  - 判断：
    - 取得成立：P0（02/03の実体版）
- 仮説B：署名URL発行が弱い（issuerの認可欠落）
  - 次の検証：
    - 署名URL発行APIの入力（file_id/key/owning_resource）と、tenant束縛の兆候を観測
  - 判断：
    - 他人の対象で発行可能：P0
- 仮説C：派生物が例外パス
  - 次の検証：
    - preview/thumbnail/export の入口を列挙し、同一fileで認可が一致するか観測
  - 判断：
    - 派生だけ取れる：P0〜P1（機密度次第）
- 仮説D：共有リンクの安全条件が満たされていない
  - 次の検証：
    - share_id の推測耐性、期限、回収、対象束縛の兆候を観測
  - 判断：
    - 恒久公開/推測可能：P0

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/` ）：
  - `04_labs/02_web/03_authz/08_file_download_authorization_signed_url/`
    - 構成案：
      - 2テナント×複数ロール
      - 取得経路：app_proxy / signed_url / public_share を切替
      - 署名URL：TTL短/長、スコープ狭/広、発行ログ有/無 を切替
      - 派生物：thumbnail/preview/export を用意し、認可の一致/不一致を再現
      - 監査：download/issue_signed_url/share_change のイベントログを必ず出す
- 取得する証跡（深掘り向け：HTTP＋周辺ログ）
  - HTTP：issuer（署名発行）→getter（取得）→派生（preview/thumbnail）
  - ヘッダ：Content-Type/Disposition、Cache-Control、ETag（実体取得の証跡）
  - URL断片：Expires/Signature（TTLの根拠）、key（スコープの根拠）※機密扱い
  - ログ：発行者、対象、TTL、拒否理由、tenant確定値
  - 監査：誰が何をDL/共有したか（調査可能性）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
# アプリ経由DL（擬似）
GET /files/999/download

# 署名URL発行（擬似）
POST /files/999/signed-url
{ "purpose": "download" }

# 派生（擬似）
GET /files/999/thumbnail
GET /files/999/preview

# 観測すること（擬似）
- file_id/key/share_id のどれが露出し、取得入口に直結しているか
- issuer（署名発行）が owning_resource/tenant に束縛されているか
- 派生入口でも同じ認可が強制されているか
~~~~
- この例で観測していること：
  - “発行と取得”の両方で認可が成立していること、派生物が例外になっていないこと
- 出力のどこを見るか（注目点）：
  - delivery_mode、identifier_exposure、tenant_binding、derivative_paths、signed_url_ttl、audit_strength
- この例が使えないケース（前提が崩れるケース）：
  - すべてのファイルがCDNの公開配信（→公開/共有の仕様境界として、対象束縛・期限・回収・監査に評価軸を寄せる）

## 参考（必要最小限）
- OWASP ASVS（Authorization、データ保護、監査）
- OWASP WSTG（Authorization Testing、File Download Authorization）
- PTES（入口列挙→差分観測→成立条件確定）
- MITRE ATT&CK（Collection/Exfiltration：ファイルは高価値）

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/03_authz_02_idor_典型パターン（一覧_検索_参照キー）.md`
- `01_topics/02_web/03_authz_03_multi-tenant_分離（org_id_tenant_id）.md`
- `01_topics/02_web/03_authz_07_graphql_authz（field_level）.md`

## 次（09以降）に進む前に確認したいこと（必要なら回答）
- 09 admin_console：
  - ファイル管理（検索/一括DL/削除/復元）が管理UIにある場合、例外パスとして非常に危険なので強めに書く
- 10 object_state：
  - 状態により公開/共有/ダウンロード可否が変わるドメイン（請求書、申請書、下書き資料）が強い場合、state×fileの結合を主軸にする
