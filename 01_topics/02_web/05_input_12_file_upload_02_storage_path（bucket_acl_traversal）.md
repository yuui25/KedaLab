## タイトル
file_upload_保存先・キー設計（bucket/ACL/到達性/パス）：アップロード後に「誰がどこから読める/書ける」を壊さない境界モデル

## 目的（この技術で到達する状態）
- アップロードの“本当の事故”が、検査（validation）よりも **保存先（storage）と到達性（delivery）** で起きる理由を説明できる。
- 次を **差分（成立根拠）** で切り分け、診断→修正提案を一気通貫で作れる。
  - (A) 保存先がローカルFSか、オブジェクトストレージ（S3/GCS/Azure Blob等）か
  - (B) URLが「直リンク（公開）」か「署名URL（期限付き）」か「アプリ経由（認可ゲート）」か
  - (C) オブジェクトキー/パスが **ユーザ入力とどう結合** されているか（prefix/tenant/uuid）
  - (D) 読み取り・上書き・列挙の権限境界（IDOR/BOLA/マルチテナント）を壊す条件
- 攻撃者視点では「RCE狙い」固定ではなく、まず **“置ける/読める/上書ける/共有できる”** のどれが成立するかを、最短で確定できる。

## 前提（対象・範囲・想定）
- 対象：
  - Webアプリのアップロード機能（プロフィール画像、添付、インポート、サポート提出、テンプレ導入、SaaS連携の添付など）
  - 保存先：ローカルFS、NFS、S3/GCS/Azure Blob、CDN、バックアップ領域
- 想定する環境：
  - CDN/WAF配下、オブジェクトストレージ直配信（署名URL）またはアプリ経由配信（download API）
  - マルチテナント（tenant_id/org_id）を想定
- できること/やらないこと（安全に検証する範囲）：
  - “権限境界・到達性・上書き可否”の確認を中心にする（大規模な列挙や負荷試験は別計画）
  - 本ファイルでは「後段処理器（変換/プレビュー等）」のRCE連鎖は主対象にしない（`execution_chain`で扱う）
- 依存する前提知識（必要最小限）：
  - HTTP（URL/ヘッダ/キャッシュ）、認可（IDOR/BOLA）、パス正規化、クラウドストレージのアクセス制御概念（IAM/ACL/署名URL）

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
- 観測対象（プロトコル/データ構造/やり取りの単位）：
  - アップロード要求：multipart、直PUT（presigned URL）、upload-init → complete の2段階API
  - レスポンス：返却URL、object_key（またはfile_id）、CDNドメイン、Content-Type/Disposition
  - 保存メタ：filename（表示名）と storage key（実体）の分離有無
- 境界の観点：
  - 資産境界（管理主体・委託先・対象範囲の線引き）：
    - アプリ管理のDB（file_id, owner_id, tenant_id）と、ストレージ管理のオブジェクト（bucket/key）が一致しているか
    - CDN/ストレージが第三者（クラウド）なら、その公開設定が資産境界を決める
  - 信頼境界（外部連携・第三者・越境ポイント）：
    - 署名URLでクライアントが直接ストレージへPUTする場合、アプリは「保存処理」を信頼境界の外へ委譲している
    - 共有リンク（share link）や外部添付（SaaS/メール）へ出ていく導線
  - 権限境界（権限の切替/伝播/委任）：
    - file_id → bucket/key の解決点が **認可判定点**（ここが弱いとIDOR/BOLA）
    - 署名URLの発行点（誰が何のkeyに対して発行できるか）が **書込み権限の委任点**
- 重要なフィールド/差分/状態（「ここが変わると意味が変わる」点）：
  - `file_id` と `object_key` の関係（ランダム/規則的/入力結合）
  - keyの構造：`tenant_id/` prefix があるか、ユーザ入力がprefixやディレクトリ相当を作れるか
  - “公開”の有無：直リンクで誰でもGETできるか、アプリ経由で認可が走るか
  - overwrite：同じkeyで再アップロードできるか（仕様・設計・権限制御の差）
  - レスポンスヘッダ：`Content-Disposition`、`X-Content-Type-Options: nosniff`、`Cache-Control`（配信設計の差）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が“確定”できるか：
  - 保存方式（FS直書き / オブジェクトストレージ / ハイブリッド）
  - 配信方式（公開直リンク / 署名URL / アプリ経由）
  - 認可の場所（download APIで判定 or ストレージ公開設定で実質無効化）
  - キー設計（予測可能性・テナント分離・入力結合の有無）
- 何が“推定”できるか（推定の根拠/前提）：
  - 返却URLが `*.s3.*` や `storage.googleapis.com` 等ならクラウドストレージの可能性が高い
  - CDNドメインでも、オリジンがストレージであることが多い（ただし確定にはレスポンス差分が必要）
- 何は“言えない”か（不足情報・観測限界）：
  - バケットポリシー/IAM条件（prefix制約等）は外部からは観測できない場合がある
  - “列挙可否”は、テストスコープや合法性の制約を受けやすい（無差別列挙は避ける）
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：アプリ経由DL（file_id）で認可を必ず通す（境界が明確）
  - パターンB：署名URLで期限付きアクセス（境界＝署名発行の権限 + 期限 + keyスコープ）
  - パターンC：公開直リンク（境界が“公開設定”に吸収され、認可が実質無効化しやすい）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す“狙い目”：
  - 公開直リンク：**認可不在の可能性** が高く、BOLA/IDORより早く情報漏えいに到達し得る
  - 署名URL：発行APIが弱いと、**本来許されない key へのPUT/GET を委任** される（権限境界の欠陥）
  - 規則的キー（`tenant/user/filename` 等）：推測や衝突（overwrite）で影響が拡大しやすい
  - 同一keyでの置換が可能：プロフィール画像等で **他人の見た目・内容差し替え** や、ワークフロー攪乱に繋がる
- 優先度の付け方（時間制約がある場合の順序）：
  1) “誰でも読めるか”（公開/認可ゲートの有無）
  2) “他人のものを読めるか”（IDOR/BOLA：file_id → owner/tenant）
  3) “上書きできるか”（同一key衝突、署名URLのPUT権限、更新APIの認可）
  4) “共有リンク/外部連携で越境するか”（想定外共有・長期有効）
  5) “キャッシュ/Content-Typeで受動的被害が出るか”（配信設計の穴）
- 代表的な攻め筋（この観測から自然に繋がるもの）：
  - 攻め筋1：download API のIDOR/BOLA（file_id列挙/推測ではなく、業務UIから得た参照差分で確認）
  - 攻め筋2：署名URL発行のスコープ不備（prefix制約/対象key固定/メソッド制限/期限が適切か）
  - 攻め筋3：キー衝突・上書き（“同名アップロード”が誰の資産を置換するか）
  - 攻め筋4：公開設定（bucket/containerの匿名アクセス、ACL/IAMの意図せぬ公開）
- 「見える/見えない」による戦略変更：
  - CDN配下でURLが難読化されていても、最終的に “公開直リンク” なら認可は実質効かない
  - SSO前提でも、ストレージが公開ならSSOは境界にならない（境界がズレている）

## 次に試すこと（仮説A/Bの分岐と検証）
> ここが最重要。条件が違うと次の手が変わる形で書く。

- 仮説A：保存先はオブジェクトストレージで、クライアント直PUT（署名URL）を採用している
  - 次の検証：
    - 署名URLの発行APIで「何がスコープになっているか」を差分で確認する
      - keyがサーバ固定（uuid）か、入力（filename/prefix/tenant）と結合しているか
      - method/Content-Type/Content-Length などに制約があるか（“何でもPUT”になっていないか）
      - 有効期限が短いか、失効（revocation）や再発行時の扱いがあるか
    - overwriteの扱いを確認する（同一keyに対する再PUTがどう扱われるか）
  - 期待する観測（成功/失敗時に何が見えるか）：
    - サーバ固定keyなら、入力を変えても storage key が変わらない（予測可能性・衝突が低い）
    - 入力結合があるなら、prefixや名前の差分で “別の保存位置” に流れる兆候が出る

- 仮説B：保存先はローカルFS（またはNFS）で、URLはアプリ/静的配信が直接参照している
  - 次の検証：
    - 「保存パスの決定」にユーザ入力が混ざる点（folder、カテゴリ、filename）を特定し、
      正規化・allowlist・basename化が働いているかを差分で確認する（本質は `join→realpath→base配下判定`）
    - 公開到達性：アップロード領域が webroot 配下 / 静的配信配下かを確認する
  - 期待する観測：
    - 保存先が webroot 配下なら、配信ヘッダやURLパターンが静的資産に近づく
    - 正規化が弱いと、保存先のディレクトリ構造が入力差分で揺れる

- 仮説C：マルチテナントで、object_key が tenant_id prefix に依存している
  - 次の検証：
    - tenant切替時に同一 file_id が参照されないこと（DB側）と、prefixが一致すること（ストレージ側）を確認
    - 共有リンク機能があるなら、tenant境界を越える“例外パス”が仕様として存在するかを確認
  - 期待する観測：
    - 正常なら、tenantが違うと key解決も拒否され、署名URLも発行されない

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/` ）：
  - `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`（HTTP差分観測の設計）
  - （追加候補）`04_labs/02_web/05_input/12_file_upload_storage_path_bucket_acl/`（新規）
- 参照ファイル：
  - 本topics：`05_input_12_file_upload_01_validation（mime_magic_polyglot）.md`
  - 本topics：`05_input_12_file_upload_03_execution_chain（preview_processor_rce）.md`
- 取得する証跡（目的ベースで最小限）：
  - アプリHTTPログ（upload-init / presign / complete / download）
  - 返却URL（署名URL含む）、レスポンスヘッダ、エラー差分
  - クラウド監査ログ（可能なら）：S3 access log / CloudTrail、GCS audit log、Azure storage log
- 観測の取り方（どの視点で差分を見るか）：
  - 入力（filename/metadata）を少し変えたときに、storage key / URL / 権限判定がどう変わるか
  - “同一ユーザ”と“別ユーザ/別テナント”で、同じ file_id / key がどう扱われるか

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
# 例：安全寄りのキー設計（擬似コード）
# - 表示名(display_name)と保存キー(storage_key)を分離
# - storage_keyはサーバ生成のuuidを基本にし、tenantでprefix固定
storage_key = f"{tenant_id}/{uuidv4()}"

# 例：ダウンロードはアプリ経由（認可ゲート）
GET /api/files/{file_id}/download
-> サーバで owner/tenant を確認
-> 必要なら短期の署名URLを発行して302/JSONで返す（直リンク固定にしない）
~~~~
- この例で観測していること：
  - “ユーザ入力が保存先を決めない”構造になっているか（境界固定）
  - downloadが必ず認可判定点を通るか
- 出力のどこを見るか（注目点）：
  - storage_keyの予測可能性（規則的か、uuidか）
  - 署名URLの期限、対象keyの固定性、発行APIの認可
- この例が使えないケース（前提が崩れるケース）：
  - 業務要件で「同名ファイルの上書き」や「同一URLの恒久共有」が必要な場合（別途、共有境界設計が必要）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：
    - Access Control（アップロード資産の読み書き）
    - File Upload/Files（アップロードの安全な扱い全般）
  - 該当要件（可能ならID）：
    - （環境によりASVS版が揺れるため、ここでは“要件の意図”で固定）
  - このファイルの内容が「満たす/破れる」ポイント：
    - “保存先が公開設定に吸収されて認可が無効化”していないか
    - “署名URL発行”が書込み権限の委任点になっていることを認識し、スコープを固定できているか
    - “キー設計（tenant/uuid）”でIDOR/衝突/上書きを構造的に潰せているか
- WSTG：
  - 該当カテゴリ/テスト観点：
    - Cloud Storage の誤設定テスト（ストレージ直リンク/公開設定/アクセスパターン）
    - File Permission（Upload files/directory の権限と到達性）
  - 該当が薄い場合：この技術が支える前提：
    - “ファイルが置ける場所”＝資産境界の確定（以降の攻め筋の優先度を決める）
- PTES：
  - 該当フェーズ：
    - Vulnerability Analysis / Exploitation（境界モデル化→差分で成立根拠確定）
  - 前後フェーズとの繋がり（1行）：
    - validationで弾けなかった形式が「どこに置かれ、誰が到達できるか」を確定して初めて、実害（漏えい/改ざん/連鎖）が評価できる。
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：
    - Initial Access（T1190）
    - Collection / Impact（公開・共有・改ざんが成立する場合）
  - 攻撃者の目的（この技術が支える意図）：
    - “置ける/読める/上書ける/共有できる”の成立条件を見つけ、情報漏えいや改ざん、後段処理器への到達に繋げる。

## 参考（必要最小限）
- OWASP File Upload Cheat Sheet（認可・安全な保存・多層防御の基本）
- OWASP WSTG（Cloud Storage / File Permission の観測観点）
- AWS S3（Object Ownership/ACL、presigned URLの仕様）
- Google Cloud Storage（Uniform bucket-level access / Public access prevention）
- Azure Blob Storage（匿名アクセス無効化、セキュリティ推奨）

## リポジトリ内リンク（最大3つまで）
- 関連 topics：
  - `05_input_12_file_upload_01_validation（mime_magic_polyglot）.md`
  - `05_input_12_file_upload_03_execution_chain（preview_processor_rce）.md`
- 関連 playbooks：
  - `02_playbooks/02_web_recon_入口→境界→検証方針.md`
- 関連 labs / cases：
  - `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
