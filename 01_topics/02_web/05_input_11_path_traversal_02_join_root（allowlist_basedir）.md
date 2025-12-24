## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS
  - この技術で満たす/破れる点：
    - ユーザ入力からファイルパスを組み立てる場合、「許可された親ディレクトリ配下に必ず収まる」ことを保証する必要がある（CWE-22の要件を満たす/破るの核）。
    - “文字列の禁止（../を弾く）”だけでは不十分。**joinの仕様（絶対パスでbaseが捨てられる等）**、**canonicalize（実体解決）前後の差**、**シンボリックリンクやTOCTOU**で崩れる。
    - 最も強い対策は「入力でパスを受け取らず、ID→サーバ側引き当て」に寄せる（FS境界を入力境界から切り離す）。
  - 支える前提：
    - 05_inputは「入力が別の実行系に渡る境界」。本ファイルは FS境界のうち **join（連結）/root（基準）** の設計が、どの条件で崩れるかを“差分”で確定する。
- WSTG
  - 該当テスト観点：
    - Directory Traversal / File Include（WSTG-ATHZ-01）に対し、単なる `../` ではなく **base dir拘束（baseir）と join仕様** を中心に検証設計する。
  - どの観測・検証に対応するか：
    - 入力点（path/query/body/header）ごとの「join→canonicalize→base判定」の挙動差を取り、どこで境界が崩れたかを再現性で立証する。
- PTES
  - 位置づけ：
    - Vulnerability Analysis：実装方式（ID参照/allowlist/相対パス許容/canonicalize有無）をモデル化し、回避可能性を差分で確定。
    - Exploitation：目的は“手数”ではなく、**どの条件でbase dir拘束が外れるか**、**シンボリックリンク/TOCTOUで実体が外に出るか**を証拠化する。
    - Reporting：再発しない提案（ID参照化、正規化後実体判定、open時のNOFOLLOW、ログ）をセットで提示。
- MITRE ATT&CK
  - 初期侵入：T1190（公開アプリの脆弱性悪用）
  - 目的への接続：
    - Credential Access / Collection：設定・秘密情報の読取、ソース読取による二次脆弱性発見
    - Execution / Persistence：書込みや実行連鎖（アップロード/テンプレ/設定の置換）に接続し得る（ただし成立には“書込み先”と“実行経路”が必要で、切り分けが重要）

---

## タイトル
path_traversal：join/root（allowlist・base dir拘束）が壊れる条件を差分で確定する

---

## 目的（このファイルで到達する状態）
- 「../の亜種」ではなく、**join（連結）と base directory（基準）拘束**の設計が崩れる条件を、
  - 実装仕様（言語/フレームワーク/OS）
  - 観測差分（入力A/Bで結果がどう変わるか）
  の2軸で説明できる。
- 報告として次を言い切れる：
  - “どの判定が弱いか”（絶対パスでbaseが捨てられる／文字列prefix判定のみ／canonicalize不足／symlink/TOCTOU未対策）
  - “どう直すべきか”（ID参照化が最優先、次に canonicalize後の実体拘束、最後にopen時の安全化）

---

## 前提：このファイルが扱う境界
- `05_input_11_path_traversal_01_normalization`：dotdot/encoding（表現揺れ）中心
- 本ファイル：**join（base + user）** と **root（基準ディレクトリ）** の扱い中心
- ここで押さえると、次が“設計として”整理できる：
  - `03_archive（zip_slip）`：展開時のjoin/root
  - `12_file_upload_02_storage_path`：保存先のjoin/root
  - `03_authz_08_file_access`：ファイル参照の認可モデル（IDOR/署名URL）

---

## 境界モデル（入力→join→実体解決→判定→open）
### 1) 典型データフロー（読取系）
- 入力：`file=<ユーザ入力>`
- 変換：
  1) allowlist（許可ファイル名の集合） or 形式制約（英数のみ等）
  2) join：`candidate = join(base_dir, user_value)`
  3) canonicalize：`resolved = realpath(candidate)`（実体解決）
  4) base dir拘束：`resolved` が `base_dir` 配下か判定
  5) open/read
- 失敗しやすい点：2) join と 4) 判定の“仕様誤解”／3) の欠落／5) のTOCTOU

### 2) 典型データフロー（書込系：危険度が上がる）
- 入力：`filename=<ユーザ入力>`
- 変換：
  1) join（保存先ディレクトリ + ファイル名）
  2) canonicalize/拘束
  3) open/write（この“open”が安全でないと symlink/TOCTOU で外へ書ける）
- 失敗しやすい点：open時の “リンク追従” と “作成/上書きの挙動”

---

## 何が起きると「join/rootが崩れた」と言えるか（結果の意味＝状態）
- 状態J0：入力がファイル参照に影響する（入口の存在）
- 状態J1：joinの仕様により **base_dirが無効化**される（例：ユーザ入力が絶対パス扱い）
- 状態J2：canonicalize不足で **“見かけ上base配下”が通る**（`../`や区切り揺れの残存）
- 状態J3：base判定が文字列前方一致などで **セグメント境界を誤る**（`/app/dataX` が `/app/data` と判定される等）
- 状態J4：symlink/TOCTOUで **判定後に実体が外へすり替わる**（“チェックは正しいのにopenが危ない”）
- 状態J5：OS差で **想定外のroot/デバイス/名前解決**が混入する（Windowsのドライブ/UNC/特殊パス等）

本ファイルのゴールは、J1〜J4のどれで壊れているかを“差分で確定”すること。

---

## joinが壊れる典型（最重要）：絶対パスが base を捨てる
多くの言語/標準APIで「join(base, user)」は、`user` が “絶対パス” と認識されると base を捨てる。

- 意味：
  - 開発者は「base_dirに必ず入る」と誤解しやすい。
  - 攻撃者は「絶対パス扱いになる入力表現」を探すだけで J1 に到達する可能性がある。
- 診断の観測方針：
  - “同じ入力点”で、相対入力（安全な想定）と絶対入力（危険）を比較し、
  - join結果（またはレスポンス）に差分が出るかを見る。

~~~~
# 擬似コード（危ない設計の典型）
base = "/var/app/files"
user = request.query["file"]

candidate = join(base, user)   # ← user が絶対扱いだと base が捨てられる実装が多い
data = read(candidate)
~~~~

---

## allowlist（許可集合）の設計：強いが、設計を誤ると無意味になる
### 1) allowlistの正しい使い方（強い）
- “ファイル名（キー）”を allowlist にする：
  - 例：`invoice.pdf` / `terms.html` / `logo.png` のように **列挙可能な固定集合**
- ユーザ入力は「キー」だけにし、実体パスはサーバ側で引き当てる（ID参照の軽量版）。

~~~~
# 強い：入力をキーとして扱い、サーバ側で実体へ引き当て
allowed = {
  "terms": "/var/app/static/terms.html",
  "privacy": "/var/app/static/privacy.html",
}
key = request.query["doc"]
path = allowed.get(key) or deny
return read(path)
~~~~

### 2) allowlistが弱くなるパターン（境界が曖昧になる）
- allowlistが「ドメイン/ディレクトリ単位」「前方一致」「拡張子だけ」になっている
  - allowlistというより“ゆるい制約”になり、join/root/正規化の問題が復活する
- 診断の意味：
  - allowlistの粒度が粗いほど「正規化のズレ」や「symlink/TOCTOU」など別の破綻経路が残りやすい

---

## base directory拘束：文字列ではなく “実体” で拘束する
PortSwigger等の一般的な防御指針は「検証後に base dir に結合し、FS APIで canonicalize、canonicalize後のパスが base dir から始まることを確認」と整理される。 :contentReference[oaicite:4]{index=4}  
ただし実務で重要なのは「startsWithの意味」を **“パスセグメント境界”** として定義すること。

### 1) よくある誤り：文字列前方一致だけ
- `resolved.startswith(base_dir)` のような文字列判定は、セグメント境界を誤る可能性がある。
- 期待する性質：
  - `resolved` が `base_dir` **配下の子孫**である（同一prefixの別ディレクトリではない）

### 2) 推奨：パスAPIで “親子関係” を判定
- OS/言語のPath APIで「baseからの相対化が可能か」「..が含まれないか」で判断する、等。
- 重要なのは **canonicalize後** に判定すること（canonicalize前は “見かけ” が残る）。

~~~~
# 擬似コード：base拘束の考え方（実体解決→親子関係）
base = realpath("/var/app/files")
candidate = join(base, user)

resolved = realpath(candidate)          # 実体解決（リンクや .. を潰した“結果”）
if not is_descendant(resolved, base):   # パスAPIで親子関係（セグメント境界）を判定
  deny
return read(resolved)
~~~~

---

## symlink / hardlink / TOCTOU：チェックが正しくても open が負ける
### 1) 何が問題か（状態J4）
- 多くの実装は、
  - (a) `resolved = realpath(candidate)` で確認して
  - (b) その後に `open(candidate)` してしまう
- ここに時間差（TOCTOU）があると、**確認した“実体”と、openされる“実体”がズレる**可能性が出る。

### 2) 実務での切り分け（読取と書込で重みが違う）
- 読取：
  - 影響は情報漏えいが中心。ただしソース/設定が読めると二次被害が跳ねる。
- 書込：
  - “どこへ書けるか”次第で永続化・改ざん・実行連鎖まであり得る。
  - 診断では「書込先の制御」「リンク追従」「作成/上書き」までを条件として分解する。

### 3) 防御の設計論（ここまで書けると報告が強い）
- 可能なら「ディレクトリFD基準で open（openat系）」「NOFOLLOW（リンク追従禁止）」「原子的作成（O_EXCL等）」の思想へ寄せる。
- Webアプリで完璧にやるのが難しい場合でも、最低限：
  - 書込ディレクトリを“ユーザが変更できない場所”に固定
  - 既存ファイルの上書きを禁止
  - 生成したファイル名をサーバ側で決定（ユーザ入力を採用しない）
  を組み合わせると、J4の成立条件を大幅に減らせる。

---

## OS差・実装差（join/rootの解釈が増えるほど事故る）
### 1) Windows系（代表的に問題が起こりやすい理由）
- ドライブレター、UNC、特殊プレフィックスなどにより「絶対扱い」の判定が複雑。
- アプリが想定していない“root相当”の表現が混入しやすい（J1/J5へ寄る）。

### 2) Linux/コンテナ系
- コンテナ内のbase dirに閉じていても、ボリュームマウント等で“見える範囲”が広がることがある。
- “OSの制約があるから安全”は設計根拠にならない（環境差で壊れる）。

---

## 観測ポイント（ここを取れないと“薄い指摘”になる）
- 入口：
  - どの入力がファイル参照に使われるか（パラメータ/ヘッダ/ボディ/パス）
- join段：
  - join前の base_dir
  - join後の candidate（“baseが捨てられていないか”が見える）
- 実体解決段：
  - resolved（realpath/canonical path）
  - 解決時にリンク追従したか（可能ならフラグ）
- 判定段：
  - allowlist hit/miss
  - base拘束の判定結果とルールID
- open段：
  - 読取/書込の別
  - 作成/上書き/追記の別
  - 例外（どの段で落ちたか：ログでわかるように）

~~~~
# ログ最小フィールド（再現性の核）
request_id
input_channel
raw_input
base_dir
candidate_path
resolved_path
decision (allow|deny)
rule_id
operation (read|write|list)
~~~~

---

## 検証設計（意味→判断→次の一手）
### ステップ1：入口の確定
- “画像表示/添付DL/テンプレ切替/言語ファイル/ログ閲覧/エクスポート取得” を優先的に探索
- 入口が複数ある場合、同じ防御実装が使い回されているか（共通関数）を意識して観測を揃える

### ステップ2：join仕様（J1）の有無を差分で推定
- 同一入力点で、相対想定と絶対想定を比較し、挙動が変わるかを見る
- ここで差分が出るなら「baseが捨てられる/解釈が変わる」可能性が高い

### ステップ3：canonicalize→base拘束（J2/J3）の強度を判定
- 正規化の結果（resolved）を見せられるなら最短
- 見せられないなら、レスポンス差分（同一ファイル名なのに到達先が変わる）を慎重に積み上げる
  - 例：200/403/404の変化は“ヒント”だが、断言せずログや挙動で裏取りする

### ステップ4：TOCTOU/リンク追従（J4）の有無を切り分け（可能な範囲で）
- 診断範囲が許すなら、書込系（アップロード/エクスポート生成/ログ出力）を優先
- 目的は“危険な手順”ではなく、
  - open時にリンク追従するか
  - 上書きが可能か
  - ファイル名をユーザが指定できるか
  の3条件を満たすかを切り分けること

---

## 攻撃者視点での利用（現実寄り：意思決定に落とす）
- J1（base捨て）：
  - 最短で境界を越える可能性があるため優先度が高い
- J3（文字列prefix判定）：
  - 実装が“頑張っているように見える”ため見落とされやすいが、差分が出ると修正は設計変更級（報告価値が高い）
- J4（TOCTOU/リンク追従）：
  - 条件が揃うと影響が跳ねる。診断では「書込があるか」を起点に、成立条件を分解して評価する

---

## 次に試すこと（仮説A/Bで分岐）
### 仮説A：ID参照/強いallowlistで、join/rootの問題が土俵にない
- 観測：
  - 入力がキーで、実体パスが固定（またはサーバ側で引き当て）
  - 絶対/相対など表現揺れで挙動が変わらない
- 次の一手：
  - `03_authz_08_file_access`（ファイル参照の権限境界：IDOR/署名URL）へ接続
  - `12_file_upload_02_storage_path`（保存先やACLの設計）へ接続

### 仮説B：相対パスを受け、join/rootが実装依存で崩れる余地がある
- 観測：
  - 入力表現の差で結果が変わる（特に“絶対扱い”でbaseが捨てられる）
  - canonicalize/判定/例外の差分が再現する
- 次の一手：
  - `01_normalization` と合わせて「どの層がdecode/normalize/joinを担うか」を一本化して再現
  - 書込が絡むなら `12_file_upload_03_execution_chain`（実行連鎖）へ、読取のみでも `06_config_02_Secrets管理` へ接続して二次影響を評価

---

## 手を動かす検証（Labs：手順ではなく設計）
- 追加候補Lab（例）
  - `04_labs/02_web/05_input/11_path_traversal_join_root/`
- 設計要件（最低限）
  - 実装パターンを3種用意し、差分で“どこが強い/弱いか”を観測できること：
    1) 危ない：joinのみ（base拘束なし）
    2) 中間：canonicalize後に文字列prefix判定
    3) 強い：ID参照 or allowlist引き当て＋安全なopen設計
  - ログで `base_dir / candidate / resolved / decision / rule_id` が取れること
  - 読取と書込（可能なら）を分けて影響の差を観測できること

---

## 深掘りリンク（最大8）
- `05_input_11_path_traversal_01_normalization（dotdot_encoding）.md`
- `05_input_11_path_traversal_03_archive（zip_slip）.md`
- `05_input_12_file_upload_02_storage_path（bucket_acl_traversal）.md`
- `05_input_12_file_upload_03_execution_chain（preview_processor_rce）.md`
- `03_authz_08_file_access_ダウンロード認可（署名URL）.md`
- `06_config_02_Secrets管理と漏えい経路（JS_ログ_設定_クラウド）.md`
- `02_playbooks/02_web_recon_入口→境界→検証方針.md`
- `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
