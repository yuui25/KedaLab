## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS
  - この技術で満たす/破れる点：
    - アーカイブ展開は「ファイルアップロード」ではなく **任意パスへのファイル作成（＝FS書込み）** に等しい。したがって、入力検査（拡張子/MIME）ではなく、**展開先境界（base dir）・正規化・リンク追従・権限分離・リソース制限**が要件の中心。
    - “展開結果を後段で処理（import/preview/build）する”場合、展開＝実行連鎖の入口になり、RCE/情報漏えい/破壊に繋がる。
- WSTG
  - 該当テスト観点：
    - アップロード機能の「想定外形式」「悪性コンテンツ」を、受理可否だけでなく **受理後の処理（展開、変換、検査）** まで含めて確認する。
- PTES
  - 位置づけ：
    - 情報収集：アーカイブが使われる機能（インポート、テーマ/テンプレ導入、ログ/証跡アップロード、バルク登録、エクスポート復元）を棚卸し。
    - 脆弱性分析：展開器（zip/tar/7z、OSコマンド、ライブラリ）と設定（リンク追従、overwrite、base dir判定、上限）をモデル化。
    - 侵害評価：Zip Slip/リンク系/爆弾の成立条件を“差分”で固め、実害（任意ファイル作成、設定改ざん、DoS、後段RCE）へ接続。
- MITRE ATT&CK
  - 初期侵入：T1190（公開アプリの脆弱性悪用：アップロード→展開）
  - 影響：DoS（リソース枯渇）、改ざん（任意ファイル作成/置換）
  - 実行/永続化（成立条件つき）：
    - 展開先が webroot / 実行パス / 設定パスに近い場合、後段の実行連鎖（スクリプト読込、テンプレ解釈、ジョブ設定）に接続し得る。

---

## タイトル
file_upload_アーカイブ処理（zip/tar/7z）：展開＝FS境界破り（Zip Slip/リンク/爆弾）を“成立根拠（差分）”で確定する

---

## 目的（このファイルで到達する状態）
- アーカイブ機能を見たときに、次を説明できる：
  1) 展開が走るトリガ（アップロード直後 / インポート実行時 / 管理者操作 / バッチ）
  2) 展開先（base dir）と、その外へ書ける条件（正規化、絶対パス、区切り、Unicode、リンク）
  3) overwrite（上書き）と権限（誰が何を壊せるか）
  4) リソース制限（zip bomb / tar bomb / 7z bomb）の有無
- “薄い”所見（拡張子だけ）で終わらず、**成立根拠（差分）→影響範囲→対策の設計条件**まで落とす。

---

## 扱う範囲（このファイルの守備範囲）
- 本ファイル：アーカイブの **展開処理（processor）** に集中
  - zip/tar/7z の差分
  - Zip Slip（パストラバーサル）、リンク追従、絶対パス、ドライブレター、UNC、区切り差分
  - “tar bomb / zip bomb / 7z bomb” のリソース枯渇
  - 外部コマンド展開（unzip/tar/7z）に伴うオプション注入/パス注入の設計論点
- 別ファイルへ接続：
  - `05_input_11_path_traversal_01_normalization（dotdot_encoding）.md`：正規化一般
  - `05_input_12_file_upload_02_storage_path（bucket_acl_traversal）.md`：保存/到達性/ACL
  - `05_input_12_file_upload_03_execution_chain（preview_processor_rce）.md`：展開後の処理連鎖（import/build/preview）

---

## 境界モデル（展開は“ファイル作成API”である）
### 1) データフロー（最小モデル）
Upload（アーカイブ受理）
→ 保存（原本 archive）
→ Processor（展開）
→ 出力（展開ディレクトリ）
→ 後段（import/preview/scan/serve）

ここでの本質：
- Processorは **ユーザ入力に基づいて大量のファイルを作成**する。
- したがって “パス決定” と “リンク/上書き/権限” が境界の中心。

### 2) 境界（3種類）
- 資産境界：
  - 原本（archive）と、展開物（extracted）と、派生物（変換結果）が別資産になる
- 信頼境界：
  - 展開器が外部コマンドか、ライブラリか
  - 展開器がシンボリックリンクやハードリンクを尊重するか
- 権限境界：
  - 展開器の実行ユーザ（webプロセス/ワーカー/隔離コンテナ）
  - 展開先の権限（書ける範囲、noexec、マウント境界、chroot）

---

## “成立根拠（差分）”で見る：展開系の主要破綻パターン
> 重要：トリック集ではなく、少数の差分で「どの防御層が欠けているか」を確定する。

### パターンA：Zip Slip（パストラバーサル）＝ base dir 逸脱
- 典型差分（概念）：
  - `../`（Unix）や `..\`（Windows）を含むエントリ名
  - 絶対パス（`/etc/...`、`C:\...`）や UNC（`\\server\share\...`）
  - 区切り・正規化差分（`..%2f` 等の“URL”ではなく、アーカイブ内のファイル名が持つバイト列としての差）
- 観測で確定したいこと：
  - 展開先が固定の base dir か
  - 正規化後に base dir 配下判定（realpath / canonicalize）をしているか
  - “書込み先パス”の生成に `join(base, entry_name)` のみを使っていないか

### パターンB：リンク（symlink/hardlink）追従＝ “外へ出る別ルート”
- Zip Slip対策があっても、リンク追従で破れることがある。
  - 展開物に symlink が含まれる
  - 後続の “コピー/移動/スキャン/変換” がリンクを辿る
- 観測で確定したいこと：
  - 展開時にリンクを作れるか（許容しているか）
  - 展開後の処理が `follow_symlinks` していないか（再帰処理が危険）
  - “リンクが指す先”をアクセスできる権限（root相当なら危険度が跳ね上がる）

### パターンC：overwrite（上書き）＝ “同名/既存ファイル置換”
- 典型：
  - 展開先に既存ファイルがある場合に上書きされる
  - “同名展開”が許容される（特にテンプレ導入や復元）
- 観測で確定したいこと：
  - overwriteを禁止しているか（存在時エラー/隔離）
  - “どのファイルが上書き対象になり得るか”（設定/テンプレ/ジョブ定義/authorized_keys 等）

### パターンD：アーカイブ爆弾（リソース枯渇）＝ DoS
- 典型：
  - 展開後サイズが巨大（圧縮率が極端）
  - ファイル数が極端に多い（inode枯渇）
  - ネストが深い（再帰処理・パス長制限）
  - 7z の辞書サイズ/メモリ要求が高い（メモリDoS）
- 観測で確定したいこと：
  - 展開前に “見積り” があるか（一覧取得、合計サイズ、ファイル数、深さ）
  - 展開処理のタイムアウト/クォータ/上限があるか
  - ワーカーキューが隔離されているか（共有だと影響が大きい）

---

## zip / tar / 7z：差分（成立根拠）を作る観点
### 1) zip の特徴（危険が出る場所）
- エントリ名の文字列として `../` が入る（Zip Slipの典型）
- Windows系区切り `\` を含むケース、`C:\` 等のドライブ表現
- ファイル数が多い・ネストが深い（DoS）
- “暗号化zip”や“Zip64”が処理系に差分を作る（パーサ/上限/例外）

### 2) tar の特徴（zipより“リンク・特殊ファイル”が絡みやすい）
- tarは “パス” だけでなく、次を含み得る：
  - symlink/hardlink
  - デバイスファイル（※環境により拒否されるべき）
  - パーミッション/所有者情報（復元系で危険）
- tar bomb（ディレクトリ階層なしで大量ファイルが直下に展開される）で“予想外の汚染”が起きやすい
- pax拡張等で長いパスを持ち得る（パス長・正規化の差分）

### 3) 7z の特徴（変換器・メモリDoS・多形式対応が攻撃面）
- 7zは多様な圧縮方式/辞書サイズを取り得るため、展開時のメモリ/CPU要求が跳ねやすい
- 多形式を扱う解凍器（7zバイナリ、ライブラリ）は攻撃面が広い
- “外部コマンド呼び出し”で展開している場合、オプション注入の余地が出る（後述）

---

## 観測ポイント（薄くしない：どこを見れば境界が確定するか）
### 1) ユーザ側（HTTP/挙動）で取れるもの
- アップロード直後に展開されるか（時間差、別API呼び出し）
- “展開結果”がどこで見えるか
  - インポート一覧、ファイルツリー表示、ログ、プレビュー生成
- エラーの性質
  - “invalid archive” なのか “path not allowed” なのか “too many files” なのか

### 2) サーバ側（可能なら依頼して取る：価値が高い）
- 展開ログ（推奨最小フィールド）
~~~~
request_id
user_id / role / tenant_id
archive_type (zip|tar|7z)
trigger (upload|import|admin|batch)
extract_base_dir
entry_count_estimated / entry_count_actual
total_uncompressed_bytes_estimated / actual
max_depth / max_path_len
policy_decision (allow|reject|quarantine)
reject_reason (rule_id)
symlink_detected (yes/no)
hardlink_detected (yes/no)
overwrite_attempt (yes/no)
timeout_ms / runtime_ms
exec_mode (library|cli)
cli_command (sanitized) / exit_code
~~~~
- 外部コマンドの場合は、コマンド文字列を“サニタイズ済み”で残す（注入の手掛かりになる）

---

## 攻撃者視点（現実寄り）：最短で狙う順序
> “Zip SlipでRCE”のように短絡しない。まず「書ける」「上書ける」「外へ出る」「止められる」を確定する。

1) 展開トリガを確定（アップロード直後か、インポート実行時か）
2) 展開先の性質を推定
   - webrootに近いか（公開配信の匂い）
   - 設定/テンプレ領域に近いか（後段実行連鎖の匂い）
3) base dir 逸脱の可否（Zip Slip差分）
4) リンク追従の可否（symlink/hardlink）
5) overwriteの可否（既存ファイル置換）
6) DoS（上限不備）の可否（実害は大きいが、検証は安全に“設計欠陥”として確定する）

---

## 外部コマンド展開（unzip/tar/7z）の“別の境界”：オプション注入/パス注入
アプリがライブラリではなくOSコマンドで展開している場合、次の境界が追加される。

- オプション注入（例：ファイル名が `-something` で始まる、引数解釈境界が壊れる）
- 引数組み立て（shell=True 等）によるメタ文字解釈
- 作業ディレクトリ/出力先指定の不備（`-o` や `--directory` 的な指定）

本ファイルの目的は“攻撃手順の提供”ではなく、診断として次を言い切れること：
- 「展開がCLIで行われ、引数境界が存在する（＝追加の入力→実行境界）」
- 「ファイル名/パスが引数に混ざる設計で、オプション注入耐性が不足している可能性」

---

## 防御（設計としての優先順位：processorを安全にする）
### 1) 展開は “隔離ワーカー + 最小権限 + no-network” を前提にする
- Webプロセス内で展開しない（攻撃面と権限が直結する）
- 展開ワーカーは：
  - 専用ユーザ
  - 最小権限（書込みは専用ディレクトリのみ）
  - 可能ならネットワーク遮断（SSRF/OOBを切る）

### 2) base dir 逸脱を“正規化後に”必ず判定
- 単に `startswith(base)` のような文字列比較は危険
- 実装の要点：
  - join → canonicalize（realpath相当）→ base配下判定
  - 例外：絶対パス/ドライブ/UNCは即拒否
  - パス区切り差分（`/` と `\`）やUnicode正規化差分に注意（言語/OS依存）

### 3) リンク（symlink/hardlink）と特殊ファイルの扱いを設計で禁止/隔離
- 展開前にアーカイブ内一覧を取り、リンク/特殊ファイルが含まれるなら拒否・隔離
- 展開後の後段処理でも “follow_symlinks禁止” を徹底（展開対策だけでは不足）

### 4) overwrite を禁止（または安全な名前付けへ）
- 展開先は “新規専用ディレクトリ（uuid）” を切り、既存と混ぜない
- 同名衝突は拒否し、後段のimportは “読み取りのみ” で処理する

### 5) リソース制限（DoSは再現より“設計で潰す”）
- 展開前に見積り（エントリ数、合計非圧縮サイズ、最大深さ、最大パス長）
- 制限：
  - max_entries
  - max_total_uncompressed_bytes
  - max_depth
  - max_path_len
  - max_runtime（タイムアウト）
  - per-user rate limit（インポート連打防止）
- 展開先のファイルシステム：
  - quota
  - noexec
  - nodev/nosuid（可能なら）
  - 使い捨て（ジョブ単位で消える）

---

## 次に試すこと（仮説A/B：検証の分岐）
### 仮説A：安全寄り（正規化＋base dir判定＋リンク禁止＋上限あり）
- 観測される兆候：
  - “path not allowed” “entry rejected” のようなルールベース拒否
  - サイズ/件数/時間で明確に拒否される
  - 展開物は常に uuid ディレクトリ配下
- 次の一手：
  - それでも “後段のimport処理” が危険になり得る（テンプレ/設定/コード解釈）。`execution_chain` へ接続し、展開物の利用箇所を評価する。

### 仮説B：危険寄り（単純展開、リンク追従、上限なし、overwriteあり）
- 観測される兆候：
  - エントリ名の差分で展開結果が揺れる（ディレクトリ構造がそのまま作られる）
  - 展開後に公開配信URLやアプリ内参照が即有効になる
  - 展開処理が重くなっても止まらない（DoS土壌）
- 次の一手：
  - 影響評価を“最短”で行う：
    - どこに書けるか（base dir逸脱/リンク）
    - 何が上書きできるか（overwrite）
    - それが“実行連鎖”につながるか（設定/テンプレ/ジョブ/配信）

---

## 手を動かす検証（Labs：手順ではなく設計）
- 追加候補Lab（例）
  - `04_labs/02_web/05_input/12_file_upload_archive_processor_zip_tar_7z/`
- Lab設計要件（差分で境界を確定できること）
  - 展開実装パターンを最低3つ作る：
    1) 単純展開（脆弱）
    2) 正規化＋base判定（中）
    3) 正規化＋base判定＋リンク拒否＋上限＋隔離（強）
  - 7zのメモリ負荷、zip/tarの件数/サイズ/深さで挙動差が観測できる
  - ログに “見積り→拒否理由（rule_id）→実測” が残る

---

## コマンド/リクエスト例（例示は最小限・意味中心）
~~~~
# 擬似コード：安全な展開の骨格（概念）
base = make_new_dir(uuid)
for entry in list_entries(archive):
  if entry.is_symlink or entry.is_hardlink or entry.is_special:
    reject("link/special not allowed")
  if is_absolute(entry.name) or has_drive_or_unc(entry.name):
    reject("absolute path not allowed")
  out = canonicalize(join(base, entry.name))
  if not out.startswith(canonicalize(base) + path_sep):
    reject("path traversal")
  enforce_limits(entry)  # count/size/depth/pathlen
extract_entries_to(base)
~~~~
- ここでの判断点：
  - “joinだけ”で終わらず、canonicalize後に base配下判定しているか
  - リンクを入口で落としているか
  - 上限が “事前見積り＋実測” で二重化されているか

---

## 深掘りリンク（最大8）
- `05_input_12_file_upload_01_validation（mime_magic_polyglot）.md`
- `05_input_12_file_upload_02_storage_path（bucket_acl_traversal）.md`
- `05_input_12_file_upload_03_execution_chain（preview_processor_rce）.md`
- `05_input_11_path_traversal_01_normalization（dotdot_encoding）.md`
- `05_input_11_path_traversal_03_archive（zip_slip）.md`
- `05_input_05_command_injection_02_args（option_injection）.md`
- `05_input_05_command_injection_01_shell（metachar_pipeline）.md`
- `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
