# 05_input_12_file_upload_04_image_processor（imagemagick_exif_svg）

画像処理（ImageMagick/EXIF/SVG）― アップロード→変換→配信の「入力→実行」境界モデル

## 目的（この技術で到達する状態）
- 「画像アップロード」を、単なる拡張子・MIMEの問題として扱わず、次の **3段階の境界**でモデル化して検証できる状態にする。
  1) **Upload境界**：入力（ファイル本体・ファイル名・Content-Type・メタデータ・多部品フォーム）
  2) **Processing境界**：サーバ側の処理（ImageMagick/ExifTool/libvips/ffmpeg/Ghostscript等）
  3) **Serving境界**：配信（同一オリジン配信 / CDN / 別ドメイン / Content-Type付与 / CSP / cache）
- この3段階のうち、重大事故が起きやすいのが **Processing境界**。「変換する」「サムネ作る」「EXIF落とす」「SVGをPNGにする」等は"実行"であり、入力→実行境界そのもの。
- 実務で次を即断できる：
  - 画像処理の"攻撃面4点セット"（RCE/SSRF/XSS/DoS）のどれが成立するか
  - どの観測（ログ/相関キー/ネットワーク）で成立根拠を固めるか
  - 修正を「処理エンジンの隔離」と「配信分離」に落とせる

## 前提（対象・範囲・想定）
- 対象：画像アップロード機能、画像処理パイプライン（サムネ生成、メタデータ除去、AI/OCR前処理、SVGラスタライズ、PDF/AI/EPS等のプレビュー生成）
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - クラウド/オンプレミス、CDN/WAF配下
  - 処理ワーカー：Webプロセス内か、非同期ジョブ（queue/worker）か
  - 配信方式：同一オリジン配信 / CDN / 別ドメイン
- できること/やらないこと（安全に検証する範囲）：
  - できること：画像処理の"攻撃面4点セット"（RCE/SSRF/XSS/DoS）のどれが成立するかの確定、成立根拠の観測設計
  - やらないこと：破壊的な処理の実行、本番環境での過度な試行、RCEの再現実証（許可範囲外）
- 依存する前提知識（必要最小限）：
  - `05_input_12_file_upload_01_validation（mime_magic_polyglot）.md`
  - `05_input_12_file_upload_02_storage_path（bucket_acl_traversal）.md`
  - `05_input_09_ssrf_01_reachability（internal_localhost_metadata）.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：
    - 画像処理の3段階の境界（Upload/Processing/Serving）
    - ImageMagick（coder と delegate の二層構造、policy.xml）
    - EXIF（メタデータ抽出/除去、パーサの脆弱性）
    - SVG（XML＋スクリプト＋外部参照、同一オリジン配信のXSS）
    - 画像処理の"攻撃面4点セット"（RCE/SSRF/XSS/DoS）
  - 扱わない（別ユニットへ接続）：
    - ファイルアップロードの検証（validation） → `05_input_12_file_upload_01_validation（mime_magic_polyglot）.md`
    - 保存先・キー設計 → `05_input_12_file_upload_02_storage_path（bucket_acl_traversal）.md`
    - 後段処理器のRCE連鎖 → `05_input_12_file_upload_03_execution_chain（preview_processor_rce）.md`

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
- 観測対象（プロトコル/データ構造/やり取りの単位）：
  - アップロード要求：multipart、ファイル本体・ファイル名・Content-Type・メタデータ・多部品フォーム
  - レスポンス：返却URL、Content-Type/Disposition、派生画像のサイズ・フォーマット、画像のハッシュやメタデータの変化
  - サーバログ：エラーメッセージの指紋（"not authorized" "policy" "ImageMagick" "convert" 等）、処理遅延のパターン、変換エラー、外部参照、ワーカー
- 境界の観点：
  - 資産境界（管理主体・委託先・対象範囲の線引き）：
    - 「アップロードされた原本」：保存先（ローカルFS、オブジェクトストレージ、DB BLOB）
    - 「派生物（サムネ/変換結果）」：別バケット・別パス・別ACLになっていることが多い
    - 「処理ワーカー」：Webプロセス内か、非同期ジョブ（queue/worker）か
  - 信頼境界（外部連携・第三者・越境ポイント）：
    - 画像処理エンジンが **外部リソース**に触れるか（HTTP fetch、delegate経由の外部コマンド、外部バイナリ）
    - 画像処理エンジンが **ファイルシステム**に触れる範囲（@file/間接参照、テンポラリ、キャッシュ）
    - SVGや画像内参照が、外部URLへのアクセスを誘発していないか
  - 権限境界（権限の切替/伝播/委任）：
    - 画像処理が「Webプロセス権限」で動く：RCEが即サーバ権限に直結しやすい
    - 画像処理が「隔離ワーカー」で動く：それでも SSRF/情報漏えい/横展開の踏み台になりうる
    - 画像処理が「同一オリジン配信」される：SVGやContent-Type誤りがXSSに直結しやすい
- 重要なフィールド/差分/状態（「ここが変わると意味が変わる」点）：
  - 状態S1：アップロード後に"必ず再エンコード"される（JPEG/PNG固定）
  - 状態S2：SVGが"そのまま同一オリジン配信"される
  - 状態S3：EXIFが"除去される"（ExifTool等が動く）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が"確定"できるか：
  - 画像処理の"攻撃面4点セット"（RCE/SSRF/XSS/DoS）のどれが成立するか
  - どの観測（ログ/相関キー/ネットワーク）で成立根拠を固めるか
  - 処理エンジンの特定（ImageMagick/ExifTool/libvips/ffmpeg/Ghostscript等）
  - 配信方式の確定（同一オリジン配信 / CDN / 別ドメイン）
- 何が"推定"できるか（推定の根拠/前提）：
  - 変換/サムネの痕跡（派生画像のサイズ・フォーマットが一定、画像のハッシュやメタデータが変化）
  - エラーメッセージの指紋（"not authorized" "policy" "ImageMagick" "convert" 等の文言）
  - 処理遅延のパターン（サイズ/フレーム数に比例して極端に遅くなる）
  - 外部到達性（SSRF/外部参照）の兆候
- 何は"言えない"か（不足情報・観測限界）：
  - 観測で「処理している事実」を固める必要がある（ここが薄いと、以降の検証が全部ブレる）
  - RCEの再現実証（許可範囲外）
  - 実行系の内部実装詳細（policy.xmlの具体的な設定、リソース制限の具体的な値）
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：ImageMagick系（policy堅い／隔離あり）だが、Serving境界が弱い（SVGが残る／誤Content-Type／同一オリジン配信）
  - パターンB：Processing境界が弱い（delegate/coder/EXIF処理が危険）（高リスク）
  - パターンC：アップロード後に"必ず再エンコード"される（JPEG/PNG固定）（多くの"拡張子偽装"は潰れる可能性が上がるが、Processing境界が太くなる）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す"狙い目"：
  - 画像処理の"攻撃面4点セット"（RCE/SSRF/XSS/DoS）のどれが成立するか
  - 変換エンジン特定 → delegate/coder/policy差分の特定
  - SVGを"画像"として許容している設計を起点に、UI/管理画面/プロフィール等の閲覧導線を探す
- 優先度の付け方（時間制約がある場合の順序）：
  1) 画像処理の"攻撃面4点セット"（RCE/SSRF/XSS/DoS）のどれが成立するかの確定
  2) 処理エンジンの特定（ImageMagick/ExifTool/libvips/ffmpeg/Ghostscript等）
  3) 配信方式の確定（同一オリジン配信 / CDN / 別ドメイン）
  4) 成立根拠の観測設計（ログ/相関キー/ネットワーク）
- 代表的な攻め筋（この観測から自然に繋がるもの）：
  - 攻め筋1：ImageMagick 利用の当たりを付ける（変換・ポリシー・リソース）
  - 攻め筋2：EXIF の処理有無を確定する（抽出/除去）
  - 攻め筋3：SVG の扱いを確定する（配信 or ラスタライズ）
  - 攻め筋4：外部到達性（SSRF/外部参照）の兆候の確認
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）：
  - 観測で「処理している事実」を固める必要がある（ここが薄いと、以降の検証が全部ブレる）
  - 以下は「攻撃の完成」ではなく、**成立根拠（差分）を観測するための最小セット**

## 次に試すこと（仮説A/Bの分岐と検証）
> ここが最重要。条件が違うと次の手が変わる形で書く。

- 仮説A：ImageMagick系（policy堅い／隔離あり）だが、Serving境界が弱い
  - 次の検証：
    - SVGが残る／誤Content-Type／同一オリジン配信 → XSS主導で影響評価へ
    - キャッシュ/CDNのキー設計次第で横展開（別ファイルに接続）
  - 期待する観測（成功/失敗時に何が見えるか）：
    - policy/resource制限が堅い → 外部参照/DoS/メタデータ処理へ重点
    - 別ドメイン（ユーザコンテンツドメイン）配信 → 影響は低下（ただし完全ではない）
    - 同一ドメイン・同一クッキー文脈 → 重大（ASVS観点の設計不備）
- 仮説B：Processing境界が弱い（delegate/coder/EXIF処理が危険）
  - 次の検証：
    - 変換エンジンの実行環境（Web直実行か／ワーカーか）、外部到達性（HTTP可否）、一時ファイル、権限を詰める
    - "成立根拠"が取れたら、次は `05_input_12_file_upload_03_execution_chain（preview_processor_rce）.md` 側のチェーン整理に接続する
  - 期待する観測：
    - 制限が弱い → 変換エンジン由来のRCE/SSRF成立条件へ重点
    - ワーカー隔離＋最小権限＋更新運用あり → 影響限定（それでもSSRF/DoSは残る）
    - Webプロセス直実行／更新停滞 → 高リスク

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：`04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
- 取得する証跡（目的ベースで最小限）：
  - HAR（アップロード～参照）
  - サーバログ（変換エラー、外部参照、ワーカー）
  - OS観測（/tmp の一時ファイル、CPU/メモリ、プロセス）
- 観測の取り方（どの視点で差分を見るか）：
  - "どれを取れば境界が確定するか"で設計する
  - 同一画像を「小→中→大」「単一→多フレーム」で投入し、処理時間と失敗点を見る
  - 同一JPGにEXIFを含めたもの／含めないものを用意し、アップ後のダウンロードでEXIFが残るかを見る
  - SVGをアップして、配信がSVGのままか、PNG等に変換されるか
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/image_processor 2>/dev/null
    cd ~/keda_evidence/image_processor
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可されたスコープ** のみ
      - 観測は **代表点の抽出** のみ
      - RCEの再現実証は許可範囲外
  - 相関キー（最低限）を作る（後で必ず効く）
    - request_id, file_id, upload_method, processing_engine, content_type, delivery_method, processing_time, error_class

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は"手段"であり"結論"ではない。必ず「何を観測している例か」を添える。

~~~~
# 以下は「攻撃の完成」ではなく、**成立根拠（差分）を観測するための最小セット**
#
# 1) ImageMagick 利用の当たりを付ける（変換・ポリシー・リソース）
# - 同一画像を「小→中→大」「単一→多フレーム」で投入し、処理時間と失敗点を見る
# - 失敗点が画素数/フレーム数で切れるなら policy/resource limit の存在を疑う
#
# 2) EXIF の処理有無を確定する（抽出/除去）
# - 同一JPGにEXIFを含めたもの／含めないものを用意し、アップ後のダウンロードでEXIFが残るかを見る
# - EXIFが消える：サーバ側で strip/再エンコードしている可能性（= パーサ/変換が走っている）
#
# 3) SVG の扱いを確定する（配信 or ラスタライズ）
# - SVGをアップして、配信がSVGのままか、PNG等に変換されるか
# - SVGがそのまま配信される場合：Content-Type と Content-Disposition を確認
~~~~

- この例で観測していること：
  - 画像処理の"攻撃面4点セット"（RCE/SSRF/XSS/DoS）のどれが成立するか
  - 処理エンジンの特定（ImageMagick/ExifTool/libvips/ffmpeg/Ghostscript等）
  - 配信方式の確定（同一オリジン配信 / CDN / 別ドメイン）
- 出力のどこを見るか（注目点）：
  - 変換/サムネの痕跡（派生画像のサイズ・フォーマットが一定、画像のハッシュやメタデータが変化）
  - エラーメッセージの指紋（"not authorized" "policy" "ImageMagick" "convert" 等の文言）
  - 処理遅延のパターン（サイズ/フレーム数に比例して極端に遅くなる）
  - 外部到達性（SSRF/外部参照）の兆候
  - 配信方式（同一オリジン配信 / CDN / 別ドメイン）
- この例が使えないケース（前提が崩れるケース）：
  - 画像処理が行われていない場合、または処理エンジンが特定できない場合

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：V5 Validation, Sanitization and Encoding、V12 Files / Resources
  - 該当要件（可能ならID）：V5.1.1、V5.1.2、V5.2.1、V12.1.1、V12.1.2
  - このファイルの内容が「満たす/破れる」ポイント：
    - v5.0.0 の「ファイル／リソース」要件（アップロード、保存、実行分離、SSRF保護）に直結する。特に「アップロード後にサーバ側で処理（変換/サムネ/メタデータ除去）する」構成は、入力検証だけでなく"処理エンジンの権限・外部到達性・リソース制限"が必須になる。
    - 満たす：処理エンジンの隔離、配信分離、policy/resource制限、EXIF処理の安全化、SVGの別ドメイン配信
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：WSTG-INPV-09 Testing for Upload of Unexpected File Types、WSTG-INPV-10 Testing for Upload of Malicious Files
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：
    - アップロード機能に対する「想定外拡張子」「悪性ファイル」「処理系の挙動」を、アップロード"後段"の処理（変換・プレビュー・メタデータ）まで含めて検証する。
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Intelligence Gathering、Vulnerability Analysis、Exploitation、Post-Exploitation
  - 前後フェーズとの繋がり（1行）：
    - Intelligence Gathering（処理系推定）→ Vulnerability Analysis（delegate/coder/メタデータ/配信方式の弱点抽出）→ Exploitation（RCE/SSRF/XSS/DoSの成立可否確認）→ Post-Exploitation（権限/到達性の拡大）に接続する。
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Initial Access、Execution、Discovery、Collection
  - 攻撃者の目的（この技術が支える意図）：
    - 初期侵入：T1190 Exploit Public-Facing Application（アップロード→変換系の脆弱性経由）
    - 実行：T1059 Command and Scripting Interpreter（変換エンジン/メタデータ処理のコマンド実行に接続した場合）
    - 内部探索：SSRF が成立する場合は Discovery/Collection に波及（内部HTTP、メタデータ、管理面の到達性）
  - 参照：https://attack.mitre.org/tactics/TA0001/

## 参考（必要最小限）
- ImageMagick Security Policy / Resources
- ImageTragick（CVE-2016-3714）NVD / Red Hat / JVN
- Ghostscript関連（ImageMagickでPS/EPS/PDF/XPS無効化可能）
- ExifTool（CVE-2021-22204 / CVE-2022-23935）
- SVGのXSS・同一生成元への影響（Mozilla等）
- OWASP WSTG（Unexpected/Malicious Upload）

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`05_input_12_file_upload_01_validation（mime_magic_polyglot）.md`
- 関連 topics：`05_input_12_file_upload_02_storage_path（bucket_acl_traversal）.md`
- 関連 topics：`05_input_12_file_upload_03_execution_chain（preview_processor_rce）.md`

---

## 深掘りリンク（最大8）
- `05_input_12_file_upload_01_validation（mime_magic_polyglot）.md`
- `05_input_12_file_upload_02_storage_path（bucket_acl_traversal）.md`
- `05_input_12_file_upload_03_execution_chain（preview_processor_rce）.md`
- `05_input_12_file_upload_05_archive_processor（zip_tar_7z）.md`
- `05_input_11_path_traversal_01_normalization（dotdot_encoding）.md`
- `05_input_09_ssrf_01_reachability（internal_localhost_metadata）.md`
- `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
- `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
