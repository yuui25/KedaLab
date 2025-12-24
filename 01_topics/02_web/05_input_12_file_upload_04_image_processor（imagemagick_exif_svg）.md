# 画像処理（ImageMagick/EXIF/SVG）― アップロード→変換→配信の「入力→実行」境界モデル

## ガイドライン対応（ASVS / WSTG / PTES / ATT&CK）
- ASVS（例）
  - v5.0.0 の「ファイル／リソース」要件（アップロード、保存、実行分離、SSRF保護）に直結する。特に「アップロード後にサーバ側で処理（変換/サムネ/メタデータ除去）する」構成は、入力検証だけでなく“処理エンジンの権限・外部到達性・リソース制限”が必須になる。  
    参照：ASVS 5.0.0 / Index ASVS（V12系） 
- WSTG（例）
  - アップロード機能に対する「想定外拡張子」「悪性ファイル」「処理系の挙動」を、アップロード“後段”の処理（変換・プレビュー・メタデータ）まで含めて検証する。 
- PTES（位置づけ）
  - Intelligence Gathering（処理系推定）→ Vulnerability Analysis（delegate/coder/メタデータ/配信方式の弱点抽出）→ Exploitation（RCE/SSRF/XSS/DoSの成立可否確認）→ Post-Exploitation（権限/到達性の拡大）に接続する。
- ATT&CK（例）
  - 初期侵入：T1190 Exploit Public-Facing Application（アップロード→変換系の脆弱性経由）
  - 実行：T1059 Command and Scripting Interpreter（変換エンジン/メタデータ処理のコマンド実行に接続した場合）
  - 内部探索：SSRF が成立する場合は Discovery/Collection に波及（内部HTTP、メタデータ、管理面の到達性）

---

## このファイルの目的
「画像アップロード」を、単なる拡張子・MIMEの問題として扱わず、次の **3段階の境界**でモデル化して検証できる状態にする。

1) **Upload境界**：入力（ファイル本体・ファイル名・Content-Type・メタデータ・多部品フォーム）  
2) **Processing境界**：サーバ側の処理（ImageMagick/ExifTool/libvips/ffmpeg/Ghostscript等）  
3) **Serving境界**：配信（同一オリジン配信 / CDN / 別ドメイン / Content-Type付与 / CSP / cache）

この3段階のうち、重大事故が起きやすいのが **Processing境界**。  
「変換する」「サムネ作る」「EXIF落とす」「SVGをPNGにする」等は“実行”であり、入力→実行境界そのもの。

---

## 対象スコープ（実務で頻出の画像処理パイプライン）
- 画像アップロード → サムネ生成（JPG/PNG/WebP）
- 画像アップロード → メタデータ除去（EXIF strip）
- 画像アップロード → AI/OCR前処理（リサイズ、回転、色空間変換）
- SVGアップロード → ラスタライズ（PNG化）
- PDF/AI/EPS等 “画像扱い” → プレビュー生成（※ここはGhostscript delegateが絡みやすい）

---

## 境界モデル（資産境界／信頼境界／権限境界）

### 資産境界
- 「アップロードされた原本」：保存先（ローカルFS、オブジェクトストレージ、DB BLOB）
- 「派生物（サムネ/変換結果）」：別バケット・別パス・別ACLになっていることが多い
- 「処理ワーカー」：Webプロセス内か、非同期ジョブ（queue/worker）か

### 信頼境界
- 画像処理エンジンが **外部リソース**に触れるか（HTTP fetch、delegate経由の外部コマンド、外部バイナリ）
- 画像処理エンジンが **ファイルシステム**に触れる範囲（@file/間接参照、テンポラリ、キャッシュ）

### 権限境界
- 画像処理が「Webプロセス権限」で動く：RCEが即サーバ権限に直結しやすい
- 画像処理が「隔離ワーカー」で動く：それでも SSRF/情報漏えい/横展開の踏み台になりうる
- 画像処理が「同一オリジン配信」される：SVGやContent-Type誤りがXSSに直結しやすい

---

## まず押さえる：画像処理の“攻撃面4点セット”
画像処理は、攻撃者視点では次の4系統の成果（Impact）に分解できる。

1) **RCE（実行）**：変換エンジン／delegate／メタデータ処理の脆弱性
2) **SSRF（到達性）**：外部参照（URL）やdelegateが内部へ到達
3) **XSS（クライアント実行）**：SVG/HTML混入、誤Content-Type、同一オリジン配信
4) **DoS（資源枯渇）**：巨大画像、画像爆弾、フレーム多数、変換無限/高コスト

本ファイルは特に (1)(2)(3) を“現実寄り”に深掘りする（(4)も検証観点として必須）。

---

## ImageMagick（Imagemagick/Imagick）の成立根拠（なぜ危険になりうるか）

### 1) coder と delegate の二層構造
- **coder**：入力形式（PNG/JPG/GIF/SVG/PDF…）を解釈する“入口”
- **delegate**：特定形式の処理を外部プログラムに委譲する“外部呼び出し”
  - 例：PS/PDF/EPS → Ghostscript、SVG → Inkscape/RSVG など（環境差が大きい）

この二層のどちらかが「外部コマンド」や「外部取得」を伴うと、入力→実行境界が太くなる。

### 2) policy.xml が“最後の砦”になりがち
ImageMagick には security policy があり、危険な coder/delegate、リソース（メモリ/ディスク/時間）等を制限できる。  
ただし、デフォルトや運用により“意図せず危険設定”になっている例が多い。 

### 3) 既知の代表例：ImageTragick（CVE-2016-3714）
- 一部の coder が「シェルメタ文字等」を通じて任意コード実行に接続し得る、というクラスの問題として有名。  
- 重要なのは「CVEそのもの」より、**“画像形式の解釈→delegate/外部実行→RCE”**という構造が、今でも設計上の本質的リスクとして残ること。 

---

## EXIF（メタデータ）の成立根拠（なぜ危険になりうるか）
EXIFは「ただの付帯情報」ではなく、次の理由で入力→実行境界を作る。

- サービス側が **ExifTool等でメタデータ抽出/除去**を行う（= パーサが動く）
- パーサ自体に脆弱性があると、画像アップロードがRCEへ接続する（例：ExifToolの既知CVE） 
- さらに運用上の典型として「CLIをシェル経由で呼ぶ」「ファイル名を安全に渡していない」「ワーカー権限が強い」が揃うと、実害が増幅する

---

## SVGの成立根拠（なぜ危険になりうるか）
SVGは“画像”として扱われがちだが、実際には **XML＋スクリプト＋外部参照**を含み得る「ミニアプリ」に近い。  
- アップロードSVGが **同一オリジンで image/svg+xml として配信**されると、XSSに直結し得る。 
- SVG→PNG等のラスタライズを行う場合、ImageMagickが **delegate（Inkscape/RSVG）**を呼ぶことがあり、外部参照・変換系の攻撃面が増える。 

---

## 観測ポイント（攻撃面を“確定”するための見方）
ここが薄いと、以降の検証が全部ブレる。観測で「処理している事実」を固める。

### A. サーバが“何をしているか”（Processing境界の確定）
- 変換/サムネの痕跡
  - 派生画像のサイズ・フォーマットが一定（例：必ずJPEG化、WebP化）
  - 画像のハッシュやメタデータが変化（EXIFが消える、色空間が変わる）
- エラーメッセージの指紋
  - “not authorized” “policy” “ImageMagick” “convert” 等の文言（スタック/ログに残る場合）
- 処理遅延のパターン
  - サイズ/フレーム数に比例して極端に遅くなる（resource limitが無い/弱い）

### B. 外部到達性（SSRF/外部参照）の兆候
- SVGや画像内参照が、外部URLへのアクセスを誘発していないか
- 変換失敗時のエラーに “delegate” “URL” “HTTP” の痕跡がないか

### C. 配信方式（Serving境界の確定）
- アップロードしたファイルが **同一オリジン**で参照できるか
- `Content-Type` が何で返るか（特に SVG/HTML の混入）
- `Content-Disposition` が `inline` か `attachment` か
- CDN/キャッシュが絡むか（別ドメイン配信か）

---

## 手を動かす検証（安全な範囲で“成立条件”を見る）
以下は「攻撃の完成」ではなく、**成立根拠（差分）を観測するための最小セット**。

### 1) ImageMagick 利用の当たりを付ける（変換・ポリシー・リソース）
- 同一画像を「小→中→大」「単一→多フレーム」で投入し、処理時間と失敗点を見る  
  - 失敗点が画素数/フレーム数で切れるなら policy/resource limit の存在を疑う 
- もし“PDF/PS/EPS”系の入力が通る設計なら、Ghostscript delegate が絡む前提で境界を見直す（原則は無効化されているべき） 

### 2) EXIF の処理有無を確定する（抽出/除去）
- 同一JPGにEXIFを含めたもの／含めないものを用意し、アップ後のダウンロードでEXIFが残るかを見る  
  - EXIFが消える：サーバ側で strip/再エンコードしている可能性（= パーサ/変換が走っている）
  - EXIFが残る：クライアント由来情報がそのまま配信される（XSS/情報漏えい/追跡の論点へ）

### 3) SVG の扱いを確定する（配信 or ラスタライズ）
- SVGをアップして、配信がSVGのままか、PNG等に変換されるか
- SVGがそのまま配信される場合：
  - Content-Type と Content-Disposition を確認（同一オリジンの `image/svg+xml` は特に危険） 
- SVGが変換される場合：
  - delegate（Inkscape/RSVG）を使う環境では外部参照が論点になり得るため、外部到達性（ログ/監視）で根拠を取る 

---

## 結果の意味（状態として読む：診断の結論に落ちる形）

### 状態S1：アップロード後に“必ず再エンコード”される（JPEG/PNG固定）
- 意味：
  - 多くの“拡張子偽装”は潰れる可能性が上がる
  - ただし Processing境界が太くなる（変換エンジンが動く＝RCE/SSRF/DoSの土台）
- 攻撃者視点：
  - 「変換エンジン特定」→「delegate/coder/policy差分の特定」へ進む
- 次の一手：
  - 仮説A：policy/resource制限が堅い → 外部参照/DoS/メタデータ処理へ重点
  - 仮説B：制限が弱い → 変換エンジン由来のRCE/SSRF成立条件へ重点

### 状態S2：SVGが“そのまま同一オリジン配信”される
- 意味：
  - XSS（特に格納型）に直結し得る（被害：セッション/トークン/操作乗っ取り）
- 攻撃者視点：
  - SVGを“画像”として許容している設計を起点に、UI/管理画面/プロフィール等の閲覧導線を探す
- 次の一手：
  - 仮説A：別ドメイン（ユーザコンテンツドメイン）配信 → 影響は低下（ただし完全ではない）
  - 仮説B：同一ドメイン・同一クッキー文脈 → 重大（ASVS観点の設計不備）

### 状態S3：EXIFが“除去される”（ExifTool等が動く）
- 意味：
  - パーサが動いているため、ExifTool等のCVE影響範囲、実行権限、隔離状況が主論点になる 
- 攻撃者視点：
  - 「画像アップロード」＝「サーバ側でメタデータ処理が走る」なら、RCE系の期待値が上がる
- 次の一手：
  - 仮説A：ワーカー隔離＋最小権限＋更新運用あり → 影響限定（それでもSSRF/DoSは残る）
  - 仮説B：Webプロセス直実行／更新停滞 → 高リスク

---

## 攻撃チェーン（現実寄り：どう繋がるか）
「画像処理」は単発脆弱性ではなく、次のような“連鎖”で深刻化する。

- Upload（入力注入）
  → Processing（変換/抽出/ラスタライズ）
  → Serving（同一オリジン配信/誤Content-Type/キャッシュ）
  → 追加影響（XSSで管理者セッション奪取 → 設定変更 → さらなるRCE/情報漏えい）

このチェーンを切る設計は「入力検証」だけでは不十分で、**(a)処理エンジンの隔離** と **(b)配信分離** が中核になる。

---

## 防御側への設計メモ（診断所見を“実装”に落とす観点）
ここは報告テンプレ化せず、境界に直結する最小限のみ。

### 1) ImageMagick を使うなら policy を前提にする
- 危険な coder/delegate を無効化（例：URL系、PS/PDF/EPS/XPS 等は原則無効化を検討） 
- リソース制限（memory/map/disk/time/width/height/frame）を明示的に設ける 
- policy評価の自動点検（CIでチェックする）など“運用で担保”する 

### 2) EXIF は「処理する＝パーサを動かす」と認識する
- ExifTool等のバージョン更新と隔離（ワーカー分離、最小権限、ネットワーク遮断）
- メタデータ除去は“安全なライブラリ”選定と監視が要る（既知CVEの影響を受ける） 

### 3) SVG は“許可するなら別ドメイン配信”が基本
- 同一オリジンで `image/svg+xml` として配信しない設計（ユーザコンテンツドメイン、`Content-Disposition: attachment`、`text/plain` 配信等の方針） 

---

## 次に試すこと（仮説A/B：検証の分岐）
### 仮説A：ImageMagick系（policy堅い／隔離あり）だが、Serving境界が弱い
- SVGが残る／誤Content-Type／同一オリジン配信 → XSS主導で影響評価へ
- キャッシュ/CDNのキー設計次第で横展開（別ファイルに接続）

### 仮説B：Processing境界が弱い（delegate/coder/EXIF処理が危険）
- 変換エンジンの実行環境（Web直実行か／ワーカーか）、外部到達性（HTTP可否）、一時ファイル、権限を詰める
- “成立根拠”が取れたら、次は 05_input_12_file_upload_03_execution_chain（preview_processor_rce） 側のチェーン整理に接続する

---

## 04_labs での再現（設計として）
- 04_labs/01_local/02_proxy_計測・改変ポイント設計.md に寄せて、
  - HAR（アップロード～参照）
  - サーバログ（変換エラー、外部参照、ワーカー）
  - OS観測（/tmp の一時ファイル、CPU/メモリ、プロセス）
  を“どれを取れば境界が確定するか”で設計する。

---

## 関連（同フォルダ内）
- 05_input_12_file_upload_01_validation（mime_magic_polyglot）.md
- 05_input_12_file_upload_02_storage_path（bucket_acl_traversal）.md
- 05_input_12_file_upload_03_execution_chain（preview_processor_rce）.md
- 05_input_11_path_traversal_01_normalization（dotdot_encoding）.md
- 05_input_09_ssrf_01_reachability（internal_localhost_metadata）.md

---

## 参考（一次情報・仕様・根拠）
- ImageMagick Security Policy / Resources 
- ImageTragick（CVE-2016-3714）NVD / Red Hat / JVN 
- Ghostscript関連（ImageMagickでPS/EPS/PDF/XPS無効化可能） 
- ExifTool（CVE-2021-22204 / CVE-2022-23935） 
- SVGのXSS・同一生成元への影響（Mozilla等） 
- WSTG（Unexpected/Malicious Upload） 
