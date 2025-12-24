## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - この技術で満たす/破れる点：入力検証（危険文字の扱いではなく「シェル境界を跨がない」設計）、安全なAPI利用（shell経由実行の排除）、エラーハンドリング（エラー差分がオラクル化しない）、監査（プロセス生成・実行引数・呼出し元の相関）
  - 支える前提：Command Injectionは「入力→実行」境界の代表であり、SSTI/デシリアライズより“現場で遭遇頻度が高いのに見落とされやすい”（ログに残りにくい/再現しづらい/機能要件で混入しやすい）
- WSTG：
  - 該当テスト観点：Testing for Command Injection（WSTG-INPV-12）での検証設計（差分観測、タイミング、出力、エラー、実行痕跡） :contentReference[oaicite:0]{index=0}
  - どの観測に対応するか：本ファイルは「shell を経由しているか」を確定するための観測点（メタ文字/パイプ/リダイレクト/サブシェル）に絞る。args注入（オプション注入）は別ファイル（02_args）で扱う
- PTES：
  - 該当フェーズ：Vulnerability Analysis（入力→実行境界の仮説化）、Exploitation（ただし“安全な範囲”で成立根拠を確定：時間差・戻り値差分・プロセス生成痕跡）
  - 前後フェーズとの繋がり（1行）：Reconで見つけた「外部コマンドを使いそうな機能（PDF生成、画像変換、DNS/Whois、Git操作、バックアップ、ログ整形）」を、入力形（パラメータ/ヘッダ/ファイル名）に落として差分観測する
- MITRE ATT&CK：
  - 戦術：Execution
  - 技術：Command and Scripting Interpreter（T1059）/ Unix Shell（T1059.004） :contentReference[oaicite:1]{index=1}
  - 目的：Web入力からサーバ上のコマンド実行に到達し、後続（情報収集・横展開・永続化・持ち出し）へ接続する

## タイトル
command_injection_shell（metachar_pipeline）

## 目的（この技術で到達する状態）
- 「OSコマンドを呼んでいる」だけではなく、**(1) shell を経由しているか（＝メタ文字が“文法”として解釈されるか）**、**(2) どの境界で入力が結合されるか（文字列連結/テンプレ/ログ/ジョブ）**、**(3) どの観測で“成立根拠”を確定できるか（低侵襲）** をモデル化して説明できる
- “危険文字を弾く”のレベルを卒業し、**「shell を呼ばない/呼ぶなら固定コマンド＋引数配列＋許可リスト」**へ設計・是正案を落とし込める :contentReference[oaicite:2]{index=2}
- 似て非なるもの（args注入、PATH汚染、テンプレ注入、SSRF→内部RCE）と混同せず、**差分（成立根拠）**で切り分けられる

## 前提（対象・範囲・想定）
- 対象：Webアプリが外部コマンドを実行する機能（例）
  - 画像/動画/音声変換（ffmpeg/convert）
  - PDF生成（wkhtmltopdf/Chromium headless）
  - ネットワーク系（ping/nslookup/dig/curl）
  - Git/アーカイブ/バックアップ（tar/zip/rsync）
  - 管理機能（ログ整形、メトリクス、ジョブ起動）
- 本ファイルの範囲：**shell 経由の実行**（`/bin/sh -c`、`bash -c`、`cmd.exe /c`、`powershell -Command` 等）
  - shell 経由だと、入力が「引数」ではなく「プログラム（文）」として再解釈されるため、メタ文字・パイプ・リダイレクトが成立し得る
- 重要な切り分け
  - shell 経由（本ファイル）：**メタ文字が構文として働く**
  - 引数配列実行（別ファイル02_args）：メタ文字は“ただの文字”になりやすいが、**オプション注入**が主戦場
  - 環境依存（別ファイル03_env）：PATH/LD_PRELOAD 等で“別物が呼ばれる”

## 観測ポイント（何を見ているか：データ/境界/運用）
### 1) 「shell を経由している」典型の実装シグナル（設計上の臭い）
- Node.js：`child_process.exec()` / `execSync()`、`spawn(..., { shell:true })`
- Python：`os.system()`、`subprocess.*(..., shell=True)`
- PHP：`system()`/`exec()`/`shell_exec()`/`popen()` 等
- Ruby：バッククォート、`system()`、`Open3.popen3` の文字列渡し
- Java：`Runtime.exec(String)`（1文字列）や `ProcessBuilder` に `sh -c` を噛ませる
- 重要：**「その言語の標準APIが shell を噛むか」**が第一境界。ここが Yes なら、メタ文字は“入力検証の問題”ではなく“設計の問題”になる :contentReference[oaicite:3]{index=3}

### 2) メタ文字が“文法”として解釈される境界（metachar boundary）
- 代表カテゴリ（OS/シェルで差あり）
  - コマンド連結：`<SEP>`（例：`;` や改行 等）
  - 条件連結：`<COND>`（例：`&&`/`||`）
  - パイプ：`<PIPE>`（例：`|`）
  - リダイレクト：`<REDIR>`（例：`>`/`>>`/`<`/`2>`）
  - サブシェル/コマンド置換：`<SUB>`（例：`$(...)`/バッククォート）
  - ワイルドカード/グロブ：`<GLOB>`（例：`*`/`?`）
- 観測で確定したい点
  - 入力が **「引数」**として扱われているのか、**「シェル文」**として扱われているのか
  - どの層で結合されるか（UI→API→ジョブ→ワーカー→OS）
  - URLデコード、テンプレ展開、ログ整形などで「メタ文字が復元」される地点があるか

### 3) “成立根拠（差分）”として強い観測：出力差分・時間差・エラー差分
- 出力差分（強いがUIに出ないことも多い）
  - 実行結果がレスポンス/ファイル/ログに反映されるか
- 時間差（UIに出やすいが副作用に注意）
  - 正常系より遅延するか（ジョブ/同期処理のどちらでも観測可能）
- エラー差分（オラクル化しやすい）
  - “コマンドが解釈された時だけ”別エラーになる、exit codeが変わる、stderrが混入する
  - ただしエラー差分は情報漏えい/存在オラクルと表裏（error_model と接続） :contentReference[oaicite:4]{index=4}

### 4) パイプ/メタ文字が絡む“現実の起点”パターン（入力起点の分類）
- ファイル名起点：アップロード名、生成ファイル名、圧縮展開対象名
- URL/ホスト名起点：ping、fetch、webhookテスト、プレビュー生成
- フィルタ文字列起点：ログ検索、grep/awk/sed の式、画像変換オプション
- 管理画面の入力起点：運用者が触る＝「安全前提」でガードが薄い

### 5) command_injection_shell_key（正規化キー：後続へ渡す）
- 推奨キー：command_injection_shell_key
  - command_injection_shell_key =
    <shell_involved>(yes/no/unknown)
    + <concat_point>(ui|api|job|worker|template|unknown)
    + <metachar_class>(sep|pipe|redir|subshell|multi|unknown)
    + <observable>(response|file|log|timing|error_only|unknown)
    + <execution_context>(same_user|privileged|container|unknown)
    + <egress_possible>(yes/no/unknown)

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える（確定できる）：
  - shell を経由している（メタ文字が“構文”として効く）＝**設計上の重大境界越え** :contentReference[oaicite:5]{index=5}
  - どの入力経路で結合されているか（同期APIか、非同期ジョブ/ワーカーか）
  - どの観測（戻り・時間・エラー）で成立根拠が取れるか
- 推定（根拠付きで言える）：
  - 出力が返らず時間差だけ出る場合：blind 実行の可能性（観測点はログ/プロセス生成へ寄せる）
  - ジョブ経由でのみ再現する場合：キュー/ワーカー側で shell 実行している可能性
- 言えない（この段階では断定しない）：
  - 直ちに任意コマンド実行“完全”に到達したとは限らない（権限・コンテナ隔離・AppArmor/SELinux・実行パス制限などの現実制約がある）
  - ただし「shell を跨いだ」時点で、攻撃面としてはP0級に扱う（防御は“入力フィルタ”では止まりにくい）

## 確認（最大限詳しく：どうやって“確定”したと言えるか）
### 1) まず「shell 経由か」を確定する（メタ文字の“意味差分”を見る）
- 目的：args注入（02_args）と混同しない
- 最小の差分観測（安全寄り）
  - 同じ入力に対して、メタ文字“らしきもの”を入れた時だけ
    - 応答時間が変わる
    - エラー種別が変わる
    - 出力（レスポンス/生成物/ログ）が変わる
- 証跡として強いもの（優先）
  - リクエスト差分（同一操作で入力だけ変更）
  - サーバ側ログ（取れるなら）：プロセス生成ログ、stderr、exit code
  - 可能なら：WAF/EDR/監査ログに「シェル起動」が残る（T1059観点） :contentReference[oaicite:6]{index=6}

### 2) 結合地点（concat_point）を特定する
- UI入力 → API で即実行：同期系（レスポンス差分が出やすい）
- APIはジョブ投入 → ワーカーで実行：非同期系（時間差やジョブ状態差分が出やすい）
- バッチ/管理画面：実行ユーザが強権限になりがち（影響大）
- 方法
  - 同一入力でも「ジョブ化/即時」の経路差で再現性を比較
  - trace_id/job_id で相関（ログが取れるなら最強）

### 3) “どのメタ文字クラスが効くか”でシェル種別/防御を推定する
- sep/pipe/redir/subshell のどれが効くかで、
  - 実際に噛んでいるシェル（sh/bash/dash/cmd/powershell）
  - フィルタやクォートの有無（部分的サニタイズ）
  を推定し、次の検証（02_args/03_env へ）に繋ぐ
- 注意：ここで“攻撃用の具体コマンド列”に踏み込む必要はない
  - 目的は **成立根拠の確定** と **防御点の特定**（shell排除、固定コマンド化、引数配列化） :contentReference[oaicite:7]{index=7}

### 4) “確認できた”と言うための最低限の証跡セット（報告に耐える）
- 入力起点の証跡
  - どのパラメータ/ボディ/ファイル名が起点か（画面/エンドポイント名）
- 成立根拠（差分）証跡
  - ベース入力 vs メタ文字入力 の比較（時間/レスポンス/エラー/生成物の差）
- 実行境界の証跡（可能なら強い）
  - ジョブ経由か、同期か（job_id、状態遷移）
  - サーバログの一部（コマンド全体はマスクしても「shellが呼ばれた」事実が残れば強い）
- 影響範囲の見積り
  - 実行ユーザ権限、コンテナ隔離、外向き通信可否（egress）

## 次に試すこと（仮説A/Bの分岐と検証：低侵襲で確定）
- 仮説A：shell を経由しており、メタ文字が構文として解釈される
  - 検証（低侵襲）：
    - 入力の“メタ文字クラス”を変えて差分を取る（sep/pipe/redir/subshell）
    - 反映点がレスポンスに出ない場合は、時間差 or ジョブ状態差分で観測する
  - 判断：
    - 差分が安定再現：P0（設計欠陥として扱う）
- 仮説B：shell ではなく引数配列実行だが、オプション注入で挙動が変わっている（args注入）
  - 検証：
    - メタ文字では差分が出ないが、`-` から始まる入力で挙動が変わる/エラーが変わる
  - 判断：
    - 02_args に移送（command_injection_args_key で整理）
- 仮説C：実行はされるが“出力が一切返らない”（blind）ため、観測点が不足
  - 検証：
    - 監査/ログ/プロセス生成イベントの取得可否を確認（取れないならLabsで再現して観測点設計へ）
  - 判断：
    - 取れないまま断定しない。だが「shell関与の疑い」が濃ければP1以上で設計レビュー対象

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/` の案）：
  - `04_labs/02_web/05_input/05_command_injection_shell_metachar_pipeline/`
    - 構成案（現実運用の再現）
      - Web入力 → API → ワーカー（任意）で `sh -c "<fixed> <user_input>"` を実装した“悪い例”と、
        `execve(["fixed","--opt", user_input])` の“良い例”を切替できるようにする
      - 観測点（必須）
        - HTTP：入力差分のHAR
        - Appログ：受け取った入力（正規化後）、呼出し関数（exec/execve）、exit code
        - OSログ：プロセス生成（親子関係）、実行ユーザ、コマンドライン（マスク方針込み）
      - 防御切替（比較のため）
        - shell関与 ON/OFF
        - 固定コマンド＋引数配列化 ON/OFF
        - allowlist（入力の許可文字/形式）ON/OFF
        - タイムアウト（短/長）ON/OFF
- 取得する証跡（深掘り向け）
  - 「shell が呼ばれた」イベント（プロセスツリー）
  - どのメタ文字クラスで差分が出るか（分類表）
  - どの層で結合されたか（API/ワーカー）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
# 擬似：外部コマンド起動が疑わしい API
POST /api/tools/ping
Body: { "host": "<USER_INPUT>" }

# 観測の考え方（具体ペイロードは目的に応じて最小化）
# - base_input と metachar_input の差分で「shell関与」を疑う
# - 出力が返らないなら timing / job_status / error_model を見る

# 差分観測（擬似）
host = "example.com"                         -> baseline
host = "example.com<SEP><SAFE_MARKER>"       -> sep差分が出る？
host = "example.com<PIPE><SAFE_MARKER>"      -> pipe差分が出る？
host = "example.com<REDIR><SAFE_MARKER>"     -> redir差分が出る？
host = "example.com<SUB><SAFE_MARKER>"       -> subshell差分が出る？

# SAFE_MARKER は「影響が小さい観測用」に限定する（ラボで再現推奨）
~~~~
- この例で観測していること：
  - “host という引数”が、実は shell 文の一部として解釈されていないか（境界跨ぎ）
- 出力のどこを見るか（注目点）：
  - timing_delta、error_delta、job_state_delta、process_spawn_signal
- この例が使えないケース（前提が崩れるケース）：
  - WAF等でメタ文字が前段で落ちる場合：それ自体は防御だが、別経路（ジョブ/管理画面/ファイル名）に同様の結合点が残ることがあるため、機能横断で探索する

## 参考（必要最小限）
- OWASP WSTG：Testing for Command Injection（WSTG-INPV-12） :contentReference[oaicite:8]{index=8}
- OWASP Cheat Sheet：OS Command Injection Defense Cheat Sheet :contentReference[oaicite:9]{index=9}
- CWE-78：OS Command Injection（定義の揺れと範囲） :contentReference[oaicite:10]{index=10}
- MITRE ATT&CK：T1059 / T1059.004 :contentReference[oaicite:11]{index=11}

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/05_input_00_入力→実行境界（テンプレ デシリアライズ等）.md`
- `01_topics/02_web/04_api_09_error_model_情報漏えい（例外_スタック）.md`
- `01_topics/02_web/05_input_05_command_injection_02_args（option_injection）.md`

## 次（次トピック）に進む前に確認したいこと（必要なら回答）
- 対象システムの“外部コマンドを使いそうな機能”はどれか（PDF/画像/ネットワーク/バックアップ等）。最初に当たりを付けると、探索が「入力フォーム総当たり」から「成立しやすい面の優先度付け」になる
- 実施時の制約：本番/検証、タイムアウト、ログ取得可否（プロセス生成ログが取れるか）。blind の可能性があるため、ログが取れない場合は Labs で先に観測設計を固めるとブレにくい
- 次ファイル（02_args）では、shell ではなく引数境界に寄せ、**オプション注入（`-` 起点）** と **コマンド選択の固定化** を中心に扱う
