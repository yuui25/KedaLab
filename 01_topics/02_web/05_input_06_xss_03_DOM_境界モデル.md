## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 破れる点：サーバで安全に見える（入力検証・出力エンコード済み）にも関わらず、クライアント側JSが「信頼できないデータ（source）」を「危険なDOM操作（sink）」へ渡し、ブラウザで“実行”へ変換する（信頼境界がサーバ外へ移る）
  - 守る設計：危険sinkの禁止（innerHTML等）、安全sink（textContent等）への統一、クライアント側サニタイズの標準化、CSP（可能ならnonce運用）＋第三者JSの統制
- WSTG：
  - Client-side Testing の「Testing for DOM-Based Cross Site Scripting」を対象に含める（サーバ応答だけ見ていると抜ける）
- PTES：
  - Vulnerability Analysis：source/sinkの棚卸し（コード＋ランタイム）→成立根拠（データフロー）→影響（どの権限で何ができるか）
  - Exploitation：PoCは「実行境界を跨いだ」根拠（DOM上の解釈差分）まで。データ窃取や持続化は不要
  - Reporting：原因を「危険sink」「サニタイズ欠如/誤用」「第三者JS/テンプレ」「CSP/Trusted Types未導入」に分解して再発防止へ
- MITRE ATT&CK：
  - Drive-by Compromise（T1189）＝“Web閲覧を起点にクライアントで実行”として位置づけ（DOM XSSはその実装バグ経路の一種として説明できる）
  - 目的：被害者権限での操作代行（アカウント/ワークフロー乗っ取り）へ接続

---

## タイトル
DOM XSS（DOM-based Cross-site Scripting）境界モデル

## 目的（この技術で到達する状態）
- DOM XSSを「payloadが通る/通らない」ではなく、次の“境界モデル”で説明できる
  - Source：どこから信頼できないデータが入るか（URL、postMessage、Storage、Referrer等）
  - Transform：どの正規化/デコード/テンプレ処理が入るか（ここで“再解釈”が起きる）
  - Sink：どのDOM APIへ流れるか（innerHTML等の危険sink／textContent等の安全sink）
  - Execution：最終的にブラウザが“コード実行”または“意味のあるDOM解釈”を行う
- 実務で次を即断できる
  - サーバ側ログやWAFだけでは捕まえにくい理由（source/sinkがクライアント内）を説明できる
  - どのページ/機能が危険かを「source/sink/影響権限」で優先度付けできる
  - 修正が「入力フィルタ」ではなく「危険sinkの排除＋安全API統一＋標準サニタイズ＋CSP強化」であることを提示できる

---

## 定義（短く、判断に必要な粒度）
- DOM XSSは、クライアント側JavaScriptが信頼できないsourceを不安全にDOMへ書き戻す（sink）ことで発生する
- innerHTMLはXSSの代表的な入口であり、`<script>`が実行されない場合でも他の経路で実行に至り得る（＝「scriptが動かないから安全」は誤り）
- 対策の核は「適切な出力メソッド（sink）を使う」こと（例：innerHTMLではなくtextContent等）

---

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) 資産境界（どのページが“被害が大きいDOM”か）
- 認証後ページ、管理/運用UI、重要操作（送金/権限変更/承認）に近い画面は優先度が上がる
- 第三者JSが多い画面（タグ、分析SDK、ウィジェット）は source/sinkが増えやすい

### 2) 信頼境界（source：どこから入るか）
- URL系：`location.href/search/hash`（hashはサーバへ送られないことが多く、ログに残らない）
- ブラウザ状態：`document.referrer`、`window.name`
- メッセージング：`postMessage`（origin検証・スキーマ検証がなければ危険）
- 永続：`localStorage/sessionStorage`（“以前に保存した値”がsourceになる＝second-order化）
- DOM：`document.cookie`（HttpOnlyで軽減されるが、XSS自体は防げない）
- 外部データ：fetchしたJSONをそのまま描画（「APIは安全」でもフロントの扱いで崩れる）

### 3) 実行境界（sink：どこに入ると“再解釈”されるか）
- 代表的な危険sink（例示：分類のため）
  - HTML解釈：`innerHTML` / `outerHTML` / `insertAdjacentHTML`
  - 文字列→コード：`eval` / `Function()` / `setTimeout(string)`（コード注入に直結）
  - URL解釈：`location = ...` / `src/href`への代入（スキーム・正規化の問題）
- 安全sink（原則）
  - `textContent` / `innerText` / 属性の安全なセット（スキーム制限・URL正規化を伴う）
  - OWASPは「安全なsinkを使う」ことをDOM XSS対策の中心に置く

---

## 結果の意味（何が言える/言えない：状態として説明）
### 言える（確定できる）
- “source →（加工）→ sink” のデータフローが存在し、適切なエスケープ/サニタイズがない（または誤用）ため、ブラウザでDOM再解釈が起きる状態
- サーバ側の出力エスケープが正しくても、クライアントのsinkが危険なら成立する（サーバ防御だけでは完結しない）

### 言えない（追加観測が必要）
- 直ちに「任意JS実行が誰でも可能」とは限らない
  - どのsourceが攻撃者に制御可能か（URLだけか、保存値か、postMessageか）
  - CSPやアプリの防御（nonce等）で“実行”の形が制約される可能性
- 影響（何ができるか）は、被害者権限・画面の機能・CSRF/認可境界と複合して決まる

---

## 攻撃者視点での利用（優先度・攻め筋・現実の動き）
### 1) 優先度付け（攻撃者はここを見る）
- 被害者が高権限（運用/管理）で必ず閲覧する導線（監査、モデレーション、問い合わせ）がある画面
- URL hash / postMessage のように“サーバに残りにくいsource”がある画面（検知されにくい）
- 第三者JSやDOM操作が多い画面（sinkが増える）

### 2) “成立根拠”として何を取りに来るか（CTFではなく実務想定）
- 文字列が「HTMLとして解釈された」ことの根拠（DOM構造の差分、属性構造の差分）
- sourceが本当に攻撃者制御か（URLで再現する／保存値として後で再現する／messageで再現する）
- 影響：その画面での操作代行（状態変更）に接続できるか（窃取の実証は不要）

---

## 確認（最大限“現実寄り”：DOM XSSの見逃しを減らす）
### 手順0：まず“危険sink”を棚卸し（静的）
- 対象：自社コード＋テンプレ＋ビルド成果物（minify後も検索）
- 方針：payload探索ではなく、危険sinkがどこにあるかを起点にする（再現性が高い）

### 手順1：次に“source候補”を棚卸し（設計/実装）
- URL、postMessage、Storage、Referrer、外部API結果、設定値（second-order）を列挙
- 各sourceに「攻撃者が制御可能か？」を付与（direct/second-order/不可）

### 手順2：ランタイムで“差分＝成立根拠”を取る（安全・低侵襲）
- 推奨：ブラウザ上で“DOMが再解釈される兆候”を観測し、フローを特定する
- 例：innerHTML等への代入が起きた瞬間をログに出す（検証環境で実施）

~~~~
/*
  検証用途（ローカル/検証環境でのみ）：
  危険sinkに値が入った瞬間を捕捉して、どのコードパスが書き込んだかを特定する。
*/
(() => {
  const desc = Object.getOwnPropertyDescriptor(Element.prototype, "innerHTML");
  if (!desc || !desc.set) return;

  Object.defineProperty(Element.prototype, "innerHTML", {
    set(v) {
      try { console.log("[sink] innerHTML <-", String(v).slice(0, 200)); } catch {}
      try { console.trace("[sink] stack"); } catch {}
      return desc.set.call(this, v);
    },
    get: desc.get,
    configurable: true,
    enumerable: desc.enumerable
  });
})();
~~~~

- これで言えること：
  - 実際にinnerHTMLへ代入が発生している（sinkが動いている）
  - どのコールスタック/コード経路で起きたか（修正ポイントが確定する）
- これで言えないこと：
  - 直ちに攻撃成立、ではない（sourceが攻撃者制御か・サニタイズの有無は別途確認）

### 手順3：被害者・導線・影響を確定（“攻撃より”の本体）
- 被害者：一般/運用/管理のどれが閲覧するか
- 導線：リンク誘導（URL）なのか、保存（Storage/設定）なのか、メッセージ（postMessage）なのか
- 影響：その被害者権限で何が操作できるか（重要操作に接続できるか）

---

## 次に試すこと（仮説A/B：条件で次の手が変わる）
### 仮説A：危険sink（innerHTML等）があり、sourceがURL/hash
- 次の一手：
  - hash（#）を含む入力で再現するか確認（hashはサーバログに残りにくい＝検知観点も含める）
  - sinkへ入る直前の加工（decode/replace/テンプレ）を特定し、サニタイズ/エンコードが欠落している箇所を確定

### 仮説B：sourceがpostMessageで、origin/スキーマ検証が弱い
- 次の一手：
  - message受信側で origin検証があるか（文字列比較だけか、許可リストか）
  - 受信データがどのsinkへ入るか（HTML/URL/コード）
  - 受信データの型拘束（JSON schema相当）がない場合、second-order化も疑う

### 仮説C：sourceがStorage（second-order）で、最初の格納は別機能
- 次の一手：
  - “格納する機能”と“読み出して描画する機能”を結び、再表示点の棚卸しへ拡張（格納XSSと同様の思考）
  - Storageへ書き込む条件（誰が、いつ、どの入力で）を特定し、権限境界（他ユーザへ波及）を評価

### 仮説D：innerHTMLは使っていないが、URL代入やテンプレ展開で崩れる
- 次の一手：
  - href/src/locationへの代入を棚卸しし、スキーム制限・正規化・許可リストを確認
  - “安全に見えるAPI”でも、入力の解釈が変わる箇所（テンプレ、属性）を中心に差分観測

---

## 防御設計（再発防止まで落とす：実務で効く順）
1) 危険sinkの禁止・統制（レビュー/CIで落とす）
- innerHTML等の利用を原則禁止し、例外は集中管理（レビュー必須）
- OWASPは「適切なsinkを使う」ことを対策の中心に置く

2) 安全APIへの統一（textContent等）＋標準サニタイズの一本化
- サニタイズが必要な要件（リッチテキスト等）だけ、標準サニタイズ関数＋許可リストで運用
- “各所で独自サニタイズ”は破綻しやすい（画面差分で抜ける）

3) CSP強化（可能ならnonce運用）＋第三者JS統制
- CSPは万能ではないが、DOM XSSの影響を抑える重要な層になり得る（特にscript実行面）
- 第三者JS（タグ、SDK）の許可範囲を最小化（供給鎖の境界）

4) ランタイム監視（検証/ステージング）
- 危険sinkへの代入を検知するテスト（ヘッドレス＋計測）をCIへ
- “DOMで再解釈が起きた”を早期に検出する

---

## 手を動かす検証（Labs連動：DOM XSSは“観測”が命）
- 追加候補Lab：
  - `04_labs/02_web/05_input/06_xss_dom_boundary/`
- 最小構成（現実寄り）
  - sourceを3種：URL hash / postMessage / localStorage
  - sinkを2種：危険（innerHTML）/安全（textContent）
  - 画面を2種：認証前（低影響）/認証後（高影響）で差を作る
- 取得する証跡
  - HAR（URL・遷移・外部ロード）
  - DevToolsログ（sinkフックのtrace）
  - CSPヘッダ（有無、強度）

---

## コマンド/例（例示は最小限：判断に必要な観測だけ）
~~~~
# 目的：DOM XSSはサーバ応答に出ない場合があるため、ブラウザ上でsource/sinkを観測する
# 1) 対象ページを開く
# 2) DevToolsで sink フック（本ファイルのスニペット）を入れる
# 3) URL hash や画面操作で値を変え、innerHTML代入の有無とスタックを取る
~~~~

---

## 参考（一次情報に近いもの中心）
- OWASP Cheat Sheet：DOM based XSS Prevention（安全sinkの選択が対策の核）
- MDN：Element.innerHTML の Security considerations（innerHTMLがXSSの主要ベクタ、script以外でも成立し得る）
- OWASP WSTG：Client-side Testing に DOM-Based XSS が含まれる（対象に入れる根拠）
- MITRE ATT&CK：Drive-by Compromise（T1189）
- PortSwigger：DOM-based XSS の概説（source→DOMへのunsafe書き戻し）

---

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/05_input_06_xss_01_反射_境界モデル.md`
- `01_topics/02_web/05_input_06_xss_02_格納_境界モデル.md`
- `01_topics/02_web/06_config_03_セキュリティヘッダ（CSP_HSTS_Frame_Referrer）.md`

---

## 次（作成候補順）
- `01_topics/02_web/05_input_07_csrf_01_token（synchronizer_double_submit）.md`
