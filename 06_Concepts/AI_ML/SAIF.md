# Google SAIF（Secure AI Framework）

> **このファイルの位置づけ：** AI アプリケーションのセキュアな開発・運用のための Google のフレームワーク。OWASP が「何を攻撃されるか（リスクの技術的チェックリスト）」を提供するのに対し、SAIF は「どこを守るか・誰が守るか（パイプライン全体の設計指針）」を提供する。評価の対象範囲を決める際や、防御側の責任分担を整理する際の参照として使う。
> ML OWASP Top 10 → `AI_Red_Teaming_Concepts.md`
> LLM OWASP Top 10 → `./Generative_AI/LLM_Attacks.md`

---

## SAIF と OWASP の位置づけの違い

| 観点 | OWASP（ML / LLM Top 10） | SAIF |
|------|------------------------|------|
| **アプローチ** | 技術的なリスクチェックリスト | AI パイプライン全体を通じたセキュア設計の指針 |
| **視点** | 攻撃者目線（何が攻撃されうるか） | 防御者目線（どこをどう設計・運用するか） |
| **責任の所在** | 明示されない | モデル作成者 / モデル利用者に割り当てられる |
| **スコープ** | 個別リスクの列挙 | データ収集からデプロイまでのパイプライン全体 |

---

## SAIF の 4 エリア構造

SAIF は AI アプリケーションを以下の 4 エリアに分解する。評価対象のシステムがどのエリアにまたがっているかを確認することで、攻撃面の見落としを防ぐ。

```
[Data] → [Infrastructure] → [Model] → [Application]
  ↓              ↓              ↓            ↓
データソース    学習・評価       モデル本体    アプリ・エージェント
フィルタリング  ストレージ      入出力処理    プラグイン
訓練データ     モデルサービング
```

| エリア | 含まれるコンポーネント | 主なリスク |
|--------|---------------------|----------|
| **Data** | データソース・データフィルタリング/処理・訓練データ | Data Poisoning・Unauthorized Training Data・Excessive Data Handling |
| **Infrastructure** | モデルフレームワーク/コード・学習/チューニング/評価・データ/モデルストレージ・モデルサービング | Model Source Tampering・Model Deployment Tampering・Model Exfiltration |
| **Model** | モデル本体・入力処理・出力処理 | Model Evasion・Sensitive Data Disclosure・Inferred Sensitive Data・Insecure Model Output |
| **Application** | アプリケーション・エージェント・プラグイン | Prompt Injection・Rogue Actions・Insecure Integrated Component |

---

## リスクの 3 つの観点：導入・露出・緩和

SAIF はリスクを発生する「フェーズ」で分けて考える。同じリスクでも、導入される場所と攻撃者がそれを利用できる場所、そして緩和を適用できる場所は異なる。

| 観点 | 意味 | 使い方 |
|------|------|--------|
| **リスク導入点（Risk Introduction）** | リスクがどのコンポーネントで生じるか | 防御の根本的な対処場所を特定する |
| **リスク露出点（Risk Exposure）** | リスクが攻撃者によって実際に悪用される場所 | 攻撃者目線でどこを突けるか判断する |
| **リスク緩和点（Risk Mitigation）** | リスクを軽減できるコンポーネント・タイミング | 多層防御の設計で複数の緩和点を設ける |

**例：Data Poisoning**
- 導入点：訓練データ（Data エリア）
- 露出点：推論 API（Model/Application エリア）— 汚染されたモデルが誤った出力を返す
- 緩和点：データフィルタリング（Data エリア）+ 敵対的訓練（Infrastructure エリア）

---

## SAIF 固有のリスク（OWASP に対応物がないもの）

以下は SAIF に含まれるが ML / LLM OWASP Top 10 に対応エントリがないリスク。

### Unauthorized Training Data

- **内容：** モデルが著作権・プライバシー・ライセンス上の問題がある無許可データで訓練される
- **影響：** 法的責任・著作権侵害・個人情報規制（GDPR 等）違反
- **着火条件：** 訓練データのソースが外部・公開データを含む場合、データプロバナンス（来歴）管理がない場合
- **確認ポイント：** 訓練データの出典・ライセンスの管理体制が存在するか

### Excessive Data Handling

- **内容：** プライバシーポリシーや関連規制が許容する範囲を超えてデータを収集・保持する
- **影響：** 法的・規制上の問題（GDPR・CCPA 等）、プライバシー侵害
- **着火条件：** AI システムがユーザーデータを学習・ロギング・保存する場合
- **確認ポイント：** 「このシステムは何のデータを・どの期間・なぜ保持しているか」が明文化されているか

### Model Source Tampering

- **内容：** モデルのソースコードまたは重みを直接改ざんする（ML OWASP ML10 Model Poisoning に対応するが、SAIF ではソースコードの改ざんも含む）
- **影響：** 精度の低下・バックドアの埋め込み
- **着火条件：** モデルのソースコードまたは重みファイルへの書き込みアクセスがある場合
- **Data Poisoning との区別：** Data Poisoning は学習データ経由で間接的にモデルを歪める。Model Source Tampering はモデル成果物（コード・重み）を直接改ざんする → `AI_Red_Teaming_Concepts.md`（ML10 Model Poisoning）

### Model Deployment Tampering

- **内容：** モデルのデプロイに使うコンポーネント（コンテナ・サービングインフラ・設定ファイル）を改ざんする
- **影響：** モデルの挙動変更・バックドアの挿入・サービス停止
- **着火条件：** CI/CD パイプライン・コンテナレジストリ・サービング設定へのアクセスがある場合
- **Model Source Tampering との区別：** Source Tampering はモデル自体を狙う。Deployment Tampering はモデルを取り囲むインフラを狙う

### Inferred Sensitive Data

- **内容：** モデルが直接アクセスできない機密情報を、訓練データやプロンプトのパターンから**推論して**出力する
- **影響：** 機密情報の間接的な漏洩
- **LLM02 Sensitive Information Disclosure との区別：**
  - Sensitive Information Disclosure：モデルが直接アクセスできる情報（コンテキスト・学習データの記憶）を吐き出す
  - Inferred Sensitive Data：モデルがアクセスできない情報を、統計的パターンから**推測**して出力する（例：訓練データの偏りから特定個人の属性を推定）
- **着火条件：** モデルが人口統計・医療・金融等のセンシティブなパターンを含むデータで訓練されている場合

---

## SAIF Controls — 責任分担付き緩和策

SAIF はリスクに対する緩和策（Control）を定義し、**モデル作成者（Model Creator）** と **モデル利用者（Model Consumer）** のどちらが実施責任を持つかを明示する。

| Control | 内容 | 対象リスク | 責任者 |
|---------|------|----------|--------|
| **Input Validation and Sanitization** | 悪意あるクエリを検出してブロックまたは制限する | Prompt Injection | 作成者・利用者 |
| **Output Validation and Sanitization** | モデル出力をアプリが処理する前に検証・サニタイズする | Prompt Injection, Rogue Actions, Sensitive Data Disclosure, Inferred Sensitive Data | 作成者・利用者 |
| **Adversarial Training and Testing** | 敵対的入力でモデルを訓練し、攻撃への耐性を高める | Model Evasion, Prompt Injection, Sensitive Data Disclosure | 作成者・利用者 |

**作成者 vs 利用者の責任区分を確認する意味：**

- 評価対象が「モデルを提供する側」なのか「モデルを使ったアプリを構築する側」なのかによって、どの Control を評価すべきかが変わる
- 利用者側は基盤モデルの作成者側 Control に依存している部分があるため、基盤モデルの選定時にその Control の実装状況を確認する必要がある

---

## 注意点・落とし穴

- **SAIF は防御設計フレームワーク：** 攻撃手法のリストではなく、設計指針。攻撃者目線では OWASP が先に参照すべき起点になる
- **Inferred Sensitive Data の見落とし：** 「モデルがデータにアクセスできない」ことを確認しても、推論による間接漏洩は防げない。訓練データに含まれるセンシティブなパターンの洗い出しが必要
- **Deployment Tampering は CI/CD 攻撃と連鎖：** モデルのデプロイパイプラインは従来の DevOps セキュリティリスクをそのまま持ち込む。ML 固有のリスクとは別軸で評価が必要

---

## 関連技術

- ML OWASP Top 10 との対応表 → `./AI_Red_Teaming_Concepts.md`
- LLM OWASP Top 10 との対応表 → `./Generative_AI/LLM_Attacks.md`
- Data Poisoning の詳細 → `./Data_Attacks.md`
- Model Poisoning / Model Source Tampering の詳細 → `./AI_Red_Teaming_Concepts.md`（ML10）
- Sensitive Information Disclosure の詳細 → `./Generative_AI/LLM_Attacks.md`（LLM02）
