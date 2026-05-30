# 大規模言語モデル（LLM: Large Language Models）

> **このファイルの位置づけ：** LLM・Transformer の動作原理。プロンプトインジェクション・LLM Output Attacks・ジェイルブレイクの仕組みを理解するための直接的な前提。プロンプトがどのようにトークン列として処理されるかを把握することが攻撃設計の出発点になる。


### 適用条件・選択基準
- テキスト生成・要約・翻訳・質問応答・コード生成
- 文脈を理解した自然言語処理タスク全般
- Few-shot / Zero-shot でタスクに対応したいとき（ファインチューニング不要）
- 独自データでカスタムLLMを構築したいとき（RAG, Fine-tuning）

### 観点・着眼点

**LLMの基盤：Transformerアーキテクチャ：**

**Attentionメカニズム（自己注意機構）：**
```
Attention(Q, K, V) = softmax(QKᵀ / √dₖ) × V
```
- **Q（Query）**：「今この単語は何に注目しているか」
- **K（Key）**：「この単語はどんな情報を持っているか」
- **V（Value）**：「実際に渡す情報」
- 任意の距離にある単語の関係を直接計算できる（RNNの長期依存性問題を解決）

**Multi-Head Attention：**

- 複数のAttentionヘッドを並列に動かし、異なる側面の関係を同時に学習
- 「文法的な関係」「意味的な関係」「代名詞の参照先」など複数の依存関係を把握

**Transformerの構成：**
```
入力文 → トークン化 → 埋め込み → Positional Encoding
    → [Self-Attention + Feed-Forward] × N層
    → 出力
```
- **Positional Encoding**：順序情報を付加（RNNと違い並列処理なので位置情報を明示的に注入）

**GPT系（デコーダのみ）vs BERT系（エンコーダのみ）：**

| 特徴 | GPT系 | BERT系 |
|------|-------|--------|
| アーキテクチャ | デコーダ | エンコーダ |
| 学習目標 | 次の単語予測（自己回帰） | マスクされた単語の予測 |
| 用途 | テキスト生成、対話 | 分類、情報抽出 |
| 推論方式 | Left-to-right（逐次生成） | 双方向文脈理解 |

**スケーリング則（Scaling Laws）：**

- パラメータ数・データ量・計算量を増やすほど性能が向上する（べき乗則）
- GPT-3（1750億パラメータ）以降、規模の大きさが性能を左右

**In-Context Learning（コンテキスト内学習）：**

- **Zero-shot**：説明のみで新しいタスクを実行
- **Few-shot**：数例のデモンストレーションを見せてタスクを実行
- 重みの更新なしにプロンプトだけで対応できる

**実用的な活用パターン：**

**RAG（Retrieval-Augmented Generation）：**

- LLMの知識制限をベクトルDBからの検索で補完
- 手順：質問 → ベクトル検索で関連文書を取得 → 文書+質問をLLMに渡して回答生成
- ハルシネーション（事実と異なる生成）の抑制に効果的

**Fine-tuning（微調整）：**

- 事前学習済みモデルを特定のタスク・ドメインのデータで追加学習
- **LoRA（Low-Rank Adaptation）**：全パラメータを更新せずに少数の追加パラメータのみ更新。計算コストを大幅削減

### 手順（API経由の利用）

```python
from anthropic import Anthropic
client = Anthropic()

response = client.messages.create(
    model="claude-opus-4-6",
    max_tokens=1024,
    messages=[
        {"role": "user", "content": "Explain transformer architecture briefly"}
    ]
)
print(response.content[0].text)
```

### 注意点・落とし穴

- **ハルシネーション（Hallucination）**：LLMは存在しない事実を自信満々に生成することがある。重要な情報は必ず外部ソースで検証する。
- **コンテキスト長の限界**：モデルごとに処理できる最大トークン数がある。長文の場合はチャンク分割やRAGが必要。
- **プロンプト設計（Prompt Engineering）が重要**：同じモデルでもプロンプトの書き方で性能が大きく変わる。明確な指示・例示・出力形式の指定が有効。
- **知識カットオフ**：事前学習データには時間的な上限がある。最新情報はRAGや検索ツールで補完する。
- **コスト**：APIの利用料はトークン数に比例する。長いプロンプトは高くなる。

**セキュリティとの関連：**

- **プロンプトインジェクション攻撃**：ユーザー入力にシステムプロンプトを上書きする指示を埋め込む攻撃
- **LLMを使った攻撃支援**：コード生成機能を使ったマルウェア生成、フィッシングメール自動化
- **AIモデルのポイズニング**：学習データに悪意あるデータを混入させてモデルの挙動を操作
- **LLM 固有の攻撃分類（LLM OWASP Top 10）** → `LLM_Attacks.md`

## 関連技術

- Transformerの前身 → `../Deep_Learning/RNN.md`
- Diffusionモデル（画像生成の主流手法） → `./Diffusion_Models.md`
- RAGの実装にはベクトルデータベース（Pinecone, ChromaDB等）

> 原理（Attentionメカニズムの数学的導出・Positional Encodingの設計） → `../../06_Concepts/Transformer_Theory.md`
