# 再帰型ニューラルネットワーク（RNN: Recurrent Neural Network）

> **このファイルの位置づけ：** 系列データ処理の動作原理。テキスト系 AI（感情分析・コンテンツフィルター等）への回避攻撃や、時系列データを扱う異常検知システムへの攻撃を理解するための前提。


### 適用条件・選択基準
- 系列データ（テキスト、時系列、音声）の処理
- 過去の情報を考慮して現在の予測をしたいとき
- 翻訳・文章生成・感情分析・時系列予測
- 文中の単語の前後関係が重要な問題

### 観点・着眼点

**RNNの核心：隠れ状態（Hidden State）：**
```
hₜ = f(Wₕ × hₜ₋₁ + Wₓ × xₜ + b)
```
- `hₜ`：現在の隠れ状態（これまでの系列の「記憶」）
- `xₜ`：現在の入力
- 同じ重み `Wₕ, Wₓ` を全タイムステップで共有（パラメータ数が系列長に依存しない）

**RNNの問題点：**

- **勾配消失問題**：長い系列では、過去の情報が逆伝播の途中で薄れていく
- **長期依存性の弱さ**：「先週月曜日に行った店は___だった」のような長距離の文脈を保持しにくい

**LSTM（Long Short-Term Memory）：**

- 勾配消失を解決するために「ゲート機構」を導入した改良版RNN
- **3つのゲート**でセルの情報の流れを制御：
  - **忘却ゲート（Forget Gate）**：過去の情報をどれだけ忘れるか
  - **入力ゲート（Input Gate）**：新しい情報をどれだけ記憶するか
  - **出力ゲート（Output Gate）**：現在の隠れ状態として何を出力するか
- **セル状態（Cell State）**：情報の「高速道路」として長期記憶を維持

**GRU（Gated Recurrent Unit）：**

- LSTMを簡略化した版。ゲートが2つ（更新ゲート・リセットゲート）
- LSTMより計算コストが低く、多くの場合で同等の性能

**双方向RNN（Bidirectional RNN）：**

- 前向きと後ろ向きの2つのRNNを組み合わせる
- 文全体の文脈を使えるため、翻訳・固有表現認識に有効

**RNNの入出力パターン：**

| パターン | 説明 | 用途 |
|---------|------|------|
| Many-to-One | 系列 → 単一出力 | 感情分析、文書分類 |
| One-to-Many | 単一入力 → 系列 | 画像キャプション |
| Many-to-Many（同長） | 系列 → 系列 | 品詞タグ付け |
| Many-to-Many（異長） | 系列 → 系列（Seq2Seq） | 翻訳、要約 |

### 手順

```python
import torch.nn as nn

# LSTMの例
class TextClassifier(nn.Module):
    def __init__(self, vocab_size, embed_dim, hidden_dim, num_classes):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim)
        self.lstm = nn.LSTM(embed_dim, hidden_dim, 
                            num_layers=2, 
                            batch_first=True, 
                            dropout=0.3,
                            bidirectional=True)
        self.fc = nn.Linear(hidden_dim * 2, num_classes)  # bidirectionalなので×2
    
    def forward(self, x):
        embedded = self.embedding(x)
        output, (hidden, cell) = self.lstm(embedded)
        # 最後の隠れ状態を使って分類
        return self.fc(output[:, -1, :])
```

### 注意点・落とし穴

- **Transformerへの置き換え**：現代のNLPタスクではTransformerアーキテクチャ（BERT、GPT等）がRNN/LSTMを大幅に凌駕している。新しいNLPプロジェクトではTransformerを優先検討する。
- **並列化の難しさ**：RNNはタイムステップを順番に処理するため、GPUでの並列化が困難（Transformerはこの点で優れる）。
- **勾配クリッピング**：LSTMでも勾配爆発は起きる。`torch.nn.utils.clip_grad_norm_`で対応。
- **系列長の可変性**：バッチ処理で系列長が異なる場合はパディングとパック（`pack_padded_sequence`）が必要。

### RNNの現在の立ち位置

LSTMは長らくNLPの標準手法だったが、2017年のTransformer論文（"Attention is All You Need"）以降、NLPではTransformerが主流。一方、組み込みデバイスや低レイテンシが必要な時系列処理ではLSTM/GRUが今も使われている。

### 関連技術

- Transformerアーキテクチャ → `../Generative_AI/LLM.md`（Attentionメカニズム）
- CNN（系列処理への応用：1D CNN） → `./CNN.md`
- 時系列予測（ARIMA等の統計手法との比較）

> 原理（BPTT・LSTMゲート機構の数学的導出） → `../../06_Concepts/RNN_LSTM_Theory.md`
