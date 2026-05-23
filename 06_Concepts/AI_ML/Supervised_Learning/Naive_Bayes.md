# Naive Bayes（ナイーブベイズ）

> **このファイルの位置づけ：** 確率的分類器の動作原理。スパムフィルターや感情分析システムの迂回攻撃、テキストベースAIへのデータポイズニングを理解するための前提。


### 適用条件・選択基準
- テキスト分類（スパムフィルタリング、感情分析、ニュースカテゴリ分類）
- 高次元特徴量（多数の単語特徴量など）で学習データが少ないとき
- リアルタイム分類が必要で計算速度を優先するとき
- ベースラインモデルとして素早く試したいとき

### 観点・着眼点

**動作原理：**

- ベイズの定理に基づく確率的分類器
- 「ナイーブ（単純）」な仮定：**各特徴量がクラスに対して条件付き独立**であると仮定する

```
P(クラス|特徴量) ∝ P(クラス) × Π P(特徴量ᵢ|クラス)
```

- `P(クラス)`：事前確率（そのクラスがどれくらいの頻度で出現するか）
- `P(特徴量ᵢ|クラス)`：尤度（そのクラスのとき特徴量ᵢが出現する確率）
- 最も高い事後確率のクラスに分類

**バリアント：**

- **GaussianNB**：連続値特徴量。各クラス内でガウス分布を仮定
- **MultinomialNB**：離散カウントデータ（単語出現頻度など）。テキスト分類に最適
- **BernoulliNB**：2値特徴量（単語の有無など）

**テキスト分類での定番パイプライン：**
```
文書 → TF-IDF/CountVectorizer → MultinomialNB
```

### ベイズ式の各項の意味

スパム判定における `P(Spam|Features) = P(Features|Spam) × P(Spam) / P(Features)` の各項：

| 項 | 名前 | 意味 | スパム判定での意味 |
|----|------|------|-----------------|
| `P(Spam\|Features)` | **Hypothesis（事後確率）** | 求めたい答え | 「このメールの特徴を見た後で、スパムである確率」 |
| `P(Features\|Spam)` | **Likelihood（尤度）** | 逆方向の条件付き確率 | 「スパムメールにこの特徴が出現する確率」 |
| `P(Spam)` | **Prior（事前確率）** | 特徴を見る前の確率 | 「何も見ていない時点でスパムである確率」 |
| `P(Features)` | **Marginal Likelihood（周辺尤度）** | 正規化項 | 「スパム・非スパムを問わずこの特徴が出現する確率」 |

**Naive の仮定とは何か：**
特徴量 F1, F2 が互いに独立であると仮定することで、計算が積に分解できる。

```
P(F1, F2 | Spam) = P(F1|Spam) × P(F2|Spam)
```

現実には単語間に依存関係があるが（例：「not good」の「not」と「good」は独立ではない）、この単純化により計算コストが大幅に下がり、実用上は十分な精度が出ることが多い。

### 数値で追う計算例

**前提：** メールに特徴 F1・F2 が含まれる。スパムか否かを判定する。

```
P(Spam)        = 0.3   ← 全メールの 30% がスパム（事前確率）
P(Not Spam)    = 0.7

P(F1|Spam)     = 0.4   ← スパムメールの 40% に F1 が出る（尤度）
P(F2|Spam)     = 0.5
P(F1|Not Spam) = 0.2
P(F2|Not Spam) = 0.3
```

**Step 1：Naive 仮定で尤度を積に分解**

```
P(F1,F2|Spam)     = 0.4 × 0.5 = 0.20
P(F1,F2|Not Spam) = 0.2 × 0.3 = 0.06
```

**Step 2：全確率の定理で分母 P(F1,F2) を求める**

```
P(F1,F2) = P(F1,F2|Spam) × P(Spam) + P(F1,F2|Not Spam) × P(Not Spam)
         = 0.20 × 0.3 + 0.06 × 0.7
         = 0.060 + 0.042
         = 0.102
```

*P(F1,F2) は「どちらに分類されるかにかかわらず、この特徴が現れる確率」= 正規化のための定数。*

**Step 3：ベイズの定理で事後確率を計算**

```
P(Spam|F1,F2)     = (0.20 × 0.3) / 0.102 = 0.060 / 0.102 ≈ 0.588
P(Not Spam|F1,F2) = (0.06 × 0.7) / 0.102 = 0.042 / 0.102 ≈ 0.412
```

**Step 4：事後確率が高い方のクラスに分類**

```
0.588 > 0.412  →  スパム と判定
```

> **直感的な読み方：** 事前確率は「スパム 30%」だったが、F1・F2 という特徴を観察した後に「スパム 58.8%」へ更新された。特徴がスパムらしさの証拠として積み上がった結果。

### テキスト前処理パイプライン（NLP分類の共通手順）

ベクトル化（CountVectorizer / TF-IDF）の前に以下の順で処理する。

```python
import re, nltk
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer

nltk.download("punkt")
nltk.download("stopwords")

stemmer = PorterStemmer()
stop_words = set(stopwords.words("english"))

# Step 1: 小文字化 — "Free" と "free" を同じトークンとして扱う
df["message"] = df["message"].str.lower()

# Step 2: 記号・数字の除去 — ただしスパム文脈で意味を持つ $ ! は残す
df["message"] = df["message"].apply(lambda x: re.sub(r"[^a-z\s$!]", "", x))

# Step 3: トークン化 — 文字列をワードリストに分割
df["message"] = df["message"].apply(word_tokenize)

# Step 4: ストップワード除去 — "and" "the" "is" など意味を持たない語を削除
df["message"] = df["message"].apply(
    lambda x: [w for w in x if w not in stop_words]
)

# Step 5: ステミング — 語を語幹形に正規化
df["message"] = df["message"].apply(
    lambda x: [stemmer.stem(w) for w in x]
)

# Step 6: 文字列に戻す — TF-IDF等のベクトライザは文字列を期待する
df["message"] = df["message"].apply(lambda x: " ".join(x))
```

**ステミングとは何か（メモ：数式より直感で理解する）：**

同じ意味を持つ単語の表記揺れを統一する処理。`PorterStemmer` はルールベースで語尾を切り捨てる。

```
"running"  → "run"
"runner"   → "runner"   ← 完全には一致しないこともある
"runs"     → "run"
"fishing"  → "fish"
"fished"   → "fish"
```

**なぜ必要か：** Naive Bayes は「running と run は別の単語」として別々にカウントする。ステミングで統一しておかないと語彙サイズが無駄に大きくなり、同じ概念を表す単語が分散してしまう。

**注意点：** PorterStemmer は意味的な正しさより速度優先の粗削りな処理。`"university" → "univers"` のように意味が読み取りにくくなることがある。精度が重要な場合は **Lemmatization（見出し語化）** を検討する（`"running" → "run"` を品詞解析で正確に行う手法）。

**各ステップで情報が絞られる流れ：**

```
元の文 → 小文字化 → 記号除去 → [単語リスト] → ストップワード削除 → ステミング → "結合文字列"
           ↓              ↓           ↓                ↓                ↓
        大文字揺れ解消  数字ノイズ除去  構造化      非情報語を除去    語形の統一
```

### 手順

1. テキストの場合：上記パイプラインで前処理 → `CountVectorizer`または`TfidfVectorizer`で特徴量化
2. `MultinomialNB()`または`GaussianNB()`でfit
3. `predict_proba()`で各クラスの確率を確認
4. Precision/Recall/F1で評価（スパムフィルタはRecallを重視）
5. スムージング（`alpha`パラメータ）：訓練データに出現しなかった単語の確率を0にしない

### 注意点・落とし穴

- **独立性の仮定は現実には成立しない**：単語間には相関がある（例：「not good」の「not」と「good」）。しかし実用上は十分な精度が出ることが多い。
- **確率の正確さ**：絶対値の確率は信頼できないことが多い（確率キャリブレーションが悪い）。クラスの順位付けとして使う。
- **ゼロ頻度問題**：訓練データに出現しない特徴量の確率が0になる → ラプラススムージング（`alpha=1`）で対応。
- **連続値には不適**：GaussianNBを使うが、特徴量が非ガウス分布の場合は精度が低下する。

### 関連技術

- ロジスティック回帰（同じく確率的分類、独立性仮定なし） → `./Linear_Regression.md`
- SVM（テキスト分類でNaive Bayesと競合する手法） → `./SVM.md`
- TF-IDF / 単語ベクトル（特徴量表現）
- **CountVectorizer / Bag-of-Words の詳細（パラメータ・動作ステージ・bigram の効果）** → `./Feature_Extraction.md`
- **Pipeline・GridSearchCV・joblib（学習・チューニング・モデル保存の一連フロー）** → `./Model_Training_Pipeline.md`
- **Naive Bayes の独立性仮定を突いた Overpowering 攻撃（テキスト分類器回避）** → `../Adversarial_Examples.md`

> 原理（ベイズの定理・条件付き確率の導出） → `../../06_Concepts/Bayes_Theorem.md`
