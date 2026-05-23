# データ変換（Data Transformation）

> **このファイルの位置づけ：** ML モデルに投入する前段階のデータ加工に関する原理。カテゴリ変数のエンコーディング・分布の偏り補正・データ分割を扱う。モデルの精度・安定性はこの前処理の質に強く依存するため、攻撃側から見れば前処理パイプラインも攻撃対象になる（詳細 → `Data_Attacks.md`）。

---

## カテゴリ特徴量のエンコーディング

### 着火条件

- データセットにカテゴリ変数（文字列・ラベル型の列）が含まれており、ML モデルへ投入する前に数値変換が必要な場合
- 攻撃側: ターゲットモデルの入力形式を推定するためにエンコーディング手法の特定が必要な場合

### 観点・着眼点

ML アルゴリズムは数値演算を前提とするため、カテゴリ値をそのままでは処理できない。変換手法によって「カテゴリ間に順序関係が生まれるかどうか」が変わる点が核心。

| エンコーダー | 動作 | 使いどころ | リスク |
|------------|------|---------|------|
| **OneHotEncoder** | 各カテゴリを独立したバイナリ列に変換 | カテゴリ間に順序がない場合（例: プロトコル名、色） | カテゴリ数が多いと列数が爆発する（次元の呪い） |
| **LabelEncoder** | 各カテゴリに整数コードを割り当て | 順序付きカテゴリ（例: low/medium/high） | 順序のないカテゴリに使うと「赤=1 < 青=2」のような誤った大小関係をモデルに学習させてしまう |
| **HashingEncoder** | ハッシュ関数で整数に変換 | カテゴリのユニーク値が非常に多い場合（高カーディナリティ） | ハッシュ衝突が起きると異なるカテゴリが同じ値になる |

### 手順（One-Hot Encoding の例）

```python
from sklearn.preprocessing import OneHotEncoder
import pandas as pd

encoder = OneHotEncoder(handle_unknown='ignore', sparse_output=False)
encoded = encoder.fit_transform(df[['protocol']])
encoded_df = pd.DataFrame(encoded, columns=encoder.get_feature_names_out(['protocol']))

# 元の列を除去して置き換える
df = pd.concat([df.drop('protocol', axis=1), encoded_df], axis=1)
```

**何が起きているか：** `protocol` 列に `tcp`・`udp`・`icmp` の3種類があれば、`protocol_tcp`・`protocol_udp`・`protocol_icmp` の3列が生成される。各行はどれか1列だけ `1`、残りは `0` になる。

**`pd.get_dummies` を使う簡易版（pandas）：**

```python
import pandas as pd

# 複数列をまとめて one-hot encoding（sklearn 不要）
features_to_encode = ['protocol_type', 'service']
encoded = pd.get_dummies(df[features_to_encode])

# 数値特徴量と結合して最終的な特徴量行列を作る
train_set = encoded.join(df[numeric_features])
```

`get_dummies` は列名を `元の列名_カテゴリ値`（例: `protocol_type_tcp`）として自動生成する。`OneHotEncoder` より記述が短いが、推論時に訓練時と同じカラム構成を保証する仕組みがないため、本番環境・Pipeline 組み込みには `OneHotEncoder` が安全。

| 手法 | 適したケース |
|------|------------|
| `pd.get_dummies` | 探索・前処理スクリプトの素早い記述 |
| `sklearn.OneHotEncoder` | Pipeline 組み込み・推論時の列整合保証が必要な場合 |

### 注意点・落とし穴

- **LabelEncoder を順序のないカテゴリに使わない。** モデルが誤った大小関係を学習する原因になる
- **エンコード後のカラム名が変わる**ことに注意。後続の処理でカラム参照している場合はズレる
- `handle_unknown='ignore'` オプションを付けると、学習時に見ていない未知カテゴリが来ても無視する（付けないとエラーになる）
- `get_dummies` は訓練・テストでカテゴリの出現に差があると列数が一致しなくなる。`reindex(columns=train_columns, fill_value=0)` で揃える
- エンコード後に変換が意味のある列になっているか確認する（自動変換を盲目的に信用しない）

---

## 歪み（Skewness）の補正

### 着火条件

- 数値特徴量の分布が極端に偏っており（外れ値が多い・ロングテール）、モデルの精度や安定性に影響が疑われる場合
- 攻撃側: 外れ値領域に攻撃データを紛れ込ませることで、変換前後でのモデルの感度差を利用したい場合

### 観点・着眼点

分布の歪みがある特徴量では、少数の極端な値がモデルの学習を支配する。対数変換は大きな値を小さく圧縮し、小さな値への影響を最小限に抑える。これにより分布が均され、モデルが全データをバランスよく扱える。

```
変換前: [1, 2, 5, 1000, 5000]  ← 大きな値が支配的
変換後: [0.69, 1.10, 1.79, 6.91, 8.52]  ← 差が圧縮された
```

### 手順

```python
import numpy as np

# log1p = log(1 + x)。ゼロ値があっても log(0) にならない
df["bytes_transferred"] = np.log1p(df["bytes_transferred"])
```

**なぜ `log1p` を使うか：** `log(0)` は数学的に未定義（負の無限大）のため、ゼロを含む可能性がある列に `np.log` を直接使うとエラーまたは `-inf` が発生する。`+1` することでこれを回避する。

### 注意点・落とし穴

- **負の値を含む列には log 変換を使わない。** log(負の数) は虚数になる
- 変換前後で分布の形状を確認する（ヒストグラム等）。変換で歪みが改善されているか必ず目視確認する
- log 変換がすべての歪みに有効とは限らない。Box-Cox 変換や平方根変換が適する場合もある
- **スケーリング（StandardScaler 等）と混同しない。** スケーリングは値の範囲を揃える操作。歪みの補正とは別の目的

---

## データ分割（Data Splitting）

### 着火条件

- モデルを学習・評価する前に、データセットを用途別に分割する必要がある場合
- 攻撃側: ターゲットモデルがどのデータで評価されているかを把握し、テストセットへのアクセス・汚染を狙う場合

### 観点・着眼点

モデルの性能評価を正直に行うために、学習に使ったデータで評価することを防ぐ。テストセットは「モデルが一度も見たことのないデータ」として厳密に管理する必要があり、これを破ると評価が楽観的になる（**データ漏洩 / Data Leakage**）。

| セット | 用途 | 典型的な比率 |
|--------|------|-----------|
| **Training Set** | モデルのパラメータを学習する | 60〜80% |
| **Validation Set** | ハイパーパラメータ調整・モデル選択に使う | 10〜20% |
| **Test Set** | 最終評価にのみ使う。チューニング中は触れない | 10〜20% |

### 手順

```python
from sklearn.model_selection import train_test_split

X = df.drop("threat_level", axis=1)  # 特徴量
y = df["threat_level"]               # 正解ラベル

# Step 1: 80% を訓練用・20% をテスト用に分割
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=1337
)

# Step 2: 訓練用の 80% をさらに分割（75%:25% = 全体の 60%:20%）
X_train, X_val, y_train, y_val = train_test_split(
    X_train, y_train, test_size=0.25, random_state=1337
)

# 結果: 全体の 60% 訓練 / 20% バリデーション / 20% テスト
```

**なぜ 2 回に分けるか：** `train_test_split` は 2 グループにしか分けられない。まず Train+Val と Test に分け、次に Train+Val を Train と Val に分けることで 3 分割を実現する。

### 注意点・落とし穴

- **テストセットを絶対に先に見ない。** 「テストで精度を確認してモデルを調整」を繰り返すとテストセットへの間接的な漏洩になる
- `random_state` を固定しないと毎回異なる分割になり、実験の再現ができない
- **前処理（スケーリング・エンコーディング）は Train セットだけで fit し、Val/Test には transform のみ適用する。** Val/Test のデータを fit に使うとデータ漏洩になる

```python
# 正しい例
scaler.fit(X_train)          # Train だけで fit
X_train = scaler.transform(X_train)
X_val   = scaler.transform(X_val)   # fit はしない
X_test  = scaler.transform(X_test)  # fit はしない
```

---

## 関連技術

- データ品質への攻撃（ポイズニング） → `./Data_Attacks.md`
- データ漏洩（Data Leakage）の防止 → `./Overview.md`
- 異常検知への応用（bytes_transferred 等の特徴量設計） → `./Unsupervised_Learning/Anomaly_Detection.md`
