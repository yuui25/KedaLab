# 決定木（Decision Trees）

> **このファイルの位置づけ：** 決定木・アンサンブル学習の動作原理。ランダムフォレスト・勾配ブースティングを使った分類・異常検知システムへの攻撃（データポイズニング・回避）を理解するための前提。


### 適用条件・選択基準
- 分類・回帰のどちらでも使える汎用的な手法が必要なとき
- 非線形な決定境界が必要なとき（ロジスティック回帰が効かない場合）
- 結果の解釈性・可視化が重要なとき（「なぜその予測になったか」を説明したい）
- カテゴリ変数が多く含まれるデータ

### 観点・着眼点

**動作原理：**

- 特徴量の値に基づいて、データを再帰的に分割するツリー構造を学習
- 各分岐点（内部ノード）：「特徴量Xが閾値T以下か？」という質問
- 各葉ノード：最終的な予測値（分類ならクラス、回帰なら平均値）

**分割基準（不純度指標）：**

- **ジニ不純度（Gini Impurity）**：分類問題でよく使われる。`1 - Σpᵢ²`
- **情報利得（Information Gain）**：エントロピーの減少量。`H(parent) - weighted_avg(H(children))`
- **分散（Variance Reduction）**：回帰問題での分割基準

**アルゴリズム系統：**

- **ID3 / C4.5**：情報利得を使う古典的アルゴリズム
- **CART（Classification and Regression Trees）**：ジニ不純度を使う。scikit-learnのデフォルト

**アンサンブル拡張（重要）：**

- **ランダムフォレスト（Random Forest）**：複数の決定木を並列に学習し多数決。過学習に強い
- **勾配ブースティング（Gradient Boosting）**：弱い決定木を逐次的に積み上げる。XGBoost、LightGBMが代表

**ランダムフォレストの構築3要素：**

1. **Bootstrapping（ブートストラップサンプリング）**：訓練データから「復元抽出」で複数のサブセットを生成し、それぞれ別の決定木を学習する。各ツリーが異なるデータで学習されるため多様性が生まれる。
2. **特徴量のランダムサブセット**：各分岐点で「全特徴量の一部」だけをランダムに選んで最良分割を探す。全特徴量を使うと強い特徴量に偏ったツリーばかりになり木間の相関が高くなる。これを防ぐことで多様性を確保する。
3. **Voting / Averaging**：分類タスクでは各ツリーの多数決、回帰タスクでは平均値を最終予測とする。

**異常検知への応用（教師あり）：**

正常データのみで学習し、新しいデータ点がその正常パターンに当てはまらない（予測確率が低い）場合に異常とフラグを立てる。Isolation Forest などの教師なし手法と比較して、正常ラベルが大量に入手できる場合に有効。ネットワーク侵入検知（正常トラフィック → 通常運用、異常トラフィック → 攻撃）で典型的に使われる。

### 手順

1. データの前処理（決定木はスケーリング不要だが欠損値は処理が必要）
2. `DecisionTreeClassifier(max_depth=N)`でfit
3. `max_depth`・`min_samples_leaf`でツリーの複雑さを制御
4. `plot_tree()`または`export_graphviz()`で可視化して分岐を確認
5. `feature_importances_`で重要な特徴量を確認
6. テストデータで精度評価

**ランダムフォレストを使う場合：**

```python
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

rf = RandomForestClassifier(
    n_estimators=100,   # ツリーの本数
    random_state=42
)
rf.fit(X_train, y_train)

y_pred = rf.predict(X_test)
print(classification_report(y_test, y_pred))

# 特徴量重要度の確認（どの特徴量が判断に寄与しているか）
importances = rf.feature_importances_
```

`feature_importances_` はネットワーク侵入検知において、どのトラフィック特徴量（バイト数・エラー率等）が異常判断に最も効いているかを把握するのに役立つ。

### 注意点・落とし穴

- **過学習しやすい**：深さ制限なしで学習すると訓練データに完全適合する。`max_depth`または`min_samples_split`で制限する。
- **不安定性**：データの小さな変化でツリー構造が大きく変わることがある。ランダムフォレストで安定化。
- **軸平行な境界のみ**：決定木の決定境界は軸に平行な直線のみで構成される。斜め方向の境界が必要な場合は苦手。
- **クラス不均衡**：`class_weight='balanced'`で対応。

## 関連技術

- ランダムフォレスト（決定木のアンサンブル）
- 勾配ブースティング（XGBoost・LightGBM）
- SVMと比較：非線形境界は両方対応するが、解釈性は決定木が優れる → `./SVM.md`
- SUID/特権昇格での自動化判断ロジックの可視化ツールとして参考になる考え方

> 原理（情報エントロピー・ジニ不純度の導出） → `../../06_Concepts/Decision_Tree_Impurity.md`
