# 異常検知（Anomaly Detection）

> **このファイルの位置づけ：** 異常検知システムの動作原理。侵入検知・不正検知システムへの回避攻撃（AI Evasion）を設計するための直接的な前提。「正常に見える」攻撃トラフィックの生成原理を理解するために参照する。


### 適用条件・選択基準
- 通常のパターンから外れた異常なデータ点を自動的に検出したいとき
- ネットワーク侵入検知・不正アクセス検出
- 金融不正検知（クレジットカード詐欺）
- 製造業での製品品質異常検知
- ログ解析で異常なアクティビティを検出したいとき
- 正常データは大量にあるが異常データが少ない・ラベルがないとき

### 観点・着眼点

**異常検知の種類：**

- **点異常（Point Anomaly）**：単一のデータ点が正常範囲から外れている
- **文脈異常（Contextual Anomaly）**：文脈（時系列等）の中で見たときだけ異常
- **集合異常（Collective Anomaly）**：個々の点は正常でも、グループとして異常

**主要アルゴリズム：**

**1. 統計的手法（Gaussian / Z-score）：**

- 各特徴量がガウス分布に従うと仮定
- 平均からの標準偏差が一定以上（通常3σ）離れていれば異常
- 着火条件：データが正規分布に近い場合
- 限界：多変量の相関を考慮しない

**2. Isolation Forest：**

- ランダムな分割を繰り返して、少ないステップで孤立するデータ点を異常とみなす
- 異常点はデータが疎な領域にあるため、短い経路長で孤立する
- 着火条件：高次元データ、ラベルなし、混合型データ
- scikit-learnの`IsolationForest`で使いやすい

**3. One-Class SVM：**

- 正常データのみで学習し、その分布から外れた点を異常と判定
- カーネルトリックで非線形な境界も学習可能
- 着火条件：正常データのみ利用可能、非線形な正常パターン

**4. Autoencoder（再構成誤差）：**

- ニューラルネットワークで正常データを圧縮→復元するよう学習
- 異常データは正常パターンで学習していないため、再構成誤差が大きくなる
- 着火条件：複雑なパターン、大量の正常データがある場合

**5. LOF（Local Outlier Factor）：**

- 近傍の密度と比較して、密度が極端に低い点を異常とみなす
- 局所的な密度の違いを考慮できる

### 手順（Isolation Forestの例）

1. 正常データで学習（異常データが混在していても動作する）
   ```python
   from sklearn.ensemble import IsolationForest
   clf = IsolationForest(contamination=0.01, random_state=42)
   clf.fit(X_train)
   ```
2. `predict()`でスコアを取得（-1=異常、1=正常）
3. `contamination`パラメータ：全データに含まれる異常の割合の見積もり
4. スコアに基づいて閾値を調整（ROC曲線を描いてAUCで評価）

### 注意点・落とし穴

- **閾値の設定が難しい**：何%を異常とみなすか（`contamination`）は事前知識が必要。偽陽性と偽陰性のトレードオフを調整する。
- **ラベルなし評価の難しさ**：正解ラベルがないと精度評価が困難。少量の既知の異常を評価データとして保持しておく。
- **クラス不均衡の極端さ**：正常:異常の比率が1000:1などのケースが多い。通常の分類器で学習すると「全部正常」と予測するだけで高精度になってしまう。
- **分布の変化（コンセプトドリフト）**：時系列データでは正常パターンが変化することがある。定期的なモデル再学習が必要。
- **セキュリティ文脈での限界**：攻撃者が「正常に見える」行動（Living off the Land）を取ると検知が難しい。

### セキュリティ用途との関連

- ネットワークトラフィックの異常検知：通常のポートスキャンやC2通信を正常トラフィックから分離
- 認証ログ解析：異常な時間帯・場所からのログインを検出
- → これらはルールベース（SIEM）とML異常検知の組み合わせが現実的

---

## ランダムフォレストによるネットワーク侵入検知（教師あり異常検知）

### 着火条件

- 正常・異常の**ラベル付きデータ**が手元にある（教師あり設定）
- 高次元のネットワーク特徴量（40超のカラム等）を扱っており、単純な統計的手法では対応できない
- 特徴量重要度を確認し「どのネットワーク指標が攻撃判断に効いているか」を把握したい

### 観点・着眼点

教師なし手法（Isolation Forest等）との使い分け：

| 条件 | 推奨手法 |
|------|---------|
| ラベルなし・正常データのみ | Isolation Forest / One-Class SVM |
| ラベルあり・正常と攻撃の両方 | Random Forest（教師あり） |
| 攻撃種別まで分類したい | Random Forest（多クラス分類） |

**ランダムフォレストが侵入検知に向く理由：**

- 高次元データ（40以上の特徴量）でも過学習しにくい
- カテゴリ変数（プロトコル種別・サービス種別）と数値変数が混在していても対応しやすい
- `feature_importances_` で「どの特徴量が攻撃判断に寄与しているか」が可視化できる

### NSL-KDD データセットの特徴量構造

ネットワーク侵入検知の標準ベンチマークデータセット。KDD Cup 1999 の冗長エントリ・クラス不均衡を改善したもの。42 の特徴量 + 攻撃種別ラベルで構成される。

**特徴量カテゴリ：**

| カテゴリ | 代表的なカラム | 意味 |
|---------|-------------|------|
| 基本統計 | `duration`, `src_bytes`, `dst_bytes` | 接続時間・送受信バイト数 |
| プロトコル | `protocol_type`, `service`, `flag` | TCP/UDP/ICMP・対象サービス・接続状態 |
| コンテンツ特徴 | `num_failed_logins`, `root_shell`, `su_attempted` | 認証失敗回数・root昇格試行 |
| トラフィック統計 | `serror_rate`, `rerror_rate`, `same_srv_rate` | エラー率・同一サービスへの接続率 |
| 宛先ホスト統計 | `dst_host_count`, `dst_host_serror_rate` | 同一宛先への接続数・エラー率 |
| ラベル | `attack`, `level` | 攻撃種別・重篤度 |

**`attack` カラムの値例（二値化で使う場合）：**
```python
# 正常/異常の二値ラベルに変換
df['attack_flag'] = df['attack'].apply(lambda a: 0 if a == 'normal' else 1)
```

**多クラス攻撃カテゴリへのマッピング：**

二値分類（正常 vs 異常）よりも粒度を上げ、攻撃の種類まで分類する場合に使う。
NSL-KDD の攻撃カテゴリ定義は公式スキーマを参照：https://www.unb.ca/cic/datasets/nsl.html

| ラベル値 | 攻撃カテゴリ | 特徴 |
|---------|------------|------|
| 0 | Normal | 正常トラフィック |
| 1 | DoS | サービス妨害。大量パケットによる過負荷・接続枯渇 |
| 2 | Probe | ポートスキャン・ネットワーク偵察。攻撃の前段として使われる |
| 3 | Privilege Escalation | バッファオーバーフロー等による権限昇格 |
| 4 | Access | 認証情報の推測・不正アクセス |

```python
# 各カテゴリに属する attack 値のリストは NSL-KDD 公式スキーマを参照して定義する
# dos_attacks / probe_attacks / privilege_attacks / access_attacks の4リストを用意する

def map_attack(attack, dos_attacks, probe_attacks,
               privilege_attacks, access_attacks):
    if attack in dos_attacks:           return 1
    elif attack in probe_attacks:       return 2
    elif attack in privilege_attacks:   return 3
    elif attack in access_attacks:      return 4
    else:                               return 0  # normal

df['attack_map'] = df['attack'].apply(
    lambda a: map_attack(a, dos_attacks, probe_attacks,
                         privilege_attacks, access_attacks)
)
```

**カテゴリ変数のエンコードと特徴量行列の構築：**

```python
# protocol_type・service を one-hot encoding（順序関係を持たせない）
features_to_encode = ['protocol_type', 'service']
encoded = pd.get_dummies(df[features_to_encode])

# NSL-KDD の数値特徴量（カテゴリ列・ラベル列を除いた統計値カラム群）と結合
# 使用するカラムの完全リストは公式スキーマの numeric 列を参照
numeric_features = [col for col in df.columns
                    if col not in features_to_encode + ['attack', 'attack_flag',
                                                         'attack_map', 'level']]

train_set = encoded.join(df[numeric_features])
multi_y = df['attack_map']
```

> `flag` 列は LabelEncoder より one-hot の方が望ましいが、探索段階では `get_dummies` でまとめて処理しても支障ない。本番 Pipeline では `OneHotEncoder` を使う → `../../Data_Transformation.md`

### 評価ワークフロー（Validation → Test の2段階）

**着火条件：** モデルの学習が完了し、汎化性能を測定したい段階。

**手順：**

1. **Validation set で初期評価** → 指標を確認し問題があれば特徴量・ハイパーパラメータを調整
2. **Test set で最終評価** → Validation に過学習していないか確認するため、必ず分離したデータで最後に1回だけ評価する
3. **Confusion Matrix で誤分類パターンを可視化** → どのクラスをどのクラスと間違えているか確認

```python
from sklearn.metrics import confusion_matrix, classification_report
import seaborn as sns
import matplotlib.pyplot as plt

class_labels = ['Normal', 'DoS', 'Probe', 'Privilege', 'Access']

# Confusion Matrix の可視化
conf_matrix = confusion_matrix(y_true, predictions)
sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues',
            xticklabels=class_labels, yticklabels=class_labels)
plt.title('Network Anomaly Detection')
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.show()

# per-class の詳細レポート
print(classification_report(y_true, predictions, target_names=class_labels))
```

**Confusion Matrix の読み方：**

- **対角線上の値** = 正しく分類できた数（大きいほど良い）
- **行** = 実際のクラス / **列** = モデルが予測したクラス
- 行 i・列 j の値が大きい → クラス i のサンプルをクラス j と誤分類している
- 例：Privilege 行の Normal 列が大きい → 権限昇格攻撃を正常通信と見誤っている

**weighted avg / macro avg の乖離に注意：**

- 乖離が大きい場合はクラス不均衡のシグナル → `../../Overview.md` の「classification_report の読み方」を参照
- `support` 列が小さいクラス（< 50 程度）の指標は統計的に不安定。単独で判断しない

### 関連技術

- PCA（次元削減してから異常検知） → `./PCA.md`
- K-Meansクラスタリング（クラスタから外れた点を異常とみなす） → `./KMeans_Clustering.md`
- Autoencoder → `../Deep_Learning/Neural_Networks.md`
- Random Forest（教師あり異常検知・特徴量重要度） → `../Supervised_Learning/Decision_Trees.md`
- classification_report の読み方・weighted avg vs macro avg → `../../Overview.md`

> 原理（異常スコアの統計的な意味・ROC/AUCの解釈） → `../../06_Concepts/Anomaly_Detection_Theory.md`
