# 畳み込みニューラルネットワーク（CNN: Convolutional Neural Network）

> **このファイルの位置づけ：** CNN の動作原理。画像認識システムへの敵対的サンプル攻撃（人間には見えない微小な摂動で誤分類を引き起こす）を理解するための前提。AI Evasion 系モジュール全般で参照する。


### 適用条件・選択基準
- 画像・動画データの分類・検出・セグメンテーション
- 入力データに局所的なパターンがある（空間的または時間的な局所構造）
- テキスト分類（1D CNN）、音声認識
- 転移学習の出発点（ImageNetで事前学習済みモデルの活用）

### 観点・着眼点

**全結合層との違い：**

- 全結合層（MLP）：全ての入力ニューロンと全ての出力ニューロンが接続。画像の空間構造を無視。
- CNNは「局所的な受容野（Receptive Field）」で処理：画像の空間的な近傍のみを見る

**CNNの3つの核心的操作：**

**1. 畳み込み層（Convolutional Layer）：**

- 小さなフィルター（カーネル）を画像全体にスライドさせて特徴マップを生成
- フィルターは「エッジ検出」「テクスチャ」「形状」などの特徴を自動学習
- `num_filters`個のフィルターで`num_filters`個の特徴マップを出力
- パラメータ：`kernel_size`（フィルターのサイズ）、`stride`（スライド幅）、`padding`（境界処理）

**2. プーリング層（Pooling Layer）：**

- 特徴マップを縮小（空間サイズを小さく）する
- **Max Pooling**：領域内の最大値を残す（位置のわずかなズレに頑健）
- 計算量削減と位置不変性の向上

**3. 全結合層（Fully Connected Layer）：**

- 畳み込み・プーリングで抽出した特徴を使って最終的な分類を行う
- 通常、最後の1〜2層に配置

**層が深くなるにつれて学習される特徴の変化：**

- 浅い層：低レベルの特徴（エッジ、色のグラデーション）
- 中間の層：中レベルの特徴（テクスチャ、形状の一部）
- 深い層：高レベルの特徴（目、顔、物体の一部）

**主要なCNNアーキテクチャ：**

| モデル | 特徴 | 用途 |
|--------|------|------|
| LeNet | CNNの先駆け。小規模 | 手書き数字認識（MNIST） |
| AlexNet | 深層CNNの普及に貢献 | ImageNet分類 |
| VGGNet | シンプルな3×3フィルターの積み重ね | 転移学習のベースモデル |
| ResNet | 残差接続で超深層ネットワークを実現 | 最も広く使われる |
| EfficientNet | 深さ・幅・解像度のバランスを最適化 | 高精度・効率的 |

**転移学習（Transfer Learning）：**

- ImageNetで事前学習した重みを流用し、自分のタスク用に微調整（Fine-tuning）
- データが少ない場合に特に有効

### 手順

```python
import torch.nn as nn

class SimpleCNN(nn.Module):
    def __init__(self, num_classes):
        super().__init__()
        self.features = nn.Sequential(
            nn.Conv2d(3, 32, kernel_size=3, padding=1),  # 3ch→32ch
            nn.ReLU(),
            nn.MaxPool2d(2, 2),                           # 空間サイズを1/2
            nn.Conv2d(32, 64, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.MaxPool2d(2, 2)
        )
        self.classifier = nn.Sequential(
            nn.Flatten(),
            nn.Linear(64 * 8 * 8, 512),
            nn.ReLU(),
            nn.Dropout(0.5),
            nn.Linear(512, num_classes)
        )
    
    def forward(self, x):
        return self.classifier(self.features(x))
```

**転移学習の例（ResNet）：**
```python
import torchvision.models as models
model = models.resnet50(pretrained=True)
# 最終層のみを自タスクに合わせて変更
model.fc = nn.Linear(2048, num_classes)
```

### 注意点・落とし穴

- **大量の学習データが必要**：CNNはパラメータ数が多く、データが少ないと過学習する。転移学習を活用する。
- **計算コスト**：深いCNNの学習にはGPUが実質的に必須。
- **データ拡張（Data Augmentation）が重要**：ランダムなフリップ・回転・クロップで訓練データを水増しして汎化性能を上げる。
- **カーネルサイズの選択**：3×3フィルターを積み重ねる方が、大きなフィルターより効率的で表現力も高い（VGGNetの教訓）。
- **バッチ正規化（BN）を使う**：BNなしでは深いネットワークの学習が不安定になりやすい。

### セキュリティへの応用：マルウェア分類

#### マルウェアファミリーと分類の基礎

**マルウェアファミリー：** 動作特性・コード構造・目的が共通するマルウェアのグループ単位。
代表例：Emotet（バンキングトロイ→スパムボット）、WannaCry（ランサムウェア）。
ファミリー情報の参照先：https://malpedia.caad.fkie.fraunhofer.de/

**マルウェア分類に使う特徴量の3種別：**

| 種別 | 内容 | 例 |
|------|------|-----|
| 行動・機能的特徴 | 実行時に何をするか | ファイル暗号化・C2通信・キーロギング |
| 配送・伝播手法 | どう広がるか | メール添付・ドライブバイダウンロード・ワーム的自己複製 |
| 技術的特徴 | バイナリ構造・コード特性 | セクション構成・インポートテーブル・パッカー種別 |

**手動分類（従来手法）の限界：**

- 静的解析（逆コンパイル・文字列抽出）と動的解析（サンドボックス実行）を組み合わせて行う
- リバースエンジニアリングは時間コストが高く、スケールしない
- ML分類器はこの工程を自動化・高速化する手段として機能する

**手法選択の観点：**

| 状況 | 推奨手法 |
|------|---------|
| バイナリ自体を安全に扱えない | 画像ベースMLによる静的分類 |
| 実行環境が確保できる | 動的解析（サンドボックス）+ 行動ログをMLで分類 |
| シグネチャ未登録の亜種を検出したい | バイトプロット画像 or 特徴量ベースML（シグネチャ非依存） |

---

#### バイトプロット（Byteplot）によるマルウェア画像分類

**着火条件：** バイナリファイル（実行可能ファイル等）を機械学習で静的分類したい場合。逆コンパイルや動的実行をせずに判定したいとき。

**概念：**

- バイナリファイルの各バイト値（0〜255）をピクセル値として並べ、グレースケール画像（バイトプロット）として可視化する
- マルウェアファミリーごとに独特の視覚的パターンが現れる（コード構造・暗号化セクション・パッカーの痕跡など）
- このグレースケール画像をCNNで分類することで、シグネチャに依存しないマルウェア検出が実現できる

**画像ベース分類の安全性上の利点：**

- 実際の実行可能バイナリを直接扱わないため、解析環境がマルウェアに感染するリスクがない
- 画像ファイルとして処理するため、隔離環境（サンドボックス）なしで作業できる

**特徴：**

- 解析の早期段階で適用でき、実行環境を汚染しない
- 難読化やパッキングを施されたバイナリでも視覚的特徴が残る場合がある
- 転移学習（ResNet等）を用いることで、少ないサンプル数でも分類精度が上がりやすい

**注意点：**

- 高度な難読化・ポリモーフィック型マルウェアでは視覚的特徴が崩れ、精度が落ちる
- バイナリサイズによって画像の縦横比が変わるため、リサイズの方法がモデル精度に影響する

---

#### Malimg データセット（画像ベースマルウェア分類のベンチマーク）

**着火条件：** 画像ベースのマルウェア分類器を学習・評価する際の標準データセットとして参照する。

**データセット取得：**

```bash
# Kaggle API 経由で取得
wget https://www.kaggle.com/api/v1/datasets/download/ikrambenabd/malimg-original -O malimg.zip
unzip malimg.zip
# → malimg_paper_dataset_imgs/<ファミリー名>/ の構成で展開される
```

論文および公式ページは Kaggle 上の `ikrambenabd/malimg-original` を参照。

**データセット構造：**

- 9,339枚・25クラス（マルウェアファミリー単位）のグレースケール PNG 画像
- 各画像は Windows PE ファイル（実行可能バイナリ）をバイト単位で可視化したもの
- 1ピクセル = 1バイト（値 0→黒、255→白、中間→グレー）
- ロスレスエンコーディング：画像からバイナリを完全再現可能（情報損失なし）
- フォルダ構成：`malimg_paper_dataset_imgs/<ファミリー名>/` 形式でクラスごとに分離
- **同ファミリーのサンプルは視覚的に識別可能なパターンを共有している**（コードセクションの繰り返し構造・暗号化ブロックの濃淡パターンなど）

**クラス分布の EDA → 意思決定フロー：**

```
① クラスごとのサンプル数を集計
② 水平バープロットで可視化（クラス数が多いため horizontal が読みやすい）
③ 過剰・不足クラスを目視で特定
④ 学習後の精度が期待値を下回る場合 → 学習前にデータセットを調整する
```

```python
import os
import matplotlib.pyplot as plt
import seaborn as sns

DATA_BASE_PATH = "./malimg_paper_dataset_imgs/"

# ① クラス分布の集計
dist = {cls: len(os.listdir(os.path.join(DATA_BASE_PATH, cls)))
        for cls in os.listdir(DATA_BASE_PATH)}

# ② 水平バープロット（クラス名が長い・クラス数が多い場合は orient='h' が標準）
classes = list(dist.keys())
counts  = list(dist.values())

plt.figure(figsize=(8, 10))
sns.barplot(y=classes, x=counts, orient='h')
plt.title("Malware Class Distribution")
plt.xlabel("Samples")
plt.ylabel("Malware Family")
plt.tight_layout()
plt.show()
```

**観点・着眼点：**

| 確認するシグナル | 次のアクション |
|---------------|--------------|
| 特定クラスのサンプル数が他の 5 倍以上 | そのクラスの weighted avg が全体 accuracy を引き上げている可能性 → macro avg で評価 |
| 精度・F1 が期待値を下回る | 不均衡クラスにオーバーサンプリング or クラス重み付き損失を適用してから再学習 |
| macro avg ≪ weighted avg | 少数クラスの recall が低い → クラス不均衡が原因と判断できる |

- Malimg では `Allaple.A`・`Allaple.L` 系が他ファミリーと比較して大幅にサンプル数が多い
- 不均衡への対策：データ拡張・オーバーサンプリング（imbalanced-learn）・`CrossEntropyLoss(weight=...)` でクラス重みを指定する

---

#### PyTorch 実装パイプライン（マルウェア画像分類）

**着火条件：** Malimg 等の画像ベースマルウェアデータセットを PyTorch で学習・推論する場合。

**ステップ1：データ分割（split-folders）**

```bash
pip install split-folders
```

```python
import splitfolders

# 80% train / 20% test に分割。val フォルダは空になる
splitfolders.ratio(
    input="./malimg_paper_dataset_imgs/",
    output="./newdata/",
    ratio=(0.8, 0, 0.2)
)
# 出力: ./newdata/train/, ./newdata/val/, ./newdata/test/
```

- `ratio` の第2引数が 0 だと val フォルダは空で作成される（使わない場合はこのまま）
- 分割はランダムのため、実行ごとにテスト精度が変わりうる

**分割後の検証（実行前後にファイル数を確認する）：**

```bash
# 期待した比率で分割されているか確認
find ./data/train/ -type f | wc -l
find ./data/test/  -type f | wc -l
# → train : test ≈ 80 : 20 になっていればOK
```

- スクリプト化するなら `len(os.listdir(...))` で Python 内でも確認できる

**ステップ2：前処理 transform と DataLoader の構築**

```python
from torchvision import transforms
from torchvision.datasets import ImageFolder
from torch.utils.data import DataLoader
import os

# ImageNet 事前学習済みモデルが期待する正規化値を使う
transform = transforms.Compose([
    transforms.Resize((75, 75)),           # 全画像を同サイズに統一
    transforms.ToTensor(),                 # PIL → Tensor（値 0-1 に正規化）
    transforms.Normalize(
        mean=[0.485, 0.456, 0.406],        # ImageNet の RGB 平均
        std=[0.229, 0.224, 0.225]          # ImageNet の RGB 標準偏差
    )
])

train_dataset = ImageFolder(root=os.path.join(BASE_PATH, "train"), transform=transform)
test_dataset  = ImageFolder(root=os.path.join(BASE_PATH, "test"),  transform=transform)

train_loader = DataLoader(train_dataset, batch_size=512, shuffle=True,  num_workers=2)
test_loader  = DataLoader(test_dataset,  batch_size=1024, shuffle=False, num_workers=2)

n_classes = len(train_dataset.classes)  # データから動的にクラス数を取得
```

- `Resize(75, 75)` は速度優先の小サイズ。精度が不足する場合は `(224, 224)` に変更する
- `ImageFolder` はフォルダ名をクラスラベルとして自動認識する（フォルダ構成がラベルになる）
- `n_classes` をハードコードせず動的取得することで、クラス追加・削除後もコードが壊れない

**前処理後の画像を可視化して変換結果を確認する：**

```python
# DataLoader から1バッチ取り出して最初の1枚を表示
sample = next(iter(train_loader))[0][0]   # shape: (C, H, W) = PyTorch のチャネルファースト形式

# matplotlib は HWC（チャネル最後）を期待するため permute で次元を並べ替える
plt.imshow(sample.permute(1, 2, 0))       # (C, H, W) → (H, W, C)
plt.show()
```

- PyTorch の Tensor は常に `(C, H, W)` 形式。matplotlib は `(H, W, C)` を期待するため `permute(1, 2, 0)` が必須
- Normalize 後の値域は `[-1, 1]` 付近になるため、そのまま表示すると色調がずれる（確認目的に留める）
- リサイズを小さくするほど細部（テクスチャ・エッジ）が失われる。前処理後の画像を実際に確認することで、サイズ選択が分類に十分か判断できる

**前処理・DataLoader を関数化して再利用可能にするパターン：**

```python
def load_datasets(base_path, train_batch_size, test_batch_size):
    """
    前処理・ImageFolder・DataLoader をまとめて構築する。
    train_loader, test_loader, n_classes を返すので、
    モデル定義・学習スクリプトから1行で呼び出せる。
    """
    transform = transforms.Compose([
        transforms.Resize((224, 224)),           # ここでサイズを一元管理
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.485, 0.456, 0.406],
                             std=[0.229, 0.224, 0.225])
    ])
    train_ds = ImageFolder(root=os.path.join(base_path, "train"), transform=transform)
    test_ds  = ImageFolder(root=os.path.join(base_path, "test"),  transform=transform)

    train_loader = DataLoader(train_ds, batch_size=train_batch_size, shuffle=True,  num_workers=2)
    test_loader  = DataLoader(test_ds,  batch_size=test_batch_size,  shuffle=False, num_workers=2)

    n_classes = len(train_ds.classes)
    return train_loader, test_loader, n_classes
```

- Resize サイズ・batch_size を引数化しておくと実験時にパラメータを外から差し替えやすい
- `shuffle=True`（train）と `shuffle=False`（test）は固定。テスト時にシャッフルすると評価の再現性が失われる
- `num_workers` は CPU コア数に合わせて増やすと DataLoader のボトルネックを減らせる。Windows では `0` にしないとエラーになることがある

**ステップ3：ResNet50 転移学習モデルの定義**

**モデル選択の根拠（ResNet50 を選ぶ条件）：**

| 条件 | ResNet50 が適合する理由 |
|------|----------------------|
| 入力が画像データ | 画像分類タスクで実績のある代表的アーキテクチャ |
| データ量が限られている | ImageNet で学習済みの特徴抽出器を流用できる（転移学習） |
| 訓練コストを抑えたい | 全層 freeze + 最終層のみ学習で訓練時間を大幅短縮 |
| PoC・プロトタイプ段階 | 50 層・約 2,300 万パラメータと十分な表現力を持ちながら扱いやすい |

- ResNet50 は「残差接続（Residual Connection）」によって 50 層の深さでも勾配消失を回避している
- 同ファミリーに ResNet18（軽量・高速）、ResNet101/152（高精度・低速）があり、速度と精度のトレードオフで選択する

```python
import torch.nn as nn
import torchvision.models as models

class MalwareClassifier(nn.Module):
    def __init__(self, n_classes, hidden_size=1000):
        super().__init__()
        self.resnet = models.resnet50(weights='DEFAULT')  # ImageNet 学習済み重みを使用
        # 特徴抽出層をすべて freeze（最終 FC 層のみ学習対象）
        for param in self.resnet.parameters():
            param.requires_grad = False
        # 最終 FC 層を差し替え：in_features を動的に読み取る
        # → ResNet18/34/101 等に変更してもコードが壊れない
        num_features = self.resnet.fc.in_features  # ResNet50 は 2048
        self.resnet.fc = nn.Sequential(
            nn.Linear(num_features, hidden_size),
            nn.ReLU(),
            nn.Linear(hidden_size, n_classes)
        )

    def forward(self, x):
        return self.resnet(x)
```

- **全層 freeze の理由：** ImageNet 学習済みの特徴抽出器はそのまま流用できる。分類ヘッドのみ学習することで、数日〜数週間単位かかる訓練コストを数十分に短縮できる
- **trade-off：** 全層 freeze は訓練速度を最大化するが精度の上限が下がる。精度重視なら freeze を解除するか一部だけ unfreeze（最終数ブロックを学習対象にする）する
- `weights='DEFAULT'` は最新の推奨済み重みを自動選択（`pretrained=True` は非推奨）
- **`fc.in_features` を動的に読み取るパターン：** ResNet50 は `2048`、ResNet18/34 は `512` と variant ごとに異なる。ハードコードせず `model.fc.in_features` で読み取れば、バックボーンを変更してもコードが壊れない

**ステップ4：訓練ループ**

```python
import torch
import time

def compute_accuracy(n_correct, n_total):
    return round(100 * n_correct / n_total, 2)

def train(model, train_loader, n_epochs, verbose=False):
    model.train()   # ← Dropout・BatchNorm を訓練モードに切り替える（必須）
    criterion = torch.nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters())

    # エポックごとのメトリクスを記録しておく（後で訓練曲線を描くため）
    history = {"accuracy": [], "loss": []}

    for epoch in range(n_epochs):
        running_loss, n_total, n_correct = 0, 0, 0
        t0 = time.time()
        for inputs, labels in train_loader:
            optimizer.zero_grad()
            outputs = model(inputs)
            loss = criterion(outputs, labels)
            loss.backward()
            optimizer.step()
            _, predicted = outputs.max(1)
            n_total       += labels.size(0)
            n_correct     += predicted.eq(labels).sum().item()
            running_loss  += loss.item()

        epoch_acc  = compute_accuracy(n_correct, n_total)
        epoch_loss = running_loss / len(train_loader)
        history["accuracy"].append(epoch_acc)
        history["loss"].append(epoch_loss)

        if verbose:
            elapsed = int((time.time() - t0) * 1000)
            print(f"[Epoch {epoch+1}/{n_epochs}] Acc: {epoch_acc:.2f}%  "
                  f"Loss: {epoch_loss:.4f}  ({elapsed} ms)")
    return history
```

- **`model.train()` は訓練開始時に必ず呼ぶ**。`model.eval()` を使った後に再度訓練するケースで忘れやすい
- `optimizer.zero_grad()` → `loss.backward()` → `optimizer.step()` の順序は必須
- `outputs.max(1)` で予測クラスのインデックスを取得（戻り値の第1要素は max 値自体で不要）
- `compute_accuracy()` を独立させることで evaluate ループからも再利用できる
- `history` dict にエポックごとの値を貯めておくと、訓練後に曲線を描いて収束・過学習を診断できる

**ステップ5：単体推論と評価**

```python
def predict(model, data):
    """バッチデータに対する予測クラスを返す（evaluate から分離しておくと再利用しやすい）"""
    model.eval()
    with torch.no_grad():
        output = model(data)
        _, predicted = torch.max(output, 1)
    return predicted

def evaluate(model, test_loader):
    """テストセット全体の accuracy を返す"""
    model.eval()
    n_correct, n_total = 0, 0
    with torch.no_grad():
        for data, target in test_loader:
            predicted  = predict(model, data)
            n_total   += target.size(0)
            n_correct += (predicted == target).sum().item()
    return compute_accuracy(n_correct, n_total)
```

- `predict()` を分離することで、単一サンプルの推論・混同行列の作成・可視化など evaluate 以外の用途にも流用できる
- `model.eval()` は Dropout・BatchNorm を推論モードに切り替える（忘れると精度が不安定になる）
- `torch.no_grad()` は勾配グラフを生成せずメモリ使用量を削減する

**ステップ6：モデルの保存**

```python
def save_model(model, path):
    """TorchScript 形式で保存する（デプロイ時に Python 環境が不要になる）"""
    model_scripted = torch.jit.script(model)
    model_scripted.save(path)
```

- `torch.jit.script` はモデルのコードをコンパイルして保存する。`torch.save(model.state_dict(), ...)` より移植性が高い
- ロード時は `torch.jit.load(path)` を使う（クラス定義が不要）

**ステップ7：訓練曲線の可視化と診断**

```python
import matplotlib.pyplot as plt

def plot_history(history, metric="accuracy"):
    """history dict から訓練曲線を描く"""
    data = history[metric]
    plt.figure()
    plt.plot(range(1, len(data) + 1), data, marker='o')
    plt.title(f"Training {metric.capitalize()} per Epoch")
    plt.xlabel("Epoch")
    plt.ylabel(metric.capitalize())
    plt.grid(True)
    plt.show()

# 使い方
plot_history(history, "accuracy")
plot_history(history, "loss")
```

**訓練曲線の読み方：**

| 曲線の形状 | 診断 | 対処 |
|-----------|------|------|
| Accuracy が右肩上がりで収束 | 正常な学習 | エポック数を増やして上限を探る |
| Accuracy が途中で横ばい | 学習率が低い・容量不足 | lr を上げる・hidden_size を増やす |
| 終盤で Accuracy が下がる | 過学習の兆候 | Dropout 追加・Data Augmentation |
| Loss が下がらない | 勾配消失・lr が大きすぎる | lr を小さくする・BN を追加する |
| 訓練精度 ≫ テスト精度（8% 以上乖離） | 過学習 | 正則化・データ拡張・freeze 解除の見直し |

**ステップ8：ハイパーパラメータの集約パターン**

実験を繰り返す場合、パラメータをスクリプト冒頭に集約しておくと変更箇所が一目でわかる：

```python
# ── ハイパーパラメータ（ここだけ変えれば実験できる）──
DATA_PATH          = "./data/"
N_EPOCHS           = 10
TRAIN_BATCH_SIZE   = 512
TEST_BATCH_SIZE    = 1024
HIDDEN_LAYER_SIZE  = 1000
MODEL_SAVE_PATH    = "classifier.pth"

# ── パイプライン ──
train_loader, test_loader, n_classes = load_datasets(
    DATA_PATH, TRAIN_BATCH_SIZE, TEST_BATCH_SIZE)
model    = MalwareClassifier(n_classes, hidden_size=HIDDEN_LAYER_SIZE)
history  = train(model, train_loader, N_EPOCHS, verbose=True)
save_model(model, MODEL_SAVE_PATH)
accuracy = evaluate(model, test_loader)
print(f"Test accuracy: {accuracy}%")
plot_history(history, "accuracy")
plot_history(history, "loss")
```

- パラメータを定数として宣言することで、同じコードで異なる設定を試せる
- `verbose=True` にすると各エポックの精度・損失・時間が出力される（訓練中の監視用）

**性能参考値（Malimg・10 エポック・全層 freeze・Resize 75×75）：**

| エポック | 訓練精度 | 備考 |
|---------|---------|------|
| 1 | ~57% | 最終FC層の初期収束フェーズ |
| 3 | ~89% | 実用的な最低ラインの目安 |
| 10 | ~96% | 訓練データでの精度 |
| — | **~88.5%** | テストデータでの精度（汎化性能） |

- 訓練精度とテスト精度の約 8% 乖離は過学習の兆候。より強い Dropout や Data Augmentation を追加する余地がある
- 精度はデータ分割のランダムシードに依存するため実行ごとに変わりうる

**注意点・落とし穴：**

- グレースケール画像（1ch）を ImageNet 学習済みモデル（3ch 期待）に入力する際は、PNG を RGB 変換するか `transforms.Grayscale(3)` で 3ch に複製する必要がある
- `num_workers` を増やすと高速化するが、Windows 環境では `num_workers=0` にしないとエラーになる場合がある
- バッチサイズを大きくすると GPU メモリ不足になりやすい。512 → 256 → 128 と下げて調整する

---

### 関連技術

- ニューラルネットワーク基礎 → `./Neural_Networks.md`
- RNN（系列データ処理との組み合わせ：ビデオ認識等） → `./RNN.md`
- 物体検出（YOLO、Faster R-CNN等）：CNNを骨格に使う
- セグメンテーション（U-Net等）
- 異常検知（ネットワークトラフィック分類等）→ `../Unsupervised_Learning/Anomaly_Detection.md`

> 原理（畳み込み演算・受容野・パラメータ共有の数学的意味） → `../../06_Concepts/CNN_Theory.md`
