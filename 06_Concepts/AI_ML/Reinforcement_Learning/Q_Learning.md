# Q-Learning

> **このファイルの位置づけ：** Q-Learning の動作原理。RLエージェントの学習過程への攻撃（報酬関数の操作・経験データのポイズニング）や、Q値テーブルを標的とした攻撃を理解するための前提。


### 適用条件・選択基準
- 離散的な状態空間と行動空間を持つ問題（テーブルサイズが現実的な場合）
- 環境のモデル（遷移確率・報酬関数）が未知でもよい（モデルフリー）
- ゲームAI（Tic-Tac-Toe、迷路等）、簡単なロボット制御
- 強化学習の基礎アルゴリズムとして理解が必要なとき

### 観点・着眼点

**動作原理：**

- 状態sで行動aをとったときの「Q値」（期待累積報酬）を反復的に更新するテーブル学習
- **Qテーブル**：行が状態、列が行動の表。各セルがQ値
- 行動選択：各状態でQテーブルの最大値の行動を選択（+探索）

**Q値更新式（Bellmanの最適方程式）：**
```
Q(s, a) ← Q(s, a) + α × [r + γ × max_a' Q(s', a') - Q(s, a)]
```
- `α`：学習率（0〜1）。大きいほど新しい情報を重視
- `γ`：割引率（0〜1）。将来の報酬の重み
- `r`：即時報酬
- `s'`：遷移後の次の状態
- `max_a' Q(s', a')`：次の状態での最大Q値（**オフポリシー**：実際に選ぶ行動と無関係に最大値を使う）

**学習フロー：**
1. Qテーブルをすべて0で初期化
2. 環境をリセット（初期状態 s を取得）
3. ε-greedyで行動 a を選択
4. 行動を実行して報酬 r と次の状態 s' を観測
5. Q値を更新式で更新
6. s ← s' として繰り返す
7. エピソード終了まで継続、多数のエピソードを繰り返す

**オフポリシー（Off-Policy）の特徴：**

- 実際に取った行動（ε-greedyによる探索行動）ではなく、**最適な行動**のQ値を使って更新
- 探索中でも最適方策に向けて学習が進む → 収束が速い

### 手順

```python
import numpy as np

# Qテーブルの初期化
Q = np.zeros((n_states, n_actions))
alpha, gamma, epsilon = 0.1, 0.9, 0.1

for episode in range(n_episodes):
    state = env.reset()
    done = False
    while not done:
        # ε-greedy行動選択
        if np.random.random() < epsilon:
            action = env.action_space.sample()  # 探索
        else:
            action = np.argmax(Q[state])         # 活用
        
        next_state, reward, done, _ = env.step(action)
        
        # Q値更新
        Q[state, action] += alpha * (
            reward + gamma * np.max(Q[next_state]) - Q[state, action]
        )
        state = next_state
```

### 注意点・落とし穴

- **状態空間の爆発**：状態数が多すぎるとQテーブルのサイズが現実的でなくなる。連続状態空間にはDQN（Deep Q-Network）を使う。
- **εの設定**：εが高すぎると学習が遅く、低すぎると局所解に陥る。訓練初期は大きく、徐々に減衰させる（ε decay）。
- **収束の遅さ**：Q値の更新が徐々に伝播するため、大きな状態空間では収束に時間がかかる。
- **決定的な環境が前提**：確率的な遷移でも動作するが、収束が遅くなる。

## 関連技術

- SARSA（オンポリシー版のQ-learning） → `./SARSA.md`
- Deep Q-Network（DQN：Q-learningとニューラルネットワークの組み合わせ）
- 強化学習の全体像 → `./RL_Overview.md`

> 原理（Bellman方程式・最適性の証明） → `../../06_Concepts/Bellman_Equation.md`
