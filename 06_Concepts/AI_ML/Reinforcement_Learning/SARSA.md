# SARSA（State-Action-Reward-State-Action）

> **このファイルの位置づけ：** オンポリシー強化学習の動作原理。Q-Learning との違い（安全性・収束性）を理解することで、どのような攻撃シナリオで各アルゴリズムへの攻撃が有効かを判断できる。


### 適用条件・選択基準
- Q-Learningと同じく離散的な状態・行動空間の強化学習問題
- **安全性が重要**な実世界環境（危険な探索を避けたい場合）
- 学習中の実際の挙動も最適化したいとき（探索コストが高い問題）
- Q-LearningとSARSAの違いを理解・比較したいとき

### 観点・着眼点

**Q-LearningとSARSAの最大の違い：**

| 特徴 | Q-Learning | SARSA |
|------|-----------|-------|
| 方策タイプ | **オフポリシー（Off-Policy）** | **オンポリシー（On-Policy）** |
| 更新に使う次の行動 | 最大Q値の行動（仮想的な最適行動） | 実際に選択した行動 |
| 安全性 | 探索時の危険を無視 | 探索時の危険も考慮 |
| 収束先 | 最適方策のQ値 | ε-greedy方策のQ値 |

**SARSA更新式：**
```
Q(s, a) ← Q(s, a) + α × [r + γ × Q(s', a') - Q(s, a)]
```
- `Q(s', a')`：**実際に次のステップで選択した行動 a' のQ値**（最大値ではない）
- `(s, a, r, s', a')`の5つ組が名前の由来

**なぜ「オンポリシー」なのか：**

- 更新に使うのは「実際に取る行動 a'」のQ値
- 探索（ε-greedy）で危険な行動をとった場合、その行動の低いQ値が反映される
- 結果として、危険を避ける方向に学習が進む

**Q-LearningとSARSAの挙動の違い（崖の例）：**

- 崖のそばを通る経路：Q-Learningは最短経路を学習するが、探索中に崖に落ちる。SARSAは探索の安全性を考慮して崖から遠ざかる。

### 手順

```python
for episode in range(n_episodes):
    state = env.reset()
    # SARSAでは最初の行動をここで選ぶ
    if np.random.random() < epsilon:
        action = env.action_space.sample()
    else:
        action = np.argmax(Q[state])
    
    done = False
    while not done:
        next_state, reward, done, _ = env.step(action)
        
        # 次の行動も今選ぶ（実際に選択する行動）
        if np.random.random() < epsilon:
            next_action = env.action_space.sample()
        else:
            next_action = np.argmax(Q[next_state])
        
        # SARSA更新：next_actionのQ値を使う（最大値ではない）
        Q[state, action] += alpha * (
            reward + gamma * Q[next_state, next_action] - Q[state, action]
        )
        state, action = next_state, next_action
```

### 注意点・落とし穴

- **収束先の違い**：SARSAはε-greedy方策のQ値に収束する（ε=0にしない限り最適方策には収束しない）。εを徐々に0に近づける（ε decay）ことで最適解に近づける。
- **安全性と効率性のトレードオフ**：SARSAは安全だが、Q-Learningより学習効率が悪いことが多い。
- **Q-Learningとの使い分け**：実環境でシミュレーション不可能な場合はSARSA。シミュレーションで事前学習できる場合はQ-Learningが有利。

### 関連技術

- Q-Learning（オフポリシー版との比較） → `./Q_Learning.md`
- 強化学習の全体像 → `./RL_Overview.md`

> 原理（オン・オフポリシーの収束性の違い） → `../../06_Concepts/Bellman_Equation.md`
