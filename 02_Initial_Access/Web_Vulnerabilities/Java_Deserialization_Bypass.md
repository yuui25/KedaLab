# Java デシリアライズ allowlist バイパス

> 原理 → `../../06_Concepts/Java_Deserialization.md`

---

### 着火条件

以下が揃った Java アプリケーションを対象にするとき：

- ネットワーク経由で Java オブジェクトのデシリアライズを行っている
- `ObjectInputStream`（またはそのラッパーライブラリ）を使用している
- allowlist（許可クラスリスト）による防御が実装されている
- `resolveClass()` のみが override されており `resolveProxyClass()` が未 override

**着火の優先度**: allowlist が実装されている = 「防御しているつもり」の状態。
その前提を崩せると判断した場合に試みる。

---

### 環境前提

- 実行環境: テスター端末
- 必要なツール:
  - `ysoserial`（Java デシリアライズガジェットチェーン生成ツール。別途インストール要、インターネットアクセス要）
  - `Java`（JDK 8 以上）
  - オフライン代替: ガジェットチェーンをバイト列として手動構築（高難度）

---

### 観点・着眼点

**先に確認すること:**

1. エンドポイントが Java デシリアライズを受け付けているか
   - バイト列先頭 `AC ED 00 05`（16進）= Java シリアライズデータのマジックバイト
   - `Content-Type: application/x-java-serialized-object`
2. allowlist が実装されているか（通常クラスを送って `ClassNotFoundException` に "not allowed" / "accept" 等の文言があるか）
3. ターゲット JVM のクラスパスに既知のガジェットライブラリがあるか

**攻撃者の思考トレース**:
allowlist で通常クラスが弾かれる = `resolveClass()` は保護されている。
では `resolveProxyClass()` は？ → Java の仕様上この2つは別のコードパス。
片方だけ守っても Proxy 形式で送れば通る可能性がある。

**何が出たら次に何をするか:**

| シグナル | 次のアクション |
|---|---|
| 通常クラス送信 → `not in accept list` / `not allowed` 等のエラー | allowlist が動作確認 → Proxy バイパスを試みる |
| Proxy 送信 → エラーなし / デシリアライズ成功 | allowlist バイパス確認 → ガジェットチェーンへ進む |
| Proxy 送信 → `not allowed` と同じメッセージ | `resolveProxyClass()` も保護済み → この手法は使えない |
| RCE 確認 → `id` の出力 / DNS コールバック受信 | 侵入後の列挙へ → `03_Post_Access_Linux/Enumeration_Checklist.md` |

---

### 手順

#### Step 1: エンドポイント確認

```
# [Attacker]
# Java シリアライズのマジックバイトを確認（バイナリ先頭）
hexdump -C [CAPTURED_REQUEST_BODY] | head -3
# 出力例: ac ed 00 05 ... → Java シリアライズデータ
```

#### Step 2: allowlist の動作確認（対照実験）

通常クラスのシリアライズデータを送り、エラーメッセージを確認する。

```
# [Attacker] ランダムな通常クラスを送信して応答を観察
# エラーに "not in accept list" / "not allowed" 等が含まれれば allowlist が動作している
```

#### Step 3: Proxy バイパスの試行

Java の `Proxy.newProxyInstance()` を使い、allowlist 外のインターフェースを持つ
Proxy オブジェクトをシリアライズしてエンドポイントに送信する。

```java
// [Attacker] Proxy オブジェクトの生成イメージ
// インターフェースに allowlist 外のクラスを指定
Object proxy = Proxy.newProxyInstance(
    classLoader,
    new Class[]{[NON_ALLOWLISTED_INTERFACE]},
    handler
);
// シリアライズして送信
```

**確認ポイント**: 通常クラスは弾かれるがこの Proxy が素通りした場合 = allowlist バイパス確認。

#### Step 4: ガジェットチェーンで RCE

クラスパス上にガジェットライブラリが存在する場合、ysoserial でペイロードを生成して送信する。

```bash
# [Attacker] ysoserial でガジェットペイロード生成
java -jar ysoserial.jar [GADGET_NAME] "[COMMAND]" > payload.bin

# エンドポイントに送信（プロトコルに応じて調整）
```

コールバック受信が必要な場合:
- DNS コールバック: `[ATTACKER_IP]` でリスナーを立ててコールバックを受信する
- リバースシェル: `../../06_Concepts/Reverse_Shell.md`（攻撃側の準備①②）を参照

---

### 攻撃側の準備（必要な場合）

**DNS コールバック受信:**
```bash
# [Attacker] tcpdump でDNSコールバックを受信
tcpdump -i [INTERFACE] port 53
```

**リバースシェル受信:**
```bash
# [Attacker] nc でリバースシェルを待ち受け
nc -lvnp [PORT]
```

---

### 刺さらなかったとき

| 条件不成立のシグナル | 判断と次の手 |
|---|---|
| Proxy 送信も `resolveProxyClass()` でブロックされる | 両経路が保護済み → この手法は使えない |
| ガジェットライブラリがクラスパスにない | クラスロードは確認できても RCE に繋がらない → SSRF / 情報漏洩系の影響評価に切り替える |
| エンドポイントがバイト列を受け付けない | プロトコルが違う（XML / JSON 等）→ `XXE.md` や `Deserialization_Other.md` を確認 |

---

### 注意点・落とし穴

- **ガジェットのバージョン依存**: ysoserial のガジェットはライブラリのバージョンに依存する。Commons Collections 3.x 向けと 4.x 向けは別ペイロード。
- **Java バージョン制限**: JDK 8 以降はセキュリティマネージャや `jdk.serialFilter` でデシリアライズ自体をブロックできる。エラーが `InvalidClassException` や `filter status: REJECTED` の場合はこれを疑う。
- **allowlist の確認が先**: allowlist がない環境ではこのバイパスを考える前に通常のデシリアライズ攻撃が直接使える。バイパスを試みるのは allowlist の存在を確認してから。

---

### 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）
- **想定される SIEM/EDR 検知**: デシリアライズ経由の `Runtime.exec()` 呼び出し、異常プロセス生成
- **業務影響リスク**: ガジェットチェーンの種類によってはサービス停止の可能性あり
- **原状回復必須項目**: ✅ テスト中に生成したプロセス・ファイルの削除
- **取得情報の取扱**: 暗号化保管 / 案件終了時破棄
- **演習環境での扱い**: 制約なし（本番前提セクションをスキップしてよい）

---

### 関連技術

- 前：Webエンドポイント列挙・バイト列の確認 → `../../01_Reconnaissance/Web_Enumeration.md`
- 前：原理の理解 → `../../06_Concepts/Java_Deserialization.md`
- 後：RCE 取得後の次の手 → `../../03_Post_Access_Linux/Enumeration_Checklist.md`
