# MITRE ATT&CK フレームワーク — 概要と使い方

## このファイルの位置づけ

kedalab 全体の「ATT&CK 軸での参照」を支える概念ガイド。
[`TECHNIQUES_INDEX_MITRE.md`](../TECHNIQUES_INDEX_MITRE.md) を引く前に一度読むことで、ID の意味・Navigator の操作・Atomic Red Team との連携が理解できる。

参照元ファイル:
- [`../TECHNIQUES_INDEX_MITRE.md`](../TECHNIQUES_INDEX_MITRE.md) — ATT&CK ID → kedalab ファイルの横断インデックス

---

## 1. MITRE ATT&CK とは

**ATT&CK（Adversarial Tactics, Techniques, and Common Knowledge）** は、実際の攻撃者の行動を体系化した知識ベース。MITRE Corporation が管理し、世界中のセキュリティコミュニティが継続的に更新している。

### なぜ存在するか

従来の脆弱性管理は「CVE ベース（脆弱性単位）」だった。しかしペネトレーションテスト・脅威インテリジェンス・EDR 製品の検知ルール設計には、「攻撃者がどういう順序で何をするか」という行動単位の記述が必要だった。ATT&CK はその空白を埋める共通言語として設計されている。

### 何ができるか

- 実施したテスト手法を標準 ID で報告書に記載できる
- 顧客の要件（「ATT&CK T1558.003 に対応できること」等）を技術的に解釈できる
- テストカバレッジを Tactic / Technique 軸で可視化し、報告書に添付できる
- Atomic Red Team によって Technique 単位の再現テスト（検知確認）ができる

---

## 2. 構造

### 3 層構造

```
Tactic（戦術）
  └── Technique（手法）
        └── Sub-Technique（サブ手法）
```

| 層 | 例 | 説明 |
|----|----|------|
| Tactic | TA0006 Credential Access | 攻撃者が「何を達成しようとしているか」 |
| Technique | T1558 Steal or Forge Kerberos Tickets | 「どのような手法で達成するか」 |
| Sub-Technique | T1558.003 Kerberoasting | 「その手法の具体的なバリアント」 |

### ID 表記ルール

| 形式 | 例 | 意味 |
|------|----|------|
| `TA0001` | TA0001 | Tactic（`TA` プレフィックス） |
| `T1078` | T1078 | Technique（サブなし） |
| `T1078.001` | T1078.001 | Sub-Technique（ドット区切りで 3 桁） |

Sub-Technique が存在する場合、親 Technique（`T1078`）は参照用として残るが、**報告書ではより具体的な Sub-Technique ID を優先して使う**。

### Enterprise Matrix の Tactic 一覧

| ID | Tactic | 概要 |
|----|--------|------|
| TA0043 | Reconnaissance | 侵入前の情報収集 |
| TA0042 | Resource Development | インフラ・ツールの準備 |
| TA0001 | Initial Access | 最初の足がかり |
| TA0002 | Execution | 悪意あるコードの実行 |
| TA0003 | Persistence | アクセスの維持 |
| TA0004 | Privilege Escalation | 権限の昇格 |
| TA0005 | Defense Evasion | 検知回避 |
| TA0006 | Credential Access | 認証情報の窃取 |
| TA0007 | Discovery | 環境の探索 |
| TA0008 | Lateral Movement | 横展開 |
| TA0009 | Collection | 情報収集 |
| TA0011 | Command and Control | C2 通信 |
| TA0010 | Exfiltration | データ持ち出し |
| TA0040 | Impact | 破壊・妨害 |

> 同じ Technique が複数 Tactic に登場することがある（例: T1550.002 Pass the Hash は TA0005 と TA0008 の両方）。これは ATT&CK の設計上の意図であり重複ではない。「同じ手法が複数の目的で使われる」ことを表している。

### Matrix の種類

| Matrix | 対象 | 用途 |
|--------|------|------|
| Enterprise | Windows / Linux / macOS / Cloud / Network / Containers | ペネトレ案件の主参照先 |
| Mobile | Android / iOS | モバイルアプリ診断 |
| ICS | 産業制御システム | OT/ICS ペネトレ |

> kedalab は **Enterprise Matrix** のみを対象とする。ICS・Mobile は別スコープ。
> AI Red Teaming は ATT&CK ではなく **MITRE ATLAS** のスコープ。将来 `TECHNIQUES_INDEX_ATLAS.md` として別建て予定。

---

## 3. attack.mitre.org の使い方

公式: https://attack.mitre.org/

### サイト構成

```
attack.mitre.org/
├── Matrices/      … Matrix 全体を Tactic × Technique 表で閲覧
├── Tactics/       … Tactic（TA0001 等）の一覧・詳細
├── Techniques/    … Technique（T1078 等）の一覧・詳細
├── Groups/        … APT グループの使用 Technique 一覧
├── Software/      … ツール（Cobalt Strike 等）が使う Technique
└── Mitigations/   … 各 Technique への対策
```

### Technique 詳細ページの見方

Technique ID をクリックすると以下が確認できる：

| セクション | 内容 | 優先度 |
|-----------|------|--------|
| Description | 手法の説明・成立条件 | 高 |
| Sub-Techniques | バリアント一覧 | 高 |
| **Procedure Examples** | 実際の攻撃グループの使用事例 | **最重要** |
| Detection | 検知ポイント（Event ID・ログ観点） | 高（Blue Team 視点） |
| Mitigations | 対策（顧客向け説明の素材） | 中 |
| References | 出典論文・ブログ | 参考 |

> **Procedure Examples が最重要。** 実際の APT グループがどのようにその手法を使ったかが具体例として載っており、「この手法が通用する環境条件」の理解に直結する。「この Technique は理論上わかるが実際にどう使われるか」を知りたいときはここを読む。

### 検索の使い方

サイト上部の検索ボックスに Technique 名・ID・キーワードを入力して絞り込める。

- ID 直打ち: `T1558.003` → 該当 Technique に直接飛ぶ
- キーワード: `kerberoast` → 関連する Technique が列挙される
- グループ名: `APT29` → そのグループが使う Technique 一覧が出る

---

## 4. ATT&CK Navigator の使い方

公式（オンライン）: https://mitre-attack.github.io/attack-navigator/
ソースコード: https://github.com/mitre-attack/attack-navigator

### Navigator でできること

| 操作 | 用途 |
|------|------|
| Technique にスコアを付ける | テストカバレッジを色分けで可視化 |
| Technique をハイライト | 今回の案件スコープを図示 |
| APT グループのレイヤーを重ねる | 特定の脅威アクターが使う手法を可視化 |
| レイヤーを JSON 出力 | 報告書への添付・カバレッジ共有 |

### 基本操作フロー

1. https://mitre-attack.github.io/attack-navigator/ を開く
2. 「Create New Layer」→「Enterprise ATT&CK」を選択
3. 対象の Technique を選択して右クリック → 「Score」でスコア（0〜100）を入力
4. 「Scoring」タブでカラーグラデーションを設定（例: 0=未実施・1=実施済み）
5. 「Export」→「Download SVG」または「Download JSON」で出力

### レイヤー JSON の活用

レイヤーは JSON で保存・共有できる。以下は最小構成の例：

```json
{
  "name": "[PROJECT_NAME] Coverage",
  "versions": {"attack": "14", "navigator": "4.9"},
  "domain": "enterprise-attack",
  "techniques": [
    {
      "techniqueID": "T1558.003",
      "score": 1,
      "comment": "Kerberoasting テスト済み"
    },
    {
      "techniqueID": "T1190",
      "score": 1,
      "comment": "Web 診断テスト済み"
    }
  ]
}
```

JSON を Navigator にインポートすれば、前回案件のカバレッジを引き継いで比較できる。報告書に SVG として添付すると「どの Tactic/Technique をカバーしたか」の一覧として機能する。

### APT グループレイヤーの重ね合わせ

1. Navigator 上部「Open Existing Layer」→「From URL」を選択
2. MITRE が公開するグループ別 JSON URL を入力
   - 例（APT29）: https://attack.mitre.org/groups/G0016/
   - ページ内の「ATT&CK Navigator Layers」リンクから JSON URL を取得
3. 自分のカバレッジレイヤーと重ねて「どの手法をまだカバーしていないか」を確認

---

## 5. Atomic Red Team の使い方

公式リポジトリ: https://github.com/redcanaryco/atomic-red-team
Invoke-AtomicRedTeam（実行モジュール）: https://github.com/redcanaryco/invoke-atomicredteam

### Atomic Red Team とは

Red Canary が管理するオープンソースの **「Technique 単位の再現テストライブラリ」**。
各 ATT&CK Technique に YAML で記述されたテストケース（Atomic Test）が対応しており、PowerShell モジュール **Invoke-AtomicRedTeam** を使って実行できる。

本来は Blue Team 向けの「自環境でこの Technique が検知できるか確認するシミュレーションツール」として設計されている。ペネトレ観点では以下の用途で使う：

- 「この Technique の標準的な実行方法」をコマンドレベルで確認する
- 自環境のEDR検知ルール確認・チューニングの素材にする
- 「この手法が対象環境で刺さるか」の最小再現手順を得る

### インストール

**事前準備（必須）：** PowerShell 5.1 以上（Windows）または PowerShell Core（Linux/macOS）が必要。インターネットアクセスが必要。

```powershell
# [Attacker] Atomic Red Team モジュールのインストール
Install-Module -Name invoke-atomicredteam,powershell-yaml -Scope CurrentUser

# [Attacker] リポジトリ本体のダウンロード（テスト YAML を参照するために必要）
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force
```

インストール後、`C:\AtomicRedTeam\atomics\` 配下に Technique ID 別のフォルダが作成される。

オフライン環境では GitHub からzipでダウンロードして手動展開する:
https://github.com/redcanaryco/atomic-red-team/archive/refs/heads/master.zip
展開後、`-PathToAtomicsFolder` パラメータで展開先を指定して使う。

### 基本コマンド

```powershell
# [Attacker] 特定の Technique のテスト内容を確認（実行前の確認 — 必ず先に実行）
Invoke-AtomicTest T1558.003 -ShowDetails

# [Attacker] 前提ツール・依存関係のインストールのみ実行
Invoke-AtomicTest T1558.003 -GetPrereqs

# [Attacker] テスト実行（全テストケース）
Invoke-AtomicTest T1558.003

# [Attacker] テスト番号を指定して実行（複数テストがある場合）
Invoke-AtomicTest T1558.003 -TestNumbers 1

# [Attacker] クリーンアップ（テスト後の痕跡削除 — 必ず実行）
Invoke-AtomicTest T1558.003 -Cleanup

# [Attacker] atomics フォルダを明示的に指定する場合（オフライン展開時等）
Invoke-AtomicTest T1558.003 -PathToAtomicsFolder "C:\AtomicRedTeam\atomics"
```

### atomics フォルダの直接参照（PowerShell 不要）

PowerShell モジュールを使わなくても、`atomics/` フォルダ内の YAML と Markdown を直接参照できる。Linux 環境・制限された環境での手順確認に有効。

```
atomic-red-team/
└── atomics/
    ├── T1558.003/
    │   ├── T1558.003.yaml   … テスト定義（構造化）
    │   └── T1558.003.md     … Markdown で読みやすい説明
    ├── T1110.003/
    │   ├── T1110.003.yaml
    │   └── T1110.003.md
    └── ...
```

GitHub 上でも直接閲覧できる:
https://github.com/redcanaryco/atomic-red-team/tree/master/atomics

### YAML の読み方

各 Technique のテストは以下の構造で記述されている：

```yaml
attack_technique: T1558.003
display_name: "Steal or Forge Kerberos Tickets: Kerberoasting"
atomic_tests:
  - name: Request A Ticket
    description: |
      SPN を持つサービスアカウントに対してチケットをリクエストし、
      オフラインクラックのためにメモリに保持する。
    supported_platforms:
      - windows
    input_arguments:
      spn:
        description: ターゲットにする SPN
        type: string
        default: HTTP/[DC_FQDN]
    executor:
      name: powershell
      elevation_required: false
      command: |
        Add-Type -AssemblyName System.IdentityModel
        New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken \
          -ArgumentList "#{spn}"
```

YAML を読む際の着眼点：

| フィールド | 確認すること |
|-----------|------------|
| `supported_platforms` | Windows のみか、Linux/macOS でも動くか |
| `elevation_required` | 管理者権限が必要か |
| `input_arguments` | パラメータの意味とデフォルト値（`#{}` 形式で参照される） |
| `executor.command` | 実際に実行されるコマンド（ここを読めば手動実行も可） |
| `executor.cleanup_command` | テスト後に元に戻すコマンド |

### テスト実行時の確認フロー

```
1. -ShowDetails でテスト内容を確認（何が実行されるかを把握してから実行）
2. -GetPrereqs で依存ツールをインストール
3. テスト実行
4. 検知ログを確認
5. -Cleanup で痕跡削除
```

**本番環境・顧客環境での Atomic Red Team 実行は事前合意必須。**
Cleanup コマンドが存在しない Technique もあるため、`-ShowDetails` で確認してから実行する。

---

## 6. 報告書での ATT&CK ID 活用

### 記載パターン（発見事項ごと）

```
発見事項: Kerberoasting による サービスアカウント認証情報の取得
ATT&CK: T1558.003 Steal or Forge Kerberos Tickets: Kerberoasting
Tactic: TA0006 Credential Access
```

### kedalab インデックスとの連携フロー

```
手順を実施
  → kedalab ファイル（例: Kerberoasting.md）で手順参照
  → TECHNIQUES_INDEX_MITRE.md で ATT&CK ID を逆引き
  → 報告書の発見事項に ATT&CK ID を記載
  → Navigator でカバレッジを可視化して添付
```

---

## 関連技術

- 前：[`../TECHNIQUES_INDEX_MITRE.md`](../TECHNIQUES_INDEX_MITRE.md) — ATT&CK ID → kedalab ファイルの横断インデックス
- 後：[`./OWASP_WSTG_Guide.md`](./OWASP_WSTG_Guide.md) — Web 診断軸のフレームワーク概要
