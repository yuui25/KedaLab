# kedalab — 技術ノウハウ集


## このリポジトリの目的

セキュリティ技術の調査・検証作業を通じて得た「着眼点・手順・判断ロジック」を、特定のターゲットや環境に依存しない汎用的な知識として蓄積するリポジトリです。

特定のシステムや演習環境の情報は一切含みません。純粋に「どこで・何を・なぜ確認するか」という技術的観点のみをまとめています。

利用シーンは OSCP 等のペネトレ資格演習・bug bounty・home lab・各種演習環境での技術練習。
どのコンテキストでも「攻撃者の思考トレース」を再現できる粒度で書くことを目的としています。

---

## kedalab の使い方

**いきなり技術ファイル（01〜07フォルダ）を開かない。**
Playbook が「今どこにいるか」と「次に何をすべきか」を繋ぐ唯一のナビゲーションになっている。

### Step 0 — 本番の場合は前提確認を先にする

本番で実施する場合は、技術調査に入る前に以下を確認する：

- スコープ（IP範囲・FQDN・除外システム）
- 実施可否（破壊的テスト・シェル取得・権限昇格・横展開・永続化テストの個別承認）
- 業務影響（営業時間・重要システムの稼働・冗長化）
- 緊急連絡ライン（業務影響発生時の即時連絡先）
- 取得情報の取扱（保管・破棄・暗号化の規定）

詳細は [`06_Concepts/Pentest_Fundamentals.md`](./06_Concepts/Pentest_Fundamentals.md) を参照。

> 演習環境（HTB / OSCP 等）では Step 0 はスキップしてよい。

### Step 1 — 最初に開くファイルを決める

手元にある情報を確認して以下の表で出発点を決める。

| 手元にある情報 | 最初に開くファイル |
|--------------|-----------------|
| IPのみ（最多） | `00_Playbook/00_OS_Identification.md` |
| 認証情報（ID/パス）が提供済み（OS不明） | `00_Playbook/00_OS_Identification.md`（認証情報があれば SSH/RDP 接続が最速判定） |
| ドメインのみ（IPが不明） | `01_Reconnaissance/DNS_Enumeration.md` で IP 特定 → `00_Playbook/00_OS_Identification.md` へ |
| インターネット露出IPのみ（エッジアプライアンス・公開Webシステム等、製品・OS不明） | `00_Playbook/External_Service_Recon_Flow.md` |
| Webシステムが疑われる（ペネトレ・シェル取得目的） | `00_Playbook/Linux_Attack_Flow.md` Step 2 |
| Webシステムが疑われる（Web診断スコープ・脆弱性の網羅的洗い出し） | `00_Playbook/Web_Vuln_Flow.md` |
| Linuxと判明している | `00_Playbook/Linux_Attack_Flow.md` |
| Windowsと判明している | `00_Playbook/Windows_AD_Attack_Flow.md` |
| 内部 VLAN に接続済み（認証情報あり・なし問わず、内部 LAN テスト開始時） | `00_Playbook/Internal_LAN_Pentest_Flow.md` |

### Step 2 — Playbook を上から順に読む

各 Playbook は「今の状況で何を確認するか」→「その結果どの手法を試すか」という判断フローになっている。
コマンドを打ちながら、出力を Playbook の判断表と照らし合わせて次のステップを決める。

### Step 3 — 詳細が必要なときだけ技術ファイルを開く

Playbook の各ステップにリンクが張ってある。「このコマンドの意味がわからない」「もう少し詳しいオプションが知りたい」
というときだけリンク先を開く。最初からすべて読もうとしない。

### Step 4 — 手法が通用しなかったとき

各技術ファイルに「刺さらなかったとき」セクションがある。
「〜が出たらこの手法は使えない → 代替として〜を試す」という形で書いてあるので、
エラーや想定外の出力が返ってきたらそこを確認する。

---

## よく使う3つの引き方

| やりたいこと | 使う場所 |
|------------|---------|
| 技術名がわかっている（「XXEってどこ？」） | `TECHNIQUES_INDEX.md` をキーワード検索 |
| 今の状況から次の手を探したい | `00_Playbook/` の該当フローを読む |
| ツールのコマンドオプションを忘れた | `05_Tools_Reference/` の該当ツール |

---

## 詰まったときの確認順序

1. 今開いている Playbook の「刺さらなかったとき」セクションを確認したか
2. 技術ファイルの「注意点・落とし穴」セクションを確認したか
3. `TECHNIQUES_INDEX.md` で別のアプローチを探したか
4. `06_Concepts/` で原理を確認し、自分の環境で前提条件が崩れていないか確認したか

上記を確認してもなお進まない場合は、当該ツール・脆弱性の公式ドキュメント・公開アドバイザリ等の一次情報を当たる。

---

## 「なぜそうなるのか」が気になったとき

`06_Concepts/` フォルダに原理の説明ファイルがある。作業中に参照するものではなく、
**手が止まって「そもそもなぜこれが効くのか」を理解したいときだけ開く**。

本番のペネトレと演習の世界観の違いを把握したい場合は [`06_Concepts/Pentest_Fundamentals.md`](./06_Concepts/Pentest_Fundamentals.md) を読む。

---

## 全体像

IPだけ渡された状態からゴール（権限昇格・機密情報取得）までの大きな流れ：

```
[偵察] → [初期アクセス] → [侵入後列挙] → [権限昇格]
   ↓            ↓                ↓               ↓
 01_Recon/  02_Initial_Access/  03〜04_Post/   03〜04_Post/
```

まず `00_Playbook/` のフローを開き、現在のフェーズを確認してから詳細ファイルに進む。

---

## 状況から直接フォルダに飛ぶ

| 状況 | 参照先 |
|------|--------|
| スキャン結果を見ている | `01_Reconnaissance/` |
| インターネット露出サービス（エッジアプライアンス・公開Web）の初手 | `00_Playbook/External_Service_Recon_Flow.md` |
| Webシステムが疑われる（ペネトレ・シェル取得目的） | `00_Playbook/Linux_Attack_Flow.md` Step 2 |
| Webシステムが疑われる（Web診断スコープ・脆弱性網羅的洗い出し） | `00_Playbook/Web_Vuln_Flow.md` |
| Webアプリを触っている（調査中盤） | `02_Initial_Access/Web_Vulnerabilities/` |
| 見たことのない技術・機能に当たり、脆弱性クラスの名前もわからない | `00_Playbook/01_Unknown_Tech_Research.md` |
| バイナリ・ファイルを取得した | `02_Initial_Access/Binary_Analysis.md` |
| Linuxシェルを取った直後 | `03_Post_Access_Linux/Enumeration_Checklist.md` |
| Windows ADシェルを取った直後 | `04_Post_Access_Windows_AD/Enumeration_Checklist.md` |
| Windows 認証情報を取得し WinRM (5985/5986) が開いている | `02_Initial_Access/WinRM.md` |
| 管理者認証情報があるが WinRM (5985/5986) が閉じている | `02_Initial_Access/Impacket_Exec.md` |
| BloodHoundで権限が判明した | `04_Post_Access_Windows_AD/ACE_Abuse/` |
| 内部 VLAN に接続済み（認証情報あり・なし問わず、内部 LAN 攻撃の全体フローを確認したい） | `00_Playbook/Internal_LAN_Pentest_Flow.md` |
| コマンドのオプションを忘れた | `05_Tools_Reference/` |
| 手順は知っているが「なぜ効くか」がわからない | `06_Concepts/` の該当ファイル |
| 環境が違って手順が通用しない | `06_Concepts/` で原理を確認し、条件を読み解く |
| AI Red Teaming の攻撃手法の前提知識を確認したい | `06_Concepts/AI_ML/` の該当ファイル |
| LLM・プロンプトインジェクションの仕組みを知りたい | `06_Concepts/AI_ML/Generative_AI/LLM.md` |
| LLM アプリへの偵察を始めたい | `07_AI_Red_Teaming/01_Reconnaissance/` |
| プロンプトインジェクション・Jailbreakを試みたい | `07_AI_Red_Teaming/02_LLM_Prompt_Injection/` |
| 敵対的サンプル攻撃の原理を知りたい | `06_Concepts/AI_ML/Deep_Learning/Neural_Networks.md` |
| 異常検知システムへの回避の原理を知りたい | `06_Concepts/AI_ML/Unsupervised_Learning/Anomaly_Detection.md` |

---

## 各ファイルの構成

各 `.md` ファイルは以下の構成で書かれている。**「着火条件」を最初に確認する習慣をつける** — 手順より先に「今の状況がこの条件に合っているか」を確認することで無駄な試行を減らせる。

- **着火条件** — この技術を試すべき状況。「この出力が見えたら使う」という判断基準。
- **観点・着眼点** — なぜそれに気づくべきか、どこを見るべきかの思考プロセス。
- **手順** — 実際のコマンド・操作。
- **注意点・落とし穴** — 失敗しやすいポイント。失敗した手法の記録もここにある。
- **関連技術** — 次に試すべき手法へのリンク。

---

## 技術を持ち込むときのルール

演習環境（HTB / OSCP 等）で出会った技術を kedalab に追加するときは、
**演習特有の固有値（IP・ドメイン・ユーザー名・フラグ名・弱パスワード）をそのまま転記しない**。
判断ロジック・条件・シグナルに翻訳して書く。書き方の詳細は [`WRITING_GUIDE.md`](./WRITING_GUIDE.md) を参照。

---

> **AI（Claude）への指示は [`CLAUDE.md`](./CLAUDE.md) を参照。**

---

## フォルダ構成

個別ファイルの一覧は `TECHNIQUES_INDEX.md` を参照。ここではディレクトリの役割のみ記載する。

```
kedalab/
├── README.md                        # このファイル（方針・ルール）
├── TECHNIQUES_INDEX.md              # 全技術の横断インデックス
│
├── 00_Playbook/                     # 判断フロー（何を・どの順で試すか）
│   └── 00_OS_Identification.md      # ← 調査の起点。OS判定からここを開く
│
├── 01_Reconnaissance/               # サービス・ホスト・Web調査
│
├── 02_Initial_Access/               # 最初の足がかりを得る手法
│   └── Web_Vulnerabilities/         # Web系脆弱性はサブフォルダに集約
│
├── 03_Post_Access_Linux/            # Linux侵入後の動き
│   └── Enumeration_Checklist.md     # ← 侵入直後はここから
│
├── 04_Post_Access_Windows_AD/       # Windows AD侵入後の動き
│   ├── ACE_Abuse/                   # ACE権限濫用（GenericAll等）
│   ├── Delegation_Attacks/          # 委任攻撃（RBCD等）
│   └── Kerberos_Attacks/            # Kerberos攻撃（Kerberoasting等）
│
├── 05_Tools_Reference/              # ツール別クイックリファレンス
│
├── 06_Concepts/                     # 「なぜそうなるか」の原理・背景知識
│   └── AI_ML/                       # AI・機械学習の原理（AI Red Teaming前提知識）
│
├── 07_AI_Red_Teaming/               # AI Red Teaming 攻撃手順（LLM・ML・AIシステム）
│   ├── 01_Reconnaissance/           # LLMアプリ偵察・フィンガープリンティング
│   ├── 02_LLM_Prompt_Injection/     # プロンプトインジェクション・Jailbreak
│   ├── 03_LLM_Output_Attacks/       # LLM出力経由のXSS・SQLi・コードインジェクション
│   ├── 04_AI_Data_Attacks/          # データポイズニング・ラベルフリッピング・トロイの木馬
│   ├── 05_AI_Application_System/    # MCPの脆弱性・モデルデプロイ改ざん・Rogue Actions
│   └── 06_AI_Evasion/               # 敵対的サンプル・First-Order/Sparsity攻撃
│
└── 08_Cloud_Identity/               # クラウドID基盤（現在スコープ外・将来拡張用の見出し予約）
```

### 各セクションの役割

**00_Playbook** — 「今何をすべきか」の判断フロー。技術の詳細はここに書かず、各セクションへのリンクを使う。新しい手法を覚えたら、まずここの分岐に追加できないか考える。

**01_Reconnaissance** — 調査フェーズ。ポートスキャン・Web列挙・SMB・LDAPなどサービスごとの確認観点。

**02_Initial_Access** — 最初の侵入手法。Webの脆弱性、認証情報の発見、バイナリ解析など。

**03_Post_Access_Linux** — Linuxシステムへの侵入後。権限昇格を中心に。

**04_Post_Access_Windows_AD** — Windows AD環境への侵入後。ADは手法の種類が多いためサブフォルダで整理。

**05_Tools_Reference** — ツールのよく使うオプションや組み合わせのクイックリファレンス。

**06_Concepts** — 「なぜそうなるか」の原理・背景知識。作業ファイル（01〜05）は「着火条件→手順」に徹し、動作原理はここに分離する。詳細は後述。

**07_AI_Red_Teaming** — AI システムを対象とした攻撃手順。LLM・MLモデル・AIアプリケーションへの攻撃フェーズ別に整理する。背景知識は `06_Concepts/AI_ML/` を参照し、このフォルダは「着火条件→手順」に徹する。ネットワーク・システム系ペネトレスト（01〜05）と対称な構造を持つ。

**08_Cloud_Identity** — クラウドID基盤（Entra ID・ハイブリッドAD・Conditional Access 等）の見出し予約。**現時点では kedalab のスコープ外で、内部の README.md に将来扱う想定の領域だけが記載されている。** オンプレミス AD は `04_Post_Access_Windows_AD/` を参照する。

---

*このリポジトリは進行中のドキュメントです。不完全な状態のファイルがあっても問題ありません。「書きかけ」のメモでも追記していくことに価値があります。*

## ライセンス・注意事項

> **個人の学習ノートです。** 著者は職業ペネトレスターではなく、OSCP 等の資格演習・bug bounty・home lab 等で学んだ内容を整理しているセキュリティ学習者です。職業的実務経験に基づくものではありません。
> 正確性は保証しません。記載手法は自身が所有または明示的に許可されたシステムにのみ使用してください。
> ライセンスは [MIT](./LICENSE) です。誤り指摘・改善案は GitHub Issues 経由でお願いします。
