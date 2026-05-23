# OWASP WSTG フレームワーク — 概要と使い方

## このファイルの位置づけ

kedalab の「WSTG 軸での参照」を支える概念ガイド。
[`TECHNIQUES_INDEX_WSTG.md`](../TECHNIQUES_INDEX_WSTG.md) を引く前に一度読むことで、WSTG の ID 体系・ドキュメントの読み方・テストでの活用フローが理解できる。

参照元ファイル:
- [`../TECHNIQUES_INDEX_WSTG.md`](../TECHNIQUES_INDEX_WSTG.md) — WSTG ID → kedalab ファイルの横断インデックス

---

## 1. OWASP WSTG とは

**WSTG（Web Security Testing Guide）** は、OWASP（Open Web Application Security Project）が管理する Web アプリケーション診断の標準ガイドライン。Web に特化した診断手法を体系化しており、テストケース単位に ID が付与されている。

現行バージョンは **v4.2**（kedalab の参照基準）。

### なぜ存在するか

Web アプリ診断は「テスター個人のスキル・経験に依存する」という問題があった。WSTG はこれを標準化し、「何をテストすべきか・どう確認するか・どう報告するか」を公式ドキュメントとして定義した。対象組織の RFP（提案依頼書）に「WSTG 準拠」と指定されることも多く、共通言語として機能する。

### MITRE ATT&CK との使い分け

| フレームワーク | 対象 | 主な用途 |
|---------------|------|---------|
| MITRE ATT&CK | OS・AD・ネットワーク・クラウド全般 | インフラ・AD 診断 |
| OWASP WSTG | Web アプリケーション | Web 診断 |

Web 診断スコープでは **WSTG を主軸**に使う。ATT&CK はアプリより上の OS・インフラレイヤーを扱う場合に切り替える。WSTG はネットワーク・AD・OS レイヤーをスコープ外としているため、それらは ATT&CK で参照する。

---

## 2. 構造

### ID 体系

```
WSTG-[カテゴリ]-[番号]
例: WSTG-INPV-05
```

カテゴリ略称と対応する診断領域：

| カテゴリ | 略称 | テスト領域 |
|---------|------|-----------|
| 情報収集 | INFO | サーバー特定・フレームワーク判定・エントリポイント特定 |
| 設定管理 | CONF | プラットフォーム設定・バックアップファイル・管理画面露出 |
| ID 管理 | IDNT | アカウント列挙・ユーザー名ポリシー |
| 認証 | ATHN | デフォルト認証・ブルートフォース・パスワードポリシー |
| 認可 | ATHZ | ディレクトリトラバーサル・IDOR・認可バイパス |
| セッション管理 | SESS | Cookie セキュリティ・セッション固定・CSRF |
| 入力検証 | INPV | SQLi・XSS・XXE・コマンドインジェクション・SSRF |
| エラー処理 | ERRH | エラーメッセージの情報漏洩 |
| 暗号化 | CRYP | TLS 設定・弱い暗号スイート |
| ビジネスロジック | BUSL | 機能固有のロジック欠陥（手動確認が主） |
| クライアントサイド | CLNT | DOM XSS・オープンリダイレクト・CORS |
| API テスト | APIT | GraphQL・WebSocket |

> kedalab で最も対応の厚いカテゴリは **WSTG-INPV（入力検証）**。SQLi・XSS・XXE・コマンドインジェクション・SSRF が含まれる。

---

## 3. WSTG サイトの使い方

公式 v4.2: https://owasp.org/www-project-web-security-testing-guide/v42/

### サイト構成

ドキュメントはカテゴリ別フォルダで構成されている：

```
/v42/4-Web_Application_Security_Testing/
├── 01-Information_Gathering/          … WSTG-INFO
├── 02-Configuration_and_Deployment_Management_Testing/  … WSTG-CONF
├── 03-Identity_Management_Testing/    … WSTG-IDNT
├── 04-Authentication_Testing/         … WSTG-ATHN
├── 05-Authorization_Testing/          … WSTG-ATHZ
├── 06-Session_Management_Testing/     … WSTG-SESS
├── 07-Input_Validation_Testing/       … WSTG-INPV
├── 08-Testing_for_Error_Handling/     … WSTG-ERRH
├── 09-Testing_for_Weak_Cryptography/  … WSTG-CRYP
├── 10-Business_Logic_Testing/         … WSTG-BUSL
├── 11-Client-side_Testing/            … WSTG-CLNT
└── 12-API_Testing/                    … WSTG-APIT
```

フォルダ番号（01〜12）がカテゴリ番号に対応している。WSTG-INPV-05 を見たければ `07-Input_Validation_Testing/` の 5 番目のファイル。

### テストケースページの見方

各テストケースページには以下のセクションが含まれる：

| セクション | 内容 | 優先度 |
|-----------|------|--------|
| Summary | 脆弱性の概要・なぜ問題か | 高 |
| Test Objectives | このテストで確認すべきこと | 高 |
| **How to Test** | 具体的なテスト手順 | **最重要** |
| Remediation | 修正方法（対象組織説明の素材） | 高 |
| References | CWE 番号・関連論文 | 参考 |

> **How to Test セクションが最重要。** ブラックボックス / グレーボックス別に手順が分かれており、ツールとコマンドの両方が記載されている。「この脆弱性の探し方を体系的に確認したい」場面で参照する。

### How to Test の構成パターン

多くのテストケースは以下の流れで記述されている：

```
1. 自動スキャンによる初期探索
2. 手動での確認手順
3. 判断基準（これが出たら脆弱性あり）
4. ツール別の操作例（Burp Suite / curl / 特定スキャナ等）
```

---

## 4. 診断フローでの WSTG 活用

### テスト開始時のカバレッジ確認

```
1. 対象組織の RFP・スコープに WSTG ID が指定されているか確認
2. TECHNIQUES_INDEX_WSTG.md で該当 ID に kedalab ファイルが存在するか確認
3. kedalab 対応あり → kedalab ファイルで手順参照
4. kedalab 対応なし → WSTG サイトで How to Test を確認し、手動テスト
```

### テスト実施中の使い方

```
実施した手法
  → kedalab ファイルで手順参照
  → TECHNIQUES_INDEX_WSTG.md で WSTG ID を逆引き
  → 報告書の発見事項に WSTG ID を記載
```

### カバレッジ集計の計算式

```
カバレッジ = kedalab に対応ファイルがある WSTG ID 数 ÷ テストスコープ内の WSTG ID 全数
```

対象組織に提示するカバレッジは「スコープ内の全 ID を分母」にする。WSTG 全 ID を分母にすると BUSLOGIC・APIT 等の手動対応領域まで含まれて正確でない。

---

## 5. 報告書での WSTG ID 活用

### 記載パターン（発見事項ごと）

```
発見事項: SQL インジェクションによる認証バイパス
WSTG: WSTG-INPV-05 Testing for SQL Injection
重篤度: Critical
```

### カテゴリ全体をカバーした場合の記載

```
実施スコープ: WSTG-INPV 全テストケース（WSTG-INPV-01〜20）を実施
```

### kedalab インデックスとの連携フロー

```
手順を実施
  → kedalab ファイル（例: SQLi.md）で手順参照
  → TECHNIQUES_INDEX_WSTG.md で WSTG ID を逆引き
  → 報告書の発見事項に WSTG ID を記載
```

---

## 6. バージョン管理

kedalab は **v4.2 ベース**で記載している。WSTG は定期的に改訂されるため、以下を確認する：

| リソース | URL |
|---------|-----|
| 最新版 | https://owasp.org/www-project-web-security-testing-guide/ |
| v4.2 安定版 | https://owasp.org/www-project-web-security-testing-guide/v42/ |
| GitHub リリース | https://github.com/OWASP/wstg/releases |

> 対象組織との合意は「WSTG v4.2 準拠」のように**バージョンを明記**する。改訂で項目番号がずれる場合があるため、バージョンなしの「WSTG 準拠」では後から齟齬が生じる。

---

## 関連技術

- 前：[`../TECHNIQUES_INDEX_WSTG.md`](../TECHNIQUES_INDEX_WSTG.md) — WSTG ID → kedalab ファイルの横断インデックス
- 後：[`./MITRE_ATTCK_Guide.md`](./MITRE_ATTCK_Guide.md) — インフラ・AD 診断軸のフレームワーク概要
