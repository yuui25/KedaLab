---
description: kedalab 全体に対して kedaweb 互換性 + WRITING_GUIDE 自己チェックを実行
allowed-tools: Glob, Read, Grep, Bash
---

kedalab 配下の公開コンテンツ全ファイルに対して、kedaweb 不変条件と WRITING_GUIDE 自己チェックを実行してください。

## 検査対象

- `00_Playbook/` 〜 `08_Cloud_Identity/` 配下の `.md`
- 除外: `_*/`、`99_kedaweb/`、`.claude/`、`.git/`、ルート直下の `.md`

## 検査項目

### kedaweb 不変条件

| ID | 項目 | チェック方法 |
|---|---|---|
| I1 | 既知トップフォルダ配下にある | パス先頭 `00_` 〜 `08_` で始まる |
| I2 | TECHNIQUES_INDEX*.md または README.md に登録 | ファイル名でインデックスを grep。対象: `TECHNIQUES_INDEX.md` / `TECHNIQUES_INDEX_AI_ML.md` / `TECHNIQUES_INDEX_WSTG.md` / `TECHNIQUES_INDEX_MITRE.md` / `TECHNIQUES_INDEX_GUIDELINES.md` のいずれか、または `README.md`（Playbook ファイルの場合）|
| I3 | `## 関連技術` または `### 関連技術` セクション存在 | 正規表現 `^(##\|###)\s*関連技術\s*$` |
| I4 | `前：` / `後：` / `関連：` ラベル使用 | 正規表現 `(前\|後\|関連)[:：]` |
| I5 | バッククォート相対パス | 関連技術セクション内に `` `*.md` `` が存在 |
| F1 | 関連技術内にルート相対パスがない | 関連技術節内の `` `0N_Folder/...md` `` 形式を検出（`./`/`../` または bare で書く） |
| F2 | 太字ラベル直後に空行 | `\*\*[^\n]+[:：]\*\*\n[-*\|]` パターンの不在を確認 |
| F3 | 関連技術内にディレクトリ参照がない | 関連技術節内の `` `Folder/` `` 形式（末尾 `/` 終わり）を検出（具体的な `*.md` を指す） |

### WRITING_GUIDE 自己チェック grep

WRITING_GUIDE.md 末尾の「自己チェック」セクションに記載された全パターンを実行：

- 演習環境名（HTB / HackTheBox / OSCP / TryHackMe / VulnHub）— テンプレート boilerplate は除外
- CTF 用語（user.txt / root.txt / flag.txt / 攻略 / リタイアマシン）
- 演習由来固有値（10.10.x.x / corp.local / Password123! / henry / e6ff5b1cbc85 / evil.bat / ATTACKPC）
- Kali 名指し
- プレースホルダ揺れ（`<lowercase>` 形式は `[UPPER_SNAKE_CASE]` へ）— 区切り文字を含むパターンのみ
- **職業前提表現（WG-TONE）**：商用案件 / 商用ペネトレ / 商用環境 / 業務として実施 / 職業ペネトレ / プロのペンテスター / 脆弱性診断の現場 / クライアントとの合意 → 本番・学習者向けの表現に書き換え
- **機構レベルの追加チェック**：PostToolUse hook が公開リポ衛生に関わる追加パターンを検出する（具体的な検出リストはリポ外で管理）
- CVE 研究由来の固有値（プロジェクト名・関数名・行番号）
- 相対パス階層誤り（`../../../` で kedalab 外）
- テンプレート必須セクション欠落（**移行期は新構造と旧構造の両方を許容**）
  - 共通必須: `着火条件` / `関連技術`
  - いずれか必要: `観点・着眼点` または 番号付き技術ブロック（`^## [0-9]+\. `）
  - いずれか必要: `## 手順` または 技術ブロック内 `**コマンド:**`
  - 必須: `刺さらなかったとき`
  - WRITING_GUIDE の「テンプレート必須セクションの存在チェック」grep を参照

## 出力フォーマット

違反ファイルごとに以下を出力：

```
[<filepath>]
  - [<ID>] <違反内容>
  - [<ID>] <違反内容>
```

最後にサマリ：

```
合計 <N> ファイル中 <M> ファイルに違反検出
内訳:
  - I2 違反: <件数>
  - I3 違反: <件数>
  - WG 違反（演習由来語）: <件数>
  ...
```

違反ゼロなら「✅ kedaweb 不変条件・WRITING_GUIDE 自己チェック全パス」と出力してください。

## 補足

- このコマンドは PostToolUse hook（`kedaweb-compat.ps1`）の **全ファイル一括版**。hook は編集時に該当ファイル1個を検査するが、本コマンドはリポジトリ全体を走査する
- 規約詳細: `_workspace/conventions/Folder_Convention_20260515.md`
