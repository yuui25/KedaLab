# GitHub連携セットアップガイド

このドキュメントは、keda-labリポジトリをGitHubと連携させるための手順を説明します。

## 前提条件

- Gitがインストールされていること
- GitHubアカウントを持っていること
- リポジトリの初期化がまだの場合

## セットアップ手順

### 1. Gitリポジトリの初期化

プロジェクトルートで以下を実行：

~~~~
git init
git add .
git commit -m "Initial commit: keda-lab project structure"
~~~~

### 2. GitHubリポジトリの作成

1. GitHubにログイン
2. 右上の「+」→「New repository」をクリック
3. リポジトリ名：`keda-lab`（または任意の名前）
4. 説明：`Web/NWペネトレーション技術深化プロジェクト - ASM/OSINT・Labs・Cases対応`
5. 公開設定：Private（推奨）またはPublic
6. 「Create repository」をクリック

### 3. リモートリポジトリの追加とプッシュ

GitHubで作成したリポジトリのURLを取得し、以下を実行：

~~~~
# リモートリポジトリを追加（URLは実際のものに置き換える）
git remote add origin https://github.com/YOUR_USERNAME/keda-lab.git

# メインブランチを設定（GitHubのデフォルトに合わせる）
git branch -M main

# 初回プッシュ
git push -u origin main
~~~~

### 4. 今後の作業フロー

#### 日常的な作業フロー

~~~~
# 変更を確認
git status

# 変更をステージング
git add .

# コミット（意味のあるメッセージを付ける）
git commit -m "feat: 01_topics/01_asm-osint/XX_xxx.md を追加"
git commit -m "fix: 01_topics/01_asm-osint/XX_xxx.md を追加"
git commit -m "docs: 01_topics/01_asm-osint/XX_xxx.md を追加"
git commit -m "refactor: 01_topics/01_asm-osint/XX_xxx.md を追加"
git commit -m "chore: 01_topics/01_asm-osint/XX_xxx.md を追加"

# プッシュ
git push
~~~~

#### コミットメッセージの推奨形式

- `feat:` - 新機能（新しいトピック/プレイブック/ラボの追加）
- `fix:` - バグ修正
- `docs:` - ドキュメントの更新
- `refactor:` - リファクタリング（粒度の調整、構造の改善）
- `chore:` - その他の変更（.gitignore、設定ファイルなど）

例：
- `feat: 01_topics/02_web/XX_authz_xxx.md を追加`
- `docs: README.md にGitHub連携セクションを追加`
- `refactor: 01_topics/01_asm-osint/01_dns_xxx.md の粒度を調整`

## ブランチ戦略（オプション）

### シンプルな運用（推奨）

- `main`ブランチのみを使用
- 直接コミット・プッシュ（個人プロジェクトの場合）

### 機能ブランチを使う場合

~~~~
# 新しいブランチを作成
git checkout -b feature/add-new-topic

# 作業・コミット
git add .
git commit -m "feat: 新しいトピックを追加"

# プッシュ
git push -u origin feature/add-new-topic

# GitHubでPull Requestを作成してマージ
~~~~

## 注意事項

### 機密情報の管理

- `.gitignore`に機密情報（キー、証明書、認証情報など）が含まれていることを確認
- 誤って機密情報をコミットした場合は、GitHubのSecret Scanning機能を確認
- 必要に応じて`git-secrets`などのツールを使用

### ファイルサイズ

- 大きなファイル（VMイメージ、pcapファイルなど）は`.gitignore`で除外
- 必要に応じてGit LFSを使用

### 定期的なバックアップ

- GitHubはバックアップとしても機能しますが、ローカルでも定期的にバックアップを取ることを推奨

## 次のステップ

1. GitHub Actionsの設定（CI/CD、自動チェックなど）
2. Issues/Projectsの活用（タスク管理）
3. Wikiの活用（追加のドキュメント）
4. Releasesの作成（マイルストーンの管理）

## トラブルシューティング

### 認証エラー

GitHubのPersonal Access Token（PAT）を使用する場合：

~~~~
git remote set-url origin https://YOUR_TOKEN@github.com/YOUR_USERNAME/keda-lab.git
~~~~

または、SSHキーを使用：

~~~~
git remote set-url origin git@github.com:YOUR_USERNAME/keda-lab.git
~~~~

### 大きなファイルのエラー

Git LFSを使用するか、`.gitignore`で除外する。

