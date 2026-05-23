> **SSH・WinRM 等で直接ログインしてシェルを取得した場合（Linux_Attack_Flow.md の経路A）は、このファイルの手順は不要。**
> リバースシェル（経路B）経由でシェルを取得した場合のみ以下を実施する。

# シェル安定化（TTYアップグレード）

## 着火条件
- netcat / リバースシェルでシェルを取得した直後
- 以下の症状が1つでも出る場合：
  - `sudo -l` が `"a terminal is required to read the password"` エラーで失敗する
  - `su [user]` でパスワード入力画面が表示されず画面が止まる
  - `Ctrl+C` でシェルが終了してしまう
  - `vim` / `nano` 等の対話的ツールが正常に動作しない
  - タブ補完が効かない

## 観点・着眼点

netcatで受け取ったリバースシェルは**擬似TTY（pseudoterminal）がない「ダムシェル」**。
多くのコマンドがTTYの存在を前提に設計されているため、TTYなしでは動作しない。

**ダムシェルの見分け方：**

- プロンプトが `$` だけ、または `sh-5.1$` のような簡素な表示
- `Ctrl+C` を押すとシェルが終了する（本来はプロセスを止めるだけのはず）

**TTY割り当て後に可能になること：**

| 操作 | ダムシェル | TTY後 |
|------|----------|-------|
| `sudo` / `su` | エラーまたは画面フリーズ | 正常動作 |
| タブ補完 | 効かない | 有効 |
| `Ctrl+C` | シェル終了 | プロセス中断（シェルは維持） |
| `vim` / `nano` | 文字化け・動作不良 | 正常動作 |

## 手順

## 標準手順（python3が使える場合）

```bash
# Step 1: PTYを割り当てる（python3が最も一般的）
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Step 2: TERMを設定する
export TERM=xterm

# Step 3: Ctrl+Z でncをバックグラウンドに落とす（テスター端末に戻る）

# Step 4: [Attacker] ローカル端末のエコー設定を変更する（入力が二重表示されなくなる）
# ⚠️  このコマンドを打った直後、画面が一切反応しなくなる（文字が表示されない）。
#     正常な動作なので慌てない。そのまま "fg" とタイプして Enter を押す。
stty raw -echo

# Step 5: [Attacker] バックグラウンドのncをフォアグラウンドに戻す
fg
# Enterを1〜2回押すとシェルプロンプトが戻ってくる
```

完了後の確認：`Ctrl+C` が機能し、プロンプトが `user@host:~$` 形式になる。

## python3がない場合の代替手段

```bash
# python2（古いシステム）
python -c 'import pty; pty.spawn("/bin/bash")'

# script コマンド（ほぼ全Linuxにある）
script /dev/null -c bash

# perl
perl -e 'exec "/bin/bash";'
```

## stty raw -echo の意味

| コマンド部分 | 意味 |
|-----------|------|
| `stty raw` | キー入力を生のまま転送する（Ctrl+C等のシグナルが正しく伝わる） |
| `-echo` | ローカル側でのエコーを無効化（入力が二重表示されなくなる） |
| `fg` | バックグラウンドに落としたnetcatをフォアグラウンドに戻す |

## 注意点・落とし穴
- `stty raw -echo` 実行後はローカルターミナルも無応答に見える（キー入力がエコーされない）が、そのまま `fg` と打てばシェルが戻ってくる
- `stty raw -echo` は**必ず Ctrl+Z でnetcatをバックグラウンドに落としてから**実行する。順番を間違えるとセッションが切れる
- `su [user]` でパスワード入力画面が止まって進まない場合は、TTY割り当てを先に行っていないことが原因。python3 pty.spawn から再実行する
- セッションが切れた場合は再度リバースシェルペイロードを送り直す

## 関連技術
- 前：リバースシェル取得 → `../02_Initial_Access/Web_Vulnerabilities/Command_Injection.md`
- 後：侵入後の列挙 → `./Enumeration_Checklist.md`
