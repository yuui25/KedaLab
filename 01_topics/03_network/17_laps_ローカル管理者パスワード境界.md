## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回）
- ASVS：
  - 端末ローカル管理者は「認証基盤の末端」に存在する“特権ID”であり、再利用・共有・平文保管は最小権限/特権管理/監査要件を破壊する。
  - LAPSは「パスワードを一意化して再利用を潰す」統制だが、AD属性の読み取り権限（委任ACL）が広いと境界が崩れる。
- WSTG：
  - WebがIWA/AD連携（WinRM/RDP/SMB/MSSQL等）に依存する環境では、端末/サーバのローカル管理者が奪われると“Webの境界”を飛び越えて管理面へ到達する。
  - WSTGの認証/セッション/認可テストは、背後の運用基盤（LAPS/委任/監査）により現実の到達性が変わるため、前提入力として扱う。
- PTES：
  - Enum（LAPS有無・スキーマ・適用範囲・ACL）→ Analysis（読取/リセット権限の広さ）→ Post-Exploitation想定（横展開の成立条件）→ Reporting（是正/検知）で閉じる。
- MITRE ATT&CK：
  - Lateral Movement / Privilege Escalation の“成立条件”として、端末ローカル管理者PWの再利用・漏えい・過剰委任を位置づける（LAPSはそれを抑止するが、委任設計が崩れると逆に横展開の燃料になる）。

---

# 17_laps_ローカル管理者パスワード境界

## 目的（このファイルで到達する状態）
次を「状態」として、根拠（属性/ACL/適用範囲/ログ）付きで言えるようにする。

1) その環境が **Legacy LAPS** か **Windows LAPS**（または両方/移行中）か、もしくは **Entra IDへバックアップ** かを判定できる  
2) LAPSが守る境界を「ADのどの属性にPWが保管され、誰が読め、誰が期限変更/リセットできるか」で分解できる  
3) “読める主体”が広すぎる・ネストで広がる・Tierを跨ぐ、などのリスクを `15_acl_abuse` の見方で説明できる  
4) 適用範囲（どのOU/どの端末が管理対象か）と未管理端末（穴）を見つけられる  
5) 報告で、是正（委任分離・Tier設計・ポリシー値）と検知（ADアクセス/Windows LAPSイベント/変更監査）まで提示できる

---

## 前提（LAPSの“境界”の定義を固定）
### 1) Legacy LAPS と Windows LAPS の違い（境界上の要点）
- Legacy LAPS（旧 Microsoft LAPS）
  - ADコンピュータオブジェクトに **平文PW** を格納：`ms-Mcs-AdmPwd`
  - 期限：`ms-Mcs-AdmPwdExpirationTime`
  - 属性は“Confidential”等のフラグが付く（=読める主体はACLで制御される）  
- Windows LAPS（新：OS内蔵）
  - ADに平文：`msLAPS-Password`、期限：`msLAPS-PasswordExpirationTime`
  - さらに **暗号化PW**：`msLAPS-EncryptedPassword`（および履歴/DSRM系）  
  - 暗号化PWは **ms-LAPS-Encrypted-Password-Attributes** の拡張権限で制御される  
  - PowerShellモジュール（LAPS）が標準で提供され、委任発見・読取・監査設定まで含む  
- 重要：どちらも「AD属性（PW）を読める主体」が境界。平文/暗号化は“被害の形”が変わるだけで、ACLが緩いと境界が崩れる。

（属性対応の根拠：Windows LAPSとLegacy LAPSのスキーマ対応表）  
- Windows LAPS：`msLAPS-PasswordExpirationTime` ↔ Legacy：`ms-Mcs-AdmPwdExpirationTime` 等（スキーマ対応）  
- Windows LAPS拡張権限：`ms-LAPS-Encrypted-Password-Attributes`（GUIDあり）

---

## 観測ポイント（一次データ：これだけ揃えば薄くならない）
### A) AD（LDAP）で確認するもの
- コンピュータオブジェクトの属性（LAPS“実データ”）
  - Legacy：`ms-Mcs-AdmPwd`, `ms-Mcs-AdmPwdExpirationTime`
  - Windows：`msLAPS-Password`, `msLAPS-PasswordExpirationTime`, `msLAPS-EncryptedPassword`（必要なら履歴/DSRMも）
- 属性の性質（監査・複製・秘匿の前提）
  - `ms-Mcs-AdmPwd` は cleartext password を格納し、Confidential等のsearchFlagsを持つ  
  - `msLAPS-EncryptedPassword` は暗号化PWを格納し、Confidential等のsearchFlagsを持つ  
- OU（適用範囲/委任境界）
  - どのOUにLAPSが適用されるか（GPO/Intune/CSPに依存）
  - “誰がそのOU配下のLAPS PWを読めるか/期限変更できるか”（OU上の委任）

### B) クライアント側（Windows）で確認するもの
- Windows LAPSイベントログ（運用/失敗/バックアップ先の確認）
  - `Applications and Services Logs > Microsoft > Windows > LAPS > Operational`
  - 処理開始/終了/失敗（代表：10003/10004/10005）、ADバックアップ系のイベントID群

### C) ポリシー（設定値）で確認するもの
- Windows LAPSの主要設定（最小）
  - `BackupDirectory`（Disabled/Entra/AD）
  - `AdministratorAccountName`（どのローカル管理者を管理するか）
  - `PasswordAgeDays`, `PasswordLength`, `PasswordComplexity`
  - AD暗号化関連（ADバックアップ時のみ）：`ADPasswordEncryptionEnabled`, `ADPasswordEncryptionPrincipal`, 履歴サイズ等
  - 追加：`PostAuthenticationActions` など（運用要求により）

---

## 実施方法（最高に具体：判定 → スコープ → 権限 → リスク → 検知/是正）
> 原則：本番でPW取得を“実行”する前に、契約（許可）と影響（取り扱い/ログ/保管）を確定する。  
> ただし“読める状態”の証跡は、ACL/委任の根拠（誰が読めるか）で十分に示せる。

---

### Step 1：方式判定（Legacy / Windows / Entra / 移行中）
#### 1-1 AD側：属性“存在”と“実際に埋まっているか”を分けて確認
- 方式判定で重要なのは「スキーマがある」ではなく「端末オブジェクトに値が入っている」。
- Linux（ldapsearch）で“値がある端末”を探す（権限が必要な場合あり）
~~~~
# Legacy LAPS：期限属性が入っている端末を探す（期限は平文PWより取得しやすい場合がある）
ldapsearch -x -H ldap://<DC_IP> -b "<DomainDN>" -s sub \
  "(ms-Mcs-AdmPwdExpirationTime=*)" \
  dn ms-Mcs-AdmPwdExpirationTime

# Legacy LAPS：PW属性の存在（権限がないと値は取れない）
ldapsearch -x -H ldap://<DC_IP> -b "<DomainDN>" -s sub \
  "(ms-Mcs-AdmPwd=*)" \
  dn ms-Mcs-AdmPwd

# Windows LAPS：平文PW/期限/暗号化PWの有無（いずれかが入っている端末を探す）
ldapsearch -x -H ldap://<DC_IP> -b "<DomainDN>" -s sub \
  "(msLAPS-PasswordExpirationTime=*)" \
  dn msLAPS-PasswordExpirationTime

ldapsearch -x -H ldap://<DC_IP> -b "<DomainDN>" -s sub \
  "(msLAPS-EncryptedPassword=*)" \
  dn msLAPS-EncryptedPassword
~~~~
- 判断（次の一手）
  - `(ms-Mcs-AdmPwdExpirationTime=*)` が多数：Legacy運用の可能性が高い  
  - `(msLAPS-EncryptedPassword=*)` が存在：Windows LAPS（AD暗号化）運用の可能性が高い  
  - 両方が混在：移行中/OUごとに方式が違う可能性 → スコープ（Step 2）へ

#### 1-2 Windows端末側：Windows LAPSイベントログの存在とイベントIDで運用を確定
- 端末/サーバ（管理対象になっていそうな端末）で確認
  - `Microsoft-Windows-LAPS/Operational` を開けるか
  - 10003開始/10004終了/10005失敗、AD/Entraのシナリオ別イベントIDが出ているか

---

### Step 2：適用範囲（どのOU/どの端末が管理対象か）を確定
> “LAPS導入済み”でも、OU例外・サーバ例外・新規端末未適用があると、境界に穴が残る。

#### 2-1 端末一覧 × LAPS属性有無 で「未管理端末」を作る
- 目的：資産価値（Tier）で優先度付けするため、まず “管理されていない端末” を可視化する
- 例：コンピュータ全件を取り、LAPS期限属性の有無で分類（LDAP）
~~~~
# 全コンピュータのDNとOUを取り、LAPS期限が無いものを抽出する発想（実際は件数が多いのでOU単位で分割）
ldapsearch -x -H ldap://<DC_IP> -b "<DomainDN>" -s sub \
  "(&(objectClass=computer)(!(ms-Mcs-AdmPwdExpirationTime=*)))" \
  dn
~~~~
- 判断（次の一手）
  - DC/管理サーバ/基幹サーバが未管理：最優先で是正（OU設計/例外運用の見直し）
  - 一般端末の一部のみ未管理：新規端末プロビジョニング/OU移動手順の穴の可能性

#### 2-2 GPO/CSP（Windows LAPSポリシー）で“BackupDirectory”と管理対象アカウントを確定
- Windows LAPSは `BackupDirectory` が Disabled だと他設定が無視される（=導入してても効いてない）  
- 最低限確認する設定（ADバックアップ想定の例）
  - `BackupDirectory=2 (AD)` か
  - `AdministratorAccountName`（built-inかカスタムか）
  - `PasswordAgeDays`, `PasswordLength`, `PasswordComplexity`
  - `ADPasswordEncryptionEnabled`, `ADPasswordEncryptionPrincipal`（暗号化運用なら特に重要）

---

### Step 3：権限境界（誰が“読めるか/期限変更できるか”）をOU単位で確定
> LAPSの本体は「AD属性を読める権限」。“Helpdesk全員が読める”設計が本当に妥当か、Tier境界で評価する。

#### 3-1 Windows LAPS（推奨）：委任状況の発見コマンドで“読める主体”を列挙
- Windows LAPSモジュールには、OUに付与された拡張権限を列挙するコマンドがある
  - `Find-LapsADExtendedRights`（OUの委任状態の発見）
- 読取権限の委任
  - `Set-LapsADReadPasswordPermission`（“誰に読ませるか”を設定するコマンド）
- リセット（期限変更）権限の委任
  - `Set-LapsADResetPasswordPermission` / `Set-LapsADPasswordExpirationTime`

（攻撃/防御どちらでも重要な分離）
- Read権限：読める＝即座に横展開燃料になり得る
- Reset権限：単体だとDoS/運用影響が中心だが、Readと組み合わさると“即時更新→即時取得”が可能になり得る

#### 3-2 Legacy LAPS：同等の委任発見・委任設定がある
- Legacyは `AdmPwd.PS` のコマンド体系（Windows LAPSの表に対応づけがある）
- 読取権限の委任例（Legacy側の代表）
  - `Set-AdmPwdReadPasswordPermission`（OU配下コンピュータのLAPS PW読取を委任）

#### 3-3 15_acl_abuse と結合して“広さ”を判定（ここがレポートの芯）
- 手順（固定）
  1) 対象OU（例：Servers OU / Workstations OU）を列挙
  2) OUの委任（読取/リセット）で列挙された主体（グループ）をSID解決し、ネストで広がるか確認
  3) “Tierを跨いでいないか”を確認（Tier0にTier1運用者が読取権限を持つ等）
  4) 例外運用（緊急時読取のブレークグラス）があるなら、別経路（JIT/PAW/承認）になっているか確認

---

### Step 4：リスク評価（LAPSが“効いている”のに境界が崩れるパターン）
#### パターンA：読取権限が広い（境界崩壊）
- 状態：
  - 低権限に近い運用グループ/大人数グループが、サーバOUのLAPS PWを読める
- 影響：
  - 1台の端末侵害 → ADのLAPS属性を読むだけで多数端末のローカル管理者PWを得られる可能性
- 優先度決定：
  - “読める主体の広さ” × “対象OUの資産価値（Tier）” × “到達性（RDP/WinRM/SMB）”

#### パターンB：適用漏れ（穴が残る）
- 状態：
  - 重要サーバがOU例外/新規端末未移動でLAPS未管理
- 影響：
  - 再利用/初期PW/イメージ由来PWが残り、LAPS導入の目的（横展開抑止）が未達

#### パターンC：ポリシー値が弱い（統制が弱い）
- 状態：
  - `PasswordLength` が短すぎる、`PasswordAgeDays` が長すぎる、`BackupDirectory=Disabled` 等
- 影響：
  - 目的が達成されない、または運用で“手作業PW管理”が復活して別の漏えいを生む

#### パターンD：暗号化運用だが、復号できる主体が広い（実質平文と同じ）
- 状態：
  - `ADPasswordEncryptionPrincipal` 相当の権限が広く、復号可能主体が大きい
- 影響：
  - 暗号化の意図（権限の更なる限定）が達成されない

---

### Step 5：検知（監査設計：LAPSは“読まれたら終わり”になりやすいので、検知もセット）
#### 5-1 Windows LAPSイベントログ（クライアント側）
- 見る場所：`Microsoft > Windows > LAPS > Operational`
- 何が嬉しいか：
  - ポリシー処理の開始/終了/失敗（10003/10004/10005）
  - ADバックアップ/EntraバックアップのイベントID差分（シナリオ別に多数）
- 使い方（実務）：
  - “適用されている端末”の裏取り（未適用端末の発見）
  - 失敗イベントから、OU/権限/スキーマ未展開/ポリシー不整合を切り分け

#### 5-2 AD側：Directory Service Changes / Access（設計が必要）
- ポイント：
  - 監査イベントは「監査カテゴリ有効化」＋「SACL設定」が揃って初めて出る
  - “読む行為（属性読み取り）”を捕捉するには、対象オブジェクト/属性にSACLを設計して `4662` を狙う考え方になる
  - “ACL変更（権限付与）”は `ntSecurityDescriptor` 変更として `5136` / `4662` の監視が有効
- 実務の落とし所：
  - 全端末オブジェクトの“属性読取監査”はノイズが大きい → まずは **OU単位（サーバOU）**、かつ **高価値端末** に限定してSACL設計する

---

## 結果の意味（何が言える/言えない）
### 言える（最低限）
- LAPSがどの方式（Legacy/Windows/Entra）で、ADにどの属性（平文/暗号化）を格納しているか
- その属性を読める主体、期限変更/リセットできる主体が誰か（OU委任/ACL根拠つき）
- どのOU/どの端末が管理対象で、どこに未管理の穴があるか

### 言えない（この時点で断言しない）
- “即侵害できる”：到達性（RDP/WinRM/SMB）・端末の防御設定・監視状況で成立は変わる
- 本番でのPW取得/使用の正当化：契約・許可・証跡・取り扱い設計が前提（ただしACL根拠でリスク説明は可能）

---

## 次に試すこと（条件分岐：NW到達性と結合して“現実の横展開”に落とす）
### A) 読取権限が広い/疑いがある
- 次の一手
  - `15_acl_abuse` の手順で、読取権限を持つグループのネストを展開し“実質何人が読めるか”を確定
  - 対象OUがサーバ/管理系なら、Tier分離（OU分割・委任分離）を是正案の中心にする
  - 監査（4662/SACL）を“サーバOU限定”で提案する（やりすぎない）

### B) 適用漏れがある
- 次の一手
  - 未管理端末を「資産価値順」に並べ、プロビジョニング/OU移動手順を是正提案にする
  - `16_gpo` と繋げて「どのGPO/どのCSPが適用されるべきか」を運用手順として固定

### C) Windows LAPS暗号化運用（msLAPS-EncryptedPassword）を使っている
- 次の一手
  - `ADPasswordEncryptionPrincipal`（復号主体）が最小化されているかを確認
  - 可能なら “復号ができる主体” を棚卸しし、Tier0に閉じる提案（PAW/JIT運用とセット）

---

## 手を動かす検証（04_labs連動：安全に“境界の差分”が出る）
### Lab最小構成
- DC（AD DS）
- クライアント（Windows 11 / Server 2022+ 推奨：Windows LAPSを観測しやすい）
- OUを2つ：`OU_Workstations`, `OU_Servers`
- グループを2つ：`LAPS_Readers_WS`, `LAPS_Readers_SRV`

### 検証シナリオ（差分が出る順）
1) `OU_Workstations` にだけ読取委任 → WSだけ読める状態を作る  
2) 誤って `Domain Users` に読取委任 → 境界崩壊を再現（※本番では絶対にやらない）  
3) `BackupDirectory` を Disabled→AD に変え、端末側イベント（10003/10004/失敗）とAD属性の埋まり方を観測  
4) 監査：OU単位でSACLを設定し、ACL変更（5136/4662）と読取（4662）のノイズを評価する

---

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回）
- ASVS：LAPSは特権ID管理の統制。委任ACL（誰が読めるか）と監査（変更/読取）をセットで設計しないと境界が崩れる。
- WSTG：Webの外にある“運用権限（端末ローカル管理者）”がWebの境界を上書きするため、前提条件として評価する。
- PTES：Enum→Analysis→到達性結合→Reporting（是正/検知）で閉じる。LAPSは「導入有無」ではなく「境界（読取権限と適用範囲）」が本体。
- ATT&CK：横展開燃料（ローカル管理者PW）を抑止する仕組みだが、過剰委任は逆に燃料の集中保管になり得る。

---

## 深掘りリンク（最大8件）
- `05_scanning_到達性把握（nmap_masscan）.md`
- `07_pivot_tunneling（ssh_socks_chisel）.md`
- `11_ldap_enum_ディレクトリ境界（匿名_bind）.md`
- `15_acl_abuse（AD権限グラフ）.md`
- `16_gpo_永続化と権限境界.md`
- `18_winrm_psremoting_到達性と権限.md`
- `19_rdp_設定と認証（NLA）.md`
- `20_mssql_横展開（xp_cmdshell_linkedserver）.md`
