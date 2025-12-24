## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS
  - この技術で満たす/破れる点：
    - 破れる：ディレクトリ（AD）と端末設定（GPO）が“設計上の権限境界”になっている環境では、Webアプリの脆弱性が無くても、GPOの変更権限（DACL/委任）が突破口となり、横展開・永続化・防御回避が成立する。
    - 満たす：GPOの作成/編集/リンク（適用範囲変更）を最小権限で分離し、Tier分離・変更監査（AD変更＋SYSVOL変更）・承認フローで統制する。
- WSTG
  - 該当テスト観点への接続：
    - WebアプリがIWA（Kerberos/Negotiate）やAD連携（LDAP/SMB/WinRM/RDP）に依存する場合、GPOは「端末/サーバの防御設定」「認証ポリシー」「ログ設定」を一括で上書きし得るため、WSTGの認証/セッション/認可評価の“前提条件（環境依存）”として扱う。
- PTES
  - 位置づけ：Post-Exploitation / Lateral Movement / Persistence の“成立条件”を、Enumeration（AD/ACL/GPOリンク）で確定し、影響評価（適用範囲）→是正（権限分離）→検知（変更監査）まで閉じる。
  - 前後の繋がり（1行）：
    - `15_acl_abuse` で見つけた「OU/GPOへの書き込み権限」を、`05_scanning` の到達性と結合し、GPOが“どの資産に適用されるか”を根拠付きで優先度付けする。
- MITRE ATT&CK
  - 戦術：Persistence / Privilege Escalation / Lateral Movement / Defense Evasion
  - 位置づけ：GPOは“正規の構成管理”であり、権限が崩れると「正規機能の濫用」で広範囲の永続化が成立する。

---

# 16_gpo_永続化と権限境界

## タイトル
GPO（Group Policy）：GPC（AD）＋GPT（SYSVOL）の二重構造と、Link権限/編集権限/配布経路を分離して捉え、永続化の成立条件を“権限グラフ”として確定する

---

## 目的（この技術で到達する状態）
- 次を“状態”として断言できるようにする（曖昧な一般論で終えない）。
  1) GPOが **どこに保存され（AD側=GPC / SYSVOL側=GPT）**、クライアントが **どう取得して適用するか** を説明できる
  2) 永続化に繋がるGPO操作を **3つの権限（作成/編集/リンク）** に分解し、どれが欠けると成立しないかを言える
  3) 「この主体がこのOU/Domainに対してGPLinkを書ける」「この主体がこのGPOを編集できる」を、ACL（DACL）と属性（gPLink等）で根拠化できる
  4) 影響（適用範囲）を、OU階層・リンク順序・Enforced/Block・Security Filtering・WMI Filtering・Loopbackで説明できる
  5) 報告で、是正（権限分離・Tier設計・変更監査）と検知（AD変更＋SYSVOL変更＋クライアント適用ログ）まで提示できる

---

## 前提（用語と構造：ここを混ぜると薄くなる）
### 1) GPOは「ADの参照情報（GPC）」と「SYSVOLの実体（GPT）」の2つで成立する
- GPC（Group Policy Container）
  - AD内の `groupPolicyContainer` オブジェクト（参照情報）
  - 代表属性：`gPCFileSysPath`（GPTの場所を指す）
- GPT（Group Policy Template）
  - SYSVOL配下にあるファイル/フォルダ群（設定・スクリプト・Preferences等）
- 重要：クライアントは「ADでGPCを見て（どれが適用対象か）→ gPCFileSysPathを得て → そのパスのGPTを読みに行く」という二段で動く。

### 2) 適用の境界（Scope）は “どこにリンクされ、どの条件で絞られるか”
- リンク単位：Site / Domain / OU
- 適用順序（概念）：Local → Site → Domain → OU（OUは階層＋リンク順序）
- 絞り込み：
  - Security Filtering（GPOの適用対象セキュリティプリンシパル）
  - WMI Filtering（端末条件での適用分岐）
  - Loopback（ユーザー設定の適用を「ログオン先コンピュータ基準」に変える：キオスク/VDI等）

### 3) 永続化の成立条件は「作成/編集/リンク」の組み合わせで決まる（ここを分ける）
- 作成（Create）：新しいGPOを作れる
- 編集（Edit）：既存GPOの設定（GPT/GPC）を変更できる
- リンク（Link）：OU/Domain/SiteにGPOを関連付けて適用範囲を変えられる（=影響を拡げられる）
- 重要：編集権限だけでは影響範囲が小さい場合がある。リンク権限だけでも「既存の強いGPO」を繋ぎ替える/優先順序変更で影響が出ることがある。

---

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 観測対象（一次データ）
- AD（LDAP）
  - GPO：`CN=Policies,CN=System,<DomainDN>` 配下の `groupPolicyContainer`
    - 取得したい属性：`displayName`, `name`（GUID）, `gPCFileSysPath`, `versionNumber`, `whenChanged`, `nTSecurityDescriptor`
  - OU/Domain：`gPLink`, `gPOptions`（リンク設定、ブロック等）
    - 取得したい属性：OU DN, `gPLink` の中身（リンクされたGPO GUID群＋linkOptions）
- SYSVOL（SMB）
  - `\\<domain>\SYSVOL\<domain>\Policies\{GUID}\` 配下のファイル
    - GPTの入口：`GPT.INI`（バージョンなど）
    - 永続化に繋がりやすい場所（例）：Scripts / Preferences（ScheduledTasks/Services/Registry/Groups等のXML）

### 境界（Boundary）を3種類で固定する
- 資産境界：影響を受ける端末/サーバはどれか（Tier0/DC/管理サーバ/基幹サーバ/一般端末）
- 信頼境界：GPO編集やリンクを許されている主体は誰か（運用委任グループが“広すぎないか”）
- 権限境界：DACL（WriteDACL/GenericAll/WriteProperty）と、OU上の `gPLink` 変更権限がどこにあるか

---

## 実施方法（最高に具体：棚卸し→成立条件→影響→是正→検知）
> 原則：本番で“攻撃的変更”をしない。検証が必要なら、検証OU/検証GPOで「無害な設定」を使い、必ず巻き戻す。

---

### Step 0：入力を固定（再現性）
- 必須入力
  - DomainDN（例：DC=corp,DC=local）
  - 代表DC（LDAP/SMBの接続先）
  - 自分の観測点（内部端末 / VPN / ピボット越し）
- 任意入力（あると強い）
  - RSAT（GroupPolicy PowerShell）使用可否
  - BloodHound等のグラフ化可否（15_acl_abuseと連携）

---

### Step 1：GPOの全量棚卸し（GPC一覧を作る）
#### 1-A（推奨）：Windows/RSATで一覧＋レポートを作る（読み取り中心）
- 目的：GPOのGUID・表示名・変更時刻・リンク先を短時間で揃える
~~~~
# 例：GPO一覧（GUIDと表示名）
Get-GPO -All | Select-Object DisplayName, Id, Owner, CreationTime, ModificationTime

# 例：特定GPOの内容をXMLで出力（“何が設定されているか”を後で機械的に検索できる形にする）
Get-GPOReport -Guid <GPO_GUID> -ReportType Xml -Path .\gpo_<GPO_GUID>.xml
~~~~
- 判断（次の一手）
  - “重要GPO”候補（Default Domain Policy / Default Domain Controllers Policy / 基幹サーバOUにリンク）を先に抽出して深掘りへ

#### 1-B：Linux/LDAPでGPCを棚卸し（RSAT不可の現場用）
- 目的：GPO（groupPolicyContainer）の事実（GUID・gPCFileSysPath等）をLDAPで確定
~~~~
# base: CN=Policies,CN=System,<DomainDN>
ldapsearch -x -H ldap://<DC_IP> -b "CN=Policies,CN=System,<DomainDN>" -s one \
  "(objectClass=groupPolicyContainer)" \
  displayName name gPCFileSysPath versionNumber whenChanged
~~~~
- 判断（次の一手）
  - `gPCFileSysPath` が想定のSYSVOL（\\domain\SYSVOL\domain\Policies\{GUID}）から逸脱していないかを確認（逸脱は“参照先の境界”が崩れている可能性）

---

### Step 2：リンク（適用範囲）棚卸し（OU/DomainのgPLinkを解析する）
> 「どのGPOが危険か」は、内容だけでなく“どこに効くか”で決まる。

#### 2-A：OUに紐づくGPOリンクをLDAPで列挙
~~~~
# gPLinkを持つOUを列挙（=どこにGPOがリンクされているか）
ldapsearch -x -H ldap://<DC_IP> -b "<DomainDN>" -s sub \
  "(&(objectClass=organizationalUnit)(gPLink=*))" \
  distinguishedName gPLink gPOptions
~~~~

#### 2-B：gPLink文字列の読み方（最低限）
- 典型形式（概念）：
  - `[LDAP://cn={GPO-GUID},cn=policies,cn=system,DC=...;linkOptions]` が連結して入る
- linkOptions（例）
  - Enabled/Disabled、Enforced（強制）等がビットで表現される
- 判断（次の一手）
  - Domain直下/上位OUに強制（Enforced）があるGPOは、影響が広いので優先度を上げる
  - 逆に“下位OUのBlock Inheritance”で効かない経路があるため、必ずOU階層と一緒に評価する

#### 2-C：RSATで継承・リンク状態を可視化（可能なら）
~~~~
# 例：OU単位の継承状況（どのGPOが上から降りてくるか）
Get-GPInheritance -Target "OU=<OUName>,<DomainDN>"
~~~~
- 判断（次の一手）
  - 影響範囲（適用対象コンピュータ/ユーザー）を“OU単位”で確定し、次のStep 3で「編集/リンク権限の所在」と結合する

---

### Step 3：成立条件（権限境界）を分解して確認する
> GPOの悪用は「編集できる」だけでは足りないことがある。必ず“どの権限がどの結果を生むか”を分ける。

#### 3-1 編集（Edit）権限：そのGPO自体を書き換えられるか
- 何を確認するか（状態）
  - 対象GPO（groupPolicyContainer）のDACLで、主体Sが
    - GenericAll / WriteDACL / WriteOwner / GenericWrite 等の“状態遷移権限”を持つか
  - 併せてSYSVOL側（GPT）への書き込みが実質可能か（運用上はGPO編集権限に含まれることが多いが、逸脱があると境界が崩れる）
- 実施（読み取り）
  - `15_acl_abuse` の手順で、GPOオブジェクトのDACLを抽出し、危険権限だけ抜き出す
  - GPO内容（XMLレポート）を取得し、「永続化に繋がる設定が既に入っていないか」を検査する（後述）

#### 3-2 リンク（Link）権限：OU/DomainのgPLinkを書けるか（=適用範囲を変えられる）
- 何を確認するか（状態）
  - OU/Domainオブジェクトに対して、主体Sが `gPLink` / `gPOptions` を変更できる（WriteProperty等）か
- 実施（読み取り）
  - OU/DomainのDACLを抽出し、「GPLink相当の書き込み権限が委任されている主体」を特定する（ここが運用委任で崩れやすい）
- 判断（次の一手）
  - 「リンク権限はあるが編集権限がない」場合：
    - 既存の強いGPO（例：管理サーバ設定）を別OUへリンクしてしまう、リンク順序を変える、強制を付け替える等で影響が出得るため、リンク権限単体でも高リスクになり得る。
  - 「編集権限はあるがリンク範囲が狭い」場合：
    - 影響は限定されるが、対象OUが基幹サーバなら重大。OU内の資産価値で優先度を決める。

#### 3-3 作成（Create）権限：新規GPOを作れるか（=攻撃面が拡がる）
- 何を確認するか（状態）
  - 主体SがGPOを新規作成できる（例：作成委任グループに含まれる）
  - さらに「作ったGPOをどこにリンクできるか（=Link権限）」がセットで揃うと影響が広がる
- 判断（次の一手）
  - CreateとLinkが両方揃う主体は、永続化の成立条件として優先度が高い（“好きなOUに自作GPOを刺せる”）

---

### Step 4：GPO内容の“永続化要素”を検査する（変更せずに危険度を上げる）
> 実務で価値が出るのは「どのGPOが危険な設定を配れる状態か」を、証跡付きで言えること。

#### 4-1 GPOレポート（XML/HTML）を作り、危険キーワードで機械的に当てる
- 目的：人間の目視だけにせず、再現性ある手順にする
~~~~
# 例：GPOレポートをXMLで出力→文字列検索で“設定カテゴリ”を当てる
Get-GPOReport -Guid <GPO_GUID> -ReportType Xml -Path .\gpo_<GPO_GUID>.xml

# 例：永続化/遠隔操作/防御低下に繋がりやすいカテゴリ（環境で調整）
# - ScheduledTasks / Services / Scripts / Registry / Groups / RestrictedGroups / SecurityOptions / Firewall / WinRM / RDP など
~~~~
- 判断（次の一手）
  - 「危険カテゴリが含まれる」×「影響範囲が広い」×「編集権限が緩い」＝最優先
  - 「危険カテゴリが含まれない」でも、編集権限が緩いGPOは“将来の注入点”なので是正候補

#### 4-2 SYSVOL（GPT）側の実体チェック（読み取り）
- 目的：GPOが“実際に配るファイル”を確認し、スクリプト/Preferencesの存在を事実化
~~~~
# Linux例（読み取り）：SYSVOLのPolicies配下を参照
# smbclient // <DC_or_DOMAIN>/SYSVOL -U <user>
# smb: \> cd <domain>\Policies\{GPO_GUID}\
# smb: \> ls
# 重点：GPT.INI / Machine\ / User\ / (Preferences配下のXMLなど)

# Windows例（読み取り）：UNCパスで参照
# dir \\<domain>\SYSVOL\<domain>\Policies\{GPO_GUID}\
~~~~
- 判断（次の一手）
  - スクリプトが存在するGPOは、変更された場合の影響が直感的に大きい（“実行”に直結しやすい）ため、権限・監査の優先度を上げる

#### 4-3 GPC→GPT参照先（gPCFileSysPath）の逸脱確認（参照境界）
- 目的：クライアントが“どこからGPTを取るか”を示す参照先が想定外になっていないか
- 判断（次の一手）
  - gPCFileSysPathが想定外（SYSVOL外、任意共有等）なら、GPO配布の信頼境界が崩れている可能性があるため最優先で是正・監査対象

---

### Step 5：影響評価（どこまで効くか：OU階層＋絞り込みで確定）
- 影響を決める要素（最低限）
  - リンク先（Site/Domain/OU）
  - OU階層と継承、Block Inheritance、Enforced
  - Security Filtering（誰に適用されるか）
  - WMI Filtering（どの端末に適用されるか）
  - Loopback（ユーザー設定が“どの端末で”効くか）
- 実務の結論（状態として）
  - 「このGPOは、OU=X配下のコンピュータY群に適用される（理由：リンク/継承/フィルタ）」の形で書く
  - “不明”を残さない：不明な要素（WMI/Loopback/セキュリティフィルタ）があるなら、それ自体を追加調査タスクとして明記する

---

### Step 6：是正（削除だけでなく、権限分離と設計代替で閉じる）
- 原則：GPOの権限は「作成/編集/リンク」を分離し、運用委任は“最小OU・最小GPO・最小主体”に閉じる
- 具体（設計として書ける形）
  - Tier分離（Tier0/DC/管理サーバ/一般端末でOUを分離し、上位OUに広範なリンクを置かない）
  - Default Domain Policy / Default Domain Controllers Policy を“運用でいじらない”方針（変更は専用GPOで）
  - GPO作成権限を限定（作成できる＝注入点が増える）
  - OUのgPLink書き換え権限（Link委任）を厳格化（リンクは影響範囲の変更＝高リスク操作）
  - GPO編集権限（Edit）を限定（編集＝配布内容の変更＝永続化に直結）
  - SYSVOLの監査（変更監査）とバックアップ/差分管理（“いつ・誰が・どのファイルを”）

---

### Step 7：検知（AD変更＋SYSVOL変更＋クライアント適用の三点セット）
> 「変更が起きた」だけでは足りない。どこが変わったか（GPC/GPT/Link）を分離して捕まえる。

#### 7-1 AD（GPC/OU）変更の監査：Directory Service Changes
- 狙い：GPO本体（GPC）やリンク（gPLink）が変わった瞬間を捕捉する
- 最低限の観測
  - GPO（groupPolicyContainer）の属性変更（例：versionNumber、gPCFileSysPath等）
  - OU/Domainの `gPLink` / `gPOptions` 変更（リンク/ブロック/強制）
- 実務メモ
  - 監査イベントは「SACLで有効化して初めて出る」ため、監査設計（どのオブジェクトに何を監査するか）が前提になる

#### 7-2 SYSVOL（GPT）変更の監査：ファイルアクセス監査
- 狙い：配布実体（GPT.INI、Scripts、Preferences XML等）の変更を捕捉する
- 最低限の観測
  - `\\<domain>\SYSVOL\<domain>\Policies\{GUID}\` 配下でのファイル変更（作成/更新/削除）
- 実務メモ
  - ここもSACL（ファイル/フォルダ監査）設計が前提。監査対象は“Policies配下”を中心に、ノイズを制御する

#### 7-3 クライアント側の適用ログ：GroupPolicy/Operational と gpresult
- 狙い：「変更が、実際にどの端末に適用されたか」を確定する（影響範囲の裏取り）
- 使い分け（現場）
  - 個別端末：`gpresult`（適用/拒否GPOと理由）
  - 体系：GroupPolicy/Operational（適用開始/完了、適用一覧、拒否理由など）
  - 深掘り：GPSvcのデバッグログ（適用トラブルや取得失敗の原因切り分け）

---

## 結果の意味（この出力が示す状態：何が言える/言えない）
### 言える（最低限）
- GPOはGPC（AD）とGPT（SYSVOL）で構成され、適用範囲はgPLink等のリンク情報で決まる
- 主体Sが
  - (a) GPOを編集できる（GPOのDACL上の権限）
  - (b) OU/Domainにリンクを変更できる（OU/DomainのgPLinkを触れる権限）
  - (c) 新規作成できる（作成委任）
  のどれを持つかにより、永続化の成立条件が変わる
- 影響範囲は、リンク先（OU/Domain/Site）と継承・強制・ブロック・フィルタで根拠付きに確定できる

### 言えない（この時点で断言しない）
- 即座に侵害できる（到達性、監視、資格情報強度、端末側制御で成立は変わる）
- “そのまま”本番で検証してよい（変更は広範囲影響になり得るため、検証OUでの安全設計が前提）

---

## 攻撃者視点での利用（意思決定：どれを先に見るか）
> ここは手口列挙ではなく、優先度付けの軸として使う。

### 優先順位の原則（実務）
1) 高価値OU/Domainに対する Link権限（gPLink変更）が緩い
2) 影響が広いGPO（上位OU/Domain、Enforced）に対する Edit権限が緩い
3) Create権限＋Link権限が同一主体に揃う（“好きに刺せる”）
4) gPCFileSysPathの参照先を変えられる（配布の信頼境界が崩れる）

### “危険度が跳ねる状態”の例（状態で書く）
- 低権限に近い主体が、Domain直下/上位OUのgPLinkを書ける
- 既にスクリプト/Preferences（タスク/サービス/レジストリ等）を配るGPOに対して、編集権限が委任されている
- Default系GPO（全域に効く）に対する編集権限が過剰
- 監査（AD変更/SYSVOL変更）が無く、変更が追えない

---

## 次に試すこと（仮説A/B：条件で手が変わる）
### 仮説A：OU/DomainのgPLinkを書ける主体が見つかった（Link権限）
- 次の一手
  - そのOU配下の資産価値（Tier）を確定し、影響範囲を明記
  - 主体が「どのGPOをリンクできるか（既存GPO）」と「新規作成できるか（Create）」を確認
  - `15_acl_abuse` でOUのDACLを裏取りし、レポートにACE根拠を残す

### 仮説B：特定GPOに編集権限が見つかった（Edit権限）
- 次の一手
  - そのGPOがどこにリンクされ、誰に適用されるか（Step 2/5）を確定
  - GPOレポート（XML）で永続化に繋がるカテゴリが含まれるかを検査（変更せず危険度を高める）
  - 監査（GPC/GPT）とバックアップ運用の有無を確認し、是正に繋げる

### 仮説C：gPCFileSysPathが想定外、または変更できそう（参照境界）
- 次の一手
  - 参照先の共有（SMB）の管理主体・ACL・署名/アクセス制御を確認
  - “参照先変更の監査”が取れるか（GPC属性の監査）を確認し、最優先で是正計画へ

### 仮説D：目立つ権限緩和が見つからない
- 次の一手
  - 変更監査が整っているか（整っていないなら将来の改変点として是正提案）
  - 代替の横展開経路（`14_delegation` / `13_adcs` / `10_ntlm_relay` / `18_winrm` / `19_rdp` / `20_mssql`）へ主軸を移し、GPOは“防御設定の前提確認”として維持する

---

## 手を動かす検証（04_labsと連動：安全に差分が出る設計）
> 目的：本番での危険な変更を避けつつ、「GPOの二重構造」「リンクの影響」「監査ログ」を観測で理解する。

### Lab最小構成
- DC（AD DS + SYSVOL）
- メンバーサーバ（管理対象：Computer GPO適用）
- クライアント端末（User GPO適用）
- OUを3つ
  - OU_Tier0（DC/管理）
  - OU_Servers（メンバーサーバ）
  - OU_Workstations（クライアント）

### 変数（1つずつ変える）
- Linkの変化：OUにリンク/解除、リンク順序、Enforced、Block Inheritance
- Filterの変化：Security Filtering（対象グループ）、WMI Filter（OS条件など）
- GPO内容：無害な設定（壁紙/バナー/ログ設定など）だけを入れて差分を観測

### 観測点（必須）
- AD（GPC/OU）
  - GPOの `versionNumber`, `gPCFileSysPath`, `whenChanged`
  - OUの `gPLink`, `gPOptions`
- SYSVOL（GPT）
  - `GPT.INI` の差分
  - Machine/User配下の差分（設定がファイルにどう落ちるか）
- クライアント
  - gpresult（適用/拒否の理由）
  - GroupPolicy/Operational（適用開始/完了、適用一覧）

### 巻き戻し（必須）
- 変更前にスナップショット
- 変更は“検証OUだけ”に限定
- 変更ログ（誰がいつ何を変えたか）をLabでも残す（監査設計の練習）

---

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回）
- ASVS：GPO権限（作成/編集/リンク）と監査（AD変更＋SYSVOL変更）を最小権限・職務分離・変更管理で統制することが、認証基盤/端末基盤の境界維持に直結する。
- WSTG：WebがAD連携する環境では、GPOが端末/サーバの防御と認証挙動を変えるため、WSTGの認証/セッション/認可評価の“前提条件”として観測・固定する。
- PTES：列挙（GPO/リンク/ACL）→成立条件（作成/編集/リンク）→影響（適用範囲）→是正（権限分離/Tier）→検知（変更監査＋適用ログ）で閉じる。
- ATT&CK：GPOは正規の構成管理であり、権限が崩れるとPersistence/Defense Evasion/Lateral Movementに接続する“広域な配布チャネル”になる。

---

## 深掘りリンク（作成済み / 予定：最大8件）
- `05_scanning_到達性把握（nmap_masscan）.md`
- `07_pivot_tunneling（ssh_socks_chisel）.md`
- `11_ldap_enum_ディレクトリ境界（匿名_bind）.md`
- `14_delegation（unconstrained_constrained_RBCD）.md`
- `15_acl_abuse（AD権限グラフ）.md`
- `18_winrm_psremoting_到達性と権限.md`
- `19_rdp_設定と認証（NLA）.md`
- `20_mssql_横展開（xp_cmdshell_linkedserver）.md`
