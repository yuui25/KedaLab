# 09_smb_enum_共有・権限・匿名（null_session）

## 具体例（出力の見方）
- 共有一覧で「閲覧可/書込可」を区別する

## 失敗パターンと対処
- 匿名不可: 認証情報の有無を先に確認

## 次に試すこと
- `10_ntlm_relay_成立条件（SMB署名_LLMNR）.md`へ接続
SMBの共有/権限/匿名可否を境界として確定し、横展開と認証攻撃の入口判断に繋げる

## 目標（この技術で到達する状態）
- 445/139が開いている対象に対して、次を“観測根拠つき”で言い切れる。
  1) SMBの実体（Windows/Samba/NAS等の種別、SMB dialect/署名要件、ドメイン帰属）
  2) 匿名（null session）/Guest/認証済み それぞれで「見える共有」「入れる共有」「書ける共有」を区別できる
  3) 共有権限（Share Permission）とファイル権限（NTFS/ACL）の“二段階”を混ぜずに評価できる
  4) 得られた結果から、次工程（NTLM relay / LDAP / Kerberos / GPO / LAPS / WinRM/RDP）へ、迷いなく入力を渡せる
- さらに実務品質として、以下ができる。
  - 影響制御（ログ/負荷/試行回数）を意識した列挙設計ができる
  - 成果物（表）として、IPごとの状態（匿名可否、共有、R/W、署名要件）を整理できる

## 前提・対象・範囲・想定
### 対象（代表）
- Windows（Workgroup / AD参加サーバ / DC / ファイルサーバ）
- Samba（Linuxファイルサーバ、NAS、アプライアンス）
- ルータ/複合機などのSMB実装機（限定的な挙動に注意）

### スコープと安全
- SMB列挙は“認証試行”を伴う。許可された範囲・時間窓・送信元IPを固定する
- 目標は「共有と権限の境界確定」。パスワード当てや過剰試行は別テーマ（合意の上で実施）

### SMBの“境界モデル”（混ぜると誤診する）
- 境界1：到達性（L4）… 445/139へ届くか（`05_scanning`）
- 境界2：SMBの握手… SMB1/2/3どれで会話できるか、署名要件は何か
- 境界3：認証… 匿名/Guest/ユーザ/NTLM/Kerberosで挙動がどう変わるか
- 境界4：共有（Share）… 共有一覧が見えるか、入れるか
- 境界5：権限（ACL）… 入室後の読み/書き可否（Share権限＋NTFS/ACL）

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) SMB “握手”の観測
- 観測するもの
  - SMB dialect（SMB1の可否、SMB2/3の可否）
  - 署名（SMB Signing）が enabled か required か
  - ドメイン/ホスト名/OS推定（可能な範囲）
- 意味
  - 署名required は NTLM relay 成立条件を大きく制限する（`10_ntlm_relay` へ接続）
  - dialect/署名が取れない場合、L4/IDS/IPS/WAFで制御されている可能性を疑う

### 2) 認証境界の観測（null / Guest / 認証済み）
- 観測するもの
  - null session（ユーザ名空/パス空）の可否
  - Guestの可否
  - 失敗時の応答（ACCESS_DENIED / LOGON_FAILURE / STATUS_NOT_SUPPORTED 等）
- 意味
  - 共有一覧が見えることと、共有に入れることは別
  - 認証成功でも権限が弱いことは普通に起きる

### 3) 共有権限とファイル権限（2段階）を分離して観測
- 観測するもの
  - Share単位：READ/WRITE 可能か（入口の権限）
  - ディレクトリ/ファイル単位：list/read/write 可能か（内部の権限）
- 意味
  - ShareでWRITEでも、NTFS/ACLで拒否されることがある
  - “書ける”は横展開・永続化・改ざんの入口になり得るため根拠を残す

### 4) 証跡として残す最低限
- ip / hostname（取れれば）
- domain（取れれば）
- signing（enabled / required / unknown）
- anonymous/guest の可否（一覧/入室/読/書）
- shares（名前、説明、アクセス可否、R/W推定、根拠）

## 結果の意味（その出力が示す状態：何が言える/言えない）
### 状態A：null sessionで共有一覧が見える
- 言える
  - 匿名で共有メタ情報が見える＝情報露出の可能性
  - 次に「入室可能な共有があるか」を確認する価値がある
- 言えない
  - 中身のR/W可否は別途確認が必要

### 状態B：null sessionで共有に入れて list/read できる
- 言える
  - 機微情報が置かれている運用なら境界破綻の可能性が高い
  - 共有用途次第でWeb/AD/クラウドへ連鎖し得る
- 言えない
  - それが“意図した公開”か“事故”かは運用確認が必要

### 状態C：null sessionは不可、Guestは可
- 言える
  - Guestマッピングで実質匿名が成立している可能性
  - 共有と権限の境界がGuestの扱いで破れている可能性
- 言えない
  - その公開が意図的かどうかは確認が必要

### 状態D：署名required
- 言える
  - SMB relayの成立条件は強く制限される
  - ただし認証済み列挙は成立し得る
- 言えない
  - “安全”とは言えない（共有/権限が弱ければ別経路で破れる）

## 攻撃者視点での利用（意思決定：なぜSMBが“入口”になるか）
### 1) 匿名で読める共有がある
- 意思決定：まず“情報で勝てる”可能性が高い（設定/鍵/バックアップ）
- 次に繋がる：Webの認証/秘密管理、ADのスクリプト/配布、クラウド権限
- 診断としての主張：公開範囲と権限境界の破綻を事実で示せる

### 2) 書ける共有がある
- 意思決定：横展開/永続化/改ざんの入口になり得る（本ファイルは成立条件の確定まで）
- 診断としての主張：Write成立は重大。共有用途と配置を踏まえて妥当性を問える

### 3) 署名required / 匿名不可
- 意思決定：SMB単体での突破は起きにくい。LDAP/Kerberos/WinRM/RDPへ移る
- 診断としての主張：SMB境界は成立している可能性がある（他経路は別評価）

## 次に試すこと（仮説A/Bの分岐：条件が違うと次の手が変わる）
### 分岐1：匿名で共有一覧が取れる
- 仮説A：一覧のみで入室不可（情報露出のみ）
  - 次の一手：共有名/説明から用途推定し、認証後の再検証計画を立てる
- 仮説B：入室/読が成立する共有がある
  - 次の一手：共有用途に沿って機微の有無を観測し、Web/AD/クラウドへ繋ぐ

### 分岐2：匿名もGuestも不可
- 仮説A：境界が閉じている（認証が必要）
  - 次の一手：`11_ldap_enum` / `12_kerberos` の認証前提へ進む
- 仮説B：観測点が悪い（FW/セグメント制御）
  - 次の一手：`07_pivot_tunneling` で観測点を移し再実施する

### 分岐3：Pivot越しのSMBでSOCKS相性問題がある
- 仮説A：SOCKS越しのSMBクライアントが不安定
  - 次の一手：ローカルポートフォワードで `localhost:<port>` に固定して実施する

## 手を動かす検証（Labs連動：観測点を明確に）
### 実施方法（最高に具体：手順を固定し、結果を表に落とす）
> 方針：低侵襲→少試行→事実確定（共有/権限）→必要なら深掘り
> まず「匿名で見えるか」を最短で確定し、その後に“共有ごとのR/W”へ進む

#### Step 0：入力を整える（`05_scanning` の成果を受ける）
- 入力（最低限）
  - SMB候補（445/tcp open、必要なら139）
  - `targets_smb.txt`（IP一覧）
- 出力（成果物）
  - `smb_matrix.md`（IPごとの signing / anonymous / shares / R/W / 次の一手）

#### Step 1：SMBの握手と署名を確定する
> 匿名可否の前に、後段の意思決定（relay/横展開）に効く情報を取る
~~~~
nmap -Pn -n -p 445 --script smb2-security-mode,smb2-time,smb-os-discovery <ip> -oN 09_smb_nmap_<ip>.txt
~~~~
- signing: required → `10_ntlm_relay` は成立しにくい
- smb-os-discovery が取れない → `08_firewall_waf` で層の確認

#### Step 2：null session（匿名）で共有一覧が見えるか確定する
~~~~
smbclient -N -L //<ip> -m SMB3
rpcclient -U "" -N <ip> -c "srvinfo"
~~~~
- 共有一覧が見える → Step 3へ（共有ごとのR/W）
- 拒否 → Step 2b（Guest/低権限）

#### Step 2b：Guest/空パスで“実質匿名”が成立するか確認する
~~~~
smbclient -U "guest%"" -L //<ip> -m SMB3
~~~~
- Guestで共有が増える/入れる → Step 3へ
- 不可 → 認証済み列挙へ（`03_creds` で準備）

#### Step 3：共有ごとのR/Wを確定する
~~~~
smbclient -N //<ip>/<share> -m SMB3 -c "ls"
~~~~
- lsが通る → read成立。必要なら対象ディレクトリへ
- ACCESS_DENIED → 次の共有へ

#### Step 4：匿名でユーザ/グループ情報が漏れるか（可能な環境のみ）
~~~~
rpcclient -U "" -N <ip> -c "lsaquery"
rpcclient -U "" -N <ip> -c "enumdomusers"
rpcclient -U "" -N <ip> -c "enumdomgroups"
~~~~
- enumdomusers が通る → `11_ldap_enum` / `12_kerberos` で活用
- どれも拒否 → 共有評価を優先

#### Step 5：管理共有（ADMIN$/C$）の扱い
~~~~
smbclient -N //<ip>/C$ -m SMB3 -c "ls"
~~~~
- 低権限で入れないなら境界は成立
- 入れるなら重大。根拠と運用確認が必要

#### Step 6：結果を“意思決定できる形”に整形する
~~~~
| ip | host | domain | signing | anon_list | anon_read | anon_write | shares(R/W) | 次の一手 |
|---|---|---|---|---|---|---|---|---|
| 10.0.0.10 | FS01 | CORP | required | yes | no | no | Public:R, IT:Denied | 11 LDAP / 12 Kerberos |
| 10.0.0.20 | NAS | - | enabled | yes | yes | yes | share:R/W | 影響評価と運用合意 |
~~~~

### 04_labs と接続：観測→解釈→利用を再現
- パターン1：Windowsファイルサーバ
  - 共有A：匿名で一覧だけ見える（入室不可）
  - 共有B：GuestでRead可
  - 共有C：特定ユーザのみRead/Write（Share権限とNTFSの二段階を意図的にズラす）
  - 観測：Securityログ（4624/4625/5140/5145）で差分を確認
- パターン2：Samba
  - map to guest の有無で“実質匿名”が変わる
  - SMBバージョン制限で列挙ツールの挙動を観測する

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
nmap -Pn -n -p 445 --script smb2-security-mode,smb2-time,smb-os-discovery <ip> -oN 09_smb_nmap_<ip>.txt
smbclient -N -L //<ip> -m SMB3
~~~~
- ここで観測すること：署名要件、共有一覧、匿名可否
- 出力の注目点：signing required/enabled、共有名/説明、匿名での到達可否
- 使えないケース：445/139が到達できない、観測点が外側すぎる

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS
  - 位置づけ：SMB共有は「機微データ保護」「アクセス制御」「運用境界（管理系と業務系の分離）」の実体。匿名/Guestで見える・書けるは、認可/設定/運用の破綻として説明できる
  - この技術で支える前提：共有（資産）境界と権限境界（誰が何へアクセスできるか）を外形から確定し、アプリ要件以前の露出を潰す判断材料にする
- WSTG
  - 位置づけ：Web中心のWSTGでも「ファイル配布（設定、鍵、バックアップ）がWeb以外に露出している」ケースは実務で多い。SMBから設定/鍵/ログが取れると、WebのAuthN/AuthZや秘密管理の検証に直結する
  - この技術で支える前提：Webテストの前に“機微が別経路で漏れる”入口を排除/証明する
- PTES
  - 位置づけ：Scanning/Enumeration → Vulnerability Analysis の中核。SMBは「横展開・資格情報・永続化」に直結するため、到達したら優先して確定する価値が高い
  - 前後接続：05/06で見えた445/139を、ここで「何が見えるか（共有）」「誰として見えるか（匿名/Guest/認証）」「どこまでできるか（R/W）」へ落とし、10/11/12/以降へ渡す
- MITRE ATT&CK
  - T1135 Network Share Discovery：共有の列挙とアクセス確認
  - T1087 Account Discovery：匿名/低権限でのユーザ/グループ推定（可能な環境のみ）
  - T1021.002 Remote Services: SMB/Windows Admin Shares：成立条件の前段（本ファイルは“列挙と境界確定”に集中）
  - （接続）NTLM Relay（10）やAD列挙（11/12/15/16）へ繋がる「入口情報」を作る

## 参考（必要最小限）
- Microsoft SMB Protocols: https://learn.microsoft.com/en-us/windows/win32/fileio/microsoft-smb-protocols
- Samba smbclient man page: https://www.samba.org/samba/docs/current/man-html/smbclient.1.html

## リポジトリ内リンク（最大3つまで）
- `01_topics/03_network/05_scanning_到達性把握（nmap_masscan）.md`
- `01_topics/03_network/06_service_fingerprint（banner_tls_alpn）.md`
- `01_topics/03_network/10_ntlm_relay_成立条件（SMB署名_LLMNR）.md`

## 深掘りリンク（最大8）
- `01_topics/03_network/05_scanning_到達性把握（nmap_masscan）.md`
- `01_topics/03_network/06_service_fingerprint（banner_tls_alpn）.md`
- `01_topics/03_network/07_pivot_tunneling（ssh_socks_chisel）.md`
- `01_topics/03_network/08_firewall_waf_検知と回避の境界（観測中心）.md`
- `01_topics/03_network/10_ntlm_relay_成立条件（SMB署名_LLMNR）.md`
- `01_topics/03_network/11_ldap_enum_ディレクトリ境界（匿名_bind）.md`
- `01_topics/03_network/12_kerberos_asrep_kerberoast_成立条件.md`
- `01_topics/03_network/16_gpo_永続化と権限境界.md`
