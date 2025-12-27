# 17_laps_ローカル管理者パスワード境界

## 前提知識（最低限）
- Legacy LAPS と Windows LAPS の違い
- 代表属性: `ms-Mcs-AdmPwd`, `msLAPS-Password`

## 具体例（注目点）
- LAPS属性の値と有効期限を読む

## 失敗パターンと対処
- 読み取り不可: 権限付与範囲を確認
LAPSの方式/適用範囲/読取権限を境界として確定し、横展開リスクを評価する

## 目標（この技術で到達する状態）
- Legacy LAPS / Windows LAPS / Entraバックアップの判定ができる
- AD属性（PW/期限）とACL（誰が読める/期限変更できるか）で境界を分解できる
- 読取主体の広さ/ネスト/Tier跨ぎを `15_acl_abuse` の視点で説明できる
- 適用範囲（OU/端末）と未管理端末を特定できる
- 是正（委任分離/ポリシー）と検知（ADアクセス/LAPSイベント）まで提示できる

## 前提・対象・範囲・想定
### Legacy LAPSとWindows LAPSの違い
- Legacy：`ms-Mcs-AdmPwd` / `ms-Mcs-AdmPwdExpirationTime`
- Windows：`msLAPS-Password` / `msLAPS-PasswordExpirationTime` / `msLAPS-EncryptedPassword`
- どちらも「AD属性を読める主体」が境界

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### A) AD（LDAP）
- Legacy：`ms-Mcs-AdmPwd` / `ms-Mcs-AdmPwdExpirationTime`
- Windows：`msLAPS-Password` / `msLAPS-PasswordExpirationTime` / `msLAPS-EncryptedPassword`
- OUの委任（誰が読取/期限変更できるか）

### B) クライアント側（Windows）
- `Microsoft-Windows-LAPS/Operational` のイベント

### C) ポリシー
- `BackupDirectory` / `AdministratorAccountName` / `PasswordAgeDays` / `PasswordLength`
- 暗号化運用の場合：`ADPasswordEncryptionEnabled` / `ADPasswordEncryptionPrincipal`

## 結果の意味（何が言える/言えない）
- 言える
  - 方式（Legacy/Windows/Entra）とAD属性の実運用
  - 読取主体/期限変更主体の範囲（ACL根拠）
  - 適用範囲と未管理端末の穴
- 言えない
  - 即侵害できる（到達性/防御設定/監視で変わる）
  - 本番でのPW取得の正当化（許可と取扱い設計が前提）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- 読取権限が広いほど横展開燃料が集中する
- 未管理端末が高価値OUにある場合は最優先
- 暗号化PWでも復号主体が広ければ実質平文と同じ

## 次に試すこと（条件分岐）
### A) 読取権限が広い/疑いがある
- `15_acl_abuse` で読取主体のネストを展開し実質範囲を確定
- Tier分離/委任分離の是正案へ

### B) 適用漏れがある
- 未管理端末を資産価値順に並べて是正提案
- `16_gpo` と接続して適用経路を固定

### C) 暗号化運用を使っている
- 復号主体（ADPasswordEncryptionPrincipal）の最小化を確認

## 手を動かす検証（Labs連動：観測点を明確に）
### 実施方法（判定→スコープ→権限→リスク→検知/是正）
~~~~
# Legacy LAPS（期限属性）

## 前提知識（最低限）
- Legacy LAPS と Windows LAPS の違い
- 代表属性: `ms-Mcs-AdmPwd`, `msLAPS-Password`

## 具体例（注目点）
- LAPS属性の値と有効期限を読む

## 失敗パターンと対処
- 読み取り不可: 権限付与範囲を確認
ldapsearch -x -H ldap://<DC_IP> -b "<DomainDN>" -s sub \
  "(ms-Mcs-AdmPwdExpirationTime=*)" dn ms-Mcs-AdmPwdExpirationTime

# Windows LAPS（期限属性）

## 前提知識（最低限）
- Legacy LAPS と Windows LAPS の違い
- 代表属性: `ms-Mcs-AdmPwd`, `msLAPS-Password`

## 具体例（注目点）
- LAPS属性の値と有効期限を読む

## 失敗パターンと対処
- 読み取り不可: 権限付与範囲を確認
ldapsearch -x -H ldap://<DC_IP> -b "<DomainDN>" -s sub \
  "(msLAPS-PasswordExpirationTime=*)" dn msLAPS-PasswordExpirationTime
~~~~
- OU単位で未管理端末を洗い出す
- LAPSイベント（Operational）で適用/失敗を確認

### Lab最小構成
- DC + Windowsクライアント
- OUを2つ作り、読取委任の差分を観測

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
ldapsearch -x -H ldap://<DC_IP> -b "<DomainDN>" -s sub "(msLAPS-EncryptedPassword=*)" dn
~~~~
- ここで観測すること：Windows LAPS暗号化PWの運用有無
- 出力の注目点：値が入っている端末の範囲
- 使えないケース：権限不足（委任/ACL確認へ）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：特権IDの統制と監査の境界としてLAPSを評価する
- WSTG：Webの前提条件として端末管理者権限の統制を評価する
- PTES：Enum→Analysis→到達性結合→Reportingで閉じる
- MITRE ATT&CK：横展開燃料の抑止境界として扱う

## 参考（必要最小限）
- Microsoft LAPS（Legacy/Windows）公式ドキュメント

## リポジトリ内リンク（最大3つまで）
- `01_topics/03_network/15_acl_abuse（AD権限グラフ）.md`
- `01_topics/03_network/16_gpo_永続化と権限境界.md`
- `01_topics/03_network/05_scanning_到達性把握（nmap_masscan）.md`

## 深掘りリンク（最大8）
- `01_topics/03_network/05_scanning_到達性把握（nmap_masscan）.md`
- `01_topics/03_network/07_pivot_tunneling（ssh_socks_chisel）.md`
- `01_topics/03_network/11_ldap_enum_ディレクトリ境界（匿名_bind）.md`
- `01_topics/03_network/15_acl_abuse（AD権限グラフ）.md`
- `01_topics/03_network/16_gpo_永続化と権限境界.md`
