# 15_acl_abuse（AD権限グラフ）

## 具体例（権限グラフ）
- 代表的な委任経路を図で示す

## ツール選択の基準
- BloodHound: 可視化に強い
ADのACLを権限伝播の配線図として整理し、成立経路と是正/検知まで落とす

## 目標（この技術で到達する状態）
- ADのACL（DACL/ACE）を「設定の羅列」ではなく権限伝播のグラフとして扱う
  1) 誰がどのオブジェクトにどの権限を持つかを事実として示せる
  2) その権限が何を可能にするかを状態として説明できる
  3) 到達性/認証素材と結合したときの横展開経路を優先度付けできる
  4) 是正案（代替設計）と検知（変更追跡/ベースライン）まで閉じられる

## 前提・対象・範囲・想定
- 対象：AD（ユーザー/グループ/コンピュータ/OU/GPO/ドメイン/証明書テンプレ等）
- ACL前提：Security Descriptor に DACL（許可/拒否）と SACL（監査）
- 範囲の切り方
  - 高価値ノード（Tier0/基幹）と広い主体（Domain Users等）を軸に絞る
- 想定する入力
  - `11_ldap_enum`（DN/SID/グループ構造）
  - `05_scanning` / `18_winrm` / `19_rdp` / `20_mssql`（到達性）
  - `12_kerberos` / `13_adcs` / `14_delegation`（別の権限伝播）

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) 観測対象（一次データ）
- nTSecurityDescriptor / DACL / ACE
- ACEの最小フィールド
  - Trustee（SID/主体）
  - Allow/Deny
  - Rights（GenericAll/WriteDACL/WriteOwner/GenericWrite/属性Write 等）
  - Inheritance（継承元と範囲）

### 2) 境界の固定
- 資産境界：高価値オブジェクト（Domain/DC/Tier0/GPO/基幹サーバ）
- 信頼境界：広すぎる主体（Domain Users/Authenticated Users/Everyone 等）
- 権限境界：状態遷移を起こす権限（変更/メンバー追加/所有者変更）

### 3) “権限＝状態遷移”として見る
- GenericAll / WriteDACL / WriteOwner / GenericWrite
- AddMember（グループ）
- ForceChangePassword（ユーザー）
- AllExtendedRights（ドメイン等）

### 4) 取り方の分岐
- A：BloodHound等で最短経路を可視化
- B：ツール制約時は高価値ノードに絞ってDACLを手作業抽出

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える
  - 特定主体が特定オブジェクトに状態遷移権限を持つ
  - その権限は境界を破る入口になり得る
- 言えない
  - 直ちに侵害が成立する（到達性/他条件が必要）
  - その主体が侵害されやすいかは別評価

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- 優先度の軸
  - 影響：高価値ノードか
  - 成立容易性：1手で状態遷移できる権限か
  - 露出：主体が広い/ネストで広がるか
  - 鎖：到達性や他境界と結合して実行可能か
- “短い鎖”の典型
  - 低権限が管理グループ/OU/GPO/重要コンピュータにWriteDACL/GenericAll
  - 重要グループにAddMemberが付与
  - ドメインにAllExtendedRightsが広く付与
  - RBCD作成に繋がる書き込み権限

## 次に試すこと（仮説A/Bの分岐と検証）
### 仮説A：グラフが作れる
- 次の一手
  1) 高価値ノードへの最短パス抽出
  2) Edgeを原本ACEで裏取り
  3) Trusteeの広さを `11_ldap_enum` で確認
  4) 到達性（`05_scanning`）と結合し実行可能性を評価

### 仮説B：グラフが作れない
- 次の一手
  1) Domain/Admin/DC/Tier0/GPO/重要サーバに絞る
  2) 危険権限だけ抽出して優先度付け
  3) 継承元を辿り付与箇所を確定
  4) 代替設計（専用グループ/OU分割/Tier分離）を提案

### 仮説C：危険権限が見つからない
- 次の一手
  - 変更検知（属性変更監査）の整備
  - 別経路（`14_delegation` / `13_adcs` / `10_ntlm_relay` / `12_kerberos`）へ移る

## 手を動かす検証（Labs連動：観測点を明確に）
### 実施方法（差分が出る設計）
- DC + Member Server + Client
- OUを2つ作り継承差分を作る
- 検証用グループに権限を1つずつ付与してグラフの変化を観測
- 観測点：DACL差分 / グラフ差分 / 変更ログ

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
# DACL表示例（PowerShell）

## 具体例（権限グラフ）
- 代表的な委任経路を図で示す

## ツール選択の基準
- BloodHound: 可視化に強い
# Get-Acl "AD:\CN=SomeGroup,OU=Groups,DC=example,DC=local" | Format-List

## 具体例（権限グラフ）
- 代表的な委任経路を図で示す

## ツール選択の基準
- BloodHound: 可視化に強い
~~~~
- ここで観測すること：ACEの存在と権限種別
- 出力の注目点：Trustee / Rights / Inheritance
- 使えないケース：権限不足、ツール制約

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：最小権限/特権管理/監査の中核としてACLを扱う
- WSTG：WebのAuthN/AuthZ評価の前提としてAD権限伝播を入力化する
- PTES：列挙→分析→経路評価→報告（是正/検知）で閉じる
- MITRE ATT&CK：Privilege Escalation/Lateral Movement/Persistenceの成立条件として固定

## 参考（必要最小限）
- Windows ACL/ACEの基礎
- BloodHound（AD権限グラフ）

## リポジトリ内リンク（最大3つまで）
- `01_topics/03_network/11_ldap_enum_ディレクトリ境界（匿名_bind）.md`
- `01_topics/03_network/12_kerberos_asrep_kerberoast_成立条件.md`
- `01_topics/03_network/14_delegation（unconstrained_constrained_RBCD）.md`

## 深掘りリンク（最大8）
- `01_topics/03_network/05_scanning_到達性把握（nmap_masscan）.md`
- `01_topics/03_network/12_kerberos_asrep_kerberoast_成立条件.md`
- `01_topics/03_network/13_adcs_証明書サービス悪用の境界.md`
- `01_topics/03_network/14_delegation（unconstrained_constrained_RBCD）.md`
