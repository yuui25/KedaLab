# 21_nfs_共有とroot_squash境界

## 前提知識（最低限）
- root_squashはrootを匿名UIDへ変換

## 具体例（注目点）
- UID/GIDの一致と書込可否

## 失敗パターンと対処
- showmountが空: エクスポート設定を確認
NFSの到達性/exports/IDマッピングを境界として確定する

## 目標（この技術で到達する状態）
- 111/2049の到達性を経路別に確定できる
- exportの範囲と権限（ro/rw）を説明できる
- root_squash/no_root_squash の境界を判定できる
- NFSv3/v4差分とshowmountの限界を理解できる
- 監査/是正まで提示できる

## 前提・対象・範囲・想定
- NFSはRPCサービスの集合（111/2049等）
- showmountはv2/v3のみ（v4は表示されない）
- root_squashはuid0を匿名化する境界

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
- 到達性：111/2049
- RPC登録：rpcbind/mountd/nfsd
- exports：対象パスと許可クライアント
- IDマッピング：root_squash/all_squash/anonuid
- 監査：exports変更/マウント/アクセス

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 言える：共有範囲/権限/root_squashの有無
- 言えない：即侵害可能性（到達性/運用/監視で変わる）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- `*(rw)` や no_root_squash は優先度が高い
- 到達性が広いほどデータ収集面が拡大する

## 次に試すこと（仮説A/Bの分岐と検証）
### 仮説A：showmountでexportsが取れる
- 最小マウントで ro/rw と root_squash を確認

### 仮説B：showmountが空
- NFSv4前提の追加確認（運用提示の共有パスで最小マウント）

## 手を動かす検証（Labs連動：観測点を明確に）
~~~~
nmap -Pn -n -sT -p 111,2049 --open <target_ip> -oN nfs_reach_<target>.txt
showmount -e <target_ip>
rpcinfo -p <target_ip>
~~~~

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
sudo mount -t nfs -o ro,nosuid,nodev,noexec,vers=3,proto=tcp <ip>:/<export> /mnt/keda_nfs/<target>
ls -lan /mnt/keda_nfs/<target> | head
~~~~
- ここで観測すること：共有の存在とUID/GIDの見え方
- 出力の注目点：所有者UID（root_squash判定の前提）
- 使えないケース：許可されていないexportへのマウント

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：共有の到達性/権限/監査の境界
- WSTG：インフラ構成管理の検証対象
- PTES：到達性→共有列挙→権限境界→是正/監査
- MITRE ATT&CK：T1039 Data from Network Shared Drive

## 参考（必要最小限）
- exports(5): https://man7.org/linux/man-pages/man5/exports.5.html
- showmount: https://download.oracle.com/docs/cd/E23823_01/pdf/816-4555.pdf
- rpcinfo: https://docs.oracle.com/cd/E19455-01/806-0916/rfsrefer-41/index.html

## リポジトリ内リンク（最大3つまで）
- `01_topics/03_network/05_scanning_到達性把握（nmap_masscan）.md`
- `01_topics/03_network/09_smb_enum_共有・権限・匿名（null_session）.md`
- `01_topics/03_network/28_exfiltration_持ち出し経路（DNS_HTTP_SMB）.md`

## 深掘りリンク（最大8）
- `01_topics/03_network/05_scanning_到達性把握（nmap_masscan）.md`
- `01_topics/03_network/07_pivot_tunneling（ssh_socks_chisel）.md`
- `01_topics/03_network/09_smb_enum_共有・権限・匿名（null_session）.md`
- `01_topics/03_network/28_exfiltration_持ち出し経路（DNS_HTTP_SMB）.md`
