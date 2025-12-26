# 03_nw_targets_最小セット（到達性・列挙・境界）

## 目的
- NW側の到達性/列挙/境界を、pcapとログで説明できる最小セットを確定する。
- “スキャンの羅列”ではなく、到達性→認証→権限の差分を作れる構成にする。

## 最小セット（推奨）
1) Windows or Linux サーバ（1台）
   - RDP/SSH 等の認証境界を観測
2) 共有サービス（SMB/NFS いずれか）
   - 共有/権限の境界を観測

## 最小差分セット
- 到達性：Host-Only 内で到達できる/できない
- 認証：匿名/認証必須
- 権限：一般/管理相当

## 取得する証跡
- pcap（必要時）
- サービス応答ログ（可能なら）

## リポジトリ内リンク（最大3つまで）
- 関連 labs：`04_labs/02_virtualization/03_networking_nat_hostonly_bridge.md`
- 関連 labs：`04_labs/01_local/03_capture_証跡取得（pcap_harl_log）.md`
- 関連 playbooks：`02_playbooks/06_network_enum_to_post_列挙→侵入後の導線.md`

