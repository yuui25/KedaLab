# 01_target-vm_教材ホスト設計（docker前提）

## 目的
- Web/API教材を1台のTarget VM上で回せるようにし、観測点（Proxy/HAR/pcap）を固定する。
- 検証の巻き戻し（snapshot/reset）を前提に、同条件比較を成立させる。

## 前提
- 対象：VirtualBox想定（Host-Onlyセグメント）。
- 教材はDockerで稼働させる（差し替え・復帰が速い）。

## 最小構成（推奨）
- OS：Ubuntu LTS
- NIC：
  - Host-Only：検証セグメント
  - NAT：パッケージ取得のみ（必要時）
- 監視点：Target側の最低限ログ（アプリログ/コンテナログ）

## 使う教材
- Web教材：`04_labs/03_targets/04_keda_app_教材Webアプリ（自作）.md`
- API教材：`04_labs/03_targets/02_api_targets_検証用API選定.md` の候補から最小2つ

## 巻き戻しの基準
- S0：OS + Docker導入直後
- S1：keda_app 起動確認済み

## リポジトリ内リンク（最大3つまで）
- 関連 labs：`04_labs/02_virtualization/03_networking_nat_hostonly_bridge.md`
- 関連 labs：`04_labs/05_automation/02_snapshots_reset_検証の巻き戻し.md`
- 関連 labs：`04_labs/03_targets/04_keda_app_教材Webアプリ（自作）.md`

