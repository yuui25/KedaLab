# 01_iac_terraform_or_bicep.md

## 目的
- 検証環境の「同条件比較」をIaCで担保し、差分の原因を環境ブレではなく入力差に収束させる。

## 何をやるか（最小）
- 変えないもの：ネットワーク/権限/ログ取得の前提
- 変えてよいもの：検証対象（教材/構成）

## 方針
- IaCは“フル自動化”が目的ではなく、**再現性の固定点**を作るために使う。
- まずは「NW分離」「ログ取得」「最小構成」だけをコード化する。

## リポジトリ内リンク（最大3つまで）
- 関連 labs：`04_labs/05_automation/02_snapshots_reset_検証の巻き戻し.md`
- 関連 labs：`04_labs/02_virtualization/03_networking_nat_hostonly_bridge.md`
- 関連 labs：`04_labs/04_cloud/03_logging_クラウド監査ログの取り方.md`

