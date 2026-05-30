# GOAD 演習ラボ構築（VMware Workstation + WSL / Vagrant + Ansible）

> **スコープ**: GOAD（Game of Active Directory）演習ラボの構築手順。**Windows ホスト + VMware Workstation + WSL** の組み合わせで縮小版 **GOAD-Light**（3 VM / 1 forest / 2 domains）を建てる。AD 攻撃手法の習得に使う。ラボ構築後に何を練習するかは `../04_Post_Access_Windows_AD/` 系を参照。

## 着火条件

- AD 攻撃技術の習得のため演習環境を手元に構築したい場合

---

## 構成と前提

- **provider = VMware Workstation** / **lab = GOAD-Light** / **provisioner = local**（WSL 内で ansible 実行）
- **動作アーキテクチャ（重要）:** **VM 作成 = Windows 側の `vagrant.exe`** / **脆弱 AD の流し込み = WSL 内の ansible** という分業。
  - 橋渡しは **WSL が既定で Windows の PATH を引き継ぐ**こと。WSL 内の `goad.sh` がそのまま Windows の `vagrant.exe` を呼ぶ。
  - 帰結: **WSL 側に vagrant を入れる必要はない**（ansible だけ WSL に入れる）。

**マシン要件の目安:**

| 項目 | 目安 |
|---|---|
| RAM | GOAD-Light 最低 **20GB**（フル GOAD は 24GB+）。余裕を持って 32GB 推奨 |
| ディスク空き | **80GB 以上**（box キャッシュ + 展開後 VM で膨らむ。フル GOAD 5VM の目安が約 115GB） |
| 仮想化 | VBS / メモリ整合性(HVCI) を ON のまま使う場合、VMware は **Windows Hypervisor Platform 経由で共存**（VMware 17.6 相当以降の機能） |

---

## フェーズA：VMware Workstation + Vagrant VMware Utility（Windows 側・GUI）

GUI インストーラとアカウント登録が絡むため手動で実施する。

### A-1. VMware Workstation Pro

- 入手先: Broadcom ポータル（`support.broadcom.com`、無料アカウント登録要）。インストール時に **「Personal Use」** を選べばライセンスキー不要。
- ⚠️ **バージョン選択に落とし穴**: VMware Workstation のバージョン表記が従来の `17.x` から**カレンダー方式（例: 25H2 / 26H1）に変更**されている。
  - **`for Linux` 版は選ばない**（WSL ではなくネイティブ Linux 用）。

> **なぜ「最新の major」を避ける場合があるか（実例ベースの注意）:**
> あるカレンダー版で Windows 版が初めて **64bit 化**された世代では、レジストリ登録先が
> 32bit 側 `HKLM:\SOFTWARE\WOW6432Node\VMware, Inc.\VMware Workstation` から
> 64bit ネイティブ側 `HKLM:\SOFTWARE\VMware, Inc.\VMware Workstation` へ移動した。
> 一方その時点の **Vagrant VMware Utility は旧来どおり 32bit 側を見にいく**ため、
> A-2 の msi が「requires a valid installation of VMware Workstation」で失敗した。
> → **対処は 1 世代前（32bit 側に登録される版）を使う**こと。Utility 側が追従するまでは枯れた版が安全。
> 教訓: 「最新 = 安定」ではない。ツールチェーン（Utility / プラグイン）の対応状況を先に確認する。

### A-2. Vagrant VMware Utility

- 入手先: HashiCorp 公式（`developer.hashicorp.com` の Vagrant VMware provider ページ）の Windows 版インストーラ。
- 役割: **Vagrant が VMware を制御するためのブリッジ。プラグインとは別物**で、これが無いと `vagrant up` が VMware を掴めない。
- 導入後の確認: サービス `VagrantVMware` が Running / Automatic（`Get-Service VagrantVMware`）。
- 💡 `vagrant-vmware-desktop` プラグイン自体は OSS 化されており**ライセンス費用は不要**（HashiCorp Vagrant VMware FAQ）。

---

## フェーズB：Vagrant プラグイン導入（Windows PowerShell）

```powershell
vagrant plugin install vagrant-reload vagrant-vmware-desktop winrm winrm-fs winrm-elevated
vagrant plugin list
```

> **落とし穴: `plugin list` に winrm 系が出ない**
> 5 つすべて `Installed!` と出ても、`vagrant plugin list` には `vagrant-reload` と `vagrant-vmware-desktop` の 2 つしか出ないことがある。
> 理由: **`winrm` / `winrm-fs` / `winrm-elevated` は Vagrant 本体に同梱（default plugin）**のため list に表示されない。
> 確認の傍証: `vagrant -h` のサブコマンド一覧に `winrm` / `winrm-config` が出ていれば読み込まれている。
> → list に出ないこと自体は問題ではない。実体の確認は後段の `goad.sh check` で行う。

---

## フェーズC：WSL 側の準備（Debian / WSL1）

> **WSL は VMware では必須ではない**（公式）。ローカル hypervisor（VMware / VirtualBox）向けには、**WSL を使わず Windows に Python + Git を入れて `py goad.py -m vm` で provisioning まで回す**ネイティブ方式が用意されている。
> 公式原文: *"This mode doesn't need WSL but it is only if you plan to install goad locally on vmware or virtualbox"*。
> **WSL が必須なのは AWS / Azure 等の cloud provider**（`-m vm` 以外）。
>
> 本書は **WSL(Debian) で `goad.sh` を回す方式**を採る（Linux 上で ansible を扱いたい場合の選択肢。手数を最小化したいなら上記のネイティブ方式の方が少ない）。この方式を採る場合のみ以下のフェーズC が必要。

### C-1. WSL のバージョンは WSL1 を検討する

```powershell
wsl -l -v   # 各ディストロが VERSION 1 / 2 どちらか確認
```

> **なぜ WSL1 か（重要な判断）:**
> **WSL2 は独立した NAT 仮想ネットワーク**を持つため、**WSL2 内の ansible が Windows ホスト上の VMware VM（host-only 網）に WinRM 到達できない**事故が起きやすい。
> **WSL1 は Windows のネットワークスタックを共有**するので、この「ansible(WSL) → VM(Windows hypervisor)」到達性の問題が出にくい。
> Windows 11 既定は WSL2 なので、必要なら `wsl --set-version [DISTRO] 1` で WSL1 へ変換する。

### C-2. ディストロ導入

```powershell
wsl --install -d Debian
```
- 初回起動で UNIX ユーザ名 / パスワードを設定。
- 💡 公式が動作確認しているのは Debian 12 (bookworm)。新しい版（Debian 13 等）でも下記パッケージが揃えば動くが、詰まった際の切り分けを減らすなら公式と同じ版に揃える手もある。

### C-3. 依存パッケージ（Debian コンソール内）

```bash
python3 --version
sudo apt update
sudo apt install -y python3 python3-pip python3-venv libpython3-dev git
```
- ⚠️ 最近の Debian WSL イメージは最小構成で **python3 すら未導入**のことがある（`command not found` は想定内、上記で解消）。
- **vagrant は apt で入れない**（Windows 側の vagrant.exe を使うため）。

---

## フェーズD：GOAD 取得・チェック・構築

### clone（WSL 内）

> **clone 先は Windows 可視パス（`/mnt/c/...`）にする**：VM 作成は Windows 側 vagrant.exe、provisioning は WSL 内 ansible が**同じ GOAD ディレクトリ**を使うため、双方から見える `/mnt/c` 配下に置く。

```bash
cd /mnt/c/Users/[WIN_USER]
git clone https://github.com/Orange-Cyberdefense/GOAD
cd GOAD
```

### 対話コンソールで check → install

```bash
./goad.sh
```
```
GOAD> set_lab GOAD-Light
GOAD> set_provider vmware
GOAD> set_provisioner local
GOAD> set_ip_range [IP_RANGE]   # 第3オクテットまで。例: 192.168.56
GOAD> check                     # 前提診断（全項目 [+] を確認）
GOAD> install                   # 構築開始（box取得 + vagrant up + ansible）
```

- **`set_ip_range` は第3オクテットまで**（公式の例: `192.168.56 (only the first three digits)`）。第4オクテットまで入れると不正でプロンプトのレンジ表示が変わらない。正しく受理されるとプロンプトの IP レンジ表示が更新される。
- ⚠️ **採用するレンジが自宅/物理 LAN のサブネットと衝突しないこと**を `ipconfig` で確認（衝突するとルーティングが physical 側に流れて VM へ届かない）。
- `check` の主な確認項目: `vagrant.exe` / `ansible-playbook` / ansible galaxy collections（`ansible.windows` `community.general` `community.windows`）/ 各プラグイン / `vmrun.exe` のパス。

> **`check` 出力でアーキテクチャの裏取りができる**：
> `[+] vagrant.exe found in PATH`（= WSL から Windows の vagrant.exe を呼べている）と
> `[+] ... vmrun.exe present in /mnt/c/Program Files (x86)/VMware/...`（= 32bit パス）が出る。

---

## 構築の流れ（内部で何が起きるか）

1. **box の取得** … Windows Server の Vagrant box をダウンロード。**ここが一番時間とディスクを食う**。
2. **`vagrant.exe up`** … VMware 上に 3 VM を起動（VM 作成は **NAT 側 NIC** 経由で vagrant が通信するため、ここまでは host-only 網が壊れていても成功し得る）。
3. **ansible provisioning** … WSL の ansible が **WinRM (HTTPS 5986)** 経由で各 VM に入り、AD フォレスト + 脆弱設定を流し込む。**ここで host-only 網（後述）が要る**。

provisioning は AD 昇格（dcpromo）→ 再起動 → 再接続待ち、意図的な待機 playbook 等を含むため**長時間**（環境により 30 分〜）かかる。`FAILED - RETRYING` は再起動待ちのリトライで正常なことが多い。

---

## ネットワークの最大の落とし穴：host-only アダプタの IP が振られない

VMware + WSL で GOAD を建てるときに**最も詰まりやすい点**。症状と原因・対処を独立して記す。

**症状:** `vagrant up` は成功するのに、ansible が**全 VM で `UNREACHABLE`**（5986 への接続が refused / timeout）になり provisioning が abort する。

**原因:** GOAD の VM は NIC を 2 枚持つ（NAT 側 + private 側 = host-only）。ansible が狙うのは **private 網（host-only / `[IP_RANGE].0/24`）**。ところが **Windows ホストの host-only 仮想アダプタ（VMnetX）が正しい `[IP_RANGE].1` を取得できず、APIPA（`169.254.x.x`）にフォールバック**することがある。ホストがラボ網に正しい IP を持たないため、ホストも WSL も VM に届かない。

> **なぜ起きるか（仕様）:** `vagrant.exe up` / 起動時に
> `Configuring secondary network adapters through VMware on Windows is not yet supported. You will need to manually configure the network adapter.`
> と表示される。**Windows ホストでは vagrant-vmware-desktop が副 NIC のネット設定を自動で行わない仕様**で、host-only アダプタの IP 設定は手作業前提。
> （ゲスト側の static IP は GOAD の ansible が設定するため、ゲストは `[IP_RANGE].x` を持っている。）

**確認:**
```powershell
# host-only アダプタの IP を確認（169.254.x なら未取得）
Get-NetIPAddress -InterfaceAlias "VMware Network Adapter VMnetX" -AddressFamily IPv4
```
（`VMnetX` は実際のアダプタ名に置換。VMware の「仮想ネットワーク エディタ」で `[IP_RANGE].0` の host-only がどの VMnet 番号かを確認できる。）

**対処:** その host-only アダプタに **`[IP_RANGE].1`（/24）を手動設定**する。
```powershell
Get-NetIPAddress -InterfaceAlias "VMware Network Adapter VMnetX" -AddressFamily IPv4 | Remove-NetIPAddress -Confirm:$false
New-NetIPAddress -InterfaceAlias "VMware Network Adapter VMnetX" -IPAddress [IP_RANGE].1 -PrefixLength 24
```
（コントロールパネルのアダプタ設定からでも可。GUI の場合は **IPv4 のプロパティとアダプタのプロパティの両方で OK を押す**こと＝押し忘れると反映されない Windows の挙動。）

⚠️ **PC / VMware の再起動で APIPA に戻ることがある**。ラボ起動前のチェック項目にする。

---

## 検証（構築完了後）

**到達性は `ping` でなく WinRM ポートで判定する**（Windows Server は既定で ICMP エコーをブロックするため ping は当てにならない）。

```powershell
# 各 VM の WinRM HTTPS (5986) 到達確認（TcpTestSucceeded : True を見る）
Test-NetConnection [IP_RANGE].10 -Port 5986
Test-NetConnection [IP_RANGE].11 -Port 5986
Test-NetConnection [IP_RANGE].22 -Port 5986
```
- `arp -a` に対象 VM の MAC が出れば L2 到達はできている（5986 が通れば WinRM も OK）。

**RDP / ログイン:**
```powershell
mstsc /v:[IP_RANGE].10
```
> **RDP の落とし穴:** ユーザー名を `administrator` だけにすると `[IP_RANGE].10\administrator`（= その端末のローカル管理者）として認証され、**DC にはローカル管理者が無いため必ず失敗**する。
> **UPN（`administrator@[PARENT_DOMAIN]`）かドメイン付き（`[NETBIOS]\administrator`）で入力**する。資格情報は GOAD の `ad/[LAB]/data/config.json`（`domain_password` 等）に定義されている。

**WinRM で直接確認**（非ドメインのクライアントから）:
```powershell
$pw  = ConvertTo-SecureString '[PASSWORD]' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('administrator@[PARENT_DOMAIN]',$pw)
Invoke-Command -ComputerName [IP_RANGE].10 -UseSSL -Credential $cred `
  -SessionOption (New-PSSessionOption -SkipCACheck -SkipCNCheck) -ScriptBlock { hostname; whoami }
```

---

## 攻撃端末（Kali）を lab ネットワークに置く

ラボを攻撃する側の端末。assume-breach（内部 LAN に居る攻撃者）を模すため、**lab の host-only セグメント（`[IP_RANGE].0/24`）に直結した Kali** を用意する。

- **入手**: Kali 公式の **VMware 用プリビルド VM イメージ**（kali.org の「Get Kali → Virtual Machines」）。`.7z` を 7-Zip で展開し `.vmx` を VMware Workstation で開く（起動時「コピーしました」を選択）。デフォルト資格情報 `kali` / `kali`。ISO 新規インストールより速い。
- **保存場所**: ダウンロードフォルダのまま使わない（一時領域）。**専用フォルダ**（VMware 既定の `Documents\Virtual Machines\` か専用 `…\VMware VMs\` 等）へ。移動は **VM 停止 → VMware を閉じる → フォルダ丸ごと移動 → `.vmx` を開き直す →「移動しました」**。今後の既定保存先は 環境設定 → ワークスペース で変更。
- **lab 接続**: VM 設定 →「ネットワーク アダプタ」→「カスタム: 特定の仮想ネットワーク」→ **lab の host-only VMnet**（`[IP_RANGE].0/24` のもの）。
- **静的 IP（永続）**: host-only は DHCP オフ運用なので静的に。Kali は NetworkManager 管理なので `nmcli` で恒久設定する（再起動しても維持）:
  ```bash
  nmcli con show                                  # 有線接続名を確認（既定 "Wired connection 1"）
  sudo nmcli con mod "Wired connection 1" ipv4.method manual ipv4.addresses [IP_RANGE].99/24
  sudo nmcli con mod "Wired connection 1" ipv4.dns [IP_RANGE].10   # DNS=DC で名前解決が楽
  sudo nmcli con mod "Wired connection 1" ipv4.gateway ""          # host-only は GW 不要
  sudo nmcli con up "Wired connection 1"
  ```
  > 一時的でよければ `sudo ip addr add [IP_RANGE].99/24 dev eth0`（揮発・再起動で消える）。
- **疎通確認**: `nc -zv [IP_RANGE].10 5986` が `open` なら lab 到達 OK。届かなければ **ホスト側 host-only アダプタの IP（`[IP_RANGE].1`）が APIPA に戻っていないか**確認（「ネットワークの最大の落とし穴」参照）。

**操作は SSH 推奨**（VMware コンソールのカーソル問題を回避＋コピペ可）:
```bash
sudo systemctl enable ssh --now    # Kali 側で1回（自動起動として永続）
```
```powershell
ssh kali@[IP_RANGE].99             # ホスト（Windows Terminal）から
```
CLI 作業（nmap / netexec / bloodhound-python / impacket / evil-winrm / certipy）は SSH、**GUI（BloodHound グラフ等）だけ VMware コンソール**、の併用が快適。

> **VMware コンソールでマウスカーソルが消える**（マウスは動くが描画されない）場合：まず 3D アクセラレーション OFF を確認、それでも消えるなら `.vmx` に `mks.enableHWCursor = "FALSE"` を追記。CLI を SSH に逃がせば実害はほぼ無い。

> **Kali VM が要るのは「L2 攻撃」**：Responder（LLMNR/NBT-NS ポイズニング）/ mitm6 / NTLM relay positioning は、セグメントの L2 に実参加する端末でないと機能しない。**TCP/認証ベース**（nmap / netexec / bloodhound-python / impacket / evil-winrm / certipy）だけなら **WSL（WSL1）でも可**（WSL は L2 参加者でないため Responder 等は不可）。assume-breach（low-priv 貸与）の大半は TCP 系で WSL でも回せるが、Responder で初期 cred を自力取得する流れや relay 練習は Kali VM が必要。

---

## ラボの操作（アクセス / 起動・停止・再起動 / snapshot・リセット）

### アクセス方法

- **RDP**: `mstsc /v:[IP_RANGE].10`。ユーザー名は **UPN（`administrator@[PARENT_DOMAIN]`）かドメイン付き（`[NETBIOS]\administrator`）**で入力する（`administrator` 単独はローカル扱いで失敗。「検証」参照）。
- **WinRM（PowerShell）**: 「検証」の `Invoke-Command` / `Enter-PSSession`（`-UseSSL` + `New-PSSessionOption -SkipCACheck -SkipCNCheck`）。対話したいときは `Enter-PSSession` に置き換える。
- 資格情報は GOAD の `ad/[LAB]/data/config.json`（各ドメインの `domain_password` 等）に定義されている。

### 起動 / 停止 / 再起動（goad コンソール）

| 操作 | ラボ全体 | 個別 VM |
|---|---|---|
| 状態確認 | `status` | `status` |
| 起動 | `start` | `start_vm [VM_NAME]` |
| 停止（シャットダウン） | `stop` | `stop_vm [VM_NAME]` |
| 再起動 | `stop` → `start` | `restart_vm [VM_NAME]` |
| 破棄（完全削除） | `destroy` | `destroy_vm [VM_NAME]` |

⚠️ **PC / VMware を再起動した後、ラボを `start` する前に** host-only アダプタの IP（`[IP_RANGE].1`）が APIPA に戻っていないか確認・再設定する（「ネットワークの最大の落とし穴」参照）。これを忘れると起動できても provisioning 済みの VM に届かない。

### snapshot / リセット

- **構築直後にクリーン状態の snapshot を取る**: goad コンソール `snapshot`。GOAD は壊して学ぶ前提なので、再構築（長時間）を避けるため実質必須。
- **リセット（クリーン状態へ復帰）**: `reset`（直近の snapshot へ revert）。**事前に `snapshot` を取ってあること**が前提。攻撃で AD を壊しても数分で戻せる。

### 再プロビジョニング（VM 作り直し不要）

ネットワーク等を直した後、**box / VM を作り直さず provisioning だけ再実行**する:

| やりたいこと | goad コンソールコマンド |
|---|---|
| 全 playbook を再実行 | `provision_lab` |
| 特定 playbook から最後まで | `provision_lab_from [PLAYBOOK]` |
| 単一 playbook のみ | `provision [PLAYBOOK]` |

⚠️ **`install` は「provide + jumpbox + provision_lab」**なので VM 作成からやり直す。再 provisioning には使わない。

---

## 刺さらなかったとき（トラブルシュート）

| 症状 | 切り分け・対処 |
|---|---|
| Utility msi が「requires a valid installation of VMware Workstation」 | VMware の **64bit 化世代 × 旧 Utility** の検出ギャップ。Utility が 32bit 側レジストリ(WOW6432Node)を見るのにネイティブ側に登録されているため。→ **32bit 側に登録される 1 世代前の VMware** を使う。確認: `Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\VMware, Inc.\VMware Workstation"` の InstallPath が空でないこと |
| `vagrant up` で VMware を掴めない | Vagrant VMware Utility 未導入 / サービス `VagrantVMware` 停止（`Get-Service VagrantVMware`） |
| box DL が遅い・失敗 | ネットワーク or ディスク空き不足。途中失敗時は再実行で resume できるか確認 |
| ansible が全 VM `UNREACHABLE`（5986 refused / timeout） | **host-only アダプタの IP 未取得（APIPA）が最有力**（上記「ネットワークの最大の落とし穴」参照）。`vagrant up` は NAT 経由なので成功する点に注意 |
| ping は通らないが WinRM は通る | Windows Server 既定で **ICMP をブロック**。到達判定は `Test-NetConnection -Port 5986` で行う |
| VM が極端に遅い | VBS(メモリ整合性) 共存のオーバーヘッド。許容できなければメモリ整合性 OFF を検討（要再起動・要判断） |
| RDP が「ログオンに失敗」 | ユーザー名を UPN / ドメイン付きにする（`administrator` 単独はローカル扱いになり DC で失敗） |
| VM が約1時間ごとにシャットダウン / 背景が黒・透かし表示 | **Windows Server 評価版の 180 日期限切れ**。各 VM 内で `slmgr /rearm`（要再起動・既定 6 回まで）。使い切ったら box から再構築（「ゲスト OS の評価版期限」参照） |

---

## ライセンスについて（要確認領域）

- **個人の学習用途**: VMware Workstation Pro は無償化されており、インストール時に「Personal Use」を選べばキー不要で使える。
- **組織 / 商用利用**: 無償可否は製品個別の **SPD（Specific Program Documentation / 特定プログラム文書、`legaldocs.broadcom.com`）/ 製品使用権**が定める。基本契約（Foundation Agreement）には個人/商用の無料区分は無く、SPD が優先される。商用利用の前に SPD を確認すること。契約・法務領域なので断定しない。

---

## ゲスト OS（Windows Server）の評価版期限：180 日

GOAD の VM は **Windows Server の評価版（Evaluation）**イメージから作られる。VMware 側のライセンスとは**別物**で、こちらにも期限がある。

- **評価期間は OS の初回起動から 180 日**。
- 期限切れ後は **デスクトップ背景が黒 + 透かし表示、さらに約 1 時間ごとに自動シャットダウン**（Windows License Manager Service による）して、ラボとして使えなくなる。

**期限が来ても再構築は不要。`slmgr /rearm` での延長が簡単。**（box からの再構築が要るのは、後述のとおり rearm を 6 回使い切った後だけ。）

### 簡単な延長手順（各 VM で 1 回ずつ）

RDP か VMware コンソールで **3 台すべて（2 DC + サーバ）**に入り、**管理者権限**の cmd / PowerShell で：

```powershell
slmgr /dlv      # 残り日数・残り rearm 回数の確認（任意）
slmgr /rearm    # 評価期間を 180 日にリセット
```
実行したら **その VM を再起動**（タイマーが 180 日に戻る）。これを 3 台で行うだけ。

### まとめてやりたい場合（ホストから WinRM で 3 台一括）

各 VM の administrator 資格情報は `ad/[LAB]/data/config.json`（**dc01 は親ドメイン、dc02 / srv02 は子ドメインで別パスワード**）。

```powershell
# [PASSWORD] は各ホストのドメインに対応するものに（親 / 子で異なる）
$targets = @(
  @{ ip='[IP_RANGE].10'; user='administrator@[PARENT_DOMAIN]'; pw='[DC01_PASSWORD]' },
  @{ ip='[IP_RANGE].11'; user='administrator@[CHILD_DOMAIN]';  pw='[DC02_PASSWORD]' },
  @{ ip='[IP_RANGE].22'; user='administrator@[CHILD_DOMAIN]';  pw='[SRV02_PASSWORD]' }
)
foreach ($t in $targets) {
  $cred = New-Object System.Management.Automation.PSCredential($t.user, (ConvertTo-SecureString $t.pw -AsPlainText -Force))
  Invoke-Command -ComputerName $t.ip -UseSSL -Credential $cred `
    -SessionOption (New-PSSessionOption -SkipCACheck -SkipCNCheck) `
    -ScriptBlock { cscript //nologo "$env:windir\System32\slmgr.vbs" /rearm; Restart-Computer -Force }
}
```

### 再構築が必要になるのはいつか

- `slmgr /rearm` は **既定で 6 回**まで（180 日 × 6 ≒ 最長 3 年）。
- 6 回使い切ると `slmgr /rearm` が `0xC004D307`（maximum allowed number of re-arms has been exceeded）を返す。**ここで初めて box からの再構築（＝新規 OS で 180 日リセット）か正規ライセンス投入が必要**。

> ⚠️ **snapshot の `reset` は延長手段ではない**：revert はその snapshot 時点の残り評価日数に戻すだけで、回数無制限の延長にはならない。期限管理は `slmgr /rearm`、最終手段が再構築。

---

## 参考（出典）

- GOAD GitHub: `github.com/Orange-Cyberdefense/GOAD`
- GOAD Docs（Windows / Linux / Usage）: `orange-cyberdefense.github.io/GOAD/`
- Vagrant VMware provider FAQ: `developer.hashicorp.com/vagrant/docs/providers/vmware/faq`

---

## 関連技術
- 後（ラボ構築後、まず AD を列挙する）→ `../04_Post_Access_Windows_AD/Enumeration_Checklist.md`
- 後（権限関係を可視化する）：`BloodHound.md`
- 後（SMB/WinRM への認証確認・パスワードスプレー）：`Netexec.md`
- 関連（ラボ内 VM への WinRM / SMB 操作）：`Impacket_Suite.md`
