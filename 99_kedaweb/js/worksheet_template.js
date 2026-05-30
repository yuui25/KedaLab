/* =============================================================
   kedalab — worksheet template（作戦ノート＝「型」の定義）
   =============================================================

   HTB / OSCP / ペネトレで毎回埋める作戦ノートのひな形。kedaweb の
   Worksheet セクションがこの定義を読んで記入フォームを描画し、
   チェック/記入は localStorage に自動保存、`.md`/`.txt` で書き出せる。

   ★ この配列が「あなたの型(メソッド)」そのもの。
     毎回同じ手順で回して過不足を見つけ、ここを直して締めていく。
     項目を足す/減らす/並べ替える = テンプレ追記だけ(app.js は不変)。

   ── 構造 ──────────────────────────────────────────────────────
   meta:     上部の単一行入力(ターゲット情報)。[{ id, label, placeholder }]
   sections: 本体。type で描画が変わる。
     type:"checklist" — items:[{ label, file? }]
        file があればその kedalab ファイルへ ↗ リンク(クリックで本文表示)。
        各項目に1行メモ欄が付く。
     type:"text"      — 自由記述の textarea(placeholder 可)。
     共通: playbook を指定するとセクション見出しに「▶ flow」リンクが出る。

   file / playbook のパスは kedalab ルート相対。実在すること。
   ============================================================= */
window.KEDA_WORKSHEET = {
  version: "2026-05-30",

  meta: [
    { id: "target",   label: "TARGET",   placeholder: "10.10.10.x" },
    { id: "hostname", label: "HOSTNAME", placeholder: "" },
    { id: "os",       label: "OS",       placeholder: "Linux / Windows" },
    { id: "date",     label: "DATE",     placeholder: "2026-..." },
    { id: "scope",    label: "SCOPE / RULES", placeholder: "本番のみ: 実施可否・除外・連絡先を先に合意（演習は空欄可）" }
  ],

  sections: [
    {
      id: "recon",
      title: "[01] RECON / 列挙",
      type: "checklist",
      playbook: "00_Playbook/External_Service_Recon_Flow.md",
      items: [
        { label: "全ポートスキャン (nmap -p- → 詳細)",   file: "05_Tools_Reference/Nmap.md" },
        { label: "サービス/バージョン特定",              file: "01_Reconnaissance/Network_Scanning.md" },
        { label: "Web 列挙 (80/443)",                    file: "01_Reconnaissance/Web_Enumeration.md" },
        { label: "Web レスポンス精査 (ヘッダ/エラー)",   file: "01_Reconnaissance/Web_Response_Triage.md" },
        { label: "SMB 列挙 (139/445)",                   file: "01_Reconnaissance/SMB_Enumeration.md" },
        { label: "SNMP 列挙 (161/udp)",                  file: "01_Reconnaissance/SNMP_Enumeration.md" },
        { label: "LDAP/AD 列挙 (389/636)",               file: "01_Reconnaissance/LDAP_Enumeration.md" },
        { label: "公開ファイル/露出の確認",              file: "01_Reconnaissance/Exposed_Files.md" }
      ]
    },
    {
      id: "web",
      title: "[02-W] WEB 脆弱性",
      type: "checklist",
      playbook: "00_Playbook/Web_Vuln_Flow.md",
      items: [
        { label: "Triage で当たりを付ける (.req/.res 照合)", file: "01_Reconnaissance/Web_Response_Triage.md" },
        { label: "SQLi (エラー/数値パラメータ)",         file: "02_Initial_Access/Web_Vulnerabilities/SQLi.md" },
        { label: "ファイルアップロード",                 file: "02_Initial_Access/Web_Vulnerabilities/File_Upload.md" },
        { label: "パストラバーサル / LFI",               file: "02_Initial_Access/Web_Vulnerabilities/Path_Traversal.md" },
        { label: "コマンドインジェクション",             file: "02_Initial_Access/Web_Vulnerabilities/Command_Injection.md" },
        { label: "SSRF / Open Redirect",                 file: "02_Initial_Access/Web_Vulnerabilities/SSRF.md" },
        { label: "認証系 (JWT/OAuth/IDOR)",              file: "02_Initial_Access/Web_Vulnerabilities/IDOR.md" }
      ]
    },
    {
      id: "initial",
      title: "[02] INITIAL ACCESS",
      type: "checklist",
      items: [
        { label: "default / 弱い資格情報",               file: "02_Initial_Access/Default_Credentials.md" },
        { label: "資格情報の発見 (露出/再利用)",         file: "02_Initial_Access/Credential_Discovery.md" },
        { label: "既知 CVE 照合 (バージョン → exploit)", file: "05_Tools_Reference/Searchsploit.md" },
        { label: "エッジ機器/アプライアンス CVE",        file: "02_Initial_Access/Edge_Appliance_CVEs.md" },
        { label: "サービス別侵入 (SSH/FTP/MSSQL 等)",    file: "02_Initial_Access/MSSQL_Exploitation.md" }
      ]
    },
    {
      id: "privesc_lin",
      title: "[03] POST / PRIVESC — Linux",
      type: "checklist",
      playbook: "00_Playbook/Linux_Attack_Flow.md",
      items: [
        { label: "シェル安定化 (TTY/PATH)",              file: "03_Post_Access_Linux/Shell_Stabilization.md" },
        { label: "列挙 (linpeas/手動チェックリスト)",    file: "03_Post_Access_Linux/Enumeration_Checklist.md" },
        { label: "sudo 設定の悪用",                      file: "03_Post_Access_Linux/Sudo_Misconfig.md" },
        { label: "SUID/SGID",                            file: "03_Post_Access_Linux/SUID_SGID.md" },
        { label: "capabilities",                         file: "03_Post_Access_Linux/Capabilities.md" },
        { label: "カーネル exploit (最後の手段)",        file: "03_Post_Access_Linux/Kernel_Exploits.md" }
      ]
    },
    {
      id: "privesc_win",
      title: "[04] POST / PRIVESC — Windows / AD",
      type: "checklist",
      playbook: "00_Playbook/Windows_AD_Attack_Flow.md",
      items: [
        { label: "ドメイン列挙 (BloodHound 等)",         file: "04_Post_Access_Windows_AD/Enumeration_Checklist.md" },
        { label: "資格情報ダンプ",                       file: "04_Post_Access_Windows_AD/Credential_Dumping.md" },
        { label: "特権トークン",                         file: "04_Post_Access_Windows_AD/Privilege_Tokens.md" },
        { label: "DPAPI / ブラウザ資格情報",             file: "04_Post_Access_Windows_AD/DPAPI_Browser_Creds.md" }
      ]
    },

    { id: "loot",     title: "LOOT  (cred : where-found : works-on)", type: "text",
      placeholder: "例)\nadmin:Summer2026! : /admin login : web, SMB\nsvc_sql / hash : MSSQL : ..." },
    { id: "foothold", title: "FOOTHOLD  (どう入ったか)", type: "text",
      placeholder: "vector / 使った exploit / 取得したシェルのユーザ" },
    { id: "privesc",  title: "PRIVESC  (どう昇格したか)", type: "text",
      placeholder: "vector → root/SYSTEM までの経路" },
    { id: "proof",    title: "PROOF", type: "text",
      placeholder: "user.txt:\nroot.txt:" },
    { id: "notes",    title: "NOTES / 振り返り (型の改善メモ)", type: "text",
      placeholder: "詰まった所・次回試すこと・このテンプレに足したい項目" }
  ]
};
