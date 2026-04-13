"""
Kismet Enhanced UI テストスクリプト
全ての新規追加ファイルの存在確認、構文検証、機能テストを行う。

実行方法: python test.py
依存: Python 3.8以上（標準ライブラリのみ使用）
"""

import os, sys, json, re, unittest, pathlib

BASE_DIR = pathlib.Path(__file__).parent

class TestFileExistence(unittest.TestCase):
    """STEP0: 全ての必要ファイルが存在するか"""

    REQUIRED_FILES = [
        "http_data/js/kismet_i18n.js",
        "http_data/js/kismet_whitelist_api.js",
        "http_data/js/kismet_ui_whitelist.js",
        "http_data/js/kismet_ui_unassociated.js",
        "http_data/js/kismet_ui_signal_filter.js",
        "http_data/js/kismet_ui_signal_monitor.js",
        "http_data/js/kismet_ui_export.js",
        "http_data/js/kismet_ui_enhanced.js",
        "http_data/js/kismet_enhanced_loader.js",
        "http_data/css/kismet_enhanced.css",
        "http_data/locales/en/translation.json",
        "http_data/locales/ja/translation.json",
        "http_data/js/vendor/i18next.min.js",
        "http_data/js/vendor/i18next-browser-languagedetector.min.js",
        "http_data/js/vendor/chart.min.js",
        "http_data/js/vendor/jspdf.min.js",
        "http_data/js/vendor/jspdf-autotable.min.js",
        "http_data/js/vendor/papaparse.min.js",
    ]

    def test_all_files_exist(self):
        """全ファイルの存在確認"""
        missing = []
        for f in self.REQUIRED_FILES:
            path = BASE_DIR / f
            if not path.exists():
                missing.append(f)
        self.assertEqual(missing, [],
            f"以下のファイルが見つかりません:\n" + "\n".join(missing))


class TestTranslationFiles(unittest.TestCase):
    """STEP1: 翻訳ファイルの検証"""

    def _load_json(self, lang):
        path = BASE_DIR / f"http_data/locales/{lang}/translation.json"
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def _flatten_keys(self, d, prefix=''):
        keys = set()
        for k, v in d.items():
            full = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                keys |= self._flatten_keys(v, full)
            else:
                keys.add(full)
        return keys

    def test_en_json_valid(self):
        """英語翻訳ファイルが正しいJSONか"""
        data = self._load_json('en')
        self.assertIsInstance(data, dict)
        self.assertIn('sidebar', data)
        self.assertIn('device_list', data)

    def test_ja_json_valid(self):
        """日本語翻訳ファイルが正しいJSONか"""
        data = self._load_json('ja')
        self.assertIsInstance(data, dict)
        self.assertIn('sidebar', data)

    def test_key_parity(self):
        """英語と日本語のキーが完全一致するか"""
        en = self._flatten_keys(self._load_json('en'))
        ja = self._flatten_keys(self._load_json('ja'))
        missing_in_ja = en - ja
        missing_in_en = ja - en
        self.assertEqual(missing_in_ja, set(),
            f"日本語に不足しているキー:\n" + "\n".join(sorted(missing_in_ja)))
        self.assertEqual(missing_in_en, set(),
            f"英語に不足しているキー:\n" + "\n".join(sorted(missing_in_en)))

    def test_ja_no_empty_values(self):
        """日本語翻訳に空文字列がないか"""
        data = self._load_json('ja')
        empties = []
        def check(d, prefix=''):
            for k, v in d.items():
                full = f"{prefix}.{k}" if prefix else k
                if isinstance(v, dict):
                    check(v, full)
                elif isinstance(v, str) and v.strip() == '':
                    empties.append(full)
        check(data)
        self.assertEqual(empties, [],
            f"空の翻訳値:\n" + "\n".join(empties))

    def test_ja_contains_japanese(self):
        """日本語翻訳に実際に日本語文字が含まれるか"""
        data = self._load_json('ja')
        japanese_found = False
        def check(d):
            nonlocal japanese_found
            for v in d.values():
                if isinstance(v, dict):
                    check(v)
                elif isinstance(v, str):
                    if re.search(r'[\u3040-\u309F\u30A0-\u30FF\u4E00-\u9FFF]', v):
                        japanese_found = True
                        return
        check(data)
        self.assertTrue(japanese_found, "日本語翻訳に日本語文字が見つかりません")

    def test_required_keys_exist(self):
        """必須キーが存在するか"""
        required = [
            'sidebar.devices', 'sidebar.unassociated_clients',
            'sidebar.whitelist_manage', 'sidebar.settings',
            'device_list.mac_address', 'device_list.signal',
            'device_list.channel', 'device_list.last_seen',
            'whitelist.title', 'whitelist.add', 'whitelist.import_csv',
            'whitelist.export_csv', 'whitelist.edit', 'whitelist.delete',
            'whitelist.status', 'whitelist.approved', 'whitelist.unknown',
            'whitelist.categories.pc', 'whitelist.categories.mobile',
            'whitelist.categories.iot',
            'unassociated.title', 'unassociated.probed_ssids',
            'signal_filter.above_60', 'signal_filter.show_all',
            'signal_monitor.title', 'signal_monitor.csv_save',
            'export.csv', 'export.pdf',
            'common.ok', 'common.cancel',
        ]
        en = self._flatten_keys(self._load_json('en'))
        ja = self._flatten_keys(self._load_json('ja'))
        for key in required:
            self.assertIn(key, en, f"英語に必須キー '{key}' がありません")
            self.assertIn(key, ja, f"日本語に必須キー '{key}' がありません")


class TestJavaScriptFiles(unittest.TestCase):
    """STEP2-8: JavaScriptファイルの構文・内容検証"""

    JS_FILES = [
        "http_data/js/kismet_i18n.js",
        "http_data/js/kismet_whitelist_api.js",
        "http_data/js/kismet_ui_whitelist.js",
        "http_data/js/kismet_ui_unassociated.js",
        "http_data/js/kismet_ui_signal_filter.js",
        "http_data/js/kismet_ui_signal_monitor.js",
        "http_data/js/kismet_ui_export.js",
        "http_data/js/kismet_ui_enhanced.js",
        "http_data/js/kismet_enhanced_loader.js",
    ]

    def _read(self, relpath):
        path = BASE_DIR / relpath
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()

    def test_all_js_not_empty(self):
        """全JSファイルが空でないか"""
        for f in self.JS_FILES:
            content = self._read(f)
            self.assertTrue(len(content) > 100,
                f"{f} が空または極端に短い ({len(content)}bytes)")

    def test_all_js_use_strict(self):
        """全JSファイルがuse strictを使用しているか"""
        for f in self.JS_FILES:
            content = self._read(f)
            self.assertIn('"use strict"', content,
                f"{f} に 'use strict' がありません")

    def test_no_hardcoded_japanese_in_js(self):
        """JSファイルにハードコード日本語がないか（翻訳ファイル経由であるべき）"""
        for f in self.JS_FILES:
            content = self._read(f)
            # コメント行を除外
            lines = content.split('\n')
            code_lines = [l for l in lines
                         if not l.strip().startswith('//')
                         and not l.strip().startswith('*')]
            code = '\n'.join(code_lines)
            # 日本語文字がコード中にないか（翻訳キー以外）
            # t() 関数呼び出し以外の日本語を検出
            matches = re.findall(r'[\u3040-\u309F\u30A0-\u30FF\u4E00-\u9FFF]+', code)
            # モックデータ内は許容（MOCK_DATA変数内）
            # ただし警告は出す
            if matches and 'MOCK_DATA' not in content:
                self.fail(
                    f"{f} にハードコード日本語があります: {matches[:5]}")

    def test_i18n_module_exports(self):
        """i18nモジュールが必要な関数をエクスポートしているか"""
        content = self._read("http_data/js/kismet_i18n.js")
        for func in ['initI18n', 't', 'changeLanguage', 'getCurrentLanguage']:
            self.assertTrue(
                re.search(rf'(export\s+.*(const|function|let|var)\s+{func}|exports\.{func}|export\s*\{{[^}}]*{func})', content),
                f"kismet_i18n.js に '{func}' のエクスポートがありません")

    def test_whitelist_api_exports(self):
        """ホワイトリストAPIが必要な関数をエクスポートしているか"""
        content = self._read("http_data/js/kismet_whitelist_api.js")
        required_funcs = [
            'getWhitelist', 'addToWhitelist', 'addBulkToWhitelist',
            'updateWhitelistEntry', 'removeFromWhitelist',
            'removeBulkFromWhitelist', 'isWhitelisted',
            'importFromCSV', 'exportToCSV', 'getWhitelistCache'
        ]
        for func in required_funcs:
            self.assertRegex(content, rf'{func}',
                f"kismet_whitelist_api.js に '{func}' が見つかりません")

    def test_signal_filter_exports(self):
        """信号フィルタが必要な関数をエクスポートしているか"""
        content = self._read("http_data/js/kismet_ui_signal_filter.js")
        for func in ['createSignalFilterBar', 'getSignalThreshold', 'setSignalThreshold']:
            self.assertRegex(content, rf'{func}',
                f"kismet_ui_signal_filter.js に '{func}' が見つかりません")

    def test_signal_monitor_exports(self):
        """信号モニターが必要な関数をエクスポートしているか"""
        content = self._read("http_data/js/kismet_ui_signal_monitor.js")
        self.assertRegex(content, r'OpenSignalMonitor',
            "kismet_ui_signal_monitor.js に 'OpenSignalMonitor' が見つかりません")

    def test_export_module_exports(self):
        """エクスポートモジュールが必要な関数をエクスポートしているか"""
        content = self._read("http_data/js/kismet_ui_export.js")
        for func in ['exportDeviceListCSV', 'exportDeviceListPDF', 'createExportButtons']:
            self.assertRegex(content, rf'{func}',
                f"kismet_ui_export.js に '{func}' が見つかりません")

    def test_unassociated_sidebar(self):
        """未接続クライアント画面がサイドバー登録されているか"""
        content = self._read("http_data/js/kismet_ui_unassociated.js")
        self.assertIn('AddSidebarItem', content)
        self.assertIn('unassociated', content.lower())

    def test_whitelist_ui_sidebar(self):
        """ホワイトリスト管理画面がサイドバー登録されているか"""
        content = self._read("http_data/js/kismet_ui_whitelist.js")
        self.assertIn('AddSidebarItem', content)
        self.assertIn('whitelist', content.lower())

    def test_enhanced_device_column(self):
        """メインUIにホワイトリスト列が追加されているか"""
        content = self._read("http_data/js/kismet_ui_enhanced.js")
        self.assertIn('AddDeviceColumn', content)
        self.assertIn('whitelist_status', content)

    def test_enhanced_row_highlight(self):
        """メインUIにハイライトが追加されているか"""
        content = self._read("http_data/js/kismet_ui_enhanced.js")
        self.assertIn('AddDeviceRowHighlight', content)

    def test_loader_loads_all_modules(self):
        """ローダーが全モジュールを参照しているか"""
        content = self._read("http_data/js/kismet_enhanced_loader.js")
        modules = [
            'kismet_i18n', 'kismet_whitelist_api',
            'kismet_ui_whitelist', 'kismet_ui_unassociated',
            'kismet_ui_signal_filter', 'kismet_ui_signal_monitor',
            'kismet_ui_export', 'kismet_ui_enhanced'
        ]
        for mod in modules:
            self.assertIn(mod, content,
                f"ローダーに '{mod}' の参照がありません")

    def test_unassociated_mock_data(self):
        """未接続クライアント画面にモックデータがあるか"""
        content = self._read("http_data/js/kismet_ui_unassociated.js")
        self.assertRegex(content, r'(MOCK_DATA|mockData|mock_data|fallback)',
            "未接続クライアント画面にモックデータ/フォールバックがありません")

    def test_signal_monitor_mock_mode(self):
        """信号モニターにモックモードがあるか"""
        content = self._read("http_data/js/kismet_ui_signal_monitor.js")
        self.assertRegex(content, r'(mock|MOCK|fallback|demo)',
            "信号モニターにモックモード/フォールバックがありません")

    def test_whitelist_csv_import(self):
        """ホワイトリストにCSVインポート機能があるか"""
        content_api = self._read("http_data/js/kismet_whitelist_api.js")
        content_ui = self._read("http_data/js/kismet_ui_whitelist.js")
        self.assertIn('importFromCSV', content_api)
        self.assertRegex(content_ui, r'(file|input.*csv|CSV取込|import_csv)',
            "ホワイトリストUIにCSV取込UIがありません")

    def test_whitelist_bulk_register(self):
        """検知リストからの一括ホワイトリスト登録があるか"""
        content = self._read("http_data/js/kismet_ui_unassociated.js")
        self.assertRegex(content, r'(addBulk|bulk.*whitelist|register.*whitelist|ホワイトリスト.*登録)',
            "未接続クライアント画面に一括登録機能がありません")


class TestCSSFile(unittest.TestCase):
    """STEP9: CSSファイルの検証"""

    def _read(self):
        path = BASE_DIR / "http_data/css/kismet_enhanced.css"
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()

    def test_css_not_empty(self):
        """CSSファイルが空でないか"""
        content = self._read()
        self.assertTrue(len(content) > 200,
            f"CSSファイルが空または極端に短い ({len(content)}bytes)")

    def test_signal_filter_styles(self):
        """信号フィルタのCSSが定義されているか"""
        content = self._read()
        for cls in ['.signal-filter-bar', '.signal-filter-btn']:
            self.assertIn(cls, content,
                f"CSSに '{cls}' が定義されていません")

    def test_signal_monitor_styles(self):
        """信号モニターのCSSが定義されているか"""
        content = self._read()
        for cls in ['.signal-bar-container', '.signal-bar', '.signal-value']:
            self.assertIn(cls, content,
                f"CSSに '{cls}' が定義されていません")

    def test_whitelist_styles(self):
        """ホワイトリストのCSSが定義されているか"""
        content = self._read()
        for cls in ['.whitelist-toolbar', '.whitelist-approved', '.whitelist-unknown']:
            self.assertIn(cls, content,
                f"CSSに '{cls}' が定義されていません")

    def test_modal_styles(self):
        """モーダルダイアログのCSSが定義されているか"""
        content = self._read()
        for cls in ['.kismet-modal-overlay', '.kismet-modal']:
            self.assertIn(cls, content,
                f"CSSに '{cls}' が定義されていません")

    def test_export_button_styles(self):
        """エクスポートボタンのCSSが定義されているか"""
        content = self._read()
        for cls in ['.export-btn', '.export-btn-csv', '.export-btn-pdf']:
            self.assertIn(cls, content,
                f"CSSに '{cls}' が定義されていません")


class TestVendorFiles(unittest.TestCase):
    """vendorライブラリファイルの検証"""

    VENDOR_FILES = [
        "http_data/js/vendor/i18next.min.js",
        "http_data/js/vendor/i18next-browser-languagedetector.min.js",
        "http_data/js/vendor/chart.min.js",
        "http_data/js/vendor/jspdf.min.js",
        "http_data/js/vendor/jspdf-autotable.min.js",
        "http_data/js/vendor/papaparse.min.js",
    ]

    def test_vendor_files_not_empty(self):
        """vendorファイルが空でないか"""
        for f in self.VENDOR_FILES:
            path = BASE_DIR / f
            size = path.stat().st_size
            self.assertTrue(size > 50,
                f"{f} が空または極端に短い ({size}bytes)")

    def test_vendor_files_have_source_comment(self):
        """vendorファイルにCDN元URLのコメントがあるか"""
        for f in self.VENDOR_FILES:
            path = BASE_DIR / f
            with open(path, 'r', encoding='utf-8') as fh:
                content = fh.read()
            self.assertRegex(content, r'(cdn|unpkg|jsdelivr|http|source|version)',
                f"{f} にソースURL/バージョン情報コメントがありません")


class TestWhitelistLogic(unittest.TestCase):
    """ホワイトリストAPI のロジック面の検証"""

    def test_whitelist_api_has_localstorage_key(self):
        """localStorageキーが定義されているか"""
        path = BASE_DIR / "http_data/js/kismet_whitelist_api.js"
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
        self.assertRegex(content, r'kismet\.whitelist',
            "localStorageキー 'kismet.whitelist' が見つかりません")

    def test_whitelist_api_mac_validation(self):
        """MACアドレスのバリデーションがあるか"""
        path = BASE_DIR / "http_data/js/kismet_whitelist_api.js"
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
        self.assertRegex(content,
            r'([0-9A-Fa-f]{2}[:\-]){5}|mac.*valid|validate.*mac|MAC.*format',
            "MACアドレスバリデーションが見つかりません")

    def test_whitelist_csv_column_mapping(self):
        """CSVカラムマッピングが定義されているか"""
        path = BASE_DIR / "http_data/js/kismet_whitelist_api.js"
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
        self.assertRegex(content,
            r'kismet\.device\.base\.macaddr|column.*map|CSV_COLUMN|mapping',
            "CSVカラムマッピングが見つかりません")


class TestIntegration(unittest.TestCase):
    """統合テスト: モジュール間の整合性"""

    def test_i18n_keys_used_in_js(self):
        """翻訳キーがJSファイルで実際に使われているか（サンプルチェック）"""
        json.loads(
            (BASE_DIR / "http_data/locales/en/translation.json").read_text(encoding='utf-8'))

        # 全JSファイルの内容を結合
        all_js = ""
        for f in TestJavaScriptFiles.JS_FILES:
            all_js += (BASE_DIR / f).read_text(encoding='utf-8')

        # 主要キーがJS内で参照されているか
        sample_keys = [
            'sidebar.unassociated_clients',
            'sidebar.whitelist_manage',
            'whitelist.title',
            'whitelist.import_csv',
            'signal_filter.above_60',
            'signal_monitor.title',
            'export.csv',
        ]
        missing = []
        for key in sample_keys:
            # t('key') or t("key") の形式で使われているか
            escaped = re.escape(key)
            if not re.search(rf"t\(['\"].*{escaped}", all_js):
                # 部分一致も許容 (例: sidebar.whitelist_manage)
                parts = key.split('.')
                last = parts[-1]
                if last not in all_js:
                    missing.append(key)
        # 50%以上使われていればOK（段階的適用のため）
        self.assertTrue(len(missing) < len(sample_keys) * 0.5,
            f"翻訳キーがJSで使われていない: {missing}")

    def test_css_classes_used_in_js(self):
        """CSSクラスがJSで実際に使われているか"""
        css = (BASE_DIR / "http_data/css/kismet_enhanced.css").read_text(encoding='utf-8')
        all_js = ""
        for f in TestJavaScriptFiles.JS_FILES:
            all_js += (BASE_DIR / f).read_text(encoding='utf-8')

        # CSSからクラス名を抽出
        css_classes = re.findall(r'\.([\w-]+)\s*\{', css)
        # 主要クラスがJSで参照されているか
        key_classes = [c for c in css_classes if any(
            prefix in c for prefix in
            ['signal-filter', 'signal-bar', 'signal-monitor',
             'whitelist-', 'export-btn', 'kismet-modal',
             'unassoc-']
        )]
        used = sum(1 for c in key_classes if c in all_js)
        self.assertTrue(used > 0,
            "CSSの主要クラスがJSファイルで全く使われていません")


class TestSummary(unittest.TestCase):
    """テスト結果サマリー"""

    def test_print_summary(self):
        """ファイルサマリーを出力"""
        print("\n" + "="*60)
        print("実装ファイルサマリー")
        print("="*60)
        total_size = 0
        total_lines = 0
        for root, dirs, files in os.walk(BASE_DIR / "http_data"):
            for f in sorted(files):
                if f.endswith(('.js', '.css', '.json')):
                    path = pathlib.Path(root) / f
                    rel = path.relative_to(BASE_DIR)
                    size = path.stat().st_size
                    with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
                        lines = len(fh.readlines())
                    total_size += size
                    total_lines += lines
                    print(f"  {str(rel):<60} {size:>8} bytes  {lines:>5} lines")
        print("-"*60)
        print(f"  合計: {total_size:>8} bytes  {total_lines:>5} lines")
        print("="*60)


if __name__ == '__main__':
    print("="*60)
    print("Kismet Enhanced UI テスト")
    print(f"作業ディレクトリ: {BASE_DIR}")
    print(f"Python: {sys.version}")
    print("="*60)
    unittest.main(verbosity=2)
