// Single-screen white-label TOTP authenticator.
//
// Branding (app name, colors, logo) comes from branding.json, bundled as an
// asset and loaded via rootBundle. Rebranding = edit branding.json and
// replace the icon, no code changes needed.

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show rootBundle;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'otpauth.dart';
import 'totp.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final branding = await Branding.load();
  runApp(AuthenticatorApp(branding: branding));
}

/// Visual identity loaded from branding.json.
class Branding {
  const Branding({
    required this.appName,
    required this.issuer,
    required this.primaryColor,
    required this.accentColor,
    required this.logoPath,
  });

  final String appName;
  final String issuer;
  final Color primaryColor;
  final Color accentColor;
  final String logoPath;

  static Future<Branding> load() async {
    final raw = await rootBundle.loadString('branding.json');
    final json = jsonDecode(raw) as Map<String, dynamic>;
    return Branding(
      appName: json['appName'] as String? ?? 'Authenticator',
      issuer: json['issuer'] as String? ?? '',
      primaryColor: _parseColor(json['primaryColor'] as String? ?? '#1E88E5'),
      accentColor: _parseColor(json['accentColor'] as String? ?? '#FFC107'),
      logoPath: json['logoPath'] as String? ?? '',
    );
  }

  static Color _parseColor(String hex) {
    var h = hex.replaceFirst('#', '').trim();
    if (h.length == 6) h = 'FF$h';
    return Color(int.parse(h, radix: 16));
  }
}

class AuthenticatorApp extends StatelessWidget {
  const AuthenticatorApp({super.key, required this.branding});

  final Branding branding;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: branding.appName,
      theme: ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(
          seedColor: branding.primaryColor,
          secondary: branding.accentColor,
        ),
      ),
      home: AccountsPage(branding: branding),
    );
  }
}

class AccountsPage extends StatefulWidget {
  const AccountsPage({super.key, required this.branding});

  final Branding branding;

  @override
  State<AccountsPage> createState() => _AccountsPageState();
}

class _AccountsPageState extends State<AccountsPage> {
  static const _storageKey = 'accounts';
  static const _storage = FlutterSecureStorage();

  final List<OtpAccount> _accounts = [];
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _loadAccounts();
    // Rebuild once per second so codes and countdowns stay live.
    _timer = Timer.periodic(const Duration(seconds: 1), (_) {
      if (mounted) setState(() {});
    });
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  Future<void> _loadAccounts() async {
    final raw = await _storage.read(key: _storageKey);
    if (raw == null) return;
    try {
      final list = jsonDecode(raw) as List<dynamic>;
      setState(() {
        _accounts
          ..clear()
          ..addAll(list.map((e) => OtpAccount.fromJson(e as Map<String, dynamic>)));
      });
    } on FormatException {
      // Corrupted store; start empty rather than crash.
    }
  }

  Future<void> _saveAccounts() {
    return _storage.write(
      key: _storageKey,
      value: jsonEncode(_accounts.map((a) => a.toJson()).toList()),
    );
  }

  Future<void> _addAccount() async {
    final controller = TextEditingController();
    final uri = await showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Add account'),
        content: TextField(
          controller: controller,
          autofocus: true,
          maxLines: 3,
          decoration: const InputDecoration(
            hintText: 'otpauth://totp/Acme:alice@example.com?secret=...',
            border: OutlineInputBorder(),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, controller.text),
            child: const Text('Add'),
          ),
        ],
      ),
    );
    if (uri == null || uri.trim().isEmpty) return;

    try {
      final account = parseOtpauthUri(uri);
      if (account.type != 'totp') {
        throw const FormatException('Only TOTP accounts are supported in this example');
      }
      // Validate the secret now so bad input fails before saving.
      base32Decode(account.secret);
      setState(() => _accounts.add(account));
      await _saveAccounts();
    } on FormatException catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Could not add account: ${e.message}')),
      );
    }
  }

  Future<void> _deleteAccount(OtpAccount account) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Delete account?'),
        content: Text('Remove ${account.label}? This cannot be undone.'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Delete'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    setState(() => _accounts.remove(account));
    await _saveAccounts();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text(widget.branding.appName)),
      body: _accounts.isEmpty
          ? const Center(
              child: Text('No accounts yet.\nTap + to add one from an otpauth:// URI.',
                  textAlign: TextAlign.center),
            )
          : ListView.builder(
              itemCount: _accounts.length,
              itemBuilder: (context, index) =>
                  _AccountTile(account: _accounts[index], onDelete: () => _deleteAccount(_accounts[index])),
            ),
      floatingActionButton: FloatingActionButton(
        onPressed: _addAccount,
        tooltip: 'Add account',
        child: const Icon(Icons.add),
      ),
    );
  }
}

class _AccountTile extends StatelessWidget {
  const _AccountTile({required this.account, required this.onDelete});

  final OtpAccount account;
  final VoidCallback onDelete;

  @override
  Widget build(BuildContext context) {
    final Uint8List key = base32Decode(account.secret);
    final code = totp(
      key,
      period: account.period,
      digits: account.digits,
      algorithm: account.algorithm,
    );
    final remaining = remainingSeconds(period: account.period);

    return ListTile(
      title: Text(account.label),
      subtitle: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (account.issuer != null && account.issuer!.isNotEmpty)
            Text(account.issuer!, style: Theme.of(context).textTheme.bodySmall),
          const SizedBox(height: 4),
          Text(
            code,
            style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                  letterSpacing: 4,
                  fontWeight: FontWeight.bold,
                ),
          ),
          const SizedBox(height: 4),
          Row(
            children: [
              Expanded(
                child: LinearProgressIndicator(value: remaining / account.period),
              ),
              const SizedBox(width: 8),
              Text('${remaining}s'),
            ],
          ),
        ],
      ),
      isThreeLine: true,
      trailing: IconButton(
        icon: const Icon(Icons.delete_outline),
        tooltip: 'Delete',
        onPressed: onDelete,
      ),
    );
  }
}
