// Crypto polyfills must be imported first, before anything that might
// touch the crypto API. 2fa-kit only uses the standard Web Crypto API
// (globalThis.crypto.subtle and crypto.getRandomValues), which React
// Native does not ship natively.
import "react-native-get-random-values";
import QuickCrypto from "react-native-quick-crypto";

if (typeof globalThis.crypto === "undefined" || !globalThis.crypto.subtle) {
  // react-native-quick-crypto implements the Web Crypto interface in
  // native code, so 2fa-kit can call crypto.subtle unchanged.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  globalThis.crypto = QuickCrypto as any;
}

import React, { useEffect, useRef, useState } from "react";
import {
  Alert,
  Button,
  FlatList,
  KeyboardAvoidingView,
  Platform,
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  View,
} from "react-native";
import * as SecureStore from "expo-secure-store";
import { parseUri, totp } from "2fa-kit";

const STORAGE_KEY = "accounts";
const PERIOD_SECONDS = 30;

interface Account {
  label: string;
  issuer?: string;
  secret: string;
}

interface CodeState {
  code: string;
  remaining: number;
}

function formatCode(code: string): string {
  return code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code;
}

export default function App() {
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [codes, setCodes] = useState<Record<string, CodeState>>({});
  const [uri, setUri] = useState("");
  const [error, setError] = useState<string | null>(null);
  // Codes must not be persisted before the stored accounts have loaded,
  // or the save effect below would overwrite storage with an empty list.
  const loaded = useRef(false);

  useEffect(() => {
    (async () => {
      try {
        const raw = await SecureStore.getItemAsync(STORAGE_KEY);
        if (raw) {
          const parsed = JSON.parse(raw);
          if (Array.isArray(parsed)) {
            setAccounts(parsed as Account[]);
          }
        }
      } catch {
        setError("Could not read stored accounts.");
      } finally {
        loaded.current = true;
      }
    })();
  }, []);

  useEffect(() => {
    if (!loaded.current) return;
    SecureStore.setItemAsync(STORAGE_KEY, JSON.stringify(accounts)).catch(() => {
      setError("Could not save accounts.");
    });
  }, [accounts]);

  useEffect(() => {
    let cancelled = false;
    async function tick() {
      const results = await Promise.all(
        accounts.map(async (account) => {
          try {
            const result = await totp(account.secret);
            return [account.secret, result] as const;
          } catch {
            return [account.secret, { code: "------", remaining: 0 }] as const;
          }
        }),
      );
      if (!cancelled) {
        setCodes(Object.fromEntries(results));
      }
    }
    tick();
    const interval = setInterval(tick, 1000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [accounts]);

  function addAccount() {
    setError(null);
    const value = uri.trim();
    if (!value) return;
    try {
      const parsed = parseUri(value);
      if (parsed.type !== "totp") {
        setError("Only TOTP accounts are supported by this example.");
        return;
      }
      const account: Account = { label: parsed.label, secret: parsed.secret };
      if (parsed.issuer !== undefined) {
        account.issuer = parsed.issuer;
      }
      setAccounts((current) => [...current, account]);
      setUri("");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  function confirmRemove(account: Account) {
    Alert.alert("Remove account", `Remove ${account.issuer ?? account.label}?`, [
      { text: "Cancel", style: "cancel" },
      {
        text: "Remove",
        style: "destructive",
        onPress: () =>
          setAccounts((current) =>
            current.filter((item) => item.secret !== account.secret),
          ),
      },
    ]);
  }

  function renderAccount({ item }: { item: Account }) {
    const code = codes[item.secret];
    const fraction = code ? code.remaining / PERIOD_SECONDS : 0;
    return (
      <Pressable onLongPress={() => confirmRemove(item)} style={styles.row}>
        <View style={styles.rowText}>
          <Text style={styles.issuer}>{item.issuer ?? "No issuer"}</Text>
          <Text style={styles.label}>{item.label}</Text>
          <Text style={styles.code}>{code ? formatCode(code.code) : "..."}</Text>
        </View>
        <View style={styles.rowSide}>
          <Text style={styles.remaining}>{code ? `${code.remaining}s` : ""}</Text>
          <View style={styles.progressTrack}>
            <View style={[styles.progressFill, { flex: fraction }]} />
            <View style={{ flex: 1 - fraction }} />
          </View>
        </View>
      </Pressable>
    );
  }

  return (
    <KeyboardAvoidingView
      style={styles.screen}
      behavior={Platform.OS === "ios" ? "padding" : undefined}
    >
      <Text style={styles.title}>2fa-kit Authenticator</Text>
      <FlatList
        data={accounts}
        keyExtractor={(item) => item.secret}
        renderItem={renderAccount}
        ListEmptyComponent={
          <Text style={styles.empty}>
            No accounts yet. Paste an otpauth:// URI below to add one.
          </Text>
        }
        contentContainerStyle={accounts.length === 0 ? styles.emptyContainer : undefined}
      />
      {error ? <Text style={styles.error}>{error}</Text> : null}
      <View style={styles.addForm}>
        <TextInput
          style={styles.input}
          value={uri}
          onChangeText={setUri}
          placeholder="otpauth://totp/...?secret=..."
          autoCapitalize="none"
          autoCorrect={false}
        />
        <Button title="Add account" onPress={addAccount} />
      </View>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  screen: {
    flex: 1,
    paddingTop: 60,
    paddingHorizontal: 16,
    backgroundColor: "#ffffff",
  },
  title: {
    fontSize: 22,
    fontWeight: "600",
    marginBottom: 16,
  },
  emptyContainer: {
    flexGrow: 1,
    justifyContent: "center",
  },
  empty: {
    textAlign: "center",
    color: "#666666",
  },
  row: {
    flexDirection: "row",
    alignItems: "center",
    paddingVertical: 12,
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: "#cccccc",
  },
  rowText: {
    flex: 1,
  },
  issuer: {
    fontSize: 13,
    color: "#666666",
  },
  label: {
    fontSize: 15,
    fontWeight: "500",
  },
  code: {
    fontSize: 28,
    fontVariant: ["tabular-nums"],
    letterSpacing: 2,
    marginTop: 4,
  },
  rowSide: {
    alignItems: "flex-end",
    width: 56,
  },
  remaining: {
    fontSize: 13,
    color: "#666666",
    marginBottom: 4,
  },
  progressTrack: {
    flexDirection: "row",
    height: 4,
    width: "100%",
    backgroundColor: "#e0e0e0",
    borderRadius: 2,
    overflow: "hidden",
  },
  progressFill: {
    backgroundColor: "#2563eb",
  },
  error: {
    color: "#b91c1c",
    marginVertical: 8,
  },
  addForm: {
    paddingVertical: 12,
    gap: 8,
  },
  input: {
    borderWidth: 1,
    borderColor: "#cccccc",
    borderRadius: 6,
    paddingHorizontal: 10,
    paddingVertical: 8,
    fontSize: 14,
  },
});
