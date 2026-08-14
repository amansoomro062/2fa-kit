# 2fa-kit Expo Authenticator Example

A minimal Expo (React Native) authenticator app built on the
[`2fa-kit`](../../) package. It demonstrates that 2fa-kit runs fully
on-device: every TOTP code is computed locally with the Web Crypto API,
with no network access and no server involved.

What it does:

- Stores accounts (label, issuer, base32 secret) in `expo-secure-store`.
- Recomputes each account's TOTP code every second with `totp()` and shows
  the code plus a countdown to expiry.
- Adds accounts by pasting an `otpauth://` URI, parsed with `parseUri()`.
- Removes accounts via long-press, with a confirmation dialog.

## Prerequisites

- Node.js 20 or newer.
- An Android or iOS device/emulator with the platform tooling installed
  (Android Studio, or Xcode on macOS).
- A development build. This example uses `react-native-quick-crypto`, which
  contains native code, so it does NOT work in Expo Go. You must build a
  dev client with `npx expo prebuild` and `npx expo run:android` /
  `npx expo run:ios` (or an EAS development build).

## Setup

```sh
cd examples/expo-authenticator
npm install
npx expo prebuild
npx expo run:android   # or: npx expo run:ios
```

## How the crypto works

2fa-kit only calls the standard Web Crypto API: `crypto.getRandomValues`
and `crypto.subtle`. React Native does not provide these, so `App.tsx`
imports two polyfills before anything else:

- `react-native-get-random-values` for `crypto.getRandomValues`.
- `react-native-quick-crypto` for `crypto.subtle`, assigned to
  `globalThis.crypto` when the standard object is missing.

After that, the library code runs unchanged, exactly as it does on Node
or in a browser.

## Testing end-to-end

1. Enrol with any site that offers TOTP two-factor authentication (GitHub,
   for example) and copy the otpauth URI or the "text code" setup key.
   Alternatively, generate a test URI with the parent package:

   ```sh
   # run from the repository root, after `npm run build`
   node --input-type=module -e "
     import { generateSecret, buildUri } from './dist/index.js';
     const secret = await generateSecret();
     console.log(buildUri({ label: 'alice@example.com', issuer: '2fa-kit Demo', secret }));
   "
   ```

2. Paste the `otpauth://totp/...` URI into the input field in the app and
   tap "Add account".
3. Compare the 6-digit codes shown in the app with another authenticator
   (or with the site's verification prompt). They should match and rotate
   every 30 seconds.

## Status

Scaffolded and reviewed against the 2fa-kit and Expo SDK 52 APIs, but not
yet run on a physical device. Dependency versions are pinned for Expo
SDK 52 (React Native 0.76, React 18.3.1); if you use a newer SDK, align
the versions with `npx expo install --check`.
