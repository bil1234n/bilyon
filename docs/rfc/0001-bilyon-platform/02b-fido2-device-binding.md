# §2.2 FIDO2 / WebAuthn and Hardware Device Binding

[← RFC index](README.md)

## 2.2.1 Credential model

Biometrics are matched **on the device only**. The template and the match result stay inside the
Secure Enclave or TEE. On Android, the biometric TA hands Keystore/KeyMint an HMAC-authenticated
hardware auth token, and only then is the key usable. The server receives signatures, never biometric data or
match scores.

| Credential | Created with | Synced? | Attestable? | Authorises |
|---|---|---|---|---|
| `K_pass` passkey | WebAuthn / `ASAuthorizationPlatformPublicKeyCredentialProvider` / Credential Manager | Yes (iCloud Keychain, Google PM) | Generally no (`fmt: "none"`) | Login, session, recovery, reading data |
| `K_dev` transaction key | Secure Enclave `SecKeyCreateRandomKey` / Keystore `KeyPairGenerator` | No | iOS: via App Attest binding; Android: Key Attestation | Every money movement above the gesture limit (dynamic linking) |
| `K_gest` gesture key | As `K_dev`, but auth valid for 60 s after one biometric | No | As `K_dev` | Throws ≤ gesture limit (default 100.00) during an armed window, subject to velocity limits |
| `K_off(aid)` | As `K_dev`, one per allowance | No | As `K_dev` | Offline spend tokens (§3.A) |

Synced passkeys are excellent phishing-resistant login credentials. But they cannot prove *which device*
signed, and providers do not attest them. Money therefore needs a second, hardware-bound key (design
decision D4).

## 2.2.2 Passkey registration

```text
App / browser                                   FIDO2 RP (Go)                         Store
  │── POST /v1/webauthn/register/begin ─────────▶│ challenge = CSPRNG(32), single use,   │
  │                                             │ TTL 120 s, bound to session + user ──▶│
  │◀─ PublicKeyCredentialCreationOptions ───────│                                       │
  │ navigator.credentials.create() / platform API (biometric UV on device)              │
  │── POST /v1/webauthn/register/finish ────────▶│ verify (steps R1–R10) ───────────────▶│ credential row
  │◀─ 201 {credential_id} ──────────────────────│                                       │
```

```json
{
  "rp": { "id": "bilyon.example", "name": "Bilyon" },
  "user": { "id": "3q2-7wAAAAA... (32 random bytes, never PII)", "name": "alice", "displayName": "Alice" },
  "challenge": "base64url(32 bytes)",
  "pubKeyCredParams": [ { "type": "public-key", "alg": -7 }, { "type": "public-key", "alg": -257 } ],
  "authenticatorSelection": { "residentKey": "required", "userVerification": "required" },
  "attestation": "none",
  "excludeCredentials": [ { "type": "public-key", "id": "base64url(existing credential id)" } ],
  "hints": [ "client-device" ],
  "extensions": { "credProps": true },
  "timeout": 120000
}
```

Server verification (WebAuthn L3 §7.1). Any failure returns `400 webauthn_invalid` with the step ID logged:

| Step | Check |
|---|---|
| R1 | `clientDataJSON.type == "webauthn.create"` |
| R2 | `challenge` equals the stored one (constant time), unexpired, and is atomically marked used |
| R3 | `origin` ∈ {`https://bilyon.example`, `https://pay.bilyon.example`, `android:apk-key-hash:<b64url(SHA-256(signing cert))>`}; `crossOrigin` false |
| R4 | `attestationObject` decodes (strict CBOR) into `fmt`, `attStmt`, `authData` |
| R5 | `authData.rpIdHash == SHA-256("bilyon.example")` |
| R6 | Flags: UP = 1, **UV = 1**, AT = 1. Record BE (backup-eligible) and BS (backed-up) |
| R7 | `credentialId` ≤ 1023 B and not registered to any account |
| R8 | COSE key alg ∈ {−7, −257} and matches the requested params |
| R9 | `fmt` = `none` is accepted. Other formats are verified and the AAGUID recorded (informational, never required) |
| R10 | Persist `credential_id, user_id, cose_pubkey, sign_count, transports, be, bs, aaguid` |

## 2.2.3 Passkey authentication

```json
{ "challenge": "base64url(32 bytes)", "rpId": "bilyon.example", "allowCredentials": [],
  "userVerification": "required", "timeout": 60000 }
```

| Step | Check |
|---|---|
| A1 | Resolve the credential by `rawId`; discoverable flow: `userHandle` → account; it must match any pre-identified user |
| A2 | `type == "webauthn.get"`; challenge matches, is unexpired and unused; origin allow-list as R3 |
| A3 | `rpIdHash` matches; UP = 1, UV = 1 |
| A4 | Verify the signature over `authenticatorData ‖ SHA-256(clientDataJSON)`. WebAuthn ES256 signatures are **ASN.1 DER**, unlike the raw `r‖s` COSE signatures in §2.1 |
| A5 | `signCount`: if either stored or received is non-zero, received MUST be greater than stored; otherwise raise a clone signal to risk. Synced passkeys report 0, which is not an error |
| A6 | Log BS transitions (a credential becoming backed up) as a risk feature |
| A7 | Issue a 10-minute access token bound to a device-held proof-of-possession key (DPoP-style: every request carries a signature over method, URL, timestamp and nonce), plus a rotating refresh token |

## 2.2.4 Binding the device transaction key

**iOS (Secure Enclave + App Attest)**

```swift
let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                             [.privateKeyUsage, .biometryCurrentSet], nil)!
let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                            kSecAttrKeySizeInBits as String: 256,
                            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
                            kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: true,
                                                            kSecAttrAccessControl as String: access]]
let kDev = SecKeyCreateRandomKey(attrs as CFDictionary, &error)!
// Bind K_dev to an attested app instance:
let keyId = try await DCAppAttestService.shared.generateKey()
let clientDataHash = Data(SHA256.hash(data: Data("bilyon/bind/v1".utf8) + challenge + x963(kDev)))
let attestation = try await DCAppAttestService.shared.attestKey(keyId, clientDataHash: clientDataHash)
```

The server verifies the App Attest object as follows. The `x5c` chain must lead to the Apple App
Attestation root. The nonce extension (OID `1.2.840.113635.100.8.2`) must equal
`SHA-256(authData ‖ clientDataHash)`. `SHA-256(credCert pubkey) == keyId`. `rpIdHash ==
SHA-256(teamID.bundleID)`. The counter must be 0, and the AAGUID must be `appattest` (production). The server
then stores the App Attest key and receipt. Limitation: iOS does not let third parties attest that a key lives in the
Secure Enclave. Attested app code asserts it. This is why iOS offline allowances stay in Tier K
(§3.A.1).

**Android (StrongBox/TEE + Key Attestation + Play Integrity)**

```kotlin
val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
    .setDigests(KeyProperties.DIGEST_SHA256)
    .setIsStrongBoxBacked(true)                       // retry without on StrongBoxUnavailableException
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG) // 0 = auth per use
    .setInvalidatedByBiometricEnrollment(true)
    .setUnlockedDeviceRequired(true)
    .setAttestationChallenge(challenge)
    .build()
KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply { initialize(spec) }.generateKeyPair()
val chain = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.getCertificateChain(alias)
```

| Check (server) | Requirement |
|---|---|
| Chain | Leads to a Google hardware attestation root (including RKP-provisioned intermediates); no entry on the attestation revocation list |
| `attestationChallenge` | Equals the bind challenge |
| `attestationSecurityLevel` | `TrustedEnvironment` or `StrongBox` (recorded; StrongBox raises limits) |
| Hardware-enforced auth list | `purpose = SIGN`, `algorithm = EC`, `ecCurve = P-256`, biometric `userAuthType`, no `noAuthRequired`, no `authTimeout` for `K_dev` / 60 s for `K_gest` |
| Root of trust | `verifiedBootState = Verified`, `deviceLocked = true`, `osPatchLevel` no older than 12 months |
| App identity | `attestationApplicationId` matches the package name and signing-certificate digest |
| Play Integrity | `PLAY_RECOGNIZED`, `MEETS_DEVICE_INTEGRITY` (`MEETS_STRONG_INTEGRITY` for Tier S), nonce = `H(challenge ‖ K_dev.pub)` |
| Tier S coins (§3.A.9) | Each coin key, created with `setMaxUsageCount(1)`, shows `usageCountLimit = 1` **and** `rollbackResistance` in the TEE/StrongBox-enforced list. Software-enforced limits are rejected |

## 2.2.5 Transaction authorisation (dynamic linking)

Every online money movement carries a `TxAuth` COSE_Sign1 (`external_aad = "bilyon/txauth/v1"`) signed
by `K_dev` (or `K_gest` within the gesture limit):

```cddl
txauth = { 1 => 1, 2 => id16 (intent_id), 3 => minor (amount), 4 => currency,
           5 => h32 (payee_ref = H(payee account id)), 6 => id16 (server nonce), 7 => epoch,
           ? 8 => tstr (fx quote id), ? 9 => uint (gesture kind: 1 flick, 2 split, 3 grab) }
```

The server checks that amount, currency, payee and quote are **byte-identical** to the intent it holds
(PSD2 RTS Art. 5: the authentication code is specific to amount and payee). The biometric prompt shows
the same amount and payee (`LAContext.localizedReason` / `BiometricPrompt` title), so what the user
sees is what the key signs. `K_gest` signatures are accepted only up to the gesture limit and within
velocity limits (default: 5 throws or 250.00 per armed minute).

## 2.2.6 Web, Mini-Apps and Secure Payment Confirmation

On Chromium browsers, web checkout uses **Secure Payment Confirmation**. The browser shows the payee
and total in its own UI, and the assertion's `clientDataJSON` (`type: "payment.get"`) contains
`payment.{rpId, topOrigin, payeeName|payeeOrigin, total, instrument}`. The server compares those fields
with the intent, which gives dynamic linking on the web. Browsers without SPC use a plain WebAuthn
assertion with `challenge = H(intent fields ‖ nonce)`. The amount is then rendered by our page, not by the
browser, so these flows have a lower limit (default 250.00).

## 2.2.7 Lifecycle and recovery

| Event | Handling |
|---|---|
| Biometric enrolment changes | `.biometryCurrentSet` / `setInvalidatedByBiometricEnrollment` invalidate `K_dev`, `K_gest`, `K_off`. The user re-binds after passkey login plus step-up (liveness for high tiers). Open allowances are closed by the server at expiry |
| Device lost or stolen | User (or support) revokes the device. Its allowances go on the CRL and the passkey still works on a new device. Biometric gating means a thief cannot sign offline tokens |
| App reinstall / backup restore | Hardware keys are `ThisDeviceOnly` and the offline vault is excluded from backups, so a restored vault has no usable key (§3.A.4) |
| Clone signal (`signCount` regression, App Attest counter anomaly) | Step-up, lower limits, and manual review if it repeats |
