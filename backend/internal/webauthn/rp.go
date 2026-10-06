package webauthn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/bil1234n/bilyon/backend/internal/cose"
)

// Config configures the relying party.
type Config struct {
	RPID   string // e.g. "bilyon.example"
	RPName string // e.g. "Bilyon"
	// Origins allowed in client data (R3): https web origins and Android
	// app origins of the form android:apk-key-hash:<base64url(SHA-256)>.
	Origins             []string
	RegistrationTimeout time.Duration  // default 120 s
	LoginTimeout        time.Duration  // default 60 s
	TrustAnchors        *x509.CertPool // optional; anchored attestations are marked so
	Now                 func() time.Time
}

// Algorithms the relying party accepts (R8), in preference order.
var supportedAlgs = []int64{cose.AlgES256, cose.AlgRS256}

// Credentials is the credential and account store the relying party uses
// (PGStore in production).
type Credentials interface {
	UserByID(ctx context.Context, id uuid.UUID) (User, error)
	UserByHandle(ctx context.Context, handle []byte) (User, error)
	CredentialByID(ctx context.Context, id []byte) (Credential, error)
	CredentialsForUser(ctx context.Context, userID uuid.UUID) ([]Credential, error)
	InsertCredential(ctx context.Context, c Credential) error
	RecordAssertion(ctx context.Context, u AssertionUpdate) error
}

// RP runs WebAuthn ceremonies.
type RP struct {
	cfg        Config
	rpIDHash   [32]byte
	origins    map[string]bool
	challenges ChallengeStore
	creds      Credentials
}

// New validates the configuration and returns a relying party.
func New(cfg Config, challenges ChallengeStore, creds Credentials) (*RP, error) {
	if cfg.RPID == "" || strings.ContainsAny(cfg.RPID, "/:") {
		return nil, fmt.Errorf("webauthn: invalid RP ID %q", cfg.RPID)
	}
	if cfg.RPName == "" {
		return nil, errors.New("webauthn: RP name is required")
	}
	if len(cfg.Origins) == 0 {
		return nil, errors.New("webauthn: at least one origin is required")
	}
	origins := map[string]bool{}
	for _, o := range cfg.Origins {
		if err := checkOrigin(o, cfg.RPID); err != nil {
			return nil, err
		}
		origins[o] = true
	}
	if cfg.RegistrationTimeout == 0 {
		cfg.RegistrationTimeout = 120 * time.Second
	}
	if cfg.LoginTimeout == 0 {
		cfg.LoginTimeout = 60 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &RP{cfg: cfg, rpIDHash: sha256.Sum256([]byte(cfg.RPID)), origins: origins, challenges: challenges,
		creds: creds}, nil
}

// checkOrigin accepts https origins whose host is the RP ID or one of its
// subdomains, and Android app origins.
func checkOrigin(o, rpID string) error {
	if hash, ok := strings.CutPrefix(o, "android:apk-key-hash:"); ok {
		raw, err := base64.RawURLEncoding.DecodeString(hash)
		if err != nil || len(raw) != sha256.Size {
			return fmt.Errorf("webauthn: invalid Android origin %q", o)
		}
		return nil
	}
	u, err := url.Parse(o)
	if err != nil || u.Scheme != "https" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("webauthn: origin %q must be https://host[:port]", o)
	}
	host := u.Hostname()
	if host != rpID && !strings.HasSuffix(host, "."+rpID) {
		return fmt.Errorf("webauthn: origin %q is not within RP ID %q", o, rpID)
	}
	return nil
}

func newFlowID() (string, []byte, error) {
	buf := make([]byte, 16+32)
	if _, err := rand.Read(buf); err != nil {
		return "", nil, err
	}
	return base64.RawURLEncoding.EncodeToString(buf[:16]), buf[16:], nil
}

// BeginRegistration starts a passkey registration for user (§2.2.2). It
// returns the creation options for the client and the flow id the client
// must send back with the response.
func (rp *RP) BeginRegistration(ctx context.Context, user User) (*CreationOptions, string, error) {
	if user.Status != "active" {
		return nil, "", fmt.Errorf("webauthn: account %s is %s", user.ID, user.Status)
	}
	existing, err := rp.creds.CredentialsForUser(ctx, user.ID)
	if err != nil {
		return nil, "", err
	}
	flowID, challenge, err := newFlowID()
	if err != nil {
		return nil, "", err
	}
	exclude := make([]CredentialDescriptor, 0, len(existing))
	for _, c := range existing {
		exclude = append(exclude, CredentialDescriptor{Type: "public-key", ID: c.ID, Transports: c.Transports})
	}
	params := make([]CredentialParameter, len(supportedAlgs))
	for i, a := range supportedAlgs {
		params[i] = CredentialParameter{Type: "public-key", Alg: a}
	}
	c := ceremony{Kind: "create", Challenge: challenge, UserID: user.ID, Algs: supportedAlgs,
		Expires: rp.cfg.Now().Add(rp.cfg.RegistrationTimeout)}
	if err := rp.challenges.Put(ctx, flowID, c, rp.cfg.RegistrationTimeout); err != nil {
		return nil, "", err
	}
	return &CreationOptions{
		RP:                     RelyingPartyEntity{ID: rp.cfg.RPID, Name: rp.cfg.RPName},
		User:                   UserEntity{ID: user.Handle, Name: user.DisplayName, DisplayName: user.DisplayName},
		Challenge:              challenge,
		PubKeyCredParams:       params,
		Timeout:                rp.cfg.RegistrationTimeout.Milliseconds(),
		ExcludeCredentials:     exclude,
		AuthenticatorSelection: AuthenticatorSelection{ResidentKey: "required", UserVerification: "required"},
		Attestation:            "none",
		Hints:                  []string{"client-device"},
		Extensions:             map[string]any{"credProps": true},
	}, flowID, nil
}

// takeCeremony consumes the flow's ceremony and checks the client data
// against it: type (R1/A2), challenge (R2/A2) and origin (R3/A2).
func (rp *RP) takeCeremony(ctx context.Context, flowID, kind string, rawClientData []byte) (ceremony, error) {
	step := map[string]string{"create": "R2", "get": "A2"}[kind]
	c, err := rp.challenges.Take(ctx, flowID)
	if errors.Is(err, ErrNotFound) {
		return ceremony{}, fail(step, "unknown, expired or already used flow")
	}
	if err != nil {
		return ceremony{}, err
	}
	if c.Kind != kind {
		return ceremony{}, fail(step, "flow is a %s ceremony", c.Kind)
	}
	if !rp.cfg.Now().Before(c.Expires) {
		return ceremony{}, fail(step, "challenge expired")
	}
	cd, err := parseClientData(rawClientData, step)
	if err != nil {
		return ceremony{}, err
	}
	wantType := map[string]string{"create": "webauthn.create", "get": "webauthn.get"}[kind]
	if cd.Type != wantType {
		return ceremony{}, fail(map[string]string{"create": "R1", "get": "A2"}[kind], "client data type %q", cd.Type)
	}
	got, err := cd.challengeBytes()
	if err != nil || !constantTimeEqual(got, c.Challenge) {
		return ceremony{}, fail(step, "challenge mismatch")
	}
	originStep := map[string]string{"create": "R3", "get": "A2"}[kind]
	if !rp.origins[cd.Origin] {
		return ceremony{}, fail(originStep, "origin %q not allowed", cd.Origin)
	}
	if cd.CrossOrigin != nil && *cd.CrossOrigin {
		return ceremony{}, fail(originStep, "cross-origin ceremony")
	}
	if cd.TopOrigin != "" {
		return ceremony{}, fail(originStep, "embedded ceremony (topOrigin %q)", cd.TopOrigin)
	}
	return c, nil
}

// FinishRegistration verifies a registration response (R1–R10) and stores
// the credential.
func (rp *RP) FinishRegistration(ctx context.Context, flowID string, resp *RegistrationResponse) (*Credential, error) {
	if err := checkCredentialEnvelope("R4", resp.ID, resp.RawID, resp.Type); err != nil {
		return nil, err
	}
	c, err := rp.takeCeremony(ctx, flowID, "create", resp.Response.ClientDataJSON)
	if err != nil {
		return nil, err
	}
	att, err := parseAttestationObject(resp.Response.AttestationObject)
	if err != nil {
		return nil, err
	}
	ad, err := parseAuthenticatorData(att.AuthData, true)
	if err != nil {
		return nil, err
	}
	if !constantTimeEqual(ad.RPIDHash, rp.rpIDHash[:]) {
		return nil, fail("R5", "rpIdHash mismatch")
	}
	if !ad.up() || !ad.uv() {
		return nil, fail("R6", "user presence %v, user verification %v", ad.up(), ad.uv())
	}
	if !constantTimeEqual(ad.CredentialID, resp.RawID) {
		return nil, fail("R7", "credential id differs from rawId")
	}
	if _, err := rp.creds.CredentialByID(ctx, ad.CredentialID); err == nil {
		return nil, fail("R7", "credential already registered")
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if !slices.Contains(c.Algs, ad.Key.Alg) {
		return nil, fail("R8", "algorithm %d was not requested", ad.Key.Alg)
	}
	cdh := sha256.Sum256(resp.Response.ClientDataJSON)
	res, err := verifyAttestation(att.Format, att.Statement,
		&verifyContext{ad: ad, cdh: cdh[:], anchors: rp.cfg.TrustAnchors, now: rp.cfg.Now()})
	if err != nil {
		return nil, err
	}
	keyRaw, err := ad.Key.Encode()
	if err != nil {
		return nil, fail("R10", "encode key: %v", err)
	}
	cred := Credential{ID: ad.CredentialID, UserID: c.UserID, PublicKey: keyRaw, Alg: ad.Key.Alg,
		SignCount: ad.SignCount, Transports: validTransports(resp.Response.Transports), BackupEligible: ad.be(),
		BackedUp: ad.bs(), AAGUID: ad.AAGUID, AttestationFormat: res.Format, AttestationTrust: res.Trust}
	if err := rp.creds.InsertCredential(ctx, cred); err != nil {
		if errors.Is(err, ErrCredentialExists) {
			return nil, fail("R7", "credential already registered")
		}
		return nil, err
	}
	return &cred, nil
}

// BeginLogin starts a discoverable passkey login (§2.2.3). userID, when
// not nil, pre-identifies the account the credential must belong to.
func (rp *RP) BeginLogin(ctx context.Context, userID *uuid.UUID) (*RequestOptions, string, error) {
	flowID, challenge, err := newFlowID()
	if err != nil {
		return nil, "", err
	}
	c := ceremony{Kind: "get", Challenge: challenge, Expires: rp.cfg.Now().Add(rp.cfg.LoginTimeout)}
	if userID != nil {
		c.UserID = *userID
	}
	if err := rp.challenges.Put(ctx, flowID, c, rp.cfg.LoginTimeout); err != nil {
		return nil, "", err
	}
	return &RequestOptions{Challenge: challenge, RPID: rp.cfg.RPID, AllowCredentials: []CredentialDescriptor{},
		UserVerification: "required", Timeout: rp.cfg.LoginTimeout.Milliseconds()}, flowID, nil
}

// LoginResult describes a verified assertion.
type LoginResult struct {
	UserID       uuid.UUID
	CredentialID []byte
	// CloneSignal is set when the signature counter did not advance (A5);
	// login proceeds and the risk engine decides on step-up.
	CloneSignal bool
	BackedUp    bool
}

// FinishLogin verifies an assertion (A1–A6) and records its effects.
func (rp *RP) FinishLogin(ctx context.Context, flowID string, resp *AssertionResponse) (*LoginResult, error) {
	if err := checkCredentialEnvelope("A1", resp.ID, resp.RawID, resp.Type); err != nil {
		return nil, err
	}
	c, err := rp.takeCeremony(ctx, flowID, "get", resp.Response.ClientDataJSON)
	if err != nil {
		return nil, err
	}
	cred, err := rp.creds.CredentialByID(ctx, resp.RawID)
	if errors.Is(err, ErrNotFound) {
		return nil, fail("A1", "unknown credential")
	}
	if err != nil {
		return nil, err
	}
	if len(resp.Response.UserHandle) > 0 {
		u, err := rp.creds.UserByHandle(ctx, resp.Response.UserHandle)
		if errors.Is(err, ErrNotFound) || (err == nil && u.ID != cred.UserID) {
			return nil, fail("A1", "user handle does not own the credential")
		}
		if err != nil {
			return nil, err
		}
	}
	if c.UserID != uuid.Nil && c.UserID != cred.UserID {
		return nil, fail("A1", "credential belongs to another account than the one identified")
	}
	user, err := rp.creds.UserByID(ctx, cred.UserID)
	if err != nil {
		return nil, err
	}
	if user.Status != "active" {
		return nil, fail("A1", "account is %s", user.Status)
	}
	ad, err := parseAuthenticatorData(resp.Response.AuthenticatorData, false)
	if err != nil {
		return nil, err
	}
	if !constantTimeEqual(ad.RPIDHash, rp.rpIDHash[:]) {
		return nil, fail("A3", "rpIdHash mismatch")
	}
	if !ad.up() || !ad.uv() {
		return nil, fail("A3", "user presence %v, user verification %v", ad.up(), ad.uv())
	}
	if ad.be() != cred.BackupEligible {
		return nil, fail("A3", "backup eligibility changed")
	}
	if err := verifyAssertionSignature(cred.PublicKey, resp.Response.AuthenticatorData, resp.Response.ClientDataJSON,
		resp.Response.Signature); err != nil {
		return nil, err
	}
	clone := (cred.SignCount != 0 || ad.SignCount != 0) && ad.SignCount <= cred.SignCount
	update := AssertionUpdate{CredentialID: cred.ID, UserID: cred.UserID, SignCount: ad.SignCount, BackedUp: ad.bs(),
		CloneSignal: clone, BecameBacked: ad.bs() && !cred.BackedUp}
	if err := rp.creds.RecordAssertion(ctx, update); err != nil {
		return nil, err
	}
	return &LoginResult{UserID: cred.UserID, CredentialID: cred.ID, CloneSignal: clone, BackedUp: ad.bs()}, nil
}
