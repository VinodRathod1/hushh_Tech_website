/**
 * Auth Services Unit Tests
 *
 * Covers: signOut, getSession, isLoggedIn, getFullName, getAccessToken,
 *         checkRegistrationStatus, emailLogin, and mfaService.
 *
 * All Supabase calls are mocked — no real network requests are made.
 * Environment: node (window / localStorage are mocked manually where needed).
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ─── Shared Mock Session ──────────────────────────────────────────────────────
const MOCK_SESSION = {
  access_token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.mock-access-token",
  refresh_token: "mock-refresh-token",
  expires_in: 3600,
  token_type: "bearer",
  user: {
    id: "user-uuid-789",
    email: "contributor@hushh.ai",
    app_metadata: { provider: "email" },
    user_metadata: {
      full_name: "Hushh Contributor",
      avatar_url: "https://example.com/avatar.png",
    },
    email_confirmed_at: "2026-01-01T00:00:00.000Z",
    aud: "authenticated",
    created_at: "2026-01-01T00:00:00.000Z",
  },
};

// ─── Hoisted Mock Declarations ────────────────────────────────────────────────
// All vi.fn() instances must be declared inside vi.hoisted() so they are
// available before the vi.mock() factory functions execute.
const {
  mockSignOut,
  mockGetSession,
  mockSignInWithPassword,
  mockGetUser,
  mockGetUserDetails,
  mockMfaEnroll,
  mockMfaChallenge,
  mockMfaVerify,
  mockMfaUnenroll,
  mockMfaListFactors,
  mockGetAuthenticatorAssuranceLevel,
  mockIlike,
  mockSelect,
  mockFrom,
  baseSupabaseClient,
  mockResourcesConfig,
  mockConfigObj,
} = vi.hoisted(() => {
  const mockSignOut = vi.fn();
  const mockGetSession = vi.fn();
  const mockSignInWithPassword = vi.fn();
  const mockGetUser = vi.fn();
  const mockGetUserDetails = vi.fn();
  const mockMfaEnroll = vi.fn();
  const mockMfaChallenge = vi.fn();
  const mockMfaVerify = vi.fn();
  const mockMfaUnenroll = vi.fn();
  const mockMfaListFactors = vi.fn();
  const mockGetAuthenticatorAssuranceLevel = vi.fn();

  // Chainable query builder: .from().select().ilike()
  const mockIlike = vi.fn();
  const mockSelect = vi.fn(() => ({ ilike: mockIlike }));
  const mockFrom = vi.fn(() => ({ select: mockSelect }));

  const baseSupabaseClient = {
    auth: {
      signOut: mockSignOut,
      getSession: mockGetSession,
      signInWithPassword: mockSignInWithPassword,
      getUser: mockGetUser,
      mfa: {
        enroll: mockMfaEnroll,
        challenge: mockMfaChallenge,
        verify: mockMfaVerify,
        unenroll: mockMfaUnenroll,
        listFactors: mockMfaListFactors,
        getAuthenticatorAssuranceLevel: mockGetAuthenticatorAssuranceLevel,
      },
    },
    from: mockFrom,
  };

  // Mutable objects — individual tests can set supabaseClient to null
  const mockResourcesConfig = { supabaseClient: baseSupabaseClient as any };
  const mockConfigObj = { supabaseClient: baseSupabaseClient as any };

  return {
    mockSignOut,
    mockGetSession,
    mockSignInWithPassword,
    mockGetUser,
    mockGetUserDetails,
    mockMfaEnroll,
    mockMfaChallenge,
    mockMfaVerify,
    mockMfaUnenroll,
    mockMfaListFactors,
    mockGetAuthenticatorAssuranceLevel,
    mockIlike,
    mockSelect,
    mockFrom,
    baseSupabaseClient,
    mockResourcesConfig,
    mockConfigObj,
  };
});

// ─── Module Mocks ─────────────────────────────────────────────────────────────
vi.mock("../src/resources/resources", () => ({
  default: { config: mockResourcesConfig },
}));

vi.mock("../src/resources/config/config", () => ({
  default: mockConfigObj,
}));

vi.mock("../src/services/services", () => ({
  default: {
    authentication: {
      getUserDetails: mockGetUserDetails,
    },
  },
}));

// ─── Static Imports (after all vi.mock() calls) ───────────────────────────────
import signOut from "../src/services/authentication/signOut";
import getSession from "../src/services/authentication/getSession";
import isLoggedIn from "../src/services/authentication/isLoggedIn";
import getFullName from "../src/services/authentication/getFullName";
import getAccessToken from "../src/services/authentication/getAccessToken";
import checkRegistrationStatus from "../src/services/authentication/checkRegistrationStatus";
import {
  enrollMFA,
  verifyMFAEnrollment,
  challengeMFA,
  verifyMFAChallenge,
  unenrollMFA,
  getMFAFactors,
  getAssuranceLevel,
  hasMFAEnrolled,
  getVerifiedMFAFactors,
} from "../src/services/authentication/mfaService";

// ═════════════════════════════════════════════════════════════════════════════
// 1. signOut
// ═════════════════════════════════════════════════════════════════════════════

describe("Auth Service — signOut", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockResourcesConfig.supabaseClient = baseSupabaseClient as any;
  });

  it("should call supabase auth.signOut() exactly once when client is defined", async () => {
    mockSignOut.mockResolvedValue({ error: null });

    await signOut();

    expect(mockSignOut).toHaveBeenCalledOnce();
  });

  it("should NOT call auth.signOut() when supabaseClient is null", async () => {
    mockResourcesConfig.supabaseClient = null as any;

    await signOut();

    expect(mockSignOut).not.toHaveBeenCalled();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 2. getSession
// ═════════════════════════════════════════════════════════════════════════════

describe("Auth Service — getSession", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockResourcesConfig.supabaseClient = baseSupabaseClient as any;
  });

  it("should call supabase auth.getSession() exactly once", async () => {
    mockGetSession.mockResolvedValue({
      data: { session: MOCK_SESSION },
      error: null,
    });

    await getSession();

    expect(mockGetSession).toHaveBeenCalledOnce();
  });

  it("should return undefined because the session result is intentionally discarded", async () => {
    mockGetSession.mockResolvedValue({
      data: { session: MOCK_SESSION },
      error: null,
    });

    const result = await getSession();

    expect(result).toBeUndefined();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 3. isLoggedIn
// ═════════════════════════════════════════════════════════════════════════════

describe("Auth Service — isLoggedIn", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should return true and call setter with true when a session exists", async () => {
    mockGetUserDetails.mockResolvedValue({ data: MOCK_SESSION });
    const setter = vi.fn();

    const result = await isLoggedIn(setter);

    expect(result).toBe(true);
    expect(setter).toHaveBeenCalledOnce();
    expect(setter).toHaveBeenCalledWith(true);
  });

  it("should return false and call setter with false when no session exists", async () => {
    mockGetUserDetails.mockResolvedValue({ data: null });
    const setter = vi.fn();

    const result = await isLoggedIn(setter);

    expect(result).toBe(false);
    expect(setter).toHaveBeenCalledWith(false);
  });

  it("should return false and not crash when setter is null", async () => {
    mockGetUserDetails.mockResolvedValue({ data: null });

    await expect(isLoggedIn(null as any)).resolves.not.toThrow();

    const result = await isLoggedIn(null as any);
    expect(result).toBe(false);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 4. getFullName
// ═════════════════════════════════════════════════════════════════════════════

describe("Auth Service — getFullName", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should return the full_name string from user_metadata and call setter", async () => {
    mockGetUserDetails.mockResolvedValue({ data: MOCK_SESSION });
    const setter = vi.fn();

    const result = await getFullName(setter);

    expect(result).toBe("Hushh Contributor");
    expect(setter).toHaveBeenCalledOnce();
    expect(setter).toHaveBeenCalledWith("Hushh Contributor");
  });

  it("should return undefined when there is no active session", async () => {
    mockGetUserDetails.mockResolvedValue({ data: null });

    const result = await getFullName(null as any);

    expect(result).toBeUndefined();
  });

  it("should not crash when setter is null and session is absent", async () => {
    mockGetUserDetails.mockResolvedValue({ data: null });

    await expect(getFullName(null as any)).resolves.not.toThrow();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 5. getAccessToken
// ═════════════════════════════════════════════════════════════════════════════

describe("Auth Service — getAccessToken", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should return the access_token from session and call setter with it", async () => {
    mockGetUserDetails.mockResolvedValue({ data: MOCK_SESSION });
    const setter = vi.fn();

    const result = await getAccessToken(setter);

    expect(result).toBe(MOCK_SESSION.access_token);
    expect(setter).toHaveBeenCalledOnce();
    expect(setter).toHaveBeenCalledWith(MOCK_SESSION.access_token);
  });

  it("should return null explicitly when there is no session (early return guard)", async () => {
    mockGetUserDetails.mockResolvedValue({ data: null });

    const result = await getAccessToken(null as any);

    expect(result).toBeNull();
  });

  it("should not crash when setter is null and session is absent", async () => {
    mockGetUserDetails.mockResolvedValue({ data: null });

    await expect(getAccessToken(null as any)).resolves.not.toThrow();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 6. checkRegistrationStatus
// ═════════════════════════════════════════════════════════════════════════════

describe("Auth Service — checkRegistrationStatus", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockConfigObj.supabaseClient = baseSupabaseClient as any;
  });

  it("should return isRegistered:true and hasHushhId:true for a user with a valid hushh_id", async () => {
    mockIlike.mockResolvedValue({
      data: [{ email: "contributor@hushh.ai", hushh_id: "HID-12345" }],
      error: null,
    });

    const result = await checkRegistrationStatus("contributor@hushh.ai");

    expect(result).toEqual(
      expect.objectContaining({ isRegistered: true, hasHushhId: true })
    );
    expect(result.userData).toBeDefined();
  });

  it("should return hasHushhId:false when hushh_id is an empty string", async () => {
    mockIlike.mockResolvedValue({
      data: [{ email: "contributor@hushh.ai", hushh_id: "" }],
      error: null,
    });

    const result = await checkRegistrationStatus("contributor@hushh.ai");

    expect(result.isRegistered).toBe(false);
    expect(result.hasHushhId).toBe(false);
  });

  it("should return hasHushhId:false when hushh_id is only whitespace (trim check)", async () => {
    mockIlike.mockResolvedValue({
      data: [{ email: "contributor@hushh.ai", hushh_id: "   " }],
      error: null,
    });

    const result = await checkRegistrationStatus("contributor@hushh.ai");

    expect(result.hasHushhId).toBe(false);
    expect(result.isRegistered).toBe(false);
  });

  it("should return all false when user is not found in the database (empty array)", async () => {
    mockIlike.mockResolvedValue({ data: [], error: null });

    const result = await checkRegistrationStatus("unknown@hushh.ai");

    expect(result).toEqual({
      isRegistered: false,
      hasHushhId: false,
      userData: null,
    });
  });

  it("should return all false when the database returns an error", async () => {
    mockIlike.mockResolvedValue({
      data: null,
      error: { message: "DB connection failed" },
    });

    const result = await checkRegistrationStatus("contributor@hushh.ai");

    expect(result).toEqual({
      isRegistered: false,
      hasHushhId: false,
      userData: null,
    });
  });

  it("should return all false gracefully when an exception is thrown", async () => {
    mockIlike.mockRejectedValue(new Error("Unexpected network error"));

    const result = await checkRegistrationStatus("contributor@hushh.ai");

    expect(result).toEqual({
      isRegistered: false,
      hasHushhId: false,
      userData: null,
    });
  });

  it("regression: source file must NOT contain the old Supabase project URL", async () => {
    const fs = await import("fs");
    const source = fs.readFileSync(
      "src/services/authentication/checkRegistrationStatus.ts",
      "utf-8"
    );

    expect(source).not.toContain("rpmzykoxqnbozgdoqbpc");
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 7. emailLogin
// Node environment has no DOM — window and localStorage are mocked manually.
// ═════════════════════════════════════════════════════════════════════════════

describe("Auth Service — emailLogin", () => {
  let originalWindow: any;
  let originalLocalStorage: any;

  const mockLocalStorage = {
    setItem: vi.fn(),
    getItem: vi.fn(),
    removeItem: vi.fn(),
    clear: vi.fn(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockResourcesConfig.supabaseClient = baseSupabaseClient as any;

    // Preserve originals so afterEach can restore them
    originalWindow = (global as any).window;
    originalLocalStorage = (global as any).localStorage;

    // Mock window.location for redirect assertions
    Object.defineProperty(global, "window", {
      value: { location: { href: "" } },
      writable: true,
      configurable: true,
    });

    // Mock localStorage for setItem assertions
    Object.defineProperty(global, "localStorage", {
      value: mockLocalStorage,
      writable: true,
      configurable: true,
    });
  });

  afterEach(() => {
    Object.defineProperty(global, "window", {
      value: originalWindow,
      writable: true,
      configurable: true,
    });
    Object.defineProperty(global, "localStorage", {
      value: originalLocalStorage,
      writable: true,
      configurable: true,
    });
  });

  it("should return 'error' when supabaseClient is null", async () => {
    mockResourcesConfig.supabaseClient = null as any;
    const { default: emailLogin } = await import(
      "../src/services/authentication/emailLogin"
    );

    const result = await emailLogin("test@hushh.ai", "password123");

    expect(result).toBe("error");
  });

  it("should return 'error' when signInWithPassword fails", async () => {
    mockSignInWithPassword.mockResolvedValue({
      data: null,
      error: { message: "Invalid login credentials" },
    });
    const { default: emailLogin } = await import(
      "../src/services/authentication/emailLogin"
    );

    const result = await emailLogin("test@hushh.ai", "wrongpassword");

    expect(result).toBe("error");
  });

  it("should return 'email_not_verified' when the user's email is not confirmed", async () => {
    mockSignInWithPassword.mockResolvedValue({ data: MOCK_SESSION, error: null });
    mockGetUser.mockResolvedValue({
      data: { user: { email_confirmed_at: null } },
      error: null,
    });
    const { default: emailLogin } = await import(
      "../src/services/authentication/emailLogin"
    );

    const result = await emailLogin("unverified@hushh.ai", "password123");

    expect(result).toBe("email_not_verified");
  });

  it("should set localStorage.isLoggedIn and redirect to /hushh-user-profile on success", async () => {
    mockSignInWithPassword.mockResolvedValue({ data: MOCK_SESSION, error: null });
    mockGetUser.mockResolvedValue({
      data: { user: { email_confirmed_at: "2026-01-01T00:00:00.000Z" } },
      error: null,
    });
    const { default: emailLogin } = await import(
      "../src/services/authentication/emailLogin"
    );

    await emailLogin("contributor@hushh.ai", "securepass");

    expect(mockLocalStorage.setItem).toHaveBeenCalledWith("isLoggedIn", "true");
    expect((global as any).window.location.href).toBe("/hushh-user-profile");
  });

  it("should return 'error' gracefully when an unexpected exception is thrown", async () => {
    mockSignInWithPassword.mockRejectedValue(new Error("Network failure"));
    const { default: emailLogin } = await import(
      "../src/services/authentication/emailLogin"
    );

    await expect(
      emailLogin("test@hushh.ai", "password123")
    ).resolves.not.toThrow();

    mockSignInWithPassword.mockRejectedValue(new Error("Network failure"));
    const result = await emailLogin("test@hushh.ai", "password123");
    expect(result).toBe("error");
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 8. mfaService — enrollMFA
// ═════════════════════════════════════════════════════════════════════════════

describe("Auth Service — mfaService › enrollMFA", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockConfigObj.supabaseClient = baseSupabaseClient as any;
  });

  it("should return { data, error: null } on successful TOTP enrollment", async () => {
    const mockEnrollData = {
      id: "factor-id-001",
      totp: {
        qr_code: "data:image/png;base64,mockqrcode",
        secret: "MOCKSECRET123",
        uri: "otpauth://totp/Hushh:contributor?secret=MOCKSECRET123",
      },
    };
    mockMfaEnroll.mockResolvedValue({ data: mockEnrollData, error: null });

    const result = await enrollMFA();

    expect(result.error).toBeNull();
    expect(result.data).toEqual(
      expect.objectContaining({ id: "factor-id-001" })
    );
    expect(mockMfaEnroll).toHaveBeenCalledWith(
      expect.objectContaining({ factorType: "totp" })
    );
  });

  it("should return { data: null, error } when supabaseClient is null", async () => {
    mockConfigObj.supabaseClient = null as any;

    const result = await enrollMFA();

    expect(result.data).toBeNull();
    expect(result.error).toBeDefined();
  });

  it("should return { data: null, error } when the enroll API returns an error", async () => {
    mockMfaEnroll.mockResolvedValue({
      data: null,
      error: { message: "MFA already enrolled" },
    });

    const result = await enrollMFA();

    expect(result.data).toBeNull();
    expect(result.error).toEqual(
      expect.objectContaining({ message: "MFA already enrolled" })
    );
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 8. mfaService — verifyMFAEnrollment (two-step: challenge → verify)
// ═════════════════════════════════════════════════════════════════════════════

describe("Auth Service — mfaService › verifyMFAEnrollment", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockConfigObj.supabaseClient = baseSupabaseClient as any;
  });

  it("should return early with { data: null, error } and never call verify when challenge fails", async () => {
    mockMfaChallenge.mockResolvedValue({
      data: null,
      error: { message: "Challenge creation failed" },
    });

    const result = await verifyMFAEnrollment("factor-id-001", "123456");

    expect(result.data).toBeNull();
    expect(result.error).toBeDefined();
    expect(mockMfaVerify).not.toHaveBeenCalled();
  });

  it("should return { data: null, error } when the verify step fails after a successful challenge", async () => {
    mockMfaChallenge.mockResolvedValue({
      data: { id: "challenge-id-001" },
      error: null,
    });
    mockMfaVerify.mockResolvedValue({
      data: null,
      error: { message: "Invalid OTP code" },
    });

    const result = await verifyMFAEnrollment("factor-id-001", "999999");

    expect(result.data).toBeNull();
    expect(result.error).toEqual(
      expect.objectContaining({ message: "Invalid OTP code" })
    );
  });

  it("should return { data, error: null } and call both challenge and verify on full success", async () => {
    mockMfaChallenge.mockResolvedValue({
      data: { id: "challenge-id-001" },
      error: null,
    });
    mockMfaVerify.mockResolvedValue({
      data: { access_level: "aal2" },
      error: null,
    });

    const result = await verifyMFAEnrollment("factor-id-001", "123456");

    expect(result.error).toBeNull();
    expect(result.data).toBeDefined();
    expect(mockMfaChallenge).toHaveBeenCalledWith(
      expect.objectContaining({ factorId: "factor-id-001" })
    );
    expect(mockMfaVerify).toHaveBeenCalledWith(
      expect.objectContaining({
        factorId: "factor-id-001",
        challengeId: "challenge-id-001",
        code: "123456",
      })
    );
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 8. mfaService — challengeMFA
// ═════════════════════════════════════════════════════════════════════════════

describe("Auth Service — mfaService › challengeMFA", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockConfigObj.supabaseClient = baseSupabaseClient as any;
  });

  it("should return { data, error: null } with a challenge id on success", async () => {
    mockMfaChallenge.mockResolvedValue({
      data: { id: "challenge-id-002" },
      error: null,
    });

    const result = await challengeMFA("factor-id-001");

    expect(result.error).toBeNull();
    expect(result.data).toEqual(
      expect.objectContaining({ id: "challenge-id-002" })
    );
    expect(mockMfaChallenge).toHaveBeenCalledWith(
      expect.objectContaining({ factorId: "factor-id-001" })
    );
  });

  it("should return { data: null, error } when challenge creation fails", async () => {
    mockMfaChallenge.mockResolvedValue({
      data: null,
      error: { message: "Factor not found" },
    });

    const result = await challengeMFA("invalid-factor-id");

    expect(result.data).toBeNull();
    expect(result.error).toBeDefined();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 8. mfaService — verifyMFAChallenge
// ═════════════════════════════════════════════════════════════════════════════

describe("Auth Service — mfaService › verifyMFAChallenge", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockConfigObj.supabaseClient = baseSupabaseClient as any;
  });

  it("should return { data, error: null } with correct params on successful verification", async () => {
    mockMfaVerify.mockResolvedValue({
      data: { access_level: "aal2" },
      error: null,
    });

    const result = await verifyMFAChallenge(
      "factor-id-001",
      "challenge-id-001",
      "123456"
    );

    expect(result.error).toBeNull();
    expect(result.data).toEqual(
      expect.objectContaining({ access_level: "aal2" })
    );
    expect(mockMfaVerify).toHaveBeenCalledWith(
      expect.objectContaining({
        factorId: "factor-id-001",
        challengeId: "challenge-id-001",
        code: "123456",
      })
    );
  });

  it("should return { data: null, error } when OTP verification fails", async () => {
    mockMfaVerify.mockResolvedValue({
      data: null,
      error: { message: "OTP code expired" },
    });

    const result = await verifyMFAChallenge(
      "factor-id-001",
      "challenge-id-001",
      "000000"
    );

    expect(result.data).toBeNull();
    expect(result.error).toEqual(
      expect.objectContaining({ message: "OTP code expired" })
    );
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 8. mfaService — unenrollMFA
// ═════════════════════════════════════════════════════════════════════════════

describe("Auth Service — mfaService › unenrollMFA", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockConfigObj.supabaseClient = baseSupabaseClient as any;
  });

  it("should return { data, error: null } and call unenroll with the correct factorId", async () => {
    mockMfaUnenroll.mockResolvedValue({
      data: { id: "factor-id-001" },
      error: null,
    });

    const result = await unenrollMFA("factor-id-001");

    expect(result.error).toBeNull();
    expect(result.data).toBeDefined();
    expect(mockMfaUnenroll).toHaveBeenCalledWith(
      expect.objectContaining({ factorId: "factor-id-001" })
    );
  });

  it("should return { data: null, error } when unenrollment fails", async () => {
    mockMfaUnenroll.mockResolvedValue({
      data: null,
      error: { message: "Factor already removed" },
    });

    const result = await unenrollMFA("factor-id-001");

    expect(result.data).toBeNull();
    expect(result.error).toBeDefined();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 8. mfaService — getMFAFactors
// ═════════════════════════════════════════════════════════════════════════════

describe("Auth Service — mfaService › getMFAFactors", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockConfigObj.supabaseClient = baseSupabaseClient as any;
  });

  it("should return the data.all array when listFactors succeeds", async () => {
    const mockFactors = [
      { id: "factor-001", status: "verified", factor_type: "totp" },
      { id: "factor-002", status: "unverified", factor_type: "totp" },
    ];
    mockMfaListFactors.mockResolvedValue({
      data: { all: mockFactors, totp: mockFactors },
      error: null,
    });

    const result = await getMFAFactors();

    expect(result.error).toBeNull();
    expect(result.data).toEqual(mockFactors);
    expect(result.data).toHaveLength(2);
  });

  it("should return { data: null, error } when listFactors fails", async () => {
    mockMfaListFactors.mockResolvedValue({
      data: null,
      error: { message: "User not authenticated" },
    });

    const result = await getMFAFactors();

    expect(result.data).toBeNull();
    expect(result.error).toBeDefined();
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 8. mfaService — getAssuranceLevel
// ═════════════════════════════════════════════════════════════════════════════

describe("Auth Service — mfaService › getAssuranceLevel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockConfigObj.supabaseClient = baseSupabaseClient as any;
  });

  it("should return assurance level data with currentLevel and nextLevel on success", async () => {
    const mockLevelData = {
      currentLevel: "aal1",
      nextLevel: "aal2",
      currentAuthenticationMethods: [{ method: "password", timestamp: 1700000000 }],
    };
    mockGetAuthenticatorAssuranceLevel.mockResolvedValue({
      data: mockLevelData,
      error: null,
    });

    const result = await getAssuranceLevel();

    expect(result.error).toBeNull();
    expect(result.data).toEqual(
      expect.objectContaining({ currentLevel: "aal1", nextLevel: "aal2" })
    );
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 8. mfaService — hasMFAEnrolled
// Composed function — internally calls getMFAFactors → listFactors
// ═════════════════════════════════════════════════════════════════════════════

describe("Auth Service — mfaService › hasMFAEnrolled", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockConfigObj.supabaseClient = baseSupabaseClient as any;
  });

  it("should return true when at least one MFA factor exists", async () => {
    mockMfaListFactors.mockResolvedValue({
      data: {
        all: [{ id: "factor-001", status: "verified", factor_type: "totp" }],
      },
      error: null,
    });

    const result = await hasMFAEnrolled();

    expect(result).toBe(true);
  });

  it("should return false when no MFA factors exist (empty array)", async () => {
    mockMfaListFactors.mockResolvedValue({
      data: { all: [] },
      error: null,
    });

    const result = await hasMFAEnrolled();

    expect(result).toBe(false);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// 8. mfaService — getVerifiedMFAFactors
// Composed function — filters getMFAFactors() result by status === "verified"
// ═════════════════════════════════════════════════════════════════════════════

describe("Auth Service — mfaService › getVerifiedMFAFactors", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockConfigObj.supabaseClient = baseSupabaseClient as any;
  });

  it("should return only factors with status === 'verified' from a mixed-status array", async () => {
    const mixedFactors = [
      { id: "factor-001", status: "verified", factor_type: "totp" },
      { id: "factor-002", status: "unverified", factor_type: "totp" },
      { id: "factor-003", status: "verified", factor_type: "totp" },
    ];
    mockMfaListFactors.mockResolvedValue({
      data: { all: mixedFactors },
      error: null,
    });

    const result = await getVerifiedMFAFactors();

    expect(result.error).toBeNull();
    expect(result.data).toHaveLength(2);
    expect(
      result.data?.every((factor: any) => factor.status === "verified")
    ).toBe(true);
  });
});
