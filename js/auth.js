const API_BASE =
  "https://verifieddoc-platform-production.up.railway.app/api/v1";

const AUTH_STORAGE_KEY = "verifieddoc_auth";
const ORG_STORAGE_KEY = "verifieddoc_org_id";
const REFRESH_SKEW_MS = 60 * 1000;

const ROLE_REDIRECTS = {
  HOLDER: "src/prototype-dashboard-creHolder.html",
  VERIFIER: "dashboard-verifier.html",
  PLATFORM_ADMIN: "admin-dashboard.html",
};

const UI_ROLE_TO_API = {
  holder: "HOLDER",
  verifier: "VERIFIER",
};

let refreshPromise = null;

function qs(params = {}) {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === "") return;
    search.set(key, String(value));
  });
  const value = search.toString();
  return value ? `?${value}` : "";
}

function getAuthSession() {
  try {
    const raw = localStorage.getItem(AUTH_STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function saveAuthSession(session) {
  localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(session));
  if (session?.organization?.id) {
    localStorage.setItem(ORG_STORAGE_KEY, session.organization.id);
  }
}

function clearAuthSession() {
  localStorage.removeItem(AUTH_STORAGE_KEY);
  localStorage.removeItem(ORG_STORAGE_KEY);
}

function getOrganizationId() {
  return (
    localStorage.getItem(ORG_STORAGE_KEY) ||
    getAuthSession()?.organization?.id ||
    null
  );
}

function setOrganizationId(organizationId) {
  if (organizationId) localStorage.setItem(ORG_STORAGE_KEY, organizationId);
  else localStorage.removeItem(ORG_STORAGE_KEY);
}

function redirectForRole(role, session) {
  const active = session || getAuthSession();
  if (active?.organization?.id) {
    setOrganizationId(active.organization.id);
    window.location.href = "dashboard-issuing-organization.html";
    return;
  }
  const target = ROLE_REDIRECTS[role];
  if (target) window.location.href = target;
}

function getJwtExpiry(accessToken) {
  if (!accessToken) return null;
  try {
    const payload = accessToken.split(".")[1];
    const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
    const json = JSON.parse(atob(normalized));
    return typeof json.exp === "number" ? json.exp * 1000 : null;
  } catch {
    return null;
  }
}

function isAccessTokenExpired(accessToken, skewMs = REFRESH_SKEW_MS) {
  const expiresAt = getJwtExpiry(accessToken);
  if (!expiresAt) return true;
  return Date.now() >= expiresAt - skewMs;
}

async function apiRequest(
  path,
  { method = "GET", body, token, auth = false, rawBody = false, headers: extraHeaders } = {},
) {
  const headers = { ...(extraHeaders || {}) };
  if (!rawBody) headers["Content-Type"] = headers["Content-Type"] || "application/json";

  let accessToken = token;
  if (auth && !accessToken) {
    accessToken = await getValidAccessToken();
  }
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;

  const response = await fetch(`${API_BASE}${path}`, {
    method,
    headers,
    body: body == null ? undefined : rawBody ? body : JSON.stringify(body),
  });

  if (response.status === 204) return null;

  const text = await response.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { error: { code: "PARSE_ERROR", message: text } };
    }
  }

  if (!response.ok) {
    if (auth && response.status === 401 && !token) {
      try {
        const session = await refreshSession();
        return apiRequest(path, {
          method,
          body,
          token: session.accessToken,
          rawBody,
          headers: extraHeaders,
        });
      } catch {
        // Fall through.
      }
    }

    const message =
      data?.error?.message ||
      data?.message ||
      `Request failed (${response.status})`;
    const error = new Error(message);
    error.status = response.status;
    error.data = data;
    throw error;
  }

  return data;
}

async function uploadToSignedUrl(uploadUrl, file, headers = {}) {
  const response = await fetch(uploadUrl, {
    method: "PUT",
    headers: {
      "Content-Type": headers["Content-Type"] || file.type || "application/octet-stream",
      ...headers,
    },
    body: file,
  });
  if (!response.ok) {
    throw new Error(`File upload failed (${response.status})`);
  }
  return true;
}

/* ===================== Auth ===================== */

async function registerAccount(payload) {
  return apiRequest("/auth/register", { method: "POST", body: payload });
}

async function loginAccount({ email, password }) {
  return apiRequest("/auth/login", {
    method: "POST",
    body: { email, password },
  });
}

async function refreshSession(refreshToken) {
  if (refreshPromise) return refreshPromise;

  refreshPromise = (async () => {
    const session = getAuthSession();
    const token = refreshToken || session?.refreshToken;
    if (!token) {
      clearAuthSession();
      throw new Error("No refresh token available. Please log in again.");
    }
    const nextSession = await apiRequest("/auth/refresh", {
      method: "POST",
      body: { refreshToken: token },
    });
    saveAuthSession(nextSession);
    return nextSession;
  })();

  try {
    return await refreshPromise;
  } catch (err) {
    clearAuthSession();
    throw err;
  } finally {
    refreshPromise = null;
  }
}

async function logoutAccount() {
  const session = getAuthSession();
  try {
    if (session?.refreshToken) {
      await apiRequest("/auth/logout", {
        method: "POST",
        body: { refreshToken: session.refreshToken },
      });
    }
  } finally {
    clearAuthSession();
  }
}

async function getValidAccessToken() {
  const session = getAuthSession();
  if (!session?.accessToken) {
    throw new Error("Not authenticated. Please log in.");
  }
  if (!isAccessTokenExpired(session.accessToken)) {
    return session.accessToken;
  }
  const refreshed = await refreshSession(session.refreshToken);
  return refreshed.accessToken;
}

async function getMe() {
  return apiRequest("/auth/me", { auth: true });
}

async function updateMe(payload) {
  return apiRequest("/auth/me", { method: "PATCH", auth: true, body: payload });
}

async function changePassword(payload) {
  return apiRequest("/auth/me/password", {
    method: "PATCH",
    auth: true,
    body: payload,
  });
}

async function requestPasswordReset(email) {
  return apiRequest("/auth/password-reset/request", {
    method: "POST",
    body: { email },
  });
}

async function verifyPasswordResetOtp({ requestId, otp }) {
  return apiRequest("/auth/password-reset/verify", {
    method: "POST",
    body: { requestId, otp },
  });
}

async function confirmPasswordReset({ resetToken, newPassword }) {
  return apiRequest("/auth/password-reset/confirm", {
    method: "POST",
    body: { resetToken, newPassword },
  });
}

/* ===================== Holder ===================== */

async function getHolderDashboard() {
  return apiRequest("/holder/dashboard", { auth: true });
}

async function getHolderActivity(params = {}) {
  return apiRequest(`/holder/activity${qs(params)}`, { auth: true });
}

async function getHolderVerificationRequests(params = {}) {
  return apiRequest(`/holder/verification-requests${qs(params)}`, {
    auth: true,
  });
}

async function getHolderDocuments() {
  return apiRequest("/holder/documents", { auth: true });
}

async function createHolderDocumentUploadUrl(payload) {
  return apiRequest("/holder/documents/upload-url", {
    method: "POST",
    auth: true,
    body: payload,
  });
}

async function completeHolderDocumentUpload(documentId) {
  return apiRequest(`/holder/documents/${documentId}/complete`, {
    method: "POST",
    auth: true,
  });
}

async function deleteHolderDocument(documentId) {
  return apiRequest(`/holder/documents/${documentId}`, {
    method: "DELETE",
    auth: true,
  });
}

async function uploadHolderDocument({
  file,
  title,
  documentType = "OTHER",
}) {
  const signed = await createHolderDocumentUploadUrl({
    title: title || file.name,
    documentType,
    originalFileName: file.name,
    mimeType: file.type || "application/octet-stream",
    sizeBytes: file.size,
  });
  await uploadToSignedUrl(signed.uploadUrl, file, signed.headers || {});
  return completeHolderDocumentUpload(signed.documentId);
}

/* ===================== Credentials & Share ===================== */

async function getHolderCredentials(params = {}) {
  return apiRequest(`/credentials${qs(params)}`, { auth: true });
}

async function getCredential(credentialId) {
  return apiRequest(`/credentials/${credentialId}`, { auth: true });
}

async function getCredentialArtifacts(credentialId) {
  return apiRequest(`/credentials/${credentialId}/artifacts`, { auth: true });
}

async function createShareLink(credentialId, payload) {
  return apiRequest(`/credentials/${credentialId}/share-links`, {
    method: "POST",
    auth: true,
    body: payload,
  });
}

async function revokeShareLink(credentialId, shareLinkId) {
  return apiRequest(
    `/credentials/${credentialId}/share-links/${shareLinkId}/revoke`,
    { method: "PATCH", auth: true },
  );
}

/* ===================== Notifications ===================== */

async function getNotifications(params = {}) {
  return apiRequest(`/notifications${qs(params)}`, { auth: true });
}

async function markNotificationRead(notificationId) {
  return apiRequest(`/notifications/${notificationId}/read`, {
    method: "PATCH",
    auth: true,
  });
}

async function markAllNotificationsRead() {
  return apiRequest("/notifications/read-all", {
    method: "PATCH",
    auth: true,
  });
}

/* ===================== Public verify ===================== */

async function publicVerify(token) {
  return apiRequest(`/verify/${encodeURIComponent(token)}`);
}

/* ===================== Verifier ===================== */

async function getVerifierDashboard() {
  return apiRequest("/verifier/dashboard", { auth: true });
}

async function performVerification(payload) {
  return apiRequest("/verifier/verifications", {
    method: "POST",
    auth: true,
    body: payload,
  });
}

async function getVerifierVerification(verificationId) {
  return apiRequest(`/verifier/verifications/${verificationId}`, {
    auth: true,
  });
}

async function createVerifierVerificationRequest(payload) {
  return apiRequest("/verifier/verification-requests", {
    method: "POST",
    auth: true,
    body: payload,
  });
}

async function getVerifierVerificationRequest(requestId) {
  return apiRequest(`/verifier/verification-requests/${requestId}`, {
    auth: true,
  });
}

async function cancelVerifierVerificationRequest(requestId) {
  return apiRequest(`/verifier/verification-requests/${requestId}/cancel`, {
    method: "PATCH",
    auth: true,
  });
}

async function createFileVerificationUploadUrl(payload) {
  return apiRequest("/verifier/file-verifications/upload-url", {
    method: "POST",
    auth: true,
    body: payload,
  });
}

async function completeFileVerification(uploadId) {
  return apiRequest(`/verifier/file-verifications/${uploadId}/complete`, {
    method: "POST",
    auth: true,
  });
}

async function getSavedOrganizations() {
  return apiRequest("/verifier/saved-organizations", { auth: true });
}

async function saveOrganization(organizationId) {
  return apiRequest("/verifier/saved-organizations", {
    method: "POST",
    auth: true,
    body: { organizationId },
  });
}

async function unsaveOrganization(organizationId) {
  return apiRequest(`/verifier/saved-organizations/${organizationId}`, {
    method: "DELETE",
    auth: true,
  });
}

/* ===================== Organizations / Issuer ===================== */

async function applyOrganization(payload) {
  return apiRequest("/organizations", {
    method: "POST",
    auth: true,
    body: payload,
  });
}

async function getOrganization(organizationId = getOrganizationId()) {
  return apiRequest(`/organizations/${organizationId}`, { auth: true });
}

async function getOrganizationDashboard(organizationId = getOrganizationId()) {
  return apiRequest(`/organizations/${organizationId}/dashboard`, {
    auth: true,
  });
}

async function getOrganizationMembers(organizationId = getOrganizationId()) {
  return apiRequest(`/organizations/${organizationId}/members`, { auth: true });
}

async function updateOrganizationMember(
  userId,
  payload,
  organizationId = getOrganizationId(),
) {
  return apiRequest(`/organizations/${organizationId}/members/${userId}`, {
    method: "PATCH",
    auth: true,
    body: payload,
  });
}

async function createOrganizationInvitation(
  payload,
  organizationId = getOrganizationId(),
) {
  return apiRequest(`/organizations/${organizationId}/invitations`, {
    method: "POST",
    auth: true,
    body: payload,
  });
}

async function revokeOrganizationInvitation(
  invitationId,
  organizationId = getOrganizationId(),
) {
  return apiRequest(
    `/organizations/${organizationId}/invitations/${invitationId}/revoke`,
    { method: "PATCH", auth: true },
  );
}

async function acceptInvitation(payload) {
  return apiRequest("/invitations/accept", {
    method: "POST",
    auth: true,
    body: payload,
  });
}

async function getOrganizationRecipients(
  params = {},
  organizationId = getOrganizationId(),
) {
  return apiRequest(
    `/organizations/${organizationId}/recipients${qs(params)}`,
    { auth: true },
  );
}

async function getRecipientInvitations(
  params = {},
  organizationId = getOrganizationId(),
) {
  return apiRequest(
    `/organizations/${organizationId}/recipient-invitations${qs(params)}`,
    { auth: true },
  );
}

async function createRecipientInvitation(
  payload,
  organizationId = getOrganizationId(),
) {
  return apiRequest(`/organizations/${organizationId}/recipient-invitations`, {
    method: "POST",
    auth: true,
    body: payload,
  });
}

async function revokeRecipientInvitation(
  invitationId,
  organizationId = getOrganizationId(),
) {
  return apiRequest(
    `/organizations/${organizationId}/recipient-invitations/${invitationId}/revoke`,
    { method: "PATCH", auth: true },
  );
}

async function acceptRecipientInvitation(payload) {
  return apiRequest("/recipient-invitations/accept", {
    method: "POST",
    auth: true,
    body: payload,
  });
}

async function issueCredential(payload, organizationId = getOrganizationId()) {
  return apiRequest(`/organizations/${organizationId}/credentials`, {
    method: "POST",
    auth: true,
    body: payload,
  });
}

async function createCredentialArtifactUploadUrl(
  credentialId,
  payload,
  organizationId = getOrganizationId(),
) {
  return apiRequest(
    `/organizations/${organizationId}/credentials/${credentialId}/artifacts/upload-url`,
    { method: "POST", auth: true, body: payload },
  );
}

async function completeCredentialArtifactUpload(
  credentialId,
  artifactId,
  organizationId = getOrganizationId(),
) {
  return apiRequest(
    `/organizations/${organizationId}/credentials/${credentialId}/artifacts/${artifactId}/complete`,
    { method: "POST", auth: true },
  );
}

async function revokeOrganizationCredential(
  credentialId,
  payload,
  organizationId = getOrganizationId(),
) {
  return apiRequest(
    `/organizations/${organizationId}/credentials/${credentialId}/revoke`,
    { method: "PATCH", auth: true, body: payload },
  );
}

async function getOrganizationVerificationRequests(
  params = {},
  organizationId = getOrganizationId(),
) {
  return apiRequest(
    `/organizations/${organizationId}/verification-requests${qs(params)}`,
    { auth: true },
  );
}

async function getOrganizationVerificationRequest(
  requestId,
  organizationId = getOrganizationId(),
) {
  return apiRequest(
    `/organizations/${organizationId}/verification-requests/${requestId}`,
    { auth: true },
  );
}

async function reviewOrganizationVerificationRequest(
  requestId,
  payload,
  organizationId = getOrganizationId(),
) {
  return apiRequest(
    `/organizations/${organizationId}/verification-requests/${requestId}/review`,
    { method: "PATCH", auth: true, body: payload },
  );
}

async function getOrganizationRegistrationDocuments(
  organizationId = getOrganizationId(),
) {
  return apiRequest(
    `/organizations/${organizationId}/registration-documents`,
    { auth: true },
  );
}

async function createOrganizationRegistrationUploadUrl(
  payload,
  organizationId = getOrganizationId(),
) {
  return apiRequest(
    `/organizations/${organizationId}/registration-documents/upload-url`,
    { method: "POST", auth: true, body: payload },
  );
}

async function completeOrganizationRegistrationUpload(
  documentId,
  organizationId = getOrganizationId(),
) {
  return apiRequest(
    `/organizations/${organizationId}/registration-documents/${documentId}/complete`,
    { method: "POST", auth: true },
  );
}

async function deleteOrganizationRegistrationDocument(
  documentId,
  organizationId = getOrganizationId(),
) {
  return apiRequest(
    `/organizations/${organizationId}/registration-documents/${documentId}`,
    { method: "DELETE", auth: true },
  );
}

async function getOrganizationAuditLogs(
  params = {},
  organizationId = getOrganizationId(),
) {
  return apiRequest(
    `/organizations/${organizationId}/audit-logs${qs(params)}`,
    { auth: true },
  );
}

/* ===================== Admin ===================== */

async function getAdminDashboard() {
  return apiRequest("/admin/dashboard", { auth: true });
}

async function getAdminUsers(params = {}) {
  return apiRequest(`/admin/users${qs(params)}`, { auth: true });
}

async function getAdminUser(userId) {
  return apiRequest(`/admin/users/${userId}`, { auth: true });
}

async function updateAdminUserStatus(userId, payload) {
  return apiRequest(`/admin/users/${userId}/status`, {
    method: "PATCH",
    auth: true,
    body: payload,
  });
}

async function getAdminOrganizations(params = {}) {
  return apiRequest(`/admin/organizations${qs(params)}`, { auth: true });
}

async function reviewAdminOrganization(organizationId, payload) {
  return apiRequest(`/admin/organizations/${organizationId}/review`, {
    method: "PATCH",
    auth: true,
    body: payload,
  });
}

async function getAdminOrganizationRegistrationDocuments(organizationId) {
  return apiRequest(
    `/admin/organizations/${organizationId}/registration-documents`,
    { auth: true },
  );
}

async function reviewAdminOrganizationDocument(organizationId, documentId, payload) {
  return apiRequest(
    `/admin/organizations/${organizationId}/registration-documents/${documentId}/review`,
    { method: "PATCH", auth: true, body: payload },
  );
}

async function getAdminVerificationRequests(params = {}) {
  return apiRequest(`/admin/verification-requests${qs(params)}`, {
    auth: true,
  });
}

async function getAdminVerifications(params = {}) {
  return apiRequest(`/admin/verifications${qs(params)}`, { auth: true });
}

async function getAdminFraudAlerts(params = {}) {
  return apiRequest(`/admin/fraud-alerts${qs(params)}`, { auth: true });
}

async function getAdminFraudAlert(alertId) {
  return apiRequest(`/admin/fraud-alerts/${alertId}`, { auth: true });
}

async function updateAdminFraudAlertStatus(alertId, payload) {
  return apiRequest(`/admin/fraud-alerts/${alertId}/status`, {
    method: "PATCH",
    auth: true,
    body: payload,
  });
}

async function getAdminAuditLogs(params = {}) {
  return apiRequest(`/admin/audit-logs${qs(params)}`, { auth: true });
}

async function getAdminReportsSummary(params = {}) {
  return apiRequest(`/admin/reports/summary${qs(params)}`, { auth: true });
}

async function exportAdminReports(params = {}) {
  return apiRequest(`/admin/reports/export${qs(params)}`, { auth: true });
}

/* ===================== System ===================== */

async function getHealth() {
  return apiRequest("/health");
}

async function getReady() {
  return apiRequest("/ready");
}

function requireAuth(loginPath = "hero.html") {
  const session = getAuthSession();
  if (!session?.accessToken) {
    window.location.href = loginPath;
    return null;
  }
  return session;
}

function requireRole(roles, loginPath = "hero.html") {
  const session = requireAuth(loginPath);
  if (!session) return null;
  const allowed = Array.isArray(roles) ? roles : [roles];
  if (!allowed.includes(session.user?.role) && !session.organization) {
    redirectForRole(session.user?.role, session);
    return null;
  }
  return session;
}

window.VerifiedDocAuth = {
  API_BASE,
  UI_ROLE_TO_API,
  ROLE_REDIRECTS,
  getAuthSession,
  saveAuthSession,
  clearAuthSession,
  getOrganizationId,
  setOrganizationId,
  redirectForRole,
  registerAccount,
  loginAccount,
  logoutAccount,
  refreshSession,
  getValidAccessToken,
  isAccessTokenExpired,
  apiRequest,
  uploadToSignedUrl,
  getMe,
  updateMe,
  changePassword,
  requestPasswordReset,
  verifyPasswordResetOtp,
  confirmPasswordReset,
  getHolderDashboard,
  getHolderActivity,
  getHolderVerificationRequests,
  getHolderDocuments,
  createHolderDocumentUploadUrl,
  completeHolderDocumentUpload,
  deleteHolderDocument,
  uploadHolderDocument,
  getHolderCredentials,
  getCredential,
  getCredentialArtifacts,
  createShareLink,
  revokeShareLink,
  getNotifications,
  markNotificationRead,
  markAllNotificationsRead,
  publicVerify,
  getVerifierDashboard,
  performVerification,
  getVerifierVerification,
  createVerifierVerificationRequest,
  getVerifierVerificationRequest,
  cancelVerifierVerificationRequest,
  createFileVerificationUploadUrl,
  completeFileVerification,
  getSavedOrganizations,
  saveOrganization,
  unsaveOrganization,
  applyOrganization,
  getOrganization,
  getOrganizationDashboard,
  getOrganizationMembers,
  updateOrganizationMember,
  createOrganizationInvitation,
  revokeOrganizationInvitation,
  acceptInvitation,
  getOrganizationRecipients,
  getRecipientInvitations,
  createRecipientInvitation,
  revokeRecipientInvitation,
  acceptRecipientInvitation,
  issueCredential,
  createCredentialArtifactUploadUrl,
  completeCredentialArtifactUpload,
  revokeOrganizationCredential,
  getOrganizationVerificationRequests,
  getOrganizationVerificationRequest,
  reviewOrganizationVerificationRequest,
  getOrganizationRegistrationDocuments,
  createOrganizationRegistrationUploadUrl,
  completeOrganizationRegistrationUpload,
  deleteOrganizationRegistrationDocument,
  getOrganizationAuditLogs,
  getAdminDashboard,
  getAdminUsers,
  getAdminUser,
  updateAdminUserStatus,
  getAdminOrganizations,
  reviewAdminOrganization,
  getAdminOrganizationRegistrationDocuments,
  reviewAdminOrganizationDocument,
  getAdminVerificationRequests,
  getAdminVerifications,
  getAdminFraudAlerts,
  getAdminFraudAlert,
  updateAdminFraudAlertStatus,
  getAdminAuditLogs,
  getAdminReportsSummary,
  exportAdminReports,
  getHealth,
  getReady,
  requireAuth,
  requireRole,
};
