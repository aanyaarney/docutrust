import axios, { AxiosError } from 'axios';
import type {
  AuditRecord,
  ApiErrorBody,
  DashboardSummary,
  DocumentSummary,
  DocumentVersion,
  LoginResponse,
  SignResponse,
  SignatureRecord,
  VerificationReport,
} from './types';

const TOKEN_STORAGE_KEY = 'docutrust.token';

export const api = axios.create({
  baseURL: '/api/v1',
  timeout: 60_000,
});

/**
 * Token storage.
 *
 * `localStorage` is used for the demonstration. The honest trade-off: a token
 * in localStorage is readable by any script running on the page, so a
 * cross-site scripting flaw would expose it. An httpOnly cookie is not
 * reachable from JavaScript and is the stronger choice, but brings CSRF back
 * into scope and needs matching backend work (see SecurityConfiguration).
 *
 * This is documented rather than glossed over because "where does the token
 * live" is a question worth being able to answer precisely.
 */
export const tokenStorage = {
  get: (): string | null => {
    try {
      return localStorage.getItem(TOKEN_STORAGE_KEY);
    } catch {
      return null;
    }
  },
  set: (token: string): void => {
    try {
      localStorage.setItem(TOKEN_STORAGE_KEY, token);
    } catch {
      // Private browsing can refuse storage; the session still works in memory.
    }
  },
  clear: (): void => {
    try {
      localStorage.removeItem(TOKEN_STORAGE_KEY);
    } catch {
      // Nothing useful to do.
    }
  },
};

api.interceptors.request.use((config) => {
  const token = tokenStorage.get();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

/**
 * Ends the session when the server says the caller is not authenticated.
 *
 * A 401 means the token is absent, expired or invalid, and no amount of
 * retrying will help — the only useful response is to sign in again. Without
 * this the user sees an opaque error on every screen until they manually clear
 * storage.
 *
 * A 403 is deliberately *not* treated this way: it means authenticated but not
 * permitted, so signing in again would change nothing and bouncing the user to
 * the login screen would be misleading.
 *
 * The login request itself is excluded, since a 401 there is simply wrong
 * credentials and the login page handles it.
 */
api.interceptors.response.use(
  (response) => response,
  (error: unknown) => {
    if (error instanceof AxiosError) {
      const status = error.response?.status;
      const url = error.config?.url ?? '';

      if (status === 401 && !url.includes('/auth/login')) {
        tokenStorage.clear();
        try {
          localStorage.removeItem('docutrust.profile');
        } catch {
          // Nothing useful to do.
        }
        if (window.location.pathname !== '/login') {
          window.location.assign('/login');
        }
      }
    }
    return Promise.reject(error);
  },
);

/** Extracts a displayable message from an API error without leaking internals. */
export function describeError(error: unknown): string {
  if (error instanceof AxiosError) {
    const body = error.response?.data as ApiErrorBody | undefined;
    if (body?.message) {
      return body.correlationId ? `${body.message} (reference ${body.correlationId})` : body.message;
    }
    if (error.code === 'ECONNABORTED') {
      return 'The request timed out. The document may be large, or the server may be busy.';
    }
    if (!error.response) {
      return 'Could not reach the DocuTrust server. Check that the backend is running.';
    }
    return `Request failed with status ${error.response.status}.`;
  }
  return 'An unexpected error occurred.';
}

// ------------------------------------------------------------------ endpoints

export const authApi = {
  login: async (email: string, password: string): Promise<LoginResponse> => {
    const { data } = await api.post<LoginResponse>('/auth/login', { email, password });
    return data;
  },
};

export const documentsApi = {
  list: async (): Promise<DocumentSummary[]> => {
    const { data } = await api.get<DocumentSummary[]>('/documents');
    return data;
  },

  get: async (id: string): Promise<DocumentSummary> => {
    const { data } = await api.get<DocumentSummary>(`/documents/${id}`);
    return data;
  },

  upload: async (file: File): Promise<DocumentSummary> => {
    const form = new FormData();
    form.append('file', file);
    const { data } = await api.post<DocumentSummary>('/documents', form);
    return data;
  },

  sign: async (
    id: string,
    payload: {
      reason?: string;
      location?: string;
      signerDisplayName?: string;
      /** Draws an informational appearance block; adds nothing cryptographically. */
      visibleSignature?: boolean;
    },
  ): Promise<SignResponse> => {
    const { data } = await api.post<SignResponse>(`/documents/${id}/sign`, payload);
    return data;
  },

  versions: async (id: string): Promise<DocumentVersion[]> => {
    const { data } = await api.get<DocumentVersion[]>(`/documents/${id}/versions`);
    return data;
  },

  signatures: async (id: string): Promise<SignatureRecord[]> => {
    const { data } = await api.get<SignatureRecord[]>(`/documents/${id}/signatures`);
    return data;
  },

  audit: async (id: string): Promise<AuditRecord[]> => {
    const { data } = await api.get<AuditRecord[]>(`/documents/${id}/audit`);
    return data;
  },

  /** Downloads a version and hands the browser a blob to save. */
  download: async (id: string, fileName: string): Promise<void> => {
    const response = await api.get(`/documents/${id}/download`, { responseType: 'blob' });
    const url = URL.createObjectURL(response.data as Blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = fileName;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  },
};

export const verificationApi = {
  verify: async (file: File, documentId?: string): Promise<VerificationReport> => {
    const form = new FormData();
    form.append('file', file);
    if (documentId) {
      form.append('documentId', documentId);
    }
    const { data } = await api.post<VerificationReport>('/verification', form);
    return data;
  },
  /**
   * Downloads a stored verification report.
   *
   * <p>Fetched through axios rather than opened as a plain link so the bearer
   * token is attached — the endpoint is authenticated, and a bare anchor would
   * send no credentials and get a 401.
   */
  downloadReport: async (verificationId: string, format: 'html' | 'json'): Promise<void> => {
    const response = await api.get(`/verification/${verificationId}/report`, {
      params: { format },
      responseType: 'blob',
    });

    const url = URL.createObjectURL(response.data as Blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `docutrust-report-${verificationId}.${format}`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  },
};

export const dashboardApi = {
  summary: async (): Promise<DashboardSummary> => {
    const { data } = await api.get<DashboardSummary>('/dashboard/summary');
    return data;
  },
};
