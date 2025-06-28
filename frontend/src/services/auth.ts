import axios from 'axios';

const API_URL = 'http://localhost:5001/api';

export interface User {
  id: number;
  username: string;
  is_admin: boolean;
  created_at: string;
  last_login: string;
}

export interface AuthResponse {
  access_token: string;
  user: {
    id: number;
    username: string;
    is_admin: boolean;
  };
}

class AuthService {
  private static instance: AuthService;
  private token: string | null = null;
  private user: User | null = null;
  private authStateListeners: Set<() => void> = new Set();

  private constructor() {
    // Load token and user from localStorage
    this.token = localStorage.getItem('token');
    const userStr = localStorage.getItem('user');
    if (userStr) {
      try {
        this.user = JSON.parse(userStr);
      } catch (e) {
        console.error('Failed to parse user from localStorage:', e);
      }
    }
  }

  static getInstance(): AuthService {
    if (!AuthService.instance) {
      AuthService.instance = new AuthService();
    }
    return AuthService.instance;
  }

  onAuthStateChange(callback: () => void): () => void {
    this.authStateListeners.add(callback);
    return () => {
      this.authStateListeners.delete(callback);
    };
  }

  private notifyAuthStateChange(): void {
    this.authStateListeners.forEach(callback => callback());
  }

  async login(username: string, password: string): Promise<boolean> {
    try {
      console.log('Attempting login with:', { username });
      const response = await axios.post<AuthResponse>(`${API_URL}/auth/login`, {
        username,
        password
      });

      console.log('Login response:', response.data);

      if (response.data && response.data.access_token && response.data.user) {
        console.log('Login successful, setting token and user');
        this.token = response.data.access_token;
        this.user = {
          id: response.data.user.id,
          username: response.data.user.username,
          is_admin: response.data.user.is_admin,
          created_at: '',  // These fields are optional now
          last_login: ''
        };
        
        localStorage.setItem('token', this.token);
        localStorage.setItem('user', JSON.stringify(this.user));
        this.notifyAuthStateChange();
        
        return true;
      }
      console.log('Login failed: invalid response format');
      return false;
    } catch (error: any) {
      console.error('Login failed:', error.response?.data || error);
      this.token = null;
      this.user = null;
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      this.notifyAuthStateChange();
      return false;
    }
  }

  logout(): void {
    this.token = null;
    this.user = null;
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    this.notifyAuthStateChange();
  }

  getToken(): string | null {
    return this.token;
  }

  getUser(): User | null {
    if (!this.user && localStorage.getItem('user')) {
      this.user = JSON.parse(localStorage.getItem('user')!);
    }
    return this.user;
  }

  isAuthenticated(): boolean {
    return !!this.getToken();
  }

  getAuthHeader() {
    return this.token ? { Authorization: `Bearer ${this.token}` } : {};
  }
}

export default AuthService.getInstance();
