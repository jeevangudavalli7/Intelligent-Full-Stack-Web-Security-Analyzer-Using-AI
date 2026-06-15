// frontend/src/context/AuthContext.jsx  — NEW FILE (create it)
import React, { createContext, useContext, useState } from 'react';

const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(() => {
    try { return JSON.parse(sessionStorage.getItem('sa_user')); } catch { return null; }
  });
  const [token, setToken] = useState(() => sessionStorage.getItem('sa_token') || null);

  const login = (userData, accessToken) => {
    setUser(userData);
    setToken(accessToken);
    sessionStorage.setItem('sa_user', JSON.stringify(userData));
    sessionStorage.setItem('sa_token', accessToken);
  };

  const logout = () => {
    setUser(null); setToken(null);
    sessionStorage.removeItem('sa_user');
    sessionStorage.removeItem('sa_token');
  };

  return (
    <AuthContext.Provider value={{ user, token, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);