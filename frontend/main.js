        const API_URL = 'http://127.0.0.1:5000/api';

        // DOM Elements
        const loginForm = document.getElementById('loginForm');
        const messageDiv = document.getElementById('message');
        const statusDiv = document.getElementById('status');
        const userInfoDiv = document.getElementById('userInfo');
        const userDataPre = document.getElementById('userData');
        const getMeBtn = document.getElementById('getMeBtn');
        const refreshBtn = document.getElementById('refreshBtn');
        const logoutBtn = document.getElementById('logoutBtn');

        // Helper Functions
        function showMessage(msg, isError = false) {
            messageDiv.textContent = msg;
            messageDiv.className = isError ? 'error' : 'success';
            messageDiv.style.display = 'block';
            
            setTimeout(() => {
                messageDiv.style.display = 'none';
            }, 5000);
        }

        function updateStatus(msg) {
            statusDiv.textContent = `Status: ${msg}`;
        }

        function showUserInfo(user) {
            userDataPre.textContent = JSON.stringify(user, null, 2);
            userInfoDiv.style.display = 'block';
            updateStatus('Logged in');
        }

        function hideUserInfo() {
            userInfoDiv.style.display = 'none';
            updateStatus('Not logged in');
        }

        // ============================================
        // 1. HANDLE LOGIN
        // ============================================
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;

            try {
                const response = await fetch(`${API_URL}/users/login`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password })
                });

                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.message || 'Login failed');
                }

                const { token, refreshToken } = data;

                // Store both tokens
                localStorage.setItem('accessToken', token);
                localStorage.setItem('refreshToken', refreshToken);

                showMessage('✓ Login successful! Refresh token stored in DB.');
                await getUserInfo();

            } catch (error) {
                showMessage(error.message, true);
            }
        });

        // ============================================
        // 2. GET USER INFO
        // ============================================
        async function getUserInfo() {
            try {
                const token = localStorage.getItem('accessToken');
                
                if (!token) {
                    throw new Error('No access token found');
                }

                const response = await fetch(`${API_URL}/users/me`, {
                    headers: { 'Authorization': `Bearer ${token}` }
                });

                const data = await response.json();

                if (!response.ok) {
                    if (response.status === 401) {
                        showMessage('Access token expired, refreshing...', true);
                        await refreshAccessToken();
                        return await getUserInfo();
                    }
                    throw new Error(data.message || 'Failed to fetch user info');
                }

                showUserInfo(data.user);
                showMessage('✓ User info fetched successfully!');

            } catch (error) {
                showMessage(error.message, true);
            }
        }

        // ============================================
        // 3. REFRESH ACCESS TOKEN
        // ============================================
        async function refreshAccessToken() {
            try {
                const refreshToken = localStorage.getItem('refreshToken');
                
                if (!refreshToken) {
                    throw new Error('No refresh token found');
                }

                const response = await fetch(`${API_URL}/users/refresh`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ refreshToken })
                });

                const data = await response.json();

                if (!response.ok) {
                    // 🔥 If refresh fails, user is logged out everywhere
                    throw new Error(data.error || 'Refresh token invalid - logged out from all devices');
                }

                const { token: newAccessToken } = data;
                localStorage.setItem('accessToken', newAccessToken);
                
                showMessage('✓ Token refreshed successfully!');

            } catch (error) {
                showMessage(error.message + ' - Please login again', true);
                logout(false); // Don't call backend since token is already invalid
            }
        }

        // ============================================
        // 4. 🔥 DAY-4: LOGOUT (CLEARS DB TOKEN)
        // ============================================
        async function logout(callBackend = true) {
            try {
                if (callBackend) {
                    const refreshToken = localStorage.getItem('refreshToken');
                    
                    if (refreshToken) {
                        const response = await fetch(`${API_URL}/users/logout`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ refreshToken })
                        });

                        const data = await response.json();

                        if (response.ok) {
                            showMessage('✓ Logged out from ALL devices successfully!');
                        }
                    }
                }
                
                // Clear local storage
                localStorage.removeItem('accessToken');
                localStorage.removeItem('refreshToken');
                hideUserInfo();
                loginForm.reset();
                
                if (!callBackend) {
                    showMessage('✓ Logged out locally');
                }

            } catch (error) {
                // Even if backend call fails, clear local tokens
                localStorage.removeItem('accessToken');
                localStorage.removeItem('refreshToken');
                hideUserInfo();
                showMessage('Logged out (backend error: ' + error.message + ')', true);
            }
        }

        // ============================================
        // EVENT LISTENERS
        // ============================================
        getMeBtn.addEventListener('click', getUserInfo);
        refreshBtn.addEventListener('click', refreshAccessToken);
        logoutBtn.addEventListener('click', () => logout(true));

        // Check if already logged in on page load
        window.addEventListener('DOMContentLoaded', () => {
            const token = localStorage.getItem('accessToken');
            const refreshToken = localStorage.getItem('refreshToken');
            
            if (token && refreshToken) {
                updateStatus('Checking session...');
                getUserInfo();
            }
        });