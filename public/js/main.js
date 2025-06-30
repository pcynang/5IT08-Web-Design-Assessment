// Main JavaScript for the Simple User Profile Portal

// DOM Elements
const loginForm = document.getElementById('loginForm');
const registerForm = document.getElementById('registerForm');
const searchForm = document.getElementById('searchForm');
const profileForm = document.getElementById('profileForm');
const settingsForm = document.getElementById('settingsForm');
const logoutBtn = document.getElementById('logoutBtn');
const searchBtn = document.getElementById('searchBtn');
const editProfileBtn = document.getElementById('editProfileBtn');
const cancelEditBtn = document.getElementById('cancelEditBtn');
const saveSettingsBtn = document.getElementById('saveSettingsBtn');
const themeRadios = document.querySelectorAll('.theme-radio');
const menuPreferences = document.querySelectorAll('.menu-preference');

// Current page state
let currentUser = null;

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    // Check if user is logged in
    checkAuthStatus();
    
    // Initialize forms if they exist on the current page
    if (loginForm) initLoginForm();
    if (registerForm) initRegisterForm();
    if (searchBtn) initSearch();
    if (editProfileBtn) initProfile();
    if (saveSettingsBtn) initSettings();
    if (logoutBtn) initLogout();
    
    // Initialize page navigation
    initNavigation();
    
    // Apply saved theme if any
    applySavedTheme();
    
    // Apply saved menu preferences
    applySavedMenuPreferences();
});

// Check authentication status
async function checkAuthStatus() {
    try {
        // Check if we have a user in sessionStorage first (for immediate UI update)
        const storedUser = sessionStorage.getItem('currentUser');
        if (storedUser) {
            try {
                currentUser = JSON.parse(storedUser);
                updateUIForLoggedInUser();
            } catch (e) {
                console.error('Failed to parse stored user:', e);
                sessionStorage.removeItem('currentUser');
            }
        }

        // Then verify with the server
        const response = await fetch('/api/check-auth', {
            method: 'GET',
            credentials: 'same-origin',
            headers: {
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0'
            }
        });
        
        if (response.ok) {
            const data = await response.json();
            
            if (data.authenticated && data.user) {
                currentUser = data.user;
                // Store in sessionStorage for immediate access
                sessionStorage.setItem('currentUser', JSON.stringify(data.user));
                updateUIForLoggedInUser();
                
                // If we're on the login page but already authenticated, redirect to dashboard
                if (window.location.pathname === '/login') {
                    window.location.href = '/dashboard';
                }
            } else if (window.location.pathname === '/dashboard') {
                // If not authenticated but on dashboard, redirect to login
                window.location.href = '/login';
            }
        } else if (window.location.pathname === '/dashboard') {
            // If auth check fails on dashboard, redirect to login
            window.location.href = '/login';
        }
    } catch (error) {
        console.error('Auth check failed:', error);
        if (window.location.pathname === '/dashboard') {
            window.location.href = '/login';
        }
    }
}

// Initialize login form
function initLoginForm() {
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;
        
        // Basic client-side validation
        if (!username || !password) {
            showError('Please enter both username and password');
            return;
        }
        
        // Show loading state
        const submitBtn = loginForm.querySelector('button[type="submit"]');
        const originalBtnText = submitBtn.innerHTML;
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Signing in...';
        
        try {
            console.log('Attempting login with username:', username);
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Cache-Control': 'no-cache',
                    'Pragma': 'no-cache'
                },
                body: JSON.stringify({ username, password }),
                credentials: 'include', // Important for sessions to work
                cache: 'no-store'
            });
            
            const data = await response.json();
            console.log('Login response:', { status: response.status, data });
            
            if (response.ok && data.success) {
                console.log('Login successful, updating UI...', data);
                
                // Store user data in sessionStorage for immediate access
                if (data.user) {
                    currentUser = data.user;
                    sessionStorage.setItem('currentUser', JSON.stringify(data.user));
                    
                    // Update UI before redirect
                    updateUIForLoggedInUser();
                    
                    // Show success message
                    showSuccess('Login successful! Redirecting...');
                    
                    // Redirect after a short delay to show the success message
                    setTimeout(() => {
                        console.log('Redirecting to dashboard...');
                        window.location.href = '/dashboard';
                    }, 500);
                } else {
                    throw new Error('No user data in response');
                }
            } else {
                const errorMessage = data.error || 'Login failed. Please check your credentials.';
                console.error('Login failed:', errorMessage);
                showError(errorMessage);
                submitBtn.disabled = false;
                submitBtn.innerHTML = originalBtnText;
            }
        } catch (error) {
            console.error('Login error:', error);
            showError('An error occurred during login. Please try again.');
            submitBtn.disabled = false;
            submitBtn.innerHTML = originalBtnText;
        }
    });
}

// Initialize registration form
function initRegisterForm() {
    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const formData = {
            username: document.getElementById('username').value.trim(),
            email: document.getElementById('email').value.trim(),
            password: document.getElementById('password').value,
            confirmPassword: document.getElementById('confirmPassword').value,
            firstName: document.getElementById('firstName').value.trim(),
            lastName: document.getElementById('lastName').value.trim()
        };
        
        // Client-side validation
        const errors = [];
        
        if (!formData.username || formData.username.length < 4) {
            errors.push('Username must be at least 4 characters long');
        }
        
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
            errors.push('Please enter a valid email address');
        }
        
        if (formData.password.length < 8 || !/\d/.test(formData.password) || !/[A-Za-z]/.test(formData.password)) {
            errors.push('Password must be at least 8 characters long and contain both letters and numbers');
        }
        
        if (formData.password !== formData.confirmPassword) {
            errors.push('Passwords do not match');
        }
        
        if (!formData.firstName) {
            errors.push('First name is required');
        }
        
        if (!formData.lastName) {
            errors.push('Last name is required');
        }
        
        if (errors.length > 0) {
            showError(errors.join('<br>'));
            return;
        }
        
        try {
            const response = await fetch('/api/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username: formData.username,
                    email: formData.email,
                    password: formData.password,
                    firstName: formData.firstName,
                    lastName: formData.lastName
                })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                // Clear any existing error messages
                const errorAlert = document.getElementById('errorAlert');
                if (errorAlert) {
                    errorAlert.remove();
                }
                
                // Show success and redirect
                showSuccess('Registration successful! Redirecting to login...');
                setTimeout(() => {
                    window.location.href = '/login';
                }, 2000);
            } else {
                showError(data.error || 'Registration failed. Please try again.');
            }
        } catch (error) {
            console.error('Registration error:', error);
            showError('An error occurred during registration. Please try again.');
        }
    });
}

// Initialize search functionality
function initSearch() {
    // Handle form submission for search
    const searchForm = document.getElementById('searchForm');
    if (searchForm) {
        searchForm.addEventListener('submit', handleSearch);
    }
    
    // Also handle button click for backward compatibility
    if (searchBtn) {
        searchBtn.addEventListener('click', handleSearch);
    }
}

// Handle search form submission
async function handleSearch(e) {
    if (e) e.preventDefault();
    
    const idNumber = document.getElementById('searchId')?.value?.trim();
    const resultsDiv = document.getElementById('searchResults');
    const searchBtn = document.getElementById('searchBtn');
    
    // Validate input
    if (!idNumber) {
        showError('Please enter an ID number');
        return;
    }
    
    // Validate ID format (numbers only)
    if (!/^\d+$/.test(idNumber)) {
        showError('Please enter a valid ID number (numbers only)');
        return;
    }
    
    try {
        // Show loading state
        if (searchBtn) {
            const originalBtnText = searchBtn.innerHTML;
            searchBtn.disabled = true;
            searchBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Searching...';
            
            // Clear previous results and errors
            if (resultsDiv) resultsDiv.innerHTML = '';
            
            try {
                const response = await fetch(`/api/personal-info/${idNumber}`, {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    },
                    credentials: 'same-origin' // Include cookies for session
                });
                
                const data = await response.json();
                
                if (resultsDiv) {
                    if (response.ok && data.success && data.data) {
                        // Display the personal information
                        const personalInfo = data.data.personalInfo;
                        resultsDiv.innerHTML = `
                            <div class="card mb-4">
                                <div class="card-header bg-primary text-white">
                                    <h5 class="card-title mb-0">Personal Information</h5>
                                </div>
                                <div class="card-body">
                                    <div class="row">
                                        <div class="col-md-6">
                                            <h6 class="text-muted">Basic Information</h6>
                                            <dl class="mb-0">
                                                <dt>Full Name</dt>
                                                <dd class="mb-2">${personalInfo.fullName || 'N/A'}</dd>
                                                
                                                <dt>Date of Birth</dt>
                                                <dd class="mb-2">${personalInfo.dateOfBirth ? formatDate(personalInfo.dateOfBirth) : 'N/A'}</dd>
                                                
                                                <dt>Blood Type</dt>
                                                <dd class="mb-2">${personalInfo.bloodType || 'N/A'}</dd>
                                            </dl>
                                        </div>
                                        <div class="col-md-6">
                                            <h6 class="text-muted">Contact Information</h6>
                                            <dl class="mb-0">
                                                <dt>Address</dt>
                                                <dd class="mb-2">${personalInfo.address || 'N/A'}</dd>
                                                
                                                <dt>Phone</dt>
                                                <dd class="mb-2">${personalInfo.phone || 'N/A'}</dd>
                                                
                                                <dt>Email</dt>
                                                <dd class="mb-2">${personalInfo.email || 'N/A'}</dd>
                                                
                                                <dt>Emergency Contact</dt>
                                                <dd class="mb-2">${personalInfo.emergencyContact || 'N/A'}</dd>
                                            </dl>
                                        </div>
                                    </div>
                                    
                                    ${personalInfo.medicalConditions || personalInfo.allergies || personalInfo.medications ? `
                                    <div class="row mt-4">
                                        ${personalInfo.medicalConditions ? `
                                        <div class="col-md-4">
                                            <h6 class="text-muted">Medical Conditions</h6>
                                            <ul class="list-unstyled">
                                                ${Array.isArray(personalInfo.medicalConditions) 
                                                    ? personalInfo.medicalConditions.map(condition => 
                                                        `<li class="mb-1"><i class="fas fa-chevron-right me-2 text-primary"></i>${condition}</li>`
                                                      ).join('')
                                                    : `<li class="mb-1"><i class="fas fa-chevron-right me-2 text-primary"></i>${personalInfo.medicalConditions}</li>`
                                                }
                                            </ul>
                                        </div>` : ''}
                                        
                                        ${personalInfo.allergies ? `
                                        <div class="col-md-4">
                                            <h6 class="text-muted">Allergies</h6>
                                            <ul class="list-unstyled">
                                                ${Array.isArray(personalInfo.allergies)
                                                    ? personalInfo.allergies.map(allergy => 
                                                        `<li class="mb-1"><i class="fas fa-allergies me-2 text-warning"></i>${allergy}</li>`
                                                      ).join('')
                                                    : `<li class="mb-1"><i class="fas fa-allergies me-2 text-warning"></i>${personalInfo.allergies}</li>`
                                                }
                                            </ul>
                                        </div>` : ''}
                                        
                                        ${personalInfo.medications ? `
                                        <div class="col-md-4">
                                            <h6 class="text-muted">Medications</h6>
                                            <ul class="list-unstyled">
                                                ${Array.isArray(personalInfo.medications)
                                                    ? personalInfo.medications.map(med => 
                                                        `<li class="mb-1"><i class="fas fa-pills me-2 text-info"></i>${med}</li>`
                                                      ).join('')
                                                    : `<li class="mb-1"><i class="fas fa-pills me-2 text-info"></i>${personalInfo.medications}</li>`
                                                }
                                            </ul>
                                        </div>` : ''}
                                    </div>` : ''}
                                </div>
                                <div class="card-footer text-muted small">
                                    Last updated: ${new Date().toLocaleString()}
                                </div>
                            </div>
                        `;
                        
                        // Scroll to results
                        resultsDiv.scrollIntoView({ behavior: 'smooth' });
                        
                    } else {
                        showError(data.error || data.message || 'No record found for the provided ID');
                        resultsDiv.innerHTML = `
                            <div class="alert alert-warning" role="alert">
                                <i class="fas fa-exclamation-triangle me-2"></i>
                                No records found for ID: ${idNumber}
                            </div>
                        `;
                    }
                }
            } catch (error) {
                console.error('Search error:', error);
                showError('An error occurred while searching. Please try again.');
                
                if (resultsDiv) {
                    resultsDiv.innerHTML = `
                        <div class="alert alert-danger" role="alert">
                            <i class="fas fa-exclamation-circle me-2"></i>
                            An error occurred while searching. Please try again later.
                        </div>
                    `;
                }
            } finally {
                // Restore button state
                if (searchBtn) {
                    searchBtn.disabled = false;
                    searchBtn.innerHTML = originalBtnText;
                }
            }
        }
    } catch (error) {
        console.error('Error in search handler:', error);
        showError('An unexpected error occurred. Please try again.');
        
        if (resultsDiv) {
            resultsDiv.innerHTML = `
                <div class="alert alert-danger" role="alert">
                    <i class="fas fa-exclamation-circle me-2"></i>
                    An unexpected error occurred. Please refresh the page and try again.
                </div>
            `;
        }
    }
}

// Initialize profile functionality
function initProfile() {
    // Load user data
    if (currentUser) {
        document.getElementById('profileFirstName').value = currentUser.firstName || '';
        document.getElementById('profileLastName').value = currentUser.lastName || '';
        document.getElementById('profileUsername').value = currentUser.username || '';
        document.getElementById('profileEmail').value = currentUser.email || '';
    }
    
    // Toggle edit mode
    editProfileBtn.addEventListener('click', (e) => {
        e.preventDefault();
        
        // Enable form fields
        const inputs = profileForm.querySelectorAll('input');
        inputs.forEach(input => {
            if (input.id !== 'profileUsername') { // Don't allow editing username
                input.removeAttribute('disabled');
            }
        });
        
        // Show save/cancel buttons
        document.getElementById('profileFormActions').classList.remove('d-none');
        
        // Hide edit button
        editProfileBtn.classList.add('d-none');
    });
    
    // Cancel edit
    cancelEditBtn.addEventListener('click', (e) => {
        e.preventDefault();
        resetProfileForm();
    });
    
    // Save profile changes
    profileForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const updatedData = {
            firstName: document.getElementById('profileFirstName').value.trim(),
            lastName: document.getElementById('profileLastName').value.trim(),
            email: document.getElementById('profileEmail').value.trim()
        };
        
        // Basic validation
        if (!updatedData.firstName || !updatedData.lastName || !updatedData.email) {
            showError('All fields are required');
            return;
        }
        
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(updatedData.email)) {
            showError('Please enter a valid email address');
            return;
        }
        
        try {
            const response = await fetch('/api/user/profile', {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(updatedData)
            });
            
            const data = await response.json();
            
            if (response.ok) {
                // Update current user data
                Object.assign(currentUser, updatedData);
                
                // Update UI
                updateUserGreeting();
                resetProfileForm();
                
                showSuccess('Profile updated successfully');
            } else {
                showError(data.error || 'Failed to update profile');
            }
        } catch (error) {
            console.error('Profile update error:', error);
            showError('An error occurred while updating your profile');
        }
    });
}

// Reset profile form to view mode
function resetProfileForm() {
    // Disable all inputs
    const inputs = profileForm.querySelectorAll('input');
    inputs.forEach(input => input.setAttribute('disabled', true));
    
    // Hide save/cancel buttons
    document.getElementById('profileFormActions').classList.add('d-none');
    
    // Show edit button
    editProfileBtn.classList.remove('d-none');
    
    // Reset form to current user data
    if (currentUser) {
        document.getElementById('profileFirstName').value = currentUser.firstName || '';
        document.getElementById('profileLastName').value = currentUser.lastName || '';
        document.getElementById('profileEmail').value = currentUser.email || '';
    }
}

function initSettings() {
    if (currentUser && currentUser.theme) {
        document.querySelector(`input[name="theme"][value="${currentUser.theme}"]`).checked = true;
    }
    
    if (currentUser && currentUser.menuPreferences) {
        try {
            const prefs = typeof currentUser.menuPreferences === 'string' 
                ? JSON.parse(currentUser.menuPreferences) 
                : currentUser.menuPreferences;
                
            menuPreferences.forEach(checkbox => {
                checkbox.checked = prefs[checkbox.value] !== false; // Default to true if not set
            });
        } catch (error) {
            console.error('Error parsing menu preferences:', error);
        }
    }
    
    saveSettingsBtn.addEventListener('click', async () => {
        const theme = document.querySelector('input[name="theme"]:checked')?.value || '';
        
        const menuPrefs = {};
        menuPreferences.forEach(checkbox => {
            menuPrefs[checkbox.value] = checkbox.checked;
        });
        
        try {
            const response = await fetch('/api/user/preferences', {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    theme,
                    menuPreferences: menuPrefs
                })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                if (currentUser) {
                    currentUser.theme = theme;
                    currentUser.menuPreferences = menuPrefs;
                }
                
                applyTheme(theme);
                applyMenuPreferences(menuPrefs);
                
                showSuccess('Settings saved successfully');
            } else {
                showError(data.error || 'Failed to save settings');
            }
        } catch (error) {
            console.error('Save settings error:', error);
            showError('An error occurred while saving settings');
        }
    });
    
    document.querySelectorAll('.theme-option').forEach(option => {
        option.addEventListener('click', (e) => {
            e.preventDefault();
            const theme = option.getAttribute('data-theme') || '';
            applyTheme(theme);
        });
    });
}

function initLogout() {
    logoutBtn.addEventListener('click', async (e) => {
        e.preventDefault();
        
        try {
            const response = await fetch('/api/logout', {
                method: 'POST'
            });
            
            if (response.ok) {
                localStorage.removeItem('theme');
                localStorage.removeItem('menuPreferences');
                
                window.location.href = '/login';
            } else {
                const data = await response.json();
                showError(data.error || 'Failed to log out');
            }
        } catch (error) {
            console.error('Logout error:', error);
            showError('An error occurred while logging out');
        }
    });
}

function initNavigation() {
    document.querySelectorAll('[data-page]').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const page = link.getAttribute('data-page');
            showPage(page);
        });
    });
}

function showPage(page) {
    document.querySelectorAll('.page-content').forEach(el => {
        el.classList.add('d-none');
    });
    
    const pageElement = document.getElementById(`${page}Content`);
    if (pageElement) {
        pageElement.classList.remove('d-none');
    }
    
    document.querySelectorAll('.nav-link').forEach(navLink => {
        if (navLink.getAttribute('data-page') === page) {
            navLink.classList.add('active');
            navLink.setAttribute('aria-current', 'page');
        } else {
            navLink.classList.remove('active');
            navLink.removeAttribute('aria-current');
        }
    });
    
    if (history.pushState) {
        history.pushState(null, null, `#${page}`);
    }
}

function applyTheme(theme) {
    const themeLink = document.getElementById('theme-override');
    
    if (!themeLink) return;
    
    if (theme === 'dark') {
        themeLink.href = '/css/theme-dark.css';
    } else if (theme === 'blue') {
        themeLink.href = '/css/theme-blue.css';
    } else {
        themeLink.href = '';
    }

    localStorage.setItem('theme', theme);
    
    const themeRadios = document.querySelectorAll('.theme-radio');
    if (themeRadios.length > 0) {
        themeRadios.forEach(radio => {
            radio.checked = radio.value === theme;
        });
    }
}

function applySavedTheme() {
    if (!document.getElementById('theme-override')) return;
    
    const savedTheme = localStorage.getItem('theme') || '';
    if (savedTheme) {
        applyTheme(savedTheme);
    }
}

function applyMenuPreferences(prefs) {
    if (!prefs && currentUser?.menuPreferences) {
        prefs = typeof currentUser.menuPreferences === 'string'
            ? JSON.parse(currentUser.menuPreferences)
            : currentUser.menuPreferences;
    }
    
    if (prefs) {
        Object.entries(prefs).forEach(([key, visible]) => {
            const menuItem = document.querySelector(`[data-menu-item="${key}"]`);
            if (menuItem) {
                menuItem.style.display = visible ? 'block' : 'none';
            }
        });
        
        localStorage.setItem('menuPreferences', JSON.stringify(prefs));
    }
}

function applySavedMenuPreferences() {
    const savedPrefs = localStorage.getItem('menuPreferences');
    if (savedPrefs) {
        try {
            const prefs = JSON.parse(savedPrefs);
            applyMenuPreferences(prefs);
        } catch (error) {
            console.error('Error parsing saved menu preferences:', error);
        }
    }
}

function updateUIForLoggedInUser() {
    if (!currentUser) return;
    
    updateUserGreeting();
    
    if (currentUser.theme) {
        applyTheme(currentUser.theme);
    }
    
    if (currentUser.menuPreferences) {
        applyMenuPreferences();
    }
    
    const hash = window.location.hash.substring(1);
    const defaultPage = ['dashboard', 'profile', 'search', 'settings'].includes(hash) ? hash : 'dashboard';
    showPage(defaultPage);
}
function updateUserGreeting() {
    const greetingElement = document.getElementById('userGreeting');
    const fullNameElement = document.getElementById('userFullName');
    
    if (currentUser) {
        const name = [currentUser.firstName, currentUser.lastName].filter(Boolean).join(' ') || currentUser.username;
        
        if (greetingElement) {
            greetingElement.textContent = `Hello, ${name}`;
        }
        
        if (fullNameElement) {
            fullNameElement.textContent = name;
        }
    }
}

function showError(message) {
    // Remove any existing error alerts
    const existingAlerts = document.querySelectorAll('.alert-danger');
    existingAlerts.forEach(alert => alert.remove());
    
    const alertDiv = document.createElement('div');
    alertDiv.id = 'errorAlert';
    alertDiv.className = 'alert alert-danger';
    alertDiv.innerHTML = `
        <div class="d-flex align-items-center">
            <i class="bi bi-exclamation-triangle-fill me-2"></i>
            <div>${message}</div>
        </div>
    `;
    
    const container = document.querySelector('.card-body') || document.querySelector('main') || document.body;
    container.insertBefore(alertDiv, container.firstChild);
    
    setTimeout(() => {
        alertDiv.classList.add('fade');
        setTimeout(() => {
            alertDiv.remove();
        }, 300);
    }, 5000);
}

function showSuccess(message) {
    // Remove any existing success alerts
    const existingAlerts = document.querySelectorAll('.alert-success');
    existingAlerts.forEach(alert => alert.remove());
    
    // Remove any error alerts
    const errorAlerts = document.querySelectorAll('.alert-danger');
    errorAlerts.forEach(alert => alert.remove());
    
    const alertDiv = document.createElement('div');
    alertDiv.className = 'alert alert-success alert-dismissible fade show';
    alertDiv.role = 'alert';
    alertDiv.innerHTML = `
        <div class="d-flex align-items-center">
            <i class="bi bi-check-circle-fill me-2"></i>
            <div>${message}</div>
            <button type="button" class="btn-close ms-auto" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    `;
    
    const container = document.querySelector('.card-body') || document.querySelector('main') || document.body;
    container.insertBefore(alertDiv, container.firstChild);
    
    setTimeout(() => {
        const bsAlert = new bootstrap.Alert(alertDiv);
        bsAlert.close();
    }, 3000);
}

function formatDate(dateString) {
    if (!dateString) return '';
    
    try {
        const options = { year: 'numeric', month: 'long', day: 'numeric' };
        return new Date(dateString).toLocaleDateString(undefined, options);
    } catch (error) {
        console.error('Error formatting date:', error);
        return 'Invalid date';
    }
}

window.addEventListener('popstate', () => {
    const hash = window.location.hash.substring(1);
    if (['dashboard', 'profile', 'search', 'settings'].includes(hash)) {
        showPage(hash);
    }
});

document.addEventListener('DOMContentLoaded', () => {
    const passwordInput = document.getElementById('password');
    if (passwordInput) {
        passwordInput.setAttribute('autocomplete', 'current-password');
    }
    
    checkAuthStatus();
    
    if (loginForm) initLoginForm();
    if (registerForm) initRegisterForm();
    if (searchBtn) initSearch();
    if (editProfileBtn) initProfile();
    if (saveSettingsBtn) initSettings();
    if (logoutBtn) initLogout();
    
    initNavigation();
    
    applySavedTheme();
    
    applySavedMenuPreferences();
});
