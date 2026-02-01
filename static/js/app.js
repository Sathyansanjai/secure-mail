document.addEventListener("DOMContentLoaded", initApp);

function initApp() {
    // Menu toggle
    const menuToggle = document.getElementById("menuToggle");
    const sidebar = document.getElementById("sidebar");
    if (menuToggle && sidebar) {
        menuToggle.addEventListener("click", () =>
            sidebar.classList.toggle("active")
        );
    }

    // Sidebar menu items (Inbox, All Mail, Trash, Phishing) - optimized for quick response
    document.querySelectorAll(".menu-item").forEach(item => {
        item.addEventListener("click", e => {
            e.preventDefault();
            const page = item.dataset.page;

            // Immediate visual feedback
            item.style.opacity = "0.7";
            item.style.pointerEvents = "none";

            // Highlight active menu item immediately
            document.querySelectorAll(".menu-item")
                .forEach(mi => mi.classList.remove("active"));
            item.classList.add("active");

            // Load page
            if (page === "inbox") loadPage("/inbox");
            if (page === "allmail") loadPage("/allmail");
            if (page === "trash") loadPage("/trash");
            if (page === "phishing") loadPage("/phishing-logs");

            // Restore visual state after a short delay
            setTimeout(() => {
                item.style.opacity = "1";
                item.style.pointerEvents = "auto";
            }, 300);
        });
    });

    // ✅ COMPOSE BUTTON SUPPORT (NEW)
    const composeBtn = document.querySelector(".compose-btn");
    if (composeBtn) {
        composeBtn.addEventListener("click", () => {
            loadPage("/compose");

            // Remove active highlight from sidebar items
            document.querySelectorAll(".menu-item")
                .forEach(mi => mi.classList.remove("active"));
        });
    }

    // Load inbox by default
    loadPage("/inbox");
    loadStats();

    // Refresh button - optimized for quick response
    const refreshBtn = document.querySelector('.icon-btn[title="Refresh"]');
    if (refreshBtn) {
        refreshBtn.addEventListener("click", () => {
            // Immediate visual feedback
            refreshBtn.style.transform = "rotate(360deg)";
            refreshBtn.style.transition = "transform 0.5s ease";

            const activePage =
                document.querySelector(".menu-item.active")?.dataset.page || "inbox";

            if (activePage === "inbox") loadPage("/inbox", false); // Silent refresh
            if (activePage === "trash") loadPage("/trash", false);
            if (activePage === "phishing") loadPage("/phishing-logs", false);
            if (activePage === "allmail") loadPage("/allmail", false);

            loadStats();

            // Reset rotation after animation
            setTimeout(() => {
                refreshBtn.style.transform = "rotate(0deg)";
            }, 500);
        });
    }

    // Helper function for refresh
    function refreshPage() {
        const refreshBtn = document.querySelector('.icon-btn[title="Refresh"]');
        if (refreshBtn) refreshBtn.click();
    }

    // Search setup
    setupSearch();

    // Auto scan emails
    setTimeout(() => {
        fetch("/scan-emails").catch(console.error);
    }, 2000);

    // Real-time email checking (every 5 seconds)
    let emailCheckInterval = setInterval(checkNewEmails, 5000);

    // Check immediately on load
    setTimeout(checkNewEmails, 1000);

    // Auto refresh every 30 seconds (reduced frequency for better performance)
    setInterval(() => {
        const activeItem = document.querySelector(".menu-item.active");

        // If we are on compose page (no active menu item) or any other non-listed page, DO NOT redirect
        if (!activeItem) return;

        const activePage = activeItem.dataset.page;

        if (activePage === "inbox") loadPage("/inbox", false); // false = silent refresh
        if (activePage === "allmail") loadPage("/allmail", false);
        if (activePage === "trash") loadPage("/trash", false);
        if (activePage === "phishing") loadPage("/phishing-logs", false);

        loadStats();
    }, 30000);

    // Listen for page loaded events to reinitialize components
    window.addEventListener('pageLoaded', function (e) {
        const url = e.detail.url;
        console.log('Page loaded:', url);

        // Reinitialize search if needed
        setupSearch();

        // If it's compose page, ensure form is ready
        if (url.includes('/compose')) {
            // Compose form initialization is handled in compose.html script
        }
    });
}

function loadPage(url, showLoading = true) {
    const main = document.getElementById("mainContent");
    if (!main) return;

    let spinnerTimeout;
    if (showLoading) {
        // Show minimal loading indicator for faster perceived performance
        main.style.opacity = "0.5";
        main.style.transition = "opacity 0.2s";

        // Only show full spinner if loading takes more than 300ms
        spinnerTimeout = setTimeout(() => {
            main.innerHTML = `
                <div class="loading-spinner">
                    <i class="fas fa-circle-notch fa-spin"></i>
                    <p>Loading...</p>
                </div>
            `;
            main.style.opacity = "1";
        }, 300);
    }

    fetch(url, {
        credentials: 'same-origin',
        redirect: 'follow',
        headers: {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
    })
        .then(res => {
            if (spinnerTimeout) clearTimeout(spinnerTimeout);

            // Handle redirects (like authentication redirects)
            if (res.redirected) {
                // If redirected to login, reload the page
                if (res.url.includes('/') && !res.url.includes('/main')) {
                    window.location.href = '/';
                    return Promise.reject(new Error('Redirected to login'));
                }
            }

            // Get response text first to check if it's HTML error content
            return res.text().then(text => {
                if (!res.ok) {
                    // Check if response contains HTML error container (from backend)
                    if (text.includes('error-container') || text.includes('Session Expired')) {
                        // Return the HTML error content to display it
                        return text;
                    }
                    // Otherwise throw error with message
                    throw new Error(`HTTP ${res.status}: ${text.substring(0, 200)}`);
                }
                return text;
            });
        })
        .catch(err => {
            // Handle network errors gracefully
            if (err.name === 'TypeError' && err.message.includes('Failed to fetch')) {
                throw new Error('Network error: Unable to connect to server. Please check your connection and try again.');
            }
            throw err;
        })
        .then(html => {
            if (!html) {
                throw new Error("Empty response from server");
            }

            // Check if this is an error response (contains error-container)
            const isErrorResponse = html.includes('error-container') ||
                html.includes('Session Expired') ||
                html.includes('Gmail service unavailable');

            main.innerHTML = html;
            main.style.opacity = "1";

            // Only execute scripts and trigger events if it's not an error
            if (!isErrorResponse) {
                // Execute any scripts in the loaded HTML
                const scripts = main.querySelectorAll('script');
                scripts.forEach(oldScript => {
                    const newScript = document.createElement('script');
                    Array.from(oldScript.attributes).forEach(attr => {
                        newScript.setAttribute(attr.name, attr.value);
                    });
                    newScript.appendChild(document.createTextNode(oldScript.innerHTML));
                    oldScript.parentNode.replaceChild(newScript, oldScript);
                });

                // Trigger a custom event for page-specific initialization
                window.dispatchEvent(new CustomEvent('pageLoaded', { detail: { url } }));
            } else {
                // For error responses, add retry functionality
                const retryBtn = main.querySelector('.retry-btn');
                if (retryBtn) {
                    retryBtn.onclick = () => loadPage(url);
                }
            }
        })
        .catch(err => {
            if (spinnerTimeout) clearTimeout(spinnerTimeout);
            console.error("Error loading page:", err);

            if (showLoading) {
                // Check if the error response contains HTML (from backend error handling)
                // If it's a network error, show our custom error UI
                const isNetworkError = err.message.includes('Failed to fetch') ||
                    err.message.includes('NetworkError') ||
                    err.message.includes('Network error') ||
                    err.message.includes('TypeError');

                // Check for authentication/session errors
                const isAuthError = err.message.includes('401') ||
                    err.message.includes('Unauthorized') ||
                    err.message.includes('Session Expired') ||
                    err.message.includes('Redirected to login');

                if (isNetworkError || isAuthError) {
                    // Show a better error message with retry option
                    const errorTitle = isAuthError ? "Session Expired" : "Connection Error";
                    const errorMessage = isAuthError
                        ? "Your session has expired or authentication failed. Please log in again."
                        : "Unable to connect to the server. Please check your connection and try again.";
                    const errorList = isAuthError
                        ? '<li>Your Google OAuth token has expired</li><li>Please log out and log back in</li>'
                        : '<li>Check your internet connection</li><li>Server may be temporarily unavailable</li><li>Try refreshing the page</li>';

                    main.innerHTML = `
                        <div class="error-container">
                            <div class="error-icon">
                                <i class="fas fa-exclamation-triangle"></i>
                            </div>
                            <h2>${errorTitle}</h2>
                            <p>${errorMessage}</p>
                            ${!isAuthError ? `<ul class="error-list">${errorList}</ul>` : ''}
                            <div class="error-actions">
                                ${isAuthError ? `
                                    <button class="refresh-btn" onclick="window.location.href='/'">
                                        <i class="fas fa-sign-in-alt"></i> Go to Login
                                    </button>
                                ` : `
                                    <button class="retry-btn" onclick="loadPage('${url}')">
                                        <i class="fas fa-redo"></i> Retry
                                    </button>
                                    <button class="refresh-btn" onclick="window.location.reload()">
                                        <i class="fas fa-sync-alt"></i> Refresh Page
                                    </button>
                                `}
                            </div>
                            ${!isAuthError ? `<p class="error-details">Error: ${err.message}</p>` : ''}
                        </div>
                    `;
                } else {
                    // For other errors, try to show the error message from the response
                    main.innerHTML = `
                        <div class="error-container">
                            <div class="error-icon">
                                <i class="fas fa-exclamation-triangle"></i>
                            </div>
                            <h2>Error loading page</h2>
                            <p>${err.message || 'An unexpected error occurred'}</p>
                            <div class="error-actions">
                                <button class="retry-btn" onclick="loadPage('${url}')">
                                    <i class="fas fa-redo"></i> Retry
                                </button>
                                <button class="refresh-btn" onclick="window.location.reload()">
                                    <i class="fas fa-sync-alt"></i> Refresh Page
                                </button>
                            </div>
                        </div>
                    `;
                }
                main.style.opacity = "1";
            }
        });
}

function loadStats() {
    fetch("/api/stats", {
        credentials: 'same-origin'
    })
        .then(res => {
            if (!res.ok) {
                return res.json().then(data => {
                    throw new Error(data.error || `HTTP ${res.status}`);
                });
            }
            return res.json();
        })
        .then(data => {
            if (!data) return;
            const totalEl = document.getElementById("stat-total");
            const safeEl = document.getElementById("stat-safe");
            const phishingEl = document.getElementById("stat-phishing");
            const phishingCountEl = document.getElementById("phishing-count");

            if (totalEl) totalEl.textContent = data.total ?? 0;
            if (safeEl) safeEl.textContent = data.safe ?? 0;
            if (phishingEl) phishingEl.textContent = data.phishing ?? 0;
            if (phishingCountEl) phishingCountEl.textContent = data.phishing ?? 0;

            const inboxCount = document.getElementById("inbox-count");
            if (inboxCount) inboxCount.textContent = data.safe ?? 0;
            const allMailCount = document.getElementById("allmail-count");
            if (allMailCount) allMailCount.textContent = data.total ?? 0;
        })
        .catch(err => {
            // Only log errors, don't show to user (stats are non-critical)
            if (err.message && !err.message.includes('Failed to fetch')) {
                console.error("Error loading stats:", err);
            }
        });
}

function setupSearch() {
    const searchInput = document.querySelector(".search-bar input");
    if (!searchInput) return;

    let timeout;
    searchInput.addEventListener("input", function () {
        clearTimeout(timeout);
        timeout = setTimeout(() => {
            filterEmails(this.value.toLowerCase());
        }, 300);
    });
}

function filterEmails(query) {
    document.querySelectorAll(".email-card").forEach(card => {
        const sender =
            card.querySelector(".email-sender")?.textContent.toLowerCase() || "";
        const subject =
            card.querySelector(".email-subject")?.textContent.toLowerCase() || "";
        const body =
            card.querySelector(".email-preview")?.textContent.toLowerCase() || "";

        card.style.display =
            sender.includes(query) ||
                subject.includes(query) ||
                body.includes(query)
                ? "flex"
                : "none";
    });
}

// Track notified emails to prevent duplicate alerts
const notifiedEmails = new Set();

// Real-time email checking and notification system
function checkNewEmails() {
    fetch("/api/check-new-emails", {
        credentials: 'same-origin',
        headers: {
            'Accept': 'application/json'
        }
    })
        .then(res => {
            if (!res.ok) {
                // If response is not ok, try to parse JSON error
                return res.json().then(data => {
                    // Don't throw for 401 - session expired, just stop checking
                    if (res.status === 401) {
                        console.log("Session expired, stopping email checks");
                        return { new_emails: [], count: 0 };
                    }
                    throw new Error(data.error || `HTTP ${res.status}`);
                }).catch(() => {
                    // If JSON parsing fails, check status
                    if (res.status === 401) {
                        return { new_emails: [], count: 0 };
                    }
                    throw new Error(`HTTP ${res.status}: ${res.statusText}`);
                });
            }
            return res.json();
        })
        .then(data => {
            if (!data || !data.new_emails || data.count === 0) return;

            // Process each new email (only phishing emails are returned now)
            data.new_emails.forEach(email => {
                // Only show notification if we haven't notified about this email before
                if (!notifiedEmails.has(email.id)) {
                    notifiedEmails.add(email.id);
                    showEmailNotification(email);

                    // Auto-refresh trash/phishing logs if phishing detected
                    const activePage = document.querySelector(".menu-item.active")?.dataset.page;
                    if (email.is_phishing) {
                        // Refresh trash and phishing logs
                        if (activePage === "trash") {
                            setTimeout(() => loadPage("/trash", false), 1000);
                        }
                        if (activePage === "phishing") {
                            setTimeout(() => loadPage("/phishing-logs", false), 1000);
                        }
                    }
                }
            });

            // Update stats
            loadStats();
        })
        .catch(err => {
            // Only log errors, don't show to user (this runs every 5 seconds)
            // Network errors are expected if server is temporarily unavailable
            // Session expired errors are handled above
            if (err.message &&
                !err.message.includes('Failed to fetch') &&
                !err.message.includes('Session expired')) {
                console.error("Error checking new emails:", err);
            }
        });
}

function showEmailNotification(email) {
    // Only show notifications for phishing emails
    // Safe emails are logged but don't trigger alerts
    if (!email.is_phishing) {
        return;
    }

    // Create notification element
    const notification = document.createElement("div");
    notification.className = "email-notification phishing";

    const icon = "fa-shield-virus";
    const title = "Threat Detected";
    const message = `We moved a suspicious email from <strong>${email.sender}</strong> to Trash.`;

    notification.innerHTML = `
        <div class="notification-icon">
            <i class="fas ${icon}"></i>
        </div>
        <div class="notification-content">
            <div class="notification-header">
                <strong>${title}</strong>
                <span class="notification-time">Just now</span>
            </div>
            <p class="notification-message">${message}</p>
            <div class="notification-meta">
                <span class="confidence-badge">
                    <i class="fas fa-robot"></i> ${email.confidence}% Confidence
                </span>
            </div>
        </div>
        <button class="notification-close" onclick="this.parentElement.remove()">
            <i class="fas fa-times"></i>
        </button>
    `;

    // Add to notification container
    let container = document.getElementById("notificationContainer");
    if (!container) {
        container = document.createElement("div");
        container.id = "notificationContainer";
        document.body.appendChild(container);
    }

    // Prepend to show newest at top
    container.insertBefore(notification, container.firstChild);

    // Animate in
    requestAnimationFrame(() => notification.classList.add("show"));

    // Auto-remove after 10 seconds
    setTimeout(() => {
        notification.classList.remove("show");
        setTimeout(() => notification.remove(), 400); // Wait for transition
    }, 10000);

    // Browser notification (if permission granted)
    if ("Notification" in window && Notification.permission === "granted") {
        new Notification(title, {
            body: `Phishing detected from ${email.sender}. Moved to trash.`,
            icon: "/static/favicon.ico",
            tag: email.id,
            requireInteraction: false
        });
    }
}

// Request notification permission on page load
if ("Notification" in window && Notification.permission === "default") {
    Notification.requestPermission();
}


// Ensure Load More works on dynamic navigation
window.addEventListener('pageLoaded', function (e) {
    // Load More functionality for All Mail
    const valLoadMoreBtn = document.getElementById('loadMoreBtn');
    if (valLoadMoreBtn) {
        // Remove existing listener if any (to prevent duplicates)
        const newBtn = valLoadMoreBtn.cloneNode(true);
        valLoadMoreBtn.parentNode.replaceChild(newBtn, valLoadMoreBtn);

        newBtn.addEventListener('click', function () {
            const loadUrl = this.getAttribute('data-url');
            if (!loadUrl) return;

            const originalHtml = this.innerHTML;
            this.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Loading...';
            this.disabled = true;

            fetch(loadUrl, { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
                .then(response => response.text())
                .then(html => {
                    const temp = document.createElement('div');
                    temp.innerHTML = html;

                    const newEmails = temp.querySelectorAll('.email-card');
                    const list = document.getElementById('allMailList');
                    if (list) {
                        newEmails.forEach(email => {
                            email.style.opacity = '0';
                            list.appendChild(email);
                            // Micro-animation for new emails
                            setTimeout(() => {
                                email.style.transition = 'opacity 0.3s ease';
                                email.style.opacity = '1';
                            }, 50);
                        });
                    }

                    const nextBtnData = temp.querySelector('#loadMoreBtn');
                    if (nextBtnData) {
                        this.setAttribute('data-url', nextBtnData.getAttribute('data-url'));
                        this.innerHTML = originalHtml;
                        this.disabled = false;
                    } else {
                        this.remove();
                    }
                })
                .catch(err => {
                    console.error('Error loading more:', err);
                    this.innerHTML = originalHtml;
                    this.disabled = false;
                });
        });
    }
});
