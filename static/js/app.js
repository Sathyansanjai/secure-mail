// ============================================
// Smail App JavaScript
// ============================================

document.addEventListener('DOMContentLoaded', function() {
    // Initialize app
    initApp();
});

function initApp() {
    // Setup menu toggle
    const menuToggle = document.getElementById('menuToggle');
    const sidebar = document.getElementById('sidebar');
    
    if (menuToggle) {
        menuToggle.addEventListener('click', function() {
            sidebar.classList.toggle('active');
        });
    }
    
    // Setup menu items
    const menuItems = document.querySelectorAll('.menu-item');
    menuItems.forEach(item => {
        item.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Remove active class from all items
            menuItems.forEach(mi => mi.classList.remove('active'));
            
            // Add active class to clicked item
            this.classList.add('active');
            
            // Get page to load
            const page = this.getAttribute('data-page');
            loadContent(page);
        });
    });
    
    // Load inbox by default
    loadContent('inbox');
    
    // Load statistics
    loadStats();
    
    // Setup refresh button
    const refreshBtn = document.querySelector('.icon-btn[title="Refresh"]');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', function() {
            const activePage = document.querySelector('.menu-item.active').getAttribute('data-page');
            loadContent(activePage);
            loadStats();
        });
    }
}

function loadContent(page) {
    const mainContent = document.getElementById('mainContent');
    
    // Show loading state
    mainContent.innerHTML = `
        <div class="loading-spinner">
            <i class="fas fa-circle-notch fa-spin"></i>
            <p>Loading...</p>
        </div>
    `;
    
    // Map page names to routes
    const routes = {
        'inbox': '/inbox',
        'phishing': '/phishing-logs',
        'trash': '/trash'
    };
    
    const url = routes[page] || '/inbox';
    
    // Fetch content
    fetch(url)
        .then(response => response.text())
        .then(html => {
            mainContent.innerHTML = html;
            
            // Update counts
            updateCounts(page, html);
        })
        .catch(error => {
            console.error('Error loading content:', error);
            mainContent.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-exclamation-circle"></i>
                    <h3>Error Loading Content</h3>
                    <p>Please try again later.</p>
                </div>
            `;
        });
}

function updateCounts(page, html) {
    // Count email cards in the HTML
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, 'text/html');
    const emailCards = doc.querySelectorAll('.email-card');
    const count = emailCards.length;
    
    // Update badge
    if (page === 'inbox') {
        const inboxBadge = document.getElementById('inbox-count');
        if (inboxBadge) {
            inboxBadge.textContent = count;
        }
    } else if (page === 'phishing') {
        const phishingBadge = document.getElementById('phishing-count');
        if (phishingBadge) {
            phishingBadge.textContent = count;
        }
    }
}

function loadStats() {
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            // Update stats widget
            const statTotal = document.getElementById('stat-total');
            const statSafe = document.getElementById('stat-safe');
            const statPhishing = document.getElementById('stat-phishing');
            
            if (statTotal) statTotal.textContent = data.total;
            if (statSafe) statSafe.textContent = data.safe;
            if (statPhishing) statPhishing.textContent = data.phishing;
            
            // Update phishing badge
            const phishingBadge = document.getElementById('phishing-count');
            if (phishingBadge) {
                phishingBadge.textContent = data.phishing;
            }
        })
        .catch(error => {
            console.error('Error loading stats:', error);
        });
}

// Auto-refresh every 30 seconds
setInterval(function() {
    const activePage = document.querySelector('.menu-item.active');
    if (activePage) {
        const page = activePage.getAttribute('data-page');
        loadContent(page);
        loadStats();
    }
}, 30000);

// Search functionality
const searchInput = document.querySelector('.search-bar input');
if (searchInput) {
    let searchTimeout;
    searchInput.addEventListener('input', function() {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
            const query = this.value.toLowerCase();
            filterEmails(query);
        }, 300);
    });
}

function filterEmails(query) {
    const emailCards = document.querySelectorAll('.email-card');
    emailCards.forEach(card => {
        const sender = card.querySelector('.email-sender').textContent.toLowerCase();
        const subject = card.querySelector('.email-subject').textContent.toLowerCase();
        const body = card.querySelector('.email-preview') ? 
                     card.querySelector('.email-preview').textContent.toLowerCase() : '';
        
        if (sender.includes(query) || subject.includes(query) || body.includes(query)) {
            card.style.display = 'flex';
        } else {
            card.style.display = 'none';
        }
    });
}
