document.addEventListener("DOMContentLoaded", initApp);

function initApp() {
    // Menu toggle
    const menuToggle = document.getElementById("menuToggle");
    const sidebar = document.getElementById("sidebar");
    if (menuToggle && sidebar) menuToggle.addEventListener("click", () => sidebar.classList.toggle("active"));

    // Sidebar menu items
    document.querySelectorAll(".menu-item").forEach(item => {
        item.addEventListener("click", e => {
            e.preventDefault();
            const page = item.dataset.page;

            if (page === "inbox") loadPage("/inbox");
            if (page === "trash") loadPage("/trash");
            if (page === "phishing") loadPage("/phishing-logs");

            // Highlight active menu item
            document.querySelectorAll(".menu-item").forEach(mi => mi.classList.remove("active"));
            item.classList.add("active");
        });
    });

    // Load inbox by default
    loadPage("/inbox");
    loadStats();

    // Refresh button
    const refreshBtn = document.querySelector('.icon-btn[title="Refresh"]');
    if (refreshBtn) refreshBtn.addEventListener("click", () => {
        const activePage = document.querySelector(".menu-item.active")?.dataset.page || "inbox";
        if (activePage === "inbox") loadPage("/inbox");
        if (activePage === "trash") loadPage("/trash");
        if (activePage === "phishing") loadPage("/phishing-logs");
        loadStats();
    });

    // Search setup
    setupSearch();

    // Auto scan emails
    setTimeout(() => fetch("/scan-emails").catch(console.error), 2000);
    setInterval(() => {
        const activePage = document.querySelector(".menu-item.active")?.dataset.page || "inbox";
        if (activePage === "inbox") loadPage("/inbox");
        if (activePage === "trash") loadPage("/trash");
        if (activePage === "phishing") loadPage("/phishing-logs");
        loadStats();
    }, 30000);
}

function loadPage(url) {
    const main = document.getElementById("mainContent");
    if (!main) return;

    main.innerHTML = `
        <div class="loading-spinner">
            <i class="fas fa-circle-notch fa-spin"></i>
            <p>Loading...</p>
        </div>
    `;

    fetch(url)
        .then(res => {
            if (!res.ok) throw new Error("Failed to load");
            return res.text();
        })
        .then(html => main.innerHTML = html)
        .catch(err => {
            main.innerHTML = "<h2>Error loading page</h2>";
            console.error(err);
        });
}

function loadStats() {
    fetch("/api/stats")
        .then(res => res.json())
        .then(data => {
            if (!data) return;
            document.getElementById("stat-total").textContent = data.total ?? 0;
            document.getElementById("stat-safe").textContent = data.safe ?? 0;
            document.getElementById("stat-phishing").textContent = data.phishing ?? 0;
            document.getElementById("phishing-count").textContent = data.phishing ?? 0;
        })
        .catch(console.error);
}

function setupSearch() {
    const searchInput = document.querySelector(".search-bar input");
    if (!searchInput) return;

    let timeout;
    searchInput.addEventListener("input", function() {
        clearTimeout(timeout);
        timeout = setTimeout(() => filterEmails(this.value.toLowerCase()), 300);
    });
}

function filterEmails(query) {
    document.querySelectorAll(".email-card").forEach(card => {
        const sender = card.querySelector(".email-sender")?.textContent.toLowerCase() || "";
        const subject = card.querySelector(".email-subject")?.textContent.toLowerCase() || "";
        const body = card.querySelector(".email-preview")?.textContent.toLowerCase() || "";
        card.style.display = (sender.includes(query) || subject.includes(query) || body.includes(query)) ? "flex" : "none";
    });
}
