(function () {
    try {
        if (localStorage.getItem("theme") === "light") {
            document.documentElement.setAttribute("data-theme", "light");
        }
    } catch (error) {
        // Ignore storage access failures and fall back to the default theme.
    }
})();
