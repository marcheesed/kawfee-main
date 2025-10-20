const toggleButton = document.getElementById("theme-toggle");
const sunIcon = document.getElementById("icon-sun");
const moonIcon = document.getElementById("icon-moon");

// Load theme preference from localStorage
if (localStorage.getItem("theme") === "dark") {
  document.body.classList.add("dark-theme");
  sunIcon.style.display = "none";
  moonIcon.style.display = "inline";
} else {
  // default to light
  sunIcon.style.display = "inline";
  moonIcon.style.display = "none";
}

toggleButton.addEventListener("click", () => {
  if (document.body.classList.contains("dark-theme")) {
    // Switch to light
    document.body.classList.remove("dark-theme");
    localStorage.setItem("theme", "light");
    sunIcon.style.display = "inline";
    moonIcon.style.display = "none";
  } else {
    // Switch to dark
    document.body.classList.add("dark-theme");
    localStorage.setItem("theme", "dark");
    sunIcon.style.display = "none";
    moonIcon.style.display = "inline";
  }
});
