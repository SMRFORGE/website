// Mobile nav toggle
document.querySelector('.nav-toggle')?.addEventListener('click', () => {
  document.querySelector('.nav')?.classList.toggle('open');
});

// Close nav when clicking a link (mobile)
document.querySelectorAll('.nav-links a').forEach(link => {
  link.addEventListener('click', () => {
    document.querySelector('.nav')?.classList.remove('open');
  });
});

// Footer year — keeps copyright current without a deploy
const footerYear = document.getElementById('footer-year');
if (footerYear) {
  footerYear.textContent = String(new Date().getFullYear());
}
