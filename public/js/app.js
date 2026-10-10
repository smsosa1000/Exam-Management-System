/* ExamGuard Pro — Client-side JavaScript */
document.addEventListener('DOMContentLoaded', () => {
  // Add fade-in animation to cards
  document.querySelectorAll('.card, .stat-card, .question-card').forEach((el, i) => {
    el.style.animationDelay = `${i * 0.05}s`;
    el.classList.add('fade-in');
  });
});
