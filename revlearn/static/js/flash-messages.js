"use strict";

document.querySelectorAll(".flash-message").forEach((message) => {
  let timer;

  const dismiss = () => {
    window.clearTimeout(timer);
    message.classList.add("is-dismissing");
    const removalDelay = window.matchMedia("(prefers-reduced-motion: reduce)").matches
      ? 0
      : 220;
    window.setTimeout(() => message.remove(), removalDelay);
  };

  const schedule = () => {
    window.clearTimeout(timer);
    const delay = Number(message.dataset.autoDismiss);
    if (delay > 0) {
      timer = window.setTimeout(dismiss, delay);
    }
  };

  message.querySelector(".flash-dismiss")?.addEventListener("click", dismiss);
  message.addEventListener("mouseenter", () => window.clearTimeout(timer));
  message.addEventListener("mouseleave", schedule);
  message.addEventListener("focusin", () => window.clearTimeout(timer));
  message.addEventListener("focusout", schedule);
  schedule();
});
