const bar = document.querySelector(".top");
const nav = bar.querySelector("nav");
const menu = bar.querySelector(".menu");

const setOpen = open => {
  menu.setAttribute("aria-expanded", open);
  bar.classList.toggle("open", open);
};
menu.addEventListener("click", () => setOpen(menu.getAttribute("aria-expanded") !== "true"));
nav.addEventListener("click", e => e.target.closest("a") && setOpen(false));
addEventListener("keydown", e => e.key === "Escape" && setOpen(false));
addEventListener("scroll", () => bar.classList.toggle("scrolled", scrollY > 8), { passive: true });

const links = [...nav.querySelectorAll('a[href^="#"]:not(.btn)')];
const spy = new IntersectionObserver(entries => {
  for (const e of entries) {
    if (!e.isIntersecting) continue;
    for (const a of links) a.hash === "#" + e.target.id ? a.setAttribute("aria-current", "true") : a.removeAttribute("aria-current");
  }
}, { rootMargin: "-40% 0px -55% 0px" });
for (const a of links) {
  const s = document.getElementById(a.hash.slice(1));
  if (s) spy.observe(s);
}

for (const pre of document.querySelectorAll("main pre:not(.term pre)")) {
  const box = document.createElement("div");
  const b = document.createElement("button");
  box.className = "code";
  b.type = "button";
  b.className = "copy";
  b.textContent = "Copy";
  b.setAttribute("aria-label", "Copy to clipboard");
  b.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(pre.innerText);
      b.textContent = "Copied";
    } catch {
      const r = document.createRange();
      r.selectNodeContents(pre);
      getSelection().removeAllRanges();
      getSelection().addRange(r);
      b.textContent = "Selected";
    }
    setTimeout(() => (b.textContent = "Copy"), 1600);
  });
  pre.tabIndex = 0;
  pre.before(box);
  box.append(pre, b);
}
