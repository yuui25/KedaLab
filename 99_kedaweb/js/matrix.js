/* Matrix rain canvas — minimal, performant */
(function () {
  const canvas = document.getElementById("matrix");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");

  // Mix of katakana, latin, symbols — appropriate to the theme
  const charset =
    "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ" +
    "0123456789ABCDEF<>{}[]/\\=*+#@$%&!?_-:;.,";
  const chars = charset.split("");
  const fontSize = 14;
  // Easter egg: occasionally a column spells out "kedalab" instead of random chars.
  const EGG_WORD = "kedalab";
  const EGG_START_PROB = 0.0008;  // per char per frame — ~few per second across all columns
  let columns = 0;
  let drops = [];
  let words = [];  // per-column { text: string|null, idx: int }

  function resize() {
    canvas.width = window.innerWidth * window.devicePixelRatio;
    canvas.height = window.innerHeight * window.devicePixelRatio;
    canvas.style.width = window.innerWidth + "px";
    canvas.style.height = window.innerHeight + "px";
    ctx.setTransform(window.devicePixelRatio, 0, 0, window.devicePixelRatio, 0, 0);
    columns = Math.floor(window.innerWidth / fontSize);
    drops = new Array(columns).fill(0).map(() => Math.random() * -50);
    words = new Array(columns).fill(null).map(() => ({ text: null, idx: 0 }));
  }

  function draw() {
    ctx.fillStyle = "rgba(6, 8, 12, 0.15)";
    ctx.fillRect(0, 0, window.innerWidth, window.innerHeight);

    ctx.font = fontSize + "px JetBrains Mono, Consolas, monospace";

    for (let i = 0; i < columns; i++) {
      let ch;
      let isEgg = false;
      const w = words[i];
      if (w.text !== null) {
        // Continuing an in-flight egg word
        ch = w.text[w.idx++];
        isEgg = true;
        if (w.idx >= w.text.length) { w.text = null; w.idx = 0; }
      } else if (Math.random() < EGG_START_PROB) {
        // Start a new egg word on this column
        w.text = EGG_WORD;
        w.idx = 1;
        ch = w.text[0];
        isEgg = true;
      } else {
        ch = chars[Math.floor(Math.random() * chars.length)];
      }
      const x = i * fontSize;
      const y = drops[i] * fontSize;

      if (isEgg) {
        // Vivid pink accent so the egg clearly pops out of the green rain.
        ctx.fillStyle = "rgba(255, 165, 214, 1)";
      } else if (Math.random() > 0.975) {
        ctx.fillStyle = "rgba(220, 255, 230, 0.9)";
      } else {
        ctx.fillStyle = "rgba(0, 255, 156, 0.65)";
      }
      ctx.fillText(ch, x, y);

      if (y > window.innerHeight && Math.random() > 0.975) {
        drops[i] = 0;
        // Reset any pending egg if the drop wraps mid-word
        w.text = null; w.idx = 0;
      }
      drops[i] += 1;
    }
  }

  let raf;
  let lastFrame = 0;
  function loop(t) {
    if (t - lastFrame > 50) {  // ~20 fps, easy on CPU
      draw();
      lastFrame = t;
    }
    raf = requestAnimationFrame(loop);
  }

  window.addEventListener("resize", resize);
  resize();
  raf = requestAnimationFrame(loop);

  // pause on tab hidden
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      cancelAnimationFrame(raf);
    } else {
      raf = requestAnimationFrame(loop);
    }
  });
})();
