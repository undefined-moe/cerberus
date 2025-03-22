// This file contains code adapted from https://github.com/TecharoHQ/anubis under the MIT License.

import pow from "./proof-of-work.mjs";

// from Xeact
const u = (url = "", params = {}) => {
  let result = new URL(url, window.location.href);
  Object.entries(params).forEach((kv) => {
    let [k, v] = kv;
    result.searchParams.set(k, v);
  });
  return result.toString();
};

// const imageURL = (mood, cacheBuster) =>
//   u(`/.within.website/x/cmd/anubis/static/img/${mood}.webp`, { cacheBuster });

(async () => {
  const content = document.getElementById('content');
  // const image = document.getElementById('image');
  const title = document.getElementById('title');
  // const spinner = document.getElementById('spinner');
  // const anubisVersion = JSON.parse(document.getElementById('anubis_version').textContent);

  const challenge = JSON.parse(document.getElementById('challenge').textContent);
  const difficulty = JSON.parse(document.getElementById('difficulty').textContent);

  const t0 = Date.now();
  const { hash, nonce } = await pow(challenge, difficulty);
  const t1 = Date.now();
  console.log({ hash, nonce });

  title.innerHTML = "Success!";
  content.innerHTML = `Done! Took ${t1 - t0}ms, ${nonce} iterations`;
  // image.src = imageURL("happy", anubisVersion);
  // spinner.innerHTML = "";
  // spinner.style.display = "none";

  setTimeout(() => {
    const redir = window.location.href;
    const url = window.location.origin + window.location.pathname;
    window.location.href = u(url, { cerberus: true, response: hash, nonce, redir });
  }, 250);
})();