import fs from "node:fs";

const code = fs.readFileSync("public/assets/js/script.js", "utf8");
function a(cond, msg) { if (!cond) throw new Error(msg); }

// A wrong password on the login endpoint keeps its distinct message and must
// not be treated as an expired session.
a(code.includes("if(r.status===401&&path==='/api/login')throw new Error('Username/email or password is incorrect.')"),
  "wrong-login 401 must map to the distinct incorrect-credentials message");

// A non-login 401 while the user is authenticated transitions to the login UI
// (via handleSessionExpired) rather than surfacing an inline error.
a(code.includes("if(state.session)handleSessionExpired()"),
  "authenticated non-login 401 must trigger handleSessionExpired");

// The expiration handler reveals the login UI, hides protected content, clears
// the session and CSRF, and shows the standard message.
a(code.includes("function handleSessionExpired()"),
  "handleSessionExpired must be defined");
a(code.includes("state.session=null;state.csrf=''"),
  "expiration must clear session and CSRF state");
a(code.includes("dash.hidden=true") && code.includes("stage.hidden=false"),
  "expiration must hide the dashboard and reveal the auth stage");
a(code.includes("renderLogin()"),
  "expiration must return to the login form");
a(code.includes("'Your session has ended. Sign in again.'"),
  "expiration must show the standard session-ended message");

// Concurrent expiry discoveries must be coalesced into one transition.
a(code.includes("sessionExpiring=true") && code.includes("sessionExpiring=false"),
  "expiration transition must be idempotent for concurrent 401s");

console.log("webfleet session-expiry frontend contract: PASS");
