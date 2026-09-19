import fs from "node:fs";

const code = fs.readFileSync("public/assets/js/script.js", "utf8");
function a(cond, msg) { if (!cond) throw new Error(msg); }

// Login mode hides the setup-only fields. The hidden confirm/username inputs
// must not remain `required`: constraint validation runs on hidden inputs too,
// so an empty required hidden field would block form submission with an
// `invalid` event and the login form could never submit in any browser.
a(code.includes("panel==='login'"),
  "login branch must exist in setStage");
a(code.includes("$('#password-confirm').required=false"),
  "login mode must clear required on #password-confirm");
a(code.includes("$('#username').required=false"),
  "login mode must clear required on #username");
a(code.includes("$('#password-confirm').required=true"),
  "setup mode must restore required on #password-confirm");
a(code.includes("$('#username').required=true"),
  "setup mode must restore required on #username");

// The submit handler must remain a normal async fetch-based handler (no
// synchronous/blocking primitive) so the login POST reaches the server.
a(code.includes("$('#auth-form').addEventListener('submit',async(e)=>{e.preventDefault()"),
  "submit handler must preventDefault and run async");

console.log("webfleet login-form frontend contract: PASS");