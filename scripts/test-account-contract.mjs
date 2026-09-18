import fs from "node:fs";

const html = fs.readFileSync("internal/server/web/index.html", "utf8");
const js = fs.readFileSync("internal/server/web/assets/js/script.js", "utf8");
function a(cond, msg) { if (!cond) throw new Error(msg); }

// Setup form carries Username, Email, Password and Confirm password; the
// confirm field is hidden in login mode but present for first-run setup.
for (const id of ["username", "email", "password", "password-confirm"]) {
  a(html.includes('id="' + id + '"'), "auth form missing " + id);
}
a(js.includes("Username or email"), "login form must accept username or email");
a(js.includes("'Passwords do not match.'"), "setup frontend must validate password confirmation");
a(js.includes("$('#confirm-field')") && js.includes("$('#password-confirm')"), "confirm field must be wired to the setup form");
console.log("webfleet account-creation contract: ok");